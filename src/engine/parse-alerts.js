/*
 * parse-alerts.js — WR.parseAlerts(text, ctx) → { signals, entities, stats, extras }
 *
 * Formats (SPEC §3.3): Alertmanager webhook JSON ({alerts:[...]}, or a bare array, including the
 * v2 API shape where status is an object), Prometheus /api/v1/alerts (data.alerts[]) and
 * /api/v1/rules (data.groups[].rules[].alerts[]), and three text shapes:
 *   [FIRING:2] KubePodCrashLooping (payments-api prod-eu-west critical)
 *   ALERT KubePodCrashLooping{namespace="shop", pod="payments-api-7d9f8b6c5-x2k4p",severity="critical"} firing since 2026-10-05T21:49:30Z
 *   2026-10-05T21:49:30Z FIRING critical PaymentsHighErrorBurn service=payments-api cluster=prod-eu-west burn_rate=16.2
 *
 * Each alert becomes one signal; the alert name decides its kind, its labels decide the component.
 * extras.highCardinalityLabels lists label keys whose values are per-instance (pod names with
 * hashes, IPs, UUIDs, request ids, or ≥ 20 distinct values) — the stack-fit panel uses it to show
 * where metric-based tools start charging or dropping series.
 */
(function (WR) {
  'use strict';

  var T = WR.time;
  var E = WR.entities;

  // Label keys that name the affected workload, most specific meaning first (SPEC §3.3, extended
  // with the kube-prometheus / Istio spellings that show up in real payloads).
  var COMPONENT_KEYS = ['service', 'app', 'app_kubernetes_io_name', 'k8s_app', 'deployment', 'statefulset', 'daemonset',
    'workload', 'destination_workload', 'horizontalpodautoscaler', 'job_name', 'job', 'pod', 'container', 'instance'];
  var NS_KEYS = ['namespace', 'exported_namespace', 'kubernetes_namespace', 'k8s_namespace_name', 'destination_service_namespace'];
  var CLUSTER_KEYS = ['cluster', 'k8s_cluster', 'cluster_name', 'kubernetes_cluster', 'k8s_cluster_name'];

  // The scrape job / Service of the monitoring stack is not the thing that is broken. In
  // kube-prometheus, KubePodCrashLooping carries service="kube-prometheus-stack-kube-state-metrics";
  // taking that literally would blame the metrics exporter for every crash loop.
  var MONITORING = /^(?:.*kube-state-metrics.*|node-exporter|.*-node-exporter|prometheus(?:-.*)?|.*-prometheus(?:-.*)?|alertmanager.*|kubelet|cadvisor|apiserver|kube-apiserver|blackbox.*|grafana-agent|alloy|otel-collector.*|opentelemetry-collector.*|kubernetes-.*|integrations\/.*|servicemonitor\/.*|podmonitor\/.*|monitoring|federate)$/i;

  function alertKind(name, labels) {
    var n = String(name || '');
    if (/CrashLoop/i.test(n)) return 'crash_loop';
    if (/OOM/.test(n) || /oomkill|OutOfMemory/i.test(n)) return 'oom_killed';
    if (/ImagePull/i.test(n)) return 'image_pull';
    if (/NodeNotReady|NodeUnreachable/i.test(n)) return 'node_not_ready';
    if (/Pressure/i.test(n)) return 'node_pressure';
    // Case-sensitive SLO so "SlowRequests" is not an SLO alert.
    if (/ErrorBudget|Burn/i.test(n) || /SLO/.test(n) || /(^|[_-])slo([_-]|$)/i.test(n)) return 'slo_burn';
    if (/DNS/i.test(n)) return 'dns_failure';
    if (/Cert(?:ificate)?\w*Expir|Expir\w*Cert|TLS|SSLCert|Cert(?:ificate)?\w*(?:NotReady|RenewalFail|RenewFail|NotRenewed)/i.test(n)) return 'tls_error';
    if (/5xx|HighErrorRate|ErrorRateHigh|ErrorsHigh|HighErrors|HTTPErrors|ServerErrors/i.test(n)) return 'http_5xx';
    if (/Latency/i.test(n)) return 'span_slow';
    // Only autoscaler alerts mean "autoscaler at max". KubeDeploymentReplicasMismatch and
    // KubeDeploymentRolloutStuck fire on any Deployment, with or without an autoscaler.
    if (/Hpa\w*Max|MaxedOut|Hpa\w*Replicas\w*Mismatch/i.test(n)) return 'hpa_maxed';
    // KubeContainerWaiting says why in its `reason` label.
    if (/ContainerWaiting/i.test(n) && labels && labels.reason) {
      var why = String(labels.reason);
      if (/ImagePull|ErrImage|InvalidImageName/i.test(why)) return 'image_pull';
      if (/CreateContainerConfigError|CreateContainerError|RunContainerError/i.test(why)) return 'config_error';
      if (/CrashLoop/i.test(why)) return 'crash_loop';
    }
    if (/Throttl/i.test(n)) return 'throttled';
    if (/TooManyConnections|ConnectionsHigh|TooManyClients|MaxConnections|ConnectionPool/i.test(n)) return 'conn_exhaustion';
    if (/Evict/i.test(n)) return 'evicted';
    if (/RateLimit|TooManyRequests|429/i.test(n)) return 'http_429';
    if (/JobFailed/i.test(n) && labels && /migrat/i.test(String(labels.job_name || labels.job || ''))) return 'migration';
    if (/Unschedulable|NotScheduled/i.test(n)) return 'scheduling_failed';
    return 'alert_firing';
  }

  // "1h", "6h", "3d", "30m", "1 hour" → minutes; null when it is not a plain window length.
  function windowMinutes(v) {
    var m = /^\s*(\d+(?:\.\d+)?)\s*(m|min|mins|minutes?|h|hr|hours?|d|days?)\s*$/i.exec(String(v == null ? '' : v));
    if (!m) return null;
    var n = Number(m[1]), u = m[2].charAt(0).toLowerCase();
    return n * (u === 'm' ? 1 : u === 'h' ? 60 : 1440);
  }

  function severityOf(v, status) {
    if (status === 'resolved') return 'info';
    var s = String(v || '').toLowerCase();
    if (/^(critical|crit|page|p1|sev1|emergency|fatal|disaster)$/.test(s)) return 'critical';
    if (/^(error|high|major|p2|sev2)$/.test(s)) return 'error';
    if (/^(warning|warn|medium|minor|p3|sev3|average)$/.test(s)) return 'warn';
    if (/^(info|informational|low|none|ticket|p4|p5|sev4)$/.test(s)) return 'info';
    return status === 'pending' ? 'info' : 'warn';
  }

  function num(v) {
    if (v == null || v === '') return null;
    if (typeof v === 'number') return isFinite(v) ? v : null;
    var m = /-?\d+(?:\.\d+)?(?:e[+-]?\d+)?/i.exec(String(v));
    return m ? Number(m[0]) : null;
  }

  function validTime(v, opts) {
    if (!v) return null;
    if (/^0001-01-01/.test(String(v))) return null; // Alertmanager's "not set"
    return T.parse(String(v), opts);
  }

  // ------------------------------------------------------------------------------------------
  // JSON shapes → normalised alerts { name, status, labels, annotations, startsAt, endsAt, value, format }
  // ------------------------------------------------------------------------------------------
  function fromAm(a, docStatus, format) {
    var labels = a.labels || {};
    var st = a.status;
    var silenced = false;
    if (st && typeof st === 'object') {
      // Alertmanager v2 API: status.state ∈ active | suppressed | unprocessed
      silenced = st.state === 'suppressed';
      st = 'firing';
    }
    st = String(st || docStatus || 'firing').toLowerCase();
    if (st === 'active') st = 'firing';
    var value = a.value != null ? a.value : (a.values ? firstValue(a.values) : (a.valueString ? a.valueString : null));
    return {
      name: labels.alertname || a.alertname || a.name || 'UnnamedAlert', status: st === 'resolved' ? 'resolved' : st === 'pending' ? 'pending' : 'firing',
      labels: labels, annotations: a.annotations || {}, startsAt: a.startsAt || a.activeAt || null, endsAt: a.endsAt || null,
      value: value, silenced: silenced, format: format, fingerprint: a.fingerprint || null
    };
  }

  function obj(v) { return v && typeof v === 'object' && !Array.isArray(v) ? v : {}; }

  function firstValue(vals) {
    if (!vals || typeof vals !== 'object') return null;
    var k = Object.keys(vals);
    return k.length ? vals[k[0]] : null;
  }

  function fromProm(a, ruleName) {
    var labels = a.labels || {};
    var state = String(a.state || 'firing').toLowerCase();
    return {
      name: labels.alertname || ruleName || 'UnnamedAlert',
      status: state === 'pending' ? 'pending' : state === 'inactive' ? 'inactive' : 'firing',
      labels: labels, annotations: a.annotations || {}, startsAt: a.activeAt || null, endsAt: null,
      value: a.value != null ? a.value : null, format: 'Prometheus alerts JSON'
    };
  }

  function readDoc(doc, out) {
    if (!doc || typeof doc !== 'object') return false;
    if (Array.isArray(doc)) {
      if (!doc.length) return true;
      if (doc[0] && typeof doc[0] === 'object' && (doc[0].labels || doc[0].alerts)) {
        var any = false;
        doc.forEach(function (d) {
          if (d && d.alerts) any = readDoc(d, out) || any;
          else if (d && d.labels) { out.push(fromAm(d, null, 'Alertmanager JSON')); any = true; }
        });
        return any;
      }
      return false;
    }
    if (Array.isArray(doc.alerts)) {
      var fmt = doc.receiver != null || doc.groupKey != null || doc.version != null ? 'Alertmanager webhook JSON' : 'Alertmanager JSON';
      // A webhook notification is one alert group: labels every alert shares sit in groupLabels /
      // commonLabels (and commonAnnotations). Alertmanager also repeats them inside each alert, but
      // hand-trimmed or templated payloads often keep them only at the group level.
      var shared = obj(doc.groupLabels), common = obj(doc.commonLabels), commonAnn = obj(doc.commonAnnotations);
      doc.alerts.forEach(function (a) {
        if (!a || typeof a !== 'object') return;
        var own = obj(a.labels);
        var merged = Object.assign({}, a, {
          labels: Object.assign({}, shared, common, own),
          annotations: Object.assign({}, commonAnn, obj(a.annotations))
        });
        var x = fromAm(merged, doc.status, fmt);
        x.ownAlertname = own.alertname != null;
        out.push(x);
      });
      return true;
    }
    if (doc.data && typeof doc.data === 'object') {
      if (Array.isArray(doc.data.alerts)) { doc.data.alerts.forEach(function (a) { if (a) out.push(fromProm(a)); }); return true; }
      if (Array.isArray(doc.data.groups)) {
        doc.data.groups.forEach(function (g) {
          (g && g.rules || []).forEach(function (r) {
            (r && r.alerts || []).forEach(function (a) { if (a) { var x = fromProm(a, r.name); x.format = 'Prometheus rules JSON'; out.push(x); } });
          });
        });
        return true;
      }
    }
    if (doc.labels && (doc.labels.alertname || doc.startsAt)) { out.push(fromAm(doc, null, 'Alertmanager JSON')); return true; }
    return false;
  }

  // ------------------------------------------------------------------------------------------
  // Text shapes
  // ------------------------------------------------------------------------------------------
  // Alertmanager's default subject (template/default.tmpl "__subject"):
  //   [FIRING:<n>] <GroupLabels values, sorted by label name> (<CommonLabels minus GroupLabels values>)
  // so values can sit both before and inside the parentheses; custom templates often add a summary.
  var RE_SLACK = /^\s*\[(FIRING|RESOLVED)(?::\s*(\d+))?\]\s+([A-Za-z_:][\w:.-]*)(.*)$/i;
  var RE_SLACK_REST = /^((?:\s+[^\s()]+)*)\s+\(([^)]*)\)\s*(.*)$/;
  var COMMON_NS = /^(default|kube-system|kube-public|monitoring|observability|ingress-nginx|cert-manager|istio-system|argocd|flux-system|logging)$/;
  // Hand-written titles join values with words ("{{alertname}} for {{job}}" is a long-standing
  // community Slack title); those words are not label values. "in <x>" names a namespace.
  var SUBJECT_STOPWORD = /^(for|on|in|at|of|from|to|the|is|are|and|with|by|via)$/i;
  // amtool alert query (cli/format): simple "Alertname  Starts At  Summary  State" and extended
  // "Labels  Annotations  Starts At  Ends At  Generator URL  State", tabwriter-aligned, dates in
  // the "2006-01-02 15:04:05 MST" layout.
  var RE_AMTOOL_SIMPLE_H = /^\s*Alertname\s+Starts At\s+Summary\s+State\s*$/;
  var RE_AMTOOL_EXT_H = /^\s*Labels\s+Annotations\s+Starts At\s+Ends At\s+Generator URL\s+State\s*$/;
  var AM_DATE = '\\d{4}-\\d{2}-\\d{2}[ T]\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?(?:\\s?(?:[A-Z]{2,5}|[+-]\\d{2}:?\\d{2}|Z))?';
  var RE_AMTOOL_SIMPLE_ROW = new RegExp('^\\s*([A-Za-z_:][\\w:.-]*)\\s+(' + AM_DATE + ')\\s+(.*?)\\s*\\b(active|suppressed|unprocessed|firing|resolved|pending)\\s*$', 'i');
  var RE_AMTOOL_EXT_ROW = new RegExp('^(.*?)\\s+(' + AM_DATE + ')\\s+(' + AM_DATE + ')\\s+(\\S*)\\s+(active|suppressed|unprocessed|firing|resolved|pending)\\s*$', 'i');
  var ANNOTATION_KEYS = /^(summary|description|message|runbook_url|runbook|dashboard|title)$/i;
  // Body of the default notification (" - key = value" under "Labels:"/"Annotations:") and the
  // common Slack templates ("• key: value" under "Details:").
  var RE_SECTION = /^\s*\*?(Labels|Annotations|Details|Alert details|Alerts Firing|Alerts Resolved)\*?\s*:\s*$/i;
  var RE_BULLET = /^\s*(?:[-•*·]\s*)?\*?([A-Za-z_][\w.]*)\*?\s*(?:=|:)\s*(.+?)\s*$/;
  var RE_PROMQL = /^\s*(?:ALERT\s+)?([A-Za-z_:][\w:]*)\s*\{([^}]*)\}\s*(firing|pending|resolved|inactive)?\s*(?:since|at|for|from)?\s*(.*)$/i;
  var RE_STAMPED = /^(FIRING|RESOLVED|PENDING)\s+(?:(critical|warning|warn|info|page|ticket|high|medium|low|error|none)\s+)?([A-Za-z_:][\w:.-]*)\s*(.*)$/i;
  var RE_LABEL = /([A-Za-z_][\w]*)\s*=~?\s*"((?:[^"\\]|\\.)*)"/g;
  var SEV_WORD = /^(critical|warning|warn|info|page|ticket|high|medium|low|error|none|p[1-5])$/i;
  var CLUSTERISH = /(^|[-_])(prod|production|staging|stage|stg|dev|test|qa|uat|sandbox|cluster|eks|gke|aks)([-_\d]|$)|(^|-)(eu|us|ap|sa|af|me|ca)-[a-z]+(-\d)?($|-)|-(east|west|central|north|south)\d?$/i;

  function parseTextLine(line, lineNo, tzOpts, knownClusters, stats) {
    var m, labels, ann = {};
    if ((m = RE_SLACK.exec(line))) {
      labels = { alertname: m[3] };
      var tail = m[4] || '', groupVals = '', parenVals = '', summaryText = '';
      var rm = RE_SLACK_REST.exec(tail);
      if (rm) { groupVals = rm[1]; parenVals = rm[2]; summaryText = rm[3]; }
      else {
        // No parentheses: up to three bare label-like tokens are group values, anything else
        // (or anything after a dash or colon) is a summary written by a custom template.
        var tt = tail.trim();
        var toks = tt.split(/\s+/).filter(function (t) { return t && !SUBJECT_STOPWORD.test(t); });
        if (toks.length && toks.length <= 3 && !/^[-:–—]/.test(tt) && toks.every(function (t) { return /^[\w.:\/@-]+$/.test(t) && /[-\d.]|^[a-z]/.test(t); })) groupVals = tt;
        else summaryText = tt;
      }
      var vals = (groupVals + ' ' + parenVals).split(/[\s,]+/).filter(Boolean);
      var rest = [];
      var guessed = [];
      var prevWord = '';
      vals.forEach(function (v) {
        var after = prevWord;
        prevWord = SUBJECT_STOPWORD.test(v) ? v.toLowerCase() : '';
        if (prevWord) return;
        var kv = /^([\w.]+)=(.*)$/.exec(v);
        if (kv) { labels[kv[1]] = kv[2].replace(/^"|"$/g, ''); return; }
        if (SEV_WORD.test(v) && !labels.severity) { labels.severity = v.toLowerCase(); guessed.push('severity'); }
        else if (after === 'in' && !labels.namespace && !CLUSTERISH.test(v) && knownClusters.indexOf(v) < 0) { labels.namespace = v; guessed.push('namespace'); }
        else if (!labels.cluster && (knownClusters.indexOf(v) >= 0 || CLUSTERISH.test(v))) { labels.cluster = v; guessed.push('cluster'); }
        else if (!labels.pod && E.isPodName(v)) { labels.pod = v; guessed.push('pod'); }
        else rest.push(v);
      });
      // Group-label values come without keys, sorted by label name, so a namespace ("shop",
      // "kube-system") comes before the service it holds. The first unclaimed workload-looking
      // value is the workload.
      if (rest.length >= 2 && !labels.namespace && (COMMON_NS.test(rest[0]) || (rest[0].indexOf('-') < 0 && rest[1].indexOf('-') >= 0))) {
        labels.namespace = rest.shift(); guessed.push('namespace');
      }
      if (rest.length && !labels.service) { labels.service = rest[0]; guessed.push('service'); }
      if (summaryText) ann.summary = summaryText.replace(/^[-:–—\s]+/, '');
      return { name: m[3], status: m[1].toUpperCase() === 'RESOLVED' ? 'resolved' : 'firing', labels: labels, annotations: ann, startsAt: null, endsAt: null, value: null, count: m[2] ? Number(m[2]) : 1, format: 'alert text', line: lineNo, guessed: guessed };
    }
    var ex = T.extract(line, tzOpts);
    if (ex && (m = RE_STAMPED.exec(ex.rest))) {
      if (ex.tzAssumed) stats.tzAssumed++;
      var kv2 = WR.logfmt(m[4]);
      labels = { alertname: m[3] };
      Object.keys(kv2).forEach(function (k) {
        if (/^(summary|description|message|msg|runbook_url)$/.test(k)) ann[k === 'msg' || k === 'message' ? 'summary' : k] = kv2[k];
        else labels[k] = kv2[k];
      });
      if (m[2]) labels.severity = m[2].toLowerCase();
      var free = m[4].replace(/([A-Za-z_][\w.]*)=("(?:[^"\\]|\\.)*"|\S*)/g, '').trim();
      if (free && !ann.summary) ann.summary = free;
      var status = m[1].toLowerCase();
      return { name: m[3], status: status, labels: labels, annotations: ann, startsAt: status === 'resolved' ? null : ex.ts, endsAt: status === 'resolved' ? ex.ts : null, value: null, tsInferred: ex.tsInferred, format: 'alert text', line: lineNo, preParsed: true };
    }
    if ((m = RE_PROMQL.exec(line)) && /=/.test(m[2])) {
      labels = { alertname: m[1] };
      RE_LABEL.lastIndex = 0;
      var lm;
      while ((lm = RE_LABEL.exec(m[2])) !== null) labels[lm[1]] = lm[2];
      if (m[1] === 'ALERTS' && labels.alertname) m[1] = labels.alertname;
      var st = (m[3] || labels.alertstate || 'firing').toLowerCase();
      var restText = (m[4] || '').trim();
      var tsTok = /^(\S+(?:\s+\d{2}:\d{2}:\d{2}\S*)?)/.exec(restText);
      var p = tsTok ? T.parse(tsTok[1], tzOpts) : null;
      if (p && p.tzAssumed) stats.tzAssumed++;
      var after = p ? restText.slice(tsTok[1].length).trim() : restText;
      if (after) ann.summary = after.replace(/^[-:–—\s]+/, '');
      return {
        name: labels.alertname || m[1], status: st === 'resolved' ? 'resolved' : st === 'pending' ? 'pending' : st === 'inactive' ? 'inactive' : 'firing',
        labels: labels, annotations: ann, startsAt: st === 'resolved' ? null : (p ? p.ts : null), endsAt: st === 'resolved' && p ? p.ts : null,
        value: null, tsInferred: p ? p.tsInferred : false, format: 'alert text', line: lineNo, preParsed: true
      };
    }
    // logfmt: alertname=X severity=critical ...
    if (/\balertname=/.test(line)) {
      var lk = WR.logfmt(line);
      var name = lk.alertname;
      var st2 = String(lk.status || lk.state || 'firing').toLowerCase();
      var tsv = lk.startsAt || lk.activeAt || lk.ts || lk.time;
      var p2 = tsv ? T.parse(tsv, tzOpts) : (ex ? { ts: ex.ts, tsInferred: ex.tsInferred, tzAssumed: ex.tzAssumed } : null);
      if (p2 && p2.tzAssumed) stats.tzAssumed++;
      var labels3 = {};
      Object.keys(lk).forEach(function (k) {
        if (/^(summary|description|message)$/.test(k)) ann.summary = lk[k];
        else if (!/^(status|state|startsAt|activeAt|endsAt|ts|time)$/.test(k)) labels3[k] = lk[k];
      });
      return { name: name, status: st2 === 'resolved' ? 'resolved' : st2 === 'pending' ? 'pending' : 'firing', labels: labels3, annotations: ann, startsAt: p2 ? p2.ts : null, endsAt: null, value: null, tsInferred: p2 ? p2.tsInferred : false, format: 'alert text', line: lineNo, preParsed: true };
    }
    return null;
  }

  function headerColumns(header) {
    var cols = [], re = /\S+(?: \S+)*/g, m;
    while ((m = re.exec(header)) !== null) cols.push({ name: m[0], start: m.index });
    return cols;
  }

  function labelPairs(s) {
    var out = {}, lm;
    RE_LABEL.lastIndex = 0;
    while ((lm = RE_LABEL.exec(s || '')) !== null) out[lm[1]] = lm[2].replace(/\\"/g, '"');
    return out;
  }

  // "Pod shop/payments-api-7d9f8b6c5-x2k4p is crash looping." names the pod (and namespace).
  function podFromText(text, labels) {
    var m = /\b([a-z0-9][a-z0-9-]*)\/([a-z0-9][a-z0-9.-]*[a-z0-9])\b/.exec(text || '');
    if (m && E.isPodName(m[2])) { labels.namespace = labels.namespace || m[1]; labels.pod = m[2]; return; }
    var toks = String(text || '').split(/[\s,;:()"']+/);
    for (var i = 0; i < toks.length; i++) if (E.isPodName(toks[i])) { labels.pod = toks[i]; return; }
  }

  function amtoolRow(line, lineNo, table, tzOpts, stats) {
    var labels, ann = {}, startsAt = null, endsAt = null, state, tsInferred = false;
    function when(s) {
      var p = s ? T.parse(String(s).trim(), tzOpts) : null;
      if (p && p.tzAssumed) stats.tzAssumed++;
      if (p) tsInferred = tsInferred || p.tsInferred;
      return p ? p.ts : null;
    }
    if (table.type === 'simple') {
      var m = RE_AMTOOL_SIMPLE_ROW.exec(line);
      if (!m) return null;
      labels = { alertname: m[1] };
      startsAt = when(m[2]);
      if (m[3]) { ann.summary = m[3]; podFromText(m[3], labels); }
      state = m[4].toLowerCase();
    } else {
      var cells = null;
      if (table.cols && table.cols.length === 6) {
        cells = table.cols.map(function (c, i) { return line.slice(c.start, i + 1 < table.cols.length ? table.cols[i + 1].start : line.length).trim(); });
        if (!/^(active|suppressed|unprocessed|firing|resolved|pending)$/i.test(cells[5]) || when(cells[2]) == null) cells = null;
      }
      if (cells) {
        labels = labelPairs(cells[0]); ann = labelPairs(cells[1]);
        startsAt = when(cells[2]); endsAt = when(cells[3]); state = cells[5].toLowerCase();
      } else {
        // Columns collapsed (pasted through chat): split label and annotation pairs by key name.
        var x = RE_AMTOOL_EXT_ROW.exec(line);
        if (!x) return null;
        var pairs = labelPairs(x[1]);
        labels = {};
        Object.keys(pairs).forEach(function (k) { if (ANNOTATION_KEYS.test(k)) ann[k] = pairs[k]; else labels[k] = pairs[k]; });
        startsAt = when(x[2]); endsAt = when(x[3]); state = x[5].toLowerCase();
      }
      if (!labels.alertname) return null;
    }
    return {
      name: labels.alertname, status: state === 'resolved' ? 'resolved' : state === 'pending' ? 'pending' : 'firing', silenced: state === 'suppressed',
      labels: labels, annotations: ann, startsAt: startsAt, endsAt: state === 'resolved' ? endsAt : null, value: null,
      tsInferred: tsInferred, format: 'amtool', line: lineNo, preParsed: true
    };
  }

  function labelFamily(k) {
    if (COMPONENT_KEYS.indexOf(k) >= 0) return 'workload';
    if (NS_KEYS.indexOf(k) >= 0) return 'ns';
    if (CLUSTER_KEYS.indexOf(k) >= 0) return 'cluster';
    return k;
  }

  // A " - key = value" / "• key: value" line under a text alert. Explicit labels replace what the
  // subject line could only guess (its bare values), family by family.
  function attachLabel(a, key, value, section) {
    var v = String(value).replace(/^["']|["']$/g, '');
    if (section === 'annotations' || (section !== 'labels' && (ANNOTATION_KEYS.test(key) || /^alert$/i.test(key)))) {
      var ak = /^alert$/i.test(key) ? 'title' : key.toLowerCase();
      a.annotations[ak] = v;
      if (ak === 'summary' || (ak === 'description' && !a.annotations.summary)) a.annotations.summary = v;
      return;
    }
    if (key === 'alertname') return;
    var fam = labelFamily(key);
    (a.guessed || []).forEach(function (g) { if (g !== key && labelFamily(g) === fam) delete a.labels[g]; });
    a.labels[key] = v;
  }

  // ------------------------------------------------------------------------------------------
  // Labels → component
  // ------------------------------------------------------------------------------------------
  function firstLabel(labels, keys) {
    for (var i = 0; i < keys.length; i++) {
      var v = labels[keys[i]];
      if (v != null && v !== '') return { key: keys[i], value: String(v) };
    }
    return null;
  }

  function componentFor(alert, kind, cluster, clusterKnown) {
    var L = alert.labels || {};
    var nsL = firstLabel(L, NS_KEYS);
    var ns = nsL ? nsL.value : null;
    var base = { namespace: ns, cluster: cluster, clusterKnown: clusterKnown, source: 'alerts' };
    function mk(o) { var h = E.hint(Object.assign({}, base, o)); return h; }

    if (/^CoreDNS/i.test(alert.name) || /^(coredns|kube-dns)$/i.test(String(L.job || L.service || L.k8s_app || ''))) return mk({ name: 'coredns' });
    // cert-manager metrics label the Certificate by name, with its namespace in exported_namespace
    // (namespace is cert-manager's own). "auth-service-mtls" protects the auth-service workload.
    if (/Cert/i.test(alert.name) && L.name && !L.service && !L.pod) {
      var certNs = L.exported_namespace || ns;
      return mk({ name: String(L.name).replace(/-(m?tls|cert|certificate|tls-cert)$/i, ''), namespace: certNs });
    }
    if ((kind === 'node_not_ready' || kind === 'node_pressure') && (L.node || L.instance)) {
      var nodeName = String(L.node || L.instance).replace(/:\d+$/, '');
      if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(nodeName)) return mk({ node: nodeName, namespace: null });
    }
    for (var i = 0; i < COMPONENT_KEYS.length; i++) {
      var k = COMPONENT_KEYS[i];
      var v = L[k];
      if (v == null || v === '') continue;
      v = String(v);
      if (MONITORING.test(v)) continue;
      if (k === 'pod') return mk({ pod: v });
      if (k === 'instance') {
        var host = v.replace(/:\d+$/, '');
        if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || /^\[?[0-9a-f:]+\]?$/i.test(host)) continue;
        if (E.isPodName(host)) return mk({ pod: host });
        var fh = E.fromHost(host);
        if (fh && !fh.external) return mk({ name: fh.name, namespace: fh.namespace || ns });
        continue;
      }
      // Prometheus Operator job labels are "<namespace>/<name>" ("data/orders-postgresql").
      var slashNs = null;
      var sm = /^([a-z0-9][a-z0-9-]*)\/([a-z0-9][a-z0-9.-]*)$/i.exec(v);
      if (sm) { slashNs = sm[1]; v = sm[2]; }
      // "postgres-exporter" / "redis-metrics" report on the datastore beside them.
      var name = v.replace(/-(exporter|metrics)$/, '');
      return slashNs && !ns ? mk({ name: name, namespace: slashNs }) : mk({ name: name });
    }
    if (L.node && kind !== 'alert_firing') return mk({ node: String(L.node), namespace: null });
    return null;
  }

  // ------------------------------------------------------------------------------------------
  // High-cardinality label detection
  // ------------------------------------------------------------------------------------------
  var RE_IP = /^\d{1,3}(\.\d{1,3}){3}(:\d+)?$/;
  var RE_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  var RE_ID_KEY = /(^|_)(user|session|request|trace|span|customer|order|account|transaction|correlation|client)(_?id)?$|uuid|(^|_)uid$|_id$|^id$/i;
  var NEVER_HIGH = { alertname: 1, severity: 1, namespace: 1, cluster: 1, job: 1, service: 1, prometheus: 1, alertstate: 1, team: 1, env: 1, environment: 1, region: 1 };

  function perInstance(v) {
    var s = String(v);
    return RE_IP.test(s) || RE_UUID.test(s) || /^[0-9a-f]{16,}$/i.test(s) || E.isPodName(s.replace(/:\d+$/, ''));
  }

  function highCardinality(alerts) {
    var vals = Object.create(null);
    alerts.forEach(function (a) {
      Object.keys(a.labels || {}).forEach(function (k) {
        (vals[k] || (vals[k] = new Set())).add(String(a.labels[k]));
      });
    });
    var out = [];
    Object.keys(vals).forEach(function (k) {
      if (NEVER_HIGH[k]) return;
      var set = vals[k];
      var hit = set.size >= 20 || RE_ID_KEY.test(k);
      if (!hit) set.forEach(function (v) { if (!hit && perInstance(v)) hit = true; });
      if (hit) out.push(k);
    });
    return out.sort();
  }

  // ------------------------------------------------------------------------------------------
  // Main
  // ------------------------------------------------------------------------------------------
  function parseAlerts(text, ctx) {
    ctx = ctx || {};
    var stats = WR.newStats('empty');
    var result = {
      signals: [], entities: [], stats: stats,
      extras: { highCardinalityLabels: [], counts: { firing: 0, resolved: 0, pending: 0 }, burn: null, clusters: [], minTs: null, maxTs: null, alertNames: [] }
    };
    try {
      run(String(text == null ? '' : text), ctx, result);
    } catch (e) {
      WR.addWarning(stats, 'Alert parsing stopped early: ' + (e && e.message ? e.message : String(e)));
    }
    stats.signals = result.signals.length;
    return result;
  }


  function run(text, ctx, result) {
    var stats = result.stats, extras = result.extras;
    var lines = WR.splitLines(text);
    stats.lines = lines.length;
    if (!text.trim()) return;
    var tzOpts = { defaultTz: ctx.defaultTz || 'Z', year: ctx.year, now: ctx.now };
    var cur = { cluster: ctx.cluster || E.DEFAULT_CLUSTER, clusterKnown: !!ctx.cluster };
    var alerts = [];
    var formats = {};
    var table = null;      // amtool table being read
    var lastText = null;   // the last text alert, which a following "Labels:" block describes
    var section = null;    // 'labels' | 'annotations' inside such a block

    var segs = WR.segmentJson(lines);
    for (var i = 0; i < segs.length; i++) {
      var sg = segs[i];
      if (sg.type === 'json') {
        var pj = WR.parseJsonLenient(sg.text);
        if (pj.value != null) {
          var before = alerts.length;
          if (readDoc(pj.value, alerts)) {
            stats.parsed += sg.endLine - sg.startLine + 1;
            if (pj.repaired) WR.addWarning(stats, 'Alert JSON starting on line ' + sg.startLine + ' looked cut off; read the complete part.');
            locate(alerts, before, sg);
            for (var q = before; q < alerts.length; q++) { alerts[q].paneCluster = cur.cluster; alerts[q].paneClusterKnown = cur.clusterKnown; formats[alerts[q].format] = 1; }
            continue;
          }
          stats.skipped += sg.endLine - sg.startLine + 1;
          WR.addWarning(stats, 'JSON on line ' + sg.startLine + ' is not an Alertmanager or Prometheus alerts payload.');
          continue;
        }
        if (sg.startLine !== sg.endLine || /^\s*\{/.test(sg.text)) {
          stats.skipped += sg.endLine - sg.startLine + 1;
          WR.addWarning(stats, 'Alert JSON starting on line ' + sg.startLine + ' could not be read (' + WR.truncate(pj.error || 'invalid JSON', 80) + ').');
          continue;
        }
        sg = { type: 'line', lineNo: sg.startLine, text: sg.text };
      }
      var line = sg.text;
      if (!line.trim()) { section = null; table = null; continue; }
      var marker = E.detectCluster(line);
      if (marker) {
        cur = { cluster: marker, clusterKnown: true };
        if (extras.clusters.indexOf(marker) < 0) extras.clusters.push(marker);
        stats.parsed++;
        continue;
      }
      if (/^\s*#/.test(line) || /^\s*(?:[$%>]\s*)?(curl|amtool|kubectl|jq)\b/.test(line)) { stats.parsed++; continue; }

      // amtool tables
      if (RE_AMTOOL_SIMPLE_H.test(line)) { table = { type: 'simple' }; lastText = null; stats.parsed++; continue; }
      if (RE_AMTOOL_EXT_H.test(line)) { table = { type: 'extended', cols: headerColumns(line) }; lastText = null; stats.parsed++; continue; }
      if (table) {
        var ta = null;
        try { ta = amtoolRow(line, sg.lineNo, table, tzOpts, stats); } catch (e) { ta = null; }
        if (ta) {
          ta.paneCluster = cur.cluster; ta.paneClusterKnown = cur.clusterKnown;
          alerts.push(ta); formats[ta.format] = 1; stats.parsed++;
          continue;
        }
        table = null;
      }

      // "Labels:" / "Annotations:" / "Details:" blocks under a text alert
      var sm = RE_SECTION.exec(line);
      if (sm) {
        var sname = sm[1].toLowerCase();
        section = sname === 'annotations' ? 'annotations' : /^alerts /.test(sname) ? null : 'labels';
        stats.parsed++;
        continue;
      }
      if (lastText && /^\s*Source\s*:\s*\S+\s*$/.test(line)) { stats.parsed++; continue; }
      var bm = lastText ? RE_BULLET.exec(line) : null;
      if (bm && (section || ANNOTATION_KEYS.test(bm[1]) || /^alert$/i.test(bm[1]))) {
        attachLabel(lastText, bm[1], bm[2], section);
        stats.parsed++;
        continue;
      }

      var a = null;
      try { a = parseTextLine(line, sg.lineNo, tzOpts, extras.clusters, stats); } catch (e) { a = null; }
      if (a && a.name) {
        a.paneCluster = cur.cluster; a.paneClusterKnown = cur.clusterKnown;
        alerts.push(a);
        formats[a.format] = 1;
        stats.parsed++;
        lastText = a; section = null;
      } else stats.skipped++;
    }

    var fmtNames = Object.keys(formats);
    stats.format = fmtNames.length ? fmtNames.join(' + ') : (stats.lines ? 'unrecognised' : 'empty');
    if (stats.skipped) WR.addWarning(stats, stats.skipped + ' line' + (stats.skipped === 1 ? ' was' : 's were') + ' not recognised as alerts.');
    if (!alerts.length) {
      if (stats.lines) WR.addWarning(stats, 'No alerts found. Paste an Alertmanager webhook payload, Prometheus /api/v1/alerts output, or lines like "[FIRING:1] AlertName (service cluster severity)".');
      return;
    }
    buildSignals(alerts, tzOpts, result, lines);
    if (stats.tzAssumed) WR.addWarning(stats, stats.tzAssumed + ' alert time' + (stats.tzAssumed === 1 ? '' : 's') + ' had no time zone; assumed ' + T.fmtOffset(T.offsetMinutes(tzOpts.defaultTz) || 0) + '.');
  }

  /*
   * Each alert takes the line where its own "alertname" is declared, matched in document order.
   * An alert whose name came from groupLabels/commonLabels has no alertname of its own; it takes
   * the line of its own startsAt/activeAt (or fingerprint) instead, so two alerts of one group do
   * not both point at the group header.
   */
  function locate(alerts, from, seg) {
    var starts = WR.lineIndex(seg.text);
    var text = seg.text;
    var cursor = 0;
    function esc(s) { return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
    function find(re) {
      re.lastIndex = cursor;
      var m = re.exec(text);
      return m ? m.index : -1;
    }
    for (var i = from; i < alerts.length; i++) {
      var a = alerts[i];
      var at = -1;
      if (a.ownAlertname !== false) at = find(new RegExp('"alertname"\\s*:\\s*"' + esc(a.name) + '"', 'g'));
      if (at < 0 && a.startsAt) at = find(new RegExp('"(?:startsAt|activeAt)"\\s*:\\s*"' + esc(a.startsAt) + '"', 'g'));
      if (at < 0 && a.fingerprint) at = find(new RegExp('"fingerprint"\\s*:\\s*"' + esc(a.fingerprint) + '"', 'g'));
      if (at >= 0) { a.line = seg.startLine + WR.lineAt(starts, at) - 1; cursor = at + 1; }
      else a.line = seg.startLine;
    }
  }

  function buildSignals(alerts, tzOpts, result, lines) {
    var stats = result.stats, extras = result.extras;
    var ents = E.collector();
    var perLine = Object.create(null);
    var unknownTs = [];
    var names = Object.create(null);

    alerts.forEach(function (a) {
      if (a.status === 'inactive') return;
      var L = a.labels || {};
      var clusterL = firstLabel(L, CLUSTER_KEYS);
      var cluster = clusterL ? clusterL.value : a.paneCluster;
      var clusterKnown = clusterL ? true : !!a.paneClusterKnown;
      if (clusterL && extras.clusters.indexOf(cluster) < 0) extras.clusters.push(cluster);

      var mapped = alertKind(a.name, L);
      var kind = a.status === 'resolved' ? 'alert_resolved' : mapped;
      var h = componentFor(a, mapped, cluster, clusterKnown);
      if (h) h = ents.add(h);

      // time: firing → startsAt, resolved → endsAt (falling back to startsAt), pending → activeAt
      var ts = null, tsInferred = !!a.tsInferred;
      if (a.preParsed) ts = a.status === 'resolved' ? (a.endsAt != null ? a.endsAt : a.startsAt) : a.startsAt;
      else {
        var ps = validTime(a.startsAt, tzOpts), pe = validTime(a.endsAt, tzOpts);
        var pick = a.status === 'resolved' ? (pe || ps) : ps;
        if (pick) { ts = pick.ts; tsInferred = pick.tsInferred; if (pick.tzAssumed) stats.tzAssumed++; }
        a.startMs = ps ? ps.ts : null;
        a.endMs = pe ? pe.ts : null;
      }

      var ann = a.annotations || {};
      var summary = ann.summary || ann.message || ann.description || ann.title || '';
      var attrs = { alertname: a.name, status: a.status, alertKind: mapped, labels: L, format: a.format };
      if (L.severity) attrs.severityLabel = L.severity;
      if (Object.keys(ann).length) attrs.annotations = ann;
      if (ann.runbook_url) attrs.runbook = ann.runbook_url;
      if (a.count && a.count > 1) attrs.count = a.count;
      if (a.silenced) attrs.silenced = true;
      if (a.fingerprint) attrs.fingerprint = a.fingerprint;
      if (a.startMs != null) attrs.startsAt = a.startMs;
      if (a.endMs != null) attrs.endsAt = a.endMs;
      if (L.pod) attrs.pod = String(L.pod).toLowerCase();
      if (a.value != null) attrs.value = num(a.value);

      if (mapped === 'slo_burn') {
        var burn = num(first([L.burn_rate, L.burnrate, L.burnRate, ann.burn_rate, ann.burnRate, ann.burnrate]));
        if (burn == null) {
          var bm = /(\d+(?:\.\d+)?)\s*(?:x|×)\b|burn(?:ing)?(?: rate)?(?: of| at|:|=)?\s*(\d+(?:\.\d+)?)/i.exec(summary + ' ' + (ann.description || ''));
          if (bm) burn = Number(bm[1] || bm[2]);
        }
        if (burn == null && a.value != null) burn = num(a.value);
        if (burn != null) attrs.burnRate = burn;
        var er = num(first([L.error_ratio, L.errorRatio, ann.error_ratio, ann.errorRatio]));
        if (er != null) attrs.errorRatio = er > 1 ? er / 100 : er; // "2.3" written as a percent
        if (L.long_window || L.window) attrs.window = L.long_window || L.window;
        // The long window this burn was measured over, when the labels or the name say so
        // (long_window="1h", window="6h", ...Burn1h). Without it the alert cannot stand for a
        // Workbook row: its window and threshold are unknown.
        var wm = windowMinutes(attrs.window);
        if (wm == null) { var nw = /(?:^|[^a-z0-9])(?:burn)?[_-]?(\d+)(m|h|d)(?:$|[^a-z0-9])|Burn(\d+)(m|h|d)\b/i.exec(a.name || ''); if (nw) wm = windowMinutes((nw[1] || nw[3]) + (nw[2] || nw[4])); }
        if (wm != null) attrs.longWindowMinutes = wm;
      }

      var lineNo = a.line || 1;
      var k = perLine[lineNo] || 0;
      perLine[lineNo] = k + 1;
      var label = a.status === 'resolved' ? 'resolved' : a.status === 'pending' ? 'pending' : 'firing';
      var where = h ? ' — ' + h.name + (h.namespace ? ' (' + h.namespace + ')' : '') : '';
      var sig = {
        id: 'alr-' + lineNo + (k ? '.' + k : ''),
        source: 'alerts', line: lineNo, ts: ts, tsInferred: tsInferred,
        // A pending alert has not fired yet: one notch quieter than its label says.
        severity: a.status === 'pending' ? (severityOf(L.severity, 'firing') === 'critical' ? 'warn' : 'info') : severityOf(L.severity, a.status),
        kind: kind, componentId: h ? h.id : null, relatedIds: [],
        text: WR.truncate(a.name + (attrs.count ? ' ×' + attrs.count : '') + ' ' + label + where + (summary ? ': ' + summary : '') + (attrs.burnRate != null ? ' (burn rate ' + attrs.burnRate + '×)' : ''), 400),
        raw: WR.truncate(a.format === 'alert text' ? (lines[lineNo - 1] || '') : JSON.stringify({ labels: L, annotations: ann, status: a.status, startsAt: a.startsAt, endsAt: a.endsAt }), 2000),
        attrs: attrs
      };
      result.signals.push(sig);
      if (ts == null) unknownTs.push(sig);
      else {
        if (extras.minTs == null || ts < extras.minTs) extras.minTs = ts;
        if (extras.maxTs == null || ts > extras.maxTs) extras.maxTs = ts;
      }
      extras.counts[a.status] = (extras.counts[a.status] || 0) + 1;
      names[a.name] = 1;
      if (mapped === 'slo_burn' && a.status !== 'resolved' && (attrs.burnRate != null || attrs.errorRatio != null)) {
        var b = extras.burn;
        if (!b || (attrs.burnRate || 0) > (b.maxBurnRate || 0)) {
          extras.burn = { maxBurnRate: attrs.burnRate != null ? attrs.burnRate : null, errorRatio: attrs.errorRatio != null ? attrs.errorRatio : null, alertname: a.name, signalId: sig.id, componentId: sig.componentId, status: a.status,
            longWindowMinutes: attrs.longWindowMinutes != null ? attrs.longWindowMinutes : null };
        } else if (b && b.errorRatio == null && attrs.errorRatio != null) b.errorRatio = attrs.errorRatio;
      }
    });

    // Text-format alerts without a time ("[FIRING:2] ...") are "now": firing at the moment of paste.
    unknownTs.forEach(function (s) { s.tsInferred = true; s.attrs.relative = true; s.attrs.ageMs = 0; s.attrs.tsUnknown = true; });
    var now = T.resolveNow(tzOpts.now, tzOpts);
    var ref = now != null ? now : extras.maxTs;
    if (unknownTs.length && ref != null) T.rebase(unknownTs, ref);

    extras.highCardinalityLabels = highCardinality(alerts.filter(function (a) { return a.status !== 'inactive'; }));
    extras.alertNames = Object.keys(names);
    result.entities = ents.list();
  }

  function first(arr) {
    for (var i = 0; i < arr.length; i++) if (arr[i] != null && arr[i] !== '') return arr[i];
    return null;
  }

  WR.parseAlerts = parseAlerts;
  WR.parseAlerts.alertKind = alertKind;
})(globalThis.WR = globalThis.WR || {});
