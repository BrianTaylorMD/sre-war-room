/*
 * analyze.js — WR.analyze(input) → Analysis (SPEC §4). Pure, synchronous, never throws.
 *
 * Pipeline:
 *   1. context      clean the form values (zone, now, year, deployedAt, cluster, SLO)
 *   2. parse        alerts, traces, Helm first (they carry full dates), then logs with the year
 *                   those imply when the context gives none (klog/syslog stamps have no year)
 *   3. clock        now = context.now, else the latest absolute time in any pane; re-anchor every
 *                   relative time ("3m12s ago", pod tables) on that one clock
 *   4. entities     collapse pods/Services/trace names/alert labels into components; rewrite every
 *                   id (signals, changes, deploys, edges, log dependency hints, counts) to the
 *                   canonical one; give node-level OOM-killer lines back to the workload they name
 *   5. edges        trace edges (real call counts) + log-derived dependency edges (no counts)
 *   6. window       first anomaly = earliest error (ignoring a lone early outlier); window starts
 *                   15 min before it and ends at now
 *   7. statuses     failing / degraded / at-risk per SPEC §4, deepest failing node
 *   8. deploy time  Helm history/list, else a ReplicaSet hand-off seen in rollout events
 *   9. hypotheses → root → budget → rollbacks → severity, headline → traits → timeline
 *  10. cap          at most 3,000 signals in the output (all errors kept, oldest info dropped first)
 * Every stage is wrapped: a failure becomes a warning and the rest of the analysis still renders.
 */
(function (WR) {
  'use strict';

  var T = WR.time;
  var E = WR.entities;
  var MIN = 60000;
  var MAX_SIGNALS = 3000;
  var LEAD_MS = 15 * MIN;              // SPEC: the incident window starts 15 min before the first anomaly
  var OUTLIER_GAP_MS = 60 * MIN;       // a first error an hour before all the others is background noise
  var FUTURE_GAP_MS = 6 * 60 * MIN;    // a latest stamp 6 h after all the others is a clock or typo error
  var NOW_DRIFT_MS = 2 * 60 * MIN;     // a hand-set "now" this far past the evidence deserves a warning
  var NON_ANOMALY = { change: 1, rollout: 1, alert_resolved: 1 };
  var NODE_FAIL_KINDS = { node_not_ready: 1, node_pressure: 1, evicted: 1 };
  var STATUS_RANK = { root: 0, failing: 1, degraded: 2, 'at-risk': 3, healthy: 4 };
  var STATUS_IMPACT = { root: 0.9, failing: 0.75, degraded: 0.45, 'at-risk': 0.2, healthy: 0 };
  var SOURCE_ORDER = { helm: 0, alerts: 1, logs: 2, traces: 3 };

  // A deploy, a rollout or a resolved alert is context, not an anomaly; an info-level restart
  // ("Started container") neither.
  function isAnomaly(s) { return !NON_ANOMALY[s.kind] && !(s.kind === 'restart' && s.severity === 'info'); }
  function isError(s) { return isAnomaly(s) && WR.sevRank(s.severity) >= 2; }
  function isWarn(s) { return isAnomaly(s) && s.severity === 'warn'; }
  function unknownTs(s) { return !!(s.attrs && s.attrs.tsUnknown); }

  function str(v) { return v == null ? '' : typeof v === 'string' ? v : String(v); }
  function emptyParse(format) {
    return { signals: [], entities: [], stats: WR.newStats(format || 'empty'), extras: {} };
  }

  // ---------------------------------------------------------------------------------------------
  // 1. Context
  // ---------------------------------------------------------------------------------------------
  function normContext(raw, warnings) {
    var c = raw || {};
    var defaultTz = c.defaultTz == null || String(c.defaultTz).trim() === '' ? 'Z' : String(c.defaultTz).trim();
    if (T.offsetMinutes(defaultTz) == null) {
      warnings.push('Time zone "' + defaultTz + '" is not recognised; times without a zone were read as UTC.');
      defaultTz = 'Z';
    }
    var nowGiven = T.resolveNow(c.now, { defaultTz: defaultTz });
    if (c.now != null && c.now !== '' && nowGiven == null) warnings.push('Current time "' + c.now + '" could not be read; using the latest time in the evidence.');
    var year = c.year ? Number(c.year) : null;
    if (year != null && !(year > 1970 && year < 3000)) year = null;
    if (year == null && nowGiven != null) year = new Date(nowGiven).getUTCFullYear();
    var deployedAt = null;
    if (c.deployedAt != null && c.deployedAt !== '') {
      deployedAt = T.resolveNow(c.deployedAt, { defaultTz: defaultTz });
      if (deployedAt == null) warnings.push('Deployed at "' + c.deployedAt + '" could not be read; ignored.');
    }
    return {
      defaultTz: defaultTz, nowGiven: nowGiven, year: year, deployedAt: deployedAt,
      cluster: c.cluster ? String(c.cluster).trim() : null, slo: c.slo || {}
    };
  }

  /*
   * The latest observed time (logs, traces, alerts), ignoring an isolated far-future stamp: one
   * line from a mis-set clock or a typo'd year (2030 for 2026) would otherwise become "now" and
   * turn a 20-minute incident into years of budget burn. A point is dropped only when it sits more
   * than 6 hours after the next one and the dropped points are at most 5 % of all stamped points.
   */
  function latestObserved(parsers, warnings, nowGiven) {
    var pts = [];
    parsers.forEach(function (r) {
      r.signals.forEach(function (s) {
        // Zone-less stamps (klog, syslog) are still observations; relative ages, carried-over and
        // unknown times are not.
        if (s.ts == null || (s.attrs && (s.attrs.relative || s.attrs.tsUnknown || s.attrs.tsCarried))) return;
        pts.push(s.ts);
      });
      // The logs parser reports its newest few line stamps (healthy info lines are not signals):
      // a dense tail of lines hours after the errors is real time passing, not an outlier.
      if (r.extras.latestTs && r.extras.latestTs.length) pts.push.apply(pts, r.extras.latestTs);
      else if (r.extras.maxTs != null) pts.push(r.extras.maxTs);
    });
    if (!pts.length) return null;
    pts.sort(function (a, b) { return b - a; });
    var limit = Math.max(1, Math.floor(pts.length * 0.05));
    var dropped = [];
    var i = 0;
    while (pts.length - i >= 3 && dropped.length < limit) {
      var top = pts[i];
      var j = i;
      while (j < pts.length && pts[j] === top) j++;          // the same stamp counted twice is one point
      if (j >= pts.length || top - pts[j] <= FUTURE_GAP_MS) break;
      if (dropped.length + (j - i) > limit) break;
      dropped.push(top);
      i = j;
    }
    if (dropped.length) {
      var list = WR.uniq(dropped).map(function (t) { return T.fmtDateTime(t); }).join(', ');
      // With a hand-set clock the outlier only matters as a likely clock or year typo in the paste;
      // telling the user to set a time they already set would be wrong.
      warnings.push(nowGiven == null
        ? 'Ignored ' + list + ' when choosing the current time: more than ' + WR.fmtDuration(FUTURE_GAP_MS) + ' after everything else. Set the current time if that is wrong.'
        : 'A time in the evidence (' + list + ') is more than ' + WR.fmtDuration(FUTURE_GAP_MS) + ' after everything else; it looks like a clock or year typo and was left out of the time checks.');
    }
    return pts[i];
  }

  /*
   * A database that clients in another cluster reach across clusters. Logs name the host
   * (orders-postgresql.data.prod-us-east…) from a prod-us-west pod; that cluster's traces name the
   * same database only by peer.service ("orders-postgresql"), which on its own would read as a
   * second, prod-us-west database. Fold such a trace-only datastore (namespace never stated, nothing
   * else of that name in its cluster) into the one the logs tie that cluster to.
   */
  function crossClusterStores(rec, alias, depHints) {
    var byId = {};
    rec.entities.forEach(function (e) { byId[e.id] = e; });
    var reach = {};
    depHints.forEach(function (hn) {
      var f = byId[E.canon(alias, hn.from)], t = byId[E.canon(alias, hn.to)];
      if (!f || !t || t.type !== 'datastore' || f.cluster === t.cluster) return;
      var k = f.cluster + '|' + t.name;
      reach[k] = reach[k] && reach[k] !== t.id ? '?' : t.id;
    });
    var moved = false;
    rec.entities.forEach(function (e) {
      if (e.type !== 'datastore' || e.nsKnown || (e.sources || []).some(function (s) { return s !== 'traces'; })) return;
      var to = reach[e.cluster + '|' + e.name];
      if (!to || to === '?' || to === e.id || !byId[to]) return;
      var sameCluster = rec.entities.some(function (x) { return x !== e && x.name === e.name && x.cluster === e.cluster; });
      if (sameCluster) return;
      alias[e.id] = to;
      Object.keys(alias).forEach(function (k) { if (alias[k] === e.id) alias[k] = to; });
      moved = true;
    });
    if (moved) rec.entities = rec.entities.filter(function (e) { return !alias[e.id]; });
  }

  function parserCtx(ctx, year) {
    return { now: ctx.nowGiven, defaultTz: ctx.defaultTz, year: year, cluster: ctx.cluster, deployedAt: ctx.deployedAt };
  }

  function runParser(fn, text, pctx, label, warnings) {
    if (!text || !text.trim()) return emptyParse();
    try {
      var r = fn(text, pctx);
      if (!r || !r.stats) return emptyParse('unrecognised');
      r.extras = r.extras || {};
      return r;
    } catch (e) {
      warnings.push(label + ' could not be read: ' + (e && e.message ? e.message : String(e)));
      return emptyParse('error');
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Wrong-pane check. Engineers paste fast; a Helm diff in the Traces tab is read by the trace
  // parser, found to be nothing, and the incident silently looks quiet. Each pane is sniffed for
  // strong markers of every format; markers are deliberately specific (a "traceId" field inside a
  // JSON log line is not a trace document) so a correctly placed paste never trips them.
  // ---------------------------------------------------------------------------------------------
  var PANE_NAMES = { logs: 'Logs & events', traces: 'Traces', alerts: 'Alerts', helm: 'Helm diff & history' };
  var PANE_WHAT = { logs: 'Kubernetes logs or events', traces: 'traces', alerts: 'alerts', helm: 'Helm output' };
  var MARKERS = {
    helm: [/^[ \t]*[\w.-]*,[ \t]*[\w.:@-]+,[ \t]*[A-Za-z]+[ \t]*\([^)\n]*\)[ \t]+(?:has changed|has been added|has been removed|changed ownership|to be (?:added|changed|removed))/m,
      /^[ \t]*REVISION[ \t]+UPDATED[ \t]+STATUS[ \t]+CHART/m, /^[ \t]*NAME[ \t]+NAMESPACE[ \t]+REVISION[ \t]+UPDATED[ \t]+STATUS[ \t]+CHART/m, /^diff --git a\//m],
    traces: [/"resourceSpans"\s*:|"resource_spans"\s*:|"scopeSpans"\s*:|"operationName"\s*:\s*"/, /^\S*\s*trace(?:_?id)?=\S+\s+span(?:_?id)?=\S+.*\bservice=/m],
    alerts: [/"alerts"\s*:\s*\[|"alertname"\s*:\s*"/, /^[ \t]*\[(?:FIRING|RESOLVED)(?::\s*\d+)?\][ \t]+[A-Za-z_]/m, /^[ \t]*ALERT[ \t]+[A-Za-z_:][\w:]*\{/m,
      /^[ \t]*Alertname[ \t]+Starts At[ \t]+Summary/m, /^\S+[ \t]+(?:FIRING|RESOLVED|PENDING)[ \t]+(?:critical|warning|info)[ \t]+[A-Za-z_]/m],
    logs: [/^[ \t]*(?:NAMESPACE[ \t]+)?LAST SEEN[ \t]+TYPE[ \t]+REASON/m, /^[ \t]*(?:NAMESPACE[ \t]+)?NAME[ \t]+READY[ \t]+STATUS[ \t]+RESTARTS/m,
      /^[IWEF]\d{4} \d{2}:\d{2}:\d{2}\.\d+\s+\d+ \S+:\d+\]/m, /"(?:level|severity|lvl)"\s*:\s*"(?:info|warn|warning|error|debug|fatal|INFO|WARN|WARNING|ERROR|DEBUG|FATAL)"/,
      /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\S*\s+(?:\[?(?:INFO|WARN|WARNING|ERROR|DEBUG|FATAL)\]?)\s/m, /^Name:\s+\S+\s*\n(?:.*\n){0,3}Namespace:\s+\S+/m]
  };
  function sniffPanes(texts, parsed) {
    var out = { warnings: [], misplaced: {} };
    var found = {};
    ['logs', 'traces', 'alerts', 'helm'].forEach(function (p) {
      var t = texts[p] && texts[p].length > 400000 ? texts[p].slice(0, 400000) : texts[p];
      found[p] = {};
      if (!t || !t.trim()) return;
      Object.keys(MARKERS).forEach(function (k) { if (MARKERS[k].some(function (re) { return re.test(t); })) found[p][k] = true; });
    });
    ['logs', 'traces', 'alerts', 'helm'].forEach(function (p) {
      var kinds = Object.keys(found[p]);
      if (!kinds.length || found[p][p]) {
        // Right pane, but holding a second format whose own pane is empty: that part goes unread.
        kinds.filter(function (k) { return k !== p && !(texts[k] || '').trim() && k !== 'logs'; }).forEach(function (k) {
          out.warnings.push('The ' + PANE_NAMES[p] + ' pane also holds ' + PANE_WHAT[k] + '; paste that part into ' + PANE_NAMES[k] + ' so it is read as ' + PANE_WHAT[k] + '.');
        });
        return;
      }
      // Wrong pane: the pane's own parser found little, and the text carries another format's markers.
      var own = parsed[p];
      if (own && own.signals && own.signals.length > 3 && own.stats && own.stats.skipped < own.stats.parsed) return;
      out.misplaced[p] = true;
      out.warnings.push('The ' + PANE_NAMES[p] + ' pane looks like ' + kinds.map(function (k) { return PANE_WHAT[k]; }).join(' and ') +
        ' — paste it into ' + kinds.map(function (k) { return PANE_NAMES[k]; }).join(' and ') + '.');
    });
    return out;
  }

  // ---------------------------------------------------------------------------------------------
  // Certificates named in the logs pane: cert-manager describe/get output and openssl output carry
  // the Not After time and renewal errors that the line parser does not turn into signals.
  // ---------------------------------------------------------------------------------------------
  function scanCerts(text, ctx, alertSignals) {
    var certs = {}, order = [];
    function get(name, ns, cluster, clusterKnown) {
      var k = name + '|' + (ns || '');
      if (!certs[k]) {
        certs[k] = { name: name, namespace: ns || null, cluster: cluster || null, clusterKnown: !!clusterKnown, notAfter: null, notAfterLine: null, failedAttempts: null, issuerError: null, issuer: null, componentId: null };
        order.push(k);
      }
      return certs[k];
    }
    var lines = WR.splitLines(text || '');
    var curNs = null, curCluster = ctx.cluster, curKnown = !!ctx.cluster, cur = null, issuerCol = null;
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i], m;
      var cmd = E.parseCommand(line);
      if (cmd) {
        curNs = cmd.namespace || null;
        if (cmd.context) { curCluster = cmd.context; curKnown = true; }
        cur = null; issuerCol = null;
        var p = cmd.positional;
        if (/^(describe|get)$/.test(cmd.verb) && p[1] && /^(certificates?|cert|certs)(\.cert-manager\.io)?$/i.test(p[1]) && p[2]) cur = get(p[2].toLowerCase(), curNs, curCluster, curKnown);
        else if (cmd.verb === 'get' && p[1] && /^secrets?$/i.test(p[1]) && p[2] && /openssl|tls\\?\.crt/.test(line)) cur = get(p[2].toLowerCase(), curNs, curCluster, curKnown);
        continue;
      }
      var mark = E.detectCluster(line);
      if (mark) { curCluster = mark; curKnown = true; continue; }
      if (/\bISSUER\b/.test(line) && /\bNAME\b/.test(line)) { issuerCol = line.indexOf('ISSUER'); continue; }
      if ((m = /^\s*certificate(?:\.cert-manager\.io)?\/([a-z0-9][a-z0-9.-]*)/i.exec(line))) { get(m[1].toLowerCase(), curNs, curCluster, curKnown); continue; }
      if ((m = /^\s*certificaterequest(?:\.cert-manager\.io)?\/([a-z0-9][a-z0-9.-]*)/i.exec(line))) {
        var base = m[1].toLowerCase().replace(/-\d+$/, '');
        var cr = get(base, curNs, curCluster, curKnown);
        if (issuerCol != null) { var iss = line.slice(issuerCol).trim().split(/\s+/)[0]; if (iss && /^[a-z0-9][\w.-]*$/i.test(iss)) cr.issuer = iss; }
        continue;
      }
      if (!cur) continue;
      if ((m = /^\s*Not After:\s+(\S+)/.exec(line))) {
        var na = T.parse(m[1], { defaultTz: 'Z' });
        if (na) { cur.notAfter = na.ts; cur.notAfterLine = i + 1; }
      } else if ((m = /^\s*notAfter=(\w{3})\s+(\d{1,2})\s+([\d:]+)\s+(\d{4})\s+(GMT|UTC)\s*$/.exec(line))) {
        // openssl prints "Oct  5 21:00:00 2026 GMT"; reorder into the UnixDate shape WR.time reads.
        var oa = T.parse(m[1] + ' ' + m[2] + ' ' + m[3] + ' ' + m[5] + ' ' + m[4], { defaultTz: 'Z' });
        if (oa && cur.notAfter == null) { cur.notAfter = oa.ts; cur.notAfterLine = i + 1; }
      } else if ((m = /^\s*Failed Issuance Attempts:\s+(\d+)/.exec(line))) {
        cur.failedAttempts = Number(m[1]);
      } else if (!cur.issuerError && /(failed to (?:sign|issue|renew)|permission denied|Code: 40[13]|\bforbidden\b|\bunauthori[sz]ed\b)/i.test(line)) {
        cur.issuerError = { line: i + 1, text: compactIssuerError(line) };
      } else if ((m = /^\s*Message:\s+Certificate expired on (.+)$/.exec(line)) && cur.notAfter == null) {
        var ce = T.parse(m[1].replace(/\s+UTC$/, ' +0000'), { defaultTz: 'Z' });
        if (ce) { cur.notAfter = ce.ts; cur.notAfterLine = i + 1; }
      }
    }
    // Certificate alerts from cert-manager metrics name the Certificate too.
    (alertSignals || []).forEach(function (s) {
      var L = s.attrs && s.attrs.labels;
      if (!L || !L.name || !/Cert/i.test(s.attrs.alertname || '')) return;
      var c = get(String(L.name).toLowerCase(), L.exported_namespace || L.namespace || null, L.cluster || ctx.cluster, !!(L.cluster || ctx.cluster));
      if (!c.namespace) c.namespace = L.exported_namespace || L.namespace || null;
    });
    return order.map(function (k) { return certs[k]; });
  }

  // "…: Vault failed to sign certificate: Error making API request. URL: PUT https://… Code: 403.
  // Errors: * permission denied" → "Vault failed to sign certificate: Code: 403. Errors: permission
  // denied": the part an engineer acts on, without the request URL.
  function compactIssuerError(line) {
    var t = String(line).replace(/^\s*Message:\s*/, '').replace(/\s+/g, ' ').trim();
    t = t.replace(/Error making API request\.?\s*/i, '').replace(/URL: \S+ \S+\s*/i, '').replace(/\*\s*/g, '');
    var m = /(Vault|issuer|ACME|failed to (?:sign|issue|renew))/i.exec(t);
    if (m && m.index > 0) t = t.slice(m.index);
    return t;
  }

  // ---------------------------------------------------------------------------------------------
  // Deploy time from ReplicaSet hand-offs: a new ReplicaSet scaling up while an older one of the
  // same workload scales down is a rollout; a plain scale-up is just the autoscaler.
  // ---------------------------------------------------------------------------------------------
  function detectHandoffs(signals) {
    var byComp = {};
    signals.forEach(function (s) {
      if (s.kind !== 'rollout' || !s.componentId || !s.attrs || !s.attrs.replicaSet) return;
      (byComp[s.componentId] || (byComp[s.componentId] = [])).push(s);
    });
    var out = [];
    Object.keys(byComp).forEach(function (id) {
      var list = byComp[id];
      var up = {}, down = {};
      list.forEach(function (s) { if (s.attrs.direction === 'down') down[s.attrs.replicaSet] = true; else up[s.attrs.replicaSet] = true; });
      var fresh = Object.keys(up).filter(function (rs) { return !down[rs]; });
      if (!fresh.length || !Object.keys(down).length) return;
      var first = null;
      list.forEach(function (s) {
        if (fresh.indexOf(s.attrs.replicaSet) < 0 || s.ts == null || unknownTs(s)) return;
        if (!first || s.ts < first.ts) first = s;
      });
      if (first) out.push({ componentId: id, replicaSet: first.attrs.replicaSet, previous: Object.keys(down), ts: first.ts, signalId: first.id, signal: first });
    });
    return out;
  }

  // ---------------------------------------------------------------------------------------------
  // Main
  // ---------------------------------------------------------------------------------------------
  function analyze(input) {
    var warnings = [];
    try {
      return run(input || {}, warnings);
    } catch (e) {
      warnings.push('Analysis stopped early: ' + (e && e.message ? e.message : String(e)));
      return skeleton(input || {}, warnings);
    }
  }

  // A complete, empty Analysis: the fallback when something unexpected throws.
  function skeleton(input, warnings) {
    var b = null;
    try { b = WR.budget((input.context || {}).slo, {}); } catch (e) { b = null; }
    return {
      version: 1, generatedAt: typeof input.generatedAt === 'number' ? input.generatedAt : Date.now(),
      inputsPresent: { logs: !!str(input.logs).trim(), traces: !!str(input.traces).trim(), alerts: !!str(input.alerts).trim(), helm: !!str(input.helm).trim() },
      stats: { logs: WR.newStats('empty'), traces: WR.newStats('empty'), alerts: WR.newStats('empty'), helm: WR.newStats('empty') },
      window: { start: null, end: null, firstAnomaly: null, now: null },
      headline: 'The analysis could not finish; see the warnings.', severity: 'SEV4',
      clusters: [], components: [], edges: [], signals: [], changes: [], deploy: null, deploys: [], timeline: [],
      hypotheses: [], rollbacks: [], budget: b,
      traits: { clusterCount: 0, clusters: [], multiCluster: false, failingClusterCount: 0, highCardinalityLabels: [], logLinesPerMin: 0, signalsPerMin: 0, spanCount: 0, tracedServices: 0, untracedFailingComponents: [], errorTracesMissing: false, sources: { logs: false, traces: false, alerts: false, helm: false }, hasDeployTime: false },
      warnings: warnings
    };
  }

  function run(input, warnings) {
    var texts = { logs: str(input.logs), traces: str(input.traces), alerts: str(input.alerts), helm: str(input.helm) };
    var inputsPresent = { logs: !!texts.logs.trim(), traces: !!texts.traces.trim(), alerts: !!texts.alerts.trim(), helm: !!texts.helm.trim() };
    var anyInput = inputsPresent.logs || inputsPresent.traces || inputsPresent.alerts || inputsPresent.helm;
    var ctx = normContext(input.context, warnings);

    // ---- 2. parse ------------------------------------------------------------------------------
    var pc = parserCtx(ctx, ctx.year);
    var A = runParser(WR.parseAlerts, texts.alerts, pc, 'Alerts', warnings);
    var Tr = runParser(WR.parseTraces, texts.traces, pc, 'Traces', warnings);
    var Hm = runParser(WR.parseHelm, texts.helm, pc, 'Helm output', warnings);
    var year = ctx.year;
    if (year == null) {
      var hint = Math.max(A.extras.maxTs || -Infinity, Tr.extras.maxTs || -Infinity, Hm.extras.maxTs || -Infinity);
      if (isFinite(hint)) year = new Date(hint).getUTCFullYear();
    }
    var lpc = parserCtx(ctx, year);
    lpc.knownClusters = WR.uniq([].concat(A.extras.clusters || [], Tr.extras.clusters || [], Hm.extras.clusters || []).filter(Boolean));
    var L = runParser(WR.parseLogs, texts.logs, lpc, 'Logs', warnings);
    var parsed = { logs: L, traces: Tr, alerts: A, helm: Hm };
    var sniff = { warnings: [], misplaced: {} };
    try { sniff = sniffPanes(texts, parsed); } catch (e) { sniff = { warnings: [], misplaced: {} }; }

    // ---- 3. clock ------------------------------------------------------------------------------
    // "Now" is the latest observation (logs, traces, alerts). Helm times are when changes were made,
    // and zone-less helm history is the stamp most often read in the wrong zone, so it only sets
    // the clock when nothing else carries a time.
    var maxTs = latestObserved([L, Tr, A], warnings, ctx.nowGiven);
    if (maxTs == null) maxTs = Hm.extras.maxTs != null ? Hm.extras.maxTs : null;
    var now = ctx.nowGiven != null ? ctx.nowGiven : maxTs;
    if (ctx.nowGiven == null && now != null && anyInput) warnings.push('Current time not set; using the latest time in the evidence (' + T.fmtDateTime(now) + ').');
    if (ctx.nowGiven != null && maxTs != null) {
      // A clock set far from the evidence silently changes every duration and the budget.
      if (ctx.nowGiven - maxTs > NOW_DRIFT_MS) warnings.push('The current time you set (' + T.fmtDateTime(ctx.nowGiven) + ') is ' + WR.fmtDuration(ctx.nowGiven - maxTs) + ' after the latest evidence (' + T.fmtDateTime(maxTs) + '); the error budget assumes errors continued all that time.');
      else if (maxTs - ctx.nowGiven > 5 * MIN) warnings.push('Some evidence (up to ' + T.fmtDateTime(maxTs) + ') is later than the current time you set (' + T.fmtDateTime(ctx.nowGiven) + ').');
    }
    if (now != null && Hm.extras.maxTs != null && Hm.extras.maxTs > now + 5 * MIN) {
      warnings.push('Helm times are later than everything else (' + T.fmtDateTime(Hm.extras.maxTs) + ' vs ' + T.fmtDateTime(now) + '). Helm history has no time zone: check "Zone for times without one".');
    }
    var all = [].concat(L.signals, Tr.signals, A.signals, Hm.signals);
    if (now != null) T.rebase(all, now);

    // ---- 4. entities -----------------------------------------------------------------------------
    var rec = E.reconcile([].concat(L.entities, Tr.entities, A.entities, Hm.entities));
    var alias = rec.alias;
    crossClusterStores(rec, alias, L.extras.dependencyHints || []);
    E.remap(all, alias);
    var changes = (Hm.extras.changes || []).map(function (c) { return Object.assign({}, c); });
    E.remap(changes, alias);
    var deploys = (Hm.extras.deploys || []).map(function (d) { return Object.assign({}, d); });
    E.remap(deploys, alias);
    var counts = {};
    Object.keys(L.extras.componentCounts || {}).forEach(function (id) {
      var k = E.canon(alias, id), src = L.extras.componentCounts[id];
      var t = counts[k] || (counts[k] = { error: 0, warn: 0, info: 0 });
      t.error += src.error; t.warn += src.warn; t.info += src.info;
    });
    var burn = A.extras.burn ? Object.assign({}, A.extras.burn, { componentId: E.canon(alias, A.extras.burn.componentId) }) : null;

    var comps = {};
    function mkComp(e) {
      return {
        id: e.id, name: e.name, type: e.type, role: e.role || null, cluster: e.cluster, namespace: e.namespace,
        clusterKnown: !!e.clusterKnown, nsKnown: !!e.nsKnown, userFacing: !!e.userFacing,
        pods: (e.pods || []).slice(0, 50), release: e.release || null, controller: e.controller || null, _sources: (e.sources || []).slice(),
        status: 'healthy', impact: 0, firstErrorTs: null, lastErrorTs: null, firstErrorSignalId: null, statusSince: null,
        counts: { error: 0, warn: 0, info: 0 }, kinds: [], changeIds: [], deepest: false,
        _err: 0, _warn: 0, _nodeSoft: 0, _firstWarnTs: null, _kindCount: {}
      };
    }
    rec.entities.forEach(function (e) { comps[e.id] = mkComp(e); });
    function ensure(id) {
      if (!id || comps[id]) return comps[id] || null;
      var p = E.parseId(id);
      if (!p) return null;
      comps[id] = mkComp({ id: id, name: p.name, type: p.type, cluster: p.cluster, namespace: p.namespace, clusterKnown: !!ctx.cluster, nsKnown: true });
      return comps[id];
    }

    // Node-level OOM-killer lines name the process that was killed; that workload is the patient.
    all.forEach(function (s) {
      if (s.kind !== 'oom_killed' || !s.componentId || s.componentId.indexOf('node:') !== 0) return;
      // "kernel: coredns invoked oom-killer" and "Memory cgroup out of memory: Killed process N (coredns)"
      // are a container hitting its own memory limit, not node pressure.
      var m = /Killed process \d+ \(([^)]+)\)|(?:^|[\s:])([a-z0-9][\w.-]*) invoked oom-killer|task=([^,\s]+)/i.exec(s.text || s.raw || '') ||
        /Killed process \d+ \(([^)]+)\)|\b([a-z0-9][\w.-]*) invoked oom-killer|task=([^,\s]+)/i.exec(s.raw || '');
      var proc = m ? (m[1] || m[2] || m[3] || '').toLowerCase() : '';
      if (!proc) return;
      var node = E.parseId(s.componentId);
      var cands = Object.keys(comps).filter(function (id) { var c = comps[id]; return c.type !== 'node' && c.name === proc && c.cluster === node.cluster; });
      if (cands.length !== 1) return;
      s.attrs.node = node.name;
      s.attrs.reattributedFromNode = true;
      if (counts[s.componentId] && counts[s.componentId].error > 0) counts[s.componentId].error--;
      (counts[cands[0]] || (counts[cands[0]] = { error: 0, warn: 0, info: 0 })).error++;
      s.componentId = cands[0];
    });

    all.forEach(function (s) { ensure(s.componentId); if (s.attrs && s.attrs.targetId) ensure(s.attrs.targetId); });
    // A span that failed on a name lookup names cluster DNS as a party, exactly as a log line
    // saying "lookup … on 10.96.0.10:53: i/o timeout" does (the log parser adds CoreDNS for those),
    // so a traces-only paste can still point at CoreDNS.
    Tr.signals.forEach(function (s) {
      if (s.kind !== 'span_error' || !s.attrs || s.attrs.causeKind !== 'dns_failure' || !s.componentId) return;
      var caller = comps[s.componentId];
      if (!caller || caller.type === 'node') return;
      var dnsId = E.componentId('infra', caller.cluster, 'kube-system', 'coredns');
      if (!comps[dnsId]) { ensure(dnsId); comps[dnsId].clusterKnown = caller.clusterKnown; comps[dnsId].role = null; }
    });
    changes.forEach(function (c) { ensure(c.componentId); });
    deploys.forEach(function (d) { ensure(d.componentId); });

    // ---- 5. edges --------------------------------------------------------------------------------
    var traceEdges = E.mergeEdges(E.remap((Tr.extras.edges || []).map(function (e) { return Object.assign({}, e); }), alias));
    // Client spans that failed because the callee's name did not resolve never reached the callee.
    // Count them per edge so such an edge does not mark its callee failing.
    var dnsCaused = {}, clientErrs = {};
    Tr.signals.forEach(function (s) {
      if (s.kind !== 'span_error' || !s.attrs || !s.attrs.targetId) return;
      var k = s.componentId + '->' + s.attrs.targetId;
      clientErrs[k] = (clientErrs[k] || 0) + 1;
      if (s.attrs.causeKind === 'dns_failure') dnsCaused[k] = (dnsCaused[k] || 0) + 1;
    });
    var edgeMap = {}, edges = [];
    traceEdges.forEach(function (e) {
      if (!ensure(e.from) || !ensure(e.to)) return;
      var id = e.from + '->' + e.to;
      var x = { id: id, from: e.from, to: e.to, calls: e.calls, errors: e.errors, errorRate: e.calls > 0 ? e.errors / e.calls : null, p95ms: e.p95ms, status: 'ok', firstErrorTs: e.firstErrorTs, source: 'traces', _logErrors: 0,
        _dnsOnly: e.errors > 0 && dnsCaused[id] > 0 && dnsCaused[id] >= e.errors };
      edgeMap[x.id] = x; edges.push(x);
    });
    (L.extras.dependencyHints || []).forEach(function (hn) {
      var from = E.canon(alias, hn.from), to = E.canon(alias, hn.to);
      if (!from || !to || from === to) return;
      var fc = ensure(from), tc = ensure(to);
      if (!fc || !tc) return;
      // A failed lookup of a name says nothing about that target's health: keep only the edge to
      // cluster DNS. An ingress logging a 5xx for the public Host header is not a dependency.
      var isDns = tc.type === 'infra' && tc.name === 'coredns';
      if (!isDns && hn.kinds.every(function (k) { return k === 'dns_failure'; })) return;
      if (fc.role === 'ingress' && tc.type === 'external') return;
      var id = from + '->' + to;
      var x = edgeMap[id];
      if (x && x.source !== 'logs') { x.source = 'both'; x._logErrors += hn.count; return; }
      if (!x) {
        x = edgeMap[id] = { id: id, from: from, to: to, calls: 0, errors: 0, errorRate: null, p95ms: null, status: 'degraded', firstErrorTs: null, source: 'logs', _logErrors: 0 };
        edges.push(x);
      }
      x.calls += hn.count; x.errors += hn.count; x._logErrors += hn.count;
      if (hn.firstTs != null && (x.firstErrorTs == null || hn.firstTs < x.firstErrorTs)) x.firstErrorTs = hn.firstTs;
    });

    // ingress-nginx upstream names ("shop-frontend" = namespace shop, service frontend): the edge from
    // the ingress to the service it proxies, with the share of 5xx responses from the access log.
    Object.keys(L.extras.upstreams || {}).forEach(function (k) {
      var u = L.extras.upstreams[k];
      var from = E.canon(alias, u.from), fc = comps[from];
      if (!fc) return;
      var parts = u.token.split('-'), hits = [];
      for (var i = 1; i < parts.length; i++) {
        var ns = parts.slice(0, i).join('-'), svc = parts.slice(i).join('-');
        Object.keys(comps).forEach(function (id) {
          var c = comps[id];
          if (c.name === svc && c.namespace === ns && c.cluster === fc.cluster && c.id !== from && (c.type === 'service' || c.type === 'datastore')) hits.push(c.id);
        });
      }
      hits = WR.uniq(hits);
      if (hits.length !== 1) return;
      var id = from + '->' + hits[0];
      var x = edgeMap[id];
      if (!x) {
        x = edgeMap[id] = { id: id, from: from, to: hits[0], calls: 0, errors: 0, errorRate: null, p95ms: null, status: 'ok', firstErrorTs: null, source: 'logs', _logErrors: 0, _access: true };
        edges.push(x);
      }
      if (x.source !== 'logs') x.source = 'both';
      x.calls += u.calls; x.errors += u.errors; x._logErrors += u.errors;
      x.errorRate = x.calls > 0 ? x.errors / x.calls : null;
      if (u.firstErrorTs != null && (x.firstErrorTs == null || u.firstErrorTs < x.firstErrorTs)) x.firstErrorTs = u.firstErrorTs;
    });
    // An ingress that drew a log edge to the service it proxies now has a real callee; its old
    // "error to the public host" guess is gone with the external target above.

    // ---- 6. window ---------------------------------------------------------------------------------
    var errTimes = all.filter(function (s) { return isError(s) && s.ts != null && !unknownTs(s); }).map(function (s) { return s.ts; }).sort(function (a, b) { return a - b; });
    var droppedOutliers = 0;
    while (errTimes.length >= 3 && errTimes[1] - errTimes[0] > OUTLIER_GAP_MS) { errTimes.shift(); droppedOutliers++; }
    var firstAnomaly = errTimes.length ? errTimes[0] : null;
    if (firstAnomaly == null) {
      var warnTimes = all.filter(function (s) { return isWarn(s) && s.ts != null && !unknownTs(s); }).map(function (s) { return s.ts; });
      if (warnTimes.length) firstAnomaly = Math.min.apply(null, warnTimes);
    }
    if (firstAnomaly == null && errTimes.length === 0) {
      // Only errors pinned to "now" (no timestamps at all): the incident is happening now.
      var pinned = all.filter(function (s) { return isError(s) && s.ts != null; });
      if (pinned.length) firstAnomaly = Math.min.apply(null, pinned.map(function (s) { return s.ts; }));
    }
    if (droppedOutliers) warnings.push('Ignored ' + droppedOutliers + ' error' + (droppedOutliers === 1 ? '' : 's') + ' more than an hour before the rest when finding the first anomaly.');
    if (firstAnomaly != null && now != null && firstAnomaly > now && !warnings.some(function (w) { return /later than the current time/.test(w); })) warnings.push('Some evidence is later than the current time you set.');
    var minTs = null;
    all.forEach(function (s) { if (s.ts != null && !unknownTs(s) && (minTs == null || s.ts < minTs)) minTs = s.ts; });
    var win = {
      start: firstAnomaly != null ? firstAnomaly - LEAD_MS : minTs,
      end: now,
      firstAnomaly: firstAnomaly,
      now: now
    };
    function inWindow(s) { return win.start == null || s.ts == null || s.ts >= win.start; }

    // ---- 7. per-component facts and statuses ---------------------------------------------------------
    var sigsByComp = {};
    all.forEach(function (s) {
      var c = s.componentId ? comps[s.componentId] : null;
      if (!c) return;
      (sigsByComp[c.id] || (sigsByComp[c.id] = [])).push(s);
      c._kindCount[s.kind] = (c._kindCount[s.kind] || 0) + 1;
      if (s.attrs && s.attrs.pod && c.pods.indexOf(s.attrs.pod) < 0 && c.pods.length < 50 && c.type !== 'node') c.pods.push(s.attrs.pod);
      if (s.source !== 'logs') {
        var sev = WR.sevRank(s.severity);
        if (sev >= 2) c.counts.error++; else if (sev === 1) c.counts.warn++; else c.counts.info++;
      }
      if (isError(s)) {
        var hardNode = c.type !== 'node' || NODE_FAIL_KINDS[s.kind];
        if (inWindow(s)) { if (hardNode) c._err++; else c._nodeSoft++; }
        if (hardNode && s.ts != null && (c.lastErrorTs == null || s.ts > c.lastErrorTs)) c.lastErrorTs = s.ts;
      } else if (isWarn(s) && inWindow(s)) {
        c._warn++;
        if (s.ts != null && (c._firstWarnTs == null || s.ts < c._firstWarnTs)) c._firstWarnTs = s.ts;
      }
    });
    var sigById = {};
    all.forEach(function (s) { sigById[s.id] = s; });
    // First error per component: a real time beats one pinned to "now" (a pod table read at paste
    // time), otherwise the earliest wins. Node components only count node conditions here.
    Object.keys(sigsByComp).forEach(function (id) {
      var c = comps[id];
      var best = null;
      sigsByComp[id].forEach(function (s) {
        if (!isError(s) || s.ts == null || (c.type === 'node' && !NODE_FAIL_KINDS[s.kind])) return;
        if (!best) { best = s; return; }
        var bu = unknownTs(best), su = unknownTs(s);
        if ((bu && !su) || (bu === su && s.ts < best.ts)) best = s;
      });
      c.firstErrorTs = best ? best.ts : null;
      c.firstErrorSignalId = best ? best.id : null;
      sigsByComp[id].sort(function (a, b) { return (a.ts == null ? Infinity : a.ts) - (b.ts == null ? Infinity : b.ts); });
    });
    Object.keys(counts).forEach(function (id) {
      var c = ensure(id);
      if (!c) return;
      c.counts.error += counts[id].error; c.counts.warn += counts[id].warn; c.counts.info += counts[id].info;
    });
    if (burn && burn.componentId && comps[burn.componentId]) comps[burn.componentId].userFacing = true;
    all.forEach(function (s) { if (s.kind === 'slo_burn' && s.componentId && comps[s.componentId]) comps[s.componentId].userFacing = true; });
    Object.keys(comps).forEach(function (id) { if (comps[id].role === 'ingress') comps[id].userFacing = true; });

    var edgesFrom = {}, edgesTo = {};
    edges.forEach(function (e) {
      (edgesFrom[e.from] || (edgesFrom[e.from] = [])).push(e);
      (edgesTo[e.to] || (edgesTo[e.to] = [])).push(e);
    });

    var failing = {};
    Object.keys(comps).forEach(function (id) { if (comps[id]._err > 0) failing[id] = true; });
    edges.forEach(function (e) {
      // Calls into a component failing at ≥ 20 % make it failing (trace edges only: log-derived
      // edges have no call totals, so their "rate" would always be 100 %).
      if (e.source !== 'logs' && e.errorRate != null && e.errorRate >= 0.2 && !e._dnsOnly) failing[e.to] = true;
    });
    Object.keys(comps).forEach(function (id) {
      var c = comps[id];
      if (failing[id]) { c.status = 'failing'; return; }
      var callsIntoFailing = (edgesFrom[id] || []).some(function (e) {
        return failing[e.to] && (e.source === 'logs' ? e.errors > 0 : (e.errorRate || 0) >= 0.02 || e._logErrors > 0);
      });
      if (c._warn > 0 || c._nodeSoft > 0 || callsIntoFailing) c.status = 'degraded';
    });
    Object.keys(comps).forEach(function (id) {
      var c = comps[id];
      if (c.status !== 'healthy') return;
      // At risk: calls a failing component directly or through one more hop.
      var hop1 = (edgesFrom[id] || []).map(function (e) { return e.to; });
      var reach = hop1.some(function (t) { return failing[t]; }) || hop1.some(function (t) { return (edgesFrom[t] || []).some(function (e) { return failing[e.to]; }); });
      if (reach) c.status = 'at-risk';
    });
    edges.forEach(function (e) {
      if (e.source === 'logs' && e._access && !e.errors) e.status = 'ok';
      else if (e.source === 'logs') e.status = failing[e.to] ? 'failing' : 'degraded';
      else if (e.errorRate != null && e.errorRate >= 0.2) e.status = 'failing';
      else if ((e.errorRate != null && e.errorRate >= 0.02) || e._logErrors > 0) e.status = 'degraded';
      else e.status = 'ok';
    });
    Object.keys(comps).forEach(function (id) {
      var c = comps[id];
      if (!failing[id]) return;
      var inFail = (edgesTo[id] || []).some(function (e) { return e.status === 'failing' && !e._dnsOnly; });
      var outFail = (edgesFrom[id] || []).some(function (e) { return failing[e.to]; });
      c.deepest = inFail && !outFail;
    });

    // ---- 8. deploy time -------------------------------------------------------------------------------
    var handoffs = detectHandoffs(all);
    var rolloutsByComp = {};
    handoffs.forEach(function (ho) { (rolloutsByComp[ho.componentId] || (rolloutsByComp[ho.componentId] = [])).push(ho.signal); });
    deploys.forEach(function (d) {
      var sig = Hm.signals.filter(function (s) { return s.attrs && s.attrs.isDeploy && s.attrs.release === d.release && s.attrs.revision === d.revision; })[0];
      d.signalId = sig ? sig.id : null;
    });
    var rolloutTimeUsed = false;
    deploys.forEach(function (d) {
      if (d.deployedAt != null || !d.componentId) return;
      var ho = handoffs.filter(function (x) { return x.componentId === d.componentId; })[0];
      if (!ho) return;
      d.deployedAt = ho.ts; d.deployedAtSource = 'rollout-event'; d.tsInferred = true; d.replicaSet = ho.replicaSet; d.signalId = d.signalId || ho.signalId;
      rolloutTimeUsed = true;
      warnings.push('No Helm history time for ' + (d.release || 'the release') + '; deploy time taken from the ' + ho.replicaSet + ' rollout (about ' + T.fmt(ho.ts) + ' UTC). Paste `helm history` for the exact time.');
    });
    if (!deploys.length && handoffs.length) {
      handoffs.forEach(function (ho) {
        var c = comps[ho.componentId];
        deploys.push({
          release: c && c.release ? c.release : null, namespace: c ? c.namespace : null, revision: null, previousRevision: null,
          chartFrom: null, chartTo: null, appFrom: null, appTo: null, deployedAt: ho.ts, deployedAtSource: 'rollout-event', tsInferred: true,
          cluster: c ? c.cluster : null, clusterKnown: c ? c.clusterKnown : false, status: 'rolled-out', line: ho.signal.line,
          componentId: ho.componentId, replicaSet: ho.replicaSet, previousReplicaSets: ho.previous, signalId: ho.signalId, changeCount: 0
        });
        rolloutTimeUsed = true;
        warnings.push('No Helm history pasted; deploy time for ' + (c ? c.name : 'the workload') + ' taken from its ReplicaSet rollout (' + ho.replicaSet + ', about ' + T.fmt(ho.ts) + ' UTC). Paste `helm history` for the release and revisions.');
      });
    }
    if (changes.length && !deploys.some(function (d) { return d.deployedAt != null; })) {
      warnings.push('No deploy time found — paste `helm history <release>` or set Deployed at, so changes can be lined up with the first errors.');
    }
    deploys.sort(function (a, b) { return (b.deployedAt == null ? -Infinity : b.deployedAt) - (a.deployedAt == null ? -Infinity : a.deployedAt) || (b.changeCount || 0) - (a.changeCount || 0); });
    var deploy = deploys[0] || null;
    // A rollback in the pasted history either stopped the errors or it did not; say which, because
    // it decides whether the release is still the suspect.
    deploys.forEach(function (d) {
      if (!d.rolledBack || d.rolledBack.at == null) return;
      var settle = d.rolledBack.at + 2 * MIN;   // pods need a moment to roll back
      var scope = all.filter(function (s) {
        if (!isError(s) || s.ts == null || unknownTs(s) || s.source === 'helm') return false;
        var c = s.componentId ? comps[s.componentId] : null;
        return !d.componentId || s.componentId === d.componentId || (c && d.release && c.release === d.release);
      });
      var later = scope.filter(function (s) { return s.ts > settle; });
      var when = T.fmt(d.rolledBack.at) + ' UTC (r' + d.rolledBack.revision + ' → r' + d.rolledBack.to + ')';
      if (later.length) {
        warnings.push('Errors continued after the rollback of ' + (d.release || 'the release') + ' at ' + when + ': ' + plural(later.length, 'error') +
          ', the last at ' + T.fmt(Math.max.apply(null, later.map(function (s) { return s.ts; }))) + ' UTC. The release may not be the whole cause, or its pods have not recovered yet.');
      } else if (scope.length) {
        warnings.push('No errors after the rollback of ' + (d.release || 'the release') + ' at ' + when + ': the rollback appears to have stopped them.');
      }
    });
    var changesByComp = {};
    changes.forEach(function (c) {
      if (!c.componentId) return;
      (changesByComp[c.componentId] || (changesByComp[c.componentId] = [])).push(c);
      if (comps[c.componentId]) comps[c.componentId].changeIds.push(c.id);
    });
    deploys.forEach(function (d) { if (d.componentId && d.release && comps[d.componentId] && !comps[d.componentId].release) comps[d.componentId].release = d.release; });

    var compList = Object.keys(comps).map(function (id) { return comps[id]; });
    compList.sort(function (a, b) { return a.id < b.id ? -1 : a.id > b.id ? 1 : 0; });

    // ---- 9. hypotheses, root, budget, rollbacks ----------------------------------------------------------
    var facts = { certs: [] };
    try {
      facts.certs = scanCerts(texts.logs, ctx, A.signals).map(function (c) {
        var base = c.name.replace(/-(m?tls|cert|certificate|tls-cert)$/i, '');
        var match = compList.filter(function (x) { return x.name === base && (!c.namespace || x.namespace === c.namespace) && x.type !== 'node'; });
        if (match.length) c.componentId = match[0].id;
        return c;
      });
    } catch (e) { warnings.push('Certificate details could not be read: ' + (e && e.message ? e.message : e)); }

    var hctx = {
      comps: comps, compList: compList, sigsByComp: sigsByComp, signals: all, sigById: sigById,
      edges: edges, edgesFrom: edgesFrom, edgesTo: edgesTo, changes: changes, changesByComp: changesByComp,
      deploys: deploys, helmSiblings: Hm.extras.siblings || [], rolloutsByComp: rolloutsByComp, firstAnomaly: firstAnomaly, now: now, window: win,
      facts: facts, isError: isError, warn: function (m) { warnings.push(m); }
    };
    var hyps = [];
    try { hyps = WR.hypotheses(hctx); } catch (e) { warnings.push('Root-cause rules failed: ' + (e && e.message ? e.message : e)); hyps = []; }
    var top = hyps[0] || null;
    if (top && top.confidence >= 0.35 && comps[top.componentId]) comps[top.componentId].status = 'root';

    // Impact: status sets the band; errors (relative to the noisiest component) and being in the
    // users' path move it within the band. Healthy is always 0.
    var maxErr = compList.reduce(function (m, c) { return Math.max(m, c.counts.error); }, 0) || 1;
    compList.forEach(function (c) {
      if (c.status === 'healthy') { c.impact = 0; return; }
      var v = STATUS_IMPACT[c.status] + (c.userFacing ? 0.05 : 0) + 0.05 * (c.counts.error / maxErr);
      c.impact = Math.round(WR.clamp(v, 0, 1) * 100) / 100;
    });
    // When each component entered its status (drives the map's propagation replay).
    compList.forEach(function (c) {
      if (c.status === 'root' || c.status === 'failing') {
        var viaEdge = (edgesTo[c.id] || []).filter(function (e) { return e.status === 'failing' && e.firstErrorTs != null; }).map(function (e) { return e.firstErrorTs; });
        c.statusSince = c.firstErrorTs != null ? c.firstErrorTs : (viaEdge.length ? Math.min.apply(null, viaEdge) : null);
      } else if (c.status === 'degraded') {
        var ts = [c._firstWarnTs].concat((edgesFrom[c.id] || []).filter(function (e) { return failing[e.to]; }).map(function (e) { return e.firstErrorTs; }));
        if (c._nodeSoft) (sigsByComp[c.id] || []).forEach(function (s) { if (isError(s)) ts.push(s.ts); });
        ts = ts.filter(function (x) { return x != null; });
        c.statusSince = ts.length ? Math.min.apply(null, ts) : null;
      }
    });
    compList.forEach(function (c) {
      if (c.status !== 'at-risk') return;
      var ts = [];
      (edgesFrom[c.id] || []).forEach(function (e) {
        [e.to].concat((edgesFrom[e.to] || []).map(function (x) { return x.to; })).forEach(function (t) { if (failing[t] && comps[t].statusSince != null) ts.push(comps[t].statusSince); });
      });
      c.statusSince = ts.length ? Math.min.apply(null, ts) : null;
    });

    var clusterNames = WR.uniq(compList.map(function (c) { return c.cluster; }));
    var clusters = clusterNames.map(function (name) {
      var cs = compList.filter(function (c) { return c.cluster === name; });
      var f = cs.filter(function (c) { return c.status === 'root' || c.status === 'failing'; }).length;
      var d = cs.filter(function (c) { return c.status === 'degraded'; }).length;
      return { name: name, componentCount: cs.length, failing: f, degraded: d, status: f ? 'failing' : d ? 'degraded' : 'healthy' };
    }).sort(function (a, b) { return STATUS_RANK[a.status] - STATUS_RANK[b.status] || (a.name < b.name ? -1 : 1); });

    var slo = WR.budget.normalizeSlo(ctx.slo);
    var er = WR.budget.resolveErrorRatio(slo, { alertBurn: burn, traceStats: Tr.extras.traceStats || null, requests: L.extras.requests || null });
    // A burn-rate alert that is FIRING in the paste is observed fact: the budget rows show it as firing
    // even when the steady-burn model says the long window could not have filled yet.
    var observedBurn = null;
    if (burn && burn.status === 'firing') {
      var ob = burn.maxBurnRate != null ? burn.maxBurnRate : (burn.errorRatio != null ? burn.errorRatio / (1 - slo.target) : null);
      if (ob != null && isFinite(ob) && ob > 0) observedBurn = { burnRate: ob, alertname: burn.alertname, signalId: burn.signalId, longWindowMinutes: burn.longWindowMinutes != null ? burn.longWindowMinutes : null };
    }
    // The change the top cause rests on, or the deploy: errors cannot have started before it.
    var changeAt = deploy && deploy.deployedAt != null ? deploy.deployedAt : null;
    var budget = WR.budget(ctx.slo, { errorRatio: er.errorRatio, errorRatioSource: er.source, note: er.note, firstAnomaly: firstAnomaly, now: now,
      observedBurn: observedBurn, hasEvidence: !!(anyInput && firstAnomaly != null), changeAt: changeAt });
    if (anyInput && (er.source === 'traces' || er.source === 'logs' || (er.source === 'default' && firstAnomaly != null))) warnings.push(er.note);
    slo.warnings.forEach(function (w) { warnings.push(w); });

    hctx.hypotheses = hyps;
    hctx.clusters = clusters;
    hctx.budget = budget;
    var rbs = [];
    try { rbs = WR.rollbacks(hctx); } catch (e) { warnings.push('Rollback options failed: ' + (e && e.message ? e.message : e)); rbs = []; }

    // ---- severity and headline ----------------------------------------------------------------------
    // SPEC: SEV1 = a user-facing component failing AND burn ≥ the 1-hour page threshold (14.4 on a
    // 30-day window, rescaled for others); SEV2 = user-facing degraded or burn ≥ the 6-hour page
    // threshold; SEV3 = failing but not user-facing; else SEV4. A burn rate resting on the 1 %
    // default is not evidence, so it never raises the severity on its own.
    var burnCounts = budget.errorRatioSource !== 'default';
    var page1 = budget.alertRows[0].burnThreshold, page2 = budget.alertRows[1].burnThreshold;
    var ufFailing = compList.some(function (c) { return c.userFacing && (c.status === 'root' || c.status === 'failing'); });
    var ufDegraded = compList.some(function (c) { return c.userFacing && (c.status === 'root' || c.status === 'failing' || c.status === 'degraded'); });
    var anyFailing = compList.some(function (c) { return c.status === 'root' || c.status === 'failing'; });
    var severity = ufFailing && burnCounts && budget.burnRate >= page1 ? 'SEV1'
      : ufDegraded || (burnCounts && budget.burnRate >= page2) ? 'SEV2'
        : anyFailing ? 'SEV3' : 'SEV4';

    var headline = makeHeadline(anyInput, top, comps, compList, changes, deploys, clusters);

    // ---- timeline: the first error (or warning) per component per kind, plus deploys ------------------
    var deploySigIds = {};
    deploys.forEach(function (d) { if (d.signalId) deploySigIds[d.signalId] = true; });
    var seen = {}, timeline = [];
    all.filter(function (s) { return s.ts != null && ((isAnomaly(s) && WR.sevRank(s.severity) >= 1) || deploySigIds[s.id]); })
      .sort(function (a, b) { return a.ts - b.ts || (SOURCE_ORDER[a.source] - SOURCE_ORDER[b.source]) || a.line - b.line; })
      .forEach(function (s) {
        var k = (s.componentId || '-') + '|' + s.kind + (deploySigIds[s.id] ? '|' + s.id : '');
        if (seen[k]) return;
        seen[k] = true;
        timeline.push({ ts: s.ts, componentId: s.componentId, kind: s.kind, severity: s.severity, signalId: s.id });
      });

    // ---- 10. cap the stored signals -------------------------------------------------------------------
    var outSignals = all;
    if (all.length > MAX_SIGNALS) {
      var keepIds = {};
      hyps.forEach(function (x) { x.evidence.forEach(function (e) { if (e.signalId) keepIds[e.signalId] = true; }); });
      timeline.forEach(function (t) { keepIds[t.signalId] = true; });
      deploys.forEach(function (d) { if (d.signalId) keepIds[d.signalId] = true; });
      compList.forEach(function (c) { if (c.firstErrorSignalId) keepIds[c.firstErrorSignalId] = true; });
      changes.forEach(function (c) { if (c.signalId && hyps.some(function (x) { return x.evidence.some(function (e) { return e.changeId === c.id; }); })) keepIds[c.signalId] = true; });
      // Deploys, rollbacks and high-risk changes always stay; routine change records (a CRD's
      // thousand description edits) compete for the remaining room like any other info line.
      var mustKeep = function (s) { return keepIds[s.id] || isError(s) || (s.kind === 'change' && (s.severity !== 'info' || (s.attrs && (s.attrs.isDeploy || s.attrs.isRollback)))); };
      var keep = all.filter(mustKeep);
      var rest = all.filter(function (s) { return !mustKeep(s); })
        .sort(function (a, b) { return WR.sevRank(b.severity) - WR.sevRank(a.severity) || (b.ts || 0) - (a.ts || 0); });
      outSignals = keep.concat(rest.slice(0, Math.max(0, MAX_SIGNALS - keep.length)));
      warnings.push('Kept ' + outSignals.length.toLocaleString('en-US') + ' of ' + all.length.toLocaleString('en-US') + ' signals: every error and high-risk change, then the newest warnings and info lines.');
    }
    if (outSignals !== all) {
      // A change whose signal was capped away keeps its line (the jump target) but no dangling id.
      var keptIds = {};
      outSignals.forEach(function (s) { keptIds[s.id] = true; });
      changes.forEach(function (c) { if (c.signalId && !keptIds[c.signalId]) c.signalId = null; });
    }
    outSignals = outSignals.slice().sort(function (a, b) {
      return (a.ts == null ? Infinity : a.ts) - (b.ts == null ? Infinity : b.ts) || SOURCE_ORDER[a.source] - SOURCE_ORDER[b.source] || a.line - b.line;
    });

    // Component kinds, most frequent first — failure kinds ahead of context kinds (change, rollout,
    // restart, resolved alerts), so nine Helm field changes never outrank one OOM kill on a chip row.
    var CONTEXT_KINDS = { change: 1, rollout: 1, restart: 1, alert_resolved: 1 };
    compList.forEach(function (c) {
      c.kinds = Object.keys(c._kindCount).sort(function (a, b) {
        return (CONTEXT_KINDS[a] ? 1 : 0) - (CONTEXT_KINDS[b] ? 1 : 0) || c._kindCount[b] - c._kindCount[a] || (a < b ? -1 : 1);
      });
    });

    var extras = { logs: L.extras, traces: Tr.extras, alerts: A.extras, helm: Hm.extras };
    var stats = { logs: L.stats, traces: Tr.stats, alerts: A.stats, helm: Hm.stats };
    var traits;
    try {
      traits = WR.traits({ components: compList, edges: edges, signals: all, stats: stats, extras: extras, clusters: clusters, deploy: deploy, window: win, inputsPresent: inputsPresent });
    } catch (e) {
      warnings.push('Incident traits failed: ' + (e && e.message ? e.message : e));
      traits = skeleton(input, []).traits;
    }

    // Parser warnings follow the analysis-level ones. A parser's "no deploy time" note is replaced
    // by ours when a rollout supplied the time.
    ['logs', 'traces', 'alerts', 'helm'].forEach(function (k) {
      // A pane pasted into the wrong tab gets one clear sentence (first in the list), not a dozen
      // "not recognised" lines from the parser that was never meant to read it.
      if (sniff.misplaced[k]) return;
      (stats[k].warnings || []).forEach(function (w) {
        if (rolloutTimeUsed && /^No deploy time found/.test(w)) return;
        if (/^No deploy time found/.test(w) && warnings.some(function (x) { return /^No deploy time found/.test(x); })) return;
        warnings.push(w);
      });
    });

    var components = compList.slice().sort(function (a, b) {
      return STATUS_RANK[a.status] - STATUS_RANK[b.status] || b.impact - a.impact || (a.id < b.id ? -1 : 1);
    }).map(function (c) {
      return {
        id: c.id, name: c.name, type: c.type, role: c.role, cluster: c.cluster, namespace: c.namespace,
        status: c.status, impact: c.impact, userFacing: c.userFacing,
        firstErrorTs: c.firstErrorTs, lastErrorTs: c.lastErrorTs, statusSince: c.statusSince,
        counts: c.counts, kinds: c.kinds, pods: c.pods, release: c.release, changeIds: c.changeIds
      };
    });

    return {
      version: 1,
      generatedAt: typeof input.generatedAt === 'number' ? input.generatedAt : (now != null ? now : Date.now()),
      inputsPresent: inputsPresent,
      stats: stats,
      window: win,
      headline: headline,
      severity: severity,
      clusters: clusters,
      components: components,
      edges: edges.map(function (e) {
        return {
          id: e.id, from: e.from, to: e.to, calls: e.calls, errors: e.errors,
          errorRate: e.errorRate == null ? null : Math.round(e.errorRate * 10000) / 10000,
          p95ms: e.p95ms, status: e.status, firstErrorTs: e.firstErrorTs, source: e.source
        };
      }),
      signals: outSignals,
      changes: changes,
      deploy: deploy,
      deploys: deploys,
      timeline: timeline,
      hypotheses: hyps.map(function (x) {
        return { id: x.id, title: x.title, category: x.category, componentId: x.componentId, confidence: x.confidence, summary: x.summary,
          evidence: x.evidence, against: x.against, nextChecks: x.nextChecks, rule: x.rule, relatedComponentIds: x.relatedComponentIds };
      }),
      rollbacks: rbs,
      budget: budget,
      traits: traits,
      warnings: WR.uniq(sniff.warnings.concat(warnings))
    };
  }

  // ---------------------------------------------------------------------------------------------
  // Headline: one plain sentence naming the component, cluster, what it is doing, and the release
  // only when the top hypothesis actually cites that release.
  // ---------------------------------------------------------------------------------------------
  var STATE_WORDS = [
    ['crash_loop', 'crash-looping'], ['oom_killed', 'being killed for running out of memory'], ['image_pull', 'unable to pull its image'],
    ['config_error', 'failing to start'], ['conn_exhaustion', 'out of database connections'], ['tls_error', 'failing certificate checks'],
    ['dns_failure', 'failing name lookups'], ['probe_failed', 'failing its health checks'], ['evicted', 'losing pods to eviction'],
    ['node_not_ready', 'not ready'], ['http_429', 'being rate limited'], ['conn_refused', 'refusing connections'], ['timeout', 'timing out'], ['http_5xx', 'returning server errors']
  ];
  function stateWord(c) {
    for (var i = 0; i < STATE_WORDS.length; i++) if (c.kinds.indexOf(STATE_WORDS[i][0]) >= 0 || c._kindCount[STATE_WORDS[i][0]]) return STATE_WORDS[i][1];
    return 'failing';
  }

  function makeHeadline(anyInput, top, comps, compList, changes, deploys, clusters) {
    if (!anyInput) return 'Paste logs, traces, alerts or Helm output to start.';
    if (top && top.confidence >= 0.35 && comps[top.componentId]) {
      var c = comps[top.componentId];
      // Name the cluster only when the evidence or the form stated it (never the placeholder).
      var cl = c.clusterKnown ? c.cluster : null;
      var where = c.name + (cl ? ' in ' + cl : '');
      var also = (top.relatedComponentIds || []).map(function (id) { return comps[id] && comps[id].clusterKnown ? comps[id].cluster : null; }).filter(Boolean);
      if (also.length && cl) where = c.name + ' in ' + [cl].concat(also).join(' and ');
      var rel = top._release || null;
      if (!rel) {
        var cited = top.evidence.map(function (e) { return e.changeId; }).filter(Boolean);
        var ch = changes.filter(function (x) { return cited.indexOf(x.id) >= 0 && x.release; })[0];
        if (ch) rel = ch.release;
      }
      var d = rel ? deploys.filter(function (x) { return x.release === rel; })[0] : null;
      var after = rel ? ' after Helm release ' + rel + (d && d.revision != null ? ' r' + d.revision : '') : '';
      switch (top.category) {
        case 'dns':
          return c.name === 'coredns' ? 'Name lookups are failing' + (cl ? ' across ' + cl : '') + ': CoreDNS is ' + stateWord(c) + after
            : where + ' cannot resolve the names it calls';
        case 'network-policy':
          return 'Traffic to ' + where + ' is blocked by a NetworkPolicy change' + after;
        case 'node-pressure':
          return (c.type === 'node' ? 'Node ' : '') + where + ' is ' + stateWord(c) + ', and its pods are failing';
        case 'scheduling-capacity':
          return where + ' cannot schedule new pods (not enough capacity)' + after;
        case 'tls-cert':
          return where + ' is serving ' + (top._anchor && top._anchor.type === 'event' ? 'an expired' : 'a rejected') + ' certificate, so calls to it fail';
        case 'connection-exhaustion':
          return where + ' is out of database connections' + after;
        case 'resource-limits':
          return where + ' is ' + stateWord(c) + after;
        case 'bad-deploy':
          return where + ' is ' + stateWord(c) + after;
        case 'dependency-failure':
          return where + ' is failing and taking its callers down with it';
        default:
          return where + ' is ' + stateWord(c) + after;
      }
    }
    var failing = compList.filter(function (x) { return x.status === 'failing' || x.status === 'root'; })
      .sort(function (a, b) { return b.counts.error - a.counts.error || (a.id < b.id ? -1 : 1); });
    if (failing.length) return plural(failing.length, 'component') + ' failing, no clear root cause yet; most errors in ' + failing[0].name + (failing[0].clusterKnown ? ' (' + failing[0].cluster + ')' : '');
    var degraded = compList.filter(function (x) { return x.status === 'degraded'; });
    if (degraded.length) return degraded[0].name + (degraded[0].clusterKnown ? ' in ' + degraded[0].cluster : '') + ' is degraded; nothing is failing outright';
    return 'No failing components in the pasted evidence';
  }
  function plural(n, one) { return n + ' ' + one + (n === 1 ? '' : 's'); }

  analyze.isError = isError;
  analyze.isAnomaly = isAnomaly;
  analyze.scanCerts = scanCerts;
  analyze.detectHandoffs = detectHandoffs;
  analyze.MAX_SIGNALS = MAX_SIGNALS;
  WR.analyze = analyze;
})(globalThis.WR = globalThis.WR || {});
