/*
 * hypotheses.js — WR.hypotheses(hctx) → Hypothesis[] (sorted by confidence, at most 6)
 *
 * A rule library: each rule looks at the reconciled evidence (signals per component, edges with
 * status, Helm changes and deploys, facts scanned from the pasted text) and proposes candidate root
 * causes with an evidence chain that points back at signal ids, change ids and line numbers.
 *
 * Scoring is deterministic and the same for every rule (SPEC §4):
 *   base  = 1 − Π(1 − wᵢ)            over the evidence weights wᵢ (independent-ish clues add up,
 *                                     but never past 1)
 *   × 1.15 when the anchoring change (its deploy time, or its ReplicaSet rollout) or anchoring
 *          event (a certificate's Not After) comes 0–60 min before the component's first error
 *   × 0.6  when the component's errors started before the anchoring change (1 min clock slack)
 *   × 1.1  when the component is the deepest failing node on failing edges (none of its callees
 *          is failing — the failure starts there rather than passing through)
 *   confidence = min(0.95, raw); held at 0.5 when fewer than two evidence items support it.
 * Ties (several hypotheses at the 0.95 cap) are broken by the raw score, then by how specific the
 * category is (a named mechanism beats "bad deploy", which beats "dependency failure"), then by id.
 *
 * hctx is built by analyze.js; see buildHypothesisContext there for the field list.
 */
(function (WR) {
  'use strict';

  // Signal kinds in plain words, for sentences ("killed for running out of memory, crash-looping").
  var PLAIN_KIND = {
    oom_killed: 'killed for running out of memory', crash_loop: 'crash-looping', image_pull: 'unable to pull its image',
    config_error: 'missing configuration', probe_failed: 'failing health checks', evicted: 'evicted', node_not_ready: 'on a node that is not ready',
    node_pressure: 'short of node resources', scheduling_failed: 'unable to be scheduled', pvc_pending: 'waiting for a volume',
    dns_failure: 'failing name lookups', conn_refused: 'refusing connections', timeout: 'timing out', tls_error: 'failing certificate checks',
    http_5xx: 'returning server errors', http_429: 'rate limited', throttled: 'CPU-throttled', hpa_maxed: 'at its autoscaler maximum',
    rollout: 'rolling out', restart: 'restarting', panic: 'throwing exceptions', db_error: 'hitting database errors',
    conn_exhaustion: 'out of database connections', migration: 'failing a migration', error_generic: 'logging errors',
    span_error: 'failing in traces', span_slow: 'slow in traces', alert_firing: 'alerting', slo_burn: 'burning error budget'
  };
  function plainKind(k) { return PLAIN_KIND[k] || String(k || '').replace(/_/g, ' '); }

  var T = WR.time;
  var MIN = 60000;
  var MAX_HYPOTHESES = 6;
  var MAX_PER_COMPONENT = 3;

  // More specific mechanisms first. Used only to break ties at equal scores.
  var CATEGORY_ORDER = ['tls-cert', 'dns', 'image-pull', 'config-error', 'resource-limits', 'connection-exhaustion',
    'network-policy', 'probe-misconfig', 'node-pressure', 'scheduling-capacity', 'rate-limiting', 'bad-deploy',
    'dependency-failure', 'unknown'];
  function specificity(cat) { var i = CATEGORY_ORDER.indexOf(cat); return i < 0 ? 99 : i; }

  // -------------------------------------------------------------------------------------------
  // Small text and command helpers
  // -------------------------------------------------------------------------------------------
  function at(ts) { return ts == null ? 'at an unknown time' : 'at ' + T.fmt(ts) + ' UTC'; }
  function times(n) { return n === 1 ? 'once' : n + ' times'; }
  function plural(n, one, many) { return n + ' ' + (n === 1 ? one : (many || one + 's')); }
  function quote(s, n) { return '"' + WR.truncate(String(s || '').replace(/\s+/g, ' ').trim(), n || 110) + '"'; }
  // Quote the telling part of a long line: start a little before the first match of `re`.
  function quoteAt(s, re, n) {
    var t = String(s || '').replace(/\s+/g, ' ').trim();
    var m = re ? re.exec(t) : null;
    if (m && m.index > 20) t = '…' + t.slice(Math.max(0, m.index - 12));
    return quote(t, n);
  }
  function mins(ms) { return WR.fmtDuration(ms); }
  // " in prod-eu-west", or nothing when the paste never named a cluster (never the placeholder).
  function inCl(comp) { return comp && comp.clusterKnown && comp.cluster ? ' in ' + comp.cluster : ''; }

  // kubectl prefix for read-only checks. When the cluster was never stated we leave --context out
  // (the engineer's current context) rather than inventing a name.
  function kc(comp) {
    var p = ['kubectl'];
    if (comp && comp.clusterKnown && comp.cluster) p.push('--context ' + comp.cluster);
    if (comp && comp.namespace && comp.type !== 'node') p.push('-n ' + comp.namespace);
    return p.join(' ');
  }
  function kcCluster(comp) {
    return 'kubectl' + (comp && comp.clusterKnown && comp.cluster ? ' --context ' + comp.cluster : '');
  }
  function helmFlags(d) {
    return (d.namespace ? ' -n ' + d.namespace : '') + (d.clusterKnown && d.cluster ? ' --kube-context ' + d.cluster : '');
  }
  function workloadRef(comp) {
    var c = (comp && comp.controller) || '';
    if (/StatefulSet/i.test(c)) return 'statefulset/' + comp.name;
    if (/DaemonSet/i.test(c)) return 'daemonset/' + comp.name;
    return 'deployment/' + (comp ? comp.name : '<name>');
  }
  function podRegex(comp) { return comp.name + '-.*'; }

  // A pod of this component, preferring one that showed the given kinds.
  function pickPod(h, comp, kinds) {
    var sigs = h.sigsByComp[comp.id] || [];
    for (var i = 0; i < sigs.length; i++) {
      if (sigs[i].attrs && sigs[i].attrs.pod && (!kinds || kinds.indexOf(sigs[i].kind) >= 0)) return sigs[i].attrs.pod;
    }
    for (i = 0; i < sigs.length; i++) if (sigs[i].attrs && sigs[i].attrs.pod) return sigs[i].attrs.pod;
    return comp.pods && comp.pods.length ? comp.pods[0] : null;
  }
  function pickContainer(h, comp) {
    var sigs = h.sigsByComp[comp.id] || [];
    for (var i = 0; i < sigs.length; i++) if (sigs[i].attrs && sigs[i].attrs.container) return sigs[i].attrs.container;
    var chs = h.changesByComp[comp.id] || [];
    for (i = 0; i < chs.length; i++) {
      var m = /containers\[([^\]]+)\]/.exec(chs[i].field || '');
      if (m) return m[1];
    }
    return comp.name;
  }

  // -------------------------------------------------------------------------------------------
  // Evidence builders
  // -------------------------------------------------------------------------------------------
  function evSig(sig, text, weight) {
    return { signalId: sig ? sig.id : null, changeId: null, text: text, weight: weight, source: sig ? sig.source : null, line: sig ? sig.line : null };
  }
  function evChange(ch, text, weight) {
    return { signalId: null, changeId: ch.id, text: text || ch.summary, weight: weight, source: 'helm', line: ch.line == null ? null : ch.line };
  }
  function evFact(source, line, text, weight) {
    return { signalId: null, changeId: null, text: text, weight: weight, source: source, line: line == null ? null : line };
  }

  // A failed span says how it failed in its status message, which the trace parser classifies
  // with the log rules (attrs.causeKind). For the mechanisms with their own rule — DNS, TLS,
  // connection exhaustion — that span is the same evidence as a log line saying so, so a
  // traces-only paste still reaches the specific diagnosis.
  var SPAN_MECHANISMS = { dns_failure: 1, tls_error: 1, conn_exhaustion: 1 };
  function mechanism(s) {
    if (s.kind === 'span_error' && s.attrs && SPAN_MECHANISMS[s.attrs.causeKind]) return s.attrs.causeKind;
    return s.kind;
  }

  function sigsOf(h, compId, kinds, filter) {
    var all = h.sigsByComp[compId] || [];
    var out = [];
    for (var i = 0; i < all.length; i++) {
      var s = all[i];
      if (kinds && kinds.indexOf(s.kind) < 0) continue;
      if (filter && !filter(s)) continue;
      out.push(s);
    }
    return out;
  }
  // The earliest signal by time (any time, including ones pinned to "now"); else the first listed.
  function firstOf(list) {
    var best = null;
    for (var i = 0; i < list.length; i++) {
      var s = list[i];
      if (s.ts != null && (!best || s.ts < best.ts)) best = s;
    }
    return best || list[0] || null;
  }
  // Same, but ignoring signals whose time was unknown and pinned to "now".
  function firstTimed(list) {
    var best = null;
    for (var i = 0; i < list.length; i++) {
      var s = list[i];
      if (s.ts == null || (s.attrs && s.attrs.tsUnknown)) continue;
      if (!best || s.ts < best.ts) best = s;
    }
    return best || firstOf(list);
  }
  // Prefer a signal whose text matches re (e.g. the line that literally says "expired").
  function preferText(list, re) {
    for (var i = 0; i < list.length; i++) if (re.test(list[i].text || '')) return list[i];
    return firstTimed(list);
  }
  function isFailingStatus(st) { return st === 'failing' || st === 'root'; }

  function deployFor(h, release, compId) {
    for (var i = 0; i < h.deploys.length; i++) {
      var d = h.deploys[i];
      if (release && d.release === release) return d;
    }
    for (i = 0; i < h.deploys.length; i++) if (compId && h.deploys[i].componentId === compId) return h.deploys[i];
    return null;
  }
  function changeTime(h, ch) {
    var d = deployFor(h, ch.release, ch.componentId);
    return d && d.deployedAt != null ? d.deployedAt : null;
  }

  // -------------------------------------------------------------------------------------------
  // Rules. Each pushes candidates: { category, componentId, rule, title, summary, evidence[],
  // against[], nextChecks[], anchor: { ts, type:'change'|'event' } | null, covers: [componentId] }
  // -------------------------------------------------------------------------------------------

  // ---- resource limits: OOM kills (and CPU throttling) ----------------------------------------
  function ruleResourceLimits(h, out) {
    h.compList.forEach(function (comp) {
      if (comp.type === 'node' || comp.type === 'external') return;
      var oom = sigsOf(h, comp.id, ['oom_killed'], function (s) { return s.source !== 'alerts'; });
      var oomAlerts = sigsOf(h, comp.id, ['oom_killed'], function (s) { return s.source === 'alerts'; });
      var cpu = sigsOf(h, comp.id, ['throttled'], function (s) { return /cpu/i.test(s.text || '') || (s.attrs && /cpu/i.test(s.attrs.alertname || '')); });
      var chs = h.changesByComp[comp.id] || [];
      var memCut = chs.filter(function (c) { return c.category === 'resources' && /limits\.memory$/.test(c.field || '') && c.direction === 'down'; })[0];
      var memReq = chs.filter(function (c) { return c.category === 'resources' && /requests\.memory$/.test(c.field || '') && c.direction === 'down'; })[0];
      var cpuCut = chs.filter(function (c) { return c.category === 'resources' && /limits\.cpu$/.test(c.field || '') && c.direction === 'down'; })[0];
      if (!oom.length && !oomAlerts.length && !(cpu.length && cpuCut)) return;

      var memoryCase = oom.length || oomAlerts.length;
      var ev = [], against = [], anchor = null;
      var limit = null, exit137 = false;
      oom.forEach(function (s) { if (s.attrs && s.attrs.memoryLimit) limit = s.attrs.memoryLimit; if (s.attrs && s.attrs.exitCode === 137) exit137 = true; });
      if (!limit && memCut) limit = memCut.after;
      var crash = sigsOf(h, comp.id, ['crash_loop']);
      var f = firstTimed(oom.length ? oom : oomAlerts);

      // Kubernetes' own records (events, describe, pod status) lead; the kernel's OOM-killer lines
      // reattributed from nodes are a separate, corroborating clue below.
      var kernel = oom.filter(function (s) { return s.attrs && s.attrs.reattributedFromNode; });
      var k8sOom = oom.filter(function (s) { return !(s.attrs && s.attrs.reattributedFromNode); });
      var restarts = 0;
      oom.concat(crash).forEach(function (s) { if (s.attrs && s.attrs.restartCount > restarts) restarts = s.attrs.restartCount; if (s.attrs && s.attrs.restarts > restarts) restarts = s.attrs.restarts; });
      if (oom.length) {
        f = firstTimed(oom);
        ev.push(evSig(f, comp.name + ' containers were killed for running out of memory (OOMKilled, ' + plural(oom.length, 'record') + (kernel.length && k8sOom.length ? ' from Kubernetes and the kernel' : '') + ', first ' + at(f.ts) + ')' +
          (exit137 ? ', exit code 137' : '') + (limit ? ', memory limit ' + limit : '') + (restarts ? ', ' + plural(restarts, 'restart') + ' so far' : '') + '.', 0.5));
      }
      if (memCut) {
        ev.push(evChange(memCut, 'Helm lowered the memory limit: ' + memCut.summary + (memCut.release ? ' (release ' + memCut.release + ')' : '') + '.', 0.45));
        var t = changeTime(h, memCut);
        if (t != null) anchor = { ts: t, type: 'change' };
      }
      if (memReq && memCut) ev.push(evChange(memReq, 'The memory request went down too: ' + memReq.summary + '.', 0.05));
      if (crash.length && memoryCase) {
        var fc = firstTimed(crash);
        ev.push(evSig(fc, 'Kubernetes reports CrashLoopBackOff for ' + comp.name + ' ' + times(crash.length) + ' — the kill-restart cycle after each out-of-memory kill.', 0.15));
      }
      // With Kubernetes records pasted, the alert only corroborates them. Alone (an alerts-only
      // paste), it is the OOM observation itself — kube-state-metrics' last-terminated reason — and
      // carries nearly the weight of an event record.
      if (oomAlerts.length) {
        ev.push(evSig(oomAlerts[0], 'Alert ' + (oomAlerts[0].attrs.alertname || 'OOM') + ' is firing for ' + comp.name +
          (oom.length ? '.' : ': its containers were killed for running out of memory' + (oomAlerts.length > 1 ? ' (' + plural(oomAlerts.length, 'alert') + ')' : '') + '.'), oom.length ? 0.15 : 0.4));
      }
      // Kernel OOM-killer lines on nodes that name this workload's process (reattributed in analyze).
      // It must cite a kernel line other than the one the main item already cites, or it would
      // count the same record twice.
      var kernelOther = kernel.filter(function (s) { return !f || s.id !== f.id; });
      if (kernelOther.length && k8sOom.length) ev.push(evSig(kernelOther[0], 'The kernel\'s out-of-memory killer on ' + plural(WR.uniq(kernel.map(function (s) { return s.attrs.node; })).length, 'node') + ' killed the ' + comp.name + ' process ' + times(kernel.length) + '.', 0.1));
      // New memory-hungry settings shipped in the same release make a lower limit worse.
      var hungry = chs.filter(function (c) {
        return (c.category === 'env' || c.category === 'configmap') && c.before == null &&
          /cache|warm|buffer|heap|memory|prefetch|batch|preload|pool/i.test(c.field || '');
      });
      if (hungry.length && memoryCase) {
        var names = hungry.slice(0, 2).map(function (c) { var m = /env\[([^\]]+)\]|\.data\.([\w.-]+)$/.exec(c.field || ''); var n = m ? (m[1] || m[2]) : c.field; return c.after != null && c.after !== '(redacted)' ? n + '=' + WR.truncate(c.after, 24) : n; });
        ev.push(evChange(hungry[0], 'The same release also turns on ' + names.join(' and ') + ', which likely ' + (names.length > 1 ? 'need' : 'needs') + ' more memory.', 0.1));
        if (!anchor) { var t2 = changeTime(h, hungry[0]); if (t2 != null) anchor = { ts: t2, type: 'change' }; }
      }
      if (cpu.length && cpuCut) {
        ev.push(evSig(cpu[0], comp.name + ' is CPU-throttled ' + times(cpu.length) + '.', 0.3));
        ev.push(evChange(cpuCut, 'Helm lowered the CPU limit: ' + cpuCut.summary + '.', 0.35));
        if (!anchor) { var t3 = changeTime(h, cpuCut); if (t3 != null) anchor = { ts: t3, type: 'change' }; }
      }

      if (memoryCase && !memCut) against.push({ text: 'No memory limit change for ' + comp.name + ' in the pasted Helm diff; memory use may have grown on its own (traffic, a leak, a larger data set).' });
      if ((memCut || hungry.length) && !anchor) against.push({ text: 'No deploy time found — paste `helm history` or set Deployed at.' });
      var pressure = h.signals.filter(function (s) { return s.kind === 'node_pressure' && h.comps[s.componentId] && h.comps[s.componentId].cluster === comp.cluster; });
      if (pressure.length) against.push({ text: 'Nodes' + inCl(comp) + ' also report memory pressure; evictions point at the node, not the container limit.' });
      var sib = siblingsHealthy(h, comp);
      if (sib.length && !memCut) against.push({ text: comp.name + ' runs without out-of-memory kills in ' + sib.join(', ') + '; compare the two clusters\' limits and traffic.' });

      var pod = pickPod(h, comp, ['oom_killed', 'crash_loop']);
      var ctr = pickContainer(h, comp);
      var checks = [];
      if (pod) {
        checks.push({ cmd: kc(comp) + ' describe pod ' + pod, why: 'Last State, Reason (OOMKilled), Exit Code 137 and the memory limit of each container.' });
        checks.push({ cmd: kc(comp) + ' top pod ' + pod + ' --containers', why: 'Current memory use against the limit (needs metrics-server).' });
        checks.push({ cmd: kc(comp) + ' get events --field-selector involvedObject.name=' + pod + ' --sort-by=.lastTimestamp', why: 'When the kills and back-offs started for this pod.' });
      }
      checks.push({ cmd: 'max by (pod) (container_memory_working_set_bytes{namespace="' + comp.namespace + '", pod=~"' + podRegex(comp) + '", container="' + ctr + '"})', why: 'Prometheus query: working-set memory per pod — the number the OOM killer compares with the limit.' });
      checks.push({ cmd: 'sum by (pod) (increase(kube_pod_container_status_restarts_total{namespace="' + comp.namespace + '", pod=~"' + podRegex(comp) + '"}[30m]))', why: 'Prometheus query: restarts per pod over the incident.' });
      var d = memCut ? deployFor(h, memCut.release, comp.id) : deployFor(h, comp.release, comp.id);
      if (d && d.release && d.previousRevision != null) {
        checks.push({ cmd: 'helm get values ' + d.release + helmFlags(d) + ' --revision ' + d.previousRevision, why: 'The resources the last good revision ran with.' });
      }

      var title = memCut
        ? 'Memory limit cut to ' + memCut.after + ' gets ' + comp.name + ' killed for running out of memory'
        : cpuCut && !memoryCase ? 'CPU limit cut is throttling ' + comp.name
          : comp.name + ' is running out of memory' + (limit ? ' at its ' + limit + ' limit' : '');
      var summary = memCut
        ? comp.name + inCl(comp) + ' is killed by the kernel when it exceeds its memory limit, which the latest release lowered (' + memCut.summary + '). Each kill restarts the container, and repeated restarts put it in CrashLoopBackOff, so callers see refused connections.'
        : comp.name + inCl(comp) + ' keeps exceeding its memory limit' + (limit ? ' (' + limit + ')' : '') + ' and is killed for running out of memory (OOMKilled), then restarted.';
      out.push({ category: 'resource-limits', componentId: comp.id, rule: memCut ? 'oom-after-limit-cut' : cpuCut && !memoryCase ? 'cpu-throttled-after-limit-cut' : 'oom-killed',
        title: title, summary: summary, evidence: ev, against: against, nextChecks: checks, anchor: anchor, covers: [comp.id] });
    });
  }

  // Same component name in other clusters with no error signals (healthy siblings).
  function siblingsHealthy(h, comp) {
    return h.compList.filter(function (c) {
      return c.id !== comp.id && c.name === comp.name && c.cluster !== comp.cluster && c.status === 'healthy';
    }).map(function (c) { return c.cluster; });
  }

  // ---- bad deploy: a release (or ReplicaSet rollout) right before the failures ------------------
  function ruleBadDeploy(h, out) {
    h.deploys.forEach(function (d) {
      if (!d.componentId) return;
      var comp = h.comps[d.componentId];
      if (!comp) return;
      var relChanges = h.changes.filter(function (c) { return d.release ? c.release === d.release : c.componentId === comp.id; });
      // A failing caller on an edge into the component also counts as the component misbehaving.
      var inFail = (h.edgesTo[comp.id] || []).some(function (e) { return e.status === 'failing'; });
      var unhealthy = isFailingStatus(comp.status) || comp.status === 'degraded' || inFail;
      // A deploy of a component that shows no errors is weak evidence: scale every clue down.
      var k = unhealthy ? 1 : 0.4;
      var ev = [], against = [];
      var depSig = d.signalId ? h.sigById[d.signalId] : null;
      var what = d.release ? 'Helm release ' + d.release + (d.previousRevision != null ? ' r' + d.previousRevision + ' → r' + d.revision : d.revision != null ? ' r' + d.revision : '')
        : 'A new ReplicaSet' + (d.replicaSet ? ' ' + d.replicaSet : '') + ' of ' + comp.name;
      ev.push({ signalId: depSig ? depSig.id : null, changeId: null,
        text: what + (d.deployedAt != null ? ' rolled out ' + at(d.deployedAt) : ' was deployed (time unknown)') +
          (d.chartFrom && d.chartTo && d.chartFrom !== d.chartTo ? ', chart ' + d.chartFrom + ' → ' + d.chartTo : '') + '.',
        weight: 0.2 * k, source: depSig ? depSig.source : (d.deployedAtSource === 'rollout-event' ? 'logs' : 'helm'), line: depSig ? depSig.line : (d.line == null ? null : d.line) });
      var firstErr = comp.firstErrorTs;
      if (d.deployedAt != null && firstErr != null && firstErr >= d.deployedAt - MIN && firstErr - d.deployedAt <= 120 * MIN) {
        var fe = h.sigById[comp.firstErrorSignalId];
        ev.push(evSig(fe, comp.name + ' first failed ' + mins(Math.max(0, firstErr - d.deployedAt)) + ' after the deploy' + (fe ? ': ' + quote(fe.text, 90) : '') + '.', 0.3 * k));
      }
      var mig = relChanges.filter(function (c) { return c.category === 'migration-hook'; })[0];
      var high = relChanges.filter(function (c) { return c.risk === 'high' && c !== mig; });
      var med = relChanges.filter(function (c) { return c.risk === 'medium'; });
      var migErr = h.signals.filter(function (s) { return s.kind === 'migration' && WR.sevRank(s.severity) >= 2; });
      var dbErr = sigsOf(h, comp.id, ['db_error'], function (s) { return h.isError(s); });
      // A pre-upgrade migration changes the database before the new pods start, and a rollback
      // cannot undo it, so it is the most important change to name.
      if (mig) ev.push(evChange(mig, 'A schema migration ran as a Helm pre-upgrade hook in this release (' + mig.summary + ').', 0.2 * k));
      if (mig && migErr.length) ev.push(evSig(migErr[0], 'The database migration failed: ' + quote(migErr[0].text, 90) + '.', 0.3 * k));
      else if (mig && dbErr.length) ev.push(evSig(firstTimed(dbErr), 'Database errors on ' + comp.name + ' after the migration ' + times(dbErr.length) + ': ' + quote(firstTimed(dbErr).text, 90) + '.', 0.25 * k));
      high.slice(0, mig ? 1 : 2).forEach(function (c) { ev.push(evChange(c, 'High-risk change in this release: ' + c.summary + '.', 0.15 * k)); });
      med.slice(0, 2).forEach(function (c) { ev.push(evChange(c, 'Also changed: ' + c.summary + '.', 0.05 * k)); });
      var ro = (h.rolloutsByComp[comp.id] || [])[0];
      if (ro && d.deployedAtSource !== 'rollout-event') ev.push(evSig(ro, 'Kubernetes rolled out a new ReplicaSet' + (ro.attrs.replicaSet ? ' (' + ro.attrs.replicaSet + ')' : '') + ' for ' + comp.name + '.', 0.1 * k));

      var anchor = d.deployedAt != null ? { ts: d.deployedAt, type: 'change' } : null;
      if (d.deployedAt == null) against.push({ text: 'No deploy time found — paste `helm history` or set Deployed at.' });
      if (!unhealthy) against.push({ text: comp.name + ' shows no errors in the pasted evidence, and nothing that calls it is failing.' });
      var gf = firstErr != null ? firstErr : h.firstAnomaly;
      if (d.deployedAt != null && gf != null && gf - d.deployedAt > 60 * MIN) against.push({ text: 'The first errors came ' + mins(gf - d.deployedAt) + ' after this deploy; a bad release usually fails within minutes.' });
      if (d.deployedAt != null && gf != null && gf < d.deployedAt - MIN) against.push({ text: 'Errors started ' + mins(d.deployedAt - gf) + ' before this deploy.' });
      if (relChanges.length && !high.length && !med.length) against.push({ text: 'The release changed only labels and version numbers.' });
      var sib = siblingsHealthy(h, comp);
      if (sib.length && unhealthy) against.push({ text: comp.name + ' is healthy in ' + sib.join(', ') + ' — consistent with the release if that cluster has not been upgraded yet; check its Helm history.' });
      // Already rolled back: failures that outlive the rollback (after the pods had 2 minutes to
      // roll) argue against the release being the whole story.
      if (d.rolledBack && d.rolledBack.at != null) {
        var lateErr = (h.sigsByComp[comp.id] || []).filter(function (s) { return h.isError(s) && s.ts != null && s.ts > d.rolledBack.at + 2 * MIN && !(s.attrs && s.attrs.tsUnknown); });
        if (lateErr.length) against.push({ text: 'The release was rolled back to r' + d.rolledBack.to + ' ' + at(d.rolledBack.at) + ', yet ' + comp.name + ' kept failing (' + plural(lateErr.length, 'error') + ' after it).' });
      }

      var checks = [];
      if (d.release) {
        checks.push({ cmd: 'helm history ' + d.release + helmFlags(d) + ' --max 5', why: 'Which revision is live and when each one was deployed.' });
        if (d.previousRevision != null && d.revision != null) {
          checks.push({ cmd: 'helm diff revision ' + d.release + ' ' + d.previousRevision + ' ' + d.revision + helmFlags(d), why: 'Every manifest change between the last good and the current revision (helm-diff plugin).' });
          checks.push({ cmd: 'helm get values ' + d.release + helmFlags(d) + ' --revision ' + d.previousRevision, why: 'The values the last good revision used.' });
        }
      }
      if (comp.type !== 'external') checks.push({ cmd: kc(comp) + ' rollout history ' + workloadRef(comp), why: 'ReplicaSet revisions of the workload and when they rolled out.' });

      out.push({
        category: 'bad-deploy', componentId: comp.id, rule: mig ? (migErr.length ? 'migration-hook-failed' : 'migration-hook') : (d.deployedAtSource === 'rollout-event' ? 'rollout-correlation' : 'deploy-correlation'),
        title: (d.release ? 'Helm release ' + d.release + (d.revision != null ? ' r' + d.revision : '') : 'The new rollout') + ' broke ' + comp.name,
        summary: what + ' changed ' + plural(relChanges.length, 'field') + ' (' + plural(high.length, 'high-risk change') + ')' +
          (unhealthy ? ' shortly before ' + comp.name + ' started failing.' : '; ' + comp.name + ' itself looks healthy.'),
        evidence: ev, against: against, nextChecks: checks, anchor: anchor, covers: [comp.id], release: d.release || null
      });
    });
  }

  // ---- DNS: name lookups failing across services ----------------------------------------------
  function ruleDns(h, out) {
    var byCluster = {};
    h.signals.forEach(function (s) {
      if (mechanism(s) !== 'dns_failure' || !s.componentId) return;
      var c = h.comps[s.componentId];
      if (!c) return;
      (byCluster[c.cluster] || (byCluster[c.cluster] = [])).push(s);
    });
    Object.keys(byCluster).forEach(function (cluster) {
      var list = byCluster[cluster];
      var corednsId = WR.entities.componentId('infra', cluster, 'kube-system', 'coredns');
      var core = h.comps[corednsId] || null;
      var clientSigs = list.filter(function (s) { return s.componentId !== corednsId; });
      var affected = WR.uniq(clientSigs.map(function (s) { return s.componentId; }));
      var coreErr = core ? sigsOf(h, core.id, null, function (s) { return h.isError(s); }) : [];
      var target = core && (affected.length >= 2 || coreErr.length || core.status !== 'healthy') ? core : null;
      if (!target) {
        // One service failing to resolve: the name itself is the suspect, not cluster DNS.
        var counts = WR.groupBy(clientSigs, 'componentId');
        var best = Object.keys(counts).sort(function (a, b) { return counts[b].length - counts[a].length || (a < b ? -1 : 1); })[0];
        target = best ? h.comps[best] : null;
      }
      if (!target) return;
      var ev = [], against = [], anchor = null;
      var f = firstTimed(clientSigs.length ? clientSigs : list);
      var names = affected.map(function (id) { return h.comps[id] ? h.comps[id].name : id; });
      ev.push(evSig(f, 'Name lookups fail in ' + plural(affected.length || 1, 'service') + (names.length ? ' (' + names.slice(0, 6).join(', ') + (names.length > 6 ? ', …' : '') + ')' : '') +
        ', ' + plural(list.length, 'error') + ', first ' + at(f && f.ts) + ': ' + quoteAt(f && f.text, /lookup|no such host|SERVFAIL|NXDOMAIN|resolv|EAI_AGAIN|UnknownHost/i, 110) + '.', Math.min(0.55, 0.35 + 0.05 * Math.max(0, affected.length - 1))));
      if (target.id === corednsId && affected.length >= 2 && f) {
        // A second service failing lookups at the same time is an independent observation: one
        // bad host name cannot explain both, a shared resolver can.
        var s2 = firstTimed(clientSigs.filter(function (s) { return s.componentId !== f.componentId; }));
        if (s2) ev.push(evSig(s2, 'Lookups also fail from ' + (h.comps[s2.componentId] ? h.comps[s2.componentId].name : 'another service') + ' ' + at(s2.ts) + ': ' + quoteAt(s2.text, /lookup|no such host|SERVFAIL|NXDOMAIN|resolv|EAI_AGAIN|UnknownHost/i, 90) + '.', 0.15));
      }
      if (target.id === corednsId) {
        if (coreErr.length) {
          var kinds = WR.uniq(coreErr.map(function (s) { return s.kind; }));
          var fc = firstTimed(coreErr);
          ev.push(evSig(fc, 'CoreDNS itself is failing (' + kinds.slice(0, 4).map(plainKind).join(', ') + '; ' + plural(coreErr.length, 'signal') + ').', 0.3));
          var coreOom = coreErr.filter(function (s) { return s.kind === 'oom_killed'; });
          var oomCite = coreOom.filter(function (s) { return !fc || s.id !== fc.id; })[0];
          if (coreOom.length && oomCite) ev.push(evSig(oomCite, 'CoreDNS pods are killed for running out of memory ' + times(coreOom.length) + ', so lookups time out while they restart.', 0.1));
        }
        var chs = (h.changesByComp[corednsId] || []).filter(function (c) { return c.risk !== 'low'; });
        var cfg = chs.filter(function (c) { return c.category === 'configmap'; })[0] || chs[0];
        if (cfg) {
          ev.push(evChange(cfg, 'The CoreDNS configuration changed: ' + cfg.summary + '.', cfg.category === 'configmap' ? 0.35 : 0.2));
          var t = changeTime(h, cfg);
          if (t != null) anchor = { ts: t, type: 'change' };
          else against.push({ text: 'No deploy time found — paste `helm history` or set Deployed at.' });
        } else {
          against.push({ text: 'No CoreDNS change in the pasted Helm output; upstream resolvers, node-local DNS or network policy can also break lookups.' });
        }
      }
      var dnsAlerts = h.signals.filter(function (s) { return s.source === 'alerts' && s.kind === 'dns_failure' && h.comps[s.componentId] && h.comps[s.componentId].cluster === cluster; });
      if (dnsAlerts.length) ev.push(evSig(dnsAlerts[0], 'Alert ' + (dnsAlerts[0].attrs.alertname || '') + ' is firing.', 0.2));
      var external = clientSigs.filter(function (s) { return s.attrs && s.attrs.targetId && /^external:/.test(s.attrs.targetId); });
      if (external.length && external.length === clientSigs.length) against.push({ text: 'Every failed lookup is for an external name; the upstream resolver or that zone is more likely than cluster DNS.' });
      if (affected.length === 1 && target.id !== corednsId) against.push({ text: 'Only ' + target.name + ' fails to resolve names; check the host name it uses before blaming cluster DNS.' });

      var kcs = kcCluster(target);
      var checks = [
        { cmd: kcs + ' -n kube-system get pods -l k8s-app=kube-dns -o wide', why: 'Are the CoreDNS pods running and ready, and on which nodes.' },
        { cmd: kcs + ' -n kube-system logs -l k8s-app=kube-dns --tail=50 --prefix', why: 'CoreDNS errors: upstream timeouts, SERVFAIL, plugin errors.' },
        { cmd: kcs + ' -n kube-system get configmap coredns -o yaml', why: 'The Corefile in effect (forward targets, cache, policy).' },
        { cmd: kcs + ' run dns-check --rm -it --restart=Never --image=busybox:1.36 -- nslookup kubernetes.default.svc.cluster.local', why: 'A clean test lookup from a fresh pod.' },
        { cmd: 'sum by (rcode) (rate(coredns_dns_responses_total[5m]))', why: 'Prometheus query: DNS answers by response code (SERVFAIL rising?).' },
        { cmd: 'histogram_quantile(0.99, sum by (le) (rate(coredns_dns_request_duration_seconds_bucket[5m])))', why: 'Prometheus query: 99th percentile lookup time.' }
      ];
      var dd = deployFor(h, 'coredns', corednsId);
      if (dd && dd.release && dd.previousRevision != null) checks.push({ cmd: 'helm diff revision ' + dd.release + ' ' + dd.previousRevision + ' ' + dd.revision + helmFlags(dd), why: 'What the CoreDNS release changed.' });
      out.push({
        category: 'dns', componentId: target.id, rule: target.id === corednsId ? 'cluster-dns-failing' : 'name-resolution-failing',
        title: target.id === corednsId ? 'Cluster name lookups (Domain Name System, DNS) fail: CoreDNS is failing' + inCl(target) : target.name + ' cannot resolve the names it calls',
        summary: target.id === corednsId
          ? 'Services' + inCl(target) + ' cannot resolve names (' + plural(affected.length, 'service') + ' affected). CoreDNS ' + (coreErr.length ? 'is itself failing' : 'is the shared dependency') + (anchor ? ' after its configuration changed' : '') + ', so every call that needs a lookup fails or times out.'
          : target.name + ' fails to resolve host names it depends on.',
        // Cluster DNS explains the lookup failures of every affected service: they are symptoms.
        evidence: ev, against: against, nextChecks: checks, anchor: anchor, covers: target.id === corednsId ? [target.id].concat(affected) : [target.id]
      });
    });
  }

  // ---- TLS / certificates -----------------------------------------------------------------------
  function ruleTls(h, out) {
    var tls = h.signals.filter(function (s) { return mechanism(s) === 'tls_error' && s.componentId; });
    if (!tls.length) return;
    // Vote for the component whose certificate is bad: a caller's "x509" error points at its target;
    // a server's own handshake errors and certificate alerts point at itself (alerts count triple).
    var votes = {};
    tls.forEach(function (s) {
      var id = s.attrs && s.attrs.targetId && h.comps[s.attrs.targetId] ? s.attrs.targetId : s.componentId;
      votes[id] = (votes[id] || 0) + (s.source === 'alerts' ? 3 : 1);
    });
    h.facts.certs.forEach(function (c) { if (c.componentId && h.comps[c.componentId]) votes[c.componentId] = (votes[c.componentId] || 0) + 3; });
    var ids = Object.keys(votes).sort(function (a, b) { return votes[b] - votes[a] || (a < b ? -1 : 1); });
    var comp = h.comps[ids[0]];
    if (!comp) return;
    var related = tls.filter(function (s) { return s.componentId === comp.id || (s.attrs && s.attrs.targetId === comp.id); });
    var logSigs = related.filter(function (s) { return s.source !== 'alerts'; });
    var alerts = related.filter(function (s) { return s.source === 'alerts'; });
    var expired = related.filter(function (s) { return /expired|NotAfter|not after/i.test(s.text || '') || /Expir/i.test((s.attrs && s.attrs.alertname) || ''); });
    var unknownCa = related.filter(function (s) { return /unknown authority|self.signed|verify failed/i.test(s.text || ''); });
    var ev = [], against = [], anchor = null;
    if (logSigs.length) {
      var f = preferText(logSigs, /expired/i);
      var callers = WR.uniq(logSigs.filter(function (s) { return s.componentId !== comp.id; }).map(function (s) { return h.comps[s.componentId] ? h.comps[s.componentId].name : s.componentId; }));
      ev.push(evSig(f, plural(logSigs.length, 'TLS error') + ' involve ' + comp.name + (callers.length ? ' (reported by ' + callers.concat(logSigs.some(function (s) { return s.componentId === comp.id; }) ? [comp.name] : []).join(', ') + ')' : '') + ': ' + quoteAt(f.text, /x509|certificate|tls:|handshake/i, 120) + '.', 0.45));
    }
    alerts.slice(0, 2).forEach(function (s, i) {
      ev.push(evSig(s, 'Alert ' + (s.attrs.alertname || 'TLS') + ' is ' + (s.attrs.status || 'firing') + ' for ' + comp.name + '.', i === 0 ? 0.3 : 0.15));
    });
    var cert = h.facts.certs.filter(function (c) { return c.componentId === comp.id; })[0] || h.facts.certs[0] || null;
    if (cert && cert.notAfter != null) {
      var expiredAlready = h.now != null ? cert.notAfter <= h.now : true;
      ev.push(evFact('logs', cert.notAfterLine, 'Certificate ' + (cert.name || '') + (expiredAlready ? ' expired ' : ' expires ') + at(cert.notAfter) + ' (Not After).', expiredAlready ? 0.3 : 0.1));
      if (expiredAlready) anchor = { ts: cert.notAfter, type: 'event' };
    }
    if (cert && cert.issuerError) {
      ev.push(evFact('logs', cert.issuerError.line, 'Renewal has been failing' + (cert.failedAttempts ? ' (' + cert.failedAttempts + ' failed attempts)' : '') + ': ' + quote(cert.issuerError.text, 140) + '.', 0.15));
    }
    if (unknownCa.length && !expired.length) against.push({ text: 'The errors say "unknown authority" or "verify failed", not "expired": a changed CA or trust bundle is more likely than an expired certificate.' });
    var tlsChange = h.changes.filter(function (c) { return /tls|cert|ca\.crt|ssl/i.test((c.field || '') + ' ' + (c.resourceName || '')) && c.risk !== 'low'; })[0];
    if (tlsChange) against.push({ text: 'A Helm change touched TLS settings (' + tlsChange.summary + '); check it as well.' });
    var okEdges = (h.edgesTo[comp.id] || []).filter(function (e) { return e.source !== 'logs' && e.calls > 0 && e.errors === 0; });
    if (okEdges.length) against.push({ text: 'Some callers still reach ' + comp.name + ' without errors (' + okEdges.map(function (e) { return h.comps[e.from] ? h.comps[e.from].name : e.from; }).join(', ') + '); those calls may predate the failure or skip TLS.' });

    var certName = cert && cert.name ? cert.name : comp.name + '-tls';
    var certNs = cert && cert.namespace ? cert.namespace : comp.namespace;
    var certComp = { cluster: comp.cluster, clusterKnown: comp.clusterKnown, namespace: certNs, type: comp.type };
    var checks = [
      { cmd: kc(certComp) + ' get certificate,certificaterequest', why: 'Is the cert-manager Certificate Ready, and are renewal requests failing.' },
      { cmd: kc(certComp) + ' describe certificate ' + certName, why: 'Not After, Renewal Time, failed issuance attempts and the last error.' },
      { cmd: 'cmctl status certificate ' + certName + ' -n ' + certNs + (comp.clusterKnown ? ' --context ' + comp.cluster : ''), why: 'cert-manager\'s own summary of the certificate, its request and issuer.' },
      { cmd: kc(certComp) + ' get secret ' + certName + " -o jsonpath='{.data.tls\\.crt}' | base64 -d | openssl x509 -noout -enddate -issuer", why: 'The expiry date of the certificate actually being served (the Secret named in spec.secretName).' },
      { cmd: kcCluster(comp) + ' -n cert-manager logs deploy/cert-manager --since=1h | grep ' + certName, why: 'Why renewal failed (issuer errors such as a Vault 403).' },
      { cmd: 'certmanager_certificate_expiration_timestamp_seconds{name="' + certName + '"} - time()', why: 'Prometheus query: seconds until (negative: since) expiry.' }
    ];
    out.push({
      category: 'tls-cert', componentId: comp.id, rule: expired.length || (anchor && anchor.type === 'event') ? 'certificate-expired' : 'tls-handshake-failing',
      title: (expired.length || anchor ? 'Expired certificate on ' : 'Encrypted connections (TLS handshakes) failing on ') + comp.name,
      summary: comp.name + inCl(comp) + ' presents a certificate its callers reject' + (anchor ? ': it expired ' + at(anchor.ts) : '') + '. Every Transport Layer Security (TLS) connection to it fails, so callers return errors.' +
        (cert && cert.issuerError ? ' cert-manager could not renew it because the issuer refused the request.' : ''),
      evidence: ev, against: against, nextChecks: checks, anchor: anchor, covers: [comp.id], cert: cert
    });
  }

  // ---- connection exhaustion ----------------------------------------------------------------------
  function ruleConnExhaustion(h, out) {
    var sigs = h.signals.filter(function (s) { return mechanism(s) === 'conn_exhaustion' && s.componentId && h.comps[s.componentId]; });
    if (!sigs.length) return;
    var byComp = WR.groupBy(sigs, 'componentId');
    var dbIds = Object.keys(byComp).filter(function (id) { return h.comps[id].type === 'datastore'; });
    var clientIds = Object.keys(byComp).filter(function (id) { return h.comps[id].type !== 'datastore'; });
    // A change that raises connection demand: more replicas (HPA max, replicas) or a bigger pool.
    var demand = h.changes.filter(function (c) {
      if (!c.componentId || !h.comps[c.componentId]) return false;
      if (c.category === 'hpa' && /maxreplicas|minreplicas/i.test(c.field || '') && Number(c.after) > Number(c.before)) return true;
      if (c.category === 'replicas' && Number(c.after) > Number(c.before)) return true;
      if ((c.category === 'env' || c.category === 'configmap') && /pool|max_?conn|maxconn|connections/i.test(c.field || '') && (c.before == null || Number(c.after) > Number(c.before))) return true;
      return false;
    });
    var targets = [];
    if (demand.length) targets = WR.uniq(demand.map(function (c) { return c.componentId; }));
    else if (clientIds.length) targets = [clientIds.sort(function (a, b) { return byComp[b].length - byComp[a].length || (a < b ? -1 : 1); })[0]];
    else targets = [dbIds[0]];
    // The same app in another cluster with the same symptom is folded in later by the merge step;
    // emit one candidate per client component so each cluster's evidence is kept.
    clientIds.forEach(function (id) { if (targets.indexOf(id) < 0 && targets.some(function (t) { return h.comps[t].name === h.comps[id].name; })) targets.push(id); });

    targets.forEach(function (tid) {
      var comp = h.comps[tid];
      var ev = [], against = [], anchor = null;
      var own = byComp[tid] || [];
      if (own.length) {
        // Quote the line that says it best; date it by the earliest one.
        var f = preferText(own, /pool|Hikari|not available|too many/i);
        var f0 = firstTimed(own);
        ev.push(evSig(f, comp.name + ' cannot get database connections ' + times(own.length) + ' (first ' + at(f0 && f0.ts) + '): ' + quoteAt(f.text, /pool|Hikari|not available|too many|connection slots/i, 110) + '.', 0.4));
      }
      // Server side: the database refusing clients. Prefer one in the same cluster.
      var dbs = dbIds.slice().sort(function (a, b) { return (h.comps[b].cluster === comp.cluster) - (h.comps[a].cluster === comp.cluster) || byComp[b].length - byComp[a].length; });
      var covers = [tid];
      if (dbs.length) {
        var db = h.comps[dbs[0]];
        var dsig = preferText(byComp[db.id], /too many clients|remaining connection slots|max_connections/i);
        ev.push(evSig(dsig, 'The database ' + db.name + ' (' + db.cluster + ') is refusing new connections ' + times(byComp[db.id].length) + ': ' + quoteAt(dsig.text, /too many|remaining connection|max_connections|FATAL/i, 110) + '.', 0.35));
        covers = covers.concat(dbs);
      }
      // Datastores this component calls on failing edges are the same database seen from traces.
      (h.edgesFrom[tid] || []).forEach(function (e) { if (h.comps[e.to] && h.comps[e.to].type === 'datastore' && e.status !== 'ok') covers.push(e.to); });
      var dch = demand.filter(function (c) { return c.componentId === tid; })[0] ||
        demand.filter(function (c) { return h.comps[c.componentId].name === comp.name; })[0];
      if (dch) {
        ev.push(evChange(dch, 'Helm raised the connection demand: ' + dch.summary + (dch.componentId !== tid ? ' (in ' + h.comps[dch.componentId].cluster + ')' : '') + '. Each pod opens its own pool, so more pods means more connections.', 0.35));
        var t = changeTime(h, dch);
        if (t != null) anchor = { ts: t, type: 'change' };
        else against.push({ text: 'No deploy time found — paste `helm history` or set Deployed at.' });
      }
      var maxed = sigsOf(h, tid, ['hpa_maxed']);
      if (maxed.length) ev.push(evSig(maxed[0], 'The HorizontalPodAutoscaler for ' + comp.name + ' is at its maximum, so the pod count (and the connection count) is as high as it can go.', 0.15));
      var others = clientIds.filter(function (id) { return id !== tid && h.comps[id].name !== comp.name; });
      if (others.length) {
        var o0 = firstTimed(byComp[others[0]]);
        ev.push(evSig(o0, 'Other clients of the same database fail the same way (' + WR.uniq(others.map(function (id) { return h.comps[id].name; })).join(', ') + ').', 0.1));
      }
      var connAlerts = h.signals.filter(function (s) { return s.source === 'alerts' && s.kind === 'conn_exhaustion'; });
      if (connAlerts.length) ev.push(evSig(connAlerts[0], 'Alert ' + (connAlerts[0].attrs.alertname || '') + ' is firing.', 0.15));
      if (!dch) against.push({ text: 'No change raised replicas or pool size; a slow query, a lock or a connection leak can also exhaust the pool.' });
      var dead = h.signals.filter(function (s) { return s.kind === 'db_error' && /deadlock|lock wait/i.test(s.text || ''); });
      if (dead.length) against.push({ text: 'Lock waits or deadlocks also appear; long transactions may be holding connections.' });

      var checks = [];
      var db0 = dbs.length ? h.comps[dbs[0]] : null;
      var dbPod = db0 ? pickPod(h, db0, null) : null;
      if (db0 && dbPod) checks.push({ cmd: kc(db0) + ' exec ' + dbPod + ' -- psql -U postgres -c "SELECT application_name, state, count(*) FROM pg_stat_activity GROUP BY 1, 2 ORDER BY 3 DESC;"', why: 'Who holds the connections, and how many are idle.' });
      if (db0 && dbPod) checks.push({ cmd: kc(db0) + ' exec ' + dbPod + ' -- psql -U postgres -c "SHOW max_connections;"', why: 'The server limit the pools add up against.' });
      checks.push({ cmd: kc(comp) + ' get hpa', why: 'Current and maximum replicas per autoscaler.' });
      checks.push({ cmd: kc(comp) + ' get ' + workloadRef(comp) + " -o jsonpath='{.spec.replicas}'", why: 'Replicas right now (multiply by the pool size per pod).' });
      checks.push({ cmd: 'sum by (datname, state) (pg_stat_activity_count)', why: 'Prometheus query (postgres_exporter): connections by database and state.' });
      checks.push({ cmd: 'max(pg_settings_max_connections)', why: 'Prometheus query: the configured connection limit.' });
      if (h.signals.some(function (s) { return /hikari/i.test(s.text || ''); })) checks.push({ cmd: 'sum by (pod) (hikaricp_connections_pending{namespace="' + comp.namespace + '"})', why: 'Prometheus query (Micrometer): threads waiting for a pooled connection per pod.' });

      out.push({
        category: 'connection-exhaustion', componentId: tid, rule: dch ? 'pool-demand-after-change' : 'pool-exhausted',
        title: (dch ? 'More ' + comp.name + ' pods exhaust the database connections' : comp.name + ' runs out of database connections'),
        summary: (dch ? 'The latest release lets ' + comp.name + ' scale further (' + dch.summary + '). ' : '') +
          'Every pod keeps its own connection pool, so the total wanted exceeds what ' + (db0 ? db0.name : 'the database') + ' allows; new connections are refused and requests fail or time out.',
        evidence: ev, against: against, nextChecks: checks, anchor: anchor, covers: WR.uniq(covers), demandChange: dch || null
      });
    });
  }

  // ---- image pull ------------------------------------------------------------------------------
  // The pull error says why: the tag is missing, the pull secret is refused, or the registry cannot
  // be reached. Workloads broken by the same image change (one values key such as global.image.tag)
  // are one cause, not one per workload.
  var PULL_REASONS = [
    { re: /NotFound|not found|manifest unknown|does not exist|no such manifest/i, key: 'missing', text: 'the registry says the tag does not exist' },
    { re: /unauthori[sz]ed|denied|forbidden|authentication required|\b40[13]\b|no basic auth credentials/i, key: 'auth', text: 'the registry refuses the pull credentials (pull secret)' },
    { re: /i\/o timeout|deadline exceeded|no such host|connection refused|TLS handshake timeout|dial tcp/i, key: 'unreachable', text: 'the registry cannot be reached' }
  ];
  function pullReason(sigs) {
    for (var i = 0; i < sigs.length; i++) {
      var t = String(sigs[i].text || '') + ' ' + String(sigs[i].raw || '');
      if (!/rpc error|failed to pull|failed to resolve|manifest|unauthori|denied|forbidden|timeout|no such host/i.test(t)) continue;
      for (var j = 0; j < PULL_REASONS.length; j++) if (PULL_REASONS[j].re.test(t)) return { sig: sigs[i], key: PULL_REASONS[j].key, text: PULL_REASONS[j].text };
    }
    return null;
  }
  // "rpc error: code = NotFound … invoice-api:v4.12.0: not found": the code and the decisive tail.
  function pullQuote(sig) {
    var t = String(sig.text || '').replace(/\s+/g, ' ').trim();
    var code = /rpc error: code = \w+/.exec(t);
    var tail = t.length > 90 ? '…' + t.slice(-90) : t;
    return quote((code && t.indexOf(code[0]) < t.length - 90 ? code[0] + ' ' : '') + tail, 200);
  }
  function tagOf(ref) { var m = /:([^:@\/]+)$/.exec(String(ref || '')); return m ? m[1] : (/^[\w.-]+$/.test(String(ref || '')) ? String(ref) : null); }

  function ruleImagePull(h, out) {
    var groups = [], byKey = {};
    h.compList.forEach(function (comp) {
      var pulls = sigsOf(h, comp.id, ['image_pull']);
      if (!pulls.length) return;
      var img = (h.changesByComp[comp.id] || []).filter(function (c) { return c.category === 'image' && /containers\[/.test(c.field || ''); })[0] ||
        (h.changesByComp[comp.id] || []).filter(function (c) { return c.category === 'image'; })[0];
      var key = img ? (img.release || '') + '|' + comp.cluster + '|' + tagOf(img.before) + '>' + tagOf(img.after) : comp.id;
      var g = byKey[key];
      if (!g) { g = byKey[key] = { comps: [], pulls: [], imgs: [], key: key }; groups.push(g); }
      g.comps.push(comp); g.pulls = g.pulls.concat(pulls); if (img) g.imgs.push(img);
    });
    groups.forEach(function (g) {
      // The user-facing (or noisiest) workload leads; the others are named with it.
      g.comps.sort(function (a, b) { return (b.userFacing ? 1 : 0) - (a.userFacing ? 1 : 0) || sigsOf(h, b.id, ['image_pull']).length - sigsOf(h, a.id, ['image_pull']).length; });
      var comp = g.comps[0], img = g.imgs.filter(function (c) { return c.componentId === comp.id; })[0] || g.imgs[0] || null;
      var names = g.comps.map(function (c) { return c.name; });
      var who = names.length > 1 ? names.slice(0, -1).join(', ') + ' and ' + names[names.length - 1] : names[0];
      var ev = [], against = [], anchor = null;
      var why = pullReason(g.pulls);
      var f = why ? why.sig : firstTimed(g.pulls);
      ev.push(evSig(f, 'Pods of ' + who + ' cannot pull ' + (names.length > 1 ? 'their images ' : 'their image ') + times(g.pulls.length) + (why ? '; ' + why.text : '') + ': ' + (why ? pullQuote(f) : quote(f.text, 100)) + '.', 0.55));
      g.comps.slice(1).forEach(function (c) {
        var ps = sigsOf(h, c.id, ['image_pull']);
        ev.push(evSig(firstTimed(ps), c.name + ' fails the same way (' + plural(ps.length, 'pull error') + ').', 0.1));
      });
      var mismatch = null;
      if (img) {
        ev.push(evChange(img, 'The image changed in the latest release: ' + img.summary + (g.imgs.length > 1 ? ' (and the same tag for ' + names.slice(1).join(', ') + ')' : '') + '.', 0.35));
        var t = changeTime(h, img);
        if (t != null) anchor = { ts: t, type: 'change' };
        // The new tag next to the chart's app version: "v4.12.0" against "4.12.0" is a typo.
        var dep = (h.deploys || []).filter(function (d) { return d.release && d.release === img.release; })[0];
        var nt = tagOf(img.after);
        if (dep && dep.appTo && nt && nt !== dep.appTo && nt.replace(/^v/i, '') === String(dep.appTo).replace(/^v/i, '')) {
          mismatch = { tag: nt, app: dep.appTo };
          ev.push(evChange(img, 'The new tag ' + nt + ' differs from the chart\'s app version ' + dep.appTo + ' only by a "v": likely a typo in the values.', 0.1));
        }
      } else against.push({ text: 'No image change in the pasted diff; expired registry credentials, a deleted tag or a registry outage can also cause this.' });
      // The old ReplicaSet scaled to 0 while the new pods cannot pull: the Recreate strategy (or a
      // 100 % maxUnavailable) stopped every old pod first, so that workload is down, not degraded.
      var down = g.comps.filter(function (c) {
        return sigsOf(h, c.id, ['rollout']).some(function (r) { return r.attrs && r.attrs.direction === 'down' && r.attrs.replicas === 0; });
      });
      down.forEach(function (c) {
        var r = sigsOf(h, c.id, ['rollout']).filter(function (x) { return x.attrs && x.attrs.direction === 'down' && x.attrs.replicas === 0; })[0];
        ev.push(evSig(r, c.name + '\'s old pods were stopped before the new ones could start (' + quote(r.text, 90) + '), so it has no running pods.', 0.05));
      });
      var pod = pickPod(h, comp, ['image_pull']);
      var checks = [];
      if (pod) checks.push({ cmd: kc(comp) + ' describe pod ' + pod, why: why ? 'The pull events and full error (' + why.text + ').' : 'The exact pull error (not found, unauthorized, timeout).' });
      checks.push({ cmd: kc(comp) + ' get ' + workloadRef(comp) + " -o jsonpath='{.spec.template.spec.containers[*].image}'", why: 'The image reference the pods are trying to pull.' });
      if (!why || why.key === 'auth') checks.push({ cmd: kc(comp) + ' get ' + workloadRef(comp) + " -o jsonpath='{.spec.template.spec.imagePullSecrets}'", why: 'Which pull secret is used.' });
      if (img && img.after) checks.push({ cmd: 'docker manifest inspect ' + img.after, why: 'Does that tag exist in the registry.' });
      if (mismatch && img && img.after) checks.push({ cmd: 'docker manifest inspect ' + img.after.replace(/:[^:@\/]+$/, ':' + mismatch.app), why: 'Does the tag without the "v" exist (the fix-forward).' });
      g.comps.slice(1).forEach(function (c) { checks.push({ cmd: kc(c) + ' get ' + workloadRef(c) + ' -o wide', why: 'How many ' + c.name + ' pods are ready; a workload with none is down, not degraded.' }); });
      out.push({ category: 'image-pull', componentId: comp.id, rule: img ? 'bad-image-reference' : 'image-pull-failing',
        title: who + (names.length > 1 ? ' cannot pull their container images' : ' cannot pull its container image'),
        summary: 'New pods of ' + who + ' never start because the image cannot be pulled' + (why ? ' (' + why.text + ')' : '') + (img ? ' after the image changed (' + img.summary + ')' : '') + '.' +
          (mismatch ? ' The new tag ' + mismatch.tag + ' does not match the app version ' + mismatch.app + '; the "v" looks like a typo.' : '') +
          (down.length ? ' ' + down.map(function (c) { return c.name; }).join(' and ') + (down.length > 1 ? ' are' : ' is') + ' fully down, not degraded: its old pods were stopped first, as the Recreate strategy does.' : ''),
        evidence: ev, against: against, nextChecks: checks, anchor: anchor, covers: g.comps.map(function (c) { return c.id; }),
        _imageChanges: g.imgs.map(function (c) { return c.id; }), _tagFix: mismatch });
    });
  }

  // ---- configuration errors -------------------------------------------------------------------------
  function ruleConfigError(h, out) {
    h.compList.forEach(function (comp) {
      var cfg = sigsOf(h, comp.id, ['config_error']);
      if (!cfg.length) return;
      var ev = [], against = [], anchor = null;
      var f = firstTimed(cfg);
      ev.push(evSig(f, comp.name + ' fails on its configuration ' + times(cfg.length) + ': ' + quote(f.text, 100) + '.', 0.5));
      var ch = (h.changesByComp[comp.id] || []).filter(function (c) { return /^(configmap|env|secret)$/.test(c.category); })
        .sort(function (a, b) { return (a.risk === 'high' ? 0 : 1) - (b.risk === 'high' ? 0 : 1); })[0];
      if (ch) {
        ev.push(evChange(ch, 'Configuration changed in the latest release: ' + ch.summary + '.', 0.35));
        var t = changeTime(h, ch);
        if (t != null) anchor = { ts: t, type: 'change' };
      } else against.push({ text: 'No ConfigMap, Secret or environment change in the pasted diff; the referenced object may have been deleted outside Helm.' });
      var pod = pickPod(h, comp, ['config_error']);
      var checks = [];
      if (pod) checks.push({ cmd: kc(comp) + ' describe pod ' + pod, why: 'Which ConfigMap, Secret or key is missing.' });
      checks.push({ cmd: kc(comp) + ' get configmap,secret', why: 'Do the referenced objects exist in this namespace.' });
      checks.push({ cmd: kc(comp) + ' get ' + workloadRef(comp) + " -o yaml | grep -A3 -E 'configMapKeyRef|secretKeyRef|configMapRef|secretRef'", why: 'Every ConfigMap and Secret reference in the pod template.' });
      out.push({ category: 'config-error', componentId: comp.id, rule: ch ? 'config-change-broke-startup' : 'config-missing',
        title: comp.name + ' cannot start: configuration error', summary: comp.name + ' pods fail at start-up because a referenced ConfigMap, Secret or setting is missing or invalid.',
        evidence: ev, against: against, nextChecks: checks, anchor: anchor, covers: [comp.id] });
    });
  }

  // ---- probes ---------------------------------------------------------------------------------------
  function ruleProbe(h, out) {
    h.compList.forEach(function (comp) {
      var probes = sigsOf(h, comp.id, ['probe_failed']);
      if (!probes.length) return;
      var ev = [], against = [], anchor = null;
      var f = firstTimed(probes);
      ev.push(evSig(f, 'Health probes fail on ' + comp.name + ' ' + times(probes.length) + ': ' + quote(f.text, 90) + '.', 0.25));
      var pch = (h.changesByComp[comp.id] || []).filter(function (c) { return c.category === 'probe'; });
      var tight = pch.filter(function (c) { return c.risk === 'high'; })[0] || pch[0];
      if (tight) {
        ev.push(evChange(tight, 'Probe settings changed: ' + tight.summary + '.', tight.risk === 'high' ? 0.45 : 0.25));
        var t = changeTime(h, tight);
        if (t != null) anchor = { ts: t, type: 'change' };
      } else against.push({ text: 'Probe settings did not change; failing probes are usually a symptom of the container being slow, overloaded or restarting.' });
      var other = sigsOf(h, comp.id, ['oom_killed', 'crash_loop', 'panic', 'config_error', 'conn_exhaustion']);
      if (other.length) against.push({ text: 'Health checks fail while the container is also ' + WR.uniq(other.map(function (s) { return plainKind(s.kind); })).slice(0, 3).join(', ') + ' — the probe failures look like a symptom here.' });
      var pod = pickPod(h, comp, ['probe_failed']);
      var checks = [];
      if (pod) checks.push({ cmd: kc(comp) + ' describe pod ' + pod, why: 'Probe failure messages and the probe settings in effect.' });
      // Select the container by name: containers[0] is often a sidecar (istio-proxy, a log shipper).
      var ctrSel = '{.spec.template.spec.containers[?(@.name=="' + pickContainer(h, comp) + '")]';
      checks.push({ cmd: kc(comp) + ' get ' + workloadRef(comp) + " -o jsonpath='" + ctrSel + ".readinessProbe}'", why: 'Readiness probe path, timeout and thresholds.' });
      checks.push({ cmd: kc(comp) + ' get ' + workloadRef(comp) + " -o jsonpath='" + ctrSel + ".livenessProbe}'", why: 'Liveness probe settings (a tight liveness probe restarts slow pods).' });
      out.push({ category: 'probe-misconfig', componentId: comp.id, rule: tight ? 'probe-tightened' : 'probe-failing',
        title: (tight ? 'Tighter health probes are failing ' : 'Health probes are failing on ') + comp.name,
        summary: tight ? 'The release changed ' + comp.name + '\'s probes (' + tight.summary + '); healthy-but-slow pods now fail them and are taken out of service or restarted.' : comp.name + ' fails its readiness or liveness probes.',
        evidence: ev, against: against, nextChecks: checks, anchor: anchor, covers: [comp.id] });
    });
  }

  // ---- nodes ----------------------------------------------------------------------------------------
  function ruleNodePressure(h, out) {
    var nodeSigs = h.signals.filter(function (s) { return /^(node_not_ready|node_pressure)$/.test(s.kind) && s.componentId && h.comps[s.componentId]; });
    var evict = h.signals.filter(function (s) { return s.kind === 'evicted'; });
    if (!nodeSigs.length && !evict.length) return;
    var byNode = WR.groupBy(nodeSigs, 'componentId');
    var nodeIds = Object.keys(byNode).sort(function (a, b) { return byNode[b].length - byNode[a].length || (a < b ? -1 : 1); });
    var comp = nodeIds.length ? h.comps[nodeIds[0]] : (evict[0] && h.comps[evict[0].componentId]) || null;
    if (!comp) return;
    var ev = [], against = [];
    if (nodeIds.length) {
      var f = firstTimed(byNode[nodeIds[0]]);
      ev.push(evSig(f, 'Node ' + comp.name + ' reports ' + quote(f.text, 80) + (nodeIds.length > 1 ? ' (' + plural(nodeIds.length, 'node') + ' affected)' : '') + '.', 0.45));
    }
    if (evict.length) {
      var fe = firstTimed(evict);
      ev.push(evSig(fe, plural(evict.length, 'pod') + ' evicted: ' + quote(fe.text, 90) + '.', 0.25));
    }
    var alerts = nodeSigs.filter(function (s) { return s.source === 'alerts'; });
    if (alerts.length) ev.push(evSig(alerts[0], 'Alert ' + (alerts[0].attrs.alertname || '') + ' is firing.', 0.2));
    if (!nodeIds.length) against.push({ text: 'Evictions without a node condition in the paste; a pod over its ephemeral-storage limit is evicted the same way.' });
    var isNode = comp.type === 'node';
    var checks = [
      { cmd: kcCluster(comp) + ' describe node ' + (isNode ? comp.name : '<node>'), why: 'Conditions (MemoryPressure, DiskPressure, Ready) and allocated resources.' },
      { cmd: kcCluster(comp) + ' top node', why: 'Memory and CPU use per node (needs metrics-server).' },
      { cmd: kcCluster(comp) + ' get pods -A --field-selector spec.nodeName=' + (isNode ? comp.name : '<node>') + ' -o wide', why: 'What runs on the node and was affected.' },
      { cmd: 'kube_node_status_condition{condition=~"Ready|MemoryPressure|DiskPressure|PIDPressure", status="true"}', why: 'Prometheus query (kube-state-metrics): node conditions over time.' }
    ];
    out.push({ category: 'node-pressure', componentId: comp.id, rule: nodeIds.length ? 'node-condition' : 'evictions',
      title: (isNode ? 'Node ' + comp.name : comp.name) + ' is under resource pressure', summary: 'A node ran short of memory, disk or process ids (or stopped reporting), so the kubelet evicted or lost pods running on it.',
      evidence: ev, against: against, nextChecks: checks, anchor: null, covers: [comp.id] });
  }

  // ---- scheduling / capacity -------------------------------------------------------------------------
  function ruleScheduling(h, out) {
    h.compList.forEach(function (comp) {
      if (comp.type === 'node') return;
      var sched = sigsOf(h, comp.id, ['scheduling_failed']);
      var pvc = sigsOf(h, comp.id, ['pvc_pending']);
      var maxed = sigsOf(h, comp.id, ['hpa_maxed']);
      if (!sched.length && !pvc.length) return;
      var ev = [], against = [], anchor = null;
      // One Pending pod is weak evidence; several make a capacity problem likely.
      if (sched.length) { var f = firstTimed(sched); ev.push(evSig(f, plural(sched.length, 'pod') + ' of ' + comp.name + ' cannot be scheduled: ' + quote(f.text, 90) + '.', Math.min(0.4, 0.2 + 0.05 * (sched.length - 1)))); }
      if (pvc.length) { var p = firstTimed(pvc); ev.push(evSig(p, 'Volumes for ' + comp.name + ' are not bound: ' + quote(p.text, 90) + '.', 0.4)); }
      if (maxed.length) ev.push(evSig(maxed[0], 'The autoscaler for ' + comp.name + ' is at its maximum.', 0.2));
      var rch = (h.changesByComp[comp.id] || []).filter(function (c) { return c.category === 'hpa' || c.category === 'replicas'; })[0];
      if (rch) {
        ev.push(evChange(rch, 'Replica settings changed: ' + rch.summary + '.', 0.2));
        var t = changeTime(h, rch);
        if (t != null) anchor = { ts: t, type: 'change' };
      }
      if (!sigsOf(h, comp.id, null, function (s) { return h.isError(s); }).length) against.push({ text: 'Pending pods alone do not fail requests while the running pods are healthy.' });
      if (rch && Number(rch.after) > Number(rch.before)) against.push({ text: 'The release raised the replica ceiling (' + rch.summary + '); pods waiting for room are a side effect of scaling out further, not a cause of the errors.' });
      var checks = [
        { cmd: kc(comp) + ' get events --field-selector reason=FailedScheduling --sort-by=.lastTimestamp', why: 'Why the scheduler rejects the pods (insufficient CPU or memory, taints, affinity).' },
        { cmd: kcCluster(comp) + " describe nodes | grep -A 8 'Allocated resources'", why: 'Requested versus allocatable resources per node.' }
      ];
      if (pvc.length) checks.push({ cmd: kc(comp) + ' get pvc', why: 'Which claims are Pending and on which storage class.' });
      if (maxed.length) checks.push({ cmd: kc(comp) + ' describe hpa ' + comp.name, why: 'Autoscaler conditions (ScalingLimited) and recent scaling events.' });
      out.push({ category: 'scheduling-capacity', componentId: comp.id, rule: pvc.length ? 'volume-pending' : 'unschedulable',
        title: comp.name + ' cannot get enough capacity', summary: 'New ' + comp.name + ' pods cannot be placed (not enough node capacity, a quota or an unbound volume), so the workload cannot scale to meet load.',
        evidence: ev, against: against, nextChecks: checks, anchor: anchor, covers: [comp.id] });
    });
  }

  // ---- network policy ----------------------------------------------------------------------------------
  function ruleNetworkPolicy(h, out) {
    var np = h.changes.filter(function (c) { return c.category === 'networkpolicy'; });
    if (!np.length) return;
    np.forEach(function (ch) {
      var ns = ch.namespace;
      var blocked = h.signals.filter(function (s) {
        if (!/^(conn_refused|timeout|span_error)$/.test(s.kind)) return false;
        var tgt = s.attrs && s.attrs.targetId && h.comps[s.attrs.targetId];
        var own = h.comps[s.componentId];
        return (tgt && tgt.namespace === ns) || (own && own.namespace === ns);
      });
      var comp = (ch.componentId && h.comps[ch.componentId]) || (blocked[0] && h.comps[(blocked[0].attrs && blocked[0].attrs.targetId) || blocked[0].componentId]);
      if (!comp) return;
      var ev = [evChange(ch, 'A NetworkPolicy changed: ' + ch.summary + '.', 0.4)], against = [], anchor = null;
      if (blocked.length) { var f = firstTimed(blocked); ev.push(evSig(f, plural(blocked.length, 'connection failure') + ' to or from namespace ' + ns + ': ' + quote(f.text, 90) + '.', 0.35)); }
      else against.push({ text: 'No connection timeouts or refusals involve namespace ' + ns + '.' });
      var t = changeTime(h, ch);
      if (t != null) anchor = { ts: t, type: 'change' };
      out.push({ category: 'network-policy', componentId: comp.id, rule: 'networkpolicy-change',
        title: 'NetworkPolicy change blocks traffic to ' + comp.name, summary: 'A NetworkPolicy in ' + ns + ' changed, and connections to or from it now time out or are refused.',
        evidence: ev, against: against, anchor: anchor, covers: [comp.id],
        nextChecks: [
          { cmd: kc({ cluster: comp.cluster, clusterKnown: comp.clusterKnown, namespace: ns }) + ' get networkpolicy', why: 'Policies that select pods in this namespace.' },
          { cmd: kc({ cluster: comp.cluster, clusterKnown: comp.clusterKnown, namespace: ns }) + ' describe networkpolicy ' + (ch.resourceName || '<policy>'), why: 'Allowed ingress and egress after the change.' },
          { cmd: kc(comp) + ' run np-check --rm -it --restart=Never --image=busybox:1.36 -- nc -zv -w 3 ' + comp.name + ' <port>', why: 'Can a pod in the namespace open the connection.' }
        ] });
    });
  }

  // ---- rate limiting / throttling -------------------------------------------------------------------
  function ruleRateLimit(h, out) {
    h.compList.forEach(function (comp) {
      var rl = sigsOf(h, comp.id, ['http_429', 'throttled'], function (s) { return !(s.kind === 'throttled' && /cpu/i.test((s.text || '') + ((s.attrs && s.attrs.alertname) || ''))); });
      if (!rl.length) return;
      var ev = [], against = [];
      var f = firstTimed(rl);
      var tgt = f.attrs && f.attrs.targetId && h.comps[f.attrs.targetId];
      ev.push(evSig(f, comp.name + ' is rate limited ' + times(rl.length) + (tgt ? ' by ' + tgt.name : '') + ': ' + quote(f.text, 90) + '.', 0.45));
      var alerts = rl.filter(function (s) { return s.source === 'alerts'; });
      if (alerts.length) ev.push(evSig(alerts[0], 'Alert ' + (alerts[0].attrs.alertname || '') + ' is firing.', 0.2));
      if (rl.length < 3) against.push({ text: 'Only a few rate-limit responses; they may be ordinary back-pressure.' });
      out.push({ category: 'rate-limiting', componentId: comp.id, rule: 'rate-limited',
        title: comp.name + ' is being rate limited', summary: comp.name + ' exceeds a request quota' + (tgt ? ' at ' + tgt.name : '') + ' and gets 429 Too Many Requests or throttling responses.',
        evidence: ev, against: against, anchor: null, covers: [comp.id],
        nextChecks: [
          { cmd: kc(comp) + ' logs ' + workloadRef(comp) + " --since=30m | grep -c -E ' 429 |Too Many Requests|rate limit'", why: 'How often the limit is hit.' },
          { cmd: 'sum(rate(http_requests_total{namespace="' + comp.namespace + '", code="429"}[5m]))', why: 'Prometheus query: 429 rate (metric name depends on your instrumentation).' }
        ] });
    });
  }

  // ---- dependency failure: the deepest failing callee ------------------------------------------------
  function ruleDependency(h, out, covered) {
    h.compList.forEach(function (comp) {
      if (!comp.deepest) return;
      // A specific mechanism on this component already explains it; only external and datastore
      // dependencies get a dependency hypothesis next to one (shown lower by the demotion step).
      if (covered[comp.id] && comp.type !== 'external' && comp.type !== 'datastore') return;
      var inEdges = (h.edgesTo[comp.id] || []).filter(function (e) { return e.status === 'failing'; });
      if (!inEdges.length) return;
      var ev = [], against = [];
      var traced = inEdges.filter(function (e) { return e.source !== 'logs'; });
      if (traced.length) {
        var e0 = traced.slice().sort(function (a, b) { return (b.errors || 0) - (a.errors || 0); })[0];
        // Cite something the UI can jump to: the caller's failed span to it, else any caller signal
        // naming it, else the caller's first error.
        var callerSig = h.signals.filter(function (s) { return s.source === 'traces' && s.componentId === e0.from && s.attrs && s.attrs.targetId === comp.id; })[0] ||
          h.signals.filter(function (s) { return s.componentId === e0.from && s.attrs && s.attrs.targetId === comp.id; })[0] ||
          h.signals.filter(function (s) { return s.source === 'traces' && s.componentId === e0.from && s.kind === 'span_error'; })[0] ||
          (h.comps[e0.from] && h.sigById[h.comps[e0.from].firstErrorSignalId]) || null;
        ev.push(evSig(callerSig || null, 'Calls into ' + comp.name + ' fail: ' + traced.map(function (e) { return (h.comps[e.from] ? h.comps[e.from].name : e.from) + ' ' + e.errors + ' of ' + e.calls; }).join(', ') + '.', 0.35));
      }
      var named = h.signals.filter(function (s) { return s.attrs && s.attrs.targetId === comp.id && s.source === 'logs' && WR.sevRank(s.severity) >= 2; });
      if (named.length) { var n0 = firstTimed(named); ev.push(evSig(n0, 'Callers log errors naming ' + comp.name + ' ' + times(named.length) + ': ' + quote(n0.text, 90) + '.', 0.3)); }
      var own = sigsOf(h, comp.id, null, function (s) { return h.isError(s); });
      if (own.length) { var o0 = firstTimed(own); ev.push(evSig(o0, comp.name + ' reports its own errors ' + times(own.length) + ': ' + quote(o0.text, 90) + '.', 0.2)); }
      else against.push({ text: 'No errors from ' + comp.name + ' itself in the paste; the network path or the callers\' settings may be at fault.' });
      if (comp.type === 'external') against.push({ text: comp.name + ' is outside the cluster; check its status page or provider before changing anything here.' });
      var checks = [];
      if (comp.type === 'external') {
        checks.push({ cmd: kcCluster(comp) + " run net-check --rm -it --restart=Never --image=curlimages/curl:8.10.1 -- curl -sS -o /dev/null -w '%{http_code} %{time_total}s\\n' https://" + comp.name + '/', why: 'Can the cluster reach it, and how fast does it answer.' });
      } else {
        checks.push({ cmd: kc(comp) + ' get endpointslices -l kubernetes.io/service-name=' + comp.name, why: 'Are there ready endpoints behind the Service.' });
        checks.push({ cmd: kc(comp) + ' get pods -o wide | grep ' + comp.name, why: 'Pod status, restarts and nodes.' });
        if (comp.type !== 'datastore') checks.push({ cmd: kc(comp) + ' logs ' + workloadRef(comp) + ' --since=30m --tail=100', why: 'Its own errors around the first failure.' });
      }
      out.push({ category: 'dependency-failure', componentId: comp.id, rule: 'deepest-failing-dependency',
        title: comp.name + ' is the failing dependency', summary: 'Callers fail when they call ' + comp.name + ', and nothing ' + comp.name + ' calls is failing, so the failure starts there.',
        evidence: ev, against: against, nextChecks: checks, anchor: null, covers: [comp.id] });
    });
  }

  // ---- fallback: failing with no recognised pattern ----------------------------------------------------
  function ruleUnknown(h, out) {
    var failing = h.compList.filter(function (c) { return isFailingStatus(c.status) && c.type !== 'node'; })
      .sort(function (a, b) { return (b.counts.error || 0) - (a.counts.error || 0) || (a.id < b.id ? -1 : 1); });
    if (!failing.length) return;
    var comp = failing[0];
    var errs = sigsOf(h, comp.id, null, function (s) { return h.isError(s); });
    var f = firstTimed(errs);
    var ev = [];
    if (f) ev.push(evSig(f, comp.name + ' logs ' + plural(errs.length, 'error') + ', first ' + at(f.ts) + ': ' + quote(f.text, 100) + '.', 0.3));
    out.push({ category: 'unknown', componentId: comp.id, rule: 'unrecognised-errors',
      title: comp.name + ' is failing for a reason the rules do not recognise', summary: comp.name + ' has the most errors, but they match no known failure pattern. Read its first errors and recent changes.',
      evidence: ev, against: [{ text: 'No rule matched; this is only "where the errors are", not why.' }], anchor: null, covers: [comp.id],
      nextChecks: [{ cmd: kc(comp) + ' logs ' + workloadRef(comp) + ' --since=30m --tail=200', why: 'The first errors in full.' }, { cmd: kc(comp) + ' get events --sort-by=.lastTimestamp', why: 'Recent Kubernetes events in the namespace.' }] });
  }

  function dedupeEvidence(list) {
    var best = {}, order = [];
    list.forEach(function (e, i) {
      var k = e.signalId ? 's:' + e.signalId : e.changeId ? 'c:' + e.changeId : 'i:' + i;
      if (!best[k]) { best[k] = e; order.push(k); }
      else if (e.weight > best[k].weight) best[k] = e;
    });
    return order.map(function (k) { return best[k]; });
  }

  // -------------------------------------------------------------------------------------------
  // Scoring
  // -------------------------------------------------------------------------------------------
  function score(c, h) {
    var miss = 1;
    c.evidence.forEach(function (e) { miss *= 1 - WR.clamp(e.weight, 0, 0.95); });
    var base = 1 - miss;
    var comp = h.comps[c.componentId];
    var firstErr = comp && comp.firstErrorTs != null ? comp.firstErrorTs : h.firstAnomaly;
    var mult = 1, notes = [];
    if (c.anchor && c.anchor.ts != null && firstErr != null) {
      var d = firstErr - c.anchor.ts;
      if (d >= -MIN && d <= 60 * MIN) { mult *= 1.15; notes.push('timing'); }
      else if (d < -MIN && c.anchor.type === 'change') { mult *= 0.6; notes.push('errors-before-change'); }
    }
    if (comp && comp.deepest) { mult *= 1.1; notes.push('deepest'); }
    var raw = base * mult;
    var conf = Math.min(0.95, raw);
    if (conf > 0.5 && c.evidence.length < 2) conf = 0.5;
    c.raw = raw;
    c.base = base;
    c.multipliers = notes;
    c.confidence = Math.round(conf * 1000) / 1000;
    return c;
  }

  /*
   * One mechanism seen in several clusters (orders-api exhausting connections in us-east and
   * us-west) is one hypothesis: keep the strongest, add "same pattern in …" evidence, list the rest.
   */
  function mergeAcrossClusters(cands, h) {
    var groups = {}, order = [];
    cands.forEach(function (c) {
      var comp = h.comps[c.componentId];
      var k = c.category + '|' + (comp ? comp.type + ':' + comp.name : c.componentId);
      if (!groups[k]) { groups[k] = []; order.push(k); }
      groups[k].push(c);
    });
    var out = [];
    order.forEach(function (k) {
      var g = groups[k].sort(function (a, b) { return b.raw - a.raw || (a.componentId < b.componentId ? -1 : 1); });
      var main = g[0];
      main.relatedComponentIds = [];
      g.slice(1).forEach(function (o) {
        var oc = h.comps[o.componentId];
        if (!oc || (h.comps[main.componentId] && oc.cluster === h.comps[main.componentId].cluster)) { out.push(o); return; }
        main.relatedComponentIds.push(o.componentId);
        var firstEv = o.evidence.filter(function (e) { return e.signalId; })[0];
        var fallback = !firstEv && oc.firstErrorSignalId ? h.sigById[oc.firstErrorSignalId] : null;
        main.evidence.push({
          signalId: firstEv ? firstEv.signalId : fallback ? fallback.id : null, changeId: null,
          text: 'Same pattern in ' + oc.cluster + ': ' + (firstEv ? firstEv.text : o.title),
          weight: 0.1, source: firstEv ? firstEv.source : fallback ? fallback.source : null, line: firstEv ? firstEv.line : fallback ? fallback.line : null
        });
        main.covers = WR.uniq((main.covers || []).concat(o.covers || []));
      });
      if (main.relatedComponentIds.length) {
        main.summary += ' The same pattern shows in ' + main.relatedComponentIds.map(function (id) { return h.comps[id].cluster; }).join(', ') + '.';
        score(main, h);
      }
      out.push(main);
    });
    return out;
  }

  function hypotheses(h) {
    var cands = [];
    var rules = [ruleTls, ruleDns, ruleImagePull, ruleConfigError, ruleResourceLimits, ruleConnExhaustion, ruleNetworkPolicy,
      ruleProbe, ruleNodePressure, ruleScheduling, ruleRateLimit, ruleBadDeploy];
    rules.forEach(function (r) {
      try { r(h, cands); } catch (e) { h.warn('Rule ' + (r.name || '?') + ' failed: ' + (e && e.message ? e.message : e)); }
    });
    // Components a specific mechanism already explains (bad-deploy does not count: it says when,
    // not how, so a failing dependency next to it still deserves its own card).
    var covered = {};
    cands.forEach(function (c) { if (c.category !== 'bad-deploy') (c.covers || [c.componentId]).forEach(function (id) { covered[id] = true; }); });
    try { ruleDependency(h, cands, covered); } catch (e) { h.warn('Rule dependency failed: ' + (e && e.message ? e.message : e)); }

    // Every evidence item must lead somewhere (a signal, a change or a line); an item that does
    // not is dropped rather than shown as an unverifiable claim.
    cands.forEach(function (c) { c.evidence = c.evidence.filter(function (e) { return e.signalId || e.changeId || e.line != null; }); });
    // One signal or change is one piece of evidence: when two items cite the same one, only the
    // heavier counts, so 1 − Π(1 − w) never multiplies a single record in twice.
    cands.forEach(function (c) { c.evidence = dedupeEvidence(c.evidence); });
    cands = cands.filter(function (c) { return c.evidence.length > 0; });
    cands.forEach(function (c) { score(c, h); });
    cands = mergeAcrossClusters(cands, h);

    // A dependency card for a component another hypothesis already explains is shown, but lower.
    cands.forEach(function (c) {
      if (c.category === 'dependency-failure' && covered[c.componentId]) {
        c.raw *= 0.6;
        c.confidence = Math.round(Math.min(0.95, c.raw) * 1000) / 1000;
        c.multipliers.push('covered-by-specific-hypothesis');
      }
    });

    var best = cands.reduce(function (m, c) { return Math.max(m, c.confidence); }, 0);
    if (best < 0.35) { var u = []; ruleUnknown(h, u); u.forEach(function (c) { score(c, h); cands.push(c); }); }

    cands.sort(function (a, b) {
      return b.confidence - a.confidence || b.raw - a.raw || specificity(a.category) - specificity(b.category) || (a.componentId < b.componentId ? -1 : a.componentId > b.componentId ? 1 : 0);
    });
    var perComp = {}, out = [];
    for (var i = 0; i < cands.length && out.length < MAX_HYPOTHESES; i++) {
      var c = cands[i];
      perComp[c.componentId] = (perComp[c.componentId] || 0) + 1;
      if (perComp[c.componentId] > MAX_PER_COMPONENT) continue;
      out.push(c);
    }
    return out.map(function (c) {
      c.evidence.sort(function (a, b) { return b.weight - a.weight; });
      return {
        id: 'hyp-' + WR.hash(c.category + '|' + c.componentId + '|' + c.rule),
        title: c.title,
        category: c.category,
        componentId: c.componentId,
        confidence: c.confidence,
        summary: c.summary,
        evidence: c.evidence.map(function (e) {
          return { signalId: e.signalId, changeId: e.changeId, text: e.text, weight: Math.round(e.weight * 1000) / 1000, source: e.source, line: e.line };
        }),
        against: c.against,
        nextChecks: c.nextChecks,
        rule: c.rule,
        relatedComponentIds: c.relatedComponentIds || [],
        // Internal hand-offs to rollbacks.js / analyze.js; stripped before the Analysis is returned.
        _anchor: c.anchor || null,
        _raw: Math.round(c.raw * 1000) / 1000,
        _multipliers: c.multipliers,
        _covers: c.covers || [c.componentId],
        _release: c.release || null,
        _cert: c.cert || null,
        _demandChange: c.demandChange || null,
        _imageChanges: c._imageChanges || null,
        _tagFix: c._tagFix || null
      };
    });
  }

  hypotheses.CATEGORY_ORDER = CATEGORY_ORDER;
  hypotheses.kc = kc;
  hypotheses.kcCluster = kcCluster;
  hypotheses.helmFlags = helmFlags;
  hypotheses.workloadRef = workloadRef;
  hypotheses.pickPod = pickPod;
  hypotheses.pickContainer = pickContainer;
  WR.hypotheses = hypotheses;
})(globalThis.WR = globalThis.WR || {});
