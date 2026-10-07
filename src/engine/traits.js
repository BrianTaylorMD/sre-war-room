/*
 * traits.js — WR.traits(a) → Traits
 *
 * A small, stable summary of the shape of this incident and of the evidence, used by the
 * observability-stack panel (WR.stackFit) to decide where each setup would break down:
 * multi-cluster or not, high-cardinality labels, how much log volume, whether error traces were
 * probably dropped by sampling, which failing parts are not traced at all.
 *
 * Input `a` is the analysis under construction: { components, signals, stats, extras, clusters,
 * deploy, window, inputsPresent }. Rates are null when the evidence carries no time span.
 */
(function (WR) {
  'use strict';

  function rate(count, startTs, endTs) {
    if (!count) return 0;
    if (startTs == null || endTs == null || !(endTs > startTs)) return null;
    var minutes = Math.max(1, (endTs - startTs) / 60000);
    return Math.round(count / minutes * 10) / 10;
  }

  function traits(a) {
    var comps = a.components || [];
    var stats = a.stats || {};
    var ex = a.extras || {};
    var logsEx = ex.logs || {};
    var trEx = ex.traces || {};
    var alEx = ex.alerts || {};
    var clusters = (a.clusters || []).map(function (c) { return c.name; });
    var failingClusterCount = (a.clusters || []).filter(function (c) { return c.status === 'failing'; }).length;

    var failing = comps.filter(function (c) { return c.status === 'root' || c.status === 'failing'; });
    var traced = {};
    comps.forEach(function (c) { if (c._sources && c._sources.indexOf('traces') >= 0) traced[c.id] = true; });
    var spanErrors = {}, otherErrors = {};
    (a.signals || []).forEach(function (s) {
      if (!s.componentId || WR.sevRank(s.severity) < 2 || s.kind === 'change' || s.kind === 'alert_resolved') return;
      if (s.source === 'traces') spanErrors[s.componentId] = (spanErrors[s.componentId] || 0) + 1;
      else otherErrors[s.componentId] = (otherErrors[s.componentId] || 0) + 1;
    });
    var workloads = failing.filter(function (c) { return c.type === 'service' || c.type === 'infra'; });
    var untraced = workloads.filter(function (c) { return !traced[c.id]; }).map(function (c) { return c.id; });
    // Traced, failing, erroring in logs/alerts, yet no error span: with head sampling the decision
    // to keep a trace is made before the error happens, so error traces are the first to be lost.
    // Two cases are NOT missing traces:
    //   - the callers' client spans already recorded the failures (an edge into it has errors);
    //   - the component fails in a way that stops a server span from ever existing (killed for
    //     memory, crash-looping, image or config errors, refused connections, TLS or name lookups).
    var erroringInto = {};
    (a.edges || []).forEach(function (e) { if (e && e.to && (e.errors > 0 || e.status === 'failing')) erroringInto[e.to] = true; });
    var NO_SERVER_SPAN = { oom_killed: 1, crash_loop: 1, image_pull: 1, config_error: 1, conn_refused: 1, tls_error: 1, dns_failure: 1 };
    var errorTracesMissing = !!(a.inputsPresent && a.inputsPresent.traces) && workloads.some(function (c) {
      if (!traced[c.id] || !(otherErrors[c.id] > 0) || spanErrors[c.id] || erroringInto[c.id]) return false;
      return !(c.kinds || []).some(function (k) { return NO_SERVER_SPAN[k]; });
    });

    var ts = trEx.traceStats || {};
    var w = a.window || {};
    var sigCount = (a.signals || []).length;
    return {
      clusterCount: clusters.length,
      clusters: clusters,
      multiCluster: clusters.length >= 2,
      failingClusterCount: failingClusterCount,
      highCardinalityLabels: (alEx.highCardinalityLabels || []).slice(),
      logLinesPerMin: rate((stats.logs && stats.logs.lines) || 0, logsEx.minTs, logsEx.maxTs),
      signalsPerMin: rate(sigCount, w.start, w.now),
      spanCount: ts.spans || 0,
      tracedServices: ts.services || 0,
      untracedFailingComponents: untraced,
      errorTracesMissing: errorTracesMissing,
      sources: {
        logs: !!(stats.logs && stats.logs.parsed > 0),
        traces: !!(stats.traces && stats.traces.parsed > 0 && ts.spans > 0),
        alerts: !!(stats.alerts && stats.alerts.signals > 0),
        helm: !!(stats.helm && stats.helm.parsed > 0 && ((ex.helm && (ex.helm.changes || []).length) || (ex.helm && (ex.helm.deploys || []).length)))
      },
      hasDeployTime: !!(a.deploy && a.deploy.deployedAt != null)
    };
  }

  WR.traits = traits;
})(globalThis.WR = globalThis.WR || {});
