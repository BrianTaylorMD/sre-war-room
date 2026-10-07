// WR.analyze: the Analysis contract (SPEC §4), the expected answers for every sample, graceful
// degradation, one synthetic incident per category no sample exercises, the 3,000-signal cap and
// the 150 ms performance budget.
import test from 'node:test';
import assert from 'node:assert/strict';
import load from './load.mjs';

const WR = load || globalThis.WR;
const MIN = 60000;
const PANES = ['logs', 'traces', 'alerts', 'helm'];
const CATEGORIES = ['bad-deploy', 'resource-limits', 'config-error', 'image-pull', 'dependency-failure', 'dns', 'tls-cert', 'node-pressure',
  'scheduling-capacity', 'probe-misconfig', 'network-policy', 'connection-exhaustion', 'rate-limiting', 'unknown'];
const ROLLBACK_KINDS = ['helm-rollback', 'rollout-undo', 'set-image', 'resource-restore', 'config-revert', 'canary-abort', 'traffic-shift', 'scale', 'roll-forward', 'restart'];
const STATUSES = ['root', 'failing', 'degraded', 'at-risk', 'healthy'];
const COMPONENT_TYPES = ['service', 'datastore', 'external', 'node', 'infra'];
const CHANGE_CATEGORIES = ['image', 'resources', 'replicas', 'env', 'configmap', 'secret', 'probe', 'networkpolicy', 'crd', 'migration-hook', 'hpa', 'ingress', 'service', 'rbac', 'chart', 'other'];

const isNum = (v) => typeof v === 'number' && Number.isFinite(v);
const numOrNull = (v) => v === null || isNum(v);
const strOrNull = (v) => v === null || typeof v === 'string';
const isStrArr = (v) => Array.isArray(v) && v.every((x) => typeof x === 'string');

function analyzeSample(s, drop) {
  const input = { logs: s.logs, traces: s.traces, alerts: s.alerts, helm: s.helm, context: s.context };
  if (drop) input[drop] = '';
  return WR.analyze(input);
}

// Every number in the Analysis is finite: JSON.stringify would silently turn NaN/Infinity into null.
function assertFiniteNumbers(v, path = 'analysis') {
  if (typeof v === 'number') { assert.ok(Number.isFinite(v), `${path} is ${v}`); return; }
  if (Array.isArray(v)) { v.forEach((x, i) => assertFiniteNumbers(x, `${path}[${i}]`)); return; }
  if (v && typeof v === 'object') for (const k of Object.keys(v)) assertFiniteNumbers(v[k], `${path}.${k}`);
}

function assertStats(st, name) {
  assert.ok(st && typeof st === 'object', `stats.${name}`);
  for (const k of ['lines', 'parsed', 'skipped', 'tzAssumed']) assert.ok(isNum(st[k]), `stats.${name}.${k}`);
  assert.equal(typeof st.format, 'string');
  assert.ok(isStrArr(st.warnings));
}

// The full SPEC §4 shape, plus the cross-references the UI relies on.
function assertAnalysis(a) {
  assert.equal(a.version, 1);
  assert.ok(isNum(a.generatedAt));
  PANES.forEach((p) => assert.equal(typeof a.inputsPresent[p], 'boolean', `inputsPresent.${p}`));
  PANES.forEach((p) => assertStats(a.stats[p], p));
  for (const k of ['start', 'end', 'firstAnomaly', 'now']) assert.ok(numOrNull(a.window[k]), `window.${k}`);
  assert.equal(typeof a.headline, 'string');
  assert.ok(a.headline.length > 0);
  assert.ok(['SEV1', 'SEV2', 'SEV3', 'SEV4'].includes(a.severity));
  assert.ok(isStrArr(a.warnings));

  assert.ok(Array.isArray(a.clusters));
  a.clusters.forEach((c) => {
    assert.equal(typeof c.name, 'string');
    for (const k of ['componentCount', 'failing', 'degraded']) assert.ok(isNum(c[k]), `cluster.${k}`);
    assert.ok(['failing', 'degraded', 'healthy'].includes(c.status));
  });

  const compIds = new Set();
  a.components.forEach((c) => {
    assert.ok(!compIds.has(c.id), `duplicate component ${c.id}`);
    compIds.add(c.id);
    for (const k of ['id', 'name', 'cluster', 'namespace']) assert.equal(typeof c[k], 'string', `component.${k}`);
    assert.ok(COMPONENT_TYPES.includes(c.type), c.type);
    assert.ok(c.role === null || c.role === 'ingress');
    assert.ok(STATUSES.includes(c.status));
    assert.ok(isNum(c.impact) && c.impact >= 0 && c.impact <= 1);
    assert.equal(typeof c.userFacing, 'boolean');
    assert.ok(numOrNull(c.firstErrorTs) && numOrNull(c.lastErrorTs));
    for (const k of ['error', 'warn', 'info']) assert.ok(isNum(c.counts[k]));
    assert.ok(isStrArr(c.kinds) && c.kinds.every((k) => WR.isKind(k)));
    assert.ok(isStrArr(c.pods) && isStrArr(c.changeIds));
    assert.ok(strOrNull(c.release));
    if (c.status === 'healthy') assert.equal(c.impact, 0);
  });
  const roots = a.components.filter((c) => c.status === 'root');
  const top = a.hypotheses[0];
  if (top && top.confidence >= 0.35) {
    assert.equal(roots.length, 1, 'exactly one root');
    assert.equal(roots[0].id, top.componentId);
  } else assert.equal(roots.length, 0, 'no root without a confident hypothesis');

  a.edges.forEach((e) => {
    assert.ok(compIds.has(e.from) && compIds.has(e.to), `edge ${e.id} endpoints exist`);
    assert.ok(isNum(e.calls) && isNum(e.errors) && numOrNull(e.errorRate) && numOrNull(e.p95ms) && numOrNull(e.firstErrorTs));
    assert.ok(['failing', 'degraded', 'ok'].includes(e.status));
  });

  const sigIds = new Set();
  assert.ok(a.signals.length <= WR.analyze.MAX_SIGNALS || a.signals.every((s) => WR.sevRank(s.severity) >= 2 || s.kind === 'change'));
  a.signals.forEach((s) => {
    assert.ok(!sigIds.has(s.id), `duplicate signal ${s.id}`);
    sigIds.add(s.id);
    assert.ok(PANES.includes(s.source));
    assert.ok(Number.isInteger(s.line) && s.line >= 1);
    assert.ok(numOrNull(s.ts));
    assert.equal(typeof s.tsInferred, 'boolean');
    assert.ok(WR.SEVERITIES.includes(s.severity));
    assert.ok(WR.isKind(s.kind), s.kind);
    assert.ok(s.componentId === null || compIds.has(s.componentId), `signal ${s.id} component exists`);
    assert.ok(Array.isArray(s.relatedIds));
    assert.equal(typeof s.text, 'string');
    assert.equal(typeof s.raw, 'string');
    assert.ok(s.attrs && typeof s.attrs === 'object');
  });

  const changeIds = new Set(a.changes.map((c) => c.id));
  a.changes.forEach((c) => {
    assert.ok(CHANGE_CATEGORIES.includes(c.category), c.category);
    assert.ok(['high', 'medium', 'low'].includes(c.risk));
    assert.equal(typeof c.summary, 'string');
    assert.ok(c.componentId === null || compIds.has(c.componentId));
  });
  if (a.deploy !== null) {
    assert.ok(numOrNull(a.deploy.revision) && numOrNull(a.deploy.previousRevision) && numOrNull(a.deploy.deployedAt));
    assert.ok([null, 'helm-history', 'helm-list', 'rollout-event', 'manual'].includes(a.deploy.deployedAtSource));
    assert.equal(typeof a.deploy.tsInferred, 'boolean');
  }

  for (let i = 1; i < a.timeline.length; i++) assert.ok(a.timeline[i].ts >= a.timeline[i - 1].ts, 'timeline ascending');
  a.timeline.forEach((t) => { assert.ok(sigIds.has(t.signalId)); assert.ok(WR.isKind(t.kind)); });

  assert.ok(a.hypotheses.length <= 6);
  const hypIds = new Set();
  a.hypotheses.forEach((h, i) => {
    hypIds.add(h.id);
    assert.ok(CATEGORIES.includes(h.category), h.category);
    assert.ok(compIds.has(h.componentId));
    assert.ok(isNum(h.confidence) && h.confidence >= 0 && h.confidence <= 0.95);
    if (i > 0) assert.ok(h.confidence <= a.hypotheses[i - 1].confidence, 'sorted by confidence');
    for (const k of ['id', 'title', 'summary', 'rule']) assert.equal(typeof h[k], 'string');
    assert.ok(h.evidence.length >= 1);
    if (h.confidence > 0.5) assert.ok(h.evidence.length >= 2, `${h.id}: > 0.5 needs two evidence items`);
    h.evidence.forEach((e) => {
      assert.ok(e.signalId === null || sigIds.has(e.signalId), `evidence signal ${e.signalId} exists`);
      assert.ok(e.changeId === null || changeIds.has(e.changeId), `evidence change ${e.changeId} exists`);
      assert.equal(typeof e.text, 'string');
      assert.ok(isNum(e.weight));
      assert.ok(e.source === null || PANES.includes(e.source));
      assert.ok(e.line === null || (Number.isInteger(e.line) && e.line >= 1));
      assert.ok(e.signalId || e.changeId || e.line, `${h.id}: every evidence item can be jumped to (${e.text})`);
    });
    h.against.forEach((x) => assert.equal(typeof x.text, 'string'));
    assert.ok(h.nextChecks.length >= 1);
    h.nextChecks.forEach((x) => { assert.equal(typeof x.cmd, 'string'); assert.equal(typeof x.why, 'string'); assert.ok(!/undefined|NaN|(^|[^/])null\b/.test(x.cmd), x.cmd); });
  });

  const rec = a.rollbacks.filter((r) => r.recommended);
  if (a.rollbacks.length) assert.equal(rec.length, 1, 'exactly one recommended rollback');
  if (rec.length) assert.equal(a.rollbacks[0], rec[0], 'recommended first');
  a.rollbacks.forEach((r, i) => {
    assert.ok(ROLLBACK_KINDS.includes(r.kind));
    assert.ok(r.commands.length >= 1 && isStrArr(r.commands));
    r.commands.forEach((c) => assert.ok(!/undefined|NaN|(^|[^/])null\b/.test(c), c));
    assert.ok(isNum(r.etaMinutes));
    assert.ok(['low', 'medium', 'high'].includes(r.risk));
    assert.ok(r.fixes.every((id) => hypIds.has(id)));
    assert.ok(isStrArr(r.caveats) && isStrArr(r.prerequisites));
    assert.ok(numOrNull(r.budgetSavedPct));
    if (i > 1) assert.ok(r.etaMinutes >= a.rollbacks[i - 1].etaMinutes, 'then by time to recover');
  });

  const b = a.budget;
  for (const k of ['sloTarget', 'windowDays', 'requestsPerMin', 'errorRatio', 'burnRate', 'incidentMinutes', 'consumedPct', 'remainingPct', 'badRequests', 'budgetRequests']) assert.ok(isNum(b[k]), `budget.${k}`);
  assert.ok(numOrNull(b.minutesToExhaustion));
  assert.ok(['override', 'alert', 'traces', 'logs', 'default'].includes(b.errorRatioSource));
  assert.equal(b.alertRows.length, 3);
  assert.equal(b.projection.length, 3);
  assert.equal(b.series.length, 25);
  assert.equal(b.source, 'https://sre.google/workbook/alerting-on-slos/');

  const t = a.traits;
  for (const k of ['clusterCount', 'failingClusterCount', 'spanCount', 'tracedServices']) assert.ok(isNum(t[k]), `traits.${k}`);
  for (const k of ['logLinesPerMin', 'signalsPerMin']) assert.ok(numOrNull(t[k]), `traits.${k}`);
  for (const k of ['multiCluster', 'errorTracesMissing', 'hasDeployTime']) assert.equal(typeof t[k], 'boolean');
  assert.ok(isStrArr(t.clusters) && isStrArr(t.highCardinalityLabels) && isStrArr(t.untracedFailingComponents));
  PANES.forEach((p) => assert.equal(typeof t.sources[p], 'boolean'));

  assertFiniteNumbers(a);
  JSON.parse(JSON.stringify(a)); // serialisable (fixtures, the artifact page)
}

// ---------------------------------------------------------------------------------------------
// The four samples
// ---------------------------------------------------------------------------------------------
for (const s of WR.samples) {
  const e = s.expected;
  test(`${s.id}: the Analysis has every SPEC §4 field with the right types`, () => {
    assertAnalysis(analyzeSample(s));
  });

  test(`${s.id}: top hypothesis names the expected root component, cluster and category`, () => {
    const a = analyzeSample(s);
    const top = a.hypotheses[0];
    assert.ok(top, 'a hypothesis');
    const comp = a.components.find((c) => c.id === top.componentId);
    assert.ok([e.rootComponentName, ...(e.rootComponentAlternates || [])].includes(comp.name), `root ${comp.name}`);
    assert.ok((e.rootClusters || [e.rootCluster]).includes(comp.cluster), `cluster ${comp.cluster}`);
    assert.ok((e.categories || [e.category]).includes(top.category), `category ${top.category}`);
    if (e.rootType) assert.equal(comp.type, e.rootType);
    assert.ok(top.confidence >= 0.35);
    assert.equal(comp.status, 'root');
    assert.ok(a.headline.includes(comp.name), a.headline);
  });

  test(`${s.id}: recommended rollback kind, deploy revisions and deploy time`, () => {
    const a = analyzeSample(s);
    const rec = a.rollbacks.find((r) => r.recommended);
    assert.ok(rec, 'a recommended rollback');
    assert.ok((e.recommendedKinds || [e.recommendedKind]).includes(rec.kind), `recommended ${rec.kind}`);
    assert.ok(rec.fixes.includes(a.hypotheses[0].id), 'the recommendation addresses the top hypothesis');
    assert.equal(a.deploy.release, e.release);
    assert.equal(a.deploy.revision, e.deployRevision);
    assert.equal(a.deploy.previousRevision, e.previousRevision);
    assert.equal(new Date(a.deploy.deployedAt).toISOString(), new Date(e.deployedAt).toISOString());
    if (rec.kind === 'helm-rollback') {
      assert.match(rec.commands[0], new RegExp(`^helm rollback ${e.release} ${e.previousRevision} -n \\S+ --kube-context \\S+ --wait --timeout 5m$`));
    }
  });

  test(`${s.id}: clusters, first anomaly and error budget`, () => {
    const a = analyzeSample(s);
    assert.equal(a.traits.multiCluster, e.multiCluster);
    for (const name of e.failingClusters || []) assert.equal(a.clusters.find((c) => c.name === name).status, 'failing', name);
    for (const name of e.healthyClusters || []) assert.equal(a.clusters.find((c) => c.name === name).status, 'healthy', name);
    const want = Date.parse(e.firstErrorAround);
    assert.ok(Math.abs(a.window.firstAnomaly - want) <= 2 * MIN, `first anomaly ${new Date(a.window.firstAnomaly).toISOString()} vs ${e.firstErrorAround}`);
    assert.equal(a.window.start, a.window.firstAnomaly - 15 * MIN);
    assert.equal(a.window.now, Date.parse(s.context.now));
    assert.equal(a.budget.errorRatioSource, 'alert', 'every sample carries a burn-rate alert');
    assert.equal(a.budget.sloTarget, s.context.slo.target);
    assert.equal(a.severity, 'SEV1');
  });

  test(`${s.id}: evidence, timeline and rollbacks point at things that exist`, () => {
    const a = analyzeSample(s);
    const sigIds = new Set(a.signals.map((x) => x.id));
    const changeIds = new Set(a.changes.map((x) => x.id));
    a.hypotheses.forEach((h) => h.evidence.forEach((ev) => {
      if (ev.signalId) assert.ok(sigIds.has(ev.signalId));
      if (ev.changeId) assert.ok(changeIds.has(ev.changeId));
      assert.ok(ev.signalId || ev.changeId || ev.line, 'every evidence item can be jumped to');
    }));
    // Commands that change the cluster name it explicitly.
    a.rollbacks.forEach((r) => r.commands.forEach((c) => {
      if (/^kubectl (?!argo)/.test(c)) assert.match(c, /^kubectl --context \S+/, c);
      if (/^helm rollback/.test(c)) assert.match(c, /--kube-context \S+/, c);
    }));
  });
}

test('bad-deploy-oom: the memory limit cut is the evidence, and the rollback caveats are true to Helm', () => {
  const a = analyzeSample(WR.samples.find((s) => s.id === 'bad-deploy-oom'));
  const top = a.hypotheses[0];
  const cut = a.changes.find((c) => c.category === 'resources' && /limits\.memory$/.test(c.field));
  assert.ok(top.evidence.some((e) => e.changeId === cut.id), 'cites the 512Mi → 256Mi change');
  assert.ok(top.evidence.some((e) => e.signalId && a.signals.find((s) => s.id === e.signalId).kind === 'oom_killed'));
  const helm = a.rollbacks.find((r) => r.kind === 'helm-rollback');
  assert.ok(helm.caveats.some((c) => /new revision \(r43\)/.test(c)));
  assert.ok(helm.caveats.some((c) => /prod-us-east/.test(c)), 'holds the release back from the healthy cluster');
  const restore = a.rollbacks.find((r) => r.kind === 'resource-restore');
  assert.match(restore.commands[0], /set resources deployment\/payments-api -c payments-api --limits=memory=512Mi --requests=memory=512Mi$/);
  assert.ok(a.rollbacks.some((r) => r.kind === 'traffic-shift'), 'one of two clusters failing → traffic shift');
  // Review fix: payments-api is OOM-killed and crash-looping, so it can never emit server spans, and
  // checkout-api's client spans into it already carry the failures. Nothing was lost to sampling.
  assert.equal(a.traits.errorTracesMissing, false, 'a crash-looping callee with failing client spans is not missing traces');
});

test('coredns-outage: wide blast radius through cluster DNS', () => {
  const a = analyzeSample(WR.samples.find((s) => s.id === 'coredns-outage'));
  const core = a.components.find((c) => c.name === 'coredns');
  const into = a.edges.filter((e) => e.to === core.id);
  assert.ok(into.length >= 5, 'many services depend on CoreDNS');
  assert.ok(a.components.filter((c) => c.status === 'failing').length >= 5);
  // Lookups for redis or a partner API failed in DNS, never reaching them: they are not failing.
  const ext = a.components.find((c) => c.type === 'external');
  if (ext) assert.notEqual(ext.status, 'failing');
  assert.ok(a.rollbacks.some((r) => r.kind === 'config-revert' && /yq 'select\(\.kind == "ConfigMap" and \.metadata\.name == "coredns"\)'/.test(r.commands[0])));
});

test('cert-expiry: the recommendations release is a red herring', () => {
  const s = WR.samples.find((x) => x.id === 'cert-expiry');
  const a = analyzeSample(s);
  const top = a.hypotheses[0];
  assert.notEqual(a.components.find((c) => c.id === top.componentId).name, s.expected.notTopComponentName);
  const herring = a.hypotheses.find((h) => h.componentId.endsWith('/' + s.expected.redHerringRelease));
  if (herring) {
    assert.ok(herring.confidence < 0.35, `red herring at ${herring.confidence}`);
    assert.ok(herring.against.some((x) => /no errors/.test(x.text)));
    assert.ok(herring.against.some((x) => /after this deploy/.test(x.text)));
  }
  const rec = a.rollbacks.find((r) => r.recommended);
  assert.match(rec.commands[0], /^cmctl renew auth-service-mtls -n identity --context prod-us-central$/);
  assert.ok(rec.caveats.some((c) => /403/.test(c)), 'renewal fails until the Vault issuer is fixed');
  assert.ok(top.evidence.some((e) => /Not After/.test(e.text) && e.line), 'cites the certificate Not After line');
  const rb = a.rollbacks.find((r) => r.kind === 'helm-rollback');
  if (rb) assert.equal(rb.budgetSavedPct, null, 'rolling back recommendations does not fix the incident');
});

test('db-conn-exhaustion: one hypothesis across both clusters, scale and helm rollback offered', () => {
  const a = analyzeSample(WR.samples.find((s) => s.id === 'db-conn-exhaustion'));
  const top = a.hypotheses[0];
  assert.equal(top.category, 'connection-exhaustion');
  assert.equal(a.hypotheses.filter((h) => h.category === 'connection-exhaustion').length, 1, 'clusters merged into one card');
  assert.ok(top.evidence.some((e) => e.changeId && /maxReplicas 6 → 20/.test(a.changes.find((c) => c.id === e.changeId).summary)));
  const scale = a.rollbacks.find((r) => r.kind === 'scale');
  assert.ok(scale.commands.some((c) => c === `kubectl --context prod-us-east -n orders patch hpa orders-api --type merge -p '{"spec":{"maxReplicas":6}}'`));
  assert.ok(scale.commands.some((c) => /--context prod-us-west/.test(c)));
  const helm = a.rollbacks.find((r) => r.kind === 'helm-rollback');
  assert.ok(helm.prerequisites.some((p) => /helm history orders -n orders --kube-context prod-us-west/.test(p)), 'only us-east history was pasted');
  assert.ok(!JSON.stringify(a).includes('hunter2-not-real'), 'the fake DB_PASSWORD never reaches the Analysis');
});

// ---------------------------------------------------------------------------------------------
// Graceful degradation
// ---------------------------------------------------------------------------------------------
test('no throw and a valid Analysis for empty, null and junk input', () => {
  for (const input of [undefined, null, {}, { logs: '', traces: '', alerts: '', helm: '' },
    { logs: 'hello\n\u0000\u0001 binary\n{"a":', traces: '{ not json', alerts: '[FIRING', helm: '+++ ---', context: { now: 'garbage', defaultTz: 'Mars/Phobos', slo: { target: 'x' } } },
    { logs: 12345, traces: { a: 1 }, alerts: ['x'], helm: null, context: { slo: null } }]) {
    const a = WR.analyze(input);
    assertAnalysis(a);
    assert.equal(a.hypotheses.length, 0);
    assert.equal(a.rollbacks.length, 0);
    assert.equal(a.severity, 'SEV4');
  }
  const junk = WR.analyze({ logs: 'x', context: { defaultTz: 'Mars/Phobos', now: 'soon' } });
  assert.ok(junk.warnings.some((w) => /Mars\/Phobos/.test(w)));
  assert.ok(junk.warnings.some((w) => /could not be read/.test(w)));
});

for (const s of WR.samples) {
  test(`${s.id}: each pane removed in turn still names the root`, () => {
    const want = [s.expected.rootComponentName, ...(s.expected.rootComponentAlternates || [])];
    for (const drop of PANES) {
      const a = analyzeSample(s, drop);
      assertAnalysis(a);
      assert.equal(a.inputsPresent[drop], false);
      const top = a.hypotheses[0];
      assert.ok(top, `${drop} removed: a hypothesis`);
      const comp = a.components.find((c) => c.id === top.componentId);
      assert.ok(want.includes(comp.name), `${drop} removed: root ${comp.name}`);
    }
  });
}

test('bad-deploy-oom without Helm: still payments-api, and says the deploy time came from a rollout, not helm history', () => {
  const a = analyzeSample(WR.samples.find((s) => s.id === 'bad-deploy-oom'), 'helm');
  const top = a.hypotheses[0];
  assert.equal(a.components.find((c) => c.id === top.componentId).name, 'payments-api');
  assert.ok(a.warnings.some((w) => /Helm/.test(w) && /deploy time/.test(w)), JSON.stringify(a.warnings));
  assert.equal(a.deploy.deployedAtSource, 'rollout-event');
  assert.equal(a.deploy.previousRevision, null);
  assert.ok(!a.rollbacks.some((r) => r.kind === 'helm-rollback'), 'no revision to roll back to');
  assert.ok(a.rollbacks.some((r) => r.kind === 'rollout-undo'));
});

test('a deploy-correlated hypothesis without any deploy time says so', () => {
  const s = WR.samples.find((x) => x.id === 'bad-deploy-oom');
  // Keep only the diff: no history table, no rollout events in the logs.
  const helmDiffOnly = s.helm.split('\n').filter((l, i, all) => i >= all.findIndex((x) => /has changed:/.test(x)) - 1).join('\n');
  const a = WR.analyze({ alerts: s.alerts, helm: helmDiffOnly, context: s.context });
  assertAnalysis(a);
  assert.ok(a.warnings.some((w) => /^No deploy time found/.test(w)));
  const deployCorrelated = a.hypotheses.filter((h) => h.evidence.some((e) => e.changeId));
  assert.ok(deployCorrelated.length);
  deployCorrelated.forEach((h) => assert.ok(h.against.some((x) => /No deploy time found — paste `helm history` or set Deployed at/.test(x.text)), h.title));
});

test('a manual Deployed at overrides the parsed time; a time zone mistake is flagged', () => {
  const s = WR.samples.find((x) => x.id === 'bad-deploy-oom');
  const a = WR.analyze({ logs: s.logs, traces: s.traces, alerts: s.alerts, helm: s.helm, context: { ...s.context, deployedAt: '2026-10-05T21:40:00Z' } });
  assert.equal(a.deploy.deployedAtSource, 'manual');
  assert.equal(a.deploy.deployedAt, Date.parse('2026-10-05T21:40:00Z'));
  const z = WR.analyze({ logs: s.logs, traces: s.traces, alerts: s.alerts, helm: s.helm, context: { slo: s.context.slo } });
  assert.ok(z.warnings.some((w) => /Helm times are later than everything else/.test(w)), 'zone-less helm history read as UTC lands after the errors');
});

// ---------------------------------------------------------------------------------------------
// One synthetic incident per category the samples do not exercise
// ---------------------------------------------------------------------------------------------
const ctx = (extra = {}) => ({ now: '2026-10-05T12:03:00Z', slo: { target: 0.999, windowDays: 30, requestsPerMin: 500 }, ...extra });
const history = (rel, ns, ctxName, a, b) => `$ helm history ${rel} -n ${ns} --kube-context ${ctxName}
REVISION\tUPDATED                 \tSTATUS    \tCHART      \tAPP VERSION\tDESCRIPTION
${a}       \tMon Oct  5 11:20:00 2026\tsuperseded\t${rel}-1.0.0\t1.0.0      \tUpgrade complete
${b}       \tMon Oct  5 11:56:00 2026\tdeployed  \t${rel}-1.0.1\t1.0.1      \tUpgrade complete
`;
const SYNTH = {
  'image-pull': {
    input: {
      logs: `$ kubectl --context prod-a -n web get events
LAST SEEN   TYPE      REASON    OBJECT                          MESSAGE
3m          Warning   Failed    pod/web-api-6f7d8c9b5d-x7kq2    Failed to pull image "registry.example.com/web/web-api:1.4.1": rpc error: code = NotFound desc = failed to resolve reference: manifest unknown
2m          Warning   Failed    pod/web-api-6f7d8c9b5d-x7kq2    Error: ImagePullBackOff
`,
      helm: history('web', 'web', 'prod-a', 6, 7) + `$ helm diff revision web 6 7 -n web --kube-context prod-a
web, web-api, Deployment (apps) has changed:
  # Source: web/templates/deployment.yaml
  apiVersion: apps/v1
  kind: Deployment
  metadata:
    name: web-api
  spec:
    template:
      spec:
        containers:
          - name: web-api
-           image: "registry.example.com/web/web-api:1.4.0"
+           image: "registry.example.com/web/web-api:1.4.1"
`,
      context: ctx({ cluster: 'prod-a' })
    },
    name: 'web-api', rollbacks: ['helm-rollback', 'rollout-undo', 'set-image'],
    check: (a) => assert.ok(a.rollbacks.find((r) => r.kind === 'set-image').commands[0].endsWith('set image deployment/web-api web-api=registry.example.com/web/web-api:1.4.0'))
  },
  'config-error': {
    input: {
      logs: `$ kubectl --context prod-a -n billing get events
LAST SEEN   TYPE      REASON    OBJECT                              MESSAGE
4m          Warning   Failed    pod/invoice-api-7c9d8f6b4d-pq2zx    Error: secret "invoice-db-creds" not found
3m          Warning   Failed    pod/invoice-api-7c9d8f6b4d-pq2zx    Error: CreateContainerConfigError
`,
      context: ctx()
    },
    name: 'invoice-api', rollbacks: ['roll-forward'],
    check: (a) => assert.match(a.rollbacks[0].commands[0], /create secret generic invoice-db-creds --from-literal=<key>=<value>$/)
  },
  'probe-misconfig': {
    input: {
      logs: `$ kubectl --context prod-a -n shop get events
LAST SEEN   TYPE      REASON      OBJECT                           MESSAGE
5m          Warning   Unhealthy   pod/cart-api-5d8f7c6b9d-k2m4n    Readiness probe failed: Get "http://10.1.2.3:8080/ready": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
4m          Warning   Unhealthy   pod/cart-api-5d8f7c6b9d-r7t2v    Readiness probe failed: Get "http://10.1.2.4:8080/ready": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
`,
      helm: history('cart', 'shop', 'prod-a', 3, 4) + `$ helm diff revision cart 3 4 -n shop --kube-context prod-a
shop, cart-api, Deployment (apps) has changed:
  # Source: cart/templates/deployment.yaml
  apiVersion: apps/v1
  kind: Deployment
  metadata:
    name: cart-api
  spec:
    template:
      spec:
        containers:
          - name: cart-api
            readinessProbe:
              httpGet:
                path: /ready
                port: 8080
-             timeoutSeconds: 5
+             timeoutSeconds: 1
`,
      context: ctx()
    },
    name: 'cart-api', rollbacks: ['helm-rollback']
  },
  'node-pressure': {
    input: {
      logs: `$ kubectl --context prod-a get nodes
NAME                               STATUS     ROLES   AGE   VERSION
aks-apps-11111111-vmss000001       NotReady   agent   40d   v1.31.2
aks-apps-11111111-vmss000002       Ready      agent   40d   v1.31.2
$ kubectl --context prod-a get events -A
NAMESPACE   LAST SEEN   TYPE      REASON                      OBJECT                                MESSAGE
default     9m          Warning   NodeHasInsufficientMemory   node/aks-apps-11111111-vmss000001     Node aks-apps-11111111-vmss000001 status is now: NodeHasInsufficientMemory
shop        8m          Warning   Evicted                     pod/search-api-6d5f8c7b9d-zz2kq       The node was low on resource: memory.
`,
      context: ctx()
    },
    name: 'aks-apps-11111111-vmss000001', rollbacks: ['roll-forward'],
    check: (a) => assert.ok(a.rollbacks[0].commands.includes('kubectl --context prod-a cordon aks-apps-11111111-vmss000001'))
  },
  'scheduling-capacity': {
    input: {
      logs: `$ kubectl --context prod-a -n batch get events
LAST SEEN   TYPE      REASON             OBJECT                                MESSAGE
7m          Warning   FailedScheduling   pod/report-worker-5f6d7c8b9d-a2b3c    0/12 nodes are available: 12 Insufficient memory.
6m          Warning   FailedScheduling   pod/report-worker-5f6d7c8b9d-d4f5g    0/12 nodes are available: 12 Insufficient memory.
5m          Warning   FailedScheduling   pod/report-worker-5f6d7c8b9d-h6j7k    0/12 nodes are available: 12 Insufficient memory.
`,
      context: ctx()
    },
    name: 'report-worker', rollbacks: []
  },
  'network-policy': {
    input: {
      logs: `[pod/checkout-api-7d9f8b6c5d-x2k4p/checkout-api] {"level":"error","ts":"2026-10-05T11:58:10Z","msg":"call failed","error":"dial tcp 10.0.4.12:8080: i/o timeout","upstream":"pricing-api.shop.svc.cluster.local"}
[pod/checkout-api-7d9f8b6c5d-x2k4p/checkout-api] {"level":"error","ts":"2026-10-05T11:58:40Z","msg":"call failed","error":"context deadline exceeded","upstream":"pricing-api.shop.svc.cluster.local"}
`,
      helm: history('pricing', 'shop', 'prod-a', 8, 9) + `$ helm diff revision pricing 8 9 -n shop --kube-context prod-a
shop, pricing-api, NetworkPolicy (networking.k8s.io) has changed:
  # Source: pricing/templates/networkpolicy.yaml
  apiVersion: networking.k8s.io/v1
  kind: NetworkPolicy
  metadata:
    name: pricing-api
  spec:
    podSelector:
      matchLabels:
        app: pricing-api
    ingress:
      - from:
          - podSelector:
              matchLabels:
-               app: checkout-api
+               app: checkout
`,
      context: ctx({ cluster: 'prod-a' })
    },
    name: 'pricing-api', rollbacks: ['helm-rollback']
  },
  'rate-limiting': {
    input: {
      logs: `[pod/notify-api-6c7d8f9b5d-q1w2e/notify-api] {"level":"warn","ts":"2026-10-05T11:58:00Z","msg":"provider returned 429 Too Many Requests","upstream":"api.sms-provider.example.com"}
[pod/notify-api-6c7d8f9b5d-q1w2e/notify-api] {"level":"error","ts":"2026-10-05T11:59:00Z","msg":"rate limit exceeded, dropping message","upstream":"api.sms-provider.example.com"}
[pod/notify-api-6c7d8f9b5d-q1w2e/notify-api] {"level":"error","ts":"2026-10-05T11:59:30Z","msg":"rate limit exceeded, dropping message","upstream":"api.sms-provider.example.com"}
`,
      context: ctx()
    },
    name: 'notify-api', rollbacks: [],
    check: (a) => assert.ok(!/cluster-1/.test(a.headline), 'never shows the placeholder cluster name')
  },
  'dependency-failure': {
    input: {
      traces: [
        '2026-10-05T11:58:00.000Z trace=a1 span=s1 parent=- service=checkout-api op="POST /pay" dur=3100ms status=ERROR code=502 cluster=prod-a ns=shop',
        '2026-10-05T11:58:00.010Z trace=a1 span=s2 parent=s1 service=checkout-api op="POST /v1/charge" kind=client dur=3000ms status=ERROR code=503 peer=api.partner-pay.example.com cluster=prod-a ns=shop',
        '2026-10-05T11:58:10.000Z trace=a2 span=s3 parent=- service=checkout-api op="POST /pay" dur=3100ms status=ERROR code=502 cluster=prod-a ns=shop',
        '2026-10-05T11:58:10.010Z trace=a2 span=s4 parent=s3 service=checkout-api op="POST /v1/charge" kind=client dur=3000ms status=ERROR code=503 peer=api.partner-pay.example.com cluster=prod-a ns=shop'
      ].join('\n'),
      context: ctx()
    },
    name: 'api.partner-pay.example.com', rollbacks: []
  }
};

for (const [category, c] of Object.entries(SYNTH)) {
  test(`synthetic ${category}: the rule fires and ranks first`, () => {
    const a = WR.analyze(c.input);
    assertAnalysis(a);
    const top = a.hypotheses[0];
    assert.ok(top, 'a hypothesis');
    assert.equal(top.category, category);
    assert.equal(a.components.find((x) => x.id === top.componentId).name, c.name);
    assert.deepEqual(a.rollbacks.map((r) => r.kind).sort(), c.rollbacks.slice().sort());
    if (c.check) c.check(a);
  });
}

test('synthetic release with a CRD change, a pre-upgrade migration hook and an Argo Rollout', () => {
  const helm = history('ledger', 'ledger', 'prod-a', 11, 12) + `$ helm diff revision ledger 11 12 -n ledger --kube-context prod-a
, entries.ledger.example.com, CustomResourceDefinition (apiextensions.k8s.io) has changed:
  # Source: ledger/crds/entries.yaml
  apiVersion: apiextensions.k8s.io/v1
  kind: CustomResourceDefinition
  metadata:
    name: entries.ledger.example.com
  spec:
    versions:
      - name: v1
        schema:
          openAPIV3Schema:
            properties:
              spec:
                properties:
-                 kind:
+                 entryKind:
                    type: string
ledger, ledger-migrate, Job (batch) has been added:
+ # Source: ledger/templates/migrate-job.yaml
+ apiVersion: batch/v1
+ kind: Job
+ metadata:
+   name: ledger-migrate
+   annotations:
+     helm.sh/hook: pre-upgrade
+ spec:
+   template:
+     spec:
+       restartPolicy: Never
+       containers:
+         - name: migrate
+           image: "registry.example.com/ledger/ledger-migrate:4.2.0"
ledger, ledger-api, Rollout (argoproj.io) has changed:
  # Source: ledger/templates/rollout.yaml
  apiVersion: argoproj.io/v1alpha1
  kind: Rollout
  metadata:
    name: ledger-api
  spec:
    template:
      spec:
        containers:
          - name: ledger-api
-           image: "registry.example.com/ledger/ledger-api:4.1.0"
+           image: "registry.example.com/ledger/ledger-api:4.2.0"
`;
  const logs = `$ kubectl --context prod-a -n ledger get events
LAST SEEN   TYPE      REASON    OBJECT                              MESSAGE
4m          Warning   BackOff   pod/ledger-api-6c8d7f9b5d-k2x9q     Back-off restarting failed container ledger-api in pod ledger-api-6c8d7f9b5d-k2x9q
$ kubectl --context prod-a -n ledger logs ledger-api-6c8d7f9b5d-k2x9q --previous
{"level":"error","ts":"2026-10-05T11:58:02Z","msg":"query failed: pq: column \\"entry_kind\\" does not exist","service":"ledger-api"}
{"level":"error","ts":"2026-10-05T11:58:40Z","msg":"query failed: pq: column \\"entry_kind\\" does not exist","service":"ledger-api"}
`;
  // The fixture is only meaningful if the Helm parser sees all three objects.
  const parsed = WR.parseHelm(helm, ctx());
  assert.ok(parsed.extras.changes.some((c) => c.category === 'crd'));
  assert.ok(parsed.extras.changes.some((c) => c.category === 'migration-hook'));
  assert.ok(parsed.extras.changes.some((c) => c.resourceKind === 'Rollout'));

  const a = WR.analyze({ logs, helm, context: ctx({ cluster: 'prod-a' }) });
  assertAnalysis(a);
  const top = a.hypotheses[0];
  assert.equal(top.category, 'bad-deploy');
  assert.match(top.rule, /^migration-hook/);
  assert.ok(top.evidence.some((e) => e.changeId && a.changes.find((c) => c.id === e.changeId).category === 'migration-hook'));
  const helmRb = a.rollbacks.find((r) => r.kind === 'helm-rollback');
  assert.equal(helmRb.risk, 'high');
  assert.ok(helmRb.caveats.some((c) => /does not upgrade or roll back CRDs kept in a chart's crds\/ directory/.test(c)));
  assert.ok(helmRb.caveats.some((c) => /migration hook .* already ran; rollback does not reverse it/.test(c)));
  assert.equal(helmRb.commands[1], 'kubectl argo rollouts status ledger-api -n ledger --context prod-a', 'an Argo Rollout is watched with the plugin');
  assert.ok(a.rollbacks.some((r) => r.kind === 'roll-forward'));
  const rec = a.rollbacks.find((r) => r.recommended);
  assert.equal(rec.kind, 'canary-abort');
  assert.equal(rec.commands[0], 'kubectl argo rollouts abort ledger-api -n ledger --context prod-a');
  const order = a.rollbacks.map((r) => r.kind);
  // Without the canary, the safer fix-forward is recommended over the high-risk rollback.
  const noCanary = WR.analyze({ logs, helm: helm.replace(/Rollout \(argoproj\.io\)/, 'Deployment (apps)').replace('apiVersion: argoproj.io/v1alpha1\n  kind: Rollout', 'apiVersion: apps/v1\n  kind: Deployment'), context: ctx({ cluster: 'prod-a' }) });
  assert.equal(noCanary.rollbacks.find((r) => r.recommended).kind, 'roll-forward', JSON.stringify(order));
});

// ---------------------------------------------------------------------------------------------
// Signal cap and performance
// ---------------------------------------------------------------------------------------------
test('signals are capped at 3,000, keeping every error and the newest warnings', () => {
  const lines = [];
  const t0 = Date.parse('2026-10-05T10:00:00Z');
  for (let i = 0; i < 2000; i++) lines.push(`[pod/api-7d9f8b6c5d-x2k4p/api] {"level":"error","ts":"${new Date(t0 + i * 1000).toISOString()}","msg":"upstream returned status=503","upstream":"db-proxy"}`);
  // Warn-level lines become signals only when they carry a failure kind (here: a timeout).
  for (let i = 0; i < 2500; i++) lines.push(`[pod/api-7d9f8b6c5d-x2k4p/api] {"level":"warn","ts":"${new Date(t0 + i * 1000).toISOString()}","msg":"request to catalog timed out, retrying"}`);
  const a = WR.analyze({ logs: lines.join('\n'), context: { slo: {} } });
  assertAnalysis(a);
  assert.equal(a.signals.length, 3000);
  assert.equal(a.signals.filter((s) => s.severity === 'error').length, 2000);
  // The oldest warnings were dropped, except one the timeline points at (referenced ids are kept).
  const referenced = new Set(a.timeline.map((t) => t.signalId));
  const old = a.signals.filter((s) => s.severity === 'warn' && s.ts < t0 + 1500 * 1000);
  assert.ok(old.every((s) => referenced.has(s.id)), 'only referenced old warnings survive');
  assert.ok(old.length <= 1);
  assert.ok(a.warnings.some((w) => /Kept 3,000 of 4,500 signals/.test(w)));
});

function perfInput() {
  const t0 = Date.parse('2026-10-05T21:00:00Z');
  const svcs = ['frontend', 'checkout-api', 'payments-api', 'cart-api', 'catalog-api', 'search-api', 'orders-api', 'users-api'];
  const msgs = ['request served status=200', 'request failed status=503 upstream=payments-api.shop.svc.cluster.local', 'dial tcp 10.0.3.4:5432: connect: connection refused',
    'context deadline exceeded calling catalog-api', 'cache miss for key', 'lookup search-api.shop.svc.cluster.local on 10.96.0.10:53: i/o timeout'];
  const levels = ['info', 'error', 'error', 'warn', 'info', 'error'];
  const logs = [];
  for (let i = 0; i < 5000; i++) {
    const svc = svcs[i % svcs.length], k = i % msgs.length;
    logs.push(`[pod/${svc}-7d9f8b6c5d-x${(i % 7) + 2}k4p/${svc}] {"level":"${levels[k]}","ts":"${new Date(t0 + i * 400).toISOString()}","msg":"${msgs[k]}","trace_id":"${(i % 997).toString(16).padStart(32, '0')}"}`);
  }
  const spans = [];
  for (let t = 0; t < 200; t++) {
    const traceId = (t + 1).toString(16).padStart(32, '0');
    for (let j = 0; j < 10; j++) {
      const start = BigInt(t0 + t * 1000 + j * 10) * 1000000n;
      spans.push({
        traceId, spanId: ((t * 10 + j) + 1).toString(16).padStart(16, '0'), parentSpanId: j ? ((t * 10 + j)).toString(16).padStart(16, '0') : undefined,
        name: 'GET /op' + j, kind: j % 2 ? 3 : 2, startTimeUnixNano: String(start), endTimeUnixNano: String(start + BigInt(20 + j * 5) * 1000000n),
        status: { code: t % 9 === 0 && j === 9 ? 2 : 0 }, attributes: [{ key: 'http.response.status_code', value: { intValue: t % 9 === 0 && j === 9 ? '503' : '200' } }],
        _svc: svcs[j % svcs.length]
      });
    }
  }
  const bySvc = {};
  spans.forEach((s) => { (bySvc[s._svc] = bySvc[s._svc] || []).push(s); delete s._svc; });
  const traces = JSON.stringify({ resourceSpans: Object.keys(bySvc).map((svc) => ({
    resource: { attributes: [{ key: 'service.name', value: { stringValue: svc } }, { key: 'k8s.cluster.name', value: { stringValue: 'prod-perf' } }, { key: 'k8s.namespace.name', value: { stringValue: 'shop' } }] },
    scopeSpans: [{ spans: bySvc[svc] }]
  })) });
  return { logs: logs.join('\n'), traces, alerts: '', helm: '', context: { slo: { target: 0.999, windowDays: 30, requestsPerMin: 1200 } } };
}

test('performance: 5,000 log lines + 2,000 spans analyse in under 150 ms', () => {
  const input = perfInput();
  let best = Infinity, a;
  for (let i = 0; i < 3; i++) {
    const t = performance.now();
    a = WR.analyze(input);
    best = Math.min(best, performance.now() - t);
  }
  assertAnalysis(a);
  assert.equal(a.traits.spanCount, 2000);
  assert.equal(a.stats.logs.lines, 5000);
  assert.ok(best < 150, `best of 3: ${best.toFixed(1)} ms`);
});
