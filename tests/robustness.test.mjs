// Adversarial inputs for WR.analyze: panes pasted into the wrong tab, panes missing, garbage, huge
// pastes, clocks that lie, the same workload in two clusters, an already-rolled-back release. The
// engine must never throw, must keep every number finite, must say in plain words what went wrong,
// and must never recommend something that makes the incident worse.
import test from 'node:test';
import assert from 'node:assert/strict';
import load from './load.mjs';

const WR = load || globalThis.WR;
const MIN = 60000;
const PANES = ['logs', 'traces', 'alerts', 'helm'];

function input(s, over) { return Object.assign({ logs: s.logs, traces: s.traces, alerts: s.alerts, helm: s.helm, context: s.context }, over || {}); }

function assertFinite(v, path = 'analysis') {
  if (typeof v === 'number') { assert.ok(Number.isFinite(v), `${path} is ${v}`); return; }
  if (Array.isArray(v)) { v.forEach((x, i) => assertFinite(x, `${path}[${i}]`)); return; }
  if (v && typeof v === 'object') for (const k of Object.keys(v)) assertFinite(v[k], `${path}.${k}`);
}

// Invariants every Analysis must hold, whatever was pasted.
function assertInvariants(a, label) {
  assert.ok(a && typeof a === 'object', label);
  assertFinite(a, label);
  assert.doesNotThrow(() => JSON.stringify(a), label);
  const roots = a.components.filter((c) => c.status === 'root');
  assert.ok(roots.length <= 1, `${label}: at most one root`);
  const rec = a.rollbacks.filter((r) => r.recommended);
  if (a.rollbacks.length) assert.equal(rec.length, 1, `${label}: exactly one recommended rollback option`);
  // A root suspect gets an option, or an explicit sentence that none applies — never silence.
  if (roots.length && !a.rollbacks.length) assert.ok(a.warnings.some((w) => /No rollback or stop-gap applies/.test(w)), `${label}: root ${roots[0].id} with no options and no explanation`);
  const top = a.hypotheses[0];
  if (roots.length && top && (top.category === 'connection-exhaustion' || (/^(service|infra)$/.test(roots[0].type) && /^(unknown|dependency-failure|resource-limits)$/.test(top.category)))) {
    assert.ok(a.rollbacks.some((r) => r.fixes.includes(top.id)), `${label}: ${top.category} at ${roots[0].id} gets an option that addresses it`);
  }
  for (const h of a.hypotheses) {
    const ids = h.evidence.map((e) => (e.signalId ? 's:' + e.signalId : e.changeId ? 'c:' + e.changeId : null)).filter(Boolean);
    assert.equal(new Set(ids).size, ids.length, `${label}: ${h.category} cites the same evidence twice (${ids.join(', ')})`);
    assert.ok(h.confidence >= 0 && h.confidence <= 0.95, `${label}: confidence in range`);
  }
  const sigIds = a.signals.map((s) => s.id);
  assert.equal(new Set(sigIds).size, sigIds.length, `${label}: signal ids unique`);
  const idSet = new Set(sigIds);
  for (const c of a.changes) assert.ok(c.signalId == null || idSet.has(c.signalId), `${label}: change ${c.id} points at a missing signal`);
  for (const t of a.timeline) assert.ok(idSet.has(t.signalId), `${label}: timeline signal ${t.signalId}`);
  for (const h of a.hypotheses) for (const e of h.evidence) assert.ok(e.signalId == null || idSet.has(e.signalId), `${label}: evidence signal ${e.signalId}`);
  // SPEC: cap at 3,000 but keep every error, so only a paste with more errors than that exceeds
  // it — and then the only non-errors left are changes and signals the evidence/timeline cite.
  if (a.signals.length > 3000) {
    const cited = new Set([...a.hypotheses.flatMap((h) => h.evidence.map((e) => e.signalId)), ...a.timeline.map((t) => t.signalId), ...a.deploys.map((d) => d.signalId)]);
    const extra = a.signals.filter((s) => !WR.analyze.isError(s) && s.kind !== 'change' && !cited.has(s.id));
    assert.equal(extra.length, 0, `${label}: over the cap with ${extra.length} uncited non-error signals`);
  }
  if (a.budget.incidentMinutes != null) assert.ok(a.budget.incidentMinutes <= 7 * 1440, `${label}: incident lasted ${a.budget.incidentMinutes} min`);
  for (const r of a.rollbacks) for (const c of r.commands) assert.ok(typeof c === 'string' && c.length > 0 && !/undefined|null|NaN/.test(c), `${label}: command "${c}"`);
}

test('every sample, every subset of panes: invariants hold', () => {
  for (const s of WR.samples) {
    for (let mask = 1; mask < 16; mask++) {
      const over = {};
      PANES.forEach((p, i) => { if (!(mask & (1 << i))) over[p] = ''; });
      const label = `${s.id} panes=${PANES.filter((p, i) => mask & (1 << i)).join('+')}`;
      assertInvariants(WR.analyze(input(s, over)), label);
    }
  }
});

test('every sample with no context at all, or with CRLF line endings: invariants hold', () => {
  for (const s of WR.samples) {
    assertInvariants(WR.analyze({ logs: s.logs, traces: s.traces, alerts: s.alerts, helm: s.helm }), s.id + ' no context');
    const crlf = {};
    PANES.forEach((p) => { crlf[p] = s[p].replace(/\n/g, '\r\n'); });
    const a = WR.analyze(input(s, crlf));
    assertInvariants(a, s.id + ' CRLF');
    const b = WR.analyze(input(s));
    assert.equal(a.hypotheses[0].category, b.hypotheses[0].category, s.id + ' CRLF changes nothing');
    assert.equal(a.hypotheses[0].confidence, b.hypotheses[0].confidence, s.id + ' CRLF changes nothing');
  }
});

test('panes pasted into the wrong tab: no throw, and a warning that names the right pane', () => {
  for (const s of WR.samples) {
    const rotated = { logs: s.helm, traces: s.logs, alerts: s.traces, helm: s.alerts };
    const a = WR.analyze(input(s, rotated));
    assertInvariants(a, s.id + ' rotated');
    const misplaced = a.warnings.filter((w) => /looks like .* — paste it (in|into) /i.test(w));
    assert.ok(misplaced.length >= 2, `${s.id}: misplaced-pane warnings: ${a.warnings.join(' | ')}`);
    // The warnings lead the list, where the engineer looks first.
    assert.match(a.warnings[0], /looks like/);
  }
});

test('correctly placed panes never trigger a wrong-pane warning', () => {
  for (const s of WR.samples) {
    const a = WR.analyze(input(s));
    assert.ok(!a.warnings.some((w) => /looks like .* — paste it/i.test(w)), `${s.id}: ${a.warnings.join(' | ')}`);
  }
});

test('garbage, binary, nulls and wrong types never throw', () => {
  let seed = 7;
  const rnd = () => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x7fffffff; };
  const junk = (n) => Array.from({ length: n }, () => String.fromCharCode(Math.floor(rnd() * 0xd7ff))).join('');
  const cases = [
    { logs: junk(40000), traces: junk(4000), alerts: junk(4000), helm: junk(4000) },
    { logs: '\x00\x01\x02'.repeat(2000), traces: '{"resourceSpans":[{"scopeSpans":[{"spans":[null,1,"x",{}]}]}]}', alerts: '{"alerts":[null,{"labels":null},{"labels":{"alertname":123}}]}', helm: '+ - \n--- \n+++ \n@@ \n...\n' },
    { logs: null, traces: undefined, alerts: 42, helm: {}, context: null },
    { logs: ['a'], traces: { resourceSpans: [] }, alerts: true, helm: () => 1, context: { now: 'garbage', defaultTz: 'nope', year: 'x', slo: { target: 5, windowDays: -1, requestsPerMin: 'x', budgetSpentBeforePct: 400, errorRatioOverride: -3 } } },
    { logs: '{'.repeat(5000), traces: '['.repeat(5000), alerts: '{"alerts":['.repeat(500), helm: 'a, b, Deployment (apps) has changed:\n' + '+'.repeat(5000) }
  ];
  for (const [i, c] of cases.entries()) {
    const a = WR.analyze(c);
    assertInvariants(a, 'garbage case ' + i);
    assert.equal(a.severity, 'SEV4', 'garbage is not an incident');
  }
  assertInvariants(WR.analyze(undefined), 'undefined');
  assertInvariants(WR.analyze('a string'), 'string input');
});

test('20,000-line pastes stay fast and capped', () => {
  const s = WR.samples[0];
  const lines = s.logs.split('\n');
  const big = [];
  while (big.length < 20000) big.push(...lines);
  const t0 = performance.now();
  const a = WR.analyze(input(s, { logs: big.slice(0, 20000).join('\n') }));
  const ms = performance.now() - t0;
  assertInvariants(a, '20k sample lines');
  assert.ok(ms < 1500, `20,000 lines took ${ms.toFixed(0)} ms`);
  assert.equal(a.hypotheses[0].category, 'resource-limits');

  const junk = Array.from({ length: 20000 }, (_, i) => 'line ' + i + ' ' + (i * 7919).toString(36).repeat(6)).join('\n');
  const t1 = performance.now();
  const b = WR.analyze({ logs: junk, traces: junk, alerts: junk, helm: junk });
  assert.ok(performance.now() - t1 < 2500, 'four 20,000-line junk panes');
  assertInvariants(b, '20k junk x4');
  assert.equal(b.severity, 'SEV4');
});

test('one stray far-future timestamp does not become "now"', () => {
  const s = WR.samples[0];
  const base = WR.analyze(input(s, { context: Object.assign({}, s.context, { now: undefined }) }));
  const a = WR.analyze(input(s, { logs: s.logs + '\n2030-01-01T00:00:00Z ERROR something exploded\n', context: Object.assign({}, s.context, { now: undefined }) }));
  assertInvariants(a, 'future outlier');
  assert.equal(a.window.now, base.window.now, 'now is still the latest real evidence');
  assert.ok(a.budget.consumedPct < 100, `consumed ${a.budget.consumedPct}%`);
  assert.ok(a.warnings.some((w) => /2030-01-01/.test(w) && /ignored|ignoring/i.test(w)), a.warnings.join(' | '));
});

test('with "now" set, a stray far-future stamp is called a typo, not a reason to set the time', () => {
  const s = WR.samples[0];
  const a = WR.analyze(input(s, { logs: s.logs + '\n2030-01-01T00:00:00Z ERROR something exploded\n' }));
  assertInvariants(a, 'future outlier with now');
  const w = a.warnings.filter((x) => /2030-01-01/.test(x));
  assert.equal(w.length, 1, a.warnings.join(' | '));
  assert.match(w[0], /typo/);
  assert.doesNotMatch(w[0], /Set the current time/);
  assert.ok(!a.warnings.some((x) => /later than the current time/i.test(x)), 'the typo does not count as late evidence');
});

test('hours of healthy log lines after the errors move "now" forward; they are not an outlier', () => {
  // The shape of `kubectl logs --since=24h` pasted the next afternoon: errors at 09:00, then a
  // steady stream of info lines until 16:00. Info lines are not signals, so the clock check must
  // still see them as many points, not one isolated stamp.
  const lines = [];
  for (let i = 0; i < 20; i++) lines.push(`2026-10-05T09:00:${String(i).padStart(2, '0')}Z ERROR payments-api upstream connect error`);
  for (let m = 0; m < 7 * 60; m += 2) lines.push(`${new Date(Date.parse('2026-10-05T09:01:00Z') + m * 60000).toISOString()} INFO payments-api request ok`);
  const a = WR.analyze({ logs: lines.join('\n'), traces: '', alerts: '', helm: '', context: {} });
  assertInvariants(a, 'dense tail');
  assert.equal(a.window.now, Date.parse('2026-10-05T15:59:00Z'));
  assert.ok(!a.warnings.some((x) => /Ignored|typo/.test(x)), a.warnings.join(' | '));
});

test('a "now" set far after the evidence is flagged; one set before it is flagged too', () => {
  const s = WR.samples[0];
  const late = WR.analyze(input(s, { context: Object.assign({}, s.context, { now: '2026-10-08T00:00:00Z' }) }));
  assertInvariants(late, 'late now');
  assert.ok(late.warnings.some((w) => /after the latest evidence/i.test(w)), late.warnings.join(' | '));
  const early = WR.analyze(input(s, { context: Object.assign({}, s.context, { now: '2026-10-04T00:00:00Z' }) }));
  assertInvariants(early, 'early now');
  assert.ok(early.warnings.some((w) => /later than the current time/i.test(w)), early.warnings.join(' | '));
});

test('only alerts / only traces / zero spans: still a usable answer', () => {
  for (const s of WR.samples) {
    for (const p of PANES) {
      const over = { logs: '', traces: '', alerts: '', helm: '' };
      over[p] = s[p];
      assertInvariants(WR.analyze(input(s, over)), `${s.id} only ${p}`);
    }
  }
  const z = WR.analyze({ traces: '{"resourceSpans":[]}', context: {} });
  assertInvariants(z, 'zero spans');
  assert.equal(z.severity, 'SEV4');
  assert.ok(z.warnings.some((w) => /no spans/i.test(w)));
});

test('the same workload name in two clusters stays two components; unclustered evidence is not glued to either', () => {
  const a = WR.analyze({
    logs: '# cluster: prod-a\n2026-10-05T21:50:00Z {"level":"error","service":"api","namespace":"shop","msg":"dial tcp 10.0.0.9:5432: connect: connection refused"}\n' +
      '# cluster: prod-b\n2026-10-05T21:50:00Z {"level":"info","service":"api","namespace":"shop","msg":"ok"}\n',
    alerts: '2026-10-05T21:51:00Z FIRING critical ApiHighErrorRate service=api namespace=shop\n',
    context: {}
  });
  assertInvariants(a, 'dup names');
  const ids = a.components.map((c) => c.id);
  assert.ok(ids.includes('service:prod-a/shop/api') && ids.includes('service:prod-b/shop/api'), ids.join(', '));
  assert.equal(a.components.find((c) => c.id === 'service:prod-b/shop/api').status, 'healthy');
  const alert = a.signals.find((s) => s.source === 'alerts');
  assert.ok(!/prod-a|prod-b/.test(alert.componentId), 'ambiguous: ' + alert.componentId);
});

test('an already rolled-back release is never "rolled back" to the bad revision', () => {
  const s = WR.samples[0];
  const lines = s.helm.split('\n');
  const i42 = lines.findIndex((l) => /^42\s/.test(l) && /deployed/.test(l));
  assert.ok(i42 > 0, 'sample 1 has the r42 history row');
  lines[i42] = lines[i42].replace('deployed  ', 'superseded');
  lines.splice(i42 + 1, 0, '43      \tMon Oct  5 23:58:30 2026\tdeployed  \tpayments-1.8.2\t2.13.4     \tRollback to 41  ');
  const a = WR.analyze(input(s, { helm: lines.join('\n') }));
  assertInvariants(a, 'after rollback');
  for (const r of a.rollbacks) for (const c of r.commands) assert.ok(!/helm rollback payments 42\b/.test(c), 'would re-apply r42: ' + c);
  assert.equal(a.deploy.revision, 42);
  assert.equal(a.deploy.previousRevision, 41);
  assert.ok(a.deploy.rolledBack && a.deploy.rolledBack.revision === 43);
  assert.equal(a.hypotheses[0].category, 'resource-limits', 'the cause is still the r42 memory cut');
  assert.ok(a.hypotheses[0].confidence >= 0.9);
  assert.ok(a.warnings.some((w) => /already rolled back/i.test(w)), a.warnings.join(' | '));
  // Errors continue after the 21:58:30 rollback in this paste: say so, and do not offer to revert
  // r42's changes again (the rollback already did).
  assert.ok(a.warnings.some((w) => /after the rollback/i.test(w)), a.warnings.join(' | '));
  assert.ok(!a.rollbacks.some((r) => r.kind === 'resource-restore'), 'the limit is already back at 512Mi');
});

test('connection exhaustion seen only at the database: the stop-gap acts on the clients, not the database', () => {
  const s = WR.samples[3];
  const a = WR.analyze(input(s, { logs: '', traces: '', helm: '' }));
  assertInvariants(a, 'db alerts only');
  for (const r of a.rollbacks) for (const c of r.commands) assert.ok(!/rollout restart (statefulset|sts)\/orders-postgresql/.test(c), 'restarts the database: ' + c);
});

test('a giant Helm diff (thousands of changed fields) is folded and capped', () => {
  const hl = ['$ helm diff upgrade big ./chart -n shop --kube-context prod-a', 'shop, big-config, ConfigMap (v1) has changed:', '  data:'];
  for (let i = 0; i < 10000; i++) { hl.push('-   KEY_' + i + ': "a' + i + '"'); hl.push('+   KEY_' + i + ': "b' + i + '"'); }
  hl.push('shop, big, Deployment (apps) has changed:', '  spec:', '    template:', '      spec:', '        containers:', '        - name: big', '-         image: registry.example.com/big:1.0.0', '+         image: registry.example.com/big:1.1.0');
  const t0 = performance.now();
  const a = WR.analyze({ helm: hl.join('\n'), context: {} });
  assert.ok(performance.now() - t0 < 1000);
  assertInvariants(a, 'giant helm diff');
  assert.ok(a.changes.length <= 45, `${a.changes.length} changes`);
  const agg = a.changes.find((c) => /more changed fields/.test(c.summary));
  assert.ok(agg, 'the rest is summarised');
  assert.match(agg.summary, /9960 more changed fields/);
  assert.ok(a.changes.some((c) => c.category === 'image'), 'the image change in the next resource is kept');
  const ids = new Set(a.signals.map((s) => s.id));
  for (const c of a.changes) assert.ok(c.signalId === null || ids.has(c.signalId), 'change signal exists: ' + c.signalId);
});

test('non-breaking spaces and a byte-order mark (copied from chat or a saved file) are plain whitespace', () => {
  const nb = '﻿shop, payments-api, Deployment (apps) has changed:\n  spec:\n    template:\n      spec:\n        containers:\n        - name: payments-api\n-         image: registry.example.com/payments:2.13.4\n+         image: registry.example.com/payments:2.14.0\n';
  const r = WR.parseHelm(nb, { defaultTz: 'Z' });
  assert.equal(r.stats.skipped, 0);
  assert.deepEqual(r.extras.changes.map((c) => c.field), ['spec.template.spec.containers[payments-api].image']);
});
