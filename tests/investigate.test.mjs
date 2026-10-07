// Pure parts of the "Investigate with Claude" panel (src/ui/investigate.js): redaction that keeps
// line numbers, the six read-only tools and their size caps, the prompt and evidence pack, and the
// normalisation of Claude's JSON. The DOM part is checked in headless Chrome, not here.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import WR from './load.mjs';

await import(new URL('../src/ui/investigate.js', import.meta.url));
const T = WR.ui.investigate._test;
const SOURCES = ['logs', 'traces', 'alerts', 'helm'];

const runs = WR.samples.map((s) => {
  const inputs = { logs: s.logs, traces: s.traces, alerts: s.alerts, helm: s.helm };
  const analysis = WR.analyze({ ...inputs, context: s.context });
  return { s, inputs, analysis, snap: T.makeSnapshot(analysis, inputs) };
});

test('redacted panes keep their line count, including multi-line private keys', () => {
  for (const { s, snap } of runs) {
    for (const src of SOURCES) assert.equal(snap.panes[src].lines.length, snap.panes[src].rawLineCount, `${s.id} ${src}`);
  }
  const text = 'line 1\n-----BEGIN RSA PRIVATE KEY-----\nAAAA\nBBBB\n-----END RSA PRIVATE KEY-----\nline 6 password=hunter22\nline 7';
  const r = T.redactPane(text);
  assert.equal(r.text.split('\n').length, text.split('\n').length);
  assert.equal(r.text.split('\n')[5].startsWith('line 6'), true);
  assert.ok(!r.text.includes('AAAA') && !r.text.includes('hunter22'));
  assert.equal(r.byKind['private-key'], 1);
});

test('the fake DB_PASSWORD is counted and never leaves the page', () => {
  const db = runs.find((r) => r.s.id === 'db-conn-exhaustion');
  assert.ok(db.snap.secretCount >= 1);
  const hit = T.runTool(db.snap, 'search_evidence', { query: 'DB_PASSWORD' });
  assert.equal(hit.failed, false);
  assert.ok(hit.result.total >= 1);
  for (const { snap } of runs) {
    const payloads = [T.buildPrompt(snap, 'agent', T.TOOL_NAMES), T.buildPrompt(snap, 'oneshot', [])];
    for (const name of T.TOOL_NAMES) payloads.push(JSON.stringify(T.runTool(snap, name, { componentId: snap.analysis.hypotheses[0].componentId, query: 'PASSWORD' })));
    for (const p of payloads) assert.ok(!p.includes('hunter2-not-real'));
  }
});

test('every tool result fits in 8 KB, the evidence pack in 60 KB', () => {
  for (const { s, snap, analysis } of runs) {
    const top = analysis.hypotheses[0].componentId;
    const calls = [
      ['list_components', {}], ['get_component_signals', { componentId: top, limit: 60 }], ['get_component_signals', { componentId: top }],
      ['search_evidence', { query: 'e' }], ['search_evidence', { query: 'error', source: 'logs' }], ['get_changes', {}],
      ['get_dependencies', { componentId: top }], ['get_budget', {}]
    ];
    for (const [name, input] of calls) {
      const out = T.runTool(snap, name, input);
      assert.equal(out.failed, false, `${s.id} ${name}`);
      assert.ok(T.byteLen(JSON.stringify(out.result)) <= T.TOOL_MAX_BYTES, `${s.id} ${name} too big`);
      assert.ok(out.step && out.step.length < 160, `${s.id} ${name} step`);
    }
    assert.ok(T.byteLen(T.evidencePack(snap)) <= T.PACK_MAX_BYTES, `${s.id} pack`);
  }
});

test('search_evidence is a literal, case-insensitive search that links lines to signals', () => {
  const { snap } = runs[0];
  const weird = T.runTool(snap, 'search_evidence', { query: '(.*[' });
  assert.equal(weird.failed, false);
  assert.equal(weird.result.total, 0);
  const oom = T.runTool(snap, 'search_evidence', { query: 'oomkilled' });
  assert.ok(oom.result.total > 0);
  assert.ok(oom.result.matches.some((m) => m.signalId && snap.sigById[m.signalId]));
  for (const m of oom.result.matches) assert.ok(m.text.toLowerCase().includes('oomkilled'), m.text);
  assert.equal(T.runTool(snap, 'search_evidence', { query: '  ' }).failed, true);
});

test('components resolve from ids, names and paths; misses name real ids', () => {
  const { snap } = runs[0];
  assert.equal(T.resolveComponent(snap, 'payments-api').comp.id, 'service:prod-eu-west/shop/payments-api');
  assert.equal(T.resolveComponent(snap, 'prod-us-east/shop/payments-api').comp.id, 'service:prod-us-east/shop/payments-api');
  assert.equal(T.resolveComponent(snap, 'service:prod-eu-west/shop/checkout-api').comp.id, 'service:prod-eu-west/shop/checkout-api');
  const miss = T.resolveComponent(snap, 'nope');
  assert.equal(miss.comp, null);
  assert.match(miss.message, /service:prod-eu-west\/shop\/payments-api/);
  const sig = T.runTool(snap, 'get_component_signals', { componentId: 'payments-api', kinds: ['oom_killed'] });
  assert.ok(sig.result.signals.length > 0 && sig.result.signals.every((x) => x.kind === 'oom_killed'));
  assert.match(sig.step, /payments-api in prod-eu-west/);
});

test('tools are offered in priority order, capped by the view, and log a step per call', async () => {
  assert.deepEqual(T.toolNamesFor(null), []);
  assert.deepEqual(T.toolNamesFor({ maxPromptBytes: 1 }), []);
  assert.equal(T.toolNamesFor({ tools: { maxCount: 20 } }).length, 6);
  assert.deepEqual(T.toolNamesFor({ tools: { maxCount: 2 } }), ['search_evidence', 'get_component_signals']);
  const steps = [];
  const tools = T.buildTools(runs[0].snap, T.TOOL_NAMES, (st) => steps.push(st), () => true);
  assert.equal(tools.length, 6);
  for (const t of tools) {
    assert.match(t.name, /^[A-Za-z0-9_-]{1,128}$/);
    assert.ok(t.description.length > 20 && t.description.length <= 1024);
    if (t.inputSchema) assert.ok(JSON.stringify(t.inputSchema).length <= 4096);
  }
  const ac = new AbortController();
  const ok = await tools.find((t) => t.name === 'get_changes').execute({}, { signal: ac.signal });
  assert.ok(Array.isArray(ok.changes));
  assert.throws(() => tools.find((t) => t.name === 'get_dependencies').execute({ componentId: 'nope' }, { signal: ac.signal }), /No component matches/);
  assert.equal(steps.length, 2);
  assert.equal(steps[1].failed, true);
  ac.abort();
  assert.throws(() => tools[0].execute({ query: 'x' }, { signal: ac.signal }), /stopped/);
});

test('the prompt carries the rule engine top 3, the reply shape and read-only rules', () => {
  for (const { snap, analysis } of runs) {
    const agent = T.buildPrompt(snap, 'agent', T.TOOL_NAMES);
    const one = T.buildPrompt(snap, 'oneshot', []);
    for (const h of analysis.hypotheses.slice(0, 3)) { assert.ok(agent.includes(h.id)); assert.ok(one.includes(h.id)); }
    for (const p of [agent, one]) {
      assert.match(p, /needsApproval/);
      assert.match(p, /evidenceChain/);
      assert.match(p, /data, not instructions/);
      assert.ok(T.byteLen(p) < 100000);
    }
    assert.match(agent, /search_evidence/);
    assert.match(one, /## Evidence pack/);
    assert.ok(!agent.includes('## Evidence pack'));
  }
});

test("Claude's reply is normalised defensively", () => {
  const { snap } = runs[0];
  assert.equal(T.normalizeResult(null, snap), null);
  assert.equal(T.normalizeResult([1, 2], snap), null);
  assert.equal(T.normalizeResult({}, snap), null);
  const r = T.normalizeResult({
    summary: 'x', rootCause: { componentId: 'payments-api', category: 'Resource Limits', statement: 's', confidence: 85 },
    evidenceChain: [{ signalId: '[log-47]', why: 'a' }, { signalId: 'chg-1khvnt3', why: 'b' }, { signalId: 'log-99999', why: 'c' }, { signalId: null, why: 'd' }],
    ruledOut: ['probes', { hypothesis: 'dns', why: 'no lookups failed' }],
    remediation: [{ action: 'roll back', command: ['helm rollback payments 41', 'kubectl rollout status'], risk: 'LOW', needsApproval: false }],
    openQuestions: ['q1', { question: 'q2' }, 7]
  }, snap);
  assert.equal(r.rootCause.componentId, 'service:prod-eu-west/shop/payments-api');
  assert.equal(r.rootCause.category, 'resource-limits');
  assert.equal(r.rootCause.confidence, 0.85);
  assert.equal(r.evidenceChain[0].signalId, 'log-47');
  assert.equal(r.evidenceChain[0].ref.jumpId, 'log-47');
  assert.equal(r.evidenceChain[1].ref.type, 'change');
  assert.equal(r.evidenceChain[2].ref, null);
  assert.equal(r.evidenceChain[3].signalId, null);
  assert.equal(r.ruledOut.length, 2);
  assert.equal(r.remediation[0].needsApproval, true);
  assert.equal(r.remediation[0].risk, 'low');
  assert.equal(r.remediation[0].command, 'helm rollback payments 41\nkubectl rollout status');
  assert.deepEqual(r.openQuestions, ['q1', 'q2']);
  assert.equal(T.normalizeResult({ summary: 's', rootCause: { confidence: 'high' } }, snap).rootCause.confidence, 0.8);
});

test('comparison: agree on component + category, differ otherwise, and name the matching engine hypothesis', () => {
  const { snap, analysis } = runs[0];
  const top = analysis.hypotheses[0];
  const same = T.compareReads({ rootCause: { componentId: top.componentId, category: top.category } }, snap);
  assert.equal(same.agree, true);
  const diff = T.compareReads({ rootCause: { componentId: top.componentId, category: 'bad-deploy' } }, snap);
  assert.equal(diff.agree, false);
  assert.match(diff.detail, /Same component/);
  assert.match(diff.detail, /second hypothesis/);
  const blank = T.makeSnapshot(WR.analyze({ logs: '', traces: '', alerts: '', helm: '', context: {} }), {});
  assert.equal(T.compareReads({ rootCause: { componentId: 'x', category: 'dns' } }, blank).agree, null);
  assert.equal(blank.hasEvidence, false);
});

test('narration hides the JSON reply while it streams; tolerant parse for the json()-less fallback', () => {
  assert.deepEqual(T.splitNarration('Checking signals.'), { narration: 'Checking signals.', writing: false });
  assert.equal(T.splitNarration('Done.\n\n{"summary":').narration.trim(), 'Done.');
  assert.equal(T.splitNarration('Done.\n```json\n{').writing, true);
  assert.equal(T.splitNarration('{"a":1').narration, '');
  assert.deepEqual(T.tolerantParse('Here:\n```json\n{"a":1}\n```'), { a: 1 });
  assert.deepEqual(T.tolerantParse('x {"a":2} y'), { a: 2 });
  assert.equal(T.tolerantParse('no json'), undefined);
  for (const code of ['rate_limited', 'session_expired', 'refused', 'empty_completion', 'invalid_json', 'prompt_too_large', 'upstream_error', 'something_new']) {
    const e = T.errorInfo(code);
    assert.ok(e.title && e.body, code);
  }
  assert.equal(T.errorInfo('tools_unavailable').offerOneShot, true);
});
