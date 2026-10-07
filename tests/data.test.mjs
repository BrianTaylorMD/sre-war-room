// Tests for the data module WR.stacks / WR.stackFit (src/data/stacks.js). They check the SPEC §6.6b shapes, that every source is one the research
// verified, that nothing is copied from a source, that talks never read as launches, and that the
// stack fit reacts to the incident and to the scale inputs.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import WR from './load.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const verified = JSON.parse(readFileSync(path.join(root, 'research/verified.json'), 'utf8'));
const WORKBOOK = 'https://sre.google/workbook/alerting-on-slos/';

const claims = [];
for (const t of verified.topics) for (const it of t.items) for (const c of it.claims) claims.push({ topic: t.key, item: it, ...c });
const VERIFIED_URLS = new Set(claims.map((c) => c.url));
const okUrl = (u) => VERIFIED_URLS.has(u) || u === WORKBOOK;

const fixtures = readdirSync(path.join(root, 'fixtures'))
  .filter((f) => /^analysis-.*\.json$/.test(f))
  .map((f) => ({ name: f, a: JSON.parse(readFileSync(path.join(root, 'fixtures', f), 'utf8')) }));

const KINDS = new Set(['announced', 'released', 'talk', 'doc', 'documented-limit']);
const ANCHORS = new Set(['#claude', '#map', '#causes', '#rollback', '#budget', '#stacks']);
const TIMINGS = new Set(['event-week', 'background']);
const LEVELS = new Set(['breaks', 'strain', 'ok']);
const VERDICTS = new Set(['Good fit', 'Workable', 'Strained']);
const STACK_IDS = ['datadog', 'grafana', 'otel', 'hosted'];
const MONTHS = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
const WINDOW = { start: '2026-03-17', end: '2026-04-03' };


// Every string in a value, skipping URLs (they are links, not prose).
function strings(v, out = []) {
  if (typeof v === 'string') { if (!/^https?:\/\//.test(v)) out.push(v); }
  else if (Array.isArray(v)) v.forEach((x) => strings(x, out));
  else if (v && typeof v === 'object') Object.keys(v).forEach((k) => { if (k !== 'url') strings(v[k], out); });
  return out;
}
const words = (s) => String(s).toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim().split(' ').filter(Boolean);
function shingles(ws, n) {
  const out = [];
  for (let i = 0; i + n <= ws.length; i++) out.push(ws.slice(i, i + n).join(' '));
  return out;
}
// Dates written in a source's `published` field: "2026-03-24", "Session dates 2026-03-24 and 2026-03-26".
const isoDates = (s) => (String(s).match(/\d{4}-\d{2}-\d{2}/g) || []);

// ------------------------------------------------------------------------------------------
// WR.stacks
// ------------------------------------------------------------------------------------------
test('stacks: shape matches SPEC 6.6b and every sourceId exists', () => {
  const st = WR.stacks;
  assert.ok(st, 'WR.stacks is defined');
  assert.equal(st.asOf, '2026-10-06');
  assert.deepEqual(st.stacks.map((x) => x.id), STACK_IDS);
  const has = (id) => Object.prototype.hasOwnProperty.call(st.sources, id);
  for (const x of st.stacks) {
    assert.ok(x.name && x.tagline, x.id + ' name and tagline');
    for (const r of ['shows', 'correlate', 'multicluster', 'ai']) {
      const row = x.rows[r];
      assert.ok(row && row.text && row.text.trim(), x.id + '.' + r + ' text');
      assert.ok(Array.isArray(row.sourceIds) && typeof row.reasoning === 'boolean', x.id + '.' + r + ' sourceIds/reasoning');
      assert.ok(row.sourceIds.length > 0 || row.reasoning, x.id + '.' + r + ' cites a source or is marked reasoning');
      row.sourceIds.forEach((id) => assert.ok(has(id), x.id + '.' + r + ' unknown sourceId ' + id));
    }
    for (const p of x.prices) {
      assert.ok(p.id && p.label && p.unit, x.id + ' price fields');
      assert.ok(p.usd === null || (typeof p.usd === 'number' && isFinite(p.usd) && p.usd >= 0), p.id + ' usd');
      if (p.sourceId !== null) assert.ok(has(p.sourceId), p.id + ' unknown sourceId ' + p.sourceId);
      else assert.equal(p.usd, null, p.id + ' a price without a source must be null');
    }
    for (const l of x.limits) {
      assert.ok(l.id && l.text && l.value, x.id + ' limit fields');
      assert.ok(has(l.sourceId), l.id + ' unknown sourceId ' + l.sourceId);
    }
  }
});

test('stacks: every source url is in research/verified.json (or is the SRE workbook)', () => {
  for (const [id, s] of Object.entries(WR.stacks.sources)) {
    assert.ok(okUrl(s.url), id + ' not verified: ' + s.url);
    assert.ok(s.title && s.asOf, id + ' title and asOf');
  }
});

test('stacks: every numeric price appears in a verified claim from the same source', () => {
  for (const x of WR.stacks.stacks) {
    for (const p of x.prices) {
      if (p.usd === null) continue;
      const url = WR.stacks.sources[p.sourceId].url;
      const text = claims.filter((c) => c.url === url).map((c) => [c.text, c.snippet, c.note].join(' ')).join(' ');
      const forms = [String(p.usd), p.usd.toFixed(2), p.usd.toFixed(3)];
      assert.ok(forms.some((f) => text.includes(f)), p.id + ' $' + p.usd + ' not found in verified claims for ' + url);
    }
  }
});

// ------------------------------------------------------------------------------------------
// Nothing copied from a source
// ------------------------------------------------------------------------------------------
function publishedText() {
  const out = strings(WR.stacks);
  const variants = [{}, { highCardinalityLabels: ['pod', 'user_id'], errorTracesMissing: true, multiCluster: true, clusterCount: 3, untracedFailingComponents: ['service:c/ns/a'], sources: { logs: true, traces: true }, logLinesPerMin: 1200 }];
  for (const f of fixtures) variants.push(f.a.traits);
  for (const v of variants) for (const sc of [{}, { activeSeries: 3000000, logsGbPerDay: 400 }, { activeSeries: 1000, nodes: 100 }]) out.push(...strings(WR.stackFit(v, sc)));
  return out;
}

test('no run of 6 or more words from any source snippet or quoted source text appears in published text', () => {
  const pub = new Set(publishedText().flatMap((s) => shingles(words(s), 6)));
  const pubShort = publishedText().map((s) => ' ' + words(s).join(' ') + ' ');
  const hits = [];
  // Snippets plus every span the research notes quote from the page ('...' or "...").
  const quoted = [];
  for (const c of claims) {
    quoted.push({ url: c.url, text: c.snippet || '', snippet: true });
    for (const m of String(c.note || '').matchAll(/'([^']{12,})'|"([^"]{12,})"|\u2018([^\u2019]{12,})\u2019|\u201c([^\u201d]{12,})\u201d/g)) quoted.push({ url: c.url, text: m[1] || m[2] || m[3] || m[4] });
  }
  for (const c of quoted) {
    const w = words(c.text);
    if (w.length >= 6) {
      for (const sh of shingles(w, 6)) if (pub.has(sh)) hits.push(c.url + ' :: "' + sh + '"');
    } else if (c.snippet && w.length >= 4) {
      const phrase = ' ' + w.join(' ') + ' ';
      if (pubShort.some((p) => p.includes(phrase))) hits.push(c.url + ' :: "' + w.join(' ') + '"');
    }
  }
  assert.deepEqual([...new Set(hits)], [], 'copied source text');
});

test('published text does not lift long runs from the research write-ups either', () => {
  const pub = new Set(publishedText().flatMap((s) => shingles(words(s), 10)));
  const hits = [];
  for (const t of verified.topics) for (const it of t.items) {
    for (const src of [it.summary, it.operationalIdea, it.appFeatureHint, ...it.claims.map((c) => c.text)]) {
      for (const sh of shingles(words(src || ''), 10)) if (pub.has(sh)) hits.push(it.id + ' :: "' + sh + '"');
    }
  }
  assert.deepEqual([...new Set(hits)], [], 'lifted research prose');
});

// ------------------------------------------------------------------------------------------
// WR.stackFit
// ------------------------------------------------------------------------------------------
function checkFit(fit, label) {
  assert.deepEqual(Object.keys(fit).sort(), [...STACK_IDS].sort(), label + ': all four stacks');
  const sources = WR.stacks.sources;
  for (const id of STACK_IDS) {
    const r = fit[id];
    const prices = new Map(WR.stacks.stacks.find((x) => x.id === id).prices.map((p) => [p.id, p]));
    assert.ok(VERDICTS.has(r.verdict), label + ' ' + id + ' verdict ' + r.verdict);
    assert.ok(Array.isArray(r.flags) && r.flags.length >= 1, label + ' ' + id + ' flags');
    for (const f of r.flags) {
      assert.ok(LEVELS.has(f.level), label + ' ' + id + ' level ' + f.level);
      assert.ok(f.text && f.because, label + ' ' + id + ' flag text and because');
      assert.ok(Array.isArray(f.sourceIds) && typeof f.reasoning === 'boolean');
      assert.ok(f.sourceIds.length > 0 || f.reasoning, label + ' ' + id + ' flag cites a source or is reasoning: ' + f.text);
      f.sourceIds.forEach((s) => assert.ok(sources[s], label + ' ' + id + ' unknown sourceId ' + s));
    }
    const order = { breaks: 0, strain: 1, ok: 2 };
    for (let i = 1; i < r.flags.length; i++) assert.ok(order[r.flags[i - 1].level] <= order[r.flags[i].level], label + ' ' + id + ' flags sorted by level');
    const breaks = r.flags.filter((f) => f.level === 'breaks').length;
    const strain = r.flags.filter((f) => f.level === 'strain').length;
    assert.equal(r.verdict, breaks ? 'Strained' : strain >= 2 ? 'Workable' : 'Good fit', label + ' ' + id + ' verdict follows the rule');
    assert.ok(Array.isArray(r.costLines) && r.costLines.length >= 1, label + ' ' + id + ' cost lines');
    for (const c of r.costLines) {
      assert.ok(c.label && c.basis, label + ' ' + id + ' cost line label and basis');
      assert.ok(c.monthlyUsd === null || (typeof c.monthlyUsd === 'number' && isFinite(c.monthlyUsd) && c.monthlyUsd >= 0), label + ' ' + id + ' monthlyUsd ' + c.monthlyUsd);
      if (c.sourceId !== null) assert.ok(sources[c.sourceId], label + ' ' + id + ' cost sourceId ' + c.sourceId);
      if (c.priceId !== null) {
        assert.ok(prices.has(c.priceId), label + ' ' + id + ' cost priceId ' + c.priceId);
        if (prices.get(c.priceId).usd === null) assert.equal(c.monthlyUsd, null, label + ' ' + id + ' an unverified price never produces a number: ' + c.label);
      }
      if (c.monthlyUsd !== null) {
        assert.ok(c.sourceId && c.priceId, label + ' ' + id + ' a priced line names its source and price: ' + c.label);
        assert.match(c.basis, /list price, before discounts/i, label + ' ' + id + ' basis says list price: ' + c.label);
      }
    }
  }
}

test('stackFit: returns all four stacks with well-formed flags and cost lines for every fixture', () => {
  assert.ok(fixtures.length >= 5);
  for (const f of fixtures) checkFit(WR.stackFit(f.a.traits, {}), f.name);
});

test('stackFit: never throws on blank or bad input; bad scale values fall back to defaults', () => {
  const base = WR.stackFit({}, {});
  checkFit(WR.stackFit(), 'undefined');
  checkFit(WR.stackFit(null, null), 'null');
  checkFit(WR.stackFit({ highCardinalityLabels: 'pod', clusterCount: 'x', logLinesPerMin: NaN }, { nodes: 'abc' }), 'junk');
  const junk = WR.stackFit({}, { nodes: 'abc', logsGbPerDay: '', activeSeries: -5, apmHosts: NaN });
  assert.deepEqual(junk, base, 'junk scale behaves like the defaults');
  const asStrings = WR.stackFit({}, { nodes: '40', logsGbPerDay: '50', activeSeries: '500,000', apmHosts: ' 20 ' });
  assert.deepEqual(asStrings, base, 'numeric strings from inputs are read as numbers');
});

test('stackFit: every stack reacts to multi-cluster, high-cardinality labels and missing error traces', () => {
  const base = { ...fixtures.find((f) => f.name === 'analysis-bad-deploy-oom.json').a.traits };
  const one = { ...base, multiCluster: false, clusterCount: 1, clusters: ['prod-eu-west'], failingClusterCount: 1 };
  const toggles = {
    multiCluster: [one, { ...one, multiCluster: true, clusterCount: 2, clusters: ['prod-eu-west', 'prod-us-east'] }],
    highCardinalityLabels: [{ ...one, highCardinalityLabels: [] }, { ...one, highCardinalityLabels: ['pod'] }],
    errorTracesMissing: [{ ...one, errorTracesMissing: false }, { ...one, errorTracesMissing: true }]
  };
  for (const [name, [off, on]] of Object.entries(toggles)) {
    const a = WR.stackFit(off, {}), b = WR.stackFit(on, {});
    for (const id of STACK_IDS) {
      assert.notDeepEqual(a[id].flags, b[id].flags, id + ' flags change when ' + name + ' toggles');
    }
  }
});

test('stackFit: the OpenTelemetry SDK cap is only blamed for per-request labels', () => {
  const pod = WR.stackFit({ highCardinalityLabels: ['pod'] }, {}).otel.flags.map((f) => f.text).join(' | ');
  const req = WR.stackFit({ highCardinalityLabels: ['user_id'] }, {}).otel.flags.map((f) => f.text).join(' | ');
  assert.match(pod, /SDK limit will not stop them/);
  assert.match(req, /SDK limit of 2,000/);
});

test('stackFit: missing error traces separate the stacks', () => {
  const fit = WR.stackFit({ errorTracesMissing: true, sources: { traces: true } }, {});
  assert.ok(fit.otel.flags.some((f) => f.level === 'breaks'), 'OpenTelemetry head sampling breaks');
  assert.ok(fit.datadog.flags.some((f) => f.level === 'ok' && /error sampler/i.test(f.text)), 'Datadog error sampler partly covers it');
  assert.ok(fit.grafana.flags.some((f) => /Tempo/.test(f.text)), 'Grafana: Tempo only has what was kept');
});

test('stackFit: cost lines follow verified unit prices and the scale inputs', () => {
  const line = (fit, id, label) => fit[id].costLines.find((c) => c.label.startsWith(label));
  const d = WR.stackFit({}, {});
  assert.equal(line(d, 'datadog', 'Infrastructure Pro').monthlyUsd, 40 * 15);
  assert.equal(line(d, 'datadog', 'APM').monthlyUsd, 20 * 31);
  assert.equal(line(d, 'datadog', 'Log ingestion').monthlyUsd, 50 * 30 * 0.10);
  assert.equal(line(d, 'datadog', 'Log indexing').monthlyUsd, null, 'GB to events is not verified');
  assert.equal(line(d, 'datadog', 'Custom metrics above').monthlyUsd, null, 'overage rate is not published');
  assert.equal(line(d, 'grafana', 'Grafana Cloud metrics').monthlyUsd, (500000 - 10000) / 1000 * 6.5);
  assert.equal(line(d, 'grafana', 'Grafana Cloud logs written').monthlyUsd, (1500 - 50) * 0.4);
  assert.equal(line(d, 'grafana', 'Self-hosted').monthlyUsd, null);
  assert.equal(line(d, 'hosted', 'Google').monthlyUsd, Math.round(500000 * 43200 / 1e6 * 0.06));
  assert.equal(line(d, 'hosted', 'Amazon').monthlyUsd, null);
  assert.equal(line(d, 'hosted', 'Azure').monthlyUsd, null);
  const big = WR.stackFit({}, { nodes: 100, apmHosts: 50, logsGbPerDay: 10, activeSeries: 1200000 });
  assert.equal(line(big, 'datadog', 'Infrastructure Pro').monthlyUsd, 1500);
  assert.equal(line(big, 'datadog', 'APM').monthlyUsd, 1550);
  assert.equal(big.hosted.verdict, 'Strained', 'Azure throttles at 1,000,000 series');
  // Google tiers: 600 billion samples crosses all four tiers.
  const tiers = WR.stackFit({}, { activeSeries: 600e9 / 43200 });
  const expected = 50e3 * 0.06 + 200e3 * 0.048 + 250e3 * 0.036 + 100e3 * 0.024;
  assert.ok(Math.abs(line(tiers, 'hosted', 'Google').monthlyUsd - expected) <= 1, 'tiered Google price');
});

test('stackFit: verdicts are not all the same across the sample incidents', () => {
  const seen = new Set();
  for (const f of fixtures) for (const [, r] of Object.entries(WR.stackFit(f.a.traits, {}))) seen.add(r.verdict);
  assert.ok(seen.size >= 2, 'verdicts vary: ' + [...seen].join(', '));
});
