// Tests for src/samples/samples.js (WR.samples) — the demo incidents that double as the engine's test corpus.
// These check the fixtures themselves: shape, formats that must parse, size budgets from SPEC section 5, and that
// every timestamp in every pane sits on the same incident clock. They never call WR.analyze, so they stay valid
// while the engine is being built.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SAMPLES_FILE = path.join(ROOT, 'src', 'samples', 'samples.js');
const SOURCE = fs.readFileSync(SAMPLES_FILE, 'utf8');

// Prefer the shared loader; fall back to evaluating samples.js alone when the loader is missing or one of the
// other source files it pulls in is not ready yet.
async function loadSamples() {
  const loader = path.join(ROOT, 'tests', 'load.mjs');
  if (fs.existsSync(loader)) {
    try {
      const mod = await import(pathToFileURL(loader).href);
      const WR = mod.WR || mod.default || globalThis.WR;
      if (WR && Array.isArray(WR.samples) && WR.samples.length) return WR.samples;
    } catch { /* fall through to the direct load */ }
  }
  const ctx = vm.createContext({});
  vm.runInContext(SOURCE, ctx, { filename: SAMPLES_FILE });
  return ctx.WR.samples;
}
// JSON round trip turns objects from another realm into plain local ones so deep equality works.
const SAMPLES = JSON.parse(JSON.stringify(await loadSamples()));
const byId = Object.fromEntries(SAMPLES.map((s) => [s.id, s]));

const IDS = ['bad-deploy-oom', 'coredns-outage', 'cert-expiry', 'db-conn-exhaustion'];
const PANES = ['logs', 'traces', 'alerts', 'helm'];
const CATEGORIES = ['bad-deploy', 'resource-limits', 'config-error', 'image-pull', 'dependency-failure', 'dns', 'tls-cert',
  'node-pressure', 'scheduling-capacity', 'probe-misconfig', 'network-policy', 'connection-exhaustion', 'rate-limiting', 'unknown'];
const ROLLBACK_KINDS = ['helm-rollback', 'rollout-undo', 'set-image', 'resource-restore', 'config-revert', 'canary-abort',
  'traffic-shift', 'scale', 'roll-forward', 'restart'];
const DAY_START = Date.parse('2026-10-05T00:00:00Z');
const MON = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

// ------------------------------------------------------------------------------------------------ helpers
const lines = (text) => text.split('\n');
const nonEmpty = (text) => lines(text).filter((l) => l.trim() !== '');
// "[FIRING:1] ..." and "[context: ...]" start with a bracket too, so a JSON array must open with { or ].
const isJson = (text) => /^\s*(\{|\[\s*[{\]])/.test(text);
const offsetMs = (tz) => {
  if (!tz || tz === 'Z' || tz === 'UTC' || tz === 'GMT') return 0;
  const m = /^([+-])(\d{2}):?(\d{2})$/.exec(tz);
  return (m[1] === '-' ? -1 : 1) * (Number(m[2]) * 60 + Number(m[3])) * 60000;
};
// Wall-clock fields read in a zone -> epoch ms.
const wall = (y, mo, d, hms, frac, tz) => {
  const [h, mi, s] = hms.split(':').map(Number);
  const ms = frac ? Number(String(frac).padEnd(3, '0').slice(0, 3)) : 0;
  return Date.UTC(y, mo, d, h, mi, s, ms) - offsetMs(tz);
};

function spanCount(text) {
  if (isJson(text)) {
    const doc = JSON.parse(text);
    if (doc.resourceSpans) return doc.resourceSpans.reduce((n, rs) => n + rs.scopeSpans.reduce((m, ss) => m + ss.spans.length, 0), 0);
    if (doc.data) return doc.data.reduce((n, t) => n + t.spans.length, 0);
    throw new Error('unknown trace JSON shape');
  }
  return lines(text).filter((l) => /\btrace=\S+/.test(l) && /\bspan=\S+/.test(l)).length;
}
function alertCount(text) {
  if (isJson(text)) {
    const doc = JSON.parse(text);
    return (Array.isArray(doc) ? doc : doc.alerts || doc.data.alerts).length;
  }
  return nonEmpty(text).filter((l) => !l.startsWith('#')).length;
}
const DIFF_HEADER = /^[a-z0-9-]+, [a-z0-9.-]+, [A-Za-z]+ \([a-z0-9./]+\) has (changed|been added|been removed):$/;
function helmDiffBlocks(text) {
  const blocks = [];
  let cur = null;
  for (const l of lines(text)) {
    if (DIFF_HEADER.test(l)) { cur = [l]; blocks.push(cur); continue; }
    if (cur && (l.trim() === '' || l.startsWith('$ ') || l.startsWith('# ') || l.startsWith('['))) { cur = null; continue; }
    if (cur) cur.push(l);
  }
  return blocks;
}
const helmHistoryRows = (text) => lines(text).filter((l) => /^\d+\s*\t/.test(l)).map((l) => l.split('\t').map((c) => c.trim()));
function ansic(cell, tz) {
  const m = /^\w{3} (\w{3}) +(\d{1,2}) (\d{2}:\d{2}:\d{2}) (\d{4})$/.exec(cell);
  return m ? wall(Number(m[4]), MON[m[1]], Number(m[2]), m[3], null, tz) : NaN;
}

// Every absolute timestamp in a pane, in all the encodings the samples use.
function timestamps(text, ctx, pane) {
  const out = [];
  const year = ctx.year;
  const push = (ms, src) => out.push({ ms, src });
  for (const line of lines(text)) {
    if (/^\s*(Not Before|Renewal Time):/.test(line)) continue;      // certificate validity, legitimately older
    if (pane === 'helm' && /^\d+\s*\t/.test(line)) continue;           // helm history rows, checked separately
    let m;
    const isoRe = /\b(\d{4})-(\d{2})-(\d{2})T(\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})?/g;
    while ((m = isoRe.exec(line))) {
      if (m[1] === '0001') continue;                                   // Alertmanager endsAt for firing alerts
      push(wall(+m[1], +m[2] - 1, +m[3], m[4], m[5], m[6] || ctx.defaultTz), m[0]);
    }
    const spaceRe = /\b(\d{4})-(\d{2})-(\d{2}) (\d{2}:\d{2}:\d{2})(?:[.,](\d+))?(?: (UTC|GMT|[+-]\d{4}))?/g;
    while ((m = spaceRe.exec(line))) push(wall(+m[1], +m[2] - 1, +m[3], m[4], m[5], m[6] || ctx.defaultTz), m[0]);
    const rfcRe = /\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), (\d{2}) (\w{3}) (\d{4}) (\d{2}:\d{2}:\d{2}) ([+-]\d{4}|UTC|GMT)/g;
    while ((m = rfcRe.exec(line))) push(wall(+m[3], MON[m[2]], +m[1], m[4], null, m[5]), m[0]);
    const nginxRe = /\[(\d{2})\/(\w{3})\/(\d{4}):(\d{2}:\d{2}:\d{2}) ([+-]\d{4})\]/g;
    while ((m = nginxRe.exec(line))) push(wall(+m[3], MON[m[2]], +m[1], m[4], null, m[5]), m[0]);
    const klogRe = /(?:^|\s)[IWEF](\d{2})(\d{2}) (\d{2}:\d{2}:\d{2})\.(\d{6})\s/g;
    while ((m = klogRe.exec(line))) push(wall(year, +m[1] - 1, +m[2], m[3], m[4], ctx.defaultTz), m[0].trim());
    if ((m = /^(\w{3}) +(\d{1,2}) (\d{2}:\d{2}:\d{2}) \S+ \S+:/.exec(line)) && MON[m[1]] !== undefined) push(wall(year, MON[m[1]], +m[2], m[3], null, ctx.defaultTz), m[0]);
    if ((m = /(\w{3}) +(\d{1,2}) (\d{2}:\d{2}:\d{2}) (\d{4}) GMT/.exec(line))) push(wall(+m[4], MON[m[1]], +m[2], m[3], null, 'Z'), m[0]);
    const epochRe = /"ts":(\d{10}\.\d+)/g;
    while ((m = epochRe.exec(line))) push(Math.round(Number(m[1]) * 1000), m[0]);
  }
  if (pane === 'traces' && isJson(text)) {
    const doc = JSON.parse(text);
    if (doc.resourceSpans) {
      for (const rs of doc.resourceSpans) for (const ss of rs.scopeSpans) for (const sp of ss.spans) {
        push(Number(BigInt(sp.startTimeUnixNano) / 1000000n), 'startTimeUnixNano');
        push(Number(BigInt(sp.endTimeUnixNano) / 1000000n), 'endTimeUnixNano');
      }
    } else {
      for (const t of doc.data) for (const sp of t.spans) {
        push(Math.floor(sp.startTime / 1000), 'startTime');
        push(Math.floor((sp.startTime + sp.duration) / 1000), 'startTime+duration');
        for (const lg of sp.logs) push(Math.floor(lg.timestamp / 1000), 'log.timestamp');
      }
    }
  }
  if (pane === 'traces' && !isJson(text)) {
    for (const l of lines(text)) {
      const m = /^(\S+) .*\bdur=(\d+)ms/.exec(l);
      if (m) push(Date.parse(m[1]) + Number(m[2]), 'span end');
    }
  }
  return out;
}

// The JSON object embedded in a log line (after a kubectl --prefix or stern prefix), or null.
function embeddedJson(line) {
  const i = line.indexOf('{');
  if (i < 0 || !line.trimEnd().endsWith('}')) return null;
  return line.slice(i);
}

// ------------------------------------------------------------------------------------------------ tests
test('WR.samples has the four SPEC scenarios in order', () => {
  assert.equal(SAMPLES.length, 4);
  assert.deepEqual(SAMPLES.map((s) => s.id), IDS);
});

test('samples.js is a classic script with no module syntax or DOM access', () => {
  assert.doesNotMatch(SOURCE, /^\s*(import|export)\b/m);
  assert.doesNotMatch(SOURCE, /\b(?:window|document)\s*\./);
  assert.match(SOURCE, /\(function \(WR\) \{\s*'use strict';/);
  assert.match(SOURCE.trimEnd(), /\}\)\(globalThis\.WR = globalThis\.WR \|\| \{\}\);$/);
  // build.mjs inlines every script into one <script> element; these sequences would end or derail it.
  assert.doesNotMatch(SOURCE, /<\/script|<!--|<script/i);
});

test('every sample has the required fields and a usable context', () => {
  for (const s of SAMPLES) {
    for (const k of ['id', 'title', 'blurb', ...PANES]) assert.ok(typeof s[k] === 'string' && s[k].trim().length > 0, `${s.id}.${k}`);
    const c = s.context;
    assert.ok(ISO_UTC.test(c.now), `${s.id} context.now is ISO UTC`);
    const now = Date.parse(c.now);
    assert.ok(now > Date.parse('2026-10-05T12:00:00Z') && now < Date.parse('2026-10-06T06:00:00Z'), `${s.id} now is the evening of 2026-10-05`);
    assert.match(c.defaultTz, /^(Z|[+-]\d{2}:\d{2})$/);
    assert.equal(c.year, 2026);
    assert.ok(typeof c.cluster === 'string' && c.cluster.length > 0);
    assert.ok(c.slo.target > 0.9 && c.slo.target < 1, `${s.id} slo.target`);
    assert.ok([7, 28, 30].includes(c.slo.windowDays), `${s.id} slo.windowDays`);
    assert.ok(c.slo.requestsPerMin > 0);
    assert.ok(c.slo.budgetSpentBeforePct >= 0 && c.slo.budgetSpentBeforePct < 100);
  }
});

test('expected answers are complete and use SPEC vocabulary', () => {
  for (const s of SAMPLES) {
    const e = s.expected;
    assert.ok(e.rootComponentName && typeof e.rootComponentName === 'string', `${s.id} rootComponentName`);
    assert.ok(Array.isArray(e.rootComponentAlternates));
    assert.ok(e.rootCluster && s.logs.includes(e.rootCluster), `${s.id} rootCluster appears in the evidence`);
    assert.ok(Array.isArray(e.categories) && e.categories.length > 0);
    for (const c of e.categories) assert.ok(CATEGORIES.includes(c), `${s.id} category ${c}`);
    assert.ok(e.categories.includes(e.category), `${s.id} category is one of categories`);
    assert.ok(Array.isArray(e.recommendedKinds) && e.recommendedKinds.length > 0);
    for (const k of e.recommendedKinds) assert.ok(ROLLBACK_KINDS.includes(k), `${s.id} rollback kind ${k}`);
    assert.ok(e.recommendedKinds.includes(e.recommendedKind));
    assert.equal(typeof e.multiCluster, 'boolean');
    assert.ok(Number.isInteger(e.deployRevision) && Number.isInteger(e.previousRevision) && e.previousRevision < e.deployRevision);
    assert.ok(ISO_UTC.test(e.deployedAt) && ISO_UTC.test(e.firstErrorAround));
    const text = PANES.map((k) => s[k]).join('\n');
    assert.ok(text.includes(e.rootComponentName), `${s.id} root component is named in the evidence`);
  }
  const s1 = byId['bad-deploy-oom'].expected;
  assert.equal(s1.rootComponentName, 'payments-api');
  assert.equal(s1.rootCluster, 'prod-eu-west');
  assert.ok(s1.categories.includes('resource-limits') && s1.categories.includes('bad-deploy'));
  assert.equal(s1.recommendedKind, 'helm-rollback');
  assert.equal(s1.deployRevision, 42);
  assert.equal(s1.previousRevision, 41);
  assert.equal(s1.multiCluster, true);
  const s2 = byId['coredns-outage'].expected;
  assert.equal(s2.rootComponentName, 'coredns');
  assert.deepEqual(s2.categories, ['dns']);
  assert.equal(s2.multiCluster, false);
  const s3 = byId['cert-expiry'].expected;
  assert.equal(s3.rootComponentName, 'auth-service');
  assert.ok(s3.rootComponentAlternates.includes('api-gateway'));
  assert.deepEqual(s3.categories, ['tls-cert']);
  assert.equal(s3.recommendedKind, 'roll-forward');
  assert.equal(s3.notTopComponentName, 'recommendations');
  const s4 = byId['db-conn-exhaustion'].expected;
  assert.equal(s4.rootComponentName, 'orders-api');
  assert.deepEqual(s4.categories, ['connection-exhaustion']);
  assert.ok(s4.recommendedKinds.includes('helm-rollback') && s4.recommendedKinds.includes('scale'));
  assert.equal(s4.multiCluster, true);
});

test('pane formats follow SPEC section 5 (JSON panes parse; text panes are text)', () => {
  const s1 = byId['bad-deploy-oom'];
  const s2 = byId['coredns-outage'];
  const s3 = byId['cert-expiry'];
  const s4 = byId['db-conn-exhaustion'];
  assert.ok(JSON.parse(s1.traces).resourceSpans, 'sample 1 traces are OTLP JSON');
  assert.ok(Array.isArray(JSON.parse(s1.alerts).alerts), 'sample 1 alerts are an Alertmanager webhook');
  assert.ok(JSON.parse(s3.traces).resourceSpans, 'sample 3 traces are OTLP JSON');
  assert.ok(Array.isArray(JSON.parse(s4.traces).data), 'sample 4 traces are Jaeger JSON');
  assert.ok(Array.isArray(JSON.parse(s4.alerts).alerts), 'sample 4 alerts are an Alertmanager webhook');
  for (const s of [s2, s3]) assert.ok(!isJson(s.alerts), `${s.id} alerts are text lines`);
  assert.ok(!isJson(s2.traces), 'sample 2 traces use the one-span-per-line text format');
  for (const s of SAMPLES) for (const k of PANES) if (isJson(s[k])) assert.doesNotThrow(() => JSON.parse(s[k]), `${s.id}.${k}`);
});

test('JSON embedded in log lines parses', () => {
  for (const s of SAMPLES) {
    for (const l of lines(s.logs)) {
      const j = embeddedJson(l);
      if (!j || /^\[\{/.test(j)) continue;
      assert.doesNotThrow(() => JSON.parse(j), `${s.id}: ${l.slice(0, 120)}`);
    }
  }
});

test('OTLP, Jaeger and Alertmanager payloads use the real encodings', () => {
  for (const id of ['bad-deploy-oom', 'cert-expiry']) {
    const doc = JSON.parse(byId[id].traces);
    for (const rs of doc.resourceSpans) {
      const keys = rs.resource.attributes.map((a) => a.key);
      assert.ok(keys.includes('service.name') && keys.includes('k8s.cluster.name'), `${id} resource attributes`);
      for (const ss of rs.scopeSpans) for (const sp of ss.spans) {
        assert.match(sp.traceId, /^[0-9a-f]{32}$/);
        assert.match(sp.spanId, /^[0-9a-f]{16}$/);
        if (sp.parentSpanId !== undefined) assert.match(sp.parentSpanId, /^[0-9a-f]{16}$/);
        assert.match(sp.startTimeUnixNano, /^\d{19}$/);
        assert.ok(BigInt(sp.endTimeUnixNano) >= BigInt(sp.startTimeUnixNano));
        for (const a of sp.attributes) assert.ok(a.key && a.value && Object.keys(a.value).length === 1 && /Value$/.test(Object.keys(a.value)[0]));
      }
    }
  }
  const jaeger = JSON.parse(byId['db-conn-exhaustion'].traces);
  for (const t of jaeger.data) {
    const ids = new Set(t.spans.map((sp) => sp.spanID));
    for (const sp of t.spans) {
      assert.ok(t.processes[sp.processID], 'processID resolves');
      for (const r of sp.references) { assert.equal(r.refType, 'CHILD_OF'); assert.ok(ids.has(r.spanID), 'parent span is in the trace'); }
      assert.ok(Number.isInteger(sp.startTime) && Number.isInteger(sp.duration));
    }
  }
  for (const id of ['bad-deploy-oom', 'db-conn-exhaustion']) {
    const doc = JSON.parse(byId[id].alerts);
    assert.equal(doc.version, '4');
    for (const a of doc.alerts) {
      for (const k of ['status', 'labels', 'annotations', 'startsAt', 'endsAt', 'generatorURL', 'fingerprint']) assert.ok(k in a, `${id} alert has ${k}`);
      assert.ok(a.labels.alertname && a.labels.severity);
      assert.match(a.fingerprint, /^[0-9a-f]{16}$/);
      if (a.status === 'firing') assert.equal(a.endsAt, '0001-01-01T00:00:00Z');
    }
  }
});

test('size budgets from SPEC section 5', () => {
  for (const s of SAMPLES) {
    const logLines = nonEmpty(s.logs).length;
    assert.ok(logLines >= 60 && logLines <= 200, `${s.id} log lines ${logLines}`);
    const spans = spanCount(s.traces);
    assert.ok(spans >= 20 && spans <= 80, `${s.id} spans ${spans}`);
    const alerts = alertCount(s.alerts);
    assert.ok(alerts >= 3 && alerts <= 8, `${s.id} alerts ${alerts}`);
    const diffLines = helmDiffBlocks(s.helm).reduce((n, b) => n + b.length, 0);
    assert.ok(diffLines >= 30 && diffLines <= 120, `${s.id} helm diff lines ${diffLines}`);
    const bytes = PANES.reduce((n, k) => n + Buffer.byteLength(s[k]), 0);
    assert.ok(bytes <= 60 * 1024, `${s.id} pane text ${bytes} bytes`);
  }
});

test('helm diff blocks use the helm-diff plugin layout', () => {
  for (const s of SAMPLES) {
    const blocks = helmDiffBlocks(s.helm);
    assert.ok(blocks.length >= 1, `${s.id} has a helm diff`);
    for (const b of blocks) {
      assert.match(b[1], /^ {2}# Source: [a-z0-9-]+\/templates\//, `${s.id}: ${b[0]}`);
      for (const l of b.slice(1)) assert.match(l, /^( {2}|[-+] )/, `${s.id} diff line: ${l}`);
      assert.ok(b.some((l) => /^[-+] /.test(l)), `${s.id} block has changes: ${b[0]}`);
    }
  }
});

test('helm history: the deployed row is the expected revision at the expected UTC time', () => {
  for (const s of SAMPLES) {
    const rows = helmHistoryRows(s.helm);
    assert.ok(rows.length >= 2, `${s.id} has helm history rows`);
    const deployed = rows.find((r) => r[2] === 'deployed');
    assert.ok(deployed, `${s.id} has a deployed row`);
    assert.equal(Number(deployed[0]), s.expected.deployRevision);
    assert.ok(rows.some((r) => Number(r[0]) === s.expected.previousRevision), `${s.id} previous revision is listed`);
    assert.equal(ansic(deployed[1], s.context.defaultTz), Date.parse(s.expected.deployedAt), `${s.id} UPDATED + defaultTz`);
    assert.ok(deployed[3].startsWith(`${s.expected.release}-`), `${s.id} chart name matches release`);
  }
});

test('every timestamp is on the incident clock: 2026-10-05 (UTC) and never after context.now', () => {
  for (const s of SAMPLES) {
    const now = Date.parse(s.context.now);
    let seen = 0;
    for (const k of PANES) {
      for (const { ms, src } of timestamps(s[k], s.context, k)) {
        seen++;
        assert.ok(Number.isFinite(ms), `${s.id}.${k} unparsable ${src}`);
        assert.ok(ms >= DAY_START, `${s.id}.${k} ${src} is before 2026-10-05`);
        assert.ok(ms <= now + 1000, `${s.id}.${k} ${src} is after context.now (${s.context.now})`);
      }
    }
    assert.ok(seen > 50, `${s.id} timestamps found: ${seen}`);
  }
});

test('timeline: deploy first, errors 2-10 minutes later (cert-expiry: red-herring deploy hours earlier)', () => {
  for (const s of SAMPLES) {
    const deploy = Date.parse(s.expected.deployedAt);
    const firstErr = Date.parse(s.expected.firstErrorAround);
    const gapMin = (firstErr - deploy) / 60000;
    if (s.id === 'cert-expiry') assert.ok(gapMin >= 150, `${s.id} red herring deploy precedes errors by ${gapMin} min`);
    else assert.ok(gapMin >= 2 && gapMin <= 10, `${s.id} first error ${gapMin.toFixed(1)} min after deploy`);
    // No warning or error in the JSON logs before the incident starts.
    const start = s.id === 'cert-expiry' ? Date.parse(s.expected.certificateNotAfter) : deploy;
    for (const l of lines(s.logs)) {
      const j = embeddedJson(l);
      if (!j || /^\[\{/.test(j)) continue;
      const o = JSON.parse(j);
      const level = String(o.level ?? o.severity ?? o.lvl ?? '').toLowerCase();
      if (!['warn', 'warning', 'error', 'fatal'].includes(level)) continue;
      const raw = o.ts ?? o.time ?? o.timestamp ?? o['@timestamp'];
      const t = typeof raw === 'number' ? raw * 1000 : Date.parse(raw);
      assert.ok(t >= start, `${s.id} ${level} line before the incident start: ${l.slice(0, 120)}`);
    }
  }
});

test('alert burn rates agree with the error ratio and the SLO target', () => {
  for (const s of SAMPLES) {
    const pairs = [];
    if (isJson(s.alerts)) {
      for (const a of JSON.parse(s.alerts).alerts) if (a.annotations.burn_rate) pairs.push([Number(a.annotations.burn_rate), Number(a.annotations.error_ratio)]);
    } else {
      for (const l of lines(s.alerts)) {
        const b = /\bburn_rate=([\d.]+)/.exec(l); const r = /\berror_ratio=([\d.]+)/.exec(l);
        if (b && r) pairs.push([Number(b[1]), Number(r[1])]);
      }
    }
    assert.equal(pairs.length, 1, `${s.id} has one SLO burn alert`);
    const [burn, ratio] = pairs[0];
    const implied = ratio / (1 - s.context.slo.target);
    assert.ok(Math.abs(implied - burn) / burn < 0.02, `${s.id} burn ${burn} vs ratio ${ratio} at target ${s.context.slo.target}`);
  }
  assert.ok(Math.abs(Number(JSON.parse(byId['bad-deploy-oom'].alerts).alerts.find((a) => a.annotations.burn_rate).annotations.burn_rate) - 16) < 1, 'sample 1 burns at about 16x');
});

test('multi-cluster samples carry cluster identity in every pane that can hold it', () => {
  const s1 = byId['bad-deploy-oom'];
  assert.ok(s1.logs.includes('# cluster: prod-eu-west') && s1.logs.includes('# cluster: prod-us-east'));
  const otlpClusters = new Set(JSON.parse(s1.traces).resourceSpans.map((rs) => rs.resource.attributes.find((a) => a.key === 'k8s.cluster.name').value.stringValue));
  assert.deepEqual([...otlpClusters].sort(), ['prod-eu-west', 'prod-us-east']);
  assert.ok(JSON.parse(s1.alerts).alerts.every((a) => a.labels.cluster === 'prod-eu-west'), 'only the failing cluster alerts');
  const s4 = byId['db-conn-exhaustion'];
  assert.ok(s4.logs.includes('--- cluster=prod-us-east ---') && s4.logs.includes('--- cluster=prod-us-west ---'));
  const jClusters = new Set(JSON.parse(s4.traces).data.flatMap((t) => Object.values(t.processes).map((p) => p.tags.find((x) => x.key === 'k8s.cluster.name').value)));
  assert.deepEqual([...jClusters].sort(), ['prod-us-east', 'prod-us-west']);
  const aClusters = new Set(JSON.parse(s4.alerts).alerts.map((a) => a.labels.cluster).filter(Boolean));
  assert.deepEqual([...aClusters].sort(), ['prod-us-east', 'prod-us-west']);
  assert.ok(s4.helm.startsWith('[context: prod-us-east]'));
});

test('exactly one fake credential, and no other secret-shaped strings', () => {
  const all = SAMPLES.map((s) => PANES.map((k) => s[k]).join('\n')).join('\n');
  assert.equal(all.split('hunter2-not-real').length - 1, 1, 'one fake DB_PASSWORD value');
  assert.match(byId['db-conn-exhaustion'].helm, /^ {4}DB_PASSWORD: "hunter2-not-real"$/m);
  assert.doesNotMatch(all, /AKIA[0-9A-Z]{16}/);
  assert.doesNotMatch(all, /-----BEGIN [A-Z ]*PRIVATE KEY-----/);
  assert.doesNotMatch(all, /\b[a-z][a-z0-9+.-]*:\/\/[^\s/:@]+:[^\s/@]+@/i, 'no credentials in URLs');
  assert.doesNotMatch(all, /[\w.+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b/, 'no email addresses');
  assert.doesNotMatch(all, /\bBearer\s+[A-Za-z0-9._-]{16,}/);
  // Real identifiers such as Go package paths and Java class names are long runs of the base64 alphabet too;
  // encoded data mixes digits with both letter cases, so only those count.
  const blobs = (all.match(/[A-Za-z0-9+/=]{40,}/g) || []).filter((r) => /\d/.test(r) && /[a-z]/.test(r) && /[A-Z]/.test(r));
  assert.deepEqual(blobs, [], 'no long base64-looking blobs');
  assert.doesNotMatch(all, /\b(?:password|passwd|token|api[_-]?key|client_secret)\s*[:=]/i, 'no other key=value secrets');
});

test('pod names in kubectl tables use real ReplicaSet hash and suffix alphabets', () => {
  const SAFE = /^[bcdfghjklmnpqrstvwxz2456789]+$/;
  for (const s of SAMPLES) {
    for (const l of lines(s.logs)) {
      const m = /^([a-z][a-z0-9-]*?)-([a-z0-9]{8,10})-([a-z0-9]{5})\s+\d+\/\d+\s/.exec(l);
      if (!m) continue;
      assert.match(m[2], SAFE, `${s.id} pod-template-hash in ${m[0]}`);
      assert.match(m[3], SAFE, `${s.id} pod suffix in ${m[0]}`);
    }
  }
});

test('cert-expiry red herring stays clean and the root is named everywhere it should be', () => {
  const s3 = byId['cert-expiry'];
  const recLines = lines(s3.logs).filter((l) => l.includes('/recommendations]'));
  assert.ok(recLines.length >= 5);
  for (const l of recLines) assert.doesNotMatch(l, /\b(ERROR|WARN|WARNING|error|warn)\b|" 5\d\d /, `recommendations is healthy: ${l.slice(0, 120)}`);
  assert.match(s3.logs, /x509: certificate has expired/);
  assert.match(s3.alerts, /CertificateExpired/);
  assert.match(s3.helm, /^discovery, recommendations, Deployment \(apps\) has changed:$/m);
});
