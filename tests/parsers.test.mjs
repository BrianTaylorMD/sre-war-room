/*
 * parsers.test.mjs — the input layer: util, time, entities, redaction and the four parsers.
 * Fixtures are small but shaped exactly like real kubectl / OTLP / Alertmanager / helm output.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import WR from './load.mjs';

const T = WR.time;
const E = WR.entities;
const utc = (...a) => Date.UTC(...a);
const OCT5 = (h, m, s = 0, ms = 0) => Date.UTC(2026, 9, 5, h, m, s, ms);

// Every signal from every parser must honour the Analysis contract (SPEC §4).
function assertSignalContract(signals, source) {
  const ids = new Set();
  for (const s of signals) {
    assert.equal(s.source, source, `source of ${s.id}`);
    assert.ok(WR.isKind(s.kind), `kind "${s.kind}" of ${s.id} is in the closed vocabulary`);
    assert.ok(['info', 'warn', 'error', 'critical'].includes(s.severity), `severity of ${s.id}`);
    assert.ok(Number.isInteger(s.line) && s.line >= 1, `line of ${s.id} is a 1-based integer`);
    assert.ok(s.componentId === null || typeof s.componentId === 'string', `componentId of ${s.id}`);
    assert.ok(s.ts === null || Number.isFinite(s.ts), `ts of ${s.id}`);
    assert.equal(typeof s.tsInferred, 'boolean');
    assert.ok(Array.isArray(s.relatedIds));
    assert.equal(typeof s.text, 'string');
    assert.equal(typeof s.raw, 'string');
    assert.equal(typeof s.attrs, 'object');
    assert.ok(!ids.has(s.id), `signal id ${s.id} is unique`);
    ids.add(s.id);
  }
}

function assertStatsShape(stats) {
  for (const k of ['lines', 'parsed', 'skipped', 'tzAssumed']) assert.ok(Number.isInteger(stats[k]), `stats.${k}`);
  assert.equal(typeof stats.format, 'string');
  assert.ok(Array.isArray(stats.warnings));
}

// =============================================================================================
describe('util', () => {
  it('escapes HTML', () => {
    assert.equal(WR.esc('<img src=x onerror="a&b">\''), '&lt;img src=x onerror=&quot;a&amp;b&quot;&gt;&#39;');
    assert.equal(WR.esc(null), '');
  });
  it('hashes deterministically', () => {
    assert.equal(WR.hash('payments'), WR.hash('payments'));
    assert.notEqual(WR.hash('payments'), WR.hash('payment'));
    assert.match(WR.hash('x'), /^[0-9a-z]+$/);
  });
  it('clamp, uniq, groupBy', () => {
    assert.equal(WR.clamp(5, 0, 1), 1);
    assert.equal(WR.clamp(-1, 0, 1), 0);
    assert.equal(WR.clamp(NaN, 0, 1), 0);
    assert.deepEqual(WR.uniq([3, 1, 3, 2, 1]), [3, 1, 2]);
    assert.deepEqual(WR.uniq([{ a: 1 }, { a: 1 }, { a: 2 }], (x) => x.a).length, 2);
    assert.deepEqual(WR.groupBy([{ k: 'a' }, { k: 'b' }, { k: 'a' }], 'k'), { a: [{ k: 'a' }, { k: 'a' }], b: [{ k: 'b' }] });
  });
  it('formats durations and percents in plain English', () => {
    assert.equal(WR.fmtDuration(850), '850 ms');
    assert.equal(WR.fmtDuration(45000), '45 s');
    assert.equal(WR.fmtDuration(192000), '3 min 12 s');
    assert.equal(WR.fmtDuration(42 * 60000), '42 min');
    assert.equal(WR.fmtDuration(2 * 3600000 + 5 * 60000), '2 h 5 min');
    assert.equal(WR.fmtDuration(3 * 86400000 + 4 * 3600000), '3 d 4 h');
    assert.equal(WR.fmtDuration(null), '—');
    assert.equal(WR.fmtPct(12.345), '12.3%');
    assert.equal(WR.fmtPct(100), '100%');
    assert.equal(WR.fmtPct(0.0004), '<0.001%');
    assert.equal(WR.fmtPct(null), '—');
    assert.equal(WR.fmtRatio(0.0162), '1.6%');
  });
  it('median and nearest-rank percentile', () => {
    assert.equal(WR.median([5, 1, 3]), 3);
    assert.equal(WR.median([1, 2, 3, 4]), 2.5);
    assert.equal(WR.percentile([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 95), 10);
    assert.equal(WR.percentile([], 95), null);
  });
  it('parses logfmt with quoted values', () => {
    assert.deepEqual(WR.logfmt('level=error msg="db down: \\"x\\"" ts=2026-10-05T21:51:06Z n=3'),
      { level: 'error', msg: 'db down: "x"', ts: '2026-10-05T21:51:06Z', n: '3' });
  });
  it('repairs cut-off JSON and reports it', () => {
    const r = WR.parseJsonLenient('{"alerts":[{"a":1},{"b":2},{"c":');
    assert.equal(r.repaired, true);
    assert.deepEqual(r.value, { alerts: [{ a: 1 }, { b: 2 }] });
    assert.equal(WR.parseJsonLenient('{"ok":true}').repaired, false);
    assert.equal(WR.parseJsonLenient('not json').value, null);
    assert.equal(WR.parseJsonLenient('').value, null);
  });
  it('segments JSON documents from marker lines', () => {
    const segs = WR.segmentJson(['# cluster: a', '{', '  "x": "}{",', '  "y": [1, 2]', '}', '{"z":1}', 'tail']);
    assert.deepEqual(segs.map((s) => s.type), ['line', 'json', 'json', 'line']);
    assert.equal(segs[1].startLine, 2);
    assert.equal(segs[1].endLine, 5);
    assert.equal(segs[2].startLine, 6);
    // bracketed text is not JSON and must not swallow the lines after it
    const t = WR.segmentJson(['[FIRING:2] A (x)', '[pod/broken', '{oops', '[context: prod]', 'next']);
    assert.deepEqual(t.map((s) => s.type), ['line', 'line', 'line', 'line', 'line']);
  });
  it('maps offsets to 1-based lines', () => {
    const starts = WR.lineIndex('a\nbb\nccc');
    assert.equal(WR.lineAt(starts, 0), 1);
    assert.equal(WR.lineAt(starts, 3), 2);
    assert.equal(WR.lineAt(starts, 7), 3);
  });
});

// =============================================================================================
describe('time', () => {
  it('RFC 3339 with Z and with an offset', () => {
    assert.deepEqual(pick(T.parse('2026-10-05T21:49:30Z')), { ts: OCT5(21, 49, 30), tsInferred: false });
    assert.deepEqual(pick(T.parse('2026-10-05T23:49:30.250+02:00')), { ts: OCT5(21, 49, 30, 250), tsInferred: false });
    assert.deepEqual(pick(T.parse('2026-10-05T16:49:30.123456789-05:00')), { ts: OCT5(21, 49, 30, 123), tsInferred: false });
  });
  it('zone-less stamps take defaultTz and are marked inferred', () => {
    const r = T.parse('2026-10-05 23:51:02,123', { defaultTz: '+02:00' });
    assert.equal(r.ts, OCT5(21, 51, 2, 123));
    assert.equal(r.tsInferred, true);
    assert.equal(r.tzAssumed, true);
    const z = T.parse('2026-10-05T21:51:02');
    assert.equal(z.ts, OCT5(21, 51, 2));
    assert.equal(z.tsInferred, true, 'still inferred when the default is Z');
    assert.equal(T.parse('2026/10/05 21:51:02', {}).ts, OCT5(21, 51, 2), 'nginx style date');
  });
  it('helm history (ANSIC) stamps', () => {
    const r = T.parse('Mon Oct  5 23:47:03 2026', { defaultTz: '+02:00' });
    assert.equal(r.ts, OCT5(21, 47, 3));
    assert.equal(r.tsInferred, true);
    assert.equal(T.parse('Mon Oct  5 23:47:03 CEST 2026').ts, OCT5(21, 47, 3), 'UnixDate with a known zone');
  });
  it('Go time.String() as printed by helm list', () => {
    const r = T.parse('2026-10-05 23:47:03.123456 +0200 CEST');
    assert.equal(r.ts, OCT5(21, 47, 3, 123));
    assert.equal(r.tsInferred, false);
  });
  it('RFC 1123 stamps from kubectl describe', () => {
    assert.equal(T.parse('Mon, 05 Oct 2026 23:51:02 +0200').ts, OCT5(21, 51, 2));
    assert.equal(T.parse('Mon, 05 Oct 2026 21:51:02 GMT').ts, OCT5(21, 51, 2));
  });
  it('klog stamps need a year: ctx.year, else the year of now, and roll back across New Year', () => {
    const r = T.parse('1005 23:51:02.123456', { year: 2026 });
    assert.equal(r.ts, OCT5(23, 51, 2, 123));
    assert.equal(r.tsInferred, true);
    assert.equal(r.yearAssumed, true);
    assert.equal(T.parse('1005 23:51:02', { now: '2026-10-06T00:00:00Z' }).ts, OCT5(23, 51, 2));
    assert.equal(T.parse('1231 23:00:00', { now: '2027-01-01T01:00:00Z' }).ts, utc(2026, 11, 31, 23, 0, 0));
  });
  it('syslog stamps with a non-UTC default zone', () => {
    const r = T.parse('Oct  5 23:51:02', { year: 2026, defaultTz: '-05:00' });
    assert.equal(r.ts, utc(2026, 9, 6, 4, 51, 2));
    assert.equal(r.tsInferred, true);
  });
  it('epoch seconds, milliseconds, microseconds and nanoseconds', () => {
    const ms = OCT5(21, 51, 2, 120);
    assert.equal(T.parse(String(ms / 1000)).ts, ms);
    assert.equal(T.parse(String(ms)).ts, ms);
    assert.equal(T.parse(String(ms * 1000)).ts, ms);
    assert.equal(T.parse(String(ms) + '000000').ts, ms);
    assert.equal(T.parse(ms).ts, ms);
    assert.equal(T.parse(String(ms)).tsInferred, false);
  });
  it('rejects garbage instead of guessing', () => {
    for (const g of ['not a time', '', '   ', '2026-13-45T99:99:99Z', 'Foo Bar 99 99:99:99 2026', '42']) assert.equal(T.parse(g), null, g);
    assert.equal(T.parse(null), null);
  });
  it('kubectl ages and Go durations', () => {
    assert.equal(T.age('45s'), 45000);
    assert.equal(T.age('3m12s'), 192000);
    assert.equal(T.age('2h'), 7200000);
    assert.equal(T.age('5d4h'), 5 * 86400000 + 4 * 3600000);
    assert.equal(T.age('2m (x5 over 10m)'), 120000);
    assert.equal(T.age('1.5s'), 1500);
    assert.equal(T.age('300ms'), 300);
    assert.equal(T.age('<unknown>'), null);
    assert.equal(T.age('abc'), null);
    assert.equal(T.durationMs('2304ms'), 2304);
    assert.equal(T.durationMs('2.5s'), 2500);
    assert.equal(T.durationMs('87'), 87);
  });
  it('formats as HH:MM:SS UTC, with an optional offset', () => {
    assert.equal(T.fmt(OCT5(21, 49, 30)), '21:49:30');
    assert.equal(T.fmt(OCT5(21, 49, 30), '+02:00'), '23:49:30');
    assert.equal(T.fmt(null), '--:--:--');
    assert.equal(T.fmtDateTime(OCT5(21, 49, 30)), '2026-10-05 21:49:30Z');
  });
  it('zone offsets', () => {
    assert.equal(T.offsetMinutes('+02:00'), 120);
    assert.equal(T.offsetMinutes('+0200'), 120);
    assert.equal(T.offsetMinutes('-0530'), -330);
    assert.equal(T.offsetMinutes('Z'), 0);
    assert.equal(T.offsetMinutes('CEST'), 120);
    assert.equal(T.offsetMinutes('bogus'), null);
    assert.equal(T.offsetMinutes('12'), null, 'a bare number is not a zone');
    assert.equal(T.offsetMinutes('a5'), null);
    assert.equal(T.offsetMinutes('UTC+2'), 120);
    assert.equal(T.offsetMinutes('\u221205:00'), -300, 'typographic minus');
    assert.equal(T.fmtOffset(120), '+02:00');
  });
  it('rebase() re-anchors relative signals on a new now', () => {
    const sigs = [{ ts: null, attrs: { relative: true, ageMs: 60000 } }, { ts: 5, attrs: {} }];
    assert.equal(T.rebase(sigs, 1000000), 1);
    assert.equal(sigs[0].ts, 940000);
    assert.equal(sigs[0].tsInferred, true);
    assert.equal(sigs[1].ts, 5);
  });
});

function pick(r) { return r && { ts: r.ts, tsInferred: r.tsInferred }; }

// =============================================================================================
describe('entities', () => {
  it('strips pod suffixes to the workload', () => {
    const cases = {
      'payments-api-7d9f8b6c5-x2k4p': ['payments-api', 'Deployment'],
      'payments-api-5f7b9c8d4-abcde': ['payments-api', 'Deployment'],
      'fluent-bit-x7k2p': ['fluent-bit', 'DaemonSet'],
      'postgres-0': ['postgres', 'StatefulSet'],
      'kafka-12': ['kafka', 'StatefulSet'],
      'redis-cache': ['redis-cache', null],
      'orders-database': ['orders-database', null],
      'coredns-5d78c9869d-abc12': ['coredns', 'Deployment']
    };
    for (const [pod, [wl, ctl]] of Object.entries(cases)) {
      const r = E.stripPod(pod);
      assert.equal(r.workload, wl, pod);
      assert.equal(r.controller, ctl, pod);
    }
    assert.equal(E.stripPod('payments-api-7d9f8b6c5-x2k4p').replicaSet, 'payments-api-7d9f8b6c5');
    assert.equal(E.stripReplicaSet('payments-api-7d9f8b6c5'), 'payments-api');
  });
  it('builds component ids and collapses CoreDNS / nodes', () => {
    assert.equal(E.componentId('service', 'prod-eu-west', 'shop', 'payments-api'), 'service:prod-eu-west/shop/payments-api');
    assert.equal(E.hint({ pod: 'coredns-5d78c9869d-abc12', namespace: 'kube-system', cluster: 'prod' }).id, 'infra:prod/kube-system/coredns');
    assert.equal(E.hint({ name: 'kube-dns', cluster: 'prod' }).id, 'infra:prod/kube-system/coredns');
    assert.equal(E.hint({ node: 'ip-10-0-1-5', cluster: 'prod' }).id, 'node:prod//ip-10-0-1-5');
    assert.deepEqual(E.parseId('service:prod/shop/payments-api'), { type: 'service', cluster: 'prod', namespace: 'shop', name: 'payments-api' });
  });
  it('types datastores and ingress gateways by name', () => {
    assert.equal(E.hint({ name: 'postgres', namespace: 'shop' }).type, 'datastore');
    assert.equal(E.hint({ pod: 'redis-master-0', namespace: 'shop' }).type, 'datastore');
    const gw = E.hint({ name: 'ingress-nginx-controller', namespace: 'ingress-nginx' });
    assert.equal(gw.type, 'service');
    assert.equal(gw.role, 'ingress');
    assert.equal(E.hint({ name: 'payments-db-migrate', namespace: 'shop' }).type, 'service', 'a migration job is not a datastore');
  });
  it('defaults the namespace to "default" but remembers it was not stated', () => {
    const h = E.hint({ name: 'checkout-api', cluster: 'prod' });
    assert.equal(h.namespace, 'default');
    assert.equal(h.nsKnown, false);
    assert.equal(h.clusterKnown, true);
    assert.equal(E.hint({ name: 'x' }).cluster, 'cluster-1');
  });
  it('recognises every cluster marker form', () => {
    assert.equal(E.detectCluster('# cluster: prod-eu-west'), 'prod-eu-west');
    assert.equal(E.detectCluster('--- cluster=prod-us-east ---'), 'prod-us-east');
    assert.equal(E.detectCluster('[context: prod-eu-west]'), 'prod-eu-west');
    assert.equal(E.detectCluster('$ kubectl --context prod-eu-west get pods -n shop'), 'prod-eu-west');
    assert.equal(E.detectCluster('kubectl get events --context=prod-us-east'), 'prod-us-east');
    assert.equal(E.detectCluster('helm history payments --kube-context prod-eu-west'), 'prod-eu-west');
    assert.equal(E.detectCluster('kubectl config use-context staging-1'), 'staging-1');
    assert.equal(E.detectCluster('kubectl --context arn:aws:eks:eu-west-1:123456789012:cluster/prod-eks get pods'), 'prod-eks');
    assert.equal(E.detectCluster('payments-api crashed in cluster prod'), null);
    assert.equal(E.detectCluster('# just a comment'), null);
  });
  it('parses command echoes', () => {
    const c = E.parseCommand('$ kubectl logs payments-api-7d9f8b6c5-x2k4p -c payments-api -n shop --tail 200 --context prod-eu-west');
    assert.equal(c.verb, 'logs');
    assert.equal(c.pod, 'payments-api-7d9f8b6c5-x2k4p');
    assert.equal(c.container, 'payments-api');
    assert.equal(c.namespace, 'shop');
    assert.equal(c.context, 'prod-eu-west');
    assert.equal(E.parseCommand('helm history payments -n shop').release, 'payments');
    assert.equal(E.parseCommand('helm diff upgrade payments ./charts/payments').release, 'payments');
    assert.equal(E.parseCommand('2026-10-05 error happened'), null);
  });
  it('reads in-cluster DNS names', () => {
    assert.deepEqual(E.fromHost('payments-api.shop.svc.cluster.local:8080'), { name: 'payments-api', namespace: 'shop', external: false });
    assert.deepEqual(E.fromHost('payments-api'), { name: 'payments-api', namespace: null, external: false });
    assert.equal(E.fromHost('api.stripe-like.example').external, true);
    assert.equal(E.fromHost('10.0.4.12:8080'), null);
  });
  it('reconciles unknown namespaces and clusters onto the one known match', () => {
    const r = E.reconcile([
      E.hint({ name: 'payments-api', namespace: 'shop', cluster: 'prod' }),
      E.hint({ name: 'payments-api', cluster: 'prod' }),                       // ns unknown
      E.hint({ name: 'payments-api', type: 'external', cluster: 'prod' }),     // trace peer
      E.hint({ name: 'checkout-api', namespace: 'shop' }),                     // cluster unknown (default)
      E.hint({ name: 'checkout-api', namespace: 'shop', cluster: 'prod' }),
      E.hint({ name: 'x', namespace: 'a', cluster: 'prod' }),
      E.hint({ name: 'x', namespace: 'b', cluster: 'prod' }),
      E.hint({ name: 'x', cluster: 'prod' })                                   // ambiguous: stays
    ]);
    assert.equal(r.alias['service:prod/default/payments-api'], 'service:prod/shop/payments-api');
    assert.equal(r.alias['external:prod/default/payments-api'], 'service:prod/shop/payments-api');
    assert.equal(r.alias['service:cluster-1/shop/checkout-api'], 'service:prod/shop/checkout-api');
    assert.equal(r.alias['service:prod/default/x'], undefined);
    const ids = r.entities.map((e) => e.id);
    assert.ok(ids.includes('service:prod/shop/payments-api'));
    assert.ok(!ids.includes('external:prod/default/payments-api'));
    assert.ok(ids.includes('service:prod/default/x'));
  });
  it('does not collapse a name that exists in two clusters', () => {
    const r = E.reconcile([
      E.hint({ name: 'payments-api', namespace: 'shop', cluster: 'prod-eu-west' }),
      E.hint({ name: 'payments-api', namespace: 'shop', cluster: 'prod-us-east' }),
      E.hint({ name: 'payments-api', namespace: 'shop' })
    ]);
    assert.equal(Object.keys(r.alias).length, 0);
  });
  it('folds a Helm release-name guess onto its one workload, and only when unambiguous', () => {
    const guess = Object.assign(E.hint({ name: 'payments', namespace: 'shop', cluster: 'prod' }), { releaseGuess: true });
    const one = E.reconcile([guess, E.hint({ name: 'payments-api', namespace: 'shop', cluster: 'prod' })]);
    assert.equal(one.alias['service:prod/shop/payments'], 'service:prod/shop/payments-api');
    const two = E.reconcile([guess, E.hint({ name: 'payments-api', namespace: 'shop', cluster: 'prod' }), E.hint({ name: 'payments-worker', namespace: 'shop', cluster: 'prod' })]);
    assert.equal(two.alias['service:prod/shop/payments'], undefined);
  });

  it('remaps ids and merges edges', () => {
    const alias = { a: 'b' };
    const sigs = E.remap([{ componentId: 'a', attrs: { targetId: 'a' } }], alias);
    assert.equal(sigs[0].componentId, 'b');
    assert.equal(sigs[0].attrs.targetId, 'b');
    const edges = E.mergeEdges([
      { from: 'x', to: 'y', calls: 3, errors: 1, p95ms: 10, firstErrorTs: 5 },
      { from: 'x', to: 'y', calls: 2, errors: 2, p95ms: 30, firstErrorTs: 3 },
      { from: 'y', to: 'y', calls: 1, errors: 0 }
    ]);
    assert.deepEqual(edges, [{ id: 'x->y', from: 'x', to: 'y', calls: 5, errors: 3, p95ms: 30, firstErrorTs: 3 }]);
  });
});

// =============================================================================================
describe('redact', () => {
  const cases = [
    ['bearer', 'Authorization: Bearer abcdefghijklmnop.qrstuvwxyz'],
    ['jwt', 'token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'],
    ['aws-key', 'key AKIAIOSFODNN7EXAMPLE used'],
    ['private-key', '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Z3V\n-----END RSA PRIVATE KEY-----'],
    ['private-key', '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC (cut off'],
    ['secret-value', 'password=hunter2'],
    ['secret-value', '+    DB_PASSWORD: c3VwZXJzZWNyZXQ='],
    ['secret-value', '"api_key": "abc123xyz"'],
    ['secret-value', 'client_secret=zzzzzz'],
    ['secret-value', 'STRIPE_TOKEN=sk_live_abcdef'],
    ['secret-value', '  - name: DB_PASSWORD\n    value: hunter2'],
    ['url-credential', 'postgres://app:s3cr3t@postgres.shop.svc:5432/payments'],
    ['email', 'paged oncall@example.com'],
    ['base64', 'blob QmFzZTY0RW5jb2RlZFNlY3JldFZhbHVlMTIzNDU2Nzg5MEFCQ0RFRg==']
  ];
  for (const [kind, text] of cases) {
    it(`redacts ${kind}: ${text.split('\n')[0].slice(0, 40)}`, () => {
      const r = WR.redact(text);
      assert.ok(r.count >= 1, 'counted');
      assert.ok(r.kinds.includes(kind), `kinds ${r.kinds} include ${kind}`);
      assert.ok(r.text.includes('[REDACTED:'), r.text);
      for (const secret of ['hunter2', 'c3VwZXJzZWNyZXQ', 'abc123xyz', 'zzzzzz', 'sk_live', 's3cr3t', 'oncall@', 'AKIAIOSFODNN7EXAMPLE', 'MIIE', 'dozjgNry', 'QmFzZTY0']) {
        assert.ok(!r.text.includes(secret), `"${secret}" removed from ${r.text}`);
      }
    });
  }
  it('keeps the username of URL credentials and the key names', () => {
    assert.equal(WR.redact('postgres://app:s3cr3t@db:5432').text, 'postgres://app:[REDACTED:url-credential]@db:5432');
    assert.equal(WR.redact('password=hunter2').text, 'password=[REDACTED:secret-value]');
  });
  it('leaves ordinary evidence alone', () => {
    const clean = [
      'image: registry.example.com/payments-api@sha256:4f1c2a8b9d0e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a',
      'trace_id=4bf92f3577b34da6a3ce929d0e0e4736 span=00f067aa0ba902b7',
      'secretName: payments-tls',
      'valueFrom:\n  secretKeyRef:\n    name: payments-db',
      'max_tokens=4096',
      'GET /apis/apps/v1/namespaces/shop/deployments/payments-api 200',
      'commit 4f1c2a8b9d0e7f6a5b4c3d2e1f0a9b8c7d6e5f4a'
    ];
    for (const c of clean) {
      const r = WR.redact(c);
      assert.equal(r.count, 0, c);
      assert.equal(r.text, c);
    }
  });
  it('counts each secret once and reports per-kind totals', () => {
    const r = WR.redact('token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U and password=x1y2z3');
    assert.equal(r.count, 2);
    assert.deepEqual(r.byKind, { jwt: 1, 'secret-value': 1 });
    assert.equal(WR.redact.looksSecret('DB_PASSWORD'), true);
    assert.equal(WR.redact.looksSecret('LOG_LEVEL', 'debug'), false);
  });
});

// =============================================================================================
describe('parseLogs', () => {
  const NOW = '2026-10-05T21:52:00Z';

  it('reads kubectl get events with relative ages against ctx.now', () => {
    const text = [
      '$ kubectl get events -n shop --context prod-eu-west',
      'LAST SEEN   TYPE      REASON              OBJECT                                MESSAGE',
      '3m12s       Normal    ScalingReplicaSet   deployment/payments-api               Scaled up replica set payments-api-7d9f8b6c5 to 3',
      '2m          Warning   OOMKilling          node/ip-10-0-1-5                      Memory cgroup out of memory: Killed process 4242 (java)',
      '45s         Warning   BackOff             pod/payments-api-7d9f8b6c5-x2k4p      Back-off restarting failed container payments-api in pod payments-api-7d9f8b6c5-x2k4p',
      '<unknown>   Warning   Unhealthy           pod/payments-api-7d9f8b6c5-x2k4p      Readiness probe failed: HTTP probe failed with statuscode: 503',
      '12s         Normal    Pulled              pod/payments-api-7d9f8b6c5-x2k4p      Container image "registry.example.com/payments-api:2.14.0" already present on machine'
    ].join('\n');
    const r = WR.parseLogs(text, { now: NOW });
    assertSignalContract(r.signals, 'logs');
    assertStatsShape(r.stats);
    const byLine = Object.fromEntries(r.signals.map((s) => [s.line, s]));
    assert.equal(byLine[3].kind, 'rollout');
    assert.equal(byLine[3].attrs.replicaSet, 'payments-api-7d9f8b6c5');
    assert.equal(byLine[3].ts, Date.parse(NOW) - 192000);
    assert.equal(byLine[3].tsInferred, true);
    assert.equal(byLine[3].componentId, 'service:prod-eu-west/shop/payments-api');
    assert.equal(byLine[4].kind, 'oom_killed');
    assert.equal(byLine[4].componentId, 'node:prod-eu-west//ip-10-0-1-5');
    assert.equal(byLine[5].kind, 'crash_loop');
    assert.equal(byLine[5].severity, 'error');
    assert.equal(byLine[5].ts, Date.parse(NOW) - 45000);
    assert.equal(byLine[6].kind, 'probe_failed');
    assert.equal(byLine[6].ts, Date.parse(NOW), '<unknown> age → now');
    assert.equal(byLine[6].attrs.ageUnknown, true);
    assert.equal(byLine[7], undefined, 'a Normal event with no failure kind is not a signal');
    assert.equal(r.stats.skipped, 0);
    assert.match(r.stats.format, /kubectl events/);
    assert.ok(r.extras.rollouts.some((x) => x.replicaSet === 'payments-api-7d9f8b6c5'));
  });

  it('reads --all-namespaces and -o wide event tables', () => {
    const all = [
      'NAMESPACE     LAST SEEN   TYPE      REASON             OBJECT                               MESSAGE',
      'kube-system   5m          Warning   Unhealthy          pod/coredns-5d78c9869d-abc12         Liveness probe failed: Get "http://10.0.0.12:8080/health": context deadline exceeded',
      'shop          4m          Warning   FailedScheduling   pod/orders-api-6c9d8f7b5-k2m4n       0/6 nodes are available: 6 Insufficient memory.'
    ].join('\n');
    const r = WR.parseLogs(all, { now: NOW, cluster: 'prod-eu-west' });
    assert.equal(r.signals[0].kind, 'probe_failed');
    assert.equal(r.signals[0].componentId, 'infra:prod-eu-west/kube-system/coredns');
    assert.equal(r.signals[1].kind, 'scheduling_failed');
    assert.equal(r.signals[1].componentId, 'service:prod-eu-west/shop/orders-api');

    const wide = [
      'LAST SEEN   TYPE      REASON    OBJECT                              SUBOBJECT                       SOURCE    MESSAGE                                 FIRST SEEN   COUNT   NAME',
      '30s         Warning   BackOff   pod/payments-api-7d9f8b6c5-x2k4p    spec.containers{payments-api}   kubelet   Back-off restarting failed container    4m           9       payments-api-7d9f8b6c5-x2k4p.17b2c'
    ].join('\n');
    const w = WR.parseLogs(wide, { now: NOW });
    assert.equal(w.signals.length, 1);
    assert.equal(w.signals[0].kind, 'crash_loop');
    assert.equal(w.signals[0].attrs.count, 9);
    assert.equal(w.signals[0].attrs.subobject, 'spec.containers{payments-api}');
    assert.equal(w.signals[0].ts, Date.parse(NOW) - 4 * 60000, 'FIRST SEEN marks the onset');
  });

  it('reads event rows pasted without their header', () => {
    const text = [
      '45s         Warning   BackOff     pod/payments-api-7d9f8b6c5-x2k4p   Back-off restarting failed container',
      '2m          Warning   Unhealthy   pod/payments-api-7d9f8b6c5-x2k4p   Liveness probe failed: connection refused',
      'shop   3m   Warning   FailedMount   pod/worker-7f8d9c6b5-m3n4p   MountVolume.SetUp failed for volume "creds" : secret "worker-creds" not found'
    ].join('\n');
    const r = WR.parseLogs(text, { now: NOW });
    assert.deepEqual(r.signals.map((s) => s.kind), ['crash_loop', 'probe_failed', 'config_error']);
    assert.equal(r.signals[0].ts, Date.parse(NOW) - 45000);
    assert.equal(r.signals[2].componentId, 'service:cluster-1/shop/worker');
    assert.equal(r.stats.skipped, 0);
  });

  it('reads kubectl get pods tables into status signals', () => {
    const text = [
      '$ kubectl get pods -n shop -o wide',
      'NAME                            READY   STATUS             RESTARTS      AGE   IP           NODE          NOMINATED NODE   READINESS GATES',
      'payments-api-7d9f8b6c5-x2k4p    0/1     CrashLoopBackOff   7 (45s ago)   12m   10.0.3.17    ip-10-0-1-5   <none>           <none>',
      'payments-api-7d9f8b6c5-q8w2n    0/1     OOMKilled          3             12m   10.0.3.18    ip-10-0-1-6   <none>           <none>',
      'checkout-api-5c8d7f9b4-q8w2n    1/1     Running            0             3d    10.0.3.40    ip-10-0-1-6   <none>           <none>',
      'orders-api-6c9d8f7b5-k2m4n      0/1     Pending            0             4m    <none>       <none>        <none>           <none>',
      'web-6d8f7c9b5-zz9x8             0/1     ImagePullBackOff   0             2m    10.0.3.50    ip-10-0-1-5   <none>           <none>',
      'worker-7f8d9c6b5-m3n4p          0/1     CreateContainerConfigError   0   2m    10.0.3.51    ip-10-0-1-5   <none>           <none>',
      'old-api-6f7d8c9b5-a1b2c         1/1     Terminating        0             2h    10.0.3.52    ip-10-0-1-5   <none>           <none>',
      'evicted-api-5d6c7b8f9-e1v2c     0/1     Evicted            0             1h    <none>       ip-10-0-1-5   <none>           <none>',
      'flaky-api-5d6c7b8f9-r3s4t       0/1     Running            2 (1m ago)    1h    10.0.3.53    ip-10-0-1-5   <none>           <none>'
    ].join('\n');
    const r = WR.parseLogs(text, { now: NOW });
    assertSignalContract(r.signals, 'logs');
    const kinds = Object.fromEntries(r.signals.map((s) => [s.attrs.pod, s.kind]));
    assert.equal(kinds['payments-api-7d9f8b6c5-x2k4p'], 'crash_loop');
    assert.equal(kinds['payments-api-7d9f8b6c5-q8w2n'], 'oom_killed');
    assert.equal(kinds['checkout-api-5c8d7f9b4-q8w2n'], undefined, 'healthy pod: entity, no signal');
    assert.equal(kinds['orders-api-6c9d8f7b5-k2m4n'], 'scheduling_failed');
    assert.equal(kinds['web-6d8f7c9b5-zz9x8'], 'image_pull');
    assert.equal(kinds['worker-7f8d9c6b5-m3n4p'], 'config_error');
    assert.equal(kinds['old-api-6f7d8c9b5-a1b2c'], 'restart');
    assert.equal(kinds['evicted-api-5d6c7b8f9-e1v2c'], 'evicted');
    assert.equal(kinds['flaky-api-5d6c7b8f9-r3s4t'], 'probe_failed');
    const crash = r.signals.find((s) => s.attrs.pod === 'payments-api-7d9f8b6c5-x2k4p');
    assert.equal(crash.ts, Date.parse(NOW) - 45000, 'last restart "(45s ago)" dates the signal');
    assert.equal(crash.attrs.restarts, 7);
    assert.equal(crash.attrs.node, 'ip-10-0-1-5');
    assert.equal(crash.componentId, 'service:cluster-1/shop/payments-api');
    assert.ok(r.entities.some((e) => e.id === 'service:cluster-1/shop/checkout-api'), 'healthy pods still appear on the map');
  });

  it('reads a kubectl describe pod excerpt', () => {
    const text = [
      'Name:             payments-api-7d9f8b6c5-x2k4p',
      'Namespace:        shop',
      'Node:             ip-10-0-1-5/10.0.1.5',
      'Controlled By:    ReplicaSet/payments-api-7d9f8b6c5',
      'Containers:',
      '  payments-api:',
      '    Image:          registry.example.com/payments-api:2.14.0',
      '    State:          Waiting',
      '      Reason:       CrashLoopBackOff',
      '    Last State:     Terminated',
      '      Reason:       OOMKilled',
      '      Exit Code:    137',
      '      Started:      Mon, 05 Oct 2026 23:50:58 +0200',
      '      Finished:     Mon, 05 Oct 2026 23:51:02 +0200',
      '    Ready:          False',
      '    Restart Count:  7',
      '    Limits:',
      '      cpu:     500m',
      '      memory:  256Mi',
      '    Requests:',
      '      memory:  256Mi',
      'Events:',
      '  Type     Reason     Age                 From               Message',
      '  ----     ------     ----                ----               -------',
      '  Normal   Pulled     5m                  kubelet            Container image "registry.example.com/payments-api:2.14.0" already present on machine',
      '  Warning  BackOff    30s (x9 over 4m)    kubelet            Back-off restarting failed container payments-api in pod payments-api-7d9f8b6c5-x2k4p'
    ].join('\n');
    const r = WR.parseLogs(text, { now: NOW, cluster: 'prod-eu-west' });
    assertSignalContract(r.signals, 'logs');
    const cid = 'service:prod-eu-west/shop/payments-api';
    const waiting = r.signals.find((s) => s.line === 9);
    assert.equal(waiting.kind, 'crash_loop');
    assert.equal(waiting.componentId, cid);
    const oom = r.signals.find((s) => s.line === 11);
    assert.equal(oom.kind, 'oom_killed');
    assert.equal(oom.attrs.exitCode, 137);
    assert.equal(oom.ts, OCT5(21, 51, 2), 'Finished time of the last state');
    assert.equal(oom.tsInferred, false);
    assert.equal(oom.attrs.restartCount, 7);
    assert.equal(oom.attrs.memoryLimit, '256Mi');
    const ev = r.signals.find((s) => s.line === 26);
    assert.equal(ev.kind, 'crash_loop');
    assert.equal(ev.attrs.count, 9);
    assert.equal(ev.ts, Date.parse(NOW) - 4 * 60000, '"x9 over 4m": first seen 4 minutes ago');
    assert.equal(r.extras.podInfo['payments-api-7d9f8b6c5-x2k4p'].containers['payments-api'].limitMemory, '256Mi');
    assert.equal(r.stats.skipped, 0);
  });

  it('leaves a describe block when a log line follows it', () => {
    const text = 'Name: postgres-0\nNamespace: orders\nStatus: Running\nFATAL:  sorry, too many clients already';
    const r = WR.parseLogs(text, { now: NOW });
    assert.equal(r.signals.length, 1);
    assert.equal(r.signals[0].kind, 'conn_exhaustion');
    assert.equal(r.signals[0].line, 4);
  });

  it('treats Exit Code 137 with reason Error as an OOM kill', () => {
    const text = 'Name: worker-0\nNamespace: jobs\nContainers:\n  worker:\n    Last State:  Terminated\n      Reason:    Error\n      Exit Code: 137';
    const r = WR.parseLogs(text, { now: NOW });
    assert.equal(r.signals[0].kind, 'oom_killed');
  });

  it('reads JSON logs with +02:00 offsets into UTC', () => {
    const text = [
      '{"ts":"2026-10-05T23:51:02.120+02:00","level":"error","service":"checkout-api","namespace":"shop","msg":"charge failed","error":"dial tcp 10.0.4.12:8080: connect: connection refused","upstream":"payments-api.shop.svc.cluster.local","trace_id":"4bf92f3577b34da6a3ce929d0e0e4736"}',
      '{"time":"2026-10-05T23:51:03.500+02:00","severity":"INFO","app":"checkout-api","message":"POST /checkout","http.status_code":503,"latency_ms":2304}',
      '{"@timestamp":"2026-10-05T21:51:04Z","lvl":"warn","logger":"checkout-api","msg":"retrying"}',
      '{"timestamp":1791237065000,"level":50,"msg":"Too Many Requests from upstream","service":{"name":"checkout-api"}}'
    ].join('\n');
    const r = WR.parseLogs(text, {});
    assertSignalContract(r.signals, 'logs');
    assert.equal(r.signals.length, 3, 'the warn line without a failure kind is counted, not signalled');
    const [a, b, c] = r.signals;
    assert.equal(a.kind, 'conn_refused');
    assert.equal(a.ts, OCT5(21, 51, 2, 120));
    assert.equal(a.tsInferred, false);
    assert.equal(a.componentId, 'service:cluster-1/shop/checkout-api');
    assert.equal(a.attrs.traceId, '4bf92f3577b34da6a3ce929d0e0e4736');
    assert.equal(a.attrs.targetId, 'service:cluster-1/shop/payments-api');
    assert.equal(b.kind, 'http_5xx');
    assert.equal(b.severity, 'error', 'an info line carrying a 503 is still an error');
    assert.equal(b.attrs.status, 503);
    assert.equal(b.attrs.latencyMs, 2304);
    assert.equal(c.kind, 'http_429');
    assert.equal(c.ts, 1791237065000);
    assert.equal(r.stats.tzAssumed, 0);
    assert.match(r.stats.format, /JSON logs/);
    // Only the first line states a namespace; the rest wait for reconcile() under "default".
    assert.equal(r.extras.componentCounts['service:cluster-1/shop/checkout-api'].lines, 1);
    assert.equal(r.extras.componentCounts['service:cluster-1/default/checkout-api'].lines, 3);
    assert.equal(r.extras.componentCounts['service:cluster-1/default/checkout-api'].warn, 1);
    assert.equal(r.extras.dependencyHints[0].to, 'service:cluster-1/shop/payments-api');
    assert.equal(r.extras.dependencyHints[0].firstTs, OCT5(21, 51, 2, 120));
  });

  it('reads kubectl logs --prefix and stern lines', () => {
    const text = [
      '[pod/payments-api-7d9f8b6c5-x2k4p/payments-api] 2026-10-05T21:51:00.000Z java.lang.OutOfMemoryError: Java heap space',
      '[pod/checkout-api-5c8d7f9b4-q8w2n/checkout-api] {"ts":"2026-10-05T21:51:01Z","level":"error","msg":"upstream connect error or disconnect/reset before headers"}',
      'payments-api-7d9f8b6c5-x2k4p payments-api 2026-10-05T21:51:02Z panic: runtime error: invalid memory address or nil pointer dereference',
      'shop checkout-api-5c8d7f9b4-q8w2n checkout-api 2026-10-05T21:51:03Z ERROR context deadline exceeded calling payments-api:8080',
      'postgres-0 postgres 2026-10-05 21:51:04.000 UTC [123] FATAL:  sorry, too many clients already'
    ].join('\n');
    const r = WR.parseLogs(text, { cluster: 'prod-eu-west' });
    assertSignalContract(r.signals, 'logs');
    assert.deepEqual(r.signals.map((s) => s.kind), ['oom_killed', 'conn_refused', 'panic', 'timeout', 'conn_exhaustion']);
    assert.equal(r.signals[0].componentId, 'service:prod-eu-west/default/payments-api');
    assert.equal(r.signals[0].attrs.container, 'payments-api');
    assert.equal(r.signals[2].attrs.pod, 'payments-api-7d9f8b6c5-x2k4p');
    assert.equal(r.signals[3].componentId, 'service:prod-eu-west/shop/checkout-api', 'stern -A namespace column');
    assert.equal(r.signals[4].componentId, 'datastore:prod-eu-west/default/postgres');
    assert.equal(r.signals[4].severity, 'critical', 'FATAL');
    const nsUnknown = r.entities.find((e) => e.name === 'payments-api');
    assert.equal(nsUnknown.nsKnown, false, 'reconcile() can later attach the real namespace');
  });

  it('reads klog, syslog and logfmt lines', () => {
    const text = [
      'E1005 23:51:04.123456       1 reflector.go:138] k8s.io/client-go: failed to list *v1.Pod: Get "https://10.96.0.1:443/api/v1/pods": dial tcp 10.96.0.1:443: i/o timeout',
      'Oct  5 23:51:05 ip-10-0-1-5 kernel: Memory cgroup out of memory: Killed process 4242 (java) total-vm:1234kB',
      'Oct  5 23:51:06 ip-10-0-1-5 kubelet[1234]: E1005 node "ip-10-0-1-5" not ready: container runtime is down',
      'level=error ts=2026-10-05T21:51:07Z msg="lookup postgres.shop.svc.cluster.local on 10.96.0.10:53: read udp 10.0.3.4:43521->10.96.0.10:53: i/o timeout" service=orders-api'
    ].join('\n');
    const r = WR.parseLogs(text, { defaultTz: '+02:00', year: 2026, cluster: 'prod-eu-west' });
    assertSignalContract(r.signals, 'logs');
    const [k, s1, s2, l] = r.signals;
    assert.equal(k.kind, 'timeout');
    assert.equal(k.severity, 'error');
    assert.equal(k.ts, OCT5(21, 51, 4, 123), 'klog stamp, zone-less → +02:00');
    assert.equal(k.tsInferred, true);
    assert.equal(s1.kind, 'oom_killed');
    assert.equal(s1.componentId, 'node:prod-eu-west//ip-10-0-1-5');
    assert.equal(s1.ts, OCT5(21, 51, 5));
    assert.equal(s2.kind, 'node_not_ready');
    assert.equal(l.kind, 'dns_failure', 'DNS beats timeout');
    assert.equal(l.ts, OCT5(21, 51, 7));
    assert.equal(l.tsInferred, false);
    assert.equal(l.attrs.targetId, 'datastore:prod-eu-west/shop/postgres');
    assert.ok(r.extras.dependencyHints.some((d) => d.to === 'infra:prod-eu-west/kube-system/coredns'), 'DNS failures point at CoreDNS');
    assert.equal(r.stats.tzAssumed, 3);
    assert.ok(r.stats.warnings.some((w) => /assumed \+02:00/.test(w)));
    assert.ok(r.stats.warnings.some((w) => /no year; assumed 2026/.test(w)));
  });

  it('switches cluster on markers mid-pane', () => {
    const text = [
      '# cluster: prod-eu-west',
      '[pod/payments-api-7d9f8b6c5-x2k4p/payments-api] 2026-10-05T21:51:00Z ERROR connection refused',
      '--- cluster=prod-us-east ---',
      '[pod/payments-api-6b8c7d9f4-p9q8r/payments-api] 2026-10-05T21:51:00Z ERROR connection refused',
      '[context: staging]',
      '[pod/payments-api-6b8c7d9f4-p9q8r/payments-api] 2026-10-05T21:51:00Z ERROR connection refused',
      '$ kubectl --context prod-ap logs payments-api-6b8c7d9f4-p9q8r -n shop',
      '2026-10-05T21:51:00Z ERROR connection refused'
    ].join('\n');
    const r = WR.parseLogs(text, {});
    assert.deepEqual(r.signals.map((s) => s.componentId), [
      'service:prod-eu-west/default/payments-api',
      'service:prod-us-east/default/payments-api',
      'service:staging/default/payments-api',
      'service:prod-ap/shop/payments-api'
    ]);
    assert.deepEqual(r.extras.clusters, ['prod-eu-west', 'prod-us-east', 'staging', 'prod-ap']);
  });

  it('gives unstamped lines after a `kubectl logs` echo to that pod and carries the last time', () => {
    const text = [
      '$ kubectl logs checkout-api-5c8d7f9b4-q8w2n -n shop',
      '2026-10-05T21:51:00Z INFO starting',
      'ERROR upstream request timeout talking to payments-api:8080',
      'java.net.ConnectException: Connection refused'
    ].join('\n');
    const r = WR.parseLogs(text, {});
    assert.equal(r.signals.length, 2);
    for (const s of r.signals) {
      assert.equal(s.componentId, 'service:cluster-1/shop/checkout-api');
      assert.equal(s.ts, OCT5(21, 51, 0));
      assert.equal(s.tsInferred, true);
    }
    assert.equal(r.signals[0].kind, 'timeout');
    assert.equal(r.signals[1].kind, 'conn_refused');
  });

  it('folds stack-trace frames into the record above, keeping a new "Caused by" failure', () => {
    const text = [
      '[pod/orders-api-6c9d8f7b5-k2m4n/orders-api] 2026-10-05T21:51:00Z ERROR request failed',
      '    at com.example.orders.Repo.save(Repo.java:42)',
      '    at com.example.orders.Api.post(Api.java:17)',
      'Caused by: org.postgresql.util.PSQLException: FATAL: remaining connection slots are reserved for non-replication superuser connections'
    ].join('\n');
    const r = WR.parseLogs(text, {});
    assert.deepEqual(r.signals.map((s) => s.kind), ['error_generic', 'conn_exhaustion']);
    assert.equal(r.signals[1].componentId, r.signals[0].componentId);
    assert.equal(r.stats.skipped, 0);
  });

  it('applies every keyword rule, in priority order', () => {
    const cases = [
      ['Memory cgroup out of memory: Killed process 4242', 'oom_killed'],
      ['Last State: Terminated Exit Code: 137', 'oom_killed'],
      ['Back-off restarting failed container', 'crash_loop'],
      ['Failed to pull image "registry.example.com/x:9": manifest unknown', 'image_pull'],
      ['Error: secret "payments-db" not found', 'config_error'],
      ['Readiness probe failed: HTTP probe failed with statuscode: 503', 'probe_failed'],
      ['The node was low on resource: memory. Container x was using 300Mi', 'evicted'],
      ['Node ip-10-0-1-5 status is now: NodeNotReady', 'node_not_ready'],
      ['Node ip-10-0-1-5 status is now: NodeHasDiskPressure DiskPressure', 'node_pressure'],
      ['0/6 nodes are available: 6 Insufficient cpu.', 'scheduling_failed'],
      ['pod has unbound immediate PersistentVolumeClaims', 'pvc_pending'],
      ['dial tcp: lookup payments-api.shop.svc.cluster.local on 10.96.0.10:53: no such host', 'dns_failure'],
      ['lookup redis on 10.96.0.10:53: read udp: i/o timeout', 'dns_failure'],
      ['dial tcp 10.0.4.12:8080: connect: connection refused', 'conn_refused'],
      ['context deadline exceeded', 'timeout'],
      ['x509: certificate has expired or is not yet valid', 'tls_error'],
      ['"GET /checkout HTTP/1.1" 503 19 "-"', 'http_5xx'],
      ['request failed status=502', 'http_5xx'],
      ['HTTP 429 Too Many Requests', 'http_429'],
      ['CPU throttling at 90%', 'throttled'],
      ['ScalingLimited the desired replica count is more than the maximum replica count', 'hpa_maxed'],
      ['Scaled up replica set payments-api-7d9f8b6c5 to 3', 'rollout'],
      ['Started container payments-api', 'restart'],
      ['panic: runtime error: index out of range', 'panic'],
      ['Traceback (most recent call last):', 'panic'],
      ['ERROR: deadlock detected', 'db_error'],
      ['FATAL: sorry, too many clients already', 'conn_exhaustion'],
      ['HikariPool-1 - Connection is not available, request timed out after 30000ms', 'conn_exhaustion'],
      ['migration 0042_add_index failed: relation "orders" already exists', 'migration']
    ];
    for (const [text, kind] of cases) assert.equal(WR.classifyText(text), kind, text);
    // generic error: level error with no other match
    const r = WR.parseLogs('2026-10-05T21:51:00Z ERROR something odd happened', {});
    assert.equal(r.signals[0].kind, 'error_generic');
  });

  it('avoids common false positives', () => {
    assert.equal(WR.classifyText('processed 500 rows in 12 ms'), null);
    assert.equal(WR.classifyText('GET /health took 512 ms'), null);
    assert.equal(WR.classifyText('2026-10-05T21:51:02.429Z started'), null, '.429 inside a timestamp');
    assert.equal(WR.classifyText('Created container payments-api'), null);
  });

  it('settles relative times on the latest absolute stamp when ctx.now is missing', () => {
    const text = [
      '2026-10-05T21:52:00Z INFO reference line',
      'LAST SEEN   TYPE      REASON    OBJECT                             MESSAGE',
      '1m          Warning   BackOff   pod/payments-api-7d9f8b6c5-x2k4p   Back-off restarting failed container'
    ].join('\n');
    const r = WR.parseLogs(text, {});
    assert.equal(r.signals[0].ts, OCT5(21, 51, 0));
    assert.equal(r.signals[0].attrs.relative, true);
    assert.equal(r.signals[0].attrs.ageMs, 60000);
    const lone = WR.parseLogs(text.split('\n').slice(1).join('\n'), {});
    assert.equal(lone.signals[0].ts, null, 'no reference at all: left for the analysis to rebase');
    assert.ok(lone.stats.warnings.some((w) => /reference time/.test(w)));
    T.rebase(lone.signals, OCT5(22, 0, 0));
    assert.equal(lone.signals[0].ts, OCT5(21, 59, 0));
  });

  it('reads get nodes and get hpa tables', () => {
    const text = [
      'NAME          STATUS     ROLES    AGE   VERSION',
      'ip-10-0-1-5   NotReady   <none>   40d   v1.30.4',
      'ip-10-0-1-6   Ready      <none>   40d   v1.30.4',
      '',
      '$ kubectl get hpa -n orders',
      'NAME         REFERENCE               TARGETS        MINPODS   MAXPODS   REPLICAS   AGE',
      'orders-api   Deployment/orders-api   cpu: 95%/70%   6         20        20         3h'
    ].join('\n');
    const r = WR.parseLogs(text, { now: NOW });
    assert.equal(r.signals[0].kind, 'node_not_ready');
    assert.equal(r.signals[0].componentId, 'node:cluster-1//ip-10-0-1-5');
    assert.equal(r.signals[1].kind, 'hpa_maxed');
    assert.equal(r.signals[1].componentId, 'service:cluster-1/orders/orders-api');
    assert.equal(r.signals[1].attrs.maxReplicas, 20);
    assert.ok(r.entities.some((e) => e.id === 'node:cluster-1//ip-10-0-1-6'));
  });

  it('never throws on junk and says what it skipped', () => {
    const junk = [
      'lorem ipsum dolor sit amet',
      '\u0000\u0001\u0002 binary ��',
      '{"unterminated": ',
      '[pod/broken',
      'LAST SEEN   TYPE      REASON    OBJECT    MESSAGE',
      'this row does not fit the table',
      '%%%%%%%%%%%%%%%%%%%%%%%%',
      'x'.repeat(5000)
    ].join('\n');
    let r;
    assert.doesNotThrow(() => { r = WR.parseLogs(junk, {}); });
    assertStatsShape(r.stats);
    assert.ok(r.stats.skipped >= 5);
    assert.ok(r.stats.warnings.length >= 1);
    for (const input of [undefined, null, '', '\n\n', 42, { a: 1 }]) assert.doesNotThrow(() => WR.parseLogs(input, undefined));
    assert.equal(WR.parseLogs('', {}).stats.format, 'empty');
    // random bytes
    let seed = 7;
    const rnd = () => (seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648;
    const noise = Array.from({ length: 300 }, () => Array.from({ length: 80 }, () => String.fromCharCode(32 + Math.floor(rnd() * 95))).join('')).join('\n');
    assert.doesNotThrow(() => WR.parseLogs(noise, {}));
  });

  it('parses 5,000 log lines in under 60 ms', () => {
    const lines = [];
    for (let i = 0; i < 5000; i++) {
      const s = String(i % 60).padStart(2, '0');
      switch (i % 5) {
        case 0: lines.push(`[pod/checkout-api-5c8d7f9b4-q8w2n/checkout-api] {"ts":"2026-10-05T23:51:${s}.120+02:00","level":"error","msg":"charge failed","error":"dial tcp 10.0.4.12:8080: connect: connection refused","trace_id":"4bf92f3577b34da6a3ce929d0e0e47${s}"}`); break;
        case 1: lines.push(`{"ts":"2026-10-05T21:51:${s}Z","level":"info","service":"frontend","msg":"GET /checkout","status":200,"latency_ms":${i % 300}}`); break;
        case 2: lines.push(`E1005 21:51:${s}.123456       1 reflector.go:138] failed to list *v1.Pod: i/o timeout`); break;
        case 3: lines.push(`level=warn ts=2026-10-05T21:51:${s}Z msg="slow query" service=orders-api duration=${i}ms`); break;
        default: lines.push(`payments-api-7d9f8b6c5-x2k4p payments-api 2026-10-05T21:51:${s}Z INFO handled request id=${i}`);
      }
    }
    const text = lines.join('\n');
    WR.parseLogs(text, {}); // warm up the JIT
    let best = Infinity;
    for (let k = 0; k < 3; k++) {
      const t0 = performance.now();
      const r = WR.parseLogs(text, {});
      best = Math.min(best, performance.now() - t0);
      assert.equal(r.stats.lines, 5000);
    }
    assert.ok(best < 60, `5,000 lines took ${best.toFixed(1)} ms`);
  });
});

// =============================================================================================
describe('parseTraces', () => {
  const nanos = (iso) => String(BigInt(Date.parse(iso)) * 1000000n);
  const resource = (svc, extra = []) => ({ attributes: [
    { key: 'service.name', value: { stringValue: svc } },
    { key: 'k8s.cluster.name', value: { stringValue: 'prod-eu-west' } },
    { key: 'k8s.namespace.name', value: { stringValue: 'shop' } },
    ...extra
  ] });
  const span = (traceId, spanId, parentSpanId, name, kind, startIso, durMs, status, attributes = []) => ({
    traceId, spanId, ...(parentSpanId ? { parentSpanId } : {}), name, kind,
    startTimeUnixNano: nanos(startIso), endTimeUnixNano: String(BigInt(nanos(startIso)) + BigInt(Math.round(durMs * 1e6))),
    status, attributes
  });
  const OTLP = {
    resourceSpans: [
      { resource: resource('frontend', [{ key: 'k8s.pod.name', value: { stringValue: 'frontend-6d5c4b3a29-abcde' } }]), scopeSpans: [{ scope: { name: 'otel-js' }, spans: [
        span('4bf92f3577b34da6a3ce929d0e0e4736', 'f1000001', null, 'GET /checkout', 2, '2026-10-05T21:52:10.120Z', 2304, { code: 2, message: 'upstream returned 502' }, [{ key: 'http.response.status_code', value: { intValue: '502' } }]),
        span('4bf92f3577b34da6a3ce929d0e0e4736', 'f1000002', 'f1000001', 'POST checkout-api', 3, '2026-10-05T21:52:10.130Z', 2280, { code: 'STATUS_CODE_ERROR' }),
        span('5a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d', 'f2000001', null, 'GET /checkout', 'SPAN_KIND_SERVER', '2026-10-05T21:50:00.000Z', 80, {}),
        span('6a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d', 'f3000001', null, 'GET /checkout', 2, '2026-10-05T21:50:01.000Z', 85, { code: 1 })
      ] }] },
      { resource: resource('checkout-api'), scopeSpans: [{ spans: [
        span('4bf92f3577b34da6a3ce929d0e0e4736', 'c1000001', 'f1000002', 'POST /checkout', 2, '2026-10-05T21:52:10.140Z', 2250, { code: 2, message: 'dial tcp 10.0.4.12:8080: connect: connection refused' }),
        span('4bf92f3577b34da6a3ce929d0e0e4736', 'c1000002', 'c1000001', 'POST /charge', 3, '2026-10-05T21:52:10.150Z', 10, { code: 2 }, [
          { key: 'peer.service', value: { stringValue: 'payments-api' } },
          { key: 'http.response.status_code', value: { intValue: 503 } }
        ]),
        span('4bf92f3577b34da6a3ce929d0e0e4736', 'c1000003', 'c1000001', 'SELECT orders', 3, '2026-10-05T21:52:10.161Z', 9, {}, [
          { key: 'db.system', value: { stringValue: 'postgresql' } },
          { key: 'db.name', value: { stringValue: 'orders' } },
          { key: 'server.address', value: { stringValue: 'postgres.shop.svc.cluster.local' } }
        ]),
        span('4bf92f3577b34da6a3ce929d0e0e4736', 'c1000004', 'c1000001', 'GET rates', 3, '2026-10-05T21:52:10.171Z', 40, {}, [
          { key: 'server.address', value: { stringValue: 'api.rates.example' } }
        ])
      ] }] }
    ]
  };

  it('reads OTLP JSON in proto3 encoding', () => {
    const text = JSON.stringify(OTLP, null, 2);
    const r = WR.parseTraces(text, {});
    assertSignalContract(r.signals, 'traces');
    assertStatsShape(r.stats);
    assert.equal(r.stats.format, 'OTLP JSON');
    assert.equal(r.stats.skipped, 0);
    assert.equal(r.extras.traceStats.spans, 8);
    assert.equal(r.extras.traceStats.traces, 3);
    assert.equal(r.extras.traceStats.errorTraces, 1);
    assert.equal(r.extras.traceStats.services, 2);
    assert.equal(r.extras.traceStats.entryErrorRatio, 1 / 3, 'one of three root spans failed');
    const errs = r.signals.filter((s) => s.kind === 'span_error');
    assert.equal(errs.length, 4, 'status 2, "STATUS_CODE_ERROR", and both checkout errors');
    const root = errs.find((s) => s.attrs.spanId === 'f1000001');
    assert.equal(root.ts, OCT5(21, 52, 10, 120));
    assert.equal(root.tsInferred, false);
    assert.equal(root.attrs.httpStatus, 502);
    assert.equal(root.componentId, 'service:prod-eu-west/shop/frontend');
    assert.equal(text.split('\n')[root.line - 1].includes('"f1000001"'), true, 'line points at the span id');
    assert.equal(errs.find((s) => s.attrs.spanId === 'c1000001').attrs.causeKind, 'conn_refused');
    assert.ok(root.relatedIds.length >= 3, 'errors in one trace link to each other');
    const edges = Object.fromEntries(r.extras.edges.map((e) => [e.to, e]));
    const fe = edges['service:prod-eu-west/shop/checkout-api'];
    assert.equal(fe.from, 'service:prod-eu-west/shop/frontend');
    assert.equal(fe.calls, 1);
    assert.equal(fe.errors, 1);
    assert.equal(fe.firstErrorTs, OCT5(21, 52, 10, 140));
    assert.equal(fe.p95ms, 2250);
    assert.equal(edges['external:prod-eu-west/default/payments-api'].errors, 1, 'uninstrumented peer → external (reconciled later)');
    assert.equal(edges['datastore:prod-eu-west/shop/postgres'].calls, 1, 'db client span → datastore named by server.address');
    assert.ok(edges['external:prod-eu-west/default/api.rates.example'], 'outside host → external');
    const fr = r.entities.find((e) => e.id === 'service:prod-eu-west/shop/frontend');
    assert.equal(fr.userFacing, true);
    assert.deepEqual(fr.pods, ['frontend-6d5c4b3a29-abcde']);
    assert.equal(r.entities.find((e) => e.name === 'checkout-api').userFacing, false);
  });

  it('flags slow spans at > 3× the median of their service + operation, minimum 1 s', () => {
    const spans = [90, 100, 110, 95, 105, 4000, 120].map((d, i) => span('t' + i, 's' + i, null, 'GET /search', 2, `2026-10-05T21:50:0${i}.000Z`, d, {}));
    const r = WR.parseTraces(JSON.stringify({ resourceSpans: [{ resource: resource('search'), scopeSpans: [{ spans }] }] }), {});
    const slow = r.signals.filter((s) => s.kind === 'span_slow');
    assert.equal(slow.length, 1);
    assert.equal(slow[0].attrs.durMs, 4000);
    assert.equal(slow[0].severity, 'warn');
    assert.equal(slow[0].attrs.medianMs, 105);
    // 3× median but under 1 s: not slow
    const fast = [10, 10, 10, 50].map((d, i) => span('u' + i, 'v' + i, null, 'GET /x', 2, `2026-10-05T21:50:0${i}.000Z`, d, {}));
    assert.equal(WR.parseTraces(JSON.stringify({ resourceSpans: [{ resource: resource('x'), scopeSpans: [{ spans: fast }] }] }), {}).signals.length, 0);
  });

  it('reads Jaeger JSON', () => {
    const us = (iso) => Date.parse(iso) * 1000;
    const jaeger = { data: [{
      traceID: 'abc123',
      spans: [
        { traceID: 'abc123', spanID: 's1', operationName: 'GET /orders', references: [{ refType: 'CHILD_OF', traceID: 'abc123', spanID: 's3' }], startTime: us('2026-10-05T21:55:00.000Z'), duration: 1800000, processID: 'p1',
          tags: [{ key: 'span.kind', type: 'string', value: 'server' }, { key: 'http.status_code', type: 'int64', value: 500 }, { key: 'error', type: 'bool', value: true }] },
        { traceID: 'abc123', spanID: 's2', operationName: 'INSERT orders', references: [{ refType: 'CHILD_OF', traceID: 'abc123', spanID: 's1' }], startTime: us('2026-10-05T21:55:00.010Z'), duration: 1750000, processID: 'p1',
          tags: [{ key: 'span.kind', type: 'string', value: 'client' }, { key: 'db.system', type: 'string', value: 'postgresql' }, { key: 'db.name', type: 'string', value: 'orders' }, { key: 'otel.status_code', type: 'string', value: 'ERROR' }, { key: 'otel.status_description', type: 'string', value: 'FATAL: sorry, too many clients already' }] },
        { traceID: 'abc123', spanID: 's3', operationName: 'GET /orders', references: [{ refType: 'CHILD_OF', traceID: 'abc123', spanID: 'g1' }], startTime: us('2026-10-05T21:54:59.990Z'), duration: 1900000, processID: 'p2',
          tags: [{ key: 'span.kind', type: 'string', value: 'client' }] },
        { traceID: 'abc123', spanID: 'g1', operationName: 'GET /api/orders', references: [], startTime: us('2026-10-05T21:54:59.980Z'), duration: 1950000, processID: 'p2',
          tags: [{ key: 'span.kind', type: 'string', value: 'server' }] }
      ],
      processes: {
        p1: { serviceName: 'orders-api', tags: [{ key: 'k8s.cluster.name', type: 'string', value: 'prod-us-east' }, { key: 'k8s.namespace.name', type: 'string', value: 'orders' }] },
        p2: { serviceName: 'api-gateway', tags: [{ key: 'k8s.cluster.name', type: 'string', value: 'prod-us-east' }, { key: 'k8s.namespace.name', type: 'string', value: 'edge' }] }
      }
    }] };
    const r = WR.parseTraces(JSON.stringify(jaeger, null, 2), {});
    assertSignalContract(r.signals, 'traces');
    assert.equal(r.stats.format, 'Jaeger JSON');
    const s1 = r.signals.find((s) => s.attrs.spanId === 's1');
    assert.equal(s1.kind, 'span_error');
    assert.equal(s1.ts, Date.parse('2026-10-05T21:55:00.000Z'));
    assert.equal(s1.componentId, 'service:prod-us-east/orders/orders-api');
    assert.equal(r.signals.find((s) => s.attrs.spanId === 's2').attrs.causeKind, 'conn_exhaustion');
    const toDb = r.extras.edges.find((e) => e.to === 'datastore:prod-us-east/orders/orders');
    assert.equal(toDb.errors, 1);
    const gwEdge = r.extras.edges.find((e) => e.from === 'service:prod-us-east/edge/api-gateway');
    assert.equal(gwEdge.to, 'service:prod-us-east/orders/orders-api');
    assert.equal(r.entities.find((e) => e.name === 'api-gateway').role, 'ingress');
    assert.equal(r.entities.find((e) => e.name === 'api-gateway').userFacing, true);
    assert.equal(r.entities.find((e) => e.name === 'orders-api').userFacing, false);
    assert.equal(r.extras.traceStats.entryErrorRatio, 0, 'the gateway root span itself succeeded');
  });

  it('reads the one-span-per-line text format with markers and zones', () => {
    const text = [
      '# cluster: prod-eu-west',
      '2026-10-05T21:52:10.120Z trace=4bf9 span=a1 parent=- service=frontend op="GET /checkout" dur=2304ms status=ERROR code=502 peer=checkout-api cluster=prod-eu-west ns=shop',
      '2026-10-05T21:52:10.130Z trace=4bf9 span=b1 parent=a1 service=checkout-api op="POST /checkout" dur=2.29s status=ERROR code=503 ns=shop kind=server',
      '2026-10-05 23:52:10.140 trace=4bf9 span=c1 parent=b1 service=checkout-api op="SELECT" dur=12ms status=OK kind=client db=postgresql ns=shop',
      'not a span line'
    ].join('\n');
    const r = WR.parseTraces(text, { defaultTz: '+02:00' });
    assertSignalContract(r.signals, 'traces');
    assert.equal(r.stats.format, 'span text');
    assert.equal(r.stats.skipped, 1);
    assert.equal(r.stats.tzAssumed, 1);
    assert.deepEqual(r.signals.map((s) => s.line), [2, 3]);
    assert.equal(r.signals[1].attrs.durMs, 2290);
    assert.equal(r.signals[1].componentId, 'service:prod-eu-west/shop/checkout-api');
    assert.ok(r.extras.edges.some((e) => e.from === 'service:prod-eu-west/shop/frontend' && e.to === 'service:prod-eu-west/shop/checkout-api' && e.errors === 1));
    assert.ok(r.extras.edges.some((e) => e.to === 'datastore:prod-eu-west/shop/postgresql'));
    assert.equal(r.extras.traceStats.entryErrorRatio, 1);
    assert.equal(r.signals[0].raw, text.split('\n')[1]);
  });

  it('recovers from cut-off JSON and survives junk', () => {
    const full = JSON.stringify(OTLP, null, 2);
    const r = WR.parseTraces(full.slice(0, Math.floor(full.length * 0.55)), {});
    assert.ok(r.extras.traceStats.spans >= 1 && r.extras.traceStats.spans < 8);
    assert.ok(r.stats.warnings.some((w) => /cut off/.test(w)));
    for (const junk of ['{"resourceSpans": [', 'garbage\nmore garbage', '[1,2,3]', '{"unrelated": true}', '', null, '{{{{']) {
      let out;
      assert.doesNotThrow(() => { out = WR.parseTraces(junk, {}); }, String(junk));
      assertStatsShape(out.stats);
      assert.equal(out.signals.length, 0);
    }
    assert.ok(WR.parseTraces('garbage', {}).stats.warnings.some((w) => /No spans found/.test(w)));
  });

  it('reads NDJSON (one OTLP export per line) after a cluster marker', () => {
    const one = JSON.stringify({ resourceSpans: [{ resource: { attributes: [{ key: 'service.name', value: { stringValue: 'a' } }] }, scopeSpans: [{ spans: [span('t1', 'x1', null, 'op', 2, '2026-10-05T21:50:00Z', 5, { code: 2 })] }] }] });
    const two = JSON.stringify({ resourceSpans: [{ resource: { attributes: [{ key: 'service.name', value: { stringValue: 'b' } }] }, scopeSpans: [{ spans: [span('t2', 'x2', null, 'op', 2, '2026-10-05T21:50:01Z', 5, { code: 2 })] }] }] });
    const r = WR.parseTraces(['# cluster: prod-us-east', one, two].join('\n'), {});
    assert.deepEqual(r.signals.map((s) => [s.line, s.componentId]), [[2, 'service:prod-us-east/default/a'], [3, 'service:prod-us-east/default/b']]);
  });
});

// =============================================================================================
describe('parseAlerts', () => {
  const WEBHOOK = {
    receiver: 'pagerduty', status: 'firing', version: '4', groupKey: '{}:{alertname="KubePodCrashLooping"}',
    alerts: [
      { status: 'firing', labels: { alertname: 'KubePodCrashLooping', namespace: 'shop', pod: 'payments-api-7d9f8b6c5-x2k4p', container: 'payments-api', job: 'kube-state-metrics', service: 'kube-prometheus-stack-kube-state-metrics', severity: 'critical', cluster: 'prod-eu-west', instance: '10.0.3.4:8080', uid: '0b8f6a1e-5c2d-4e7f-9a3b-1c2d3e4f5a6b' },
        annotations: { summary: 'Pod is crash looping.', runbook_url: 'https://runbooks.example/KubePodCrashLooping' }, startsAt: '2026-10-05T21:49:30Z', endsAt: '0001-01-01T00:00:00Z', fingerprint: 'a1b2' },
      { status: 'firing', labels: { alertname: 'PaymentsHighErrorBurn', service: 'payments-api', namespace: 'shop', severity: 'page', cluster: 'prod-eu-west', long_window: '1h', request_id: 'r-1' },
        annotations: { summary: 'Error budget burning at 16.2x', error_ratio: '0.0162' }, startsAt: '2026-10-05T21:50:00.000Z', endsAt: '0001-01-01T00:00:00Z' },
      { status: 'resolved', labels: { alertname: 'KubeNodeNotReady', node: 'ip-10-0-1-5', severity: 'warning', cluster: 'prod-eu-west' },
        annotations: {}, startsAt: '2026-10-05T20:00:00Z', endsAt: '2026-10-05T20:05:00Z' },
      { status: 'firing', labels: { alertname: 'CheckoutHighErrorRate', app: 'checkout-api', namespace: 'shop', severity: 'warning', cluster: 'prod-eu-west' },
        annotations: { description: '5xx ratio above 5%' }, startsAt: '2026-10-05T21:51:00Z' }
    ],
    groupLabels: { alertname: 'KubePodCrashLooping' }, commonLabels: {}, commonAnnotations: {}
  };

  it('reads an Alertmanager webhook payload', () => {
    const text = JSON.stringify(WEBHOOK, null, 2);
    const r = WR.parseAlerts(text, {});
    assertSignalContract(r.signals, 'alerts');
    assertStatsShape(r.stats);
    assert.equal(r.stats.format, 'Alertmanager webhook JSON');
    const [crash, burn, node, http] = r.signals;
    assert.equal(crash.kind, 'crash_loop');
    assert.equal(crash.severity, 'critical');
    assert.equal(crash.componentId, 'service:prod-eu-west/shop/payments-api', 'kube-state-metrics labels skipped, pod → workload');
    assert.equal(crash.ts, OCT5(21, 49, 30));
    assert.equal(crash.attrs.runbook, 'https://runbooks.example/KubePodCrashLooping');
    assert.equal(crash.attrs.endsAt, undefined, '0001-01-01 means "not set"');
    assert.ok(text.split('\n')[crash.line - 1].includes('"KubePodCrashLooping"'));
    assert.equal(burn.kind, 'slo_burn');
    assert.equal(burn.attrs.burnRate, 16.2, 'burn rate read from the summary');
    assert.equal(burn.attrs.errorRatio, 0.0162);
    assert.equal(burn.attrs.window, '1h');
    assert.equal(node.kind, 'alert_resolved');
    assert.equal(node.attrs.alertKind, 'node_not_ready');
    assert.equal(node.ts, OCT5(20, 5, 0), 'a resolved alert is dated by endsAt');
    assert.equal(node.severity, 'info');
    assert.equal(node.componentId, 'node:prod-eu-west//ip-10-0-1-5');
    assert.equal(http.kind, 'http_5xx');
    assert.equal(http.severity, 'warn');
    assert.equal(http.componentId, 'service:prod-eu-west/shop/checkout-api');
    assert.deepEqual(r.extras.counts, { firing: 3, resolved: 1, pending: 0 });
    assert.equal(r.extras.burn.maxBurnRate, 16.2);
    assert.equal(r.extras.burn.errorRatio, 0.0162);
    assert.equal(r.extras.burn.signalId, burn.id);
    assert.deepEqual(r.extras.highCardinalityLabels, ['instance', 'node', 'pod', 'request_id', 'uid']);
    assert.deepEqual(r.extras.clusters, ['prod-eu-west']);
  });

  it('reads a bare array and the Alertmanager v2 API shape', () => {
    const arr = [{ labels: { alertname: 'CoreDNSDown', job: 'kube-dns', severity: 'critical' }, annotations: {}, startsAt: '2026-10-05T21:40:00Z', status: { state: 'active', silencedBy: [], inhibitedBy: [] } },
      { labels: { alertname: 'KubeHpaMaxedOut', horizontalpodautoscaler: 'orders-api', namespace: 'orders', severity: 'warning' }, annotations: {}, startsAt: '2026-10-05T21:41:00Z', status: { state: 'suppressed' } }];
    const r = WR.parseAlerts(JSON.stringify(arr), { cluster: 'prod-us-east' });
    assertSignalContract(r.signals, 'alerts');
    assert.equal(r.signals[0].kind, 'dns_failure');
    assert.equal(r.signals[0].componentId, 'infra:prod-us-east/kube-system/coredns');
    assert.equal(r.signals[1].kind, 'hpa_maxed');
    assert.equal(r.signals[1].componentId, 'service:prod-us-east/orders/orders-api');
    assert.equal(r.signals[1].attrs.silenced, true);
  });

  it('reads Prometheus /api/v1/alerts', () => {
    const prom = { status: 'success', data: { alerts: [
      { labels: { alertname: 'OrdersErrorBudgetBurn', service: 'orders-api', namespace: 'orders', severity: 'critical', k8s_cluster: 'prod-us-east' }, annotations: { summary: 'orders error budget burn' }, state: 'firing', activeAt: '2026-10-05T21:30:00.123Z', value: '1.62e+01' },
      { labels: { alertname: 'PostgresqlTooManyConnections', service: 'postgres-exporter', namespace: 'orders', severity: 'warning', k8s_cluster: 'prod-us-east' }, annotations: {}, state: 'pending', activeAt: '2026-10-05T21:31:00Z', value: '98' },
      { labels: { alertname: 'Watchdog', severity: 'none' }, annotations: {}, state: 'inactive', activeAt: null, value: '1' }
    ] } };
    const r = WR.parseAlerts(JSON.stringify(prom, null, 1), {});
    assertSignalContract(r.signals, 'alerts');
    assert.equal(r.stats.format, 'Prometheus alerts JSON');
    assert.equal(r.signals.length, 2, 'inactive alerts are not signals');
    assert.equal(r.signals[0].kind, 'slo_burn');
    assert.equal(r.signals[0].attrs.burnRate, 16.2, 'value field carries the burn rate');
    assert.equal(r.signals[0].ts, OCT5(21, 30, 0, 123));
    assert.equal(r.signals[0].componentId, 'service:prod-us-east/orders/orders-api');
    assert.equal(r.signals[1].kind, 'conn_exhaustion');
    assert.equal(r.signals[1].componentId, 'datastore:prod-us-east/orders/postgres', '"-exporter" reports on the datastore');
    assert.equal(r.signals[1].severity, 'info', 'pending is one notch quieter');
    assert.equal(r.extras.counts.pending, 1);
  });

  it('does not let a stray bracket line hide the alerts after it', () => {
    const r = WR.parseAlerts(['[pod/broken', '[context: prod-us-east]', '[FIRING:1] KubePodCrashLooping (orders-api critical)'].join('\n'), {});
    assert.equal(r.signals.length, 1);
    assert.equal(r.signals[0].componentId, 'service:prod-us-east/default/orders-api');
    assert.equal(r.stats.skipped, 1);
  });

  it('reads the three text formats from the spec', () => {
    const text = [
      '# cluster: prod-eu-west',
      '[FIRING:2] KubePodCrashLooping (payments-api prod-eu-west critical)',
      'ALERT KubePodCrashLooping{namespace="shop", pod="payments-api-7d9f8b6c5-x2k4p",severity="critical"} firing since 2026-10-05T21:49:30Z',
      '2026-10-05T21:49:30Z FIRING critical PaymentsHighErrorBurn service=payments-api cluster=prod-eu-west burn_rate=16.2',
      '2026-10-05 23:40:00 FIRING warning CoreDNSErrorsHigh job=kube-dns',
      '[RESOLVED] KubeNodeNotReady (ip-10-0-1-5 prod-eu-west warning)',
      'what is this line'
    ].join('\n');
    const r = WR.parseAlerts(text, { defaultTz: '+02:00' });
    assertSignalContract(r.signals, 'alerts');
    assert.equal(r.stats.format, 'alert text');
    assert.equal(r.stats.skipped, 1);
    const [slack, promql, stamped, coredns, resolved] = r.signals;
    assert.equal(slack.kind, 'crash_loop');
    assert.equal(slack.attrs.count, 2);
    assert.equal(slack.severity, 'critical');
    assert.equal(slack.componentId, 'service:prod-eu-west/default/payments-api');
    assert.equal(slack.ts, OCT5(21, 49, 30), 'no time in the line: "now" = latest stamp in the pane');
    assert.equal(slack.tsInferred, true);
    assert.equal(slack.line, 2);
    assert.equal(promql.kind, 'crash_loop');
    assert.equal(promql.componentId, 'service:prod-eu-west/shop/payments-api');
    assert.equal(promql.ts, OCT5(21, 49, 30));
    assert.equal(promql.tsInferred, false);
    assert.equal(stamped.kind, 'slo_burn');
    assert.equal(stamped.attrs.burnRate, 16.2);
    assert.equal(stamped.componentId, 'service:prod-eu-west/default/payments-api');
    assert.equal(coredns.kind, 'dns_failure');
    assert.equal(coredns.componentId, 'infra:prod-eu-west/kube-system/coredns');
    assert.equal(coredns.ts, OCT5(21, 40, 0), 'zone-less → +02:00');
    assert.equal(coredns.tsInferred, true);
    assert.equal(r.stats.tzAssumed, 1);
    assert.equal(resolved.kind, 'alert_resolved');
    assert.equal(resolved.raw, '[RESOLVED] KubeNodeNotReady (ip-10-0-1-5 prod-eu-west warning)');
  });

  it('maps alert names to kinds', () => {
    const k = WR.parseAlerts.alertKind;
    assert.equal(k('KubeContainerOOMKilled'), 'oom_killed');
    assert.equal(k('KubePodImagePullBackOff'), 'image_pull');
    assert.equal(k('KubeNodeMemoryPressure'), 'node_pressure');
    assert.equal(k('PaymentsSLOBreach'), 'slo_burn');
    assert.equal(k('SlowRequests'), 'alert_firing', 'Slow is not SLO');
    assert.equal(k('APIHighLatency'), 'span_slow');
    assert.equal(k('CertManagerCertificateExpiringSoon'), 'tls_error');
    assert.equal(k('IngressTLSHandshakeErrors'), 'tls_error');
    // Review fix: a Deployment replicas mismatch is not an autoscaler at max (it fires without any HPA).
    assert.equal(k('KubeDeploymentReplicasMismatch'), 'alert_firing');
    assert.equal(k('KubeHpaReplicasMismatch'), 'hpa_maxed');
    assert.equal(k('KubeHpaMaxedOut'), 'hpa_maxed');
    assert.equal(k('KubeContainerWaiting', { reason: 'ImagePullBackOff' }), 'image_pull');
    assert.equal(k('KubeContainerWaiting', { reason: 'CreateContainerConfigError' }), 'config_error');
    assert.equal(k('CPUThrottlingHigh'), 'throttled');
    assert.equal(k('TargetDown'), 'alert_firing');
  });

  it('never throws on junk or cut-off payloads', () => {
    const cut = JSON.stringify(WEBHOOK, null, 2);
    const r = WR.parseAlerts(cut.slice(0, Math.floor(cut.length * 0.4)), {});
    assert.ok(r.signals.length >= 1);
    assert.ok(r.stats.warnings.some((w) => /cut off/.test(w)));
    for (const junk of ['{"alerts":[{"labels":{"alertname":"X"', 'garbage', '{"data":{}}', '[]', null, '\u0000']) {
      let out;
      assert.doesNotThrow(() => { out = WR.parseAlerts(junk, {}); }, String(junk));
      assertStatsShape(out.stats);
    }
    assert.ok(WR.parseAlerts('garbage', {}).stats.warnings.some((w) => /No alerts found/.test(w)));
  });
});

// =============================================================================================
describe('parseHelm', () => {
  const DIFF = [
    '# cluster: prod-eu-west',
    '$ helm diff upgrade payments ./charts/payments -n shop --kube-context prod-eu-west',
    'shop, payments-api, Deployment (apps) has changed:',
    '  # Source: payments/templates/deployment.yaml',
    '  apiVersion: apps/v1',
    '  kind: Deployment',
    '  metadata:',
    '    name: payments-api',
    '    labels:',
    '      app.kubernetes.io/instance: payments',
    '-     helm.sh/chart: payments-1.8.2',
    '+     helm.sh/chart: payments-1.9.0',
    '-     app.kubernetes.io/version: "2.13.4"',
    '+     app.kubernetes.io/version: "2.14.0"',
    '  spec:',
    '    replicas: 3',
    '    template:',
    '      spec:',
    '        containers:',
    '          - name: payments-api',
    '-           image: "registry.example.com/payments-api:2.13.4"',
    '+           image: "registry.example.com/payments-api:2.14.0"',
    '            env:',
    '              - name: DB_HOST',
    '                value: postgres.shop.svc.cluster.local',
    '+             - name: CACHE_WARMUP_ON_START',
    '+               value: "true"',
    '-             - name: DB_PASSWORD',
    '-               value: "hunter2-old"',
    '+             - name: DB_PASSWORD',
    '+               value: "hunter2-new"',
    '-             - name: FEATURE_LEGACY_CHECKOUT',
    '-               value: "on"',
    '            readinessProbe:',
    '              httpGet:',
    '                path: /healthz',
    '-             timeoutSeconds: 5',
    '+             timeoutSeconds: 1',
    '            resources:',
    '              limits:',
    '-               memory: 512Mi',
    '+               memory: 256Mi',
    '                cpu: 500m',
    'shop, payments-db-migrate, Job (batch) has been added:',
    '+ # Source: payments/templates/migrate-job.yaml',
    '+ apiVersion: batch/v1',
    '+ kind: Job',
    '+ metadata:',
    '+   name: payments-db-migrate',
    '+   annotations:',
    '+     helm.sh/hook: pre-upgrade',
    '+     helm.sh/hook-weight: "-5"',
    '+ spec:',
    '+   template:',
    '+     spec:',
    '+       containers:',
    '+         - name: migrate',
    '+           image: registry.example.com/payments-migrate:2.14.0',
    'shop, payments-db, Secret (v1) has changed:',
    '  apiVersion: v1',
    '  kind: Secret',
    '  metadata:',
    '    name: payments-db',
    '  data:',
    '-   DB_PASSWORD: aHVudGVyMi1vbGQ=',
    '+   DB_PASSWORD: aHVudGVyMi1uZXc=',
    'shop, payments-api, HorizontalPodAutoscaler (autoscaling) has changed:',
    '  spec:',
    '    scaleTargetRef:',
    '      name: payments-api',
    '-   maxReplicas: 6',
    '+   maxReplicas: 20',
    'shop, payments-deny-egress, NetworkPolicy (networking.k8s.io) has been added:',
    '+ apiVersion: networking.k8s.io/v1',
    '+ kind: NetworkPolicy',
    '+ metadata:',
    '+   name: payments-deny-egress',
    '+ spec:',
    '+   podSelector:',
    '+     matchLabels:',
    '+       app: payments-api',
    ', paymentmethods.payments.example.com, CustomResourceDefinition (apiextensions.k8s.io) has been added:',
    '+ apiVersion: apiextensions.k8s.io/v1',
    '+ kind: CustomResourceDefinition',
    'shop, payments-config, ConfigMap (v1) has changed:',
    '  data:',
    '-   CACHE_TTL: "300"',
    '+   CACHE_TTL: "30"',
    'shop, payments-legacy-worker, Deployment (apps) has been removed:',
    '- apiVersion: apps/v1',
    '- kind: Deployment',
    '',
    '$ helm history payments -n shop --kube-context prod-eu-west',
    'REVISION  UPDATED                   STATUS      CHART           APP VERSION  DESCRIPTION',
    '40        Sat Oct  3 10:02:11 2026  superseded  payments-1.8.1  2.13.3       Upgrade complete',
    '41        Sun Oct  4 18:12:44 2026  superseded  payments-1.8.2  2.13.4       Upgrade complete',
    '42        Mon Oct  5 23:47:03 2026  deployed    payments-1.9.0  2.14.0       Upgrade complete'
  ].join('\n');

  const parsed = WR.parseHelm(DIFF, { defaultTz: '+02:00' });
  const changes = parsed.extras.changes;
  const byField = (re) => changes.filter((c) => re.test(c.field));
  const lineOf = (needle) => DIFF.split('\n').findIndex((l) => l.includes(needle)) + 1;
  const CID = 'service:prod-eu-west/shop/payments-api';

  it('meets the signal and stats contract', () => {
    assertSignalContract(parsed.signals, 'helm');
    assertStatsShape(parsed.stats);
    assert.equal(parsed.stats.skipped, 0);
    assert.equal(parsed.stats.format, 'helm diff + helm history');
    assert.ok(parsed.signals.every((s) => s.kind === 'change'));
  });

  it('tracks the YAML path so a memory limit cut is a high-risk resources change', () => {
    const [c] = byField(/resources\.limits\.memory$/);
    assert.equal(c.field, 'spec.template.spec.containers[payments-api].resources.limits.memory');
    assert.equal(c.category, 'resources');
    assert.equal(c.before, '512Mi');
    assert.equal(c.after, '256Mi');
    assert.equal(c.risk, 'high');
    assert.equal(c.summary, 'payments-api memory limit 512Mi → 256Mi');
    assert.equal(c.componentId, CID);
    assert.equal(c.release, 'payments');
    assert.equal(c.namespace, 'shop');
    assert.equal(c.resourceKind, 'Deployment');
    assert.equal(c.resourceName, 'payments-api');
    assert.equal(c.line, lineOf('+               memory: 256Mi'));
    assert.match(c.id, /^chg-/);
  });

  it('reports an image tag change as medium-risk "image"', () => {
    const [c] = byField(/containers\[payments-api\]\.image$/);
    assert.equal(c.category, 'image');
    assert.equal(c.risk, 'medium');
    assert.equal(c.before, 'registry.example.com/payments-api:2.13.4');
    assert.equal(c.after, 'registry.example.com/payments-api:2.14.0');
    assert.equal(c.summary, 'payments-api image tag 2.13.4 → 2.14.0');
  });

  it('collapses an added env var into one change and flags removals as high', () => {
    const [add] = byField(/env\[CACHE_WARMUP_ON_START\]$/);
    assert.equal(add.category, 'env');
    assert.equal(add.before, null);
    assert.equal(add.after, 'true');
    assert.equal(add.risk, 'medium');
    assert.equal(byField(/env\[CACHE_WARMUP_ON_START\]/).length, 1, 'name + value lines fold into one change');
    const [rem] = byField(/env\[FEATURE_LEGACY_CHECKOUT\]$/);
    assert.equal(rem.after, null);
    assert.equal(rem.risk, 'high');
  });

  it('never echoes secret values', () => {
    const [env] = byField(/env\[DB_PASSWORD\]$/);
    assert.equal(env.before, '(redacted)');
    assert.equal(env.after, '(redacted)');
    const [sec] = changes.filter((c) => c.resourceKind === 'Secret');
    assert.equal(sec.category, 'secret');
    assert.equal(sec.before, '(redacted)');
    assert.equal(sec.after, '(redacted)');
    assert.match(sec.summary, /value redacted/);
    const blob = JSON.stringify(parsed);
    for (const s of ['hunter2', 'aHVudGVy']) assert.ok(!blob.includes(s), `"${s}" must not appear in the parse result`);
  });

  it('detects the migration hook, NetworkPolicy, CRD, HPA max and probe tightening', () => {
    const hook = changes.find((c) => c.category === 'migration-hook');
    assert.equal(hook.resourceName, 'payments-db-migrate');
    assert.equal(hook.risk, 'high');
    assert.equal(hook.componentId, CID);
    assert.match(hook.summary, /pre-upgrade hook/);
    const np = changes.find((c) => c.category === 'networkpolicy');
    assert.equal(np.risk, 'high');
    assert.equal(np.componentId, CID, 'owner from podSelector app label');
    const crd = changes.find((c) => c.category === 'crd');
    assert.equal(crd.risk, 'high');
    assert.equal(crd.resourceName, 'paymentmethods.payments.example.com');
    const [hpa] = byField(/maxReplicas$/);
    assert.equal(hpa.category, 'hpa');
    assert.equal(hpa.risk, 'high');
    assert.equal(hpa.before, '6');
    assert.equal(hpa.after, '20');
    assert.equal(hpa.componentId, CID);
    const [probe] = byField(/readinessProbe\.timeoutSeconds$/);
    assert.equal(probe.category, 'probe');
    assert.equal(probe.risk, 'high');
    assert.match(probe.summary, /tighter/);
  });

  it('classifies config, removals and chart labels', () => {
    const [cm] = byField(/data\.CACHE_TTL$/);
    assert.equal(cm.category, 'configmap');
    assert.equal(cm.risk, 'medium');
    assert.equal(cm.componentId, CID, 'payments-config belongs to the release workload');
    const removed = changes.find((c) => c.resourceName === 'payments-legacy-worker');
    assert.equal(removed.changeType, 'resource-removed');
    assert.equal(removed.risk, 'high');
    const [chart] = byField(/helm\.sh\/chart$/);
    assert.equal(chart.category, 'chart');
    assert.equal(chart.risk, 'low');
    assert.equal(chart.summary, 'chart payments-1.8.2 → payments-1.9.0');
  });

  it('builds the deploy record from helm history (zone-less → defaultTz)', () => {
    const d = parsed.extras.deploy;
    assert.equal(d.release, 'payments');
    assert.equal(d.namespace, 'shop');
    assert.equal(d.revision, 42);
    assert.equal(d.previousRevision, 41);
    assert.equal(d.chartFrom, 'payments-1.8.2');
    assert.equal(d.chartTo, 'payments-1.9.0');
    assert.equal(d.appFrom, '2.13.4');
    assert.equal(d.appTo, '2.14.0');
    assert.equal(d.deployedAt, OCT5(21, 47, 3));
    assert.equal(d.deployedAtSource, 'helm-history');
    assert.equal(d.tsInferred, true);
    assert.equal(d.cluster, 'prod-eu-west');
    assert.equal(d.clusterKnown, true);
    assert.equal(d.componentId, CID);
    assert.equal(parsed.stats.tzAssumed, 3);
    assert.ok(parsed.stats.warnings.includes('Helm history times have no time zone; assumed +02:00.'));
    const deploySig = parsed.signals.find((s) => s.attrs.isDeploy);
    assert.equal(deploySig.ts, OCT5(21, 47, 3));
    assert.equal(deploySig.line, lineOf('42        Mon Oct'));
    // change signals hang off the deploy time
    const memSig = parsed.signals.find((s) => s.attrs.changeId === byField(/limits\.memory$/)[0].id);
    assert.equal(memSig.ts, OCT5(21, 47, 3));
    assert.equal(memSig.severity, 'warn');
  });

  it('reads a unified diff of values.yaml', () => {
    const text = [
      '$ helm diff upgrade payments ./charts/payments -n shop',
      'diff --git a/charts/payments/values.yaml b/charts/payments/values.yaml',
      'index 3f2a1b0..9c8d7e6 100644',
      '--- a/charts/payments/values.yaml',
      '+++ b/charts/payments/values.yaml',
      '@@ -10,14 +10,14 @@ image:',
      ' image:',
      '   repository: registry.example.com/payments-api',
      '-  tag: 2.13.4',
      '+  tag: 2.14.0',
      ' resources:',
      '   limits:',
      '-    memory: 512Mi',
      '+    memory: 256Mi',
      '@@ -40,6 +40,7 @@ env:',
      ' env:',
      '-  DB_PASSWORD: s3cret-old',
      '+  DB_PASSWORD: s3cret-new',
      '+  CACHE_WARMUP_ON_START: "true"',
      ' autoscaling:',
      '-  maxReplicas: 6',
      '+  maxReplicas: 20',
      '\\ No newline at end of file'
    ].join('\n');
    const r = WR.parseHelm(text, {});
    assertSignalContract(r.signals, 'helm');
    assert.equal(r.stats.format, 'unified diff');
    assert.equal(r.stats.skipped, 0);
    const f = Object.fromEntries(r.extras.changes.map((c) => [c.field, c]));
    assert.equal(f['image.tag'].category, 'image');
    assert.equal(f['image.tag'].before, '2.13.4');
    assert.equal(f['image.tag'].summary, 'image tag 2.13.4 → 2.14.0');
    assert.equal(f['resources.limits.memory'].category, 'resources');
    assert.equal(f['resources.limits.memory'].risk, 'high');
    assert.equal(f['env.DB_PASSWORD'].before, '(redacted)');
    assert.equal(f['env.CACHE_WARMUP_ON_START'].category, 'env');
    assert.equal(f['autoscaling.maxReplicas'].category, 'hpa');
    assert.equal(f['autoscaling.maxReplicas'].risk, 'high');
    assert.ok(r.extras.changes.every((c) => c.release === 'payments' && c.resourceKind === 'values'));
    assert.ok(!JSON.stringify(r).includes('s3cret'));
    assert.ok(r.stats.warnings.some((w) => /No deploy time found/.test(w)));
  });

  it('takes the release name from the chart when no command echo is pasted', () => {
    const text = [
      'REVISION\tUPDATED                 \tSTATUS    \tCHART        \tAPP VERSION\tDESCRIPTION',
      '7       \tMon Oct  5 20:01:00 2026\tsuperseded\torders-3.2.0 \t5.1.0      \tUpgrade complete',
      '8       \tMon Oct  5 21:10:00 2026\tfailed    \torders-3.3.0 \t5.2.0      \tUpgrade "orders" failed: timed out waiting for the condition'
    ].join('\n');
    const r = WR.parseHelm(text, {});
    const d = r.extras.deploy;
    assert.equal(d.release, 'orders');
    assert.equal(d.revision, 8);
    assert.equal(d.previousRevision, 7);
    assert.equal(d.status, 'failed');
    assert.equal(d.deployedAt, OCT5(21, 10, 0));
    assert.equal(r.signals[0].severity, 'error', 'a failed upgrade is an error signal');
    assert.equal(d.clusterKnown, false);
    // With only the history pasted, the release name stands in for its workload until reconcile.
    const guess = r.entities.find((e) => e.id === d.componentId);
    assert.equal(guess.releaseGuess, true);
    const rec = E.reconcile([...r.entities, E.hint({ pod: 'orders-api-6c9d8f7b5-k2m4n', namespace: 'default' })]);
    assert.equal(rec.alias[d.componentId], 'service:cluster-1/default/orders-api');
  });

  it('reads helm list with zoned UPDATED times', () => {
    const text = [
      'NAME             NAMESPACE   REVISION   UPDATED                                   STATUS     CHART                   APP VERSION',
      'payments         shop        42         2026-10-05 23:47:03.123456 +0200 CEST     deployed   payments-1.9.0          2.14.0',
      'recommendations  shop        17         2026-10-05 18:47:03.5 +0000 UTC           deployed   recommendations-0.4.1   0.4.1'
    ].join('\n');
    const r = WR.parseHelm(text, {});
    assert.equal(r.stats.tzAssumed, 0);
    const d = r.extras.deploy;
    assert.equal(d.release, 'payments', 'most recent deploy first');
    assert.equal(d.deployedAt, OCT5(21, 47, 3, 123));
    assert.equal(d.deployedAtSource, 'helm-list');
    assert.equal(d.tsInferred, false);
    assert.equal(d.previousRevision, 41);
    assert.equal(d.previousRevisionAssumed, true);
    assert.equal(r.extras.deploys.length, 2);
    assert.equal(r.extras.deploys[1].deployedAt, OCT5(18, 47, 3, 500));
  });

  it('honours a manual "Deployed at" from the context form', () => {
    const r = WR.parseHelm(DIFF, { defaultTz: '+02:00', deployedAt: '2026-10-05T21:45:00Z' });
    assert.equal(r.extras.deploy.deployedAt, OCT5(21, 45, 0));
    assert.equal(r.extras.deploy.deployedAtSource, 'manual');
  });

  it('keeps a kube-system ConfigMap on CoreDNS and rates it high', () => {
    const text = [
      'kube-system, coredns, ConfigMap (v1) has changed:',
      '  data:',
      '    Corefile: |',
      '      .:53 {',
      '-         forward . /etc/resolv.conf',
      '+         forward . 10.0.0.53',
      '-         cache 30',
      '+         cache 0',
      '      }'
    ].join('\n');
    const r = WR.parseHelm(text, { cluster: 'prod-eu-west' });
    assert.equal(r.extras.changes.length, 1, 'all lines of one block scalar form one change');
    const c = r.extras.changes[0];
    assert.equal(c.field, 'data.Corefile');
    assert.equal(c.componentId, 'infra:prod-eu-west/kube-system/coredns');
    assert.equal(c.category, 'configmap');
    assert.equal(c.risk, 'high');
    assert.equal(c.before, 'forward . /etc/resolv.conf\ncache 30');
    assert.equal(c.after, 'forward . 10.0.0.53\ncache 0');
  });

  it('walks YAML lists at the same indent as their key', () => {
    const recs = WR.parseHelm._walkYaml([
      { marker: ' ', text: 'containers:', line: 1 },
      { marker: ' ', text: '- name: api', line: 2 },
      { marker: '-', text: '  image: a:1', line: 3 },
      { marker: '+', text: '  image: a:2', line: 4 },
      { marker: ' ', text: '- name: sidecar', line: 5 },
      { marker: ' ', text: '  image: s:1', line: 6 }
    ]);
    assert.deepEqual(recs.filter((r) => r.key === 'image').map((r) => r.path), ['containers[api].image', 'containers[api].image', 'containers[sidecar].image']);
  });

  it('never throws on junk', () => {
    for (const junk of ['nothing helm-like here', 'shop, x, Deployment (apps) has changed:\n+\n-\n+ : :', 'REVISION  UPDATED  STATUS  CHART  APP VERSION  DESCRIPTION\nnot a row', '@@ -1 +1 @@\n-a\n+b', null, '']) {
      let r;
      assert.doesNotThrow(() => { r = WR.parseHelm(junk, {}); }, String(junk));
      assertStatsShape(r.stats);
    }
    assert.ok(WR.parseHelm('nothing helm-like here', {}).stats.warnings.some((w) => /No Helm output found/.test(w)));
  });
});
