// Real-world paste variants for every parser, checked against the formats the tools actually print:
//   - kubectl get events (pkg/printers/internalversion printEvent: lowercase kind/name, -o wide adds
//     SUBOBJECT/SOURCE/FIRST SEEN/COUNT/NAME) and the newer `kubectl events` (kubectl
//     pkg/cmd/events/event_printer.go: Kind/name and "3m (x4 over 5m)" in LAST SEEN)
//   - helm-diff (databus23/helm-diff diff/report.go, diff/diff.go, manifest/parse.go): headers
//     "<ns>, <name>, <Kind> (<group>) has changed: | has been added: | has been removed: |
//     changed ownership: | has changed, but diff is empty after suppression.", "--output simple"
//     lines "... to be changed.", and "..." gap lines with --context N
//   - Alertmanager webhook payloads (groupLabels / commonLabels / commonAnnotations), the default
//     notification subject "[FIRING:n] <group values> (<common values>)" and its "Labels: - k = v"
//     body (template/default.tmpl), amtool simple and extended tables (cli/format)
//   - OTLP JSON (trace ids hex, enums as integers, 64-bit integers as strings or numbers), the
//     collector file exporter's one-request-per-line output, Tempo's {trace:{...}} wrapper, Jaeger
//     "Download JSON" with several traces
// plus terminal debris: CRLF and lone-CR line endings, tabs, ANSI colour codes, Windows paths and
// very long lines.
import test from 'node:test';
import assert from 'node:assert/strict';
import load from './load.mjs';

const WR = load || globalThis.WR;
const NOW = Date.parse('2026-10-05T22:00:00Z');
const ctx = { now: NOW, defaultTz: 'Z', year: 2026 };
const MIN = 60000;
const ESC = '\x1b';
const red = (s) => `${ESC}[31m${s}${ESC}[0m`;
const green = (s) => `${ESC}[32m${s}${ESC}[0m`;
const yellow = (s) => `${ESC}[33m${s}${ESC}[0m`;

// ------------------------------------------------------------------------------------------------
// Logs
// ------------------------------------------------------------------------------------------------
test('logs: `kubectl events` rows with "(x4 over 5m)" keep their object and take the onset time', () => {
  const text = [
    'LAST SEEN               TYPE      REASON      OBJECT                               MESSAGE',
    '3m (x4 over 5m)         Warning   Unhealthy   Pod/payments-api-7d9f8b6c5-x2k4p     Readiness probe failed: HTTP probe failed with statuscode: 503',
    '12s                     Warning   BackOff     Pod/payments-api-7d9f8b6c5-x2k4p     Back-off restarting failed container payments-api in pod payments-api-7d9f8b6c5-x2k4p_shop(abc)',
    '2m10s (x12 over 9m)     Warning   BackOff     Pod/payments-api-7d9f8b6c5-x2k4p     Back-off restarting failed container payments-api in pod payments-api-7d9f8b6c5-x2k4p_shop(abc)'
  ].join('\n');
  const r = WR.parseLogs(text, ctx);
  assert.equal(r.signals.length, 3);
  for (const s of r.signals) assert.equal(s.componentId, 'service:cluster-1/default/payments-api', s.id);
  const probe = r.signals.find((s) => s.kind === 'probe_failed');
  assert.ok(probe, 'probe_failed signal');
  assert.equal(probe.ts, NOW - 5 * MIN, 'onset = the "over" age');
  assert.equal(probe.attrs.count, 4);
  assert.equal(r.signals[2].ts, NOW - 9 * MIN);
  assert.equal(r.stats.format, 'kubectl events');
});

test('logs: `kubectl events -A` with a NAMESPACE column and the (xN over M) interval', () => {
  const text = [
    'NAMESPACE   LAST SEEN            TYPE      REASON     OBJECT                              MESSAGE',
    'shop        2m (x7 over 11m)     Warning   BackOff    Pod/payments-api-7d9f8b6c5-x2k4p    Back-off restarting failed container payments-api',
    'shop        30s                  Normal    Pulled     Pod/payments-api-7d9f8b6c5-x2k4p    Container image "registry.example.com/payments:2.14.0" already present on machine'
  ].join('\n');
  const r = WR.parseLogs(text, ctx);
  assert.equal(r.signals.length, 1);
  assert.equal(r.signals[0].componentId, 'service:cluster-1/shop/payments-api');
  assert.equal(r.signals[0].kind, 'crash_loop');
  assert.equal(r.signals[0].ts, NOW - 11 * MIN);
});

test('logs: event rows pasted without a header still read the (xN over M) interval', () => {
  const r = WR.parseLogs('5m (x3 over 20m)   Warning   FailedScheduling   Pod/orders-api-6d8f7b9c54-zz9qk   0/12 nodes are available: 12 Insufficient cpu.\n', ctx);
  assert.equal(r.signals.length, 1);
  assert.equal(r.signals[0].kind, 'scheduling_failed');
  assert.equal(r.signals[0].componentId, 'service:cluster-1/default/orders-api');
  assert.equal(r.signals[0].ts, NOW - 20 * MIN);
});

test('logs: `kubectl get events -o json` (core/v1) and events.k8s.io/v1 documents', () => {
  const core = { apiVersion: 'v1', kind: 'List', items: [
    { apiVersion: 'v1', kind: 'Event', metadata: { name: 'payments-api-7d9f8b6c5-x2k4p.17f', namespace: 'shop' },
      involvedObject: { kind: 'Pod', name: 'payments-api-7d9f8b6c5-x2k4p', namespace: 'shop', fieldPath: 'spec.containers{payments-api}' },
      reason: 'BackOff', message: 'Back-off restarting failed container payments-api in pod payments-api-7d9f8b6c5-x2k4p_shop(abc)',
      source: { component: 'kubelet', host: 'ip-10-0-1-12' }, firstTimestamp: '2026-10-05T21:50:10Z', lastTimestamp: '2026-10-05T21:58:40Z', count: 12, type: 'Warning' },
    { apiVersion: 'v1', kind: 'Event', metadata: { name: 'x.18a', namespace: 'shop' }, involvedObject: { kind: 'Pod', name: 'payments-api-7d9f8b6c5-x2k4p', namespace: 'shop' },
      reason: 'Pulled', message: 'Container image already present on machine', firstTimestamp: '2026-10-05T21:50:00Z', lastTimestamp: '2026-10-05T21:58:30Z', count: 9, type: 'Normal' }
  ] };
  const text = '$ kubectl --context prod-eu-west get events -n shop -o json\n' + JSON.stringify(core, null, 2) + '\n2026-10-05T21:59:00Z ERROR after the document\n';
  const r = WR.parseLogs(text, ctx);
  assert.equal(r.stats.skipped, 0, r.stats.warnings.join(' | '));
  const back = r.signals.find((s) => s.kind === 'crash_loop');
  assert.ok(back);
  assert.equal(back.componentId, 'service:prod-eu-west/shop/payments-api');
  assert.equal(back.ts, Date.parse('2026-10-05T21:50:10Z'), 'onset = firstTimestamp');
  assert.equal(back.tsInferred, false);
  assert.equal(back.attrs.count, 12);
  assert.match(text.split('\n')[back.line - 1], /"message"/);
  assert.ok(r.signals.some((s) => s.kind === 'error_generic' && /after the document/.test(s.text)), 'lines after the document are still read');

  const v1 = { apiVersion: 'events.k8s.io/v1', kind: 'EventList', items: [
    { apiVersion: 'events.k8s.io/v1', kind: 'Event', metadata: { name: 'y', namespace: 'orders' }, regarding: { kind: 'Pod', name: 'orders-api-6d8f7b9c54-zz9qk', namespace: 'orders' },
      reason: 'FailedScheduling', note: '0/12 nodes are available: 12 Insufficient cpu.', type: 'Warning', eventTime: '2026-10-05T21:40:00.000000Z',
      series: { count: 5, lastObservedTime: '2026-10-05T21:55:00.000000Z' }, reportingController: 'default-scheduler' }
  ] };
  const s = WR.parseLogs(JSON.stringify(v1, null, 2), ctx);
  assert.equal(s.signals.length, 1);
  assert.equal(s.signals[0].kind, 'scheduling_failed');
  assert.equal(s.signals[0].componentId, 'service:cluster-1/orders/orders-api');
  assert.equal(s.signals[0].ts, Date.parse('2026-10-05T21:40:00Z'));
  assert.equal(s.signals[0].attrs.count, 5);
});

test('logs: CRLF line endings and ANSI colour in a kubectl table', () => {
  const text = 'LAST SEEN   TYPE      REASON      OBJECT                               MESSAGE\r\n' +
    yellow('45s') + '         Warning   BackOff     pod/payments-api-7d9f8b6c5-x2k4p     Back-off restarting failed container payments-api in pod payments-api-7d9f8b6c5-x2k4p_shop(1234)\r\n' +
    '2m10s       Normal    Pulled      pod/payments-api-7d9f8b6c5-x2k4p     Container image "registry.example.com/payments:2.14.0" already present on machine\r\n';
  const r = WR.parseLogs(text, ctx);
  assert.equal(r.signals.length, 1);
  assert.equal(r.signals[0].kind, 'crash_loop');
  assert.equal(r.signals[0].componentId, 'service:cluster-1/default/payments-api');
  assert.equal(r.signals[0].ts, NOW - 45000);
  assert.ok(!/\x1b|\r/.test(r.signals[0].text), 'no escape codes or CR in the text');
});

test('logs: lone CR (old Mac / some Windows terminals) separates lines', () => {
  const r = WR.parseLogs('2026-10-05T21:55:00Z ERROR dial tcp 10.0.3.4:5432: connect: connection refused\r2026-10-05T21:55:01Z ERROR dial tcp 10.0.3.4:5432: connect: connection refused\r', ctx);
  assert.equal(r.stats.lines, 2);
  assert.deepEqual(r.signals.map((s) => s.line), [1, 2]);
  assert.ok(r.signals.every((s) => s.kind === 'conn_refused'));
});

test('logs: tab-separated pod table and colourised stern output', () => {
  const pods = WR.parseLogs('NAME\tREADY\tSTATUS\tRESTARTS\tAGE\npayments-api-7d9f8b6c5-x2k4p\t0/1\tCrashLoopBackOff\t5 (30s ago)\t10m\n', ctx);
  assert.equal(pods.signals.length, 1);
  assert.equal(pods.signals[0].kind, 'crash_loop');
  const stern = WR.parseLogs(green('payments-api-7d9f8b6c5-x2k4p') + ' ' + yellow('payments-api') + ' {"ts":"2026-10-05T21:55:00Z","level":"error","msg":"dial tcp 10.0.3.4:5432: connect: connection refused"}\n', ctx);
  assert.equal(stern.signals.length, 1);
  assert.equal(stern.signals[0].componentId, 'service:cluster-1/default/payments-api');
  assert.equal(stern.signals[0].ts, Date.parse('2026-10-05T21:55:00Z'));
});

test('logs: Windows paths and very long lines do not break the reader', () => {
  const win = WR.parseLogs('2026-10-05T21:55:00Z ERROR C:\\Program Files\\payments\\server.exe could not open C:\\data\\config.json: access is denied\n', ctx);
  assert.equal(win.signals.length, 1);
  assert.equal(win.signals[0].ts, Date.parse('2026-10-05T21:55:00Z'));
  const long = '{"ts":"2026-10-05T21:55:00Z","level":"error","service":"orders-api","msg":"' + 'x'.repeat(250000) + ' connection refused"}\n';
  const t0 = performance.now();
  const r = WR.parseLogs(long, ctx);
  assert.ok(performance.now() - t0 < 500, 'a 250 KB line parses quickly');
  assert.equal(r.signals.length, 1);
  assert.equal(r.signals[0].kind, 'conn_refused');
  assert.ok(r.signals[0].text.length <= 400 && r.signals[0].raw.length <= 2000, 'text and raw are truncated');
});

// ------------------------------------------------------------------------------------------------
// Helm
// ------------------------------------------------------------------------------------------------
const HELM_CTX = { now: NOW, defaultTz: '+02:00', year: 2026 };

test('helm: `helm diff --context 3` gap lines ("...") keep the changes around them', () => {
  const text = [
    'shop, payments-api, Deployment (apps) has changed:',
    '...',
    '          resources:',
    '            limits:',
    '-             memory: 512Mi',
    '+             memory: 256Mi',
    '              cpu: 500m',
    '...',
    '            - name: PAYMENTS_CACHE_WARMUP',
    '-             value: "false"',
    '+             value: "true"',
    '...'
  ].join('\n');
  const r = WR.parseHelm(text, HELM_CTX);
  assert.equal(r.stats.skipped, 0, JSON.stringify(r.stats.warnings));
  const mem = r.extras.changes.find((c) => /limits\.memory$/.test(c.field || ''));
  assert.ok(mem, 'memory limit change found');
  assert.equal(mem.category, 'resources');
  assert.equal(mem.risk, 'high');
  assert.equal(mem.before, '512Mi');
  assert.equal(mem.after, '256Mi');
  assert.equal(mem.componentId, 'service:cluster-1/shop/payments-api');
  const env = r.extras.changes.find((c) => /PAYMENTS_CACHE_WARMUP/.test(c.field || ''));
  assert.ok(env, 'env change found');
  assert.equal(env.category, 'env');
  assert.equal(env.before, 'false');
  assert.equal(env.after, 'true');
});

test('helm: colourised diff with CRLF line endings', () => {
  const text = yellow('shop, payments-api, Deployment (apps) has changed:') + '\r\n' +
    '  # Source: payments/templates/deployment.yaml\r\n  spec:\r\n    template:\r\n      spec:\r\n        containers:\r\n        - name: payments-api\r\n' +
    red('-         image: registry.example.com/payments:2.13.4') + '\r\n' + green('+         image: registry.example.com/payments:2.14.0') + '\r\n';
  const r = WR.parseHelm(text, HELM_CTX);
  assert.equal(r.extras.changes.length, 1);
  const c = r.extras.changes[0];
  assert.equal(c.category, 'image');
  assert.equal(c.field, 'spec.template.spec.containers[payments-api].image');
  assert.equal(c.summary, 'payments-api image tag 2.13.4 → 2.14.0');
});

test('helm: colourised unified diff (git diff --color) of values.yaml', () => {
  const text = [
    `${ESC}[1mdiff --git a/charts/payments/values.yaml b/charts/payments/values.yaml${ESC}[m`,
    `${ESC}[1mindex 3f2a1b4..9c8d7e6 100644${ESC}[m`,
    `${ESC}[1m--- a/charts/payments/values.yaml${ESC}[m`,
    `${ESC}[1m+++ b/charts/payments/values.yaml${ESC}[m`,
    `${ESC}[36m@@ -12,7 +12,7 @@${ESC}[m resources:`,
    ' resources:',
    '   limits:',
    red('-    memory: 512Mi'),
    green('+    memory: 256Mi')
  ].join('\n');
  const r = WR.parseHelm(text, HELM_CTX);
  assert.equal(r.stats.skipped, 0, JSON.stringify(r.stats.warnings));
  const mem = r.extras.changes.find((c) => /limits\.memory$/.test(c.field || ''));
  assert.ok(mem, 'memory change found');
  assert.equal(mem.risk, 'high');
});

test('helm: GNU `diff -u` on Windows (backslash paths, tab + timestamp after the name, CRLF)', () => {
  const text = '--- C:\\work\\charts\\payments\\values.yaml\t2026-10-05 21:00:00.000000000 +0200\r\n' +
    '+++ C:\\work\\charts\\payments\\values.yaml\t2026-10-05 21:05:00.000000000 +0200\r\n' +
    '@@ -10,4 +10,4 @@\r\n resources:\r\n   limits:\r\n-    memory: 512Mi\r\n+    memory: 256Mi\r\n';
  const r = WR.parseHelm(text, HELM_CTX);
  assert.equal(r.stats.skipped, 0);
  const c = r.extras.changes[0];
  assert.equal(c.field, 'resources.limits.memory');
  assert.equal(c.release, 'payments', 'release read from charts\\payments\\');
  assert.equal(c.resourceName, 'values.yaml');
  assert.equal(c.risk, 'high');
});

test('helm: "changed ownership:" and "diff is empty after suppression" headers are recognised', () => {
  const text = [
    'shop, payments-api, Deployment (apps) changed ownership:',
    'shop, payments-config, ConfigMap (v1) has changed, but diff is empty after suppression.',
    'shop, payments-api, Service (v1) has changed:',
    '  spec:',
    '    ports:',
    '    - name: http',
    '-     targetPort: 8080',
    '+     targetPort: 8081'
  ].join('\n');
  const r = WR.parseHelm(text, HELM_CTX);
  assert.equal(r.stats.skipped, 0, JSON.stringify(r.stats.warnings));
  const port = r.extras.changes.find((c) => /targetPort$/.test(c.field || ''));
  assert.ok(port);
  assert.equal(port.category, 'service');
  assert.equal(port.risk, 'high');
});

test('helm: `helm diff upgrade --output simple` lists the resources that change', () => {
  const text = [
    'shop, payments-api, Deployment (apps) to be changed.',
    'shop, payments-api, HorizontalPodAutoscaler (autoscaling) to be changed.',
    'shop, payments-pdb, PodDisruptionBudget (policy) to be added.',
    'shop, payments-legacy, ConfigMap (v1) to be removed.',
    'Plan: 1 to add, 2 to change, 1 to destroy, 0 to change ownership.'
  ].join('\n');
  const r = WR.parseHelm(text, HELM_CTX);
  assert.equal(r.stats.skipped, 0, JSON.stringify(r.stats.warnings));
  assert.match(r.stats.format, /helm diff/);
  assert.equal(r.extras.changes.length, 4);
  const hpa = r.extras.changes.find((c) => c.resourceKind === 'HorizontalPodAutoscaler');
  assert.equal(hpa.category, 'hpa');
  assert.equal(hpa.componentId, 'service:cluster-1/shop/payments-api');
  const removed = r.extras.changes.find((c) => c.resourceKind === 'ConfigMap');
  assert.equal(removed.after, null);
  assert.equal(removed.category, 'configmap');
  for (const c of r.extras.changes) assert.ok(typeof c.summary === 'string' && c.summary.length > 0);
});

test('helm: whole resources added with "+ " (pre-upgrade migration Job) and removed with "- "', () => {
  const text = [
    'shop, payments-migrate, Job (batch) has been added:',
    '- ',
    '+ # Source: payments/templates/migrate-job.yaml',
    '+ apiVersion: batch/v1',
    '+ kind: Job',
    '+ metadata:',
    '+   name: payments-migrate',
    '+   annotations:',
    '+     "helm.sh/hook": pre-upgrade',
    '+ spec:',
    '+   template:',
    '+     spec:',
    '+       containers:',
    '+       - name: migrate',
    '+         image: registry.example.com/payments-migrate:2.14.0',
    'shop, payments-config, ConfigMap (v1) has been removed:',
    '- # Source: payments/templates/cm.yaml',
    '- apiVersion: v1',
    '- kind: ConfigMap',
    '- metadata:',
    '-   name: payments-config',
    '- data:',
    '-   LOG_LEVEL: info',
    '+ '
  ].join('\n');
  const r = WR.parseHelm(text, HELM_CTX);
  assert.equal(r.stats.skipped, 0);
  const mig = r.extras.changes.find((c) => c.resourceKind === 'Job');
  assert.equal(mig.category, 'migration-hook');
  assert.equal(mig.risk, 'high');
  const cm = r.extras.changes.find((c) => c.resourceKind === 'ConfigMap');
  assert.equal(cm.after, null);
});

test('helm: a changed list item is summarised once, not twice', () => {
  const text = [
    ', widgets.example.com, CustomResourceDefinition (apiextensions.k8s.io) has changed:',
    '  spec:',
    '    versions:',
    '-   - name: v1beta1',
    '+   - name: v1'
  ].join('\n');
  const r = WR.parseHelm(text, HELM_CTX);
  const vals = r.extras.changes.flatMap((c) => [c.before, c.after]).filter((v) => v != null);
  for (const v of vals) assert.ok(!/name: (\S+), name: \1/.test(v), 'duplicated value: ' + v);
  assert.ok(r.extras.changes.every((c) => c.category === 'crd' && c.risk === 'high'));
});

test('helm: `helm history -o json` and `helm list -o json`', () => {
  const hist = '$ helm history payments -n shop -o json\n' + JSON.stringify([
    { revision: 41, updated: '2026-10-04T10:12:44.123456+02:00', status: 'superseded', chart: 'payments-1.8.2', app_version: '2.13.4', description: 'Upgrade complete' },
    { revision: 42, updated: '2026-10-05T23:47:03.5+02:00', status: 'deployed', chart: 'payments-1.9.0', app_version: '2.14.0', description: 'Upgrade complete' }
  ]);
  const r = WR.parseHelm(hist, HELM_CTX);
  assert.equal(r.stats.skipped, 0, JSON.stringify(r.stats.warnings));
  assert.match(r.stats.format, /helm history/);
  const d = r.extras.deploy;
  assert.ok(d);
  assert.equal(d.release, 'payments');
  assert.equal(d.namespace, 'shop');
  assert.equal(d.revision, 42);
  assert.equal(d.previousRevision, 41);
  assert.equal(d.deployedAt, Date.parse('2026-10-05T21:47:03.5Z'));
  assert.equal(d.tsInferred, false, 'the JSON time carries its zone');
  assert.equal(d.chartFrom, 'payments-1.8.2');

  const list = JSON.stringify([{ name: 'payments', namespace: 'shop', revision: '42', updated: '2026-10-05 23:47:03.123456 +0200 CEST', status: 'deployed', chart: 'payments-1.9.0', app_version: '2.14.0' }]);
  const l = WR.parseHelm(list, HELM_CTX);
  assert.equal(l.extras.deploy.revision, 42);
  assert.equal(l.extras.deploy.deployedAt, Date.parse('2026-10-05T21:47:03.123Z'));
  assert.equal(l.extras.deploy.deployedAtSource, 'helm-list');
});

test('helm: helm history with tabs and CRLF (helm prints tab-joined, padded cells)', () => {
  const text = 'REVISION\tUPDATED                 \tSTATUS    \tCHART         \tAPP VERSION\tDESCRIPTION     \r\n' +
    '41      \tSun Oct  4 10:12:44 2026\tsuperseded\tpayments-1.8.2\t2.13.4     \tUpgrade complete\r\n' +
    '42      \tMon Oct  5 23:47:03 2026\tdeployed  \tpayments-1.9.0\t2.14.0     \tUpgrade complete\r\n';
  const d = WR.parseHelm(text, HELM_CTX).extras.deploy;
  assert.equal(d.revision, 42);
  assert.equal(d.previousRevision, 41);
  assert.equal(d.deployedAt, Date.parse('2026-10-05T21:47:03Z'));
});

const HISTORY_AFTER_ROLLBACK = [
  '$ helm history payments -n shop --kube-context prod-eu-west',
  'REVISION\tUPDATED                 \tSTATUS    \tCHART         \tAPP VERSION\tDESCRIPTION     ',
  '40      \tThu Sep 24 11:02:37 2026\tsuperseded\tpayments-1.7.4\t2.12.1     \tRollback to 38  ',
  '41      \tWed Sep 30 16:20:09 2026\tsuperseded\tpayments-1.8.2\t2.13.4     \tUpgrade complete',
  '42      \tMon Oct  5 23:47:03 2026\tsuperseded\tpayments-1.9.0\t2.14.0     \tUpgrade complete',
  '43      \tMon Oct  5 23:58:30 2026\tdeployed  \tpayments-1.8.2\t2.13.4     \tRollback to 41  '
].join('\n');

test('helm: when the latest revision is a rollback, the suspect deploy is the upgrade it undid', () => {
  const r = WR.parseHelm(HISTORY_AFTER_ROLLBACK, HELM_CTX);
  const d = r.extras.deploy;
  assert.equal(d.revision, 42, 'the upgrade that introduced the changes');
  assert.equal(d.previousRevision, 41);
  assert.equal(d.deployedAt, Date.parse('2026-10-05T21:47:03Z'));
  assert.ok(d.rolledBack, 'rollback recorded');
  assert.equal(d.rolledBack.revision, 43);
  assert.equal(d.rolledBack.to, 41);
  assert.equal(d.rolledBack.at, Date.parse('2026-10-05T21:58:30Z'));
  assert.ok(r.stats.warnings.some((w) => /already rolled back/i.test(w)), r.stats.warnings.join(' | '));
});

test('helm: a pending-upgrade latest revision is not used as the rollback target', () => {
  const text = [
    'REVISION\tUPDATED                 \tSTATUS         \tCHART         \tAPP VERSION\tDESCRIPTION',
    '41      \tWed Sep 30 16:20:09 2026\tdeployed       \tpayments-1.8.2\t2.13.4     \tUpgrade complete',
    '42      \tMon Oct  5 23:47:03 2026\tpending-upgrade\tpayments-1.9.0\t2.14.0     \tPreparing upgrade'
  ].join('\n');
  const d = WR.parseHelm(text, HELM_CTX).extras.deploy;
  assert.equal(d.revision, 42);
  assert.equal(d.previousRevision, 41);
  assert.equal(d.status, 'pending-upgrade');
});

// ------------------------------------------------------------------------------------------------
// Traces
// ------------------------------------------------------------------------------------------------
const ns = (iso) => String(BigInt(Date.parse(iso)) * 1000000n);
function otlpReq(svc, cluster, spans) {
  return { resourceSpans: [{ resource: { attributes: [
    { key: 'service.name', value: { stringValue: svc } }, { key: 'k8s.cluster.name', value: { stringValue: cluster } }, { key: 'k8s.namespace.name', value: { stringValue: 'shop' } }
  ] }, scopeSpans: [{ scope: { name: 'io.opentelemetry.http' }, spans }] }] };
}
const TID = '4bf92f3577b34da6a3ce929d0e0e4736';
const ROOT = { traceId: TID, spanId: '00f067aa0ba902b7', name: 'GET /checkout', kind: 2, startTimeUnixNano: ns('2026-10-05T21:52:10Z'), endTimeUnixNano: ns('2026-10-05T21:52:12Z'),
  attributes: [{ key: 'http.response.status_code', value: { intValue: '502' } }], status: { code: 2, message: 'upstream 502' } };
const CHILD = { traceId: TID, spanId: '00f067aa0ba902b8', parentSpanId: '00f067aa0ba902b7', name: 'POST /pay', kind: 3, startTimeUnixNano: ns('2026-10-05T21:52:10.1Z'), endTimeUnixNano: ns('2026-10-05T21:52:11.9Z'),
  attributes: [{ key: 'peer.service', value: { stringValue: 'payments-api' } }, { key: 'http.response.status_code', value: { intValue: 503 } }], status: { code: 2 } };

test('traces: OTLP JSON lines (collector file exporter: one request per line)', () => {
  const text = JSON.stringify(otlpReq('checkout-api', 'prod-eu-west', [ROOT])) + '\n' + JSON.stringify(otlpReq('checkout-api', 'prod-eu-west', [CHILD])) + '\n';
  const r = WR.parseTraces(text, ctx);
  assert.equal(r.extras.traceStats.spans, 2);
  assert.equal(r.extras.traceStats.traces, 1);
  assert.deepEqual(r.signals.map((s) => s.line), [1, 2]);
  assert.equal(r.signals[0].attrs.httpStatus, 502, 'intValue as a string');
  assert.equal(r.signals[1].attrs.httpStatus, 503, 'intValue as a number');
});

test('traces: pretty-printed OTLP with CRLF points each span at its own line', () => {
  const text = JSON.stringify(otlpReq('checkout-api', 'prod-eu-west', [ROOT, CHILD]), null, 2).replace(/\n/g, '\r\n');
  const r = WR.parseTraces(text, ctx);
  const lines = text.split('\r\n');
  for (const s of r.signals) assert.match(lines[s.line - 1], /"traceId"|"spanId"|"name"/, `line ${s.line}: ${lines[s.line - 1]}`);
  assert.equal(r.signals.length, 2);
});

test('traces: Tempo /api/v2/traces wrapper {trace:{resourceSpans}}', () => {
  const r = WR.parseTraces(JSON.stringify({ trace: otlpReq('checkout-api', 'prod-eu-west', [ROOT, CHILD]) }), ctx);
  assert.equal(r.extras.traceStats.spans, 2);
  assert.match(r.stats.format, /OTLP/);
});

test('traces: a valid document with zero spans says so instead of "unrecognised"', () => {
  for (const doc of [{ resourceSpans: [] }, { data: [], total: 0, limit: 0, offset: 0, errors: null }]) {
    const r = WR.parseTraces(JSON.stringify(doc), ctx);
    assert.notEqual(r.stats.format, 'unrecognised', JSON.stringify(doc));
    assert.ok(r.stats.warnings.some((w) => /no spans/i.test(w)), r.stats.warnings.join(' | '));
    assert.equal(r.signals.length, 0);
  }
});

test('traces: Jaeger "Download JSON" with several traces', () => {
  const jt = (id) => ({ traceID: id, spans: [
    { traceID: id, spanID: 'a1' + id.slice(0, 14), operationName: 'GET /orders', references: [], startTime: Date.parse('2026-10-05T21:50:00Z') * 1000, duration: 2300000,
      tags: [{ key: 'span.kind', type: 'string', value: 'server' }, { key: 'http.status_code', type: 'int64', value: 500 }, { key: 'error', type: 'bool', value: true }], logs: [], processID: 'p1', warnings: null },
    { traceID: id, spanID: 'b2' + id.slice(0, 14), operationName: 'SELECT orders', references: [{ refType: 'CHILD_OF', traceID: id, spanID: 'a1' + id.slice(0, 14) }], startTime: Date.parse('2026-10-05T21:50:00.1Z') * 1000, duration: 2000000,
      tags: [{ key: 'span.kind', type: 'string', value: 'client' }, { key: 'db.system', type: 'string', value: 'postgresql' }, { key: 'otel.status_code', type: 'string', value: 'ERROR' }], logs: [], processID: 'p1', warnings: null }
  ], processes: { p1: { serviceName: 'orders-api', tags: [{ key: 'k8s.cluster.name', type: 'string', value: 'prod-us-east' }] } }, warnings: null });
  const r = WR.parseTraces(JSON.stringify({ data: [jt('1111111111111111aaaaaaaaaaaaaaaa'), jt('2222222222222222bbbbbbbbbbbbbbbb')], total: 0, limit: 0, offset: 0, errors: null }, null, 2), ctx);
  assert.equal(r.extras.traceStats.traces, 2);
  assert.equal(r.extras.traceStats.spans, 4);
  assert.equal(r.extras.traceStats.entryErrorRatio, 1);
  assert.ok(r.signals.every((s) => s.componentId === 'service:prod-us-east/default/orders-api'));
});

test('traces: text spans with tabs, CRLF and colour', () => {
  const r = WR.parseTraces(yellow('2026-10-05T21:52:10.120Z') + '\ttrace=4bf9\tspan=a1\tparent=-\tservice=frontend\top="GET /checkout"\tdur=2304ms\tstatus=ERROR\tcode=502\tpeer=checkout-api\tcluster=prod-eu-west\tns=shop\r\n', ctx);
  assert.equal(r.signals.length, 1);
  assert.equal(r.signals[0].componentId, 'service:prod-eu-west/shop/frontend');
  assert.equal(r.signals[0].ts, Date.parse('2026-10-05T21:52:10.120Z'));
});

// ------------------------------------------------------------------------------------------------
// Alerts
// ------------------------------------------------------------------------------------------------
const GROUP = {
  version: '4', groupKey: '{}:{alertname="KubePodCrashLooping"}', truncatedAlerts: 0, status: 'firing', receiver: 'pagerduty',
  groupLabels: { alertname: 'KubePodCrashLooping' },
  commonLabels: { alertname: 'KubePodCrashLooping', cluster: 'prod-eu-west', namespace: 'shop', severity: 'critical' },
  commonAnnotations: { runbook_url: 'https://runbooks.example.com/KubePodCrashLooping' },
  externalURL: 'http://alertmanager.monitoring:9093',
  alerts: [
    { status: 'firing', labels: { pod: 'payments-api-7d9f8b6c5-x2k4p' }, annotations: { description: 'Pod is crash looping.' }, startsAt: '2026-10-05T21:49:30.123456789Z', endsAt: '0001-01-01T00:00:00Z', generatorURL: 'http://prometheus/graph', fingerprint: 'a1b2c3d4e5f60718' },
    { status: 'firing', labels: { pod: 'payments-api-7d9f8b6c5-q9w8e' }, annotations: {}, startsAt: '2026-10-05T21:49:45Z', endsAt: '0001-01-01T00:00:00Z', fingerprint: 'a1b2c3d4e5f60719' }
  ]
};

test('alerts: webhook group payload — commonLabels/commonAnnotations fill in each alert', () => {
  const r = WR.parseAlerts(JSON.stringify(GROUP, null, 2), ctx);
  assert.equal(r.signals.length, 2);
  for (const s of r.signals) {
    assert.equal(s.attrs.alertname, 'KubePodCrashLooping');
    assert.equal(s.kind, 'crash_loop');
    assert.equal(s.severity, 'critical');
    assert.equal(s.componentId, 'service:prod-eu-west/shop/payments-api');
    assert.equal(s.attrs.runbook, 'https://runbooks.example.com/KubePodCrashLooping');
  }
  assert.equal(r.signals[0].ts, Date.parse('2026-10-05T21:49:30.123Z'));
  assert.ok(r.extras.clusters.includes('prod-eu-west'));
});

test('alerts: an alert\'s own labels win over commonLabels', () => {
  const doc = JSON.parse(JSON.stringify(GROUP));
  doc.alerts[1].labels.severity = 'warning';
  const r = WR.parseAlerts(JSON.stringify(doc), ctx);
  assert.equal(r.signals[0].severity, 'critical');
  assert.equal(r.signals[1].severity, 'warn');
});

test('alerts: two webhook payloads pasted one after the other, with CRLF', () => {
  const resolved = Object.assign({}, GROUP, { status: 'resolved', alerts: [Object.assign({}, GROUP.alerts[0], { status: 'resolved', endsAt: '2026-10-05T21:58:00Z' })] });
  const text = (JSON.stringify(GROUP, null, 2) + '\n' + JSON.stringify(resolved, null, 2)).replace(/\n/g, '\r\n');
  const r = WR.parseAlerts(text, ctx);
  assert.equal(r.signals.length, 3);
  assert.equal(r.signals.filter((s) => s.kind === 'alert_resolved').length, 1);
  assert.equal(r.signals.find((s) => s.kind === 'alert_resolved').ts, Date.parse('2026-10-05T21:58:00Z'));
  assert.equal(r.stats.skipped, 0);
});

test('alerts: Prometheus /api/v1/alerts with a scientific-notation value and a nanosecond offset time', () => {
  const doc = { status: 'success', data: { alerts: [{ labels: { alertname: 'PaymentsErrorBudgetBurn', service: 'payments-api', cluster: 'prod-eu-west', severity: 'critical' },
    annotations: { summary: 'Error budget burn' }, state: 'firing', activeAt: '2026-10-05T23:49:12.60602144+02:00', value: '1.62e+01' }] } };
  const r = WR.parseAlerts(JSON.stringify(doc), ctx);
  assert.equal(r.signals[0].kind, 'slo_burn');
  assert.equal(r.signals[0].attrs.burnRate, 16.2);
  assert.equal(r.signals[0].ts, Date.parse('2026-10-05T21:49:12.606Z'));
});

test('alerts: colour codes on a text alert line', () => {
  const r = WR.parseAlerts(red('[FIRING:2]') + ' KubePodCrashLooping (payments-api prod-eu-west critical)\r\n', ctx);
  assert.equal(r.signals.length, 1);
  assert.equal(r.signals[0].kind, 'crash_loop');
  assert.equal(r.signals[0].componentId, 'service:prod-eu-west/default/payments-api');
});

test('alerts: default Alertmanager subject puts group-label values before the parentheses', () => {
  // template/default.tmpl __subject: [FIRING:n] <GroupLabels values> (<CommonLabels minus GroupLabels values>)
  const r = WR.parseAlerts('[FIRING:1] PaymentsHighErrorBurn payments-api (prod-eu-west critical)\n', ctx);
  assert.equal(r.signals.length, 1);
  assert.equal(r.signals[0].kind, 'slo_burn');
  assert.equal(r.signals[0].componentId, 'service:prod-eu-west/default/payments-api');
  assert.equal(r.signals[0].severity, 'critical');
});

test('alerts: joining words in a hand-written subject ("{{alertname}} for {{job}}") are not label values', () => {
  // A long-standing community Slack title is "[FIRING:1] {{alertname}} for {{job}}"; "for" must not
  // become a namespace, or the alert lands on a separate component from the real service.
  const a = WR.parseAlerts('[FIRING:1] PaymentsHighErrorRate for payments-api\n', ctx);
  assert.equal(a.signals.length, 1);
  assert.equal(a.signals[0].componentId, 'service:cluster-1/default/payments-api');
  const b = WR.parseAlerts('[FIRING:1] PaymentsHighErrorRate for payments-api in shop\n', ctx);
  assert.equal(b.signals[0].componentId, 'service:cluster-1/shop/payments-api', '"in <x>" names the namespace');
  const c = WR.parseAlerts('[FIRING:1] PaymentsHighErrorRate for payments-api on prod-eu-west\n', ctx);
  assert.equal(c.signals[0].componentId, 'service:prod-eu-west/default/payments-api');
});

test('alerts: the default notification body ("Labels:" / " - key = value") adds labels to the alert above it', () => {
  const text = [
    '[FIRING:1] KubePodCrashLooping (prod-eu-west critical)',
    'Labels:',
    ' - alertname = KubePodCrashLooping',
    ' - cluster = prod-eu-west',
    ' - namespace = shop',
    ' - pod = payments-api-7d9f8b6c5-x2k4p',
    ' - severity = critical',
    'Annotations:',
    ' - description = Pod shop/payments-api-7d9f8b6c5-x2k4p is restarting 2.5 times / 10 minutes.',
    ' - runbook_url = https://runbooks.example.com/KubePodCrashLooping',
    'Source: http://prometheus.monitoring:9090/graph?g0.expr=x'
  ].join('\n');
  const r = WR.parseAlerts(text, ctx);
  assert.equal(r.stats.skipped, 0, r.stats.warnings.join(' | '));
  assert.equal(r.signals.length, 1);
  const s = r.signals[0];
  assert.equal(s.componentId, 'service:prod-eu-west/shop/payments-api');
  assert.equal(s.attrs.labels.namespace, 'shop');
  assert.equal(s.attrs.runbook, 'https://runbooks.example.com/KubePodCrashLooping');
  assert.match(s.text, /restarting 2\.5 times/);
});

test('alerts: Slack-style detail bullets ("• key: value") also attach as labels', () => {
  const text = [
    '[FIRING:1] PaymentsHighErrorBurn payments-api (prod-eu-west critical)',
    'Details:',
    ' • alertname: PaymentsHighErrorBurn',
    ' • burn_rate: 16.2',
    ' • namespace: shop'
  ].join('\n');
  const r = WR.parseAlerts(text, ctx);
  assert.equal(r.stats.skipped, 0, r.stats.warnings.join(' | '));
  assert.equal(r.signals[0].componentId, 'service:prod-eu-west/shop/payments-api');
  assert.equal(r.signals[0].attrs.burnRate, 16.2);
});

test('alerts: `amtool alert query` simple table (Alertname / Starts At / Summary / State)', () => {
  const text = [
    'Alertname                Starts At                Summary                                              State   ',
    'KubePodCrashLooping      2026-10-05 21:49:30 UTC  Pod shop/payments-api-7d9f8b6c5-x2k4p is crash looping.  active  ',
    'PaymentsErrorBudgetBurn  2026-10-05 21:50:00 UTC  payments-api is burning its error budget at 16.2x        active  '
  ].join('\n');
  const r = WR.parseAlerts(text, ctx);
  assert.equal(r.stats.skipped, 0, r.stats.warnings.join(' | '));
  assert.equal(r.signals.length, 2);
  assert.equal(r.signals[0].kind, 'crash_loop');
  assert.equal(r.signals[0].ts, Date.parse('2026-10-05T21:49:30Z'));
  assert.equal(r.signals[0].componentId, 'service:cluster-1/shop/payments-api', 'pod named in the summary');
  assert.equal(r.signals[1].kind, 'slo_burn');
  assert.equal(r.signals[1].attrs.burnRate, 16.2);
});

test('alerts: `amtool alert query -o extended` table reads labels and annotations', () => {
  const header = 'Labels                                                                                                   Annotations                                     Starts At                Ends At                  Generator URL                State   ';
  // Align the row under the header columns the way tabwriter does.
  const cols = ['Labels', 'Annotations', 'Starts At', 'Ends At', 'Generator URL', 'State'].map((n) => header.indexOf(n));
  const cells = ['alertname="KubePodCrashLooping" cluster="prod-eu-west" namespace="shop" pod="payments-api-7d9f8b6c5-x2k4p" severity="critical"', 'description="Pod is crash looping."', '2026-10-05 21:49:30 UTC', '2026-10-05 22:09:30 UTC', 'http://prometheus/graph?g0', 'active'];
  let aligned = '';
  cells.forEach((c, i) => { aligned = aligned.padEnd(cols[i], ' ') + c; });
  const r = WR.parseAlerts(header + '\n' + aligned + '\n', ctx);
  assert.equal(r.stats.skipped, 0, r.stats.warnings.join(' | '));
  assert.equal(r.signals.length, 1);
  assert.equal(r.signals[0].componentId, 'service:prod-eu-west/shop/payments-api');
  assert.equal(r.signals[0].severity, 'critical');
  assert.match(r.signals[0].text, /crash looping/);
});
