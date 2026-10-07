# SRE War Room — build contract

One-page incident war-room web app. The engineer pastes Kubernetes logs/events, traces, alerts and Helm
diffs/history. The page instantly (client-side, no server) produces:

1. a live **blast-radius map** (clusters → components → dependencies, coloured by impact, replayable over time)
2. **probable root causes**, ranked, each with an evidence chain that links back to the pasted lines
3. **rollback options**, ranked, with exact commands, time-to-recover, risk and caveats
4. an **error-budget impact estimate** using the Google SRE Workbook burn-rate method
5. **side-by-side observability stack recommendations** (Datadog, Grafana, OpenTelemetry, hosted cloud) that
   light up where each setup would break down *for this incident at this scale*
6. a **KubeCon Europe 2026 ideas** digest (sourced), and
7. an optional **"Investigate with Claude"** panel — a HolmesGPT-style read-only agent loop over the pasted
   evidence, run through the artifact `sample` capability. The deterministic engine must produce the full
   result without it.

Deployed as a claude.ai Artifact: one self-contained HTML file (`dist/index.html`) built by `build.mjs`.

---

## 0. Ground rules for every builder

- **Plain browser JavaScript, no frameworks, no bundler deps.** Each source file is a classic script:
  ```js
  (function (WR) {
    'use strict';
    // ...
    WR.parseLogs = parseLogs;
  })(globalThis.WR = globalThis.WR || {});
  ```
  No `import`/`export`, no top-level `await`, no DOM access in `src/engine/**` (engine must run in Node for tests).
- Node ≥ 20 tests with `node:test` + `node:assert/strict`, in `tests/*.test.mjs`. Load sources through
  `tests/load.mjs` (imports every `src/engine/*.js`, `src/samples/*.js`, `src/data/*.js` in build order, then
  exports `globalThis.WR`). Run all with `node --test tests/`.
- Only CDN allowed at runtime: `https://cdnjs.cloudflare.com` (pin exact versions) — but prefer **no library**.
  Fonts from Google Fonts only. No `fetch` to the network. No `alert/confirm/prompt`, no `window.print`,
  no `<a download>`.
- Never `innerHTML` pasted text. Build DOM with `textContent` or escape with `WR.esc()` (defined in
  `src/engine/util.js`).
- Copy in plain English. Spell out terms the first time on screen (e.g. "Service level objective (SLO)").
  No emoji. No lorem ipsum.
- Performance: analysis of 5,000 log lines + 2,000 spans must finish < 150 ms on a laptop. Cap stored signals at
  3,000 (keep all errors; drop oldest info).

## 1. Build order (concatenation order in `build.mjs`)

```
src/engine/util.js        WR.esc, WR.hash, WR.clamp, WR.uniq, WR.groupBy, WR.fmtDuration, WR.fmtPct
src/engine/time.js        WR.time
src/engine/entities.js    WR.entities
src/engine/redact.js      WR.redact
src/engine/parse-logs.js  WR.parseLogs
src/engine/parse-traces.js WR.parseTraces
src/engine/parse-alerts.js WR.parseAlerts
src/engine/parse-helm.js  WR.parseHelm
src/engine/budget.js      WR.budget
src/engine/hypotheses.js  WR.hypotheses
src/engine/rollbacks.js   WR.rollbacks
src/engine/traits.js      WR.traits
src/engine/analyze.js     WR.analyze      (orchestrator; calls everything above)
src/samples/samples.js    WR.samples
src/data/kubecon.js       WR.kubecon
src/data/stacks.js        WR.stacks, WR.stackFit
src/ui/map.js             WR.ui.map
src/ui/investigate.js     WR.ui.investigate
src/ui/app.js             WR.ui.app       (boots on DOMContentLoaded)
```
`src/ui/shell.html` holds the page markup (starts with `<title>SRE War Room</title>`, Google Fonts `<link>`s,
then `<style>/*INLINE:src/ui/styles.css*/</style>`, then the body markup, then
`<script>/*INLINE:ALL_JS*/</script>`). `build.mjs` replaces the two markers and writes `dist/index.html`.
No `<!doctype>`, `<html>`, `<head>`, `<body>` tags — the Artifact host wraps the file.

## 2. Inputs

```js
WR.analyze({
  logs:   string,   // kubectl logs (plain, JSON, --prefix, stern), kubectl get events / get pods tables,
                    // kubectl describe pod excerpts, klog lines
  traces: string,   // OTLP JSON | Jaeger JSON | one-span-per-line text (see §3.2)
  alerts: string,   // Alertmanager webhook JSON | Prometheus /api/v1/alerts JSON | text lines
  helm:   string,   // `helm diff upgrade` output and/or unified diff and/or `helm history` table
  context: {
    now?: string,            // ISO; default = latest absolute timestamp seen across all sources
    defaultTz?: string,      // offset used for zone-less timestamps, e.g. "+02:00" or "Z" (default "Z")
    year?: number,           // for klog/syslog stamps without a year (default: year of `now`)
    deployedAt?: string,     // manual override (ISO)
    cluster?: string,        // default cluster name when nothing says otherwise (default "cluster-1")
    slo: { target: 0.999, windowDays: 30, requestsPerMin: 1200, budgetSpentBeforePct: 0,
           errorRatioOverride?: number }   // 0..1
  }
}) → Analysis   // pure, synchronous, never throws (errors become warnings[])
```

**Cluster markers** recognised in any pasted text (they set the cluster for following lines of that pane):
`# cluster: prod-eu-west`, `--- cluster=prod-eu-west ---`, `[context: prod-eu-west]`,
`kubectl --context prod-eu-west ...` command echo lines. Also from data: alert label `cluster`/`k8s_cluster`,
OTLP resource attribute `k8s.cluster.name`, Jaeger process tag `k8s.cluster.name`.

## 3. Parsers

All parsers: `(text, ctx) → { signals: Signal[], entities: EntityHint[], stats: ParseStats, extras }`.
`ParseStats = { lines, parsed, skipped, format: string, tzAssumed: number, warnings: string[] }` (shown as the
pane's status chip, e.g. "142 lines · 37 signals · OTLP JSON · 3 times assumed +02:00").

### 3.1 Logs (`WR.parseLogs`)
Recognise per line (a line may match several; first specific wins):
- `kubectl get events` table: `LAST SEEN TYPE REASON OBJECT MESSAGE` (relative ages `45s`, `3m12s`, `2h`,
  `<unknown>` → ts = now − age, `tsInferred`), also `-o wide` and `--all-namespaces` (NAMESPACE first col).
- `kubectl get pods` table: `NAME READY STATUS RESTARTS AGE` (+NAMESPACE) → status signals
  (CrashLoopBackOff, OOMKilled, ImagePullBackOff, ErrImagePull, CreateContainerConfigError, Pending, Evicted,
  Error, Terminating) — no ts (use now, `tsInferred`).
- `kubectl describe pod` snippets: `Name:`, `Namespace:`, `Last State: Terminated`, `Reason: OOMKilled`,
  `Exit Code: 137`, `Restart Count:`, `Events:` sub-table.
- JSON lines: keys `ts|time|timestamp|@timestamp`, `level|severity|lvl`, `msg|message`, `service|app|logger`,
  `pod`, `namespace`, `trace_id|traceId`, `status|http.status_code`, `latency_ms|duration`.
- `kubectl logs --prefix`: `[pod/<pod>/<container>] <rest>`; stern: `<pod> <container> <rest>`.
- klog: `E1005 23:51:02.123456   1 file.go:123] msg`; syslog: `Oct  5 23:51:02 host proc[pid]: msg`;
  ISO/RFC3339 or `2026-10-05 23:51:02,123` prefixes; logfmt `level=error ts=... msg="..."`.
Pod → workload: strip `-<rs-hash 8-10 [a-z0-9]>-<5 [a-z0-9]>` (Deployment), `-<5>` (DaemonSet), `-<ordinal>`
(StatefulSet). Namespace from line/prefix/describe/table else `"default"`.

**Signal kinds** (closed vocabulary — use exactly these strings):
```
oom_killed crash_loop image_pull config_error probe_failed evicted node_not_ready node_pressure
scheduling_failed pvc_pending dns_failure conn_refused timeout tls_error http_5xx http_429 throttled
hpa_maxed rollout restart panic db_error conn_exhaustion migration error_generic
span_error span_slow
alert_firing alert_resolved slo_burn
change
```
Keyword rules (case-insensitive, examples not exhaustive):
`OOMKilled|Exit Code: 137|out of memory|Killed process` → oom_killed · `CrashLoopBackOff|Back-off restarting` →
crash_loop · `ImagePullBackOff|ErrImagePull|manifest unknown|pull access denied` → image_pull ·
`CreateContainerConfigError|secret ".*" not found|configmap ".*" not found|invalid configuration` →
config_error · `Readiness probe failed|Liveness probe failed|Startup probe failed` → probe_failed ·
`Evicted|The node was low on resource` → evicted · `NodeNotReady|node .* not ready` → node_not_ready ·
`MemoryPressure|DiskPressure|PIDPressure` → node_pressure · `FailedScheduling|Insufficient (cpu|memory|nvidia)`
→ scheduling_failed · `pod has unbound immediate PersistentVolumeClaims|ProvisioningFailed` → pvc_pending ·
`no such host|lookup .* (i/o timeout|server misbehaving)|SERVFAIL|NXDOMAIN` → dns_failure ·
`connection refused|ECONNREFUSED` → conn_refused · `context deadline exceeded|i/o timeout|timed out|ETIMEDOUT|
upstream request timeout` → timeout (but dns patterns win) · `x509|certificate has expired|tls: handshake|
certificate signed by unknown authority|SSL routines` → tls_error · ` 5\d\d |status[=: ]5\d\d|"status":5\d\d`
→ http_5xx · `429|Too Many Requests|rate limit` → http_429 · `throttl` → throttled ·
`ScalingLimited|reached max replicas|desired replica count .* max` → hpa_maxed ·
`ScalingReplicaSet|Scaled up replica set|deployment .* successfully rolled out|Created pod:` → rollout (carries
`attrs.replicaSet`, used as a deploy-time source) · `Started container|Restarting` → restart ·
`panic:|Traceback|Exception|NullPointer|segfault` → panic · `deadlock|too many connections|remaining connection
slots are reserved|pool exhausted|connection pool timeout|FATAL: sorry, too many clients` → conn_exhaustion
(if pool/connection-count wording) else db_error · `migration|migrate` with error → migration ·
level error/fatal with no other match → error_generic.

### 3.2 Traces (`WR.parseTraces`)
Formats: **OTLP JSON** (`resourceSpans[].resource.attributes[]` `service.name`, `k8s.cluster.name`,
`k8s.namespace.name`, `k8s.pod.name`; `scopeSpans[].spans[]` with `traceId, spanId, parentSpanId, name, kind,
startTimeUnixNano, endTimeUnixNano, status.code` (2 or `"STATUS_CODE_ERROR"` = error), `status.message`,
attributes `http.response.status_code|http.status_code`, `db.system`, `db.name`, `peer.service`,
`server.address`, `rpc.service`, `error.type`); **Jaeger JSON** (`data[].spans[]`, `references[]` CHILD_OF,
`processes{}.serviceName`, `tags[]` `error=true`, `http.status_code`, `otel.status_code`, `startTime` µs,
`duration` µs); **text**, one span per line:
`2026-10-05T21:52:10.120Z trace=4bf9 span=a1 parent=- service=frontend op="GET /checkout" dur=2304ms status=ERROR code=502 peer=checkout-api cluster=prod-eu-west ns=shop`
Outputs signals `span_error` / `span_slow` (slow = > 3× median duration of that service+op, min 1000 ms) and an
**edge list** in `extras.edges: [{from, to, calls, errors, p95ms, firstErrorTs}]` keyed by component ids.
Edge rule: child span service ≠ parent span service → edge parent→child. Client spans (kind CLIENT=3 or
`span.kind=client`) with `db.system` → edge to datastore component `db:<db.name||db.system>`; with
`peer.service`/`server.address` and no child span → edge to that component (type `external` if not a known
service). Mark entry components (spans with no parent, or SERVER spans whose parent is missing) as
`userFacing`. Also `extras.traceStats = { traces, spans, errorTraces, services, entryErrorRatio }` where
`entryErrorRatio = errored root spans / root spans` (used for error budget).

### 3.3 Alerts (`WR.parseAlerts`)
Formats: **Alertmanager webhook JSON** (`{alerts:[{status, labels, annotations, startsAt, endsAt}]}` or a bare
array), **Prometheus `/api/v1/alerts`** (`data.alerts[]` with `state`, `activeAt`, `value`), **text lines**:
`[FIRING:2] KubePodCrashLooping (payments-api prod-eu-west critical)`, `ALERT KubePodCrashLooping{namespace="shop",
pod="payments-api-7d9f8b6c5-x2k4p",severity="critical"} firing since 2026-10-05T21:49:30Z`,
`2026-10-05T21:49:30Z FIRING critical PaymentsHighErrorBurn service=payments-api cluster=prod-eu-west burn_rate=16.2`.
Component from labels in priority `service, app, deployment, statefulset, daemonset, job, pod (→workload),
container, instance`. Alert names map to kinds: `*CrashLooping` → crash_loop, `*OOM*` → oom_killed,
`*ImagePull*` → image_pull, `KubeNodeNotReady` → node_not_ready, `*Pressure` → node_pressure,
`*ErrorBudget*|*Burn*|*SLO*` → slo_burn (parse `burn_rate|burnrate|value` → `attrs.burnRate`; parse
`error_ratio|errorRatio` → `attrs.errorRatio`), `*5xx*|*HighErrorRate*` → http_5xx, `*Latency*` → span_slow,
`*CertificateExpir*|*TLS*` → tls_error, `*DNS*|CoreDNS*` → dns_failure, `*HPA*MaxedOut|*Replicas*Mismatch` →
hpa_maxed, `*Throttl*` → throttled, else alert_firing. Resolved alerts → alert_resolved. Severity from labels.
`extras.highCardinalityLabels`: label keys whose values look per-instance (pod names with hashes, IPs, UUIDs,
user/session/request ids, or ≥ 20 distinct values) — feeds the stack fit.

### 3.4 Helm (`WR.parseHelm`)
Recognise and combine:
- **`helm diff upgrade`** blocks: header `<namespace>, <name>, <Kind> (<group>) has changed:` /
  `has been added:` / `has been removed:`, then indented manifest with `-`/`+` lines. Track YAML path by
  indentation to know which field changed.
- **unified diff** (`diff --git`, `---`/`+++`, `@@`) of `values.yaml` or manifests.
- **`helm history <release>`** table: `REVISION UPDATED STATUS CHART APP VERSION DESCRIPTION`
  (`UPDATED` like `Mon Oct  5 23:47:03 2026` — zone-less → `defaultTz`, `tsInferred`).
  Release name from a `helm history payments` echo line, `# release: payments`, or the chart name prefix.
- **`helm list`** table (NAME NAMESPACE REVISION UPDATED STATUS CHART APP VERSION) — `UPDATED` includes zone.
Output `extras.changes: Change[]` and `extras.deploy: Deploy|null`.
```
Change = { id, release, namespace, resourceKind, resourceName, componentId, field,   // e.g. "spec.template.spec.containers[payments].resources.limits.memory"
           category: 'image'|'resources'|'replicas'|'env'|'configmap'|'secret'|'probe'|'networkpolicy'|'crd'
                    |'migration-hook'|'hpa'|'ingress'|'service'|'rbac'|'chart'|'other',
           before, after, risk: 'high'|'medium'|'low', line, summary }   // summary e.g. "memory limit 512Mi → 256Mi"
Deploy = { release, namespace, revision, previousRevision, chartFrom, chartTo, appFrom, appTo,
           deployedAt (epoch ms|null), deployedAtSource: 'helm-history'|'helm-list'|'rollout-event'|'manual'|null,
           tsInferred }
```
Risk heuristics: memory/cpu limit decrease, probe threshold tightened, replicas/hpa max change, networkpolicy,
crd, migration hook (`helm.sh/hook: pre-upgrade` + Job with `migrat`), secret/env removal → high; image tag,
env add, configmap value → medium; labels/annotations/chart version only → low.
Secrets: never echo a Secret's `data` values or env values that look secret — store `"(redacted)"`.

### 3.5 Time (`WR.time`)
`parse(str, {defaultTz, year, now}) → {ts, tsInferred}` handles RFC3339/ISO (with `Z`/offset), `YYYY-MM-DD
HH:MM:SS[,.]mmm`, klog `MMDD HH:MM:SS.uuuuuu`, syslog `Mon D HH:MM:SS`, helm `Day Mon D HH:MM:SS YYYY`, epoch
s/ms/µs/ns numbers. Zone-less → apply `defaultTz`, `tsInferred=true`. `age("3m12s") → ms`. Everything internal
is epoch ms UTC. UI shows times as `HH:MM:SS` UTC plus the offset chip when `defaultTz` ≠ Z.

### 3.6 Entities (`WR.entities`)
Component id: `${type}:${cluster}/${namespace}/${name}` (type ∈ `service, datastore, external, node, infra`).
A workload, its pods, its Service and its trace `service.name` collapse into ONE `service` component when name
(after pod-suffix stripping) + namespace + cluster match. Unknown namespace on one side matches a known one on
the other when the name is unique in that cluster. Kubernetes nodes → `node:` components. CoreDNS/kube-dns →
`infra:<cluster>/kube-system/coredns`. Ingress controllers / gateways → `service` with `role:'ingress'`.

### 3.7 Redaction (`WR.redact`)
`redact(text) → {text, count, kinds}`: bearer/JWT tokens, `AKIA[0-9A-Z]{16}`, `-----BEGIN ... PRIVATE KEY-----`
blocks, `password|passwd|secret|token|api[_-]?key|client_secret` `[:=]` values, URL credentials
`scheme://user:pass@`, emails, long base64 (≥ 40 chars) values. Used before anything is sent to Claude.

## 4. Analysis output (`WR.analyze` → Analysis) — THE contract for UI agents

```
Analysis = {
  version: 1,
  generatedAt: epoch ms,
  inputsPresent: { logs, traces, alerts, helm },                 // booleans
  stats: { logs: ParseStats, traces: ParseStats, alerts: ParseStats, helm: ParseStats },
  window: { start, end, firstAnomaly, now },                    // epoch ms (null when unknown)
  headline: string,           // "payments-api in prod-eu-west is crash-looping after Helm release payments r42"
  severity: 'SEV1'|'SEV2'|'SEV3'|'SEV4',   // SEV1: ≥1 user-facing component failing AND burn ≥ 14.4 (30-day scale);
                                            // SEV2: user-facing degraded or burn ≥ 6; SEV3: failing non-user-facing; else SEV4
  clusters: [{ name, componentCount, failing, degraded, status: 'failing'|'degraded'|'healthy' }],
  components: [{
    id, name, type, role?: 'ingress', cluster, namespace,
    status: 'root'|'failing'|'degraded'|'at-risk'|'healthy',
    impact: 0..1,  userFacing: bool,
    firstErrorTs, lastErrorTs, counts: { error, warn, info },
    kinds: string[],           // distinct signal kinds seen, most frequent first
    pods: string[], release?: string, changeIds: string[]
  }],
  edges: [{ id, from, to, calls, errors, errorRate, p95ms, status: 'failing'|'degraded'|'ok', firstErrorTs }],
  signals: Signal[],
  changes: Change[],
  deploy: Deploy|null,
  timeline: [{ ts, componentId, kind, severity, signalId }],  // ascending ts; first error per component per kind
  hypotheses: Hypothesis[],   // sorted by confidence desc, max 6
  rollbacks: Rollback[],      // sorted: recommended first, then by etaMinutes
  budget: Budget,
  traits: Traits,
  warnings: string[]          // e.g. "Helm history times have no time zone; assumed +02:00."
}
Signal = { id, source: 'logs'|'traces'|'alerts'|'helm', line, ts, tsInferred, severity: 'info'|'warn'|'error'|'critical',
           kind, componentId, relatedIds: [], text, raw, attrs }
```
**Statuses:** `failing` = error/critical signals in the incident window (or edge errorRate ≥ 0.2 into it);
`degraded` = warn signals, slow spans, or calls into a failing component with errorRate ≥ 0.02;
`at-risk` = healthy but calls (directly or transitively, max 2 hops) a failing component;
`root` = the component of the top hypothesis (exactly one, or none when top confidence < 0.35).
**Incident window:** from 15 min before `firstAnomaly` to `now`.

```
Hypothesis = { id, title, category, componentId, confidence: 0..0.95, summary,
  evidence: [{ signalId|null, changeId|null, text, weight, source, line }],   // ≥ 2 items for confidence > 0.5
  against: [{ text }],                       // counter-evidence, shown as "What argues against it"
  nextChecks: [{ cmd, why }],                // real kubectl/helm/promql commands with the actual names filled in
  rule }
categories: bad-deploy resource-limits config-error image-pull dependency-failure dns tls-cert node-pressure
            scheduling-capacity probe-misconfig network-policy connection-exhaustion rate-limiting unknown
```
Scoring (deterministic, documented in code comments): evidence weights combine as `1 − Π(1 − wᵢ)`; then
× 1.15 when the change/first signal precedes the first error by 0–60 min (`deploy.deployedAt` or the change's
rollout event); × 0.6 when errors started **before** the change; × 1.1 when the component is the deepest failing
node on failing edges (all its failing callees are healthy or absent); cap 0.95. A deploy-correlation hypothesis
without any deploy time says so in `against` ("No deploy time found — paste `helm history` or set Deployed at").

```
Rollback = { id, title, kind: 'helm-rollback'|'rollout-undo'|'set-image'|'resource-restore'|'config-revert'
             |'canary-abort'|'traffic-shift'|'scale'|'roll-forward'|'restart',
  commands: string[],        // exact, copyable, with real names/namespaces/contexts/revisions
  etaMinutes, risk: 'low'|'medium'|'high', recommended: bool, fixes: [hypothesisId],
  caveats: string[],         // e.g. "Helm does not roll back CRDs", "migration hook ran: DB schema stays at new version",
                             // "rollout undo leaves Helm release history out of sync — follow with helm rollback or a fix-forward"
  prerequisites: string[], budgetSavedPct: number|null }
```
Rules: `helm-rollback` when `deploy.previousRevision` known (`helm rollback <release> <prev> -n <ns> --kube-context <cluster> --wait --timeout 5m`);
`rollout-undo` for image-only changes; `resource-restore` when a limits decrease + OOM; `config-revert` for
configmap/env/secret; `traffic-shift` when ≥ 2 clusters and only some failing (shift away from the failing
cluster; Fleet/ingress/DNS weights — show generic commands with placeholders marked `<…>`); `canary-abort`
when Argo Rollouts/Flagger objects appear; `roll-forward` when the cause is not a change (cert expiry, external
dependency) or a migration hook makes rollback unsafe; `restart` only as a stop-gap. Exactly one `recommended`.

```
Budget = { sloTarget, windowDays, requestsPerMin, errorRatio, errorRatioSource: 'override'|'alert'|'traces'|'logs'|'default',
  burnRate,                       // errorRatio / (1 − sloTarget)
  incidentMinutes,                // now − firstAnomaly
  consumedPct,                    // burnRate × incidentMinutes / (windowDays × 1440) × 100
  remainingPct,                   // 100 − budgetSpentBeforePct − consumedPct (floor 0)
  minutesToExhaustion,            // remainingPct/100 × windowDays × 1440 / burnRate   (null if burnRate ≤ 0)
  badRequests, budgetRequests,    // errorRatio × rpm × incidentMinutes ; (1 − target) × rpm × windowDays × 1440
  alertRows: [{ severity:'Page'|'Ticket', longWindow:'1 hour'|'6 hours'|'3 days', shortWindow:'5 minutes'|'30 minutes'|'6 hours',
                longMinutes, shortMinutes, consumedPctAtFire: 2|5|10, burnThreshold, firing: bool }],
                // Google SRE Workbook Table 5-8 (30-day, 99.9%): 1h/5m 14.4 2% Page; 6h/30m 6 5% Page; 3d/6h 1 10% Ticket.
                // For other windows keep consumedPctAtFire and rescale: burnThreshold = consumed% /100 × windowDays×1440 / longMinutes.
                // wouldFire = burnRate ≥ burnThreshold; firesAfterMinutes = longMinutes × burnThreshold / burnRate
                // (Workbook detection time); firesInMinutes = max(0, firesAfter − incidentMinutes);
                // modelFiring = wouldFire && incidentMinutes ≥ firesAfterMinutes (estimate: steady burn since firstAnomaly);
                // observedFiring = a FIRING burn-rate alert in the paste stands for this row (only the most severe row
                //   whose threshold its burn clears); firing = modelFiring || observedFiring; firingSource 'alerts'|'estimate'|null.
                // DISPLAY: use row.state / row.stateText verbatim —
                //   'firing-observed' "Firing (in your alerts)" · 'firing-estimate' "Firing (estimate)" ·
                //   'pending' "Fires in about N min at this burn" · 'not-at-this-burn' "Not at this burn rate" · 'no-evidence' "No evidence yet"
  projection: [{ label: 'Mitigate now'|'In 30 minutes'|'In 2 hours', extraMinutes, consumedPct, remainingPct }],
  series: [{ t: minutesFromStart, remainingPct }],   // for the chart, 0..(incidentMinutes+120), 25 points, assuming current burn continues
  hasEvidence: bool,                // false → the UI shows an empty state, never the default-ratio numbers
  observedBurnRate, observedAlert, observedSignalId,   // the firing burn alert from the paste, or null
  notes: string[],                  // assumptions + the "likely undercounted" note when an alert fired earlier than the model allows
  source: 'https://sre.google/workbook/alerting-on-slos/' }
```

```
Traits = { clusterCount, clusters: string[], multiCluster: bool, failingClusterCount,
  highCardinalityLabels: string[], logLinesPerMin, signalsPerMin, spanCount, tracedServices, untracedFailingComponents: string[],
  errorTracesMissing: bool,       // failing components with alerts/logs errors but zero error spans → head sampling may have dropped them
  sources: { logs, traces, alerts, helm }, hasDeployTime: bool }
```

## 5. Samples (`WR.samples`) — realistic fixtures, also the test corpus
`WR.samples = [{ id, title, blurb, context, logs, traces, alerts, helm, expected }]`, four scenarios, all real
formats from §3 (mix formats across samples), timestamps on 2026-10-05, internally consistent:
1. `bad-deploy-oom` — two clusters (`prod-eu-west` failing, `prod-us-east` healthy, not yet upgraded). Helm
   release `payments` r41→r42 (`payments-1.8.2`/`2.13.4` → `payments-1.9.0`/`2.14.0`) lowers memory limit
   512Mi→256Mi and adds a cache warm-up env var. payments-api OOMKilled → CrashLoopBackOff; checkout-api gets
   connection refused / 503s; frontend (ingress) degraded; postgres healthy. Alerts in UTC `Z`; app JSON logs
   with `+02:00` offsets; `kubectl get events` with relative ages; `helm history` zone-less local time
   (context.defaultTz `+02:00`). Burn-rate alert ~16×.
   expected: `{ rootComponentName:'payments-api', rootCluster:'prod-eu-west', category:'resource-limits' or 'bad-deploy',
   recommendedKind:'helm-rollback', deployRevision:42, previousRevision:41, multiCluster:true }`.
2. `coredns-outage` — one cluster; a platform chart change to the `coredns` ConfigMap (bad forward / cache
   setting) + CoreDNS pods OOM or crash; many services log `lookup ... i/o timeout`; very wide blast radius.
   expected root: coredns (infra), category `dns`.
3. `cert-expiry` — internal mTLS / ingress certificate expired at 21:00Z; gateway → auth-service `x509: certificate
   has expired`; **red herring**: an unrelated `recommendations` Helm upgrade 3 hours earlier. expected root
   auth-service (or the ingress gateway) category `tls-cert`, recommendedKind `roll-forward`; the
   recommendations release must NOT be the top hypothesis.
4. `db-conn-exhaustion` — two clusters both degraded; `orders` release raises HPA max 6→20 replicas, each pod
   pool size 20 → Postgres `too many clients`; orders-api 500s; Jaeger JSON traces. expected root orders-api
   (or the db), category `connection-exhaustion`, recommendedKind `helm-rollback` or `scale`.
Each sample 60–200 log lines, 20–80 spans, 3–8 alerts, helm diff 30–120 lines. Use realistic names, image
registries `registry.example.com`, IPs from 10.0.0.0/8, no real company names, no real secrets (include one fake
`DB_PASSWORD` value in a diff to exercise redaction).

## 6. UI (shell.html + styles.css + app.js + map.js + investigate.js)

### 6.1 Design tokens (put exactly these first in styles.css; dark values mirror)
```css
/* Layout: incident board — evidence rail left (≈380px), board right; status strip on top; stacks below */
:root{
  --bg:#EEF1F4; --surface:#FFFFFF; --surface-2:#F5F7F9; --ink:#15202B; --ink-2:#4B5866; --ink-3:#7B8794;
  --line:#D6DDE4; --accent:#0E6F7C; --accent-ink:#FFFFFF; --focus:#0E6F7C;
  --crit:#C2261B; --crit-bg:#FBE9E7; --warn:#A86200; --warn-bg:#FFF3DF; --ok:#25774A; --ok-bg:#E5F4EC;
  --root:#C2261B; --risk:#A86200; --muted:#9AA5B1;
  --font-display:'Barlow Condensed','Arial Narrow',sans-serif;
  --font-body:'Atkinson Hyperlegible Next','Atkinson Hyperlegible',system-ui,sans-serif;
  --font-mono:'Atkinson Hyperlegible Mono','JetBrains Mono',ui-monospace,Menlo,monospace;
  --r-sm:6px; --r-md:10px; --shadow:0 1px 2px rgb(21 32 43/.06),0 4px 16px rgb(21 32 43/.06);
}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
  --bg:#0E141A; --surface:#151D25; --surface-2:#1B252F; --ink:#E6EDF3; --ink-2:#A3B1BE; --ink-3:#7D8B98;
  --line:#2A3743; --accent:#4DB6C4; --accent-ink:#06262B; --focus:#4DB6C4;
  --crit:#FF6B5E; --crit-bg:#3A1714; --warn:#F2A33A; --warn-bg:#382809; --ok:#4CC38A; --ok-bg:#0F2D20;
  --root:#FF6B5E; --risk:#F2A33A; --muted:#5B6874; --shadow:0 1px 2px rgb(0 0 0/.3); color-scheme:dark }}
:root[data-theme="dark"]{ /* same dark values */ }
body{background:var(--bg);color:var(--ink);font-family:var(--font-body)}
```
Fonts link: `https://fonts.googleapis.com/css2?family=Barlow+Condensed:wght@500;600;700&family=Atkinson+Hyperlegible+Next:wght@400;600;700&family=Atkinson+Hyperlegible+Mono:wght@400;600&display=swap`.
Display face only for: status-strip numbers, section titles, severity badge, map cluster labels. Uppercase
labels get `letter-spacing:.06em`. Numbers `font-variant-numeric:tabular-nums`. Severity is encoded in FORM as
well as colour: a 4px left stripe on cards, filled pill for failing, outlined pill for degraded, dashed outline
for at-risk, a double ring + crosshair glyph for the root suspect on the map. No emoji, no gradients, no
`rounded-lg` on everything — radius only on cards and pills. Light theme is the designed-first theme.

### 6.2 Layout
- **Status strip** (sticky, `top: env(safe-area-inset-top,0px)`): app name "SRE War Room" · severity badge ·
  headline · elapsed since first anomaly · burn rate · budget consumed · clusters affected (e.g. "1 of 2") ·
  scenario picker (`<select id="scenario">`: the four samples + "Blank incident") · buttons "Export brief",
  theme toggle.
- **Evidence rail** (left; on phones it becomes the first section): four panes as tabs —
  "Logs & events", "Traces", "Alerts", "Helm diff & history" — each a `<textarea id="in-logs|in-traces|in-alerts|in-helm">`
  in the mono face, with a status chip under it (from ParseStats) and a "Clear" link; then a "Context" group:
  SLO target (`#ctx-target`, select 99, 99.5, 99.9, 99.95, 99.99), window days (`#ctx-window` 7/28/30),
  requests per minute (`#ctx-rpm`), budget already spent % (`#ctx-spent`), error ratio override (`#ctx-ratio`,
  blank = auto), zone for times without one (`#ctx-tz`), deployed at override (`#ctx-deployed`,
  datetime-local). Every edit re-runs `WR.analyze` debounced 250 ms ("live").
- **Board** (right), in this order, each a `<section>` with an id for `#anchor` deep links:
  1. `#map` Blast radius — map (§6.3) + legend + timeline scrubber + click-for-details drawer.
  2. `#causes` Probable root causes — ranked cards: confidence meter, category chip, summary, evidence chain
     (each item a button that focuses the matching pane and selects that line), "What argues against it",
     "Next checks" (commands with Copy buttons).
  3. `#rollback` Rollback options — recommended card first with "Recommended" pill; commands with Copy; time
     to recover; risk; caveats; prerequisites; error budget saved.
  4. `#budget` Error budget — big numbers (burn rate ×, consumed %, time to exhaustion), the three workbook
     alert rows with Firing / Not firing pills, projection chart (inline SVG, remaining % vs minutes; three
     mitigation markers), the formula and a link to the source, and the assumption note.
  5. `#claude` Investigate with Claude (§6.4).
  6. `#stacks` Observability stacks (§6.5).
  7. `#kubecon` KubeCon Europe 2026 ideas (§6.6).
- Opens with sample 1 loaded (clearly labelled "Example incident — replace with your own evidence").
- Phone (≤ 760px): single column; map container scrolls horizontally inside itself; textareas 10 rows.
- Remember per-viewer: theme, last tab, and an unsent draft of the four panes in `localStorage`
  (try/catch every access; works without it).

### 6.3 Map (`WR.ui.map.render(svgContainerEl, analysis, {onSelect, at})`)
Inline SVG, no library. Layered left→right layout per cluster: users/entry (userFacing / ingress) → services
(longest-path layering on edges) → datastores/external → infra (coredns, nodes) in a bottom row. Each cluster is
a horizontal **lane** with its name in the display face and a status pill; healthy sibling clusters stay visible
(the "compare a bad cluster against healthy siblings" idea). Edges: curved paths, width by calls, colour by
status, label with error % when > 1 %. Nodes: rounded rects with name, namespace small, kind icon (simple SVG
shapes), status styling per §6.1; root gets double ring + crosshair. Timeline scrubber (`<input type=range>`)
from window.start to now with a Play button: nodes/edges take their status only after their first error time
(propagation replay); at the end everything matches `analysis`. Respect `prefers-reduced-motion` (no auto-play).
`onSelect(componentId)` opens a drawer listing that component's signals (time, kind chip, text, "show line").
All colours from CSS tokens (use classes, not literal fills). Must handle 1–60 components, 0 edges, and
components with no cluster.

### 6.4 Investigate with Claude (`WR.ui.investigate.mount(sectionEl, getAnalysis, getInputs)`)
HolmesGPT-style: read-only tools over the pasted evidence; proposes remediation, never runs it.
- `const sample = await claude.use("sample")` — if `window.claude` missing or `null`: show a quiet note
  "Claude investigation is available when this page is opened in Claude." and keep the rest of the page.
- Before sending: run `WR.redact` over everything; show "N secrets redacted" and a `<details>` preview of the
  exact payload.
- `const lim = await sample.limits().catch(()=>null)`; if `lim?.tools`, agent mode with ≤ 6 tools:
  `list_components()`, `get_component_signals({componentId, kinds?, limit?})`, `search_evidence({query, source?})`,
  `get_changes()`, `get_dependencies({componentId})`, `get_budget()`; each returns small plain JSON (≤ 8 KB) from the
  current Analysis + redacted raw text, and appends a step line to the visible investigation log ("Read 24 signals
  for payments-api"). Else one-shot with a compact evidence pack (≤ 60 KB).
- Call `sample.json(prompt, {tools?, signal, onText, modelTier})` with modelTier select (Quick / Balanced /
  Deep → quick/default/complex, default Balanced). Ask for
  `{summary, rootCause:{componentId, category, statement, confidence}, evidenceChain:[{signalId, why}],
  ruledOut:[{hypothesis, why}], remediation:[{action, command, risk, needsApproval:true}], openQuestions:[]}`.
- Render the result as a card beside the engine's top hypothesis ("Claude's read" vs "Rule engine's read"),
  flag agreement/disagreement. Stop button (AbortController per call). Error codes handled per the sample
  contract: hide on `not_granted`/`sampling_disabled`/`not_declared`/`capability_*`; message + keep control on
  `rate_limited`/`session_expired`/`refused`/`empty_completion`/`invalid_json`/`upstream_error`; never retry in code.
  `tools_unavailable` → fall back to one-shot once (user click).

### 6.5 Observability stacks (`WR.stacks`, `WR.stackFit(traits, scale) → fit`)
Four columns: **Datadog**, **Grafana (self-hosted LGTM or Grafana Cloud)**, **OpenTelemetry + a backend of your
choice**, **Hosted cloud (Azure Monitor / Amazon / Google managed Prometheus)**. Rows: How this incident shows up ·
Correlating logs, traces and metrics · Multi-cluster view · AI-assisted diagnosis · Cost at your scale ·
Breaks down when. Scale inputs (`#scale-nodes`, `#scale-logs-gb`, `#scale-series`, `#scale-apm-hosts`) with
sensible defaults. `stackFit` returns per stack `{flags:[{level:'breaks'|'strain'|'ok', text, because, sourceIds}],
costLines:[{label, monthlyUsd|null, basis, sourceId}]}` driven by traits (multiCluster, highCardinalityLabels,
errorTracesMissing, logLinesPerMin, clusterCount) and scale. **Every factual figure carries a source
`{id, url, title, asOf}` from `research/verified.json`; anything not sourced renders with a "Reasoning" chip,
never as fact.** A price that was not verified renders as "See pricing page" + link, not a number.

### 6.6 KubeCon Europe 2026 (`WR.kubecon`)
Three groups: AI-assisted diagnosis · Observability · Multi-cluster visibility. Each item: title, who, kind chip
(Announced / Released / Talk / Docs), summary, "What to do with it", "Where this app uses it" (link to the
section anchor), sources (link + date). Items that are only session titles are labelled **Talk**, never
Announced. Collapsed by default to one line each; one click expands.

### 6.6b Data shapes for §6.5 and §6.6 (binding between the data module and the UI)
```
WR.kubecon = { asOf:'2026-10-06', event:{ name, dates, city, url },
  groups: [{ id:'ai'|'observability'|'multicluster', title, intro,
    items: [{ id, title, who, kind:'announced'|'released'|'talk'|'doc'|'documented-limit',
              summary, whatToDo, appUse:{ text, anchor:'#claude'|'#map'|'#causes'|'#rollback'|'#budget'|'#stacks' }|null,
              sources:[{ url, title, published }] }] }] }

WR.stacks = { asOf:'2026-10-06',
  sources: { [sourceId]: { url, title, asOf } },
  stacks: [{ id:'datadog'|'grafana'|'otel'|'hosted', name, tagline,
    rows: { shows, correlate, multicluster, ai }:  each { text, sourceIds:[], reasoning:bool },
    prices: [{ id, label, unit, usd:number|null, basis, sourceId }],    // usd null = not verified → "See pricing page"
    limits: [{ id, text, value, sourceId }] }] }

WR.stackFit(traits, scale) → { [stackId]: { verdict:'Good fit'|'Workable'|'Strained',
  flags:[{ level:'breaks'|'strain'|'ok', text, because, sourceIds:[], reasoning:bool }],
  costLines:[{ label, monthlyUsd:number|null, basis, sourceId|null }] } }
scale = { nodes, logsGbPerDay, activeSeries, apmHosts }   // defaults 40, 50, 500000, 20
```

### 6.7 Export brief
"Export brief" builds a Markdown incident brief (headline, severity, timeline, top 3 hypotheses with evidence,
recommended rollback + commands, budget numbers, open questions) and offers it via the `downloads` capability
(`claude.use("downloads")` → `save({filename:'incident-brief-<date>.md', data})`); if unavailable, a "Copy
brief" button (clipboard in the click handler, fallback: select a `<textarea>` with the text).
