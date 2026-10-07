/*
 * SRE War Room — sample incidents (WR.samples)
 *
 * Four complete incidents pasted the way an on-call engineer would paste them: kubectl tables with their real
 * column padding, kubectl describe excerpts, application logs in several encodings, OTLP / Jaeger / text
 * traces, Alertmanager payloads and helm-diff output. They are the app's demo content and the engine's test
 * corpus at the same time, so every pane of a sample tells the same story on the same clock.
 *
 * Shape (SPEC section 5):
 *   { id, title, blurb, context, logs, traces, alerts, helm, expected }
 *   context  — passed straight to WR.analyze (now, defaultTz, year, cluster, slo).
 *   expected — what a correct analysis should conclude. Fields:
 *     rootComponentName / rootComponentAlternates  name (not id) of the top hypothesis' component, and other
 *                                                  names that are also a correct reading of the evidence
 *     rootCluster (rootClusters)                   cluster(s) the root component may sit in
 *     category / categories                        SPEC's single answer, and every acceptable category
 *     recommendedKind / recommendedKinds           SPEC's single answer, and every acceptable rollback kind
 *     release, deployRevision, previousRevision    the Helm release the deploy evidence points at
 *     deployedAt                                   UTC instant Deploy.deployedAt must equal once defaultTz is
 *                                                  applied to the zone-less helm history time
 *     firstErrorAround                             UTC of the first error visible in the panes (relative
 *                                                  event ages make this fuzzy by up to a minute)
 *     multiCluster, failingClusters, healthyClusters
 *     notTopComponentName, redHerringRelease       (cert-expiry) the release that must not be blamed
 *
 * Time zones are deliberately mixed, because real pastes are:
 *   bad-deploy-oom       alerts in UTC, app JSON logs at +02:00, kubectl ages relative to context.now,
 *                        helm history in zone-less local time (defaultTz +02:00)
 *   coredns-outage       everything UTC (defaultTz Z); this is the only sample with klog / journalctl stamps
 *   cert-expiry          helm history zone-less at -04:00; every other stamp carries its zone
 *   db-conn-exhaustion   helm history zone-less at -07:00; every other stamp carries its zone
 *
 * Budgets (checked by tests/samples.test.mjs): 60-200 log lines, 20-80 spans, 3-8 alerts, 30-120 helm diff
 * lines, under 60 KiB of pane text per sample. The panes contain exactly one fake credential
 * (DB_PASSWORD in the db-conn-exhaustion ConfigMap diff) so redaction has something to find; keep it that way.
 * When editing a pane, move the matching times in the other panes too.
 */
(function (WR) {
  'use strict';

  // ----------------------------------------------------------------------------------------------------
  // 1. bad-deploy-oom — Checkout failing after a payments release
  // ----------------------------------------------------------------------------------------------------

  const S1_LOGS = `# cluster: prod-eu-west
$ kubectl --context prod-eu-west -n shop get pods
NAME                            READY   STATUS             RESTARTS        AGE
checkout-api-6f9c8d7b5-4wq8z    1/1     Running            0               2d7h
checkout-api-6f9c8d7b5-r2xvn    1/1     Running            0               2d7h
frontend-7b5d9c6f84-8jkpl       1/1     Running            0               5d12h
frontend-7b5d9c6f84-tq7mz       1/1     Running            0               5d12h
payments-api-5c8d7f9b4d-h7x2q   0/1     CrashLoopBackOff   6 (2m28s ago)   24m
payments-api-5c8d7f9b4d-q9tmw   0/1     CrashLoopBackOff   6 (2m53s ago)   24m
payments-api-5c8d7f9b4d-zl4rk   0/1     CrashLoopBackOff   6 (72s ago)     24m

$ kubectl --context prod-eu-west -n shop get events --sort-by=.lastTimestamp
LAST SEEN   TYPE      REASON              OBJECT                               MESSAGE
24m         Normal    ScalingReplicaSet   deployment/payments-api              Scaled up replica set payments-api-5c8d7f9b4d to 1
24m         Normal    SuccessfulCreate    replicaset/payments-api-5c8d7f9b4d   Created pod: payments-api-5c8d7f9b4d-h7x2q
24m         Normal    Scheduled           pod/payments-api-5c8d7f9b4d-h7x2q    Successfully assigned shop/payments-api-5c8d7f9b4d-h7x2q to aks-apps-38291746-vmss000004
24m         Normal    Pulled              pod/payments-api-5c8d7f9b4d-h7x2q    Successfully pulled image "registry.example.com/shop/payments-api:2.14.0" in 3.871s (3.871s including waiting). Image size: 41823104 bytes.
24m         Normal    ScalingReplicaSet   deployment/payments-api              Scaled down replica set payments-api-7d9f8b6c5 to 2 from 3
24m         Normal    Killing             pod/payments-api-7d9f8b6c5-x2k4p     Stopping container payments-api
24m         Normal    ScalingReplicaSet   deployment/payments-api              Scaled up replica set payments-api-5c8d7f9b4d to 2 from 1
24m         Normal    SuccessfulCreate    replicaset/payments-api-5c8d7f9b4d   Created pod: payments-api-5c8d7f9b4d-q9tmw
24m         Normal    Scheduled           pod/payments-api-5c8d7f9b4d-q9tmw    Successfully assigned shop/payments-api-5c8d7f9b4d-q9tmw to aks-apps-38291746-vmss000002
24m         Normal    Pulled              pod/payments-api-5c8d7f9b4d-q9tmw    Successfully pulled image "registry.example.com/shop/payments-api:2.14.0" in 4.412s (4.412s including waiting). Image size: 41823104 bytes.
24m         Normal    ScalingReplicaSet   deployment/payments-api              Scaled down replica set payments-api-7d9f8b6c5 to 1 from 2
24m         Normal    Killing             pod/payments-api-7d9f8b6c5-bv8hn     Stopping container payments-api
24m         Normal    ScalingReplicaSet   deployment/payments-api              Scaled up replica set payments-api-5c8d7f9b4d to 3 from 2
24m         Normal    SuccessfulCreate    replicaset/payments-api-5c8d7f9b4d   Created pod: payments-api-5c8d7f9b4d-zl4rk
24m         Normal    Scheduled           pod/payments-api-5c8d7f9b4d-zl4rk    Successfully assigned shop/payments-api-5c8d7f9b4d-zl4rk to aks-apps-38291746-vmss000007
24m         Normal    Pulled              pod/payments-api-5c8d7f9b4d-zl4rk    Successfully pulled image "registry.example.com/shop/payments-api:2.14.0" in 4.906s (4.906s including waiting). Image size: 41823104 bytes.
24m         Normal    ScalingReplicaSet   deployment/payments-api              Scaled down replica set payments-api-7d9f8b6c5 to 0 from 1
24m         Normal    Killing             pod/payments-api-7d9f8b6c5-m5wqs     Stopping container payments-api
4m21s       Normal    Created             pod/payments-api-5c8d7f9b4d-q9tmw    Created container: payments-api
4m20s       Normal    Started             pod/payments-api-5c8d7f9b4d-q9tmw    Started container payments-api
4m3s        Normal    Created             pod/payments-api-5c8d7f9b4d-h7x2q    Created container: payments-api
4m2s        Normal    Started             pod/payments-api-5c8d7f9b4d-h7x2q    Started container payments-api
2m56s       Warning   Unhealthy           pod/payments-api-5c8d7f9b4d-q9tmw    Readiness probe failed: Get "http://10.244.1.19:8080/readyz": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
2m54s       Normal    Created             pod/payments-api-5c8d7f9b4d-zl4rk    Created container: payments-api
2m53s       Normal    Started             pod/payments-api-5c8d7f9b4d-zl4rk    Started container payments-api
2m31s       Warning   Unhealthy           pod/payments-api-5c8d7f9b4d-h7x2q    Readiness probe failed: Get "http://10.244.3.27:8080/readyz": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
75s         Warning   Unhealthy           pod/payments-api-5c8d7f9b4d-zl4rk    Readiness probe failed: Get "http://10.244.5.44:8080/readyz": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
32s         Warning   BackOff             pod/payments-api-5c8d7f9b4d-q9tmw    Back-off restarting failed container payments-api in pod payments-api-5c8d7f9b4d-q9tmw_shop(cd6c1861-44a0-4f59-baf2-8676e3e51367)
31s         Warning   BackOff             pod/payments-api-5c8d7f9b4d-zl4rk    Back-off restarting failed container payments-api in pod payments-api-5c8d7f9b4d-zl4rk_shop(0724245d-6d14-453d-be5a-eb6dcf8f09b2)
16s         Warning   BackOff             pod/payments-api-5c8d7f9b4d-h7x2q    Back-off restarting failed container payments-api in pod payments-api-5c8d7f9b4d-h7x2q_shop(2415af9d-a521-4a8d-a87c-f894a817c898)

$ kubectl --context prod-eu-west get events -A --field-selector reason=OOMKilling --sort-by=.lastTimestamp | head -n 5
NAMESPACE   LAST SEEN   TYPE      REASON       OBJECT                              MESSAGE
default     22m         Warning   OOMKilling   node/aks-apps-38291746-vmss000004   Memory cgroup out of memory: Killed process 29629 (payments-api) total-vm:1918527kB, anon-rss:258394kB, file-rss:11675kB, shmem-rss:0kB, UID:10001 pgtables:784kB oom_score_adj:985
default     21m         Warning   OOMKilling   node/aks-apps-38291746-vmss000002   Memory cgroup out of memory: Killed process 30806 (payments-api) total-vm:1926414kB, anon-rss:258642kB, file-rss:12684kB, shmem-rss:0kB, UID:10001 pgtables:827kB oom_score_adj:985
default     21m         Warning   OOMKilling   node/aks-apps-38291746-vmss000007   Memory cgroup out of memory: Killed process 32659 (payments-api) total-vm:1905060kB, anon-rss:257385kB, file-rss:10775kB, shmem-rss:0kB, UID:10001 pgtables:826kB oom_score_adj:985
default     20m         Warning   OOMKilling   node/aks-apps-38291746-vmss000004   Memory cgroup out of memory: Killed process 34416 (payments-api) total-vm:1939873kB, anon-rss:257341kB, file-rss:11888kB, shmem-rss:0kB, UID:10001 pgtables:791kB oom_score_adj:985

$ kubectl --context prod-eu-west -n shop describe pod payments-api-5c8d7f9b4d-h7x2q | sed -n '1,14p;/^Containers:/,/^Conditions:/p;/^Events:/,$p'
Name:             payments-api-5c8d7f9b4d-h7x2q
Namespace:        shop
Priority:         0
Service Account:  payments-api
Node:             aks-apps-38291746-vmss000004/10.224.0.37
Start Time:       Mon, 05 Oct 2026 23:47:06 +0200
Labels:           app.kubernetes.io/instance=payments
                  app.kubernetes.io/name=payments-api
                  pod-template-hash=5c8d7f9b4d
Annotations:      <none>
Status:           Running
IP:               10.244.3.27
IPs:
  IP:           10.244.3.27
Containers:
  payments-api:
    Image:          registry.example.com/shop/payments-api:2.14.0
    Port:           8080/TCP
    Host Port:      0/TCP
    State:          Waiting
      Reason:       CrashLoopBackOff
    Last State:     Terminated
      Reason:       OOMKilled
      Exit Code:    137
      Started:      Tue, 06 Oct 2026 00:07:57 +0200
      Finished:     Tue, 06 Oct 2026 00:09:32 +0200
    Ready:          False
    Restart Count:  6
    Limits:
      cpu:     1
      memory:  256Mi
    Requests:
      cpu:      250m
      memory:   256Mi
    Liveness:   http-get http://:http/healthz delay=10s timeout=2s period=10s #success=1 #failure=3
    Readiness:  http-get http://:http/readyz delay=5s timeout=2s period=5s #success=1 #failure=3
    Environment:
      GOMEMLIMIT:                     460MiB
      PAYMENTS_DB_HOST:               postgres.data.svc.cluster.local
      PAYMENTS_CACHE_WARMUP:          true
      PAYMENTS_CACHE_WARMUP_ENTRIES:  1200000
Conditions:
Events:
  Type     Reason     Age                   From               Message
  ----     ------     ---                   ----               -------
  Normal   Scheduled  24m                   default-scheduler  Successfully assigned shop/payments-api-5c8d7f9b4d-h7x2q to aks-apps-38291746-vmss000004
  Normal   Pulled     24m                   kubelet            Successfully pulled image "registry.example.com/shop/payments-api:2.14.0" in 3.871s (3.871s including waiting). Image size: 41823104 bytes.
  Normal   Pulled     4m3s (x6 over 21m)    kubelet            Container image "registry.example.com/shop/payments-api:2.14.0" already present on machine
  Normal   Created    4m3s (x7 over 24m)    kubelet            Created container: payments-api
  Normal   Started    4m3s (x7 over 24m)    kubelet            Started container payments-api
  Warning  Unhealthy  2m31s (x13 over 22m)  kubelet            Readiness probe failed: Get "http://10.244.3.27:8080/readyz": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
  Warning  BackOff    21s (x31 over 22m)    kubelet            Back-off restarting failed container payments-api in pod payments-api-5c8d7f9b4d-h7x2q_shop(2415af9d-a521-4a8d-a87c-f894a817c898)

$ kubectl --context prod-eu-west -n shop logs payments-api-5c8d7f9b4d-h7x2q --previous
{"level":"info","ts":"2026-10-06T00:07:57.212+02:00","caller":"cmd/main.go:58","msg":"starting payments-api","service":"payments-api","version":"2.14.0","go":"go1.25.1","gomemlimit":"460MiB"}
{"level":"info","ts":"2026-10-06T00:07:57.249+02:00","caller":"store/postgres.go:41","msg":"connected to postgres","service":"payments-api","host":"postgres.data.svc.cluster.local","db":"payments","pool_max":25}
{"level":"info","ts":"2026-10-06T00:07:57.301+02:00","caller":"cache/warmup.go:77","msg":"cache warm-up started","service":"payments-api","entries_target":1200000,"source":"authorizations_v2"}
{"level":"info","ts":"2026-10-06T00:07:57.388+02:00","caller":"server/http.go:33","msg":"listening","service":"payments-api","addr":":8080"}
{"level":"info","ts":"2026-10-06T00:08:28.415+02:00","caller":"cache/warmup.go:112","msg":"cache warm-up progress","service":"payments-api","entries_loaded":400000,"heap_inuse_mb":118,"rss_mb":151}
{"level":"info","ts":"2026-10-06T00:08:59.038+02:00","caller":"cache/warmup.go:112","msg":"cache warm-up progress","service":"payments-api","entries_loaded":800000,"heap_inuse_mb":187,"rss_mb":214}
{"level":"warn","ts":"2026-10-06T00:09:18.796+02:00","caller":"runtime/memwatch.go:40","msg":"memory usage above 85% of cgroup limit","service":"payments-api","rss_mb":224,"limit_mb":256}
{"level":"warn","ts":"2026-10-06T00:09:23.888+02:00","caller":"middleware/log.go:61","msg":"slow request","service":"payments-api","route":"POST /v1/authorize","status":200,"latency_ms":2614,"gc_cpu_fraction":0.41}
{"level":"warn","ts":"2026-10-06T00:09:29.710+02:00","caller":"runtime/memwatch.go:40","msg":"memory usage above 95% of cgroup limit","service":"payments-api","rss_mb":247,"limit_mb":256}

$ stern --context prod-eu-west -n shop checkout-api --since 30m --exclude healthz
checkout-api-6f9c8d7b5-4wq8z checkout-api {"level":"info","message":"checkout completed","timestamp":"2026-10-05T23:44:31.356+02:00","service":"checkout-api","order_id":"ord_PGXJ9V","status":200,"latency_ms":214,"trace_id":"dc41a28668cf61637c27b87c598b680b"}
checkout-api-6f9c8d7b5-r2xvn checkout-api {"level":"info","message":"checkout completed","timestamp":"2026-10-05T23:46:58.611+02:00","service":"checkout-api","order_id":"ord_5SHQDZ","status":200,"latency_ms":188,"trace_id":"bba908ef60462ff748088d015da4af1c"}
checkout-api-6f9c8d7b5-r2xvn checkout-api {"level":"info","message":"checkout completed","timestamp":"2026-10-05T23:49:34.432+02:00","service":"checkout-api","order_id":"ord_6WFP7R","status":200,"latency_ms":3012,"trace_id":"a519e4c8b76e57dd9b57d5366ecbd563"}
checkout-api-6f9c8d7b5-4wq8z checkout-api {"level":"error","message":"payment authorization failed","timestamp":"2026-10-05T23:49:52.099+02:00","service":"checkout-api","order_id":"ord_SCDZR9","upstream":"payments-api","error":"read ECONNRESET","status":503,"latency_ms":1964,"trace_id":"299f7d3f4c350e1620c78612fabeab0d"}
checkout-api-6f9c8d7b5-r2xvn checkout-api {"level":"error","message":"payment authorization failed","timestamp":"2026-10-05T23:50:09.120+02:00","service":"checkout-api","order_id":"ord_MC4NFX","upstream":"payments-api","error":"socket hang up","status":503,"latency_ms":1288,"trace_id":"32a9e9346756a54823fc751f1ebddc42"}
checkout-api-6f9c8d7b5-4wq8z checkout-api {"level":"error","message":"payment authorization failed","timestamp":"2026-10-05T23:50:16.031+02:00","service":"checkout-api","order_id":"ord_8KQLSJ","upstream":"payments-api","error":"timeout of 2000ms exceeded","status":503,"latency_ms":2018,"trace_id":"54d8e467cccb793141f28cda7840e327"}
checkout-api-6f9c8d7b5-4wq8z checkout-api {"level":"info","message":"checkout completed","timestamp":"2026-10-05T23:50:58.540+02:00","service":"checkout-api","order_id":"ord_XBWJ7H","status":200,"latency_ms":559,"trace_id":"dae0260ce70ba61f91c4f0ef234d0742"}
checkout-api-6f9c8d7b5-r2xvn checkout-api {"level":"info","message":"checkout completed","timestamp":"2026-10-05T23:53:34.002+02:00","service":"checkout-api","order_id":"ord_RX7BBQ","status":200,"latency_ms":439,"trace_id":"809d72b5991683e07998ac72114f79f2"}
checkout-api-6f9c8d7b5-r2xvn checkout-api {"level":"error","message":"payment authorization failed","timestamp":"2026-10-05T23:54:10.572+02:00","service":"checkout-api","order_id":"ord_VPLC75","upstream":"payments-api","error":"connect ECONNREFUSED 10.0.142.17:8080","status":503,"latency_ms":2,"trace_id":"9cca576488d4a08d954aa629381328b8"}
checkout-api-6f9c8d7b5-4wq8z checkout-api {"level":"warn","message":"circuit breaker opened","timestamp":"2026-10-05T23:54:27.782+02:00","service":"checkout-api","upstream":"payments-api","failures":12,"window":"30s"}
checkout-api-6f9c8d7b5-4wq8z checkout-api {"level":"error","message":"payment authorization failed","timestamp":"2026-10-05T23:55:26.202+02:00","service":"checkout-api","order_id":"ord_N86MPR","upstream":"payments-api","error":"timeout of 2000ms exceeded","status":503,"latency_ms":2018,"trace_id":"cd97bbe528c0754499ec24bdae996e19"}
checkout-api-6f9c8d7b5-r2xvn checkout-api {"level":"error","message":"payment authorization failed","timestamp":"2026-10-05T23:56:39.124+02:00","service":"checkout-api","order_id":"ord_7H7K4N","upstream":"payments-api","error":"connect ECONNREFUSED 10.0.142.17:8080","status":503,"latency_ms":2,"trace_id":"40e6899ff41260833a07fb4e5e26728c"}
checkout-api-6f9c8d7b5-r2xvn checkout-api {"level":"info","message":"checkout completed","timestamp":"2026-10-05T23:57:49.945+02:00","service":"checkout-api","order_id":"ord_JNDTDG","status":200,"latency_ms":196,"trace_id":"9a478eac81d97d409a150e79d84b7002"}
checkout-api-6f9c8d7b5-r2xvn checkout-api {"level":"error","message":"payment authorization failed","timestamp":"2026-10-05T23:58:33.149+02:00","service":"checkout-api","order_id":"ord_QZWT2T","upstream":"payments-api","error":"timeout of 2000ms exceeded","status":503,"latency_ms":2018,"trace_id":"2fb1fc12d3af47eb515d520adbdeb670"}
checkout-api-6f9c8d7b5-4wq8z checkout-api {"level":"error","message":"payment authorization failed","timestamp":"2026-10-05T23:59:48.998+02:00","service":"checkout-api","order_id":"ord_C89ZVV","upstream":"payments-api","error":"connect ECONNREFUSED 10.0.142.17:8080","status":503,"latency_ms":5,"trace_id":"9423f9ed90ac10e1f6d31d8b3f93b05e"}
checkout-api-6f9c8d7b5-4wq8z checkout-api {"level":"error","message":"payment authorization failed","timestamp":"2026-10-06T00:00:28.142+02:00","service":"checkout-api","order_id":"ord_GM965S","upstream":"payments-api","error":"connect ECONNREFUSED 10.0.142.17:8080","status":503,"latency_ms":8,"trace_id":"53753737ff37e6d570b19b718cc855fb"}
checkout-api-6f9c8d7b5-4wq8z checkout-api {"level":"error","message":"payment authorization failed","timestamp":"2026-10-06T00:01:10.180+02:00","service":"checkout-api","order_id":"ord_RJSWCN","upstream":"payments-api","error":"connect ECONNREFUSED 10.0.142.17:8080","status":503,"latency_ms":8,"trace_id":"f9eb9fe698001c49268132a77c9ee94d"}
checkout-api-6f9c8d7b5-4wq8z checkout-api {"level":"error","message":"payment authorization failed","timestamp":"2026-10-06T00:02:29.953+02:00","service":"checkout-api","order_id":"ord_D6VBPF","upstream":"payments-api","error":"timeout of 2000ms exceeded","status":503,"latency_ms":2018,"trace_id":"d61b386279738c0cef0f70eabfc8fb87"}
checkout-api-6f9c8d7b5-r2xvn checkout-api {"level":"info","message":"checkout completed","timestamp":"2026-10-06T00:03:39.995+02:00","service":"checkout-api","order_id":"ord_S6GZCG","status":200,"latency_ms":436,"trace_id":"d0f2c3bb012ea98b142d5b8797207c99"}
checkout-api-6f9c8d7b5-4wq8z checkout-api {"level":"error","message":"payment authorization failed","timestamp":"2026-10-06T00:04:19.029+02:00","service":"checkout-api","order_id":"ord_BPBCMV","upstream":"payments-api","error":"connect ECONNREFUSED 10.0.142.17:8080","status":503,"latency_ms":5,"trace_id":"32f7376ee6882bdcf826b678c685ad80"}
checkout-api-6f9c8d7b5-4wq8z checkout-api {"level":"error","message":"payment authorization failed","timestamp":"2026-10-06T00:04:57.734+02:00","service":"checkout-api","order_id":"ord_TX4HVM","upstream":"payments-api","error":"connect ECONNREFUSED 10.0.142.17:8080","status":503,"latency_ms":4,"trace_id":"43df985d19f2e1f210c0034a6675f46d"}
checkout-api-6f9c8d7b5-r2xvn checkout-api {"level":"error","message":"payment authorization failed","timestamp":"2026-10-06T00:05:32.981+02:00","service":"checkout-api","order_id":"ord_9G4SWL","upstream":"payments-api","error":"connect ECONNREFUSED 10.0.142.17:8080","status":503,"latency_ms":3,"trace_id":"85eafc8bbca0810a099e42ecb7a6a558"}
checkout-api-6f9c8d7b5-r2xvn checkout-api {"level":"error","message":"payment authorization failed","timestamp":"2026-10-06T00:06:11.674+02:00","service":"checkout-api","order_id":"ord_JZ252P","upstream":"payments-api","error":"connect ECONNREFUSED 10.0.142.17:8080","status":503,"latency_ms":8,"trace_id":"b19c317b627ff54918018316e88935b9"}
checkout-api-6f9c8d7b5-r2xvn checkout-api {"level":"error","message":"payment authorization failed","timestamp":"2026-10-06T00:06:48.704+02:00","service":"checkout-api","order_id":"ord_7HNMCB","upstream":"payments-api","error":"connect ECONNREFUSED 10.0.142.17:8080","status":503,"latency_ms":6,"trace_id":"f6b3b346eaf09da6d5c3b736869f683c"}
checkout-api-6f9c8d7b5-r2xvn checkout-api {"level":"error","message":"payment authorization failed","timestamp":"2026-10-06T00:07:27.533+02:00","service":"checkout-api","order_id":"ord_D9794P","upstream":"payments-api","error":"connect ECONNREFUSED 10.0.142.17:8080","status":503,"latency_ms":2,"trace_id":"ea4573d7ff791c9252ee3135e457c74e"}
checkout-api-6f9c8d7b5-r2xvn checkout-api {"level":"info","message":"checkout completed","timestamp":"2026-10-06T00:10:16.650+02:00","service":"checkout-api","order_id":"ord_Q258XC","status":200,"latency_ms":320,"trace_id":"92e926ec685a79af8f3980119df89a33"}
checkout-api-6f9c8d7b5-r2xvn checkout-api {"level":"error","message":"payment authorization failed","timestamp":"2026-10-06T00:10:57.458+02:00","service":"checkout-api","order_id":"ord_KQ5ZW9","upstream":"payments-api","error":"connect ECONNREFUSED 10.0.142.17:8080","status":503,"latency_ms":4,"trace_id":"c3171cbca7757eb96ff9dd06072bd03b"}
checkout-api-6f9c8d7b5-r2xvn checkout-api {"level":"error","message":"payment authorization failed","timestamp":"2026-10-06T00:11:38.859+02:00","service":"checkout-api","order_id":"ord_B285LJ","upstream":"payments-api","error":"connect ECONNREFUSED 10.0.142.17:8080","status":503,"latency_ms":2,"trace_id":"9216f63c89e0a9c1002713b3c5a49c59"}

$ kubectl --context prod-eu-west -n shop logs -l app.kubernetes.io/name=frontend --since=30m --prefix | grep -v '"level":"info"'
[pod/frontend-7b5d9c6f84-8jkpl/frontend] {"level":"warn","time":"2026-10-05T23:49:52.119+02:00","pid":1,"hostname":"frontend-7b5d9c6f84-8jkpl","service":"frontend","msg":"checkout failed","path":"/api/checkout","upstream":"checkout-api","status":503,"latency_ms":1989,"trace_id":"299f7d3f4c350e1620c78612fabeab0d"}
[pod/frontend-7b5d9c6f84-tq7mz/frontend] {"level":"warn","time":"2026-10-05T23:50:16.052+02:00","pid":1,"hostname":"frontend-7b5d9c6f84-tq7mz","service":"frontend","msg":"checkout failed","path":"/api/checkout","upstream":"checkout-api","status":503,"latency_ms":2049}
[pod/frontend-7b5d9c6f84-8jkpl/frontend] {"level":"warn","time":"2026-10-05T23:54:10.586+02:00","pid":1,"hostname":"frontend-7b5d9c6f84-8jkpl","service":"frontend","msg":"checkout failed","path":"/api/checkout","upstream":"checkout-api","status":503,"latency_ms":29,"trace_id":"9cca576488d4a08d954aa629381328b8"}
[pod/frontend-7b5d9c6f84-tq7mz/frontend] {"level":"warn","time":"2026-10-06T00:04:57.748+02:00","pid":1,"hostname":"frontend-7b5d9c6f84-tq7mz","service":"frontend","msg":"checkout failed","path":"/api/checkout","upstream":"checkout-api","status":503,"latency_ms":27,"trace_id":"43df985d19f2e1f210c0034a6675f46d"}
[pod/frontend-7b5d9c6f84-8jkpl/frontend] {"level":"warn","time":"2026-10-06T00:11:38.873+02:00","pid":1,"hostname":"frontend-7b5d9c6f84-8jkpl","service":"frontend","msg":"checkout failed","path":"/api/checkout","upstream":"checkout-api","status":503,"latency_ms":32,"trace_id":"9216f63c89e0a9c1002713b3c5a49c59"}

$ kubectl --context prod-eu-west -n ingress-nginx logs deploy/ingress-nginx-controller --since=30m --prefix --timestamps | grep 'POST /api/checkout' | tail -n 3
[pod/ingress-nginx-controller-6c9f8d4b7-7mlxz/controller] 2026-10-05T22:04:57.764907358Z 10.224.0.37 - - [05/Oct/2026:22:04:57 +0000] "POST /api/checkout HTTP/2.0" 503 87 "https://shop.example.com/cart" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36" 628 0.025 [shop-frontend-3000] [] 10.244.1.8:3000 87 0.025 503 fa44081918d16948066f14e7ba70ee25
[pod/ingress-nginx-controller-6c9f8d4b7-7mlxz/controller] 2026-10-05T22:10:57.488665995Z 10.224.0.4 - - [05/Oct/2026:22:10:57 +0000] "POST /api/checkout HTTP/2.0" 503 87 "https://shop.example.com/cart" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36" 606 0.023 [shop-frontend-3000] [] 10.244.4.8:3000 87 0.023 503 8a9e19ce7548e01ec6a60f94874aed4d
[pod/ingress-nginx-controller-6c9f8d4b7-7mlxz/controller] 2026-10-05T22:11:38.889550806Z 10.224.0.17 - - [05/Oct/2026:22:11:38 +0000] "POST /api/checkout HTTP/2.0" 503 87 "https://shop.example.com/cart" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36" 568 0.036 [shop-frontend-3000] [] 10.244.1.8:3000 87 0.036 503 b7ccb7f30ea53bbd0e95b4b4e8f4939e

# cluster: prod-us-east
$ kubectl --context prod-us-east -n shop get pods
NAME                            READY   STATUS    RESTARTS   AGE
checkout-api-58d6c9f7b4-n4wzb   1/1     Running   0          9d
checkout-api-58d6c9f7b4-vq7lh   1/1     Running   0          9d
frontend-7b5d9c6f84-xk2vd       1/1     Running   0          12d
frontend-7b5d9c6f84-zb6nf       1/1     Running   0          12d
payments-api-7d9f8b6c5-c2hbm    1/1     Running   0          5d7h
payments-api-7d9f8b6c5-g4ntd    1/1     Running   0          5d7h
payments-api-7d9f8b6c5-w8rxs    1/1     Running   0          5d7h
$ kubectl --context prod-us-east -n shop logs payments-api-7d9f8b6c5-g4ntd --since=15m | tail -n 3
{"level":"info","ts":"2026-10-05T21:58:40.258Z","caller":"server/handler.go:88","msg":"authorization approved","service":"payments-api","route":"POST /v1/authorize","status":200,"latency_ms":74,"trace_id":"2b7639f3b9e03c7f75f15ab9ae740bbc"}
{"level":"info","ts":"2026-10-05T22:04:17.902Z","caller":"server/handler.go:88","msg":"authorization approved","service":"payments-api","route":"POST /v1/authorize","status":200,"latency_ms":111,"trace_id":"a8ae198f65c7b739fc5c68827d3dcda6"}
{"level":"info","ts":"2026-10-05T22:11:02.517Z","caller":"server/handler.go:88","msg":"authorization approved","service":"payments-api","route":"POST /v1/authorize","status":200,"latency_ms":81,"trace_id":"e80fa2741f47f684ff6afd1b7930b2a9"}`;

  const S1_TRACES = `{
  "resourceSpans": [
    {
      "resource": {
        "attributes": [
          {"key":"service.name","value":{"stringValue":"frontend"}},
          {"key":"service.version","value":{"stringValue":"5.2.0"}},
          {"key":"k8s.cluster.name","value":{"stringValue":"prod-eu-west"}},
          {"key":"k8s.namespace.name","value":{"stringValue":"shop"}},
          {"key":"k8s.pod.name","value":{"stringValue":"frontend-7b5d9c6f84-8jkpl"}}
        ]
      },
      "scopeSpans": [
        {
          "scope": {"name":"@opentelemetry/instrumentation-http","version":"0.205.0"},
          "spans": [
            {"traceId":"dc41a28668cf61637c27b87c598b680b","spanId":"3455edca8a4a1732","name":"POST /api/checkout","kind":2,"startTimeUnixNano":"1791236671120714490","endTimeUnixNano":"1791236671266199021","attributes":[{"key":"http.request.method","value":{"stringValue":"POST"}},{"key":"http.response.status_code","value":{"intValue":"200"}}],"status":{}},
            {"traceId":"dc41a28668cf61637c27b87c598b680b","spanId":"2ae4e4469fe99e0f","parentSpanId":"3455edca8a4a1732","name":"POST","kind":3,"startTimeUnixNano":"1791236671123387876","endTimeUnixNano":"1791236671260702295","attributes":[{"key":"http.request.method","value":{"stringValue":"POST"}},{"key":"server.address","value":{"stringValue":"checkout-api.shop.svc.cluster.local"}},{"key":"peer.service","value":{"stringValue":"checkout-api"}},{"key":"http.response.status_code","value":{"intValue":"200"}}],"status":{}},
            {"traceId":"299f7d3f4c350e1620c78612fabeab0d","spanId":"0ae7729e971f767a","name":"POST /api/checkout","kind":2,"startTimeUnixNano":"1791236990109220561","endTimeUnixNano":"1791236992085789297","attributes":[{"key":"http.request.method","value":{"stringValue":"POST"}},{"key":"http.response.status_code","value":{"intValue":"503"}}],"status":{"code":2,"message":"checkout-api responded 503"}},
            {"traceId":"299f7d3f4c350e1620c78612fabeab0d","spanId":"0d37c233de8b09a9","parentSpanId":"0ae7729e971f767a","name":"POST","kind":3,"startTimeUnixNano":"1791236990112168812","endTimeUnixNano":"1791236992079132356","attributes":[{"key":"http.request.method","value":{"stringValue":"POST"}},{"key":"server.address","value":{"stringValue":"checkout-api.shop.svc.cluster.local"}},{"key":"peer.service","value":{"stringValue":"checkout-api"}},{"key":"http.response.status_code","value":{"intValue":"503"}}],"status":{"code":2,"message":"HTTP 503"}},
            {"traceId":"9cca576488d4a08d954aa629381328b8","spanId":"51b7c8c0431d4c00","name":"POST /api/checkout","kind":2,"startTimeUnixNano":"1791237250542882517","endTimeUnixNano":"1791237250581917000","attributes":[{"key":"http.request.method","value":{"stringValue":"POST"}},{"key":"http.response.status_code","value":{"intValue":"503"}}],"status":{"code":2,"message":"checkout-api responded 503"}},
            {"traceId":"9cca576488d4a08d954aa629381328b8","spanId":"dfbf7a72af474d74","parentSpanId":"51b7c8c0431d4c00","name":"POST","kind":3,"startTimeUnixNano":"1791237250545686147","endTimeUnixNano":"1791237250575616442","attributes":[{"key":"http.request.method","value":{"stringValue":"POST"}},{"key":"server.address","value":{"stringValue":"checkout-api.shop.svc.cluster.local"}},{"key":"peer.service","value":{"stringValue":"checkout-api"}},{"key":"http.response.status_code","value":{"intValue":"503"}}],"status":{"code":2,"message":"HTTP 503"}},
            {"traceId":"9216f63c89e0a9c1002713b3c5a49c59","spanId":"69256ac98ec701fc","name":"POST /api/checkout","kind":2,"startTimeUnixNano":"1791238298829409782","endTimeUnixNano":"1791238298881754224","attributes":[{"key":"http.request.method","value":{"stringValue":"POST"}},{"key":"http.response.status_code","value":{"intValue":"503"}}],"status":{"code":2,"message":"checkout-api responded 503"}},
            {"traceId":"9216f63c89e0a9c1002713b3c5a49c59","spanId":"966d0a6c805abb44","parentSpanId":"69256ac98ec701fc","name":"POST","kind":3,"startTimeUnixNano":"1791238298832974067","endTimeUnixNano":"1791238298875675943","attributes":[{"key":"http.request.method","value":{"stringValue":"POST"}},{"key":"server.address","value":{"stringValue":"checkout-api.shop.svc.cluster.local"}},{"key":"peer.service","value":{"stringValue":"checkout-api"}},{"key":"http.response.status_code","value":{"intValue":"503"}}],"status":{"code":2,"message":"HTTP 503"}}
          ]
        }
      ]
    },
    {
      "resource": {
        "attributes": [
          {"key":"service.name","value":{"stringValue":"checkout-api"}},
          {"key":"service.version","value":{"stringValue":"3.7.1"}},
          {"key":"k8s.cluster.name","value":{"stringValue":"prod-eu-west"}},
          {"key":"k8s.namespace.name","value":{"stringValue":"shop"}},
          {"key":"k8s.pod.name","value":{"stringValue":"checkout-api-6f9c8d7b5-4wq8z"}}
        ]
      },
      "scopeSpans": [
        {
          "scope": {"name":"@opentelemetry/instrumentation-http","version":"0.205.0"},
          "spans": [
            {"traceId":"dc41a28668cf61637c27b87c598b680b","spanId":"f5c2e95815d49c57","parentSpanId":"2ae4e4469fe99e0f","name":"POST /v1/checkout","kind":2,"startTimeUnixNano":"1791236671125368063","endTimeUnixNano":"1791236671257496777","attributes":[{"key":"http.request.method","value":{"stringValue":"POST"}},{"key":"http.response.status_code","value":{"intValue":"200"}}],"status":{}},
            {"traceId":"dc41a28668cf61637c27b87c598b680b","spanId":"4f6b6e396ac4dec1","parentSpanId":"f5c2e95815d49c57","name":"POST","kind":3,"startTimeUnixNano":"1791236671138293213","endTimeUnixNano":"1791236671248014182","attributes":[{"key":"http.request.method","value":{"stringValue":"POST"}},{"key":"server.address","value":{"stringValue":"payments-api.shop.svc.cluster.local"}},{"key":"peer.service","value":{"stringValue":"payments-api"}},{"key":"http.response.status_code","value":{"intValue":"200"}}],"status":{}},
            {"traceId":"299f7d3f4c350e1620c78612fabeab0d","spanId":"bf14f8973c68ab3b","parentSpanId":"0d37c233de8b09a9","name":"POST /v1/checkout","kind":2,"startTimeUnixNano":"1791236990114794730","endTimeUnixNano":"1791236992078314987","attributes":[{"key":"http.request.method","value":{"stringValue":"POST"}},{"key":"http.response.status_code","value":{"intValue":"503"}}],"status":{"code":2,"message":"payment authorization failed"}},
            {"traceId":"299f7d3f4c350e1620c78612fabeab0d","spanId":"4fccb753bd5734a9","parentSpanId":"bf14f8973c68ab3b","name":"POST","kind":3,"startTimeUnixNano":"1791236990127029543","endTimeUnixNano":"1791236992058177539","attributes":[{"key":"http.request.method","value":{"stringValue":"POST"}},{"key":"server.address","value":{"stringValue":"payments-api.shop.svc.cluster.local"}},{"key":"peer.service","value":{"stringValue":"payments-api"}},{"key":"error.type","value":{"stringValue":"ECONNRESET"}}],"status":{"code":2,"message":"read ECONNRESET"}},
            {"traceId":"43df985d19f2e1f210c0034a6675f46d","spanId":"b3b1ecd93c689caf","parentSpanId":"6bd7751d9291deb9","name":"POST /v1/checkout","kind":2,"startTimeUnixNano":"1791237897709898833","endTimeUnixNano":"1791237897742449992","attributes":[{"key":"http.request.method","value":{"stringValue":"POST"}},{"key":"http.response.status_code","value":{"intValue":"503"}}],"status":{"code":2,"message":"payment authorization failed"}},
            {"traceId":"43df985d19f2e1f210c0034a6675f46d","spanId":"842252f3cae0d233","parentSpanId":"b3b1ecd93c689caf","name":"POST","kind":3,"startTimeUnixNano":"1791237897722006539","endTimeUnixNano":"1791237897726785404","attributes":[{"key":"http.request.method","value":{"stringValue":"POST"}},{"key":"server.address","value":{"stringValue":"payments-api.shop.svc.cluster.local"}},{"key":"peer.service","value":{"stringValue":"payments-api"}},{"key":"error.type","value":{"stringValue":"ECONNREFUSED"}}],"status":{"code":2,"message":"connect ECONNREFUSED 10.0.142.17:8080"}}
          ]
        },
        {
          "scope": {"name":"@opentelemetry/instrumentation-pg","version":"0.58.0"},
          "spans": [
            {"traceId":"dc41a28668cf61637c27b87c598b680b","spanId":"a61efdf3f264f41e","parentSpanId":"f5c2e95815d49c57","name":"SELECT carts","kind":3,"startTimeUnixNano":"1791236671127795900","endTimeUnixNano":"1791236671132314116","attributes":[{"key":"db.system","value":{"stringValue":"postgresql"}},{"key":"db.namespace","value":{"stringValue":"checkout"}}],"status":{}},
            {"traceId":"299f7d3f4c350e1620c78612fabeab0d","spanId":"925968177f089a5d","parentSpanId":"bf14f8973c68ab3b","name":"SELECT carts","kind":3,"startTimeUnixNano":"1791236990116021731","endTimeUnixNano":"1791236990123344425","attributes":[{"key":"db.system","value":{"stringValue":"postgresql"}},{"key":"db.namespace","value":{"stringValue":"checkout"}}],"status":{}},
            {"traceId":"43df985d19f2e1f210c0034a6675f46d","spanId":"9191d8a3f8ec74dd","parentSpanId":"b3b1ecd93c689caf","name":"SELECT carts","kind":3,"startTimeUnixNano":"1791237897711604343","endTimeUnixNano":"1791237897720040599","attributes":[{"key":"db.system","value":{"stringValue":"postgresql"}},{"key":"db.namespace","value":{"stringValue":"checkout"}}],"status":{}}
          ]
        }
      ]
    },
    {
      "resource": {
        "attributes": [
          {"key":"service.name","value":{"stringValue":"payments-api"}},
          {"key":"service.version","value":{"stringValue":"2.13.4"}},
          {"key":"k8s.cluster.name","value":{"stringValue":"prod-eu-west"}},
          {"key":"k8s.namespace.name","value":{"stringValue":"shop"}},
          {"key":"k8s.pod.name","value":{"stringValue":"payments-api-7d9f8b6c5-x2k4p"}}
        ]
      },
      "scopeSpans": [
        {
          "scope": {"name":"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp","version":"0.63.0"},
          "spans": [
            {"traceId":"dc41a28668cf61637c27b87c598b680b","spanId":"2787865ce3612f7c","parentSpanId":"4f6b6e396ac4dec1","name":"POST /v1/authorize","kind":2,"startTimeUnixNano":"1791236671141530814","endTimeUnixNano":"1791236671245936329","attributes":[{"key":"http.request.method","value":{"stringValue":"POST"}},{"key":"http.response.status_code","value":{"intValue":"200"}}],"status":{}}
          ]
        },
        {
          "scope": {"name":"github.com/exaring/otelpgx","version":"0.9.3"},
          "spans": [
            {"traceId":"dc41a28668cf61637c27b87c598b680b","spanId":"8d874ae45ba4afbc","parentSpanId":"2787865ce3612f7c","name":"INSERT authorizations","kind":3,"startTimeUnixNano":"1791236671144910764","endTimeUnixNano":"1791236671152886787","attributes":[{"key":"db.system","value":{"stringValue":"postgresql"}},{"key":"db.namespace","value":{"stringValue":"payments"}}],"status":{}}
          ]
        }
      ]
    },
    {
      "resource": {
        "attributes": [
          {"key":"service.name","value":{"stringValue":"frontend"}},
          {"key":"service.version","value":{"stringValue":"5.2.0"}},
          {"key":"k8s.cluster.name","value":{"stringValue":"prod-eu-west"}},
          {"key":"k8s.namespace.name","value":{"stringValue":"shop"}},
          {"key":"k8s.pod.name","value":{"stringValue":"frontend-7b5d9c6f84-tq7mz"}}
        ]
      },
      "scopeSpans": [
        {
          "scope": {"name":"@opentelemetry/instrumentation-http","version":"0.205.0"},
          "spans": [
            {"traceId":"a519e4c8b76e57dd9b57d5366ecbd563","spanId":"a5af61d723c01af3","name":"POST /api/checkout","kind":2,"startTimeUnixNano":"1791236971402119984","endTimeUnixNano":"1791236974325435337","attributes":[{"key":"http.request.method","value":{"stringValue":"POST"}},{"key":"http.response.status_code","value":{"intValue":"200"}}],"status":{}},
            {"traceId":"a519e4c8b76e57dd9b57d5366ecbd563","spanId":"a4b5b609d2aa74bd","parentSpanId":"a5af61d723c01af3","name":"POST","kind":3,"startTimeUnixNano":"1791236971405501148","endTimeUnixNano":"1791236974318241311","attributes":[{"key":"http.request.method","value":{"stringValue":"POST"}},{"key":"server.address","value":{"stringValue":"checkout-api.shop.svc.cluster.local"}},{"key":"peer.service","value":{"stringValue":"checkout-api"}},{"key":"http.response.status_code","value":{"intValue":"200"}}],"status":{}},
            {"traceId":"43df985d19f2e1f210c0034a6675f46d","spanId":"edf50e9e6587acaf","name":"POST /api/checkout","kind":2,"startTimeUnixNano":"1791237897704235329","endTimeUnixNano":"1791237897752068242","attributes":[{"key":"http.request.method","value":{"stringValue":"POST"}},{"key":"http.response.status_code","value":{"intValue":"503"}}],"status":{"code":2,"message":"checkout-api responded 503"}},
            {"traceId":"43df985d19f2e1f210c0034a6675f46d","spanId":"6bd7751d9291deb9","parentSpanId":"edf50e9e6587acaf","name":"POST","kind":3,"startTimeUnixNano":"1791237897707556710","endTimeUnixNano":"1791237897745871828","attributes":[{"key":"http.request.method","value":{"stringValue":"POST"}},{"key":"server.address","value":{"stringValue":"checkout-api.shop.svc.cluster.local"}},{"key":"peer.service","value":{"stringValue":"checkout-api"}},{"key":"http.response.status_code","value":{"intValue":"503"}}],"status":{"code":2,"message":"HTTP 503"}}
          ]
        }
      ]
    },
    {
      "resource": {
        "attributes": [
          {"key":"service.name","value":{"stringValue":"checkout-api"}},
          {"key":"service.version","value":{"stringValue":"3.7.1"}},
          {"key":"k8s.cluster.name","value":{"stringValue":"prod-eu-west"}},
          {"key":"k8s.namespace.name","value":{"stringValue":"shop"}},
          {"key":"k8s.pod.name","value":{"stringValue":"checkout-api-6f9c8d7b5-r2xvn"}}
        ]
      },
      "scopeSpans": [
        {
          "scope": {"name":"@opentelemetry/instrumentation-http","version":"0.205.0"},
          "spans": [
            {"traceId":"a519e4c8b76e57dd9b57d5366ecbd563","spanId":"8700b0ffad2b75f6","parentSpanId":"a4b5b609d2aa74bd","name":"POST /v1/checkout","kind":2,"startTimeUnixNano":"1791236971407513143","endTimeUnixNano":"1791236974315737025","attributes":[{"key":"http.request.method","value":{"stringValue":"POST"}},{"key":"http.response.status_code","value":{"intValue":"200"}}],"status":{}},
            {"traceId":"a519e4c8b76e57dd9b57d5366ecbd563","spanId":"d5a8c3d0d069bbf0","parentSpanId":"8700b0ffad2b75f6","name":"POST","kind":3,"startTimeUnixNano":"1791236971420920691","endTimeUnixNano":"1791236974299848662","attributes":[{"key":"http.request.method","value":{"stringValue":"POST"}},{"key":"server.address","value":{"stringValue":"payments-api.shop.svc.cluster.local"}},{"key":"peer.service","value":{"stringValue":"payments-api"}},{"key":"http.response.status_code","value":{"intValue":"200"}}],"status":{}},
            {"traceId":"9cca576488d4a08d954aa629381328b8","spanId":"502f9d2fc0ec7753","parentSpanId":"dfbf7a72af474d74","name":"POST /v1/checkout","kind":2,"startTimeUnixNano":"1791237250547239242","endTimeUnixNano":"1791237250575814553","attributes":[{"key":"http.request.method","value":{"stringValue":"POST"}},{"key":"http.response.status_code","value":{"intValue":"503"}}],"status":{"code":2,"message":"payment authorization failed"}},
            {"traceId":"9cca576488d4a08d954aa629381328b8","spanId":"7fcabde1167d274e","parentSpanId":"502f9d2fc0ec7753","name":"POST","kind":3,"startTimeUnixNano":"1791237250560760780","endTimeUnixNano":"1791237250565673806","attributes":[{"key":"http.request.method","value":{"stringValue":"POST"}},{"key":"server.address","value":{"stringValue":"payments-api.shop.svc.cluster.local"}},{"key":"peer.service","value":{"stringValue":"payments-api"}},{"key":"error.type","value":{"stringValue":"ECONNREFUSED"}}],"status":{"code":2,"message":"connect ECONNREFUSED 10.0.142.17:8080"}},
            {"traceId":"9216f63c89e0a9c1002713b3c5a49c59","spanId":"0f6aba9bd3cde0e3","parentSpanId":"966d0a6c805abb44","name":"POST /v1/checkout","kind":2,"startTimeUnixNano":"1791238298834977209","endTimeUnixNano":"1791238298871456616","attributes":[{"key":"http.request.method","value":{"stringValue":"POST"}},{"key":"http.response.status_code","value":{"intValue":"503"}}],"status":{"code":2,"message":"payment authorization failed"}},
            {"traceId":"9216f63c89e0a9c1002713b3c5a49c59","spanId":"56b897bba9513a1c","parentSpanId":"0f6aba9bd3cde0e3","name":"POST","kind":3,"startTimeUnixNano":"1791238298847587252","endTimeUnixNano":"1791238298851390960","attributes":[{"key":"http.request.method","value":{"stringValue":"POST"}},{"key":"server.address","value":{"stringValue":"payments-api.shop.svc.cluster.local"}},{"key":"peer.service","value":{"stringValue":"payments-api"}},{"key":"error.type","value":{"stringValue":"ECONNREFUSED"}}],"status":{"code":2,"message":"connect ECONNREFUSED 10.0.142.17:8080"}}
          ]
        },
        {
          "scope": {"name":"@opentelemetry/instrumentation-pg","version":"0.58.0"},
          "spans": [
            {"traceId":"a519e4c8b76e57dd9b57d5366ecbd563","spanId":"5614e4ec1bcc00f2","parentSpanId":"8700b0ffad2b75f6","name":"SELECT carts","kind":3,"startTimeUnixNano":"1791236971409997630","endTimeUnixNano":"1791236971415441441","attributes":[{"key":"db.system","value":{"stringValue":"postgresql"}},{"key":"db.namespace","value":{"stringValue":"checkout"}}],"status":{}},
            {"traceId":"9cca576488d4a08d954aa629381328b8","spanId":"0e837c45b73cd5ca","parentSpanId":"502f9d2fc0ec7753","name":"SELECT carts","kind":3,"startTimeUnixNano":"1791237250549600178","endTimeUnixNano":"1791237250554080501","attributes":[{"key":"db.system","value":{"stringValue":"postgresql"}},{"key":"db.namespace","value":{"stringValue":"checkout"}}],"status":{}},
            {"traceId":"9216f63c89e0a9c1002713b3c5a49c59","spanId":"4cc2153d6191037c","parentSpanId":"0f6aba9bd3cde0e3","name":"SELECT carts","kind":3,"startTimeUnixNano":"1791238298836469065","endTimeUnixNano":"1791238298845653198","attributes":[{"key":"db.system","value":{"stringValue":"postgresql"}},{"key":"db.namespace","value":{"stringValue":"checkout"}}],"status":{}}
          ]
        }
      ]
    },
    {
      "resource": {
        "attributes": [
          {"key":"service.name","value":{"stringValue":"payments-api"}},
          {"key":"service.version","value":{"stringValue":"2.14.0"}},
          {"key":"k8s.cluster.name","value":{"stringValue":"prod-eu-west"}},
          {"key":"k8s.namespace.name","value":{"stringValue":"shop"}},
          {"key":"k8s.pod.name","value":{"stringValue":"payments-api-5c8d7f9b4d-h7x2q"}}
        ]
      },
      "scopeSpans": [
        {
          "scope": {"name":"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp","version":"0.63.0"},
          "spans": [
            {"traceId":"a519e4c8b76e57dd9b57d5366ecbd563","spanId":"46460458f9ba33a3","parentSpanId":"d5a8c3d0d069bbf0","name":"POST /v1/authorize","kind":2,"startTimeUnixNano":"1791236971423221838","endTimeUnixNano":"1791236974293325432","attributes":[{"key":"http.request.method","value":{"stringValue":"POST"}},{"key":"http.response.status_code","value":{"intValue":"200"}}],"status":{}}
          ]
        },
        {
          "scope": {"name":"github.com/exaring/otelpgx","version":"0.9.3"},
          "spans": [
            {"traceId":"a519e4c8b76e57dd9b57d5366ecbd563","spanId":"7d420a18de549a38","parentSpanId":"46460458f9ba33a3","name":"INSERT authorizations","kind":3,"startTimeUnixNano":"1791236971426110096","endTimeUnixNano":"1791236971434228997","attributes":[{"key":"db.system","value":{"stringValue":"postgresql"}},{"key":"db.namespace","value":{"stringValue":"payments"}}],"status":{}}
          ]
        }
      ]
    },
    {
      "resource": {
        "attributes": [
          {"key":"service.name","value":{"stringValue":"frontend"}},
          {"key":"service.version","value":{"stringValue":"5.2.0"}},
          {"key":"k8s.cluster.name","value":{"stringValue":"prod-us-east"}},
          {"key":"k8s.namespace.name","value":{"stringValue":"shop"}},
          {"key":"k8s.pod.name","value":{"stringValue":"frontend-7b5d9c6f84-xk2vd"}}
        ]
      },
      "scopeSpans": [
        {
          "scope": {"name":"@opentelemetry/instrumentation-http","version":"0.205.0"},
          "spans": [
            {"traceId":"2b7639f3b9e03c7f75f15ab9ae740bbc","spanId":"8e8b00fda3fcd2b3","name":"POST /api/checkout","kind":2,"startTimeUnixNano":"1791237520233872120","endTimeUnixNano":"1791237520401016903","attributes":[{"key":"http.request.method","value":{"stringValue":"POST"}},{"key":"http.response.status_code","value":{"intValue":"200"}}],"status":{}},
            {"traceId":"2b7639f3b9e03c7f75f15ab9ae740bbc","spanId":"748f9fddb543edbd","parentSpanId":"8e8b00fda3fcd2b3","name":"POST","kind":3,"startTimeUnixNano":"1791237520236400973","endTimeUnixNano":"1791237520392999832","attributes":[{"key":"http.request.method","value":{"stringValue":"POST"}},{"key":"server.address","value":{"stringValue":"checkout-api.shop.svc.cluster.local"}},{"key":"peer.service","value":{"stringValue":"checkout-api"}},{"key":"http.response.status_code","value":{"intValue":"200"}}],"status":{}}
          ]
        }
      ]
    },
    {
      "resource": {
        "attributes": [
          {"key":"service.name","value":{"stringValue":"checkout-api"}},
          {"key":"service.version","value":{"stringValue":"3.7.1"}},
          {"key":"k8s.cluster.name","value":{"stringValue":"prod-us-east"}},
          {"key":"k8s.namespace.name","value":{"stringValue":"shop"}},
          {"key":"k8s.pod.name","value":{"stringValue":"checkout-api-58d6c9f7b4-n4wzb"}}
        ]
      },
      "scopeSpans": [
        {
          "scope": {"name":"@opentelemetry/instrumentation-http","version":"0.205.0"},
          "spans": [
            {"traceId":"2b7639f3b9e03c7f75f15ab9ae740bbc","spanId":"3c1e38f0dc857f15","parentSpanId":"748f9fddb543edbd","name":"POST /v1/checkout","kind":2,"startTimeUnixNano":"1791237520238033155","endTimeUnixNano":"1791237520392438686","attributes":[{"key":"http.request.method","value":{"stringValue":"POST"}},{"key":"http.response.status_code","value":{"intValue":"200"}}],"status":{}},
            {"traceId":"2b7639f3b9e03c7f75f15ab9ae740bbc","spanId":"9f949b502889ef1d","parentSpanId":"3c1e38f0dc857f15","name":"POST","kind":3,"startTimeUnixNano":"1791237520251002303","endTimeUnixNano":"1791237520380915874","attributes":[{"key":"http.request.method","value":{"stringValue":"POST"}},{"key":"server.address","value":{"stringValue":"payments-api.shop.svc.cluster.local"}},{"key":"peer.service","value":{"stringValue":"payments-api"}},{"key":"http.response.status_code","value":{"intValue":"200"}}],"status":{}}
          ]
        },
        {
          "scope": {"name":"@opentelemetry/instrumentation-pg","version":"0.58.0"},
          "spans": [
            {"traceId":"2b7639f3b9e03c7f75f15ab9ae740bbc","spanId":"08b764ed7a051de8","parentSpanId":"3c1e38f0dc857f15","name":"SELECT carts","kind":3,"startTimeUnixNano":"1791237520240161158","endTimeUnixNano":"1791237520245384669","attributes":[{"key":"db.system","value":{"stringValue":"postgresql"}},{"key":"db.namespace","value":{"stringValue":"checkout"}}],"status":{}}
          ]
        }
      ]
    },
    {
      "resource": {
        "attributes": [
          {"key":"service.name","value":{"stringValue":"payments-api"}},
          {"key":"service.version","value":{"stringValue":"2.13.4"}},
          {"key":"k8s.cluster.name","value":{"stringValue":"prod-us-east"}},
          {"key":"k8s.namespace.name","value":{"stringValue":"shop"}},
          {"key":"k8s.pod.name","value":{"stringValue":"payments-api-7d9f8b6c5-g4ntd"}}
        ]
      },
      "scopeSpans": [
        {
          "scope": {"name":"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp","version":"0.63.0"},
          "spans": [
            {"traceId":"2b7639f3b9e03c7f75f15ab9ae740bbc","spanId":"7c5bf3c425295788","parentSpanId":"9f949b502889ef1d","name":"POST /v1/authorize","kind":2,"startTimeUnixNano":"1791237520254105388","endTimeUnixNano":"1791237520377654059","attributes":[{"key":"http.request.method","value":{"stringValue":"POST"}},{"key":"http.response.status_code","value":{"intValue":"200"}}],"status":{}}
          ]
        },
        {
          "scope": {"name":"github.com/exaring/otelpgx","version":"0.9.3"},
          "spans": [
            {"traceId":"2b7639f3b9e03c7f75f15ab9ae740bbc","spanId":"f1edd099abf97c6f","parentSpanId":"7c5bf3c425295788","name":"INSERT authorizations","kind":3,"startTimeUnixNano":"1791237520257192557","endTimeUnixNano":"1791237520263966329","attributes":[{"key":"db.system","value":{"stringValue":"postgresql"}},{"key":"db.namespace","value":{"stringValue":"payments"}}],"status":{}}
          ]
        }
      ]
    }
  ]
}`;

  const S1_ALERTS = `{
  "receiver": "sre-pager",
  "status": "firing",
  "alerts": [
    {
      "status": "firing",
      "labels": {
        "alertname": "KubeContainerOOMKilled",
        "cluster": "prod-eu-west",
        "container": "payments-api",
        "namespace": "shop",
        "pod": "payments-api-5c8d7f9b4d-h7x2q",
        "prometheus": "monitoring/kube-prometheus-stack-prometheus",
        "severity": "warning"
      },
      "annotations": {
        "summary": "Container was OOMKilled.",
        "description": "Container payments-api in pod shop/payments-api-5c8d7f9b4d-h7x2q was OOMKilled 1 time in the last 5 minutes.",
        "runbook_url": "https://runbooks.example.com/kubernetes/kubecontaineroomkilled"
      },
      "startsAt": "2026-10-05T21:50:21.418Z",
      "endsAt": "0001-01-01T00:00:00Z",
      "generatorURL": "https://prometheus.prod-eu-west.example.com/graph?g0.expr=kube_pod_container_status_last_terminated_reason%7Breason%3D%22OOMKilled%22%2Cjob%3D%22kube-state-metrics%22%7D+%3D%3D+1+and+on+%28namespace%2C+pod%2C+container%29+increase%28kube_pod_container_status_restarts_total%7Bjob%3D%22kube-state-metrics%22%7D%5B5m%5D%29+%3E+0&g0.tab=1",
      "fingerprint": "b2634901454f3092"
    },
    {
      "status": "firing",
      "labels": {
        "alertname": "CheckoutApiHighErrorRate",
        "cluster": "prod-eu-west",
        "namespace": "shop",
        "prometheus": "monitoring/kube-prometheus-stack-prometheus",
        "service": "checkout-api",
        "severity": "critical",
        "team": "payments"
      },
      "annotations": {
        "summary": "checkout-api 5xx ratio above 5% for 3 minutes.",
        "description": "31.4% of checkout-api requests returned 5xx over the last 5 minutes.",
        "runbook_url": "https://runbooks.example.com/shop/checkout-api-errors"
      },
      "startsAt": "2026-10-05T21:53:51.207Z",
      "endsAt": "0001-01-01T00:00:00Z",
      "generatorURL": "https://prometheus.prod-eu-west.example.com/graph?g0.expr=sum+by+%28service%29+%28rate%28http_server_requests_total%7Bservice%3D%22checkout-api%22%2Ccode%3D~%225..%22%7D%5B5m%5D%29%29+%2F+sum+by+%28service%29+%28rate%28http_server_requests_total%7Bservice%3D%22checkout-api%22%7D%5B5m%5D%29%29+%3E+0.05&g0.tab=1",
      "fingerprint": "103c679770c21883"
    },
    {
      "status": "firing",
      "labels": {
        "alertname": "ErrorBudgetBurn",
        "cluster": "prod-eu-west",
        "long_window": "1h",
        "namespace": "shop",
        "prometheus": "monitoring/kube-prometheus-stack-prometheus",
        "service": "frontend",
        "severity": "critical",
        "short_window": "5m",
        "slo": "storefront-availability"
      },
      "annotations": {
        "summary": "storefront-availability is burning its error budget 16.2x faster than sustainable.",
        "description": "1h burn rate 16.2 (5m: 21.7) against a 99.9% / 30-day objective; about 2.25% of the 30-day budget is spent per hour at this rate.",
        "burn_rate": "16.2",
        "error_ratio": "0.0162",
        "runbook_url": "https://runbooks.example.com/slo/error-budget-burn"
      },
      "startsAt": "2026-10-05T22:06:11.884Z",
      "endsAt": "0001-01-01T00:00:00Z",
      "generatorURL": "https://prometheus.prod-eu-west.example.com/graph?g0.expr=%28sum%28rate%28http_requests_total%7Bservice%3D%22frontend%22%2Ccode%3D~%225..%22%7D%5B1h%5D%29%29+%2F+sum%28rate%28http_requests_total%7Bservice%3D%22frontend%22%7D%5B1h%5D%29%29%29+%2F+0.001+%3E+14.4+and+%28sum%28rate%28http_requests_total%7Bservice%3D%22frontend%22%2Ccode%3D~%225..%22%7D%5B5m%5D%29%29+%2F+sum%28rate%28http_requests_total%7Bservice%3D%22frontend%22%7D%5B5m%5D%29%29%29+%2F+0.001+%3E+14.4&g0.tab=1",
      "fingerprint": "ad421a2a12cd7e75"
    },
    {
      "status": "firing",
      "labels": {
        "alertname": "KubePodCrashLooping",
        "cluster": "prod-eu-west",
        "container": "payments-api",
        "job": "kube-state-metrics",
        "namespace": "shop",
        "pod": "payments-api-5c8d7f9b4d-h7x2q",
        "prometheus": "monitoring/kube-prometheus-stack-prometheus",
        "reason": "CrashLoopBackOff",
        "severity": "warning"
      },
      "annotations": {
        "summary": "Pod is crash looping.",
        "description": "Pod shop/payments-api-5c8d7f9b4d-h7x2q (payments-api) is in waiting state (reason: \\"CrashLoopBackOff\\").",
        "runbook_url": "https://runbooks.example.com/kubernetes/kubepodcrashlooping"
      },
      "startsAt": "2026-10-05T22:05:04.000Z",
      "endsAt": "0001-01-01T00:00:00Z",
      "generatorURL": "https://prometheus.prod-eu-west.example.com/graph?g0.expr=max_over_time%28kube_pod_container_status_waiting_reason%7Bjob%3D%22kube-state-metrics%22%2Creason%3D%22CrashLoopBackOff%22%7D%5B5m%5D%29+%3E%3D+1&g0.tab=1",
      "fingerprint": "cdc40125c933a70b"
    },
    {
      "status": "firing",
      "labels": {
        "alertname": "KubePodCrashLooping",
        "cluster": "prod-eu-west",
        "container": "payments-api",
        "job": "kube-state-metrics",
        "namespace": "shop",
        "pod": "payments-api-5c8d7f9b4d-zl4rk",
        "prometheus": "monitoring/kube-prometheus-stack-prometheus",
        "reason": "CrashLoopBackOff",
        "severity": "warning"
      },
      "annotations": {
        "summary": "Pod is crash looping.",
        "description": "Pod shop/payments-api-5c8d7f9b4d-zl4rk (payments-api) is in waiting state (reason: \\"CrashLoopBackOff\\").",
        "runbook_url": "https://runbooks.example.com/kubernetes/kubepodcrashlooping"
      },
      "startsAt": "2026-10-05T22:05:39.000Z",
      "endsAt": "0001-01-01T00:00:00Z",
      "generatorURL": "https://prometheus.prod-eu-west.example.com/graph?g0.expr=max_over_time%28kube_pod_container_status_waiting_reason%7Bjob%3D%22kube-state-metrics%22%2Creason%3D%22CrashLoopBackOff%22%7D%5B5m%5D%29+%3E%3D+1&g0.tab=1",
      "fingerprint": "55b1fd639019ce30"
    }
  ],
  "groupLabels": {
    "cluster": "prod-eu-west",
    "namespace": "shop"
  },
  "commonLabels": {
    "cluster": "prod-eu-west",
    "namespace": "shop",
    "prometheus": "monitoring/kube-prometheus-stack-prometheus"
  },
  "commonAnnotations": {},
  "externalURL": "https://alertmanager.example.com",
  "version": "4",
  "groupKey": "{}/{severity=~\\"warning|critical\\"}:{cluster=\\"prod-eu-west\\", namespace=\\"shop\\"}",
  "truncatedAlerts": 0
}`;

  const S1_HELM = `# cluster: prod-eu-west
$ helm history payments -n shop --kube-context prod-eu-west --max 5
REVISION\tUPDATED                 \tSTATUS    \tCHART         \tAPP VERSION\tDESCRIPTION     
38      \tTue Sep 22 14:03:51 2026\tsuperseded\tpayments-1.7.4\t2.12.1     \tUpgrade complete
39      \tThu Sep 24 10:41:12 2026\tsuperseded\tpayments-1.8.0\t2.13.0     \tUpgrade complete
40      \tThu Sep 24 11:02:37 2026\tsuperseded\tpayments-1.7.4\t2.12.1     \tRollback to 38  
41      \tWed Sep 30 16:20:09 2026\tsuperseded\tpayments-1.8.2\t2.13.4     \tUpgrade complete
42      \tMon Oct  5 23:47:03 2026\tdeployed  \tpayments-1.9.0\t2.14.0     \tUpgrade complete

$ helm diff revision payments 41 42 -n shop --kube-context prod-eu-west
shop, payments-api, Deployment (apps) has changed:
  # Source: payments/templates/deployment.yaml
  apiVersion: apps/v1
  kind: Deployment
  metadata:
    name: payments-api
    labels:
      app.kubernetes.io/name: payments-api
      app.kubernetes.io/instance: payments
-     app.kubernetes.io/version: "2.13.4"
+     app.kubernetes.io/version: "2.14.0"
      app.kubernetes.io/managed-by: Helm
-     helm.sh/chart: payments-1.8.2
+     helm.sh/chart: payments-1.9.0
  spec:
    replicas: 3
    revisionHistoryLimit: 5
    selector:
      matchLabels:
        app.kubernetes.io/name: payments-api
        app.kubernetes.io/instance: payments
    strategy:
      type: RollingUpdate
      rollingUpdate:
        maxSurge: 1
        maxUnavailable: 0
    template:
      metadata:
        labels:
          app.kubernetes.io/name: payments-api
          app.kubernetes.io/instance: payments
-         app.kubernetes.io/version: "2.13.4"
+         app.kubernetes.io/version: "2.14.0"
      spec:
        serviceAccountName: payments-api
        securityContext:
          runAsNonRoot: true
          runAsUser: 10001
        containers:
          - name: payments-api
-           image: "registry.example.com/shop/payments-api:2.13.4"
+           image: "registry.example.com/shop/payments-api:2.14.0"
            imagePullPolicy: IfNotPresent
            ports:
              - name: http
                containerPort: 8080
                protocol: TCP
            env:
              - name: GOMEMLIMIT
                value: "460MiB"
              - name: PAYMENTS_DB_HOST
                value: "postgres.data.svc.cluster.local"
+             - name: PAYMENTS_CACHE_WARMUP
+               value: "true"
+             - name: PAYMENTS_CACHE_WARMUP_ENTRIES
+               value: "1200000"
            resources:
              requests:
                cpu: 250m
-               memory: 512Mi
+               memory: 256Mi
              limits:
                cpu: "1"
-               memory: 512Mi
+               memory: 256Mi
            livenessProbe:
              httpGet:
                path: /healthz
                port: http
              initialDelaySeconds: 10
              periodSeconds: 10
              timeoutSeconds: 2
            readinessProbe:
              httpGet:
                path: /readyz
                port: http
              initialDelaySeconds: 5
              periodSeconds: 5
              timeoutSeconds: 2
shop, payments-api, ServiceMonitor (monitoring.coreos.com) has changed:
  # Source: payments/templates/servicemonitor.yaml
  apiVersion: monitoring.coreos.com/v1
  kind: ServiceMonitor
  metadata:
    name: payments-api
    labels:
      app.kubernetes.io/name: payments-api
-     helm.sh/chart: payments-1.8.2
+     helm.sh/chart: payments-1.9.0
      release: kube-prometheus-stack`;


  // ----------------------------------------------------------------------------------------------------
  // 2. coredns-outage — Name lookups failing across the cluster
  // ----------------------------------------------------------------------------------------------------

  const S2_LOGS = `# cluster: prod-eu-central
$ kubectl -n kube-system get pods -l k8s-app=kube-dns -o wide
NAME                       READY   STATUS             RESTARTS        AGE   IP            NODE                             NOMINATED NODE   READINESS GATES
coredns-7c9d4b8f6d-5kq2w   0/1     CrashLoopBackOff   6 (4m13s ago)   29m   10.244.0.15   aks-system-27461938-vmss000000   <none>           <none>
coredns-7c9d4b8f6d-m8z4t   0/1     CrashLoopBackOff   6 (4m22s ago)   28m   10.244.1.12   aks-system-27461938-vmss000001   <none>           <none>

$ kubectl -n kube-system get events --sort-by=.lastTimestamp
LAST SEEN   TYPE      REASON              OBJECT                          MESSAGE
29m         Normal    ScalingReplicaSet   deployment/coredns              Scaled up replica set coredns-7c9d4b8f6d to 1
29m         Normal    ScalingReplicaSet   deployment/coredns              Scaled down replica set coredns-5f8d7c9b4d to 1 from 2
29m         Normal    Killing             pod/coredns-5f8d7c9b4d-j8wqv    Stopping container coredns
29m         Normal    SuccessfulCreate    replicaset/coredns-7c9d4b8f6d   Created pod: coredns-7c9d4b8f6d-5kq2w
29m         Normal    Scheduled           pod/coredns-7c9d4b8f6d-5kq2w    Successfully assigned kube-system/coredns-7c9d4b8f6d-5kq2w to aks-system-27461938-vmss000000
28m         Normal    Pulled              pod/coredns-7c9d4b8f6d-5kq2w    Successfully pulled image "registry.example.com/mirror/coredns/coredns:1.12.3" in 5.218s (5.218s including waiting). Image size: 21914208 bytes.
28m         Normal    ScalingReplicaSet   deployment/coredns              Scaled up replica set coredns-7c9d4b8f6d to 2 from 1
28m         Normal    SuccessfulCreate    replicaset/coredns-7c9d4b8f6d   Created pod: coredns-7c9d4b8f6d-m8z4t
28m         Normal    Scheduled           pod/coredns-7c9d4b8f6d-m8z4t    Successfully assigned kube-system/coredns-7c9d4b8f6d-m8z4t to aks-system-27461938-vmss000001
28m         Normal    Pulled              pod/coredns-7c9d4b8f6d-m8z4t    Successfully pulled image "registry.example.com/mirror/coredns/coredns:1.12.3" in 4.877s (4.877s including waiting). Image size: 21914208 bytes.
28m         Normal    ScalingReplicaSet   deployment/coredns              Scaled down replica set coredns-5f8d7c9b4d to 0 from 1
28m         Normal    Killing             pod/coredns-5f8d7c9b4d-t2xbn    Stopping container coredns
5m26s       Normal    Created             pod/coredns-7c9d4b8f6d-m8z4t    Created container: coredns
5m26s       Normal    Started             pod/coredns-7c9d4b8f6d-m8z4t    Started container coredns
5m23s       Normal    Created             pod/coredns-7c9d4b8f6d-5kq2w    Created container: coredns
5m23s       Normal    Started             pod/coredns-7c9d4b8f6d-5kq2w    Started container coredns
4m31s       Warning   Unhealthy           pod/coredns-7c9d4b8f6d-m8z4t    Liveness probe failed: Get "http://10.244.1.12:8080/health": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
4m26s       Warning   Unhealthy           pod/coredns-7c9d4b8f6d-m8z4t    Readiness probe failed: HTTP probe failed with statuscode: 503
4m22s       Warning   Unhealthy           pod/coredns-7c9d4b8f6d-5kq2w    Liveness probe failed: Get "http://10.244.0.15:8080/health": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
4m17s       Warning   Unhealthy           pod/coredns-7c9d4b8f6d-5kq2w    Readiness probe failed: HTTP probe failed with statuscode: 503
40s         Warning   BackOff             pod/coredns-7c9d4b8f6d-m8z4t    Back-off restarting failed container coredns in pod coredns-7c9d4b8f6d-m8z4t_kube-system(b44a3d56-65b6-4f12-8400-3c8f66e5fe82)
37s         Warning   BackOff             pod/coredns-7c9d4b8f6d-5kq2w    Back-off restarting failed container coredns in pod coredns-7c9d4b8f6d-5kq2w_kube-system(4fd4ed0b-b2f8-48f2-9b2c-bd3487106c41)

$ kubectl -n kube-system describe pod coredns-7c9d4b8f6d-5kq2w | sed -n '/^Containers:/,/^Conditions:/p'
Containers:
  coredns:
    Image:         registry.example.com/mirror/coredns/coredns:1.12.3
    Ports:         53/UDP, 53/TCP, 9153/TCP
    Host Ports:    0/UDP, 0/TCP, 0/TCP
    Args:
      -conf
      /etc/coredns/Corefile
    State:          Waiting
      Reason:       CrashLoopBackOff
    Last State:     Terminated
      Reason:       OOMKilled
      Exit Code:    137
      Started:      Mon, 05 Oct 2026 19:25:37 +0000
      Finished:     Mon, 05 Oct 2026 19:26:47 +0000
    Ready:          False
    Restart Count:  6
    Limits:
      memory:  170Mi
    Requests:
      cpu:        100m
      memory:     70Mi
    Liveness:     http-get http://:8080/health delay=60s timeout=5s period=10s #success=1 #failure=5
    Readiness:    http-get http://:8181/ready delay=0s timeout=1s period=10s #success=1 #failure=3
    Environment:  <none>
    Mounts:
      /etc/coredns from config-volume (ro)
Conditions:

$ kubectl -n kube-system logs coredns-7c9d4b8f6d-5kq2w --previous --prefix --timestamps
[pod/coredns-7c9d4b8f6d-5kq2w/coredns] 2026-10-05T19:25:37.380819918Z .:53
[pod/coredns-7c9d4b8f6d-5kq2w/coredns] 2026-10-05T19:25:37.381763835Z CoreDNS-1.12.3
[pod/coredns-7c9d4b8f6d-5kq2w/coredns] 2026-10-05T19:25:37.382213931Z linux/amd64, go1.24.6, 6e7b8a1
[pod/coredns-7c9d4b8f6d-5kq2w/coredns] 2026-10-05T19:25:44.437939322Z [ERROR] plugin/errors: 2 api.payments-gw.example.net. A: read udp 10.244.0.15:51542->10.20.0.53:53: i/o timeout
[pod/coredns-7c9d4b8f6d-5kq2w/coredns] 2026-10-05T19:25:47.337287386Z [ERROR] plugin/errors: 2 smtp-relay.example.net. AAAA: read udp 10.244.0.15:43454->10.20.0.53:53: i/o timeout
[pod/coredns-7c9d4b8f6d-5kq2w/coredns] 2026-10-05T19:25:49.737912536Z [ERROR] plugin/errors: 2 api.payments-gw.example.net. AAAA: read udp 10.244.0.15:40497->10.20.0.53:53: i/o timeout
[pod/coredns-7c9d4b8f6d-5kq2w/coredns] 2026-10-05T19:25:50.43719781Z [WARNING] plugin/health: Local health request to "http://:8080/health" took more than 1s: 1.348s
[pod/coredns-7c9d4b8f6d-5kq2w/coredns] 2026-10-05T19:25:52.927384543Z [ERROR] plugin/errors: 2 login.identity-provider.example.net. A: read udp 10.244.0.15:39138->10.20.0.53:53: i/o timeout
[pod/coredns-7c9d4b8f6d-5kq2w/coredns] 2026-10-05T19:25:55.151698287Z [ERROR] plugin/errors: 2 smtp-relay.example.net. A: read udp 10.244.0.15:53254->10.20.0.53:53: i/o timeout
[pod/coredns-7c9d4b8f6d-5kq2w/coredns] 2026-10-05T19:25:59.826089665Z [ERROR] plugin/errors: 2 metrics-ingest.example.net. A: read udp 10.244.0.15:51459->10.20.0.53:53: i/o timeout
[pod/coredns-7c9d4b8f6d-5kq2w/coredns] 2026-10-05T19:26:26.000495222Z W1005 19:26:26.000117       1 reflector.go:561] pkg/mod/k8s.io/client-go@v0.33.1/tools/cache/reflector.go:251: failed to list *v1.EndpointSlice: Get "https://10.96.0.1:443/apis/discovery.k8s.io/v1/endpointslices?limit=500&resourceVersion=0": context deadline exceeded
[pod/coredns-7c9d4b8f6d-5kq2w/coredns] 2026-10-05T19:26:38.000367111Z [WARNING] plugin/health: Local health request to "http://:8080/health" took more than 1s: 4.912s
[pod/coredns-7c9d4b8f6d-5kq2w/coredns] 2026-10-05T19:26:43.000781261Z [ERROR] plugin/errors: 2 api.payments-gw.example.net. A: read udp 10.244.0.15:48768->10.20.0.53:53: i/o timeout

$ kubectl debug node/aks-system-27461938-vmss000000 -it --image=registry.example.com/mirror/busybox:1.37 -- chroot /host journalctl -k --since "-30 min" | grep -E 'oom-killer|Killed process'
Oct 05 19:09:37 aks-system-27461938-vmss000000 kernel: coredns invoked oom-killer: gfp_mask=0xcc0(GFP_KERNEL), order=0, oom_score_adj=992
Oct 05 19:09:37 aks-system-27461938-vmss000000 kernel: Memory cgroup out of memory: Killed process 416746 (coredns) total-vm:1346107kB, anon-rss:172770kB, file-rss:31102kB, shmem-rss:0kB, UID:65532 pgtables:595kB oom_score_adj:992
Oct 05 19:10:04 aks-system-27461938-vmss000001 kernel: coredns invoked oom-killer: gfp_mask=0xcc0(GFP_KERNEL), order=0, oom_score_adj=992
Oct 05 19:10:04 aks-system-27461938-vmss000001 kernel: Memory cgroup out of memory: Killed process 417935 (coredns) total-vm:1298076kB, anon-rss:172057kB, file-rss:31096kB, shmem-rss:0kB, UID:65532 pgtables:605kB oom_score_adj:992
Oct 05 19:10:57 aks-system-27461938-vmss000000 kernel: coredns invoked oom-killer: gfp_mask=0xcc0(GFP_KERNEL), order=0, oom_score_adj=992
Oct 05 19:10:57 aks-system-27461938-vmss000000 kernel: Memory cgroup out of memory: Killed process 419372 (coredns) total-vm:1318078kB, anon-rss:172375kB, file-rss:30283kB, shmem-rss:0kB, UID:65532 pgtables:602kB oom_score_adj:992

$ stern -n shop --since 32m --exclude healthz --exclude-container istio-proxy 'storefront|cart|catalog|checkout|payments|notification'
checkout-api-6b7f9d5c4-9tq2w checkout-api {"level":"info","ts":"2026-10-05T19:00:41.206Z","caller":"checkout/handler.go:122","msg":"checkout completed","status":200,"latency_ms":241}
payments-api-84d9c7b6f5-mz5kd payments-api {"level":"error","ts":"2026-10-05T19:05:31.887Z","caller":"gateway/client.go:77","msg":"charge request failed","error":"Post \\"https://api.payments-gw.example.net/v2/charges\\": dial tcp: lookup api.payments-gw.example.net on 10.96.0.10:53: server misbehaving","status":502}
notification-worker-6f9b8c7d5-ptx4s notification-worker {"level":"error","time":"2026-10-05T19:06:48.112Z","service":"notification-worker","msg":"send failed, will retry","err":{"type":"Error","message":"getaddrinfo EAI_AGAIN smtp-relay.example.net","code":"EAI_AGAIN","syscall":"getaddrinfo","hostname":"smtp-relay.example.net"},"attempt":1}
payments-api-84d9c7b6f5-mz5kd payments-api {"level":"error","ts":"2026-10-05T19:07:55.402Z","caller":"gateway/client.go:77","msg":"charge request failed","error":"Post \\"https://api.payments-gw.example.net/v2/charges\\": dial tcp: lookup api.payments-gw.example.net on 10.96.0.10:53: server misbehaving","status":502}
cart-api-7f6d9c8b5-2hq8x cart-api {"level":"error","ts":1791227381.233865,"caller":"store/redis.go:64","msg":"redis HGETALL failed","error":"dial tcp: lookup cart-redis.shop.svc.cluster.local on 10.96.0.10:53: read udp 10.244.3.17:45765->10.96.0.10:53: i/o timeout"}
checkout-api-6b7f9d5c4-9tq2w checkout-api {"level":"error","ts":"2026-10-05T19:09:44.120Z","caller":"checkout/handler.go:141","msg":"payments call failed","error":"Post \\"http://payments-api.shop.svc.cluster.local:8080/v1/charges\\": dial tcp: lookup payments-api.shop.svc.cluster.local on 10.96.0.10:53: read udp 10.244.4.41:42521->10.96.0.10:53: i/o timeout","status":502}
storefront-6c8b9d7f5-4kq2z storefront {"level":"error","time":"2026-10-05T19:09:59.410Z","service":"storefront","msg":"upstream request failed","upstream":"catalog-api","path":"/products/SKU-118204","status":504,"latency_ms":10012,"err":"getaddrinfo EAI_AGAIN catalog-api.shop.svc.cluster.local"}
catalog-api-5b7c9d6f8-lx4pz catalog-api {"level":"error","ts":"2026-10-05T19:10:08.944Z","caller":"related/client.go:49","msg":"related products lookup failed","error":"Get \\"http://search-api.shop.svc.cluster.local:8080/v1/related?sku=SKU-118195\\": dial tcp: lookup search-api.shop.svc.cluster.local on 10.96.0.10:53: read udp 10.244.2.34:32990->10.96.0.10:53: i/o timeout"}
cart-api-7f6d9c8b5-2hq8x cart-api {"level":"error","ts":1791227429.310886,"caller":"store/redis.go:64","msg":"redis HSET failed","error":"dial tcp: lookup cart-redis.shop.svc.cluster.local on 10.96.0.10:53: read udp 10.244.3.17:57770->10.96.0.10:53: i/o timeout"}
storefront-6c8b9d7f5-4kq2z storefront {"level":"error","time":"2026-10-05T19:11:03.640Z","service":"storefront","msg":"upstream request failed","upstream":"cart-api","path":"/cart/items","status":502,"latency_ms":10006,"err":"getaddrinfo EAI_AGAIN cart-api.shop.svc.cluster.local"}
checkout-api-6b7f9d5c4-9tq2w checkout-api {"level":"error","ts":"2026-10-05T19:11:12.020Z","caller":"checkout/handler.go:141","msg":"inventory reservation failed","error":"Post \\"http://inventory-api.shop.svc.cluster.local:8080/v1/reservations\\": dial tcp: lookup inventory-api.shop.svc.cluster.local on 10.96.0.10:53: read udp 10.244.4.41:57549->10.96.0.10:53: i/o timeout","status":502}
notification-worker-6f9b8c7d5-ptx4s notification-worker {"level":"error","time":"2026-10-05T19:12:20.770Z","service":"notification-worker","msg":"send failed, will retry","err":{"type":"Error","message":"getaddrinfo EAI_AGAIN smtp-relay.example.net","code":"EAI_AGAIN","syscall":"getaddrinfo","hostname":"smtp-relay.example.net"},"attempt":4}
cart-api-7f6d9c8b5-2hq8x cart-api {"level":"error","ts":1791227617.551868,"caller":"store/redis.go:64","msg":"redis HGETALL failed","error":"dial tcp: lookup cart-redis.shop.svc.cluster.local on 10.96.0.10:53: read udp 10.244.3.17:38969->10.96.0.10:53: i/o timeout"}
payments-api-84d9c7b6f5-mz5kd payments-api {"level":"error","ts":"2026-10-05T19:14:12.906Z","caller":"gateway/client.go:77","msg":"charge request failed","error":"Post \\"https://api.payments-gw.example.net/v2/charges\\": dial tcp: lookup api.payments-gw.example.net on 10.96.0.10:53: read udp 10.244.3.52:45001->10.96.0.10:53: i/o timeout","status":502}
checkout-api-6b7f9d5c4-9tq2w checkout-api {"level":"info","ts":"2026-10-05T19:15:02.418Z","caller":"checkout/handler.go:122","msg":"checkout completed","status":200,"latency_ms":3874}
catalog-api-5b7c9d6f8-lx4pz catalog-api {"level":"error","ts":"2026-10-05T19:16:40.118Z","caller":"store/pg.go:58","msg":"product query failed","error":"failed to connect to \`host=catalog-db.shop.svc.cluster.local user=catalog database=catalog\`: hostname resolving error (lookup catalog-db.shop.svc.cluster.local on 10.96.0.10:53: read udp 10.244.2.34:60529->10.96.0.10:53: i/o timeout)"}
checkout-api-6b7f9d5c4-9tq2w checkout-api {"level":"error","ts":"2026-10-05T19:18:21.734Z","caller":"checkout/handler.go:141","msg":"payments call failed","error":"Post \\"http://payments-api.shop.svc.cluster.local:8080/v1/charges\\": dial tcp: lookup payments-api.shop.svc.cluster.local on 10.96.0.10:53: read udp 10.244.4.41:48729->10.96.0.10:53: i/o timeout","status":502}
cart-api-7f6d9c8b5-2hq8x cart-api {"level":"error","ts":1791227995.020132,"caller":"store/redis.go:64","msg":"redis HGETALL failed","error":"dial tcp: lookup cart-redis.shop.svc.cluster.local on 10.96.0.10:53: read udp 10.244.3.17:34989->10.96.0.10:53: i/o timeout"}
catalog-api-5b7c9d6f8-lx4pz catalog-api {"level":"error","ts":"2026-10-05T19:21:49.388Z","caller":"related/client.go:49","msg":"related products lookup failed","error":"Get \\"http://search-api.shop.svc.cluster.local:8080/v1/related?sku=SKU-126062\\": dial tcp: lookup search-api.shop.svc.cluster.local on 10.96.0.10:53: read udp 10.244.2.34:52092->10.96.0.10:53: i/o timeout"}
checkout-api-6b7f9d5c4-9tq2w checkout-api {"level":"error","ts":"2026-10-05T19:23:30.612Z","caller":"checkout/handler.go:141","msg":"payments call failed","error":"Post \\"http://payments-api.shop.svc.cluster.local:8080/v1/charges\\": dial tcp: lookup payments-api.shop.svc.cluster.local on 10.96.0.10:53: read udp 10.244.4.41:46521->10.96.0.10:53: i/o timeout","status":502}
storefront-6c8b9d7f5-4kq2z storefront {"level":"error","time":"2026-10-05T19:24:52.091Z","service":"storefront","msg":"upstream request failed","upstream":"checkout-api","path":"/checkout","status":502,"latency_ms":10009,"err":"getaddrinfo EAI_AGAIN checkout-api.shop.svc.cluster.local"}
cart-api-7f6d9c8b5-2hq8x cart-api {"level":"error","ts":1791228370.247211,"caller":"store/redis.go:64","msg":"redis HSET failed","error":"dial tcp: lookup cart-redis.shop.svc.cluster.local on 10.96.0.10:53: read udp 10.244.3.17:35494->10.96.0.10:53: i/o timeout"}
catalog-api-5b7c9d6f8-lx4pz catalog-api {"level":"error","ts":"2026-10-05T19:27:44.903Z","caller":"related/client.go:49","msg":"related products lookup failed","error":"Get \\"http://search-api.shop.svc.cluster.local:8080/v1/related?sku=SKU-126062\\": dial tcp: lookup search-api.shop.svc.cluster.local on 10.96.0.10:53: read udp 10.244.2.34:58252->10.96.0.10:53: i/o timeout"}
checkout-api-6b7f9d5c4-9tq2w checkout-api {"level":"error","ts":"2026-10-05T19:29:33.170Z","caller":"checkout/handler.go:141","msg":"payments call failed","error":"Post \\"http://payments-api.shop.svc.cluster.local:8080/v1/charges\\": dial tcp: lookup payments-api.shop.svc.cluster.local on 10.96.0.10:53: read udp 10.244.4.41:52494->10.96.0.10:53: i/o timeout","status":502}
cart-api-7f6d9c8b5-2hq8x cart-api {"level":"error","ts":1791228641.5229762,"caller":"store/redis.go:64","msg":"redis HGETALL failed","error":"dial tcp: lookup cart-redis.shop.svc.cluster.local on 10.96.0.10:53: read udp 10.244.3.17:44651->10.96.0.10:53: i/o timeout"}

$ kubectl -n shop logs deploy/inventory-api --since=30m --prefix | grep -E ' (WARN|ERROR) '
[pod/inventory-api-7d5f8c9b6-r7v2n/inventory-api] 2026-10-05T19:09:55.220+00:00  WARN 1 --- [inventory-api] [nio-8080-exec-4] c.e.inventory.client.WarehouseClient     : warehouse lookup failed, serving cached stock: I/O error on GET request for "http://warehouse-sync.shop.svc.cluster.local:8080/v2/stock/SKU-118204": warehouse-sync.shop.svc.cluster.local
[pod/inventory-api-7d5f8c9b6-r7v2n/inventory-api] 2026-10-05T19:17:09.334+00:00 ERROR 1 --- [inventory-api] [nio-8080-exec-9] o.a.c.c.C.[.[.[/].[dispatcherServlet]    : Servlet.service() for servlet [dispatcherServlet] in context with path [] threw exception [Request processing failed: org.springframework.web.client.ResourceAccessException: I/O error on GET request for "http://warehouse-sync.shop.svc.cluster.local:8080/v2/stock/SKU-204117": warehouse-sync.shop.svc.cluster.local] with root cause
[pod/inventory-api-7d5f8c9b6-r7v2n/inventory-api] java.net.UnknownHostException: warehouse-sync.shop.svc.cluster.local: Temporary failure in name resolution
[pod/inventory-api-7d5f8c9b6-r7v2n/inventory-api] \tat java.base/java.net.Inet6AddressImpl.lookupAllHostAddr(Native Method)
[pod/inventory-api-7d5f8c9b6-r7v2n/inventory-api] \tat java.base/java.net.InetAddress$PlatformResolver.lookupByName(InetAddress.java:1211)

$ kubectl -n shop logs deploy/search-api --since=30m --prefix --timestamps | grep -A8 ERROR | tail -n 9
[pod/search-api-84c7d9f6b5-wq2vd/search-api] 2026-10-05T19:20:14.502899569Z [2026-10-05 19:20:14 +0000] [12] [ERROR] Error handling request /v1/related?sku=SKU-173057
[pod/search-api-84c7d9f6b5-wq2vd/search-api] 2026-10-05T19:20:14.503469535Z Traceback (most recent call last):
[pod/search-api-84c7d9f6b5-wq2vd/search-api] 2026-10-05T19:20:14.504039864Z   File "/app/search/index.py", line 88, in related
[pod/search-api-84c7d9f6b5-wq2vd/search-api] 2026-10-05T19:20:14.505642737Z     resp = self.session.post(self.base_url + "/products/_search", json=body, timeout=2.0)
[pod/search-api-84c7d9f6b5-wq2vd/search-api] 2026-10-05T19:20:14.506357738Z   File "/usr/local/lib/python3.12/site-packages/requests/adapters.py", line 700, in send
[pod/search-api-84c7d9f6b5-wq2vd/search-api] 2026-10-05T19:20:14.507785182Z     raise ConnectionError(e, request=request)
[pod/search-api-84c7d9f6b5-wq2vd/search-api] 2026-10-05T19:20:14.508170318Z requests.exceptions.ConnectionError: HTTPConnectionPool(host='search-index.shop.svc.cluster.local', port=9200): Max retries exceeded with url: /products/_search (Caused by NameResolutionError("<urllib3.connection.HTTPConnection object at 0x7f3a2c1b8d90>: Failed to resolve 'search-index.shop.svc.cluster.local' ([Errno -3] Temporary failure in name resolution)"))

$ kubectl -n shop get pods
NAME                                  READY   STATUS    RESTARTS        AGE
cart-api-7f6d9c8b5-2hq8x              1/1     Running   0               6d4h
cart-redis-0                          1/1     Running   0               41d
catalog-api-5b7c9d6f8-lx4pz           1/1     Running   0               2d19h
checkout-api-6b7f9d5c4-9tq2w          1/1     Running   0               4d1h
inventory-api-7d5f8c9b6-r7v2n         1/1     Running   0               8d
notification-worker-6f9b8c7d5-ptx4s   1/1     Running   0               3d6h
payments-api-84d9c7b6f5-mz5kd         1/1     Running   0               4d1h
search-api-84c7d9f6b5-wq2vd           1/1     Running   2 (8m19s ago)   9d
search-index-0                        1/1     Running   0               41d
storefront-6c8b9d7f5-4kq2z            1/1     Running   0               1d22h
storefront-6c8b9d7f5-wd8tn            1/1     Running   0               1d22h`;

  const S2_TRACES = `# cluster: prod-eu-central
2026-10-05T19:00:12.315Z trace=38d46ab5f0280808 span=c449a9c1 parent=- service=storefront op="GET /products/:id" kind=server dur=142ms status=OK code=200 cluster=prod-eu-central ns=shop
2026-10-05T19:00:12.319Z trace=38d46ab5f0280808 span=f13a5227 parent=c449a9c1 service=storefront op="GET" kind=client dur=128ms status=OK code=200 peer=catalog-api cluster=prod-eu-central ns=shop
2026-10-05T19:00:12.321Z trace=38d46ab5f0280808 span=f6f4e138 parent=f13a5227 service=catalog-api op="GET /v1/products/{id}" kind=server dur=121ms status=OK code=200 cluster=prod-eu-central ns=shop
2026-10-05T19:00:12.324Z trace=38d46ab5f0280808 span=06743ff9 parent=f6f4e138 service=catalog-api op="SELECT products" kind=client dur=7ms status=OK peer=catalog-db db.system=postgresql cluster=prod-eu-central ns=shop
2026-10-05T19:00:12.335Z trace=38d46ab5f0280808 span=c3bcb41f parent=f6f4e138 service=catalog-api op="GET" kind=client dur=92ms status=OK code=200 peer=search-api cluster=prod-eu-central ns=shop
2026-10-05T19:00:12.338Z trace=38d46ab5f0280808 span=ea116100 parent=c3bcb41f service=search-api op="GET /v1/related" kind=server dur=86ms status=OK code=200 cluster=prod-eu-central ns=shop
2026-10-05T19:00:12.342Z trace=38d46ab5f0280808 span=a8860898 parent=ea116100 service=search-api op="POST /products/_search" kind=client dur=71ms status=OK code=200 peer=search-index db.system=elasticsearch cluster=prod-eu-central ns=shop
2026-10-05T19:00:40.902Z trace=0908e7f04dca0373 span=f9fe236c parent=- service=storefront op="POST /checkout" kind=server dur=391ms status=OK code=200 cluster=prod-eu-central ns=shop
2026-10-05T19:00:40.905Z trace=0908e7f04dca0373 span=31f632b5 parent=f9fe236c service=storefront op="POST" kind=client dur=382ms status=OK code=200 peer=checkout-api cluster=prod-eu-central ns=shop
2026-10-05T19:00:40.907Z trace=0908e7f04dca0373 span=cd90ccec parent=31f632b5 service=checkout-api op="POST /v1/checkout" kind=server dur=374ms status=OK code=200 cluster=prod-eu-central ns=shop
2026-10-05T19:00:40.911Z trace=0908e7f04dca0373 span=af98cdf3 parent=cd90ccec service=checkout-api op="POST" kind=client dur=64ms status=OK code=200 peer=inventory-api cluster=prod-eu-central ns=shop
2026-10-05T19:00:40.914Z trace=0908e7f04dca0373 span=7f7d1f80 parent=af98cdf3 service=inventory-api op="POST /v1/reservations" kind=server dur=55ms status=OK code=200 cluster=prod-eu-central ns=shop
2026-10-05T19:00:40.978Z trace=0908e7f04dca0373 span=45367e1f parent=cd90ccec service=checkout-api op="POST" kind=client dur=290ms status=OK code=200 peer=payments-api cluster=prod-eu-central ns=shop
2026-10-05T19:00:40.981Z trace=0908e7f04dca0373 span=306af636 parent=45367e1f service=payments-api op="POST /v1/charges" kind=server dur=284ms status=OK code=200 cluster=prod-eu-central ns=shop
2026-10-05T19:00:40.984Z trace=0908e7f04dca0373 span=a3f82254 parent=306af636 service=payments-api op="POST" kind=client dur=271ms status=OK code=201 peer=api.payments-gw.example.net cluster=prod-eu-central ns=shop
2026-10-05T19:01:15.448Z trace=acf6411d5a8dfb26 span=d29195eb parent=- service=storefront op="POST /cart/items" kind=server dur=38ms status=OK code=200 cluster=prod-eu-central ns=shop
2026-10-05T19:01:15.450Z trace=acf6411d5a8dfb26 span=30c12803 parent=d29195eb service=storefront op="POST" kind=client dur=33ms status=OK code=200 peer=cart-api cluster=prod-eu-central ns=shop
2026-10-05T19:01:15.452Z trace=acf6411d5a8dfb26 span=a5e3caa2 parent=30c12803 service=cart-api op="POST /v1/carts/{id}/items" kind=server dur=27ms status=OK code=200 cluster=prod-eu-central ns=shop
2026-10-05T19:01:15.454Z trace=acf6411d5a8dfb26 span=9acfa708 parent=a5e3caa2 service=cart-api op="HSET" kind=client dur=2ms status=OK peer=cart-redis db.system=redis cluster=prod-eu-central ns=shop
2026-10-05T19:05:31.590Z trace=5027e010cd8b3e1c span=7508346c parent=- service=storefront op="POST /checkout" kind=server dur=391ms status=ERROR code=502 cluster=prod-eu-central ns=shop error="upstream checkout-api responded 502"
2026-10-05T19:05:31.593Z trace=5027e010cd8b3e1c span=91d6d1a3 parent=7508346c service=storefront op="POST" kind=client dur=382ms status=ERROR code=502 peer=checkout-api cluster=prod-eu-central ns=shop error="HTTP 502"
2026-10-05T19:05:31.595Z trace=5027e010cd8b3e1c span=1df3005a parent=91d6d1a3 service=checkout-api op="POST /v1/checkout" kind=server dur=374ms status=ERROR code=502 cluster=prod-eu-central ns=shop error="payment failed"
2026-10-05T19:05:31.599Z trace=5027e010cd8b3e1c span=f1d0e0ab parent=1df3005a service=checkout-api op="POST" kind=client dur=64ms status=OK code=200 peer=inventory-api cluster=prod-eu-central ns=shop
2026-10-05T19:05:31.602Z trace=5027e010cd8b3e1c span=c3fbd47c parent=f1d0e0ab service=inventory-api op="POST /v1/reservations" kind=server dur=55ms status=OK code=200 cluster=prod-eu-central ns=shop
2026-10-05T19:05:31.666Z trace=5027e010cd8b3e1c span=4efa92c3 parent=1df3005a service=checkout-api op="POST" kind=client dur=290ms status=ERROR code=502 peer=payments-api cluster=prod-eu-central ns=shop error="HTTP 502"
2026-10-05T19:05:31.669Z trace=5027e010cd8b3e1c span=d276af3f parent=4efa92c3 service=payments-api op="POST /v1/charges" kind=server dur=284ms status=ERROR code=502 cluster=prod-eu-central ns=shop error="charge request failed"
2026-10-05T19:05:31.672Z trace=5027e010cd8b3e1c span=0135478f parent=d276af3f service=payments-api op="POST" kind=client dur=4ms status=ERROR peer=api.payments-gw.example.net cluster=prod-eu-central ns=shop error="dial tcp: lookup api.payments-gw.example.net on 10.96.0.10:53: server misbehaving"
2026-10-05T19:09:36.213Z trace=c83ec179bd9834cf span=dd5fc4c0 parent=- service=storefront op="POST /cart/items" kind=server dur=5032ms status=ERROR code=500 cluster=prod-eu-central ns=shop error="upstream cart-api responded 500"
2026-10-05T19:09:36.215Z trace=c83ec179bd9834cf span=7348eccf parent=dd5fc4c0 service=storefront op="POST" kind=client dur=5027ms status=ERROR code=500 peer=cart-api cluster=prod-eu-central ns=shop error="HTTP 500"
2026-10-05T19:09:36.217Z trace=c83ec179bd9834cf span=d7e61dbe parent=7348eccf service=cart-api op="POST /v1/carts/{id}/items" kind=server dur=5021ms status=ERROR code=500 cluster=prod-eu-central ns=shop error="redis HSET failed"
2026-10-05T19:09:36.219Z trace=c83ec179bd9834cf span=0c887463 parent=d7e61dbe service=cart-api op="HSET" kind=client dur=5003ms status=ERROR peer=cart-redis db.system=redis cluster=prod-eu-central ns=shop error="dial tcp: lookup cart-redis.shop.svc.cluster.local on 10.96.0.10:53: read udp 10.244.3.17:42607->10.96.0.10:53: i/o timeout"
2026-10-05T19:09:39.050Z trace=825fe638b28615b5 span=b5dbaa4a parent=- service=storefront op="POST /checkout" kind=server dur=5094ms status=ERROR code=502 cluster=prod-eu-central ns=shop error="upstream checkout-api responded 502"
2026-10-05T19:09:39.053Z trace=825fe638b28615b5 span=0cee021f parent=b5dbaa4a service=storefront op="POST" kind=client dur=5086ms status=ERROR code=502 peer=checkout-api cluster=prod-eu-central ns=shop error="HTTP 502"
2026-10-05T19:09:39.055Z trace=825fe638b28615b5 span=784770dd parent=0cee021f service=checkout-api op="POST /v1/checkout" kind=server dur=5079ms status=ERROR code=502 cluster=prod-eu-central ns=shop error="payment failed"
2026-10-05T19:09:39.059Z trace=825fe638b28615b5 span=0f1db5ec parent=784770dd service=checkout-api op="POST" kind=client dur=64ms status=OK code=200 peer=inventory-api cluster=prod-eu-central ns=shop
2026-10-05T19:09:39.062Z trace=825fe638b28615b5 span=e58eb13d parent=0f1db5ec service=inventory-api op="POST /v1/reservations" kind=server dur=55ms status=OK code=200 cluster=prod-eu-central ns=shop
2026-10-05T19:09:39.126Z trace=825fe638b28615b5 span=f09ec146 parent=784770dd service=checkout-api op="POST" kind=client dur=5004ms status=ERROR peer=payments-api cluster=prod-eu-central ns=shop error="dial tcp: lookup payments-api.shop.svc.cluster.local on 10.96.0.10:53: read udp 10.244.4.41:46305->10.96.0.10:53: i/o timeout"
2026-10-05T19:09:49.398Z trace=6d5717d37a0d5551 span=b0ad9114 parent=- service=storefront op="GET /products/:id" kind=server dur=10014ms status=ERROR code=504 cluster=prod-eu-central ns=shop error="upstream timeout"
2026-10-05T19:09:49.401Z trace=6d5717d37a0d5551 span=00497df3 parent=b0ad9114 service=storefront op="GET" kind=client dur=10007ms status=ERROR peer=catalog-api cluster=prod-eu-central ns=shop error="getaddrinfo EAI_AGAIN catalog-api.shop.svc.cluster.local"
2026-10-05T19:10:03.901Z trace=dec0ca4d8d83c285 span=2126fd64 parent=- service=storefront op="GET /products/:id" kind=server dur=5161ms status=OK code=200 cluster=prod-eu-central ns=shop
2026-10-05T19:10:03.905Z trace=dec0ca4d8d83c285 span=18096bc7 parent=2126fd64 service=storefront op="GET" kind=client dur=5149ms status=OK code=200 peer=catalog-api cluster=prod-eu-central ns=shop
2026-10-05T19:10:03.907Z trace=dec0ca4d8d83c285 span=ff7ad477 parent=18096bc7 service=catalog-api op="GET /v1/products/{id}" kind=server dur=5141ms status=OK code=200 cluster=prod-eu-central ns=shop
2026-10-05T19:10:03.910Z trace=dec0ca4d8d83c285 span=76282b05 parent=ff7ad477 service=catalog-api op="SELECT products" kind=client dur=7ms status=OK peer=catalog-db db.system=postgresql cluster=prod-eu-central ns=shop
2026-10-05T19:10:03.921Z trace=dec0ca4d8d83c285 span=66444a69 parent=ff7ad477 service=catalog-api op="GET" kind=client dur=5003ms status=ERROR peer=search-api cluster=prod-eu-central ns=shop error="dial tcp: lookup search-api.shop.svc.cluster.local on 10.96.0.10:53: read udp 10.244.2.34:33673->10.96.0.10:53: i/o timeout"
2026-10-05T19:10:53.623Z trace=0fbc3482a6d93567 span=86deabf6 parent=- service=storefront op="POST /cart/items" kind=server dur=10014ms status=ERROR code=504 cluster=prod-eu-central ns=shop error="upstream timeout"
2026-10-05T19:10:53.626Z trace=0fbc3482a6d93567 span=8cbc8730 parent=86deabf6 service=storefront op="POST" kind=client dur=10007ms status=ERROR peer=cart-api cluster=prod-eu-central ns=shop error="getaddrinfo EAI_AGAIN cart-api.shop.svc.cluster.local"
2026-10-05T19:13:32.531Z trace=729ea3a8af1b83ac span=0cf75ff5 parent=- service=storefront op="POST /cart/items" kind=server dur=5032ms status=ERROR code=500 cluster=prod-eu-central ns=shop error="upstream cart-api responded 500"
2026-10-05T19:13:32.533Z trace=729ea3a8af1b83ac span=2dee1101 parent=0cf75ff5 service=storefront op="POST" kind=client dur=5027ms status=ERROR code=500 peer=cart-api cluster=prod-eu-central ns=shop error="HTTP 500"
2026-10-05T19:13:32.535Z trace=729ea3a8af1b83ac span=86cdaded parent=2dee1101 service=cart-api op="POST /v1/carts/{id}/items" kind=server dur=5021ms status=ERROR code=500 cluster=prod-eu-central ns=shop error="redis HSET failed"
2026-10-05T19:13:32.537Z trace=729ea3a8af1b83ac span=72b81333 parent=86cdaded service=cart-api op="HSET" kind=client dur=5003ms status=ERROR peer=cart-redis db.system=redis cluster=prod-eu-central ns=shop error="dial tcp: lookup cart-redis.shop.svc.cluster.local on 10.96.0.10:53: read udp 10.244.3.17:46637->10.96.0.10:53: i/o timeout"
2026-10-05T19:15:02.112Z trace=453ff7224edd0ab2 span=a7330d89 parent=- service=storefront op="GET /products/:id" kind=server dur=142ms status=OK code=200 cluster=prod-eu-central ns=shop
2026-10-05T19:15:02.116Z trace=453ff7224edd0ab2 span=9d13793c parent=a7330d89 service=storefront op="GET" kind=client dur=128ms status=OK code=200 peer=catalog-api cluster=prod-eu-central ns=shop
2026-10-05T19:15:02.118Z trace=453ff7224edd0ab2 span=acb3b483 parent=9d13793c service=catalog-api op="GET /v1/products/{id}" kind=server dur=121ms status=OK code=200 cluster=prod-eu-central ns=shop
2026-10-05T19:15:02.121Z trace=453ff7224edd0ab2 span=1c4904ae parent=acb3b483 service=catalog-api op="SELECT products" kind=client dur=7ms status=OK peer=catalog-db db.system=postgresql cluster=prod-eu-central ns=shop
2026-10-05T19:15:02.132Z trace=453ff7224edd0ab2 span=6547417c parent=acb3b483 service=catalog-api op="GET" kind=client dur=92ms status=OK code=200 peer=search-api cluster=prod-eu-central ns=shop
2026-10-05T19:15:02.135Z trace=453ff7224edd0ab2 span=56b391e8 parent=6547417c service=search-api op="GET /v1/related" kind=server dur=86ms status=OK code=200 cluster=prod-eu-central ns=shop
2026-10-05T19:15:02.139Z trace=453ff7224edd0ab2 span=8f0664eb parent=56b391e8 service=search-api op="POST /products/_search" kind=client dur=71ms status=OK code=200 peer=search-index db.system=elasticsearch cluster=prod-eu-central ns=shop
2026-10-05T19:18:16.644Z trace=83535f021ea0d090 span=42b4d2b8 parent=- service=storefront op="POST /checkout" kind=server dur=5094ms status=ERROR code=502 cluster=prod-eu-central ns=shop error="upstream checkout-api responded 502"
2026-10-05T19:18:16.647Z trace=83535f021ea0d090 span=2f314a12 parent=42b4d2b8 service=storefront op="POST" kind=client dur=5086ms status=ERROR code=502 peer=checkout-api cluster=prod-eu-central ns=shop error="HTTP 502"
2026-10-05T19:18:16.649Z trace=83535f021ea0d090 span=52adeb19 parent=2f314a12 service=checkout-api op="POST /v1/checkout" kind=server dur=5079ms status=ERROR code=502 cluster=prod-eu-central ns=shop error="payment failed"
2026-10-05T19:18:16.653Z trace=83535f021ea0d090 span=7d2fde3c parent=52adeb19 service=checkout-api op="POST" kind=client dur=64ms status=OK code=200 peer=inventory-api cluster=prod-eu-central ns=shop
2026-10-05T19:18:16.656Z trace=83535f021ea0d090 span=df3ccb15 parent=7d2fde3c service=inventory-api op="POST /v1/reservations" kind=server dur=55ms status=OK code=200 cluster=prod-eu-central ns=shop
2026-10-05T19:18:16.720Z trace=83535f021ea0d090 span=70fdfe0d parent=52adeb19 service=checkout-api op="POST" kind=client dur=5004ms status=ERROR peer=payments-api cluster=prod-eu-central ns=shop error="dial tcp: lookup payments-api.shop.svc.cluster.local on 10.96.0.10:53: read udp 10.244.4.41:43516->10.96.0.10:53: i/o timeout"
2026-10-05T19:21:44.355Z trace=9bd07f80631c0b48 span=a0d8f025 parent=- service=storefront op="GET /products/:id" kind=server dur=5161ms status=OK code=200 cluster=prod-eu-central ns=shop
2026-10-05T19:21:44.359Z trace=9bd07f80631c0b48 span=db8c991d parent=a0d8f025 service=storefront op="GET" kind=client dur=5149ms status=OK code=200 peer=catalog-api cluster=prod-eu-central ns=shop
2026-10-05T19:21:44.361Z trace=9bd07f80631c0b48 span=6ceb9492 parent=db8c991d service=catalog-api op="GET /v1/products/{id}" kind=server dur=5141ms status=OK code=200 cluster=prod-eu-central ns=shop
2026-10-05T19:21:44.364Z trace=9bd07f80631c0b48 span=5da64bf2 parent=6ceb9492 service=catalog-api op="SELECT products" kind=client dur=7ms status=OK peer=catalog-db db.system=postgresql cluster=prod-eu-central ns=shop
2026-10-05T19:21:44.375Z trace=9bd07f80631c0b48 span=155b26c2 parent=6ceb9492 service=catalog-api op="GET" kind=client dur=5003ms status=ERROR peer=search-api cluster=prod-eu-central ns=shop error="dial tcp: lookup search-api.shop.svc.cluster.local on 10.96.0.10:53: read udp 10.244.2.34:60430->10.96.0.10:53: i/o timeout"
2026-10-05T19:26:05.227Z trace=af7e8de2b360e0cc span=147aacbd parent=- service=storefront op="POST /cart/items" kind=server dur=5032ms status=ERROR code=500 cluster=prod-eu-central ns=shop error="upstream cart-api responded 500"
2026-10-05T19:26:05.229Z trace=af7e8de2b360e0cc span=45467983 parent=147aacbd service=storefront op="POST" kind=client dur=5027ms status=ERROR code=500 peer=cart-api cluster=prod-eu-central ns=shop error="HTTP 500"
2026-10-05T19:26:05.231Z trace=af7e8de2b360e0cc span=0300834c parent=45467983 service=cart-api op="POST /v1/carts/{id}/items" kind=server dur=5021ms status=ERROR code=500 cluster=prod-eu-central ns=shop error="redis HSET failed"
2026-10-05T19:26:05.233Z trace=af7e8de2b360e0cc span=00406067 parent=0300834c service=cart-api op="HSET" kind=client dur=5003ms status=ERROR peer=cart-redis db.system=redis cluster=prod-eu-central ns=shop error="dial tcp: lookup cart-redis.shop.svc.cluster.local on 10.96.0.10:53: read udp 10.244.3.17:58916->10.96.0.10:53: i/o timeout"
2026-10-05T19:29:28.080Z trace=619d0f2c69685b9a span=cdbd9d86 parent=- service=storefront op="POST /checkout" kind=server dur=5094ms status=ERROR code=502 cluster=prod-eu-central ns=shop error="upstream checkout-api responded 502"
2026-10-05T19:29:28.083Z trace=619d0f2c69685b9a span=07707593 parent=cdbd9d86 service=storefront op="POST" kind=client dur=5086ms status=ERROR code=502 peer=checkout-api cluster=prod-eu-central ns=shop error="HTTP 502"
2026-10-05T19:29:28.085Z trace=619d0f2c69685b9a span=0b0c19b8 parent=07707593 service=checkout-api op="POST /v1/checkout" kind=server dur=5079ms status=ERROR code=502 cluster=prod-eu-central ns=shop error="payment failed"
2026-10-05T19:29:28.089Z trace=619d0f2c69685b9a span=b9b24dfe parent=0b0c19b8 service=checkout-api op="POST" kind=client dur=64ms status=OK code=200 peer=inventory-api cluster=prod-eu-central ns=shop
2026-10-05T19:29:28.092Z trace=619d0f2c69685b9a span=fdc374db parent=b9b24dfe service=inventory-api op="POST /v1/reservations" kind=server dur=55ms status=OK code=200 cluster=prod-eu-central ns=shop
2026-10-05T19:29:28.156Z trace=619d0f2c69685b9a span=2da1fdd2 parent=0b0c19b8 service=checkout-api op="POST" kind=client dur=5004ms status=ERROR peer=payments-api cluster=prod-eu-central ns=shop error="dial tcp: lookup payments-api.shop.svc.cluster.local on 10.96.0.10:53: read udp 10.244.4.41:47389->10.96.0.10:53: i/o timeout"`;

  const S2_ALERTS = `[FIRING:1] CoreDNSForwardErrorsHigh (coredns kube-system prod-eu-central critical)
2026-10-05T19:15:02Z FIRING critical CoreDNSForwardLatencyHigh service=coredns namespace=kube-system cluster=prod-eu-central to=dns://10.20.0.53:53
2026-10-05T19:17:45Z FIRING critical CheckoutHighErrorRate service=checkout-api namespace=shop cluster=prod-eu-central
2026-10-05T19:22:48Z FIRING critical StorefrontErrorBudgetBurn service=storefront namespace=shop cluster=prod-eu-central slo=storefront-availability burn_rate=62.0 error_ratio=0.031 long_window=1h short_window=5m
ALERT KubePodCrashLooping{cluster="prod-eu-central",container="coredns",namespace="kube-system",pod="coredns-7c9d4b8f6d-5kq2w",severity="warning"} firing since 2026-10-05T19:25:13Z
ALERT KubePodCrashLooping{cluster="prod-eu-central",container="coredns",namespace="kube-system",pod="coredns-7c9d4b8f6d-m8z4t",severity="warning"} firing since 2026-10-05T19:25:24Z`;

  const S2_HELM = `# cluster: prod-eu-central
$ helm history coredns -n kube-system --max 4
REVISION\tUPDATED                 \tSTATUS    \tCHART         \tAPP VERSION\tDESCRIPTION     
11      \tTue Aug 11 09:14:27 2026\tsuperseded\tcoredns-1.39.0\t1.12.1     \tUpgrade complete
12      \tTue Aug 25 13:40:02 2026\tsuperseded\tcoredns-1.39.1\t1.12.1     \tUpgrade complete
13      \tThu Sep 17 10:05:48 2026\tsuperseded\tcoredns-1.39.2\t1.12.1     \tUpgrade complete
14      \tMon Oct  5 19:01:52 2026\tdeployed  \tcoredns-1.40.0\t1.12.3     \tUpgrade complete

$ helm diff revision coredns 13 14 -n kube-system
kube-system, coredns, ConfigMap (v1) has changed:
  # Source: coredns/templates/configmap.yaml
  apiVersion: v1
  kind: ConfigMap
  metadata:
    name: coredns
    namespace: kube-system
    labels:
      app.kubernetes.io/instance: coredns
      app.kubernetes.io/managed-by: Helm
      app.kubernetes.io/name: coredns
-     helm.sh/chart: coredns-1.39.2
+     helm.sh/chart: coredns-1.40.0
      k8s-app: coredns
  data:
    Corefile: |-
      .:53 {
          errors
          health {
              lameduck 5s
          }
          ready
          kubernetes cluster.local in-addr.arpa ip6.arpa {
              pods insecure
              fallthrough in-addr.arpa ip6.arpa
              ttl 30
          }
          prometheus 0.0.0.0:9153
-         forward . /etc/resolv.conf {
-             max_concurrent 1000
-         }
-         cache 30
+         forward . 10.20.0.53 10.20.0.54 {
+             policy sequential
+         }
          loop
          reload
          loadbalance
      }
kube-system, coredns, Deployment (apps) has changed:
  # Source: coredns/templates/deployment.yaml
  apiVersion: apps/v1
  kind: Deployment
  metadata:
    name: coredns
    namespace: kube-system
    labels:
      app.kubernetes.io/instance: coredns
-     app.kubernetes.io/version: "1.12.1"
+     app.kubernetes.io/version: "1.12.3"
-     helm.sh/chart: coredns-1.39.2
+     helm.sh/chart: coredns-1.40.0
      k8s-app: coredns
  spec:
    replicas: 2
    strategy:
      type: RollingUpdate
      rollingUpdate:
        maxUnavailable: 1
        maxSurge: 25%
    template:
      spec:
        priorityClassName: system-cluster-critical
        containers:
        - name: coredns
-         image: "registry.example.com/mirror/coredns/coredns:1.12.1"
+         image: "registry.example.com/mirror/coredns/coredns:1.12.3"
          imagePullPolicy: IfNotPresent
          args: [ "-conf", "/etc/coredns/Corefile" ]
          resources:
            limits:
              memory: 170Mi
            requests:
              cpu: 100m
              memory: 70Mi`;


  // ----------------------------------------------------------------------------------------------------
  // 3. cert-expiry — Sign-ins failing at the API gateway
  // ----------------------------------------------------------------------------------------------------

  const S3_LOGS = `# cluster: prod-us-central
$ kubectl --context prod-us-central -n edge logs -l app.kubernetes.io/name=api-gateway --since=40m --prefix | grep -v healthz
[pod/api-gateway-5f7b8c9d6-2kx7m/gateway] {"level":"info","ts":"2026-10-05T20:58:12.283Z","caller":"middleware/access.go:57","msg":"request","method":"GET","path":"/v1/orders","status":200,"latency_ms":77,"trace_id":"72f91bb0e5fa1c8130a27b8fd151b620"}
[pod/api-gateway-5f7b8c9d6-9vq4n/gateway] {"level":"info","ts":"2026-10-05T20:59:03.878Z","caller":"middleware/access.go:57","msg":"request","method":"GET","path":"/v1/recommendations/popular","status":200,"latency_ms":52,"trace_id":"0e9c3693ed82c0615a114b1b75fe036f"}
[pod/api-gateway-5f7b8c9d6-hl6wr/gateway] {"level":"error","ts":"2026-10-05T21:00:41.094Z","caller":"authz/introspect.go:142","msg":"token introspection failed","upstream":"auth-service.identity.svc:9443","error":"rpc error: code = Unavailable desc = connection error: desc = \\"transport: authentication handshake failed: tls: failed to verify certificate: x509: certificate has expired or is not yet valid: current time 2026-10-05T21:00:41Z is after 2026-10-05T21:00:00Z\\"","method":"GET","path":"/v1/orders","trace_id":"d1669bfc898b6b234bdd68ba1193ea43"}
[pod/api-gateway-5f7b8c9d6-hl6wr/gateway] {"level":"info","ts":"2026-10-05T21:00:41.096Z","caller":"middleware/access.go:57","msg":"request","method":"GET","path":"/v1/orders","status":503,"latency_ms":9,"trace_id":"d1669bfc898b6b234bdd68ba1193ea43"}
[pod/api-gateway-5f7b8c9d6-9vq4n/gateway] {"level":"error","ts":"2026-10-05T21:00:44.733Z","caller":"authz/introspect.go:142","msg":"token introspection failed","upstream":"auth-service.identity.svc:9443","error":"rpc error: code = Unavailable desc = connection error: desc = \\"transport: authentication handshake failed: tls: failed to verify certificate: x509: certificate has expired or is not yet valid: current time 2026-10-05T21:00:44Z is after 2026-10-05T21:00:00Z\\"","method":"GET","path":"/v1/orders","trace_id":"e3082596eefe72e59f5657a1485dcc96"}
[pod/api-gateway-5f7b8c9d6-hl6wr/gateway] {"level":"error","ts":"2026-10-05T21:00:47.019Z","caller":"authz/introspect.go:142","msg":"token introspection failed","upstream":"auth-service.identity.svc:9443","error":"rpc error: code = Unavailable desc = connection error: desc = \\"transport: authentication handshake failed: tls: failed to verify certificate: x509: certificate has expired or is not yet valid: current time 2026-10-05T21:00:47Z is after 2026-10-05T21:00:00Z\\"","method":"GET","path":"/v1/account","trace_id":"5c7133557d9bd892787ee8902d451397"}
[pod/api-gateway-5f7b8c9d6-2kx7m/gateway] {"level":"warn","ts":"2026-10-05T21:00:52.310Z","caller":"authz/breaker.go:88","msg":"auth upstream unhealthy, opening circuit","upstream":"auth-service.identity.svc:9443","consecutive_failures":5,"open_for":"30s"}
[pod/api-gateway-5f7b8c9d6-2kx7m/gateway] {"level":"info","ts":"2026-10-05T21:01:09.618Z","caller":"middleware/access.go:57","msg":"request","method":"GET","path":"/v1/account","status":200,"latency_ms":52,"trace_id":"abca29323f7a07b47ebbf32c44119ece"}
[pod/api-gateway-5f7b8c9d6-2kx7m/gateway] {"level":"warn","ts":"2026-10-05T21:01:22.311Z","caller":"authz/breaker.go:96","msg":"circuit half-open, probing upstream","upstream":"auth-service.identity.svc:9443"}
[pod/api-gateway-5f7b8c9d6-2kx7m/gateway] {"level":"warn","ts":"2026-10-05T21:01:22.318Z","caller":"authz/breaker.go:88","msg":"auth upstream unhealthy, opening circuit","upstream":"auth-service.identity.svc:9443","consecutive_failures":1,"open_for":"60s"}
[pod/api-gateway-5f7b8c9d6-9vq4n/gateway] {"level":"error","ts":"2026-10-05T21:01:37.222Z","caller":"authz/introspect.go:142","msg":"token introspection failed","upstream":"auth-service.identity.svc:9443","error":"rpc error: code = Unavailable desc = connection error: desc = \\"transport: authentication handshake failed: tls: failed to verify certificate: x509: certificate has expired or is not yet valid: current time 2026-10-05T21:01:37Z is after 2026-10-05T21:00:00Z\\"","method":"POST","path":"/v1/cart","trace_id":"4b988412e4ddb60184f9d831c6aaf314"}
[pod/api-gateway-5f7b8c9d6-9vq4n/gateway] {"level":"info","ts":"2026-10-05T21:01:37.224Z","caller":"middleware/access.go:57","msg":"request","method":"POST","path":"/v1/cart","status":503,"latency_ms":6,"trace_id":"4b988412e4ddb60184f9d831c6aaf314"}
[pod/api-gateway-5f7b8c9d6-2kx7m/gateway] {"level":"error","ts":"2026-10-05T21:02:12.884Z","caller":"authz/introspect.go:142","msg":"token introspection failed","upstream":"auth-service.identity.svc:9443","error":"rpc error: code = Unavailable desc = connection error: desc = \\"transport: authentication handshake failed: tls: failed to verify certificate: x509: certificate has expired or is not yet valid: current time 2026-10-05T21:02:12Z is after 2026-10-05T21:00:00Z\\"","method":"GET","path":"/v1/orders","trace_id":"1a22fde8f1c2a8094d768803dbe30e2b"}
[pod/api-gateway-5f7b8c9d6-hl6wr/gateway] {"level":"error","ts":"2026-10-05T21:03:58.644Z","caller":"authz/introspect.go:142","msg":"token introspection failed","upstream":"auth-service.identity.svc:9443","error":"rpc error: code = Unavailable desc = connection error: desc = \\"transport: authentication handshake failed: tls: failed to verify certificate: x509: certificate has expired or is not yet valid: current time 2026-10-05T21:03:58Z is after 2026-10-05T21:00:00Z\\"","method":"GET","path":"/v1/orders","trace_id":"4987f5d028be87a91293315f9e66304a"}
[pod/api-gateway-5f7b8c9d6-hl6wr/gateway] {"level":"info","ts":"2026-10-05T21:03:58.646Z","caller":"middleware/access.go:57","msg":"request","method":"GET","path":"/v1/orders","status":503,"latency_ms":4,"trace_id":"4987f5d028be87a91293315f9e66304a"}
[pod/api-gateway-5f7b8c9d6-9vq4n/gateway] {"level":"error","ts":"2026-10-05T21:05:31.402Z","caller":"authz/introspect.go:142","msg":"token introspection failed","upstream":"auth-service.identity.svc:9443","error":"rpc error: code = Unavailable desc = connection error: desc = \\"transport: authentication handshake failed: tls: failed to verify certificate: x509: certificate has expired or is not yet valid: current time 2026-10-05T21:05:31Z is after 2026-10-05T21:00:00Z\\"","method":"GET","path":"/v1/account","trace_id":"ccd9627fa2053909ae3b9b51ea25f7eb"}
[pod/api-gateway-5f7b8c9d6-2kx7m/gateway] {"level":"info","ts":"2026-10-05T21:06:20.202Z","caller":"middleware/access.go:57","msg":"request","method":"GET","path":"/v1/recommendations/popular","status":200,"latency_ms":47,"trace_id":"6897fe338fcc1174d1b3ce94c2449fcc"}
[pod/api-gateway-5f7b8c9d6-9vq4n/gateway] {"level":"error","ts":"2026-10-05T21:09:44.909Z","caller":"authz/introspect.go:142","msg":"token introspection failed","upstream":"auth-service.identity.svc:9443","error":"rpc error: code = Unavailable desc = connection error: desc = \\"transport: authentication handshake failed: tls: failed to verify certificate: x509: certificate has expired or is not yet valid: current time 2026-10-05T21:09:44Z is after 2026-10-05T21:00:00Z\\"","method":"POST","path":"/v1/checkout","trace_id":"17063e6674ead45c461328a1b6c50f16"}
[pod/api-gateway-5f7b8c9d6-9vq4n/gateway] {"level":"info","ts":"2026-10-05T21:09:44.911Z","caller":"middleware/access.go:57","msg":"request","method":"POST","path":"/v1/checkout","status":503,"latency_ms":9,"trace_id":"17063e6674ead45c461328a1b6c50f16"}
[pod/api-gateway-5f7b8c9d6-hl6wr/gateway] {"level":"error","ts":"2026-10-05T21:12:09.551Z","caller":"authz/introspect.go:142","msg":"token introspection failed","upstream":"auth-service.identity.svc:9443","error":"rpc error: code = Unavailable desc = connection error: desc = \\"transport: authentication handshake failed: tls: failed to verify certificate: x509: certificate has expired or is not yet valid: current time 2026-10-05T21:12:09Z is after 2026-10-05T21:00:00Z\\"","method":"GET","path":"/v1/orders","trace_id":"7f40bd3fc49639663a14d5c302871945"}
[pod/api-gateway-5f7b8c9d6-hl6wr/gateway] {"level":"error","ts":"2026-10-05T21:14:02.340Z","caller":"authz/introspect.go:142","msg":"token introspection failed","upstream":"auth-service.identity.svc:9443","error":"rpc error: code = Unavailable desc = connection error: desc = \\"transport: authentication handshake failed: tls: failed to verify certificate: x509: certificate has expired or is not yet valid: current time 2026-10-05T21:14:02Z is after 2026-10-05T21:00:00Z\\"","method":"GET","path":"/v1/account","trace_id":"1ade366119f9ba1548b67e5d9e2e9a9f"}
[pod/api-gateway-5f7b8c9d6-hl6wr/gateway] {"level":"info","ts":"2026-10-05T21:14:02.342Z","caller":"middleware/access.go:57","msg":"request","method":"GET","path":"/v1/account","status":503,"latency_ms":5,"trace_id":"1ade366119f9ba1548b67e5d9e2e9a9f"}
[pod/api-gateway-5f7b8c9d6-2kx7m/gateway] {"level":"info","ts":"2026-10-05T21:18:30.532Z","caller":"middleware/access.go:57","msg":"request","method":"GET","path":"/v1/catalog/items","status":200,"latency_ms":38,"trace_id":"57f87b11be6da06dc33f58445b37f9d4"}
[pod/api-gateway-5f7b8c9d6-9vq4n/gateway] {"level":"error","ts":"2026-10-05T21:22:15.012Z","caller":"authz/introspect.go:142","msg":"token introspection failed","upstream":"auth-service.identity.svc:9443","error":"rpc error: code = Unavailable desc = connection error: desc = \\"transport: authentication handshake failed: tls: failed to verify certificate: x509: certificate has expired or is not yet valid: current time 2026-10-05T21:22:15Z is after 2026-10-05T21:00:00Z\\"","method":"GET","path":"/v1/orders","trace_id":"eb763f7e7ec6242863cd872e6ed92a78"}
[pod/api-gateway-5f7b8c9d6-9vq4n/gateway] {"level":"info","ts":"2026-10-05T21:22:15.014Z","caller":"middleware/access.go:57","msg":"request","method":"GET","path":"/v1/orders","status":503,"latency_ms":6,"trace_id":"eb763f7e7ec6242863cd872e6ed92a78"}
[pod/api-gateway-5f7b8c9d6-2kx7m/gateway] {"level":"error","ts":"2026-10-05T21:25:40.163Z","caller":"authz/introspect.go:142","msg":"token introspection failed","upstream":"auth-service.identity.svc:9443","error":"rpc error: code = Unavailable desc = connection error: desc = \\"transport: authentication handshake failed: tls: failed to verify certificate: x509: certificate has expired or is not yet valid: current time 2026-10-05T21:25:40Z is after 2026-10-05T21:00:00Z\\"","method":"GET","path":"/v1/account","trace_id":"7c4df85f9cef278dde1d37eea6ae9407"}
[pod/api-gateway-5f7b8c9d6-hl6wr/gateway] {"level":"info","ts":"2026-10-05T21:27:51.754Z","caller":"middleware/access.go:57","msg":"request","method":"GET","path":"/v1/recommendations/popular","status":200,"latency_ms":91,"trace_id":"540368933cc87cea2ee0033658c02392"}
[pod/api-gateway-5f7b8c9d6-2kx7m/gateway] {"level":"error","ts":"2026-10-05T21:31:06.285Z","caller":"authz/introspect.go:142","msg":"token introspection failed","upstream":"auth-service.identity.svc:9443","error":"rpc error: code = Unavailable desc = connection error: desc = \\"transport: authentication handshake failed: tls: failed to verify certificate: x509: certificate has expired or is not yet valid: current time 2026-10-05T21:31:06Z is after 2026-10-05T21:00:00Z\\"","method":"POST","path":"/v1/checkout","trace_id":"412288b7a73bf86b9a6fd5f43199e16d"}
[pod/api-gateway-5f7b8c9d6-2kx7m/gateway] {"level":"info","ts":"2026-10-05T21:31:06.287Z","caller":"middleware/access.go:57","msg":"request","method":"POST","path":"/v1/checkout","status":503,"latency_ms":5,"trace_id":"412288b7a73bf86b9a6fd5f43199e16d"}
[pod/api-gateway-5f7b8c9d6-9vq4n/gateway] {"level":"error","ts":"2026-10-05T21:33:12.744Z","caller":"authz/introspect.go:142","msg":"token introspection failed","upstream":"auth-service.identity.svc:9443","error":"rpc error: code = Unavailable desc = connection error: desc = \\"transport: authentication handshake failed: tls: failed to verify certificate: x509: certificate has expired or is not yet valid: current time 2026-10-05T21:33:12Z is after 2026-10-05T21:00:00Z\\"","method":"GET","path":"/v1/account","trace_id":"c2dd97bd4fcd19a6b5bd7584ade40d0d"}
[pod/api-gateway-5f7b8c9d6-9vq4n/gateway] {"level":"info","ts":"2026-10-05T21:33:12.746Z","caller":"middleware/access.go:57","msg":"request","method":"GET","path":"/v1/account","status":503,"latency_ms":8,"trace_id":"c2dd97bd4fcd19a6b5bd7584ade40d0d"}

$ kubectl --context prod-us-central -n identity logs -l app.kubernetes.io/name=auth-service --since=40m --prefix | grep -v '"msg":"health'
[pod/auth-service-7d4c9b8f5-6pz2r/auth-service] {"level":"info","ts":"2026-10-05T20:58:12.207Z","logger":"introspect","msg":"token introspected","client":"api-gateway","active":true,"latency_ms":3}
[pod/auth-service-7d4c9b8f5-kq9xd/auth-service] {"level":"info","ts":"2026-10-05T20:59:40.552Z","logger":"introspect","msg":"token introspected","client":"api-gateway","active":true,"latency_ms":2}
[pod/auth-service-7d4c9b8f5-6pz2r/auth-service] {"level":"warn","ts":"2026-10-05T21:00:41.093Z","logger":"grpc","msg":"[core] [Server #1]grpc: Server.Serve failed to complete security handshake from \\"10.12.4.31:40489\\": remote error: tls: bad certificate","system":"grpc","grpc_log":true}
[pod/auth-service-7d4c9b8f5-kq9xd/auth-service] {"level":"warn","ts":"2026-10-05T21:00:44.736Z","logger":"grpc","msg":"[core] [Server #1]grpc: Server.Serve failed to complete security handshake from \\"10.12.5.18:58525\\": remote error: tls: bad certificate","system":"grpc","grpc_log":true}
[pod/auth-service-7d4c9b8f5-6pz2r/auth-service] {"level":"warn","ts":"2026-10-05T21:01:37.221Z","logger":"grpc","msg":"[core] [Server #1]grpc: Server.Serve failed to complete security handshake from \\"10.12.6.22:40109\\": remote error: tls: bad certificate","system":"grpc","grpc_log":true}
[pod/auth-service-7d4c9b8f5-kq9xd/auth-service] {"level":"warn","ts":"2026-10-05T21:02:12.887Z","logger":"grpc","msg":"[core] [Server #1]grpc: Server.Serve failed to complete security handshake from \\"10.12.4.31:44940\\": remote error: tls: bad certificate","system":"grpc","grpc_log":true}
[pod/auth-service-7d4c9b8f5-6pz2r/auth-service] {"level":"warn","ts":"2026-10-05T21:03:58.643Z","logger":"grpc","msg":"[core] [Server #1]grpc: Server.Serve failed to complete security handshake from \\"10.12.5.18:51923\\": remote error: tls: bad certificate","system":"grpc","grpc_log":true}
[pod/auth-service-7d4c9b8f5-kq9xd/auth-service] {"level":"warn","ts":"2026-10-05T21:09:44.908Z","logger":"grpc","msg":"[core] [Server #1]grpc: Server.Serve failed to complete security handshake from \\"10.12.6.22:59270\\": remote error: tls: bad certificate","system":"grpc","grpc_log":true}
[pod/auth-service-7d4c9b8f5-6pz2r/auth-service] {"level":"warn","ts":"2026-10-05T21:14:02.339Z","logger":"grpc","msg":"[core] [Server #1]grpc: Server.Serve failed to complete security handshake from \\"10.12.4.31:44570\\": remote error: tls: bad certificate","system":"grpc","grpc_log":true}
[pod/auth-service-7d4c9b8f5-6pz2r/auth-service] {"level":"info","ts":"2026-10-05T21:20:00.004Z","logger":"certwatch","msg":"serving certificate unchanged","source":"identity/auth-service-mtls","not_after":"2026-10-05T21:00:00Z","subject":"CN=auth-service.identity.svc"}
[pod/auth-service-7d4c9b8f5-kq9xd/auth-service] {"level":"warn","ts":"2026-10-05T21:22:15.011Z","logger":"grpc","msg":"[core] [Server #1]grpc: Server.Serve failed to complete security handshake from \\"10.12.5.18:60007\\": remote error: tls: bad certificate","system":"grpc","grpc_log":true}
[pod/auth-service-7d4c9b8f5-6pz2r/auth-service] {"level":"warn","ts":"2026-10-05T21:31:06.284Z","logger":"grpc","msg":"[core] [Server #1]grpc: Server.Serve failed to complete security handshake from \\"10.12.6.22:54255\\": remote error: tls: bad certificate","system":"grpc","grpc_log":true}

$ kubectl --context prod-us-central -n identity get certificate,certificaterequest
NAME                                            READY   SECRET              AGE
certificate.cert-manager.io/auth-service-mtls   False   auth-service-mtls   454d

NAME                                                      APPROVED   DENIED   READY   ISSUER              REQUESTOR                                         AGE
certificaterequest.cert-manager.io/auth-service-mtls-27   True                False   vault-internal-ca   system:serviceaccount:cert-manager:cert-manager   17h

$ kubectl --context prod-us-central -n identity describe certificate auth-service-mtls | sed -n '/^Status:/,$p'
Status:
  Conditions:
    Last Transition Time:  2026-10-05T21:00:00Z
    Message:               Certificate expired on Mon, 05 Oct 2026 21:00:00 UTC
    Observed Generation:   3
    Reason:                Expired
    Status:                False
    Type:                  Ready
    Last Transition Time:  2026-10-05T04:00:12Z
    Message:               The certificate request has failed to complete and will be retried: Vault failed to sign certificate: Error making API request. URL: PUT https://vault.internal.example.com/v1/pki_int/sign/auth-service Code: 403. Errors: * permission denied
    Observed Generation:   3
    Reason:                Failed
    Status:                False
    Type:                  Issuing
  Failed Issuance Attempts:  27
  Last Failure Time:         2026-10-05T04:00:12Z
  Not After:                 2026-10-05T21:00:00Z
  Not Before:                2026-07-07T21:00:00Z
  Renewal Time:              2026-09-05T21:00:00Z
  Revision:                  3
Events:                      <none>

$ kubectl --context prod-us-central -n identity get secret auth-service-mtls -o jsonpath='{.data.tls\\.crt}' | base64 -d | openssl x509 -noout -subject -issuer -enddate
subject=CN=auth-service.identity.svc
issuer=CN=Example Internal Issuing CA 2026
notAfter=Oct  5 21:00:00 2026 GMT

$ kubectl --context prod-us-central -n identity get events
No resources found in identity namespace.

$ kubectl --context prod-us-central get pods -n identity -o wide
NAME                           READY   STATUS    RESTARTS   AGE   IP           NODE                              NOMINATED NODE   READINESS GATES
auth-service-7d4c9b8f5-6pz2r   1/1     Running   0          12d   10.12.7.40   aks-general-61829374-vmss000003   <none>           <none>
auth-service-7d4c9b8f5-kq9xd   1/1     Running   0          12d   10.12.8.11   aks-general-61829374-vmss000004   <none>           <none>

$ kubectl --context prod-us-central -n discovery logs -l app.kubernetes.io/name=recommendations --since=4h --prefix --timestamps | grep -v healthz | head -n 9
[pod/recommendations-6b8c9d7f5-tx4lp/recommendations] 2026-10-05T18:02:57.902401324Z INFO:     Started server process [1]
[pod/recommendations-6b8c9d7f5-tx4lp/recommendations] 2026-10-05T18:02:57.904076153Z INFO:     Waiting for application startup.
[pod/recommendations-6b8c9d7f5-tx4lp/recommendations] 2026-10-05T18:02:58.44197101Z {"timestamp":"2026-10-05T14:02:58.441-04:00","level":"INFO","logger":"recs.model","message":"loading model","model_version":"recs-2026-10-04","diversity_weight":0.15}
[pod/recommendations-6b8c9d7f5-tx4lp/recommendations] 2026-10-05T18:03:09.20701378Z {"timestamp":"2026-10-05T14:03:09.207-04:00","level":"INFO","logger":"recs.model","message":"model loaded","items":184220,"load_ms":10766}
[pod/recommendations-6b8c9d7f5-tx4lp/recommendations] 2026-10-05T18:03:09.213308236Z INFO:     Application startup complete.
[pod/recommendations-6b8c9d7f5-tx4lp/recommendations] 2026-10-05T18:03:09.215585657Z INFO:     Uvicorn running on http://0.0.0.0:8080 (Press CTRL+C to quit)
[pod/recommendations-6b8c9d7f5-v2qzn/recommendations] 2026-10-05T18:03:28.902244276Z INFO:     Started server process [1]
[pod/recommendations-6b8c9d7f5-v2qzn/recommendations] 2026-10-05T18:03:28.90494254Z INFO:     Waiting for application startup.
[pod/recommendations-6b8c9d7f5-v2qzn/recommendations] 2026-10-05T18:03:29.441396525Z {"timestamp":"2026-10-05T14:03:29.441-04:00","level":"INFO","logger":"recs.model","message":"loading model","model_version":"recs-2026-10-04","diversity_weight":0.15}
$ kubectl --context prod-us-central -n discovery logs -l app.kubernetes.io/name=recommendations --since=40m --prefix --timestamps | grep -v healthz | tail -n 5
[pod/recommendations-6b8c9d7f5-tx4lp/recommendations] 2026-10-05T20:59:03.820593698Z INFO:     10.12.4.31:44305 - "GET /v1/recommendations/popular?limit=12 HTTP/1.1" 200 OK
[pod/recommendations-6b8c9d7f5-v2qzn/recommendations] 2026-10-05T21:06:20.126370814Z INFO:     10.12.5.18:40559 - "GET /v1/recommendations/popular?limit=12 HTTP/1.1" 200 OK
[pod/recommendations-6b8c9d7f5-tx4lp/recommendations] 2026-10-05T21:12:40.520661996Z INFO:     10.12.6.22:54132 - "GET /v1/recommendations/popular?limit=12 HTTP/1.1" 200 OK
[pod/recommendations-6b8c9d7f5-v2qzn/recommendations] 2026-10-05T21:27:51.702391608Z INFO:     10.12.4.31:51632 - "GET /v1/recommendations/popular?limit=12 HTTP/1.1" 200 OK
[pod/recommendations-6b8c9d7f5-tx4lp/recommendations] 2026-10-05T21:30:02.886954336Z INFO:     10.12.5.18:45512 - "GET /v1/recommendations/popular?limit=12 HTTP/1.1" 200 OK`;

  const S3_TRACES = `{
  "resourceSpans": [
    {
      "resource": {
        "attributes": [
          {"key":"service.name","value":{"stringValue":"api-gateway"}},
          {"key":"service.version","value":{"stringValue":"7.3.1"}},
          {"key":"k8s.cluster.name","value":{"stringValue":"prod-us-central"}},
          {"key":"k8s.namespace.name","value":{"stringValue":"edge"}},
          {"key":"k8s.pod.name","value":{"stringValue":"api-gateway-5f7b8c9d6-2kx7m"}}
        ]
      },
      "scopeSpans": [
        {
          "scope": {"name":"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp","version":"0.63.0"},
          "spans": [
            {"traceId":"72f91bb0e5fa1c8130a27b8fd151b620","spanId":"e204fb613668b810","name":"GET /v1/orders","kind":"SPAN_KIND_SERVER","startTimeUnixNano":"1791233892204802239","endTimeUnixNano":"1791233892250837603","attributes":[{"key":"http.request.method","value":{"stringValue":"GET"}},{"key":"http.route","value":{"stringValue":"/v1/orders"}},{"key":"http.response.status_code","value":{"intValue":"200"}}],"status":{}},
            {"traceId":"72f91bb0e5fa1c8130a27b8fd151b620","spanId":"043340b969307161","parentSpanId":"e204fb613668b810","name":"GET","kind":"SPAN_KIND_CLIENT","startTimeUnixNano":"1791233892212892210","endTimeUnixNano":"1791233892246221312","attributes":[{"key":"http.request.method","value":{"stringValue":"GET"}},{"key":"server.address","value":{"stringValue":"orders-api.commerce.svc"}},{"key":"peer.service","value":{"stringValue":"orders-api"}},{"key":"http.response.status_code","value":{"intValue":"200"}}],"status":{}},
            {"traceId":"abca29323f7a07b47ebbf32c44119ece","spanId":"1c4ee4189dc87642","name":"GET /v1/account","kind":"SPAN_KIND_SERVER","startTimeUnixNano":"1791234069552870872","endTimeUnixNano":"1791234069589564662","attributes":[{"key":"http.request.method","value":{"stringValue":"GET"}},{"key":"http.route","value":{"stringValue":"/v1/account"}},{"key":"http.response.status_code","value":{"intValue":"200"}}],"status":{}},
            {"traceId":"abca29323f7a07b47ebbf32c44119ece","spanId":"2076ce765c87f8ea","parentSpanId":"1c4ee4189dc87642","name":"GET","kind":"SPAN_KIND_CLIENT","startTimeUnixNano":"1791234069553540943","endTimeUnixNano":"1791234069586123473","attributes":[{"key":"http.request.method","value":{"stringValue":"GET"}},{"key":"server.address","value":{"stringValue":"accounts-api.commerce.svc"}},{"key":"peer.service","value":{"stringValue":"accounts-api"}},{"key":"http.response.status_code","value":{"intValue":"200"}}],"status":{}},
            {"traceId":"6897fe338fcc1174d1b3ce94c2449fcc","spanId":"413ad5bf10853e8d","name":"GET /v1/recommendations/popular","kind":"SPAN_KIND_SERVER","startTimeUnixNano":"1791234380117709081","endTimeUnixNano":"1791234380159267228","attributes":[{"key":"http.request.method","value":{"stringValue":"GET"}},{"key":"http.route","value":{"stringValue":"/v1/recommendations/popular"}},{"key":"http.response.status_code","value":{"intValue":"200"}}],"status":{}},
            {"traceId":"6897fe338fcc1174d1b3ce94c2449fcc","spanId":"cc435b97c591ebc2","parentSpanId":"413ad5bf10853e8d","name":"GET","kind":"SPAN_KIND_CLIENT","startTimeUnixNano":"1791234380118572026","endTimeUnixNano":"1791234380156782694","attributes":[{"key":"http.request.method","value":{"stringValue":"GET"}},{"key":"server.address","value":{"stringValue":"recommendations.discovery.svc"}},{"key":"peer.service","value":{"stringValue":"recommendations"}},{"key":"http.response.status_code","value":{"intValue":"200"}}],"status":{}},
            {"traceId":"57f87b11be6da06dc33f58445b37f9d4","spanId":"92fbee01356b9051","name":"GET /v1/catalog/items","kind":"SPAN_KIND_SERVER","startTimeUnixNano":"1791235110472690113","endTimeUnixNano":"1791235110539558432","attributes":[{"key":"http.request.method","value":{"stringValue":"GET"}},{"key":"http.route","value":{"stringValue":"/v1/catalog/items"}},{"key":"http.response.status_code","value":{"intValue":"200"}}],"status":{}},
            {"traceId":"57f87b11be6da06dc33f58445b37f9d4","spanId":"40e27f3c2e5aa498","parentSpanId":"92fbee01356b9051","name":"GET","kind":"SPAN_KIND_CLIENT","startTimeUnixNano":"1791235110473700403","endTimeUnixNano":"1791235110536542159","attributes":[{"key":"http.request.method","value":{"stringValue":"GET"}},{"key":"server.address","value":{"stringValue":"catalog-api.commerce.svc"}},{"key":"peer.service","value":{"stringValue":"catalog-api"}},{"key":"http.response.status_code","value":{"intValue":"200"}}],"status":{}},
            {"traceId":"412288b7a73bf86b9a6fd5f43199e16d","spanId":"97ff424ab0584b7c","name":"POST /v1/checkout","kind":"SPAN_KIND_SERVER","startTimeUnixNano":"1791235866281342570","endTimeUnixNano":"1791235866288639574","attributes":[{"key":"http.request.method","value":{"stringValue":"POST"}},{"key":"http.route","value":{"stringValue":"/v1/checkout"}},{"key":"http.response.status_code","value":{"intValue":"503"}}],"status":{"code":"STATUS_CODE_ERROR","message":"authentication service unavailable"}}
          ]
        },
        {
          "scope": {"name":"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc","version":"0.63.0"},
          "spans": [
            {"traceId":"72f91bb0e5fa1c8130a27b8fd151b620","spanId":"a23c19f607f5f617","parentSpanId":"e204fb613668b810","name":"auth.v1.TokenService/Introspect","kind":"SPAN_KIND_CLIENT","startTimeUnixNano":"1791233892205107860","endTimeUnixNano":"1791233892211203238","attributes":[{"key":"rpc.system","value":{"stringValue":"grpc"}},{"key":"rpc.service","value":{"stringValue":"auth.v1.TokenService"}},{"key":"rpc.method","value":{"stringValue":"Introspect"}},{"key":"server.address","value":{"stringValue":"auth-service.identity.svc"}},{"key":"server.port","value":{"intValue":"9443"}},{"key":"peer.service","value":{"stringValue":"auth-service"}},{"key":"rpc.grpc.status_code","value":{"intValue":"0"}}],"status":{}},
            {"traceId":"412288b7a73bf86b9a6fd5f43199e16d","spanId":"3e19fa800c1c861d","parentSpanId":"97ff424ab0584b7c","name":"auth.v1.TokenService/Introspect","kind":"SPAN_KIND_CLIENT","startTimeUnixNano":"1791235866282197808","endTimeUnixNano":"1791235866286060628","attributes":[{"key":"rpc.system","value":{"stringValue":"grpc"}},{"key":"rpc.service","value":{"stringValue":"auth.v1.TokenService"}},{"key":"rpc.method","value":{"stringValue":"Introspect"}},{"key":"server.address","value":{"stringValue":"auth-service.identity.svc"}},{"key":"server.port","value":{"intValue":"9443"}},{"key":"peer.service","value":{"stringValue":"auth-service"}},{"key":"rpc.grpc.status_code","value":{"intValue":"14"}}],"status":{"code":"STATUS_CODE_ERROR","message":"connection error: desc = \\"transport: authentication handshake failed: tls: failed to verify certificate: x509: certificate has expired or is not yet valid: current time 2026-10-05T21:31:06Z is after 2026-10-05T21:00:00Z\\""}}
          ]
        }
      ]
    },
    {
      "resource": {
        "attributes": [
          {"key":"service.name","value":{"stringValue":"auth-service"}},
          {"key":"service.version","value":{"stringValue":"5.0.4"}},
          {"key":"k8s.cluster.name","value":{"stringValue":"prod-us-central"}},
          {"key":"k8s.namespace.name","value":{"stringValue":"identity"}},
          {"key":"k8s.pod.name","value":{"stringValue":"auth-service-7d4c9b8f5-6pz2r"}}
        ]
      },
      "scopeSpans": [
        {
          "scope": {"name":"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc","version":"0.63.0"},
          "spans": [
            {"traceId":"72f91bb0e5fa1c8130a27b8fd151b620","spanId":"efa096fcd3b7cbdc","parentSpanId":"a23c19f607f5f617","name":"auth.v1.TokenService/Introspect","kind":"SPAN_KIND_SERVER","startTimeUnixNano":"1791233892206067564","endTimeUnixNano":"1791233892210075818","attributes":[{"key":"rpc.system","value":{"stringValue":"grpc"}},{"key":"rpc.service","value":{"stringValue":"auth.v1.TokenService"}},{"key":"rpc.method","value":{"stringValue":"Introspect"}},{"key":"rpc.grpc.status_code","value":{"intValue":"0"}}],"status":{}}
          ]
        }
      ]
    },
    {
      "resource": {
        "attributes": [
          {"key":"service.name","value":{"stringValue":"orders-api"}},
          {"key":"service.version","value":{"stringValue":"4.2.0"}},
          {"key":"k8s.cluster.name","value":{"stringValue":"prod-us-central"}},
          {"key":"k8s.namespace.name","value":{"stringValue":"commerce"}},
          {"key":"k8s.pod.name","value":{"stringValue":"orders-api-6c9d8b7f5-mxq4z"}}
        ]
      },
      "scopeSpans": [
        {
          "scope": {"name":"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp","version":"0.63.0"},
          "spans": [
            {"traceId":"72f91bb0e5fa1c8130a27b8fd151b620","spanId":"0c462c7578caa93e","parentSpanId":"043340b969307161","name":"GET /v1/orders","kind":"SPAN_KIND_SERVER","startTimeUnixNano":"1791233892213974274","endTimeUnixNano":"1791233892244399014","attributes":[{"key":"http.request.method","value":{"stringValue":"GET"}},{"key":"http.response.status_code","value":{"intValue":"200"}}],"status":{}}
          ]
        }
      ]
    },
    {
      "resource": {
        "attributes": [
          {"key":"service.name","value":{"stringValue":"api-gateway"}},
          {"key":"service.version","value":{"stringValue":"7.3.1"}},
          {"key":"k8s.cluster.name","value":{"stringValue":"prod-us-central"}},
          {"key":"k8s.namespace.name","value":{"stringValue":"edge"}},
          {"key":"k8s.pod.name","value":{"stringValue":"api-gateway-5f7b8c9d6-9vq4n"}}
        ]
      },
      "scopeSpans": [
        {
          "scope": {"name":"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp","version":"0.63.0"},
          "spans": [
            {"traceId":"0e9c3693ed82c0615a114b1b75fe036f","spanId":"82db8570957eb592","name":"GET /v1/recommendations/popular","kind":"SPAN_KIND_SERVER","startTimeUnixNano":"1791233943811525987","endTimeUnixNano":"1791233943847232119","attributes":[{"key":"http.request.method","value":{"stringValue":"GET"}},{"key":"http.route","value":{"stringValue":"/v1/recommendations/popular"}},{"key":"http.response.status_code","value":{"intValue":"200"}}],"status":{}},
            {"traceId":"0e9c3693ed82c0615a114b1b75fe036f","spanId":"613771c808c06a71","parentSpanId":"82db8570957eb592","name":"GET","kind":"SPAN_KIND_CLIENT","startTimeUnixNano":"1791233943812256782","endTimeUnixNano":"1791233943844031553","attributes":[{"key":"http.request.method","value":{"stringValue":"GET"}},{"key":"server.address","value":{"stringValue":"recommendations.discovery.svc"}},{"key":"peer.service","value":{"stringValue":"recommendations"}},{"key":"http.response.status_code","value":{"intValue":"200"}}],"status":{}},
            {"traceId":"4b988412e4ddb60184f9d831c6aaf314","spanId":"411ea0b8a45e3168","name":"POST /v1/cart","kind":"SPAN_KIND_SERVER","startTimeUnixNano":"1791234097218816385","endTimeUnixNano":"1791234097226174582","attributes":[{"key":"http.request.method","value":{"stringValue":"POST"}},{"key":"http.route","value":{"stringValue":"/v1/cart"}},{"key":"http.response.status_code","value":{"intValue":"503"}}],"status":{"code":"STATUS_CODE_ERROR","message":"authentication service unavailable"}},
            {"traceId":"17063e6674ead45c461328a1b6c50f16","spanId":"69af60a7a5eacda8","name":"POST /v1/checkout","kind":"SPAN_KIND_SERVER","startTimeUnixNano":"1791234584905335411","endTimeUnixNano":"1791234584913409903","attributes":[{"key":"http.request.method","value":{"stringValue":"POST"}},{"key":"http.route","value":{"stringValue":"/v1/checkout"}},{"key":"http.response.status_code","value":{"intValue":"503"}}],"status":{"code":"STATUS_CODE_ERROR","message":"authentication service unavailable"}},
            {"traceId":"eb763f7e7ec6242863cd872e6ed92a78","spanId":"313782c264979454","name":"GET /v1/orders","kind":"SPAN_KIND_SERVER","startTimeUnixNano":"1791235335008433784","endTimeUnixNano":"1791235335015906623","attributes":[{"key":"http.request.method","value":{"stringValue":"GET"}},{"key":"http.route","value":{"stringValue":"/v1/orders"}},{"key":"http.response.status_code","value":{"intValue":"503"}}],"status":{"code":"STATUS_CODE_ERROR","message":"authentication service unavailable"}},
            {"traceId":"c2dd97bd4fcd19a6b5bd7584ade40d0d","spanId":"b57c54c14b38352f","name":"GET /v1/account","kind":"SPAN_KIND_SERVER","startTimeUnixNano":"1791235992740379009","endTimeUnixNano":"1791235992746768317","attributes":[{"key":"http.request.method","value":{"stringValue":"GET"}},{"key":"http.route","value":{"stringValue":"/v1/account"}},{"key":"http.response.status_code","value":{"intValue":"503"}}],"status":{"code":"STATUS_CODE_ERROR","message":"authentication service unavailable"}}
          ]
        },
        {
          "scope": {"name":"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc","version":"0.63.0"},
          "spans": [
            {"traceId":"4b988412e4ddb60184f9d831c6aaf314","spanId":"19871ab00045b99a","parentSpanId":"411ea0b8a45e3168","name":"auth.v1.TokenService/Introspect","kind":"SPAN_KIND_CLIENT","startTimeUnixNano":"1791234097219499583","endTimeUnixNano":"1791234097224030580","attributes":[{"key":"rpc.system","value":{"stringValue":"grpc"}},{"key":"rpc.service","value":{"stringValue":"auth.v1.TokenService"}},{"key":"rpc.method","value":{"stringValue":"Introspect"}},{"key":"server.address","value":{"stringValue":"auth-service.identity.svc"}},{"key":"server.port","value":{"intValue":"9443"}},{"key":"peer.service","value":{"stringValue":"auth-service"}},{"key":"rpc.grpc.status_code","value":{"intValue":"14"}}],"status":{"code":"STATUS_CODE_ERROR","message":"connection error: desc = \\"transport: authentication handshake failed: tls: failed to verify certificate: x509: certificate has expired or is not yet valid: current time 2026-10-05T21:01:37Z is after 2026-10-05T21:00:00Z\\""}},
            {"traceId":"17063e6674ead45c461328a1b6c50f16","spanId":"875abda29db0687e","parentSpanId":"69af60a7a5eacda8","name":"auth.v1.TokenService/Introspect","kind":"SPAN_KIND_CLIENT","startTimeUnixNano":"1791234584906148655","endTimeUnixNano":"1791234584911869634","attributes":[{"key":"rpc.system","value":{"stringValue":"grpc"}},{"key":"rpc.service","value":{"stringValue":"auth.v1.TokenService"}},{"key":"rpc.method","value":{"stringValue":"Introspect"}},{"key":"server.address","value":{"stringValue":"auth-service.identity.svc"}},{"key":"server.port","value":{"intValue":"9443"}},{"key":"peer.service","value":{"stringValue":"auth-service"}},{"key":"rpc.grpc.status_code","value":{"intValue":"14"}}],"status":{"code":"STATUS_CODE_ERROR","message":"connection error: desc = \\"transport: authentication handshake failed: tls: failed to verify certificate: x509: certificate has expired or is not yet valid: current time 2026-10-05T21:09:44Z is after 2026-10-05T21:00:00Z\\""}},
            {"traceId":"eb763f7e7ec6242863cd872e6ed92a78","spanId":"56be113b806042b2","parentSpanId":"313782c264979454","name":"auth.v1.TokenService/Introspect","kind":"SPAN_KIND_CLIENT","startTimeUnixNano":"1791235335009159845","endTimeUnixNano":"1791235335013550170","attributes":[{"key":"rpc.system","value":{"stringValue":"grpc"}},{"key":"rpc.service","value":{"stringValue":"auth.v1.TokenService"}},{"key":"rpc.method","value":{"stringValue":"Introspect"}},{"key":"server.address","value":{"stringValue":"auth-service.identity.svc"}},{"key":"server.port","value":{"intValue":"9443"}},{"key":"peer.service","value":{"stringValue":"auth-service"}},{"key":"rpc.grpc.status_code","value":{"intValue":"14"}}],"status":{"code":"STATUS_CODE_ERROR","message":"connection error: desc = \\"transport: authentication handshake failed: tls: failed to verify certificate: x509: certificate has expired or is not yet valid: current time 2026-10-05T21:22:15Z is after 2026-10-05T21:00:00Z\\""}},
            {"traceId":"c2dd97bd4fcd19a6b5bd7584ade40d0d","spanId":"cc54e4a160e8dc6b","parentSpanId":"b57c54c14b38352f","name":"auth.v1.TokenService/Introspect","kind":"SPAN_KIND_CLIENT","startTimeUnixNano":"1791235992741308965","endTimeUnixNano":"1791235992744066210","attributes":[{"key":"rpc.system","value":{"stringValue":"grpc"}},{"key":"rpc.service","value":{"stringValue":"auth.v1.TokenService"}},{"key":"rpc.method","value":{"stringValue":"Introspect"}},{"key":"server.address","value":{"stringValue":"auth-service.identity.svc"}},{"key":"server.port","value":{"intValue":"9443"}},{"key":"peer.service","value":{"stringValue":"auth-service"}},{"key":"rpc.grpc.status_code","value":{"intValue":"14"}}],"status":{"code":"STATUS_CODE_ERROR","message":"connection error: desc = \\"transport: authentication handshake failed: tls: failed to verify certificate: x509: certificate has expired or is not yet valid: current time 2026-10-05T21:33:12Z is after 2026-10-05T21:00:00Z\\""}}
          ]
        }
      ]
    },
    {
      "resource": {
        "attributes": [
          {"key":"service.name","value":{"stringValue":"recommendations"}},
          {"key":"service.version","value":{"stringValue":"3.5.0"}},
          {"key":"k8s.cluster.name","value":{"stringValue":"prod-us-central"}},
          {"key":"k8s.namespace.name","value":{"stringValue":"discovery"}},
          {"key":"k8s.pod.name","value":{"stringValue":"recommendations-6b8c9d7f5-tx4lp"}}
        ]
      },
      "scopeSpans": [
        {
          "scope": {"name":"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp","version":"0.63.0"},
          "spans": [
            {"traceId":"0e9c3693ed82c0615a114b1b75fe036f","spanId":"2e45275f097a3aaa","parentSpanId":"613771c808c06a71","name":"GET /v1/recommendations/popular","kind":"SPAN_KIND_SERVER","startTimeUnixNano":"1791233943813347005","endTimeUnixNano":"1791233943842691447","attributes":[{"key":"http.request.method","value":{"stringValue":"GET"}},{"key":"http.response.status_code","value":{"intValue":"200"}}],"status":{}},
            {"traceId":"6897fe338fcc1174d1b3ce94c2449fcc","spanId":"814246eb15b151e3","parentSpanId":"cc435b97c591ebc2","name":"GET /v1/recommendations/popular","kind":"SPAN_KIND_SERVER","startTimeUnixNano":"1791234380119471809","endTimeUnixNano":"1791234380154784398","attributes":[{"key":"http.request.method","value":{"stringValue":"GET"}},{"key":"http.response.status_code","value":{"intValue":"200"}}],"status":{}},
            {"traceId":"540368933cc87cea2ee0033658c02392","spanId":"9c85512f8c5406a6","parentSpanId":"2b55bb324a4b2249","name":"GET /v1/recommendations/popular","kind":"SPAN_KIND_SERVER","startTimeUnixNano":"1791235671695706047","endTimeUnixNano":"1791235671741149896","attributes":[{"key":"http.request.method","value":{"stringValue":"GET"}},{"key":"http.response.status_code","value":{"intValue":"200"}}],"status":{}}
          ]
        }
      ]
    },
    {
      "resource": {
        "attributes": [
          {"key":"service.name","value":{"stringValue":"api-gateway"}},
          {"key":"service.version","value":{"stringValue":"7.3.1"}},
          {"key":"k8s.cluster.name","value":{"stringValue":"prod-us-central"}},
          {"key":"k8s.namespace.name","value":{"stringValue":"edge"}},
          {"key":"k8s.pod.name","value":{"stringValue":"api-gateway-5f7b8c9d6-hl6wr"}}
        ]
      },
      "scopeSpans": [
        {
          "scope": {"name":"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp","version":"0.63.0"},
          "spans": [
            {"traceId":"d1669bfc898b6b234bdd68ba1193ea43","spanId":"ea5f39a90aa19262","name":"GET /v1/orders","kind":"SPAN_KIND_SERVER","startTimeUnixNano":"1791234041090376736","endTimeUnixNano":"1791234041098139103","attributes":[{"key":"http.request.method","value":{"stringValue":"GET"}},{"key":"http.route","value":{"stringValue":"/v1/orders"}},{"key":"http.response.status_code","value":{"intValue":"503"}}],"status":{"code":"STATUS_CODE_ERROR","message":"authentication service unavailable"}},
            {"traceId":"4987f5d028be87a91293315f9e66304a","spanId":"911939af4ce9327f","name":"GET /v1/orders","kind":"SPAN_KIND_SERVER","startTimeUnixNano":"1791234238640664383","endTimeUnixNano":"1791234238646266270","attributes":[{"key":"http.request.method","value":{"stringValue":"GET"}},{"key":"http.route","value":{"stringValue":"/v1/orders"}},{"key":"http.response.status_code","value":{"intValue":"503"}}],"status":{"code":"STATUS_CODE_ERROR","message":"authentication service unavailable"}},
            {"traceId":"1ade366119f9ba1548b67e5d9e2e9a9f","spanId":"f41eb457fadd88ae","name":"GET /v1/account","kind":"SPAN_KIND_SERVER","startTimeUnixNano":"1791234842336345239","endTimeUnixNano":"1791234842344350349","attributes":[{"key":"http.request.method","value":{"stringValue":"GET"}},{"key":"http.route","value":{"stringValue":"/v1/account"}},{"key":"http.response.status_code","value":{"intValue":"503"}}],"status":{"code":"STATUS_CODE_ERROR","message":"authentication service unavailable"}},
            {"traceId":"540368933cc87cea2ee0033658c02392","spanId":"3b1625a29d83d0e6","name":"GET /v1/recommendations/popular","kind":"SPAN_KIND_SERVER","startTimeUnixNano":"1791235671693011941","endTimeUnixNano":"1791235671746823457","attributes":[{"key":"http.request.method","value":{"stringValue":"GET"}},{"key":"http.route","value":{"stringValue":"/v1/recommendations/popular"}},{"key":"http.response.status_code","value":{"intValue":"200"}}],"status":{}},
            {"traceId":"540368933cc87cea2ee0033658c02392","spanId":"2b55bb324a4b2249","parentSpanId":"3b1625a29d83d0e6","name":"GET","kind":"SPAN_KIND_CLIENT","startTimeUnixNano":"1791235671694339744","endTimeUnixNano":"1791235671743686710","attributes":[{"key":"http.request.method","value":{"stringValue":"GET"}},{"key":"server.address","value":{"stringValue":"recommendations.discovery.svc"}},{"key":"peer.service","value":{"stringValue":"recommendations"}},{"key":"http.response.status_code","value":{"intValue":"200"}}],"status":{}}
          ]
        },
        {
          "scope": {"name":"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc","version":"0.63.0"},
          "spans": [
            {"traceId":"d1669bfc898b6b234bdd68ba1193ea43","spanId":"df4a2210b8c4e9b9","parentSpanId":"ea5f39a90aa19262","name":"auth.v1.TokenService/Introspect","kind":"SPAN_KIND_CLIENT","startTimeUnixNano":"1791234041091480844","endTimeUnixNano":"1791234041096599522","attributes":[{"key":"rpc.system","value":{"stringValue":"grpc"}},{"key":"rpc.service","value":{"stringValue":"auth.v1.TokenService"}},{"key":"rpc.method","value":{"stringValue":"Introspect"}},{"key":"server.address","value":{"stringValue":"auth-service.identity.svc"}},{"key":"server.port","value":{"intValue":"9443"}},{"key":"peer.service","value":{"stringValue":"auth-service"}},{"key":"rpc.grpc.status_code","value":{"intValue":"14"}}],"status":{"code":"STATUS_CODE_ERROR","message":"connection error: desc = \\"transport: authentication handshake failed: tls: failed to verify certificate: x509: certificate has expired or is not yet valid: current time 2026-10-05T21:00:41Z is after 2026-10-05T21:00:00Z\\""}},
            {"traceId":"4987f5d028be87a91293315f9e66304a","spanId":"89d43691c95df458","parentSpanId":"911939af4ce9327f","name":"auth.v1.TokenService/Introspect","kind":"SPAN_KIND_CLIENT","startTimeUnixNano":"1791234238641684534","endTimeUnixNano":"1791234238644642920","attributes":[{"key":"rpc.system","value":{"stringValue":"grpc"}},{"key":"rpc.service","value":{"stringValue":"auth.v1.TokenService"}},{"key":"rpc.method","value":{"stringValue":"Introspect"}},{"key":"server.address","value":{"stringValue":"auth-service.identity.svc"}},{"key":"server.port","value":{"intValue":"9443"}},{"key":"peer.service","value":{"stringValue":"auth-service"}},{"key":"rpc.grpc.status_code","value":{"intValue":"14"}}],"status":{"code":"STATUS_CODE_ERROR","message":"connection error: desc = \\"transport: authentication handshake failed: tls: failed to verify certificate: x509: certificate has expired or is not yet valid: current time 2026-10-05T21:03:58Z is after 2026-10-05T21:00:00Z\\""}},
            {"traceId":"1ade366119f9ba1548b67e5d9e2e9a9f","spanId":"ce2e5e49556d57e9","parentSpanId":"f41eb457fadd88ae","name":"auth.v1.TokenService/Introspect","kind":"SPAN_KIND_CLIENT","startTimeUnixNano":"1791234842337805899","endTimeUnixNano":"1791234842342409821","attributes":[{"key":"rpc.system","value":{"stringValue":"grpc"}},{"key":"rpc.service","value":{"stringValue":"auth.v1.TokenService"}},{"key":"rpc.method","value":{"stringValue":"Introspect"}},{"key":"server.address","value":{"stringValue":"auth-service.identity.svc"}},{"key":"server.port","value":{"intValue":"9443"}},{"key":"peer.service","value":{"stringValue":"auth-service"}},{"key":"rpc.grpc.status_code","value":{"intValue":"14"}}],"status":{"code":"STATUS_CODE_ERROR","message":"connection error: desc = \\"transport: authentication handshake failed: tls: failed to verify certificate: x509: certificate has expired or is not yet valid: current time 2026-10-05T21:14:02Z is after 2026-10-05T21:00:00Z\\""}}
          ]
        }
      ]
    },
    {
      "resource": {
        "attributes": [
          {"key":"service.name","value":{"stringValue":"accounts-api"}},
          {"key":"service.version","value":{"stringValue":"2.9.3"}},
          {"key":"k8s.cluster.name","value":{"stringValue":"prod-us-central"}},
          {"key":"k8s.namespace.name","value":{"stringValue":"commerce"}},
          {"key":"k8s.pod.name","value":{"stringValue":"accounts-api-5d8f7c6b9-r2wtl"}}
        ]
      },
      "scopeSpans": [
        {
          "scope": {"name":"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp","version":"0.63.0"},
          "spans": [
            {"traceId":"abca29323f7a07b47ebbf32c44119ece","spanId":"3359801ebbbdb02f","parentSpanId":"2076ce765c87f8ea","name":"GET /v1/account","kind":"SPAN_KIND_SERVER","startTimeUnixNano":"1791234069554769996","endTimeUnixNano":"1791234069584126672","attributes":[{"key":"http.request.method","value":{"stringValue":"GET"}},{"key":"http.response.status_code","value":{"intValue":"200"}}],"status":{}}
          ]
        }
      ]
    },
    {
      "resource": {
        "attributes": [
          {"key":"service.name","value":{"stringValue":"catalog-api"}},
          {"key":"service.version","value":{"stringValue":"1.18.2"}},
          {"key":"k8s.cluster.name","value":{"stringValue":"prod-us-central"}},
          {"key":"k8s.namespace.name","value":{"stringValue":"commerce"}},
          {"key":"k8s.pod.name","value":{"stringValue":"catalog-api-7b6c5d9f8-nk3vp"}}
        ]
      },
      "scopeSpans": [
        {
          "scope": {"name":"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp","version":"0.63.0"},
          "spans": [
            {"traceId":"57f87b11be6da06dc33f58445b37f9d4","spanId":"bb27cfcac7e5cebf","parentSpanId":"40e27f3c2e5aa498","name":"GET /v1/catalog/items","kind":"SPAN_KIND_SERVER","startTimeUnixNano":"1791235110474515967","endTimeUnixNano":"1791235110534343718","attributes":[{"key":"http.request.method","value":{"stringValue":"GET"}},{"key":"http.response.status_code","value":{"intValue":"200"}}],"status":{}}
          ]
        }
      ]
    }
  ]
}`;

  const S3_ALERTS = `2026-10-05T21:00:52Z FIRING critical SSLCertificateExpired service=auth-service namespace=identity cluster=prod-us-central instance=auth-service.identity.svc:9443 job=blackbox-tls
[FIRING:1] ApiGatewayHighErrorRate (api-gateway prod-us-central edge critical)
2026-10-05T21:04:12Z FIRING critical ApiErrorBudgetBurn service=api-gateway namespace=edge cluster=prod-us-central slo=api-availability burn_rate=47.9 error_ratio=0.0479 long_window=1h short_window=5m
2026-10-05T21:06:40Z FIRING warning AuthServiceTLSHandshakeErrors service=auth-service namespace=identity cluster=prod-us-central
ALERT CertManagerCertNotReady{cluster="prod-us-central",condition="False",exported_namespace="identity",name="auth-service-mtls",namespace="cert-manager",severity="critical"} firing since 2026-10-05T21:10:31Z`;

  const S3_HELM = `# cluster: prod-us-central
$ helm history recommendations -n discovery --kube-context prod-us-central --max 3
REVISION\tUPDATED                 \tSTATUS    \tCHART                 \tAPP VERSION\tDESCRIPTION     
16      \tTue Sep 29 11:15:22 2026\tsuperseded\trecommendations-0.14.1\t3.4.0      \tUpgrade complete
17      \tThu Oct  1 16:40:05 2026\tsuperseded\trecommendations-0.14.2\t3.4.1      \tUpgrade complete
18      \tMon Oct  5 14:02:39 2026\tdeployed  \trecommendations-0.15.0\t3.5.0      \tUpgrade complete

$ helm diff revision recommendations 17 18 -n discovery --kube-context prod-us-central
discovery, recommendations, Deployment (apps) has changed:
  # Source: recommendations/templates/deployment.yaml
  apiVersion: apps/v1
  kind: Deployment
  metadata:
    name: recommendations
    labels:
      app.kubernetes.io/name: recommendations
      app.kubernetes.io/instance: recommendations
-     app.kubernetes.io/version: "3.4.1"
+     app.kubernetes.io/version: "3.5.0"
-     helm.sh/chart: recommendations-0.14.2
+     helm.sh/chart: recommendations-0.15.0
  spec:
    replicas: 2
    template:
      metadata:
        labels:
          app.kubernetes.io/name: recommendations
          app.kubernetes.io/instance: recommendations
-         app.kubernetes.io/version: "3.4.1"
+         app.kubernetes.io/version: "3.5.0"
      spec:
        containers:
          - name: recommendations
-           image: "registry.example.com/discovery/recommendations:3.4.1"
+           image: "registry.example.com/discovery/recommendations:3.5.0"
            ports:
              - name: http
                containerPort: 8080
            env:
              - name: MODEL_BUCKET
                value: "models-prod"
              - name: MODEL_VERSION
-               value: "recs-2026-09-28"
+               value: "recs-2026-10-04"
+             - name: RECS_DIVERSITY_WEIGHT
+               value: "0.15"
            resources:
              requests:
                cpu: 500m
                memory: 1Gi
              limits:
                memory: 2Gi
discovery, recommendations-flags, ConfigMap (v1) has changed:
  # Source: recommendations/templates/configmap.yaml
  apiVersion: v1
  kind: ConfigMap
  metadata:
    name: recommendations-flags
    labels:
      app.kubernetes.io/instance: recommendations
  data:
-   popular_fallback_ttl_seconds: "300"
+   popular_fallback_ttl_seconds: "600"
    personalised_enabled: "true"`;


  // ----------------------------------------------------------------------------------------------------
  // 4. db-conn-exhaustion — Order errors in two regions at the evening peak
  // ----------------------------------------------------------------------------------------------------

  const S4_LOGS = `--- cluster=prod-us-east ---
$ kubectl --context prod-us-east -n orders get hpa orders-api
NAME         REFERENCE               TARGETS        MINPODS   MAXPODS   REPLICAS   AGE
orders-api   Deployment/orders-api   cpu: 91%/65%   3         20        20         214d
$ kubectl --context prod-us-east -n orders describe hpa orders-api | sed -n '/^Conditions:/,$p'
Conditions:
  Type            Status  Reason            Message
  ----            ------  ------            -------
  AbleToScale     True    ReadyForNewScale  recommended size matches current size
  ScalingActive   True    ValidMetricFound  the HPA was able to successfully calculate a replica count from cpu resource utilization (percentage of request)
  ScalingLimited  True    TooManyReplicas   the desired replica count is more than the maximum replica count
Events:
  Type    Reason             Age  From                       Message
  ----    ------             ---  ----                       -------
  Normal  SuccessfulRescale  31m  horizontal-pod-autoscaler  New size: 9; reason: cpu resource utilization (percentage of request) above target
  Normal  SuccessfulRescale  29m  horizontal-pod-autoscaler  New size: 13; reason: cpu resource utilization (percentage of request) above target
  Normal  SuccessfulRescale  26m  horizontal-pod-autoscaler  New size: 17; reason: cpu resource utilization (percentage of request) above target
  Normal  SuccessfulRescale  24m  horizontal-pod-autoscaler  New size: 20; reason: cpu resource utilization (percentage of request) above target

$ kubectl --context prod-us-east -n orders get events --sort-by=.lastTimestamp | grep -v -E 'Pulled|Created|Started|Scheduled '
LAST SEEN   TYPE      REASON              OBJECT                               MESSAGE
34m         Normal    ScalingReplicaSet   deployment/orders-api                Scaled up replica set orders-api-6d8f7b9c54 to 2
33m         Normal    ScalingReplicaSet   deployment/orders-api                Scaled down replica set orders-api-7b9c6d5f48 to 4 from 6
32m         Normal    ScalingReplicaSet   deployment/orders-api                Scaled down replica set orders-api-7b9c6d5f48 to 0 from 2
31m         Normal    SuccessfulRescale   horizontalpodautoscaler/orders-api   New size: 9; reason: cpu resource utilization (percentage of request) above target
31m         Normal    ScalingReplicaSet   deployment/orders-api                Scaled up replica set orders-api-6d8f7b9c54 to 9 from 6
29m         Normal    SuccessfulRescale   horizontalpodautoscaler/orders-api   New size: 13; reason: cpu resource utilization (percentage of request) above target
29m         Normal    ScalingReplicaSet   deployment/orders-api                Scaled up replica set orders-api-6d8f7b9c54 to 13 from 9
26m         Normal    SuccessfulRescale   horizontalpodautoscaler/orders-api   New size: 17; reason: cpu resource utilization (percentage of request) above target
26m         Normal    ScalingReplicaSet   deployment/orders-api                Scaled up replica set orders-api-6d8f7b9c54 to 17 from 13
26m         Warning   FailedScheduling    pod/orders-api-6d8f7b9c54-t8wnx      0/24 nodes are available: 6 Insufficient cpu, 18 node(s) didn't match Pod's node affinity/selector. preemption: 0/24 nodes are available: 6 No preemption victims found for incoming pod, 18 Preemption is not helpful for scheduling.
26m         Normal    TriggeredScaleUp    pod/orders-api-6d8f7b9c54-t8wnx      pod triggered scale-up: [{aks-orders-40518273-vmss 6->8 (max: 12)}]
24m         Normal    SuccessfulRescale   horizontalpodautoscaler/orders-api   New size: 20; reason: cpu resource utilization (percentage of request) above target
24m         Normal    ScalingReplicaSet   deployment/orders-api                Scaled up replica set orders-api-6d8f7b9c54 to 20 from 17
62s         Warning   Unhealthy           pod/orders-api-6d8f7b9c54-4hqzm      Readiness probe failed: HTTP probe failed with statuscode: 503
46s         Warning   BackOff             pod/orders-api-6d8f7b9c54-t8wnx      Back-off restarting failed container orders-api in pod orders-api-6d8f7b9c54-t8wnx_orders(fdcd7b39-9696-44b8-8b7d-cd5655fd8a57)
43s         Warning   Unhealthy           pod/orders-api-6d8f7b9c54-b7xrd      Readiness probe failed: HTTP probe failed with statuscode: 503
28s         Warning   BackOff             pod/orders-api-6d8f7b9c54-k2v9p      Back-off restarting failed container orders-api in pod orders-api-6d8f7b9c54-k2v9p_orders(73e51aad-025f-4939-86bc-fae4a652618e)
17s         Warning   Unhealthy           pod/orders-api-6d8f7b9c54-fn2wc      Readiness probe failed: HTTP probe failed with statuscode: 503
13s         Warning   Unhealthy           pod/orders-api-6d8f7b9c54-q5lsv      Readiness probe failed: HTTP probe failed with statuscode: 503

$ kubectl --context prod-us-east -n orders get pods -l app.kubernetes.io/name=orders-api | grep -v ' 1/1 '
NAME                          READY   STATUS             RESTARTS        AGE
orders-api-6d8f7b9c54-4hqzm   0/1     Running            0               31m
orders-api-6d8f7b9c54-b7xrd   0/1     Running            0               29m
orders-api-6d8f7b9c54-fn2wc   0/1     Running            0               26m
orders-api-6d8f7b9c54-k2v9p   0/1     CrashLoopBackOff   6 (2m49s ago)   26m
orders-api-6d8f7b9c54-q5lsv   0/1     Running            0               24m
orders-api-6d8f7b9c54-t8wnx   0/1     CrashLoopBackOff   5 (3m32s ago)   26m

$ kubectl --context prod-us-east -n orders logs -l app.kubernetes.io/name=orders-api --since=40m --prefix --max-log-requests=25 | grep -v HealthEndpoint | tail -n 9
[pod/orders-api-6d8f7b9c54-6vtxq/orders-api] {"@timestamp":"2026-10-05T22:49:35.490+00:00","@version":"1","message":"Servlet.service() for servlet [dispatcherServlet] in context with path [] threw exception [Request processing failed: org.springframework.transaction.CannotCreateTransactionException: Could not open JPA EntityManager for transaction] with root cause","logger_name":"org.apache.catalina.core.ContainerBase.[Tomcat].[localhost].[/].[dispatcherServlet]","thread_name":"http-nio-8080-exec-34","level":"ERROR","level_value":40000,"stack_trace":"org.postgresql.util.PSQLException: FATAL: remaining connection slots are reserved for roles with the SUPERUSER attribute\\n\\tat org.postgresql.core.v3.QueryExecutorImpl.receiveErrorResponse(QueryExecutorImpl.java:2734)\\n\\tat org.postgresql.core.v3.ConnectionFactoryImpl.doAuthentication(ConnectionFactoryImpl.java:813)\\n\\t... 23 frames truncated"}
[pod/orders-api-6d8f7b9c54-9wd4n/orders-api] {"@timestamp":"2026-10-05T22:52:44.516+00:00","@version":"1","message":"HikariPool-1 - Connection is not available, request timed out after 30000ms (total=13, active=13, idle=0, waiting=17)","logger_name":"org.hibernate.engine.jdbc.spi.SqlExceptionHelper","thread_name":"http-nio-8080-exec-42","level":"ERROR","level_value":40000}
[pod/orders-api-6d8f7b9c54-9wd4n/orders-api] {"@timestamp":"2026-10-05T22:52:44.518+00:00","@version":"1","message":"Servlet.service() for servlet [dispatcherServlet] in context with path [] threw exception [Request processing failed: org.springframework.transaction.CannotCreateTransactionException: Could not open JPA EntityManager for transaction] with root cause","logger_name":"org.apache.catalina.core.ContainerBase.[Tomcat].[localhost].[/].[dispatcherServlet]","thread_name":"http-nio-8080-exec-52","level":"ERROR","level_value":40000,"stack_trace":"org.postgresql.util.PSQLException: FATAL: remaining connection slots are reserved for roles with the SUPERUSER attribute\\n\\tat org.postgresql.core.v3.QueryExecutorImpl.receiveErrorResponse(QueryExecutorImpl.java:2734)\\n\\tat org.postgresql.core.v3.ConnectionFactoryImpl.doAuthentication(ConnectionFactoryImpl.java:813)\\n\\t... 23 frames truncated"}
[pod/orders-api-6d8f7b9c54-hk7pl/orders-api] {"@timestamp":"2026-10-05T22:57:13.224+00:00","@version":"1","message":"HikariPool-1 - Connection is not available, request timed out after 30000ms (total=6, active=6, idle=0, waiting=42)","logger_name":"org.hibernate.engine.jdbc.spi.SqlExceptionHelper","thread_name":"http-nio-8080-exec-60","level":"ERROR","level_value":40000}
[pod/orders-api-6d8f7b9c54-hk7pl/orders-api] {"@timestamp":"2026-10-05T22:57:13.226+00:00","@version":"1","message":"Servlet.service() for servlet [dispatcherServlet] in context with path [] threw exception [Request processing failed: org.springframework.transaction.CannotCreateTransactionException: Could not open JPA EntityManager for transaction] with root cause","logger_name":"org.apache.catalina.core.ContainerBase.[Tomcat].[localhost].[/].[dispatcherServlet]","thread_name":"http-nio-8080-exec-36","level":"ERROR","level_value":40000,"stack_trace":"org.postgresql.util.PSQLException: FATAL: sorry, too many clients already\\n\\tat org.postgresql.core.v3.QueryExecutorImpl.receiveErrorResponse(QueryExecutorImpl.java:2734)\\n\\tat org.postgresql.core.v3.ConnectionFactoryImpl.doAuthentication(ConnectionFactoryImpl.java:813)\\n\\t... 23 frames truncated"}
[pod/orders-api-6d8f7b9c54-x4c2b/orders-api] {"@timestamp":"2026-10-05T23:01:42.786+00:00","@version":"1","message":"HikariPool-1 - Connection is not available, request timed out after 30000ms (total=8, active=8, idle=0, waiting=19)","logger_name":"org.hibernate.engine.jdbc.spi.SqlExceptionHelper","thread_name":"http-nio-8080-exec-34","level":"ERROR","level_value":40000}
[pod/orders-api-6d8f7b9c54-x4c2b/orders-api] {"@timestamp":"2026-10-05T23:01:42.788+00:00","@version":"1","message":"Servlet.service() for servlet [dispatcherServlet] in context with path [] threw exception [Request processing failed: org.springframework.transaction.CannotCreateTransactionException: Could not open JPA EntityManager for transaction] with root cause","logger_name":"org.apache.catalina.core.ContainerBase.[Tomcat].[localhost].[/].[dispatcherServlet]","thread_name":"http-nio-8080-exec-49","level":"ERROR","level_value":40000,"stack_trace":"org.postgresql.util.PSQLException: FATAL: remaining connection slots are reserved for roles with the SUPERUSER attribute\\n\\tat org.postgresql.core.v3.QueryExecutorImpl.receiveErrorResponse(QueryExecutorImpl.java:2734)\\n\\tat org.postgresql.core.v3.ConnectionFactoryImpl.doAuthentication(ConnectionFactoryImpl.java:813)\\n\\t... 23 frames truncated"}
[pod/orders-api-6d8f7b9c54-2mzrk/orders-api] {"@timestamp":"2026-10-05T23:04:39.915+00:00","@version":"1","message":"HikariPool-1 - Connection is not available, request timed out after 30000ms (total=10, active=10, idle=0, waiting=18)","logger_name":"org.hibernate.engine.jdbc.spi.SqlExceptionHelper","thread_name":"http-nio-8080-exec-55","level":"ERROR","level_value":40000}
[pod/orders-api-6d8f7b9c54-2mzrk/orders-api] {"@timestamp":"2026-10-05T23:04:39.917+00:00","@version":"1","message":"Servlet.service() for servlet [dispatcherServlet] in context with path [] threw exception [Request processing failed: org.springframework.transaction.CannotCreateTransactionException: Could not open JPA EntityManager for transaction] with root cause","logger_name":"org.apache.catalina.core.ContainerBase.[Tomcat].[localhost].[/].[dispatcherServlet]","thread_name":"http-nio-8080-exec-10","level":"ERROR","level_value":40000,"stack_trace":"org.postgresql.util.PSQLException: FATAL: remaining connection slots are reserved for roles with the SUPERUSER attribute\\n\\tat org.postgresql.core.v3.QueryExecutorImpl.receiveErrorResponse(QueryExecutorImpl.java:2734)\\n\\tat org.postgresql.core.v3.ConnectionFactoryImpl.doAuthentication(ConnectionFactoryImpl.java:813)\\n\\t... 23 frames truncated"}

$ kubectl --context prod-us-east -n orders logs orders-api-6d8f7b9c54-k2v9p --previous --prefix | grep -E '"level":"(ERROR|WARN)"' | head -n 3
[pod/orders-api-6d8f7b9c54-k2v9p/orders-api] {"@timestamp":"2026-10-05T23:03:04.118+00:00","@version":"1","message":"HikariPool-1 - Exception during pool initialization.","logger_name":"com.zaxxer.hikari.pool.HikariPool","thread_name":"main","level":"ERROR","level_value":40000,"stack_trace":"org.postgresql.util.PSQLException: FATAL: remaining connection slots are reserved for roles with the SUPERUSER attribute\\n\\tat org.postgresql.core.v3.QueryExecutorImpl.receiveErrorResponse(QueryExecutorImpl.java:2734)\\n\\tat org.postgresql.core.v3.ConnectionFactoryImpl.doAuthentication(ConnectionFactoryImpl.java:813)\\n\\t... 23 frames truncated"}
[pod/orders-api-6d8f7b9c54-k2v9p/orders-api] {"@timestamp":"2026-10-05T23:03:04.159+00:00","@version":"1","message":"Exception encountered during context initialization - cancelling refresh attempt: org.springframework.beans.factory.BeanCreationException: Error creating bean with name 'entityManagerFactory': Unable to obtain connection from database: FATAL: remaining connection slots are reserved for roles with the SUPERUSER attribute","logger_name":"org.springframework.boot.web.servlet.context.AnnotationConfigServletWebServerApplicationContext","thread_name":"main","level":"WARN","level_value":30000}
[pod/orders-api-6d8f7b9c54-k2v9p/orders-api] {"@timestamp":"2026-10-05T23:03:11.149+00:00","@version":"1","message":"Application run failed","logger_name":"org.springframework.boot.SpringApplication","thread_name":"main","level":"ERROR","level_value":40000}

$ kubectl --context prod-us-east -n data logs orders-postgresql-0 --since=40m --prefix --timestamps | grep -E 'FATAL|LOG:  (checkpoint|could not)' | tail -n 9
[pod/orders-postgresql-0/postgresql] 2026-10-05T22:36:52.431598116Z 2026-10-05 22:36:52.431 UTC [29166] FATAL:  remaining connection slots are reserved for roles with the SUPERUSER attribute
[pod/orders-postgresql-0/postgresql] 2026-10-05T22:36:52.64244485Z 2026-10-05 22:36:52.642 UTC [29790] FATAL:  remaining connection slots are reserved for roles with the SUPERUSER attribute
[pod/orders-postgresql-0/postgresql] 2026-10-05T22:38:20.610570637Z 2026-10-05 22:38:20.610 UTC [30462] FATAL:  remaining connection slots are reserved for roles with the SUPERUSER attribute
[pod/orders-postgresql-0/postgresql] 2026-10-05T22:41:02.884060864Z 2026-10-05 22:41:02.884 UTC [30553] FATAL:  remaining connection slots are reserved for roles with the SUPERUSER attribute
[pod/orders-postgresql-0/postgresql] 2026-10-05T22:44:30.01773223Z 2026-10-05 22:44:30.017 UTC [30776] FATAL:  sorry, too many clients already
[pod/orders-postgresql-0/postgresql] 2026-10-05T22:52:44.509389034Z 2026-10-05 22:52:44.509 UTC [31172] FATAL:  remaining connection slots are reserved for roles with the SUPERUSER attribute
[pod/orders-postgresql-0/postgresql] 2026-10-05T23:01:42.190801619Z 2026-10-05 23:01:42.190 UTC [31969] FATAL:  sorry, too many clients already
[pod/orders-postgresql-0/postgresql] 2026-10-05T23:03:11.402941634Z 2026-10-05 23:03:11.402 UTC [31544] LOG:  could not receive data from client: Connection reset by peer
[pod/orders-postgresql-0/postgresql] 2026-10-05T23:04:39.905974544Z 2026-10-05 23:04:39.905 UTC [32115] FATAL:  remaining connection slots are reserved for roles with the SUPERUSER attribute

$ kubectl --context prod-us-east -n data exec orders-postgresql-0 -c postgresql -- psql -U postgres -d orders -c "SELECT application_name, count(*) FROM pg_stat_activity WHERE backend_type = 'client backend' GROUP BY 1 ORDER BY 2 DESC;" -c "SHOW max_connections;" -c "SHOW superuser_reserved_connections;"
 application_name  | count
-------------------+-------
 orders-api        |   379
 orders-worker     |    18
 postgres_exporter |     1
 psql              |     1
(4 rows)

 max_connections
-----------------
 400
(1 row)

 superuser_reserved_connections
--------------------------------
 3
(1 row)

$ kubectl --context prod-us-east -n orders logs deploy/orders-worker --since=40m --prefix | grep -i error | tail -n 3
[pod/orders-worker-58c7d9b6f4-pz6tk/orders-worker] {"level":"error","ts":"2026-10-05T22:38:05.771Z","caller":"consumer/handler.go:91","msg":"failed to persist order event, will retry","topic":"orders.v1","partition":4,"error":"failed to connect to \`user=orders database=orders\`: 10.40.12.7:5432 (orders-postgresql.data.prod-us-east.internal.example.com): server error: FATAL: remaining connection slots are reserved for roles with the SUPERUSER attribute (SQLSTATE 53300)"}
[pod/orders-worker-58c7d9b6f4-pz6tk/orders-worker] {"level":"error","ts":"2026-10-05T22:47:19.064Z","caller":"consumer/handler.go:91","msg":"failed to persist order event, will retry","topic":"orders.v1","partition":3,"error":"failed to connect to \`user=orders database=orders\`: 10.40.12.7:5432 (orders-postgresql.data.prod-us-east.internal.example.com): server error: FATAL: sorry, too many clients already (SQLSTATE 53300)"}
[pod/orders-worker-58c7d9b6f4-pz6tk/orders-worker] {"level":"error","ts":"2026-10-05T23:00:58.322Z","caller":"consumer/handler.go:91","msg":"failed to persist order event, will retry","topic":"orders.v1","partition":0,"error":"failed to connect to \`user=orders database=orders\`: 10.40.12.7:5432 (orders-postgresql.data.prod-us-east.internal.example.com): server error: FATAL: remaining connection slots are reserved for roles with the SUPERUSER attribute (SQLSTATE 53300)"}

--- cluster=prod-us-west ---
$ kubectl --context=prod-us-west -n orders get hpa orders-api
NAME         REFERENCE               TARGETS        MINPODS   MAXPODS   REPLICAS   AGE
orders-api   Deployment/orders-api   cpu: 84%/65%   3         20        15         201d
$ kubectl --context=prod-us-west -n orders get events --sort-by=.lastTimestamp --field-selector involvedObject.kind=HorizontalPodAutoscaler
LAST SEEN   TYPE     REASON              OBJECT                               MESSAGE
30m         Normal   SuccessfulRescale   horizontalpodautoscaler/orders-api   New size: 8; reason: cpu resource utilization (percentage of request) above target
28m         Normal   SuccessfulRescale   horizontalpodautoscaler/orders-api   New size: 12; reason: cpu resource utilization (percentage of request) above target
25m         Normal   SuccessfulRescale   horizontalpodautoscaler/orders-api   New size: 15; reason: cpu resource utilization (percentage of request) above target
$ kubectl --context=prod-us-west -n orders logs -l app.kubernetes.io/name=orders-api --since=40m --prefix --max-log-requests=20 | grep -v HealthEndpoint | tail -n 5
[pod/orders-api-5f7d6c8b49-r6xbk/orders-api] {"@timestamp":"2026-10-05T22:45:14.809+00:00","@version":"1","message":"Servlet.service() for servlet [dispatcherServlet] in context with path [] threw exception [Request processing failed: org.springframework.transaction.CannotCreateTransactionException: Could not open JPA EntityManager for transaction] with root cause","logger_name":"org.apache.catalina.core.ContainerBase.[Tomcat].[localhost].[/].[dispatcherServlet]","thread_name":"http-nio-8080-exec-39","level":"ERROR","level_value":40000,"stack_trace":"org.postgresql.util.PSQLException: FATAL: remaining connection slots are reserved for roles with the SUPERUSER attribute\\n\\tat org.postgresql.core.v3.QueryExecutorImpl.receiveErrorResponse(QueryExecutorImpl.java:2734)\\n\\tat org.postgresql.core.v3.ConnectionFactoryImpl.doAuthentication(ConnectionFactoryImpl.java:813)\\n\\t... 23 frames truncated"}
[pod/orders-api-5f7d6c8b49-wz5dn/orders-api] {"@timestamp":"2026-10-05T22:53:30.223+00:00","@version":"1","message":"HikariPool-1 - Connection is not available, request timed out after 30000ms (total=9, active=9, idle=0, waiting=33)","logger_name":"org.hibernate.engine.jdbc.spi.SqlExceptionHelper","thread_name":"http-nio-8080-exec-64","level":"ERROR","level_value":40000}
[pod/orders-api-5f7d6c8b49-wz5dn/orders-api] {"@timestamp":"2026-10-05T22:53:30.226+00:00","@version":"1","message":"Servlet.service() for servlet [dispatcherServlet] in context with path [] threw exception [Request processing failed: org.springframework.transaction.CannotCreateTransactionException: Could not open JPA EntityManager for transaction] with root cause","logger_name":"org.apache.catalina.core.ContainerBase.[Tomcat].[localhost].[/].[dispatcherServlet]","thread_name":"http-nio-8080-exec-54","level":"ERROR","level_value":40000,"stack_trace":"org.postgresql.util.PSQLException: FATAL: sorry, too many clients already\\n\\tat org.postgresql.core.v3.QueryExecutorImpl.receiveErrorResponse(QueryExecutorImpl.java:2734)\\n\\tat org.postgresql.core.v3.ConnectionFactoryImpl.doAuthentication(ConnectionFactoryImpl.java:813)\\n\\t... 23 frames truncated"}
[pod/orders-api-5f7d6c8b49-8jqzv/orders-api] {"@timestamp":"2026-10-05T23:02:51.637+00:00","@version":"1","message":"HikariPool-1 - Connection is not available, request timed out after 30000ms (total=9, active=9, idle=0, waiting=21)","logger_name":"org.hibernate.engine.jdbc.spi.SqlExceptionHelper","thread_name":"http-nio-8080-exec-49","level":"ERROR","level_value":40000}
[pod/orders-api-5f7d6c8b49-8jqzv/orders-api] {"@timestamp":"2026-10-05T23:02:51.640+00:00","@version":"1","message":"Servlet.service() for servlet [dispatcherServlet] in context with path [] threw exception [Request processing failed: org.springframework.transaction.CannotCreateTransactionException: Could not open JPA EntityManager for transaction] with root cause","logger_name":"org.apache.catalina.core.ContainerBase.[Tomcat].[localhost].[/].[dispatcherServlet]","thread_name":"http-nio-8080-exec-11","level":"ERROR","level_value":40000,"stack_trace":"org.postgresql.util.PSQLException: FATAL: remaining connection slots are reserved for roles with the SUPERUSER attribute\\n\\tat org.postgresql.core.v3.QueryExecutorImpl.receiveErrorResponse(QueryExecutorImpl.java:2734)\\n\\tat org.postgresql.core.v3.ConnectionFactoryImpl.doAuthentication(ConnectionFactoryImpl.java:813)\\n\\t... 23 frames truncated"}
$ kubectl --context=prod-us-west -n orders logs deploy/orders-worker --since=40m --prefix | grep -i error | tail -n 2
[pod/orders-worker-7c4b8d6f59-mq2xs/orders-worker] {"level":"error","ts":"2026-10-05T22:39:31.044Z","caller":"consumer/handler.go:91","msg":"failed to persist order event, will retry","topic":"orders.v1","partition":11,"error":"failed to connect to \`user=orders database=orders\`: 10.40.12.7:5432 (orders-postgresql.data.prod-us-east.internal.example.com): server error: FATAL: remaining connection slots are reserved for roles with the SUPERUSER attribute (SQLSTATE 53300)"}
[pod/orders-worker-7c4b8d6f59-mq2xs/orders-worker] {"level":"error","ts":"2026-10-05T22:58:12.590Z","caller":"consumer/handler.go:91","msg":"failed to persist order event, will retry","topic":"orders.v1","partition":4,"error":"failed to connect to \`user=orders database=orders\`: 10.40.12.7:5432 (orders-postgresql.data.prod-us-east.internal.example.com): server error: FATAL: sorry, too many clients already (SQLSTATE 53300)"}`;

  const S4_TRACES = `{
  "data": [
    {
      "traceID": "f4ecf7cb8a4a95d3f60dd1f6226b6777",
      "spans": [
        {"traceID":"f4ecf7cb8a4a95d3f60dd1f6226b6777","spanID":"6eb10aa3ac97744a","flags":1,"operationName":"POST /api/orders","references":[],"startTime":1791238814330955,"duration":78863,"tags":[{"key":"span.kind","type":"string","value":"server"},{"key":"http.method","type":"string","value":"POST"},{"key":"http.status_code","type":"int64","value":201}],"logs":[],"processID":"p1","warnings":null},
        {"traceID":"f4ecf7cb8a4a95d3f60dd1f6226b6777","spanID":"696aea731312c020","flags":1,"operationName":"POST","references":[{"refType":"CHILD_OF","traceID":"f4ecf7cb8a4a95d3f60dd1f6226b6777","spanID":"6eb10aa3ac97744a"}],"startTime":1791238814332193,"duration":73084,"tags":[{"key":"span.kind","type":"string","value":"client"},{"key":"http.status_code","type":"int64","value":201},{"key":"peer.service","type":"string","value":"orders-api"}],"logs":[],"processID":"p1","warnings":null},
        {"traceID":"f4ecf7cb8a4a95d3f60dd1f6226b6777","spanID":"6025fb56c83696de","flags":1,"operationName":"POST /v1/orders","references":[{"refType":"CHILD_OF","traceID":"f4ecf7cb8a4a95d3f60dd1f6226b6777","spanID":"696aea731312c020"}],"startTime":1791238814334172,"duration":63690,"tags":[{"key":"span.kind","type":"string","value":"server"},{"key":"http.method","type":"string","value":"POST"},{"key":"http.route","type":"string","value":"/v1/orders"},{"key":"http.status_code","type":"int64","value":201}],"logs":[],"processID":"p2","warnings":null},
        {"traceID":"f4ecf7cb8a4a95d3f60dd1f6226b6777","spanID":"ee361ab6d32fd506","flags":1,"operationName":"INSERT orders.orders","references":[{"refType":"CHILD_OF","traceID":"f4ecf7cb8a4a95d3f60dd1f6226b6777","spanID":"6025fb56c83696de"}],"startTime":1791238814338415,"duration":8197,"tags":[{"key":"span.kind","type":"string","value":"client"},{"key":"db.system","type":"string","value":"postgresql"},{"key":"db.name","type":"string","value":"orders"},{"key":"peer.service","type":"string","value":"orders-postgresql"}],"logs":[],"processID":"p2","warnings":null},
        {"traceID":"f4ecf7cb8a4a95d3f60dd1f6226b6777","spanID":"a449c679c518286f","flags":1,"operationName":"POST","references":[{"refType":"CHILD_OF","traceID":"f4ecf7cb8a4a95d3f60dd1f6226b6777","spanID":"6025fb56c83696de"}],"startTime":1791238814348874,"duration":36883,"tags":[{"key":"span.kind","type":"string","value":"client"},{"key":"http.status_code","type":"int64","value":200},{"key":"peer.service","type":"string","value":"inventory-api"}],"logs":[],"processID":"p2","warnings":null},
        {"traceID":"f4ecf7cb8a4a95d3f60dd1f6226b6777","spanID":"5c4a891775ceb3ca","flags":1,"operationName":"POST /v1/reservations","references":[{"refType":"CHILD_OF","traceID":"f4ecf7cb8a4a95d3f60dd1f6226b6777","spanID":"a449c679c518286f"}],"startTime":1791238814350973,"duration":32159,"tags":[{"key":"span.kind","type":"string","value":"server"},{"key":"http.status_code","type":"int64","value":200}],"logs":[],"processID":"p3","warnings":null}
      ],
      "processes": {
        "p1": {"serviceName":"storefront","tags":[{"key":"k8s.cluster.name","type":"string","value":"prod-us-east"},{"key":"k8s.namespace.name","type":"string","value":"web"},{"key":"k8s.pod.name","type":"string","value":"storefront-84b6d9c7f5-zt4qm"},{"key":"service.version","type":"string","value":"12.4.0"}]},
        "p2": {"serviceName":"orders-api","tags":[{"key":"k8s.cluster.name","type":"string","value":"prod-us-east"},{"key":"k8s.namespace.name","type":"string","value":"orders"},{"key":"k8s.pod.name","type":"string","value":"orders-api-7b9c6d5f48-lp8vd"},{"key":"service.version","type":"string","value":"3.2.0"}]},
        "p3": {"serviceName":"inventory-api","tags":[{"key":"k8s.cluster.name","type":"string","value":"prod-us-east"},{"key":"k8s.namespace.name","type":"string","value":"orders"},{"key":"k8s.pod.name","type":"string","value":"inventory-api-5c9b7d8f64-wd8rt"},{"key":"service.version","type":"string","value":"2.11.5"}]}
      },
      "warnings": null
    },
    {
      "traceID": "b6f6a2d31afd100342730a3d9e5643f2",
      "spans": [
        {"traceID":"b6f6a2d31afd100342730a3d9e5643f2","spanID":"e4562b5df6ade605","flags":1,"operationName":"POST /api/orders","references":[],"startTime":1791238900480286,"duration":44815,"tags":[{"key":"span.kind","type":"string","value":"server"},{"key":"http.method","type":"string","value":"POST"},{"key":"http.status_code","type":"int64","value":201}],"logs":[],"processID":"p1","warnings":null},
        {"traceID":"b6f6a2d31afd100342730a3d9e5643f2","spanID":"580f646f19e0b1e7","flags":1,"operationName":"POST","references":[{"refType":"CHILD_OF","traceID":"b6f6a2d31afd100342730a3d9e5643f2","spanID":"e4562b5df6ade605"}],"startTime":1791238900482608,"duration":39429,"tags":[{"key":"span.kind","type":"string","value":"client"},{"key":"http.status_code","type":"int64","value":201},{"key":"peer.service","type":"string","value":"orders-api"}],"logs":[],"processID":"p1","warnings":null},
        {"traceID":"b6f6a2d31afd100342730a3d9e5643f2","spanID":"0e335dc0f7bb7b9a","flags":1,"operationName":"POST /v1/orders","references":[{"refType":"CHILD_OF","traceID":"b6f6a2d31afd100342730a3d9e5643f2","spanID":"580f646f19e0b1e7"}],"startTime":1791238900484141,"duration":37463,"tags":[{"key":"span.kind","type":"string","value":"server"},{"key":"http.method","type":"string","value":"POST"},{"key":"http.route","type":"string","value":"/v1/orders"},{"key":"http.status_code","type":"int64","value":201}],"logs":[],"processID":"p2","warnings":null},
        {"traceID":"b6f6a2d31afd100342730a3d9e5643f2","spanID":"4b3b6f4d26ea2d59","flags":1,"operationName":"INSERT orders.orders","references":[{"refType":"CHILD_OF","traceID":"b6f6a2d31afd100342730a3d9e5643f2","spanID":"0e335dc0f7bb7b9a"}],"startTime":1791238900488240,"duration":4451,"tags":[{"key":"span.kind","type":"string","value":"client"},{"key":"db.system","type":"string","value":"postgresql"},{"key":"db.name","type":"string","value":"orders"},{"key":"peer.service","type":"string","value":"orders-postgresql"}],"logs":[],"processID":"p2","warnings":null},
        {"traceID":"b6f6a2d31afd100342730a3d9e5643f2","spanID":"561f462b5cff02ae","flags":1,"operationName":"POST","references":[{"refType":"CHILD_OF","traceID":"b6f6a2d31afd100342730a3d9e5643f2","spanID":"0e335dc0f7bb7b9a"}],"startTime":1791238900494045,"duration":20196,"tags":[{"key":"span.kind","type":"string","value":"client"},{"key":"http.status_code","type":"int64","value":200},{"key":"peer.service","type":"string","value":"inventory-api"}],"logs":[],"processID":"p2","warnings":null},
        {"traceID":"b6f6a2d31afd100342730a3d9e5643f2","spanID":"a95253ad73e42a3f","flags":1,"operationName":"POST /v1/reservations","references":[{"refType":"CHILD_OF","traceID":"b6f6a2d31afd100342730a3d9e5643f2","spanID":"561f462b5cff02ae"}],"startTime":1791238900496949,"duration":16153,"tags":[{"key":"span.kind","type":"string","value":"server"},{"key":"http.status_code","type":"int64","value":200}],"logs":[],"processID":"p3","warnings":null}
      ],
      "processes": {
        "p1": {"serviceName":"storefront","tags":[{"key":"k8s.cluster.name","type":"string","value":"prod-us-west"},{"key":"k8s.namespace.name","type":"string","value":"web"},{"key":"k8s.pod.name","type":"string","value":"storefront-6f8d7b9c45-hx2vl"},{"key":"service.version","type":"string","value":"12.4.0"}]},
        "p2": {"serviceName":"orders-api","tags":[{"key":"k8s.cluster.name","type":"string","value":"prod-us-west"},{"key":"k8s.namespace.name","type":"string","value":"orders"},{"key":"k8s.pod.name","type":"string","value":"orders-api-6b8f9c7d55-v4lqs"},{"key":"service.version","type":"string","value":"3.2.0"}]},
        "p3": {"serviceName":"inventory-api","tags":[{"key":"k8s.cluster.name","type":"string","value":"prod-us-west"},{"key":"k8s.namespace.name","type":"string","value":"orders"},{"key":"k8s.pod.name","type":"string","value":"inventory-api-7d6c8f5b49-kp4zn"},{"key":"service.version","type":"string","value":"2.11.5"}]}
      },
      "warnings": null
    },
    {
      "traceID": "34153978fbc01c25d4cdd774fb561441",
      "spans": [
        {"traceID":"34153978fbc01c25d4cdd774fb561441","spanID":"b50cb308f94e82d1","flags":1,"operationName":"POST /api/orders","references":[],"startTime":1791239812429294,"duration":30026806,"tags":[{"key":"span.kind","type":"string","value":"server"},{"key":"http.method","type":"string","value":"POST"},{"key":"http.status_code","type":"int64","value":500},{"key":"error","type":"bool","value":true},{"key":"otel.status_code","type":"string","value":"ERROR"},{"key":"otel.status_description","type":"string","value":"POST /api/orders failed with 500"}],"logs":[],"processID":"p1","warnings":null},
        {"traceID":"34153978fbc01c25d4cdd774fb561441","spanID":"1c729d74e20fa74b","flags":1,"operationName":"POST","references":[{"refType":"CHILD_OF","traceID":"34153978fbc01c25d4cdd774fb561441","spanID":"b50cb308f94e82d1"}],"startTime":1791239812431463,"duration":30021931,"tags":[{"key":"span.kind","type":"string","value":"client"},{"key":"http.status_code","type":"int64","value":500},{"key":"peer.service","type":"string","value":"orders-api"},{"key":"error","type":"bool","value":true},{"key":"otel.status_code","type":"string","value":"ERROR"},{"key":"otel.status_description","type":"string","value":"HTTP 500"}],"logs":[],"processID":"p1","warnings":null},
        {"traceID":"34153978fbc01c25d4cdd774fb561441","spanID":"f63311e1d8b422dd","flags":1,"operationName":"POST /v1/orders","references":[{"refType":"CHILD_OF","traceID":"34153978fbc01c25d4cdd774fb561441","spanID":"1c729d74e20fa74b"}],"startTime":1791239812433674,"duration":30018389,"tags":[{"key":"span.kind","type":"string","value":"server"},{"key":"http.method","type":"string","value":"POST"},{"key":"http.route","type":"string","value":"/v1/orders"},{"key":"http.status_code","type":"int64","value":500},{"key":"error","type":"bool","value":true},{"key":"otel.status_code","type":"string","value":"ERROR"},{"key":"otel.status_description","type":"string","value":"CannotCreateTransactionException: Could not open JPA EntityManager for transaction"}],"logs":[],"processID":"p2","warnings":null},
        {"traceID":"34153978fbc01c25d4cdd774fb561441","spanID":"3f8cb02754b3d41a","flags":1,"operationName":"HikariDataSource.getConnection","references":[{"refType":"CHILD_OF","traceID":"34153978fbc01c25d4cdd774fb561441","spanID":"f63311e1d8b422dd"}],"startTime":1791239812436577,"duration":30001822,"tags":[{"key":"span.kind","type":"string","value":"client"},{"key":"db.system","type":"string","value":"postgresql"},{"key":"db.name","type":"string","value":"orders"},{"key":"peer.service","type":"string","value":"orders-postgresql"},{"key":"error","type":"bool","value":true},{"key":"otel.status_code","type":"string","value":"ERROR"},{"key":"otel.status_description","type":"string","value":"HikariPool-1 - Connection is not available, request timed out after 30000ms (total=9, active=9, idle=0, waiting=37)"}],"logs":[{"timestamp":1791239842437854,"fields":[{"key":"event","type":"string","value":"exception"},{"key":"exception.type","type":"string","value":"java.sql.SQLTransientConnectionException"},{"key":"exception.message","type":"string","value":"HikariPool-1 - Connection is not available, request timed out after 30000ms (total=9, active=9, idle=0, waiting=37)"}]}],"processID":"p2","warnings":null}
      ],
      "processes": {
        "p1": {"serviceName":"storefront","tags":[{"key":"k8s.cluster.name","type":"string","value":"prod-us-east"},{"key":"k8s.namespace.name","type":"string","value":"web"},{"key":"k8s.pod.name","type":"string","value":"storefront-84b6d9c7f5-zt4qm"},{"key":"service.version","type":"string","value":"12.4.0"}]},
        "p2": {"serviceName":"orders-api","tags":[{"key":"k8s.cluster.name","type":"string","value":"prod-us-east"},{"key":"k8s.namespace.name","type":"string","value":"orders"},{"key":"k8s.pod.name","type":"string","value":"orders-api-6d8f7b9c54-6vtxq"},{"key":"service.version","type":"string","value":"3.3.0"}]}
      },
      "warnings": null
    },
    {
      "traceID": "046c53f02ee60536ee9e92854da7b3f6",
      "spans": [
        {"traceID":"046c53f02ee60536ee9e92854da7b3f6","spanID":"7c21018676794d6b","flags":1,"operationName":"POST /api/orders","references":[],"startTime":1791240058300354,"duration":30024332,"tags":[{"key":"span.kind","type":"string","value":"server"},{"key":"http.method","type":"string","value":"POST"},{"key":"http.status_code","type":"int64","value":500},{"key":"error","type":"bool","value":true},{"key":"otel.status_code","type":"string","value":"ERROR"},{"key":"otel.status_description","type":"string","value":"POST /api/orders failed with 500"}],"logs":[],"processID":"p1","warnings":null},
        {"traceID":"046c53f02ee60536ee9e92854da7b3f6","spanID":"0e6142c12d8ef3b7","flags":1,"operationName":"POST","references":[{"refType":"CHILD_OF","traceID":"046c53f02ee60536ee9e92854da7b3f6","spanID":"7c21018676794d6b"}],"startTime":1791240058302618,"duration":30019408,"tags":[{"key":"span.kind","type":"string","value":"client"},{"key":"http.status_code","type":"int64","value":500},{"key":"peer.service","type":"string","value":"orders-api"},{"key":"error","type":"bool","value":true},{"key":"otel.status_code","type":"string","value":"ERROR"},{"key":"otel.status_description","type":"string","value":"HTTP 500"}],"logs":[],"processID":"p1","warnings":null},
        {"traceID":"046c53f02ee60536ee9e92854da7b3f6","spanID":"07567378f85b95b6","flags":1,"operationName":"POST /v1/orders","references":[{"refType":"CHILD_OF","traceID":"046c53f02ee60536ee9e92854da7b3f6","spanID":"0e6142c12d8ef3b7"}],"startTime":1791240058304348,"duration":30018376,"tags":[{"key":"span.kind","type":"string","value":"server"},{"key":"http.method","type":"string","value":"POST"},{"key":"http.route","type":"string","value":"/v1/orders"},{"key":"http.status_code","type":"int64","value":500},{"key":"error","type":"bool","value":true},{"key":"otel.status_code","type":"string","value":"ERROR"},{"key":"otel.status_description","type":"string","value":"CannotCreateTransactionException: Could not open JPA EntityManager for transaction"}],"logs":[],"processID":"p2","warnings":null},
        {"traceID":"046c53f02ee60536ee9e92854da7b3f6","spanID":"1ab311c21871426e","flags":1,"operationName":"HikariDataSource.getConnection","references":[{"refType":"CHILD_OF","traceID":"046c53f02ee60536ee9e92854da7b3f6","spanID":"07567378f85b95b6"}],"startTime":1791240058307575,"duration":30001724,"tags":[{"key":"span.kind","type":"string","value":"client"},{"key":"db.system","type":"string","value":"postgresql"},{"key":"db.name","type":"string","value":"orders"},{"key":"peer.service","type":"string","value":"orders-postgresql"},{"key":"error","type":"bool","value":true},{"key":"otel.status_code","type":"string","value":"ERROR"},{"key":"otel.status_description","type":"string","value":"HikariPool-1 - Connection is not available, request timed out after 30000ms (total=7, active=7, idle=0, waiting=44)"}],"logs":[{"timestamp":1791240088308320,"fields":[{"key":"event","type":"string","value":"exception"},{"key":"exception.type","type":"string","value":"java.sql.SQLTransientConnectionException"},{"key":"exception.message","type":"string","value":"HikariPool-1 - Connection is not available, request timed out after 30000ms (total=7, active=7, idle=0, waiting=44)"}]}],"processID":"p2","warnings":null}
      ],
      "processes": {
        "p1": {"serviceName":"storefront","tags":[{"key":"k8s.cluster.name","type":"string","value":"prod-us-west"},{"key":"k8s.namespace.name","type":"string","value":"web"},{"key":"k8s.pod.name","type":"string","value":"storefront-6f8d7b9c45-hx2vl"},{"key":"service.version","type":"string","value":"12.4.0"}]},
        "p2": {"serviceName":"orders-api","tags":[{"key":"k8s.cluster.name","type":"string","value":"prod-us-west"},{"key":"k8s.namespace.name","type":"string","value":"orders"},{"key":"k8s.pod.name","type":"string","value":"orders-api-5f7d6c8b49-cl2tm"},{"key":"service.version","type":"string","value":"3.3.0"}]}
      },
      "warnings": null
    },
    {
      "traceID": "87d890157287c2a672a53593ec4cb49e",
      "spans": [
        {"traceID":"87d890157287c2a672a53593ec4cb49e","spanID":"339a5ffb780db933","flags":1,"operationName":"POST /api/orders","references":[],"startTime":1791240279950267,"duration":12467406,"tags":[{"key":"span.kind","type":"string","value":"server"},{"key":"http.method","type":"string","value":"POST"},{"key":"http.status_code","type":"int64","value":201}],"logs":[],"processID":"p1","warnings":null},
        {"traceID":"87d890157287c2a672a53593ec4cb49e","spanID":"fac09bd02d40ace7","flags":1,"operationName":"POST","references":[{"refType":"CHILD_OF","traceID":"87d890157287c2a672a53593ec4cb49e","spanID":"339a5ffb780db933"}],"startTime":1791240279952112,"duration":12462890,"tags":[{"key":"span.kind","type":"string","value":"client"},{"key":"http.status_code","type":"int64","value":201},{"key":"peer.service","type":"string","value":"orders-api"}],"logs":[],"processID":"p1","warnings":null},
        {"traceID":"87d890157287c2a672a53593ec4cb49e","spanID":"3b8995f5a0faf13f","flags":1,"operationName":"POST /v1/orders","references":[{"refType":"CHILD_OF","traceID":"87d890157287c2a672a53593ec4cb49e","spanID":"fac09bd02d40ace7"}],"startTime":1791240279954035,"duration":12455982,"tags":[{"key":"span.kind","type":"string","value":"server"},{"key":"http.method","type":"string","value":"POST"},{"key":"http.route","type":"string","value":"/v1/orders"},{"key":"http.status_code","type":"int64","value":201}],"logs":[],"processID":"p2","warnings":null},
        {"traceID":"87d890157287c2a672a53593ec4cb49e","spanID":"bec0a149bdc44c3c","flags":1,"operationName":"HikariDataSource.getConnection","references":[{"refType":"CHILD_OF","traceID":"87d890157287c2a672a53593ec4cb49e","spanID":"3b8995f5a0faf13f"}],"startTime":1791240279957309,"duration":12408735,"tags":[{"key":"span.kind","type":"string","value":"client"},{"key":"db.system","type":"string","value":"postgresql"},{"key":"db.name","type":"string","value":"orders"},{"key":"peer.service","type":"string","value":"orders-postgresql"}],"logs":[],"processID":"p2","warnings":null},
        {"traceID":"87d890157287c2a672a53593ec4cb49e","spanID":"d74085a726a0e4ff","flags":1,"operationName":"INSERT orders.orders","references":[{"refType":"CHILD_OF","traceID":"87d890157287c2a672a53593ec4cb49e","spanID":"3b8995f5a0faf13f"}],"startTime":1791240292366171,"duration":11161,"tags":[{"key":"span.kind","type":"string","value":"client"},{"key":"db.system","type":"string","value":"postgresql"},{"key":"db.name","type":"string","value":"orders"},{"key":"peer.service","type":"string","value":"orders-postgresql"}],"logs":[],"processID":"p2","warnings":null},
        {"traceID":"87d890157287c2a672a53593ec4cb49e","spanID":"e18bda0a68f89d85","flags":1,"operationName":"POST","references":[{"refType":"CHILD_OF","traceID":"87d890157287c2a672a53593ec4cb49e","spanID":"3b8995f5a0faf13f"}],"startTime":1791240292379738,"duration":19234,"tags":[{"key":"span.kind","type":"string","value":"client"},{"key":"http.status_code","type":"int64","value":200},{"key":"peer.service","type":"string","value":"inventory-api"}],"logs":[],"processID":"p2","warnings":null},
        {"traceID":"87d890157287c2a672a53593ec4cb49e","spanID":"7da4755a36f62db7","flags":1,"operationName":"POST /v1/reservations","references":[{"refType":"CHILD_OF","traceID":"87d890157287c2a672a53593ec4cb49e","spanID":"e18bda0a68f89d85"}],"startTime":1791240292381305,"duration":15187,"tags":[{"key":"span.kind","type":"string","value":"server"},{"key":"http.status_code","type":"int64","value":200}],"logs":[],"processID":"p3","warnings":null}
      ],
      "processes": {
        "p1": {"serviceName":"storefront","tags":[{"key":"k8s.cluster.name","type":"string","value":"prod-us-east"},{"key":"k8s.namespace.name","type":"string","value":"web"},{"key":"k8s.pod.name","type":"string","value":"storefront-84b6d9c7f5-zt4qm"},{"key":"service.version","type":"string","value":"12.4.0"}]},
        "p2": {"serviceName":"orders-api","tags":[{"key":"k8s.cluster.name","type":"string","value":"prod-us-east"},{"key":"k8s.namespace.name","type":"string","value":"orders"},{"key":"k8s.pod.name","type":"string","value":"orders-api-6d8f7b9c54-2mzrk"},{"key":"service.version","type":"string","value":"3.3.0"}]},
        "p3": {"serviceName":"inventory-api","tags":[{"key":"k8s.cluster.name","type":"string","value":"prod-us-east"},{"key":"k8s.namespace.name","type":"string","value":"orders"},{"key":"k8s.pod.name","type":"string","value":"inventory-api-5c9b7d8f64-wd8rt"},{"key":"service.version","type":"string","value":"2.11.5"}]}
      },
      "warnings": null
    },
    {
      "traceID": "9a197085d87a89b3502cce100aedab03",
      "spans": [
        {"traceID":"9a197085d87a89b3502cce100aedab03","spanID":"096740ba0dfe0a9d","flags":1,"operationName":"POST /api/orders","references":[],"startTime":1791241272700088,"duration":30030041,"tags":[{"key":"span.kind","type":"string","value":"server"},{"key":"http.method","type":"string","value":"POST"},{"key":"http.status_code","type":"int64","value":500},{"key":"error","type":"bool","value":true},{"key":"otel.status_code","type":"string","value":"ERROR"},{"key":"otel.status_description","type":"string","value":"POST /api/orders failed with 500"}],"logs":[],"processID":"p1","warnings":null},
        {"traceID":"9a197085d87a89b3502cce100aedab03","spanID":"69f895552075c33f","flags":1,"operationName":"POST","references":[{"refType":"CHILD_OF","traceID":"9a197085d87a89b3502cce100aedab03","spanID":"096740ba0dfe0a9d"}],"startTime":1791241272702843,"duration":30025433,"tags":[{"key":"span.kind","type":"string","value":"client"},{"key":"http.status_code","type":"int64","value":500},{"key":"peer.service","type":"string","value":"orders-api"},{"key":"error","type":"bool","value":true},{"key":"otel.status_code","type":"string","value":"ERROR"},{"key":"otel.status_description","type":"string","value":"HTTP 500"}],"logs":[],"processID":"p1","warnings":null},
        {"traceID":"9a197085d87a89b3502cce100aedab03","spanID":"325c2c5e980877bd","flags":1,"operationName":"POST /v1/orders","references":[{"refType":"CHILD_OF","traceID":"9a197085d87a89b3502cce100aedab03","spanID":"69f895552075c33f"}],"startTime":1791241272704462,"duration":30018232,"tags":[{"key":"span.kind","type":"string","value":"server"},{"key":"http.method","type":"string","value":"POST"},{"key":"http.route","type":"string","value":"/v1/orders"},{"key":"http.status_code","type":"int64","value":500},{"key":"error","type":"bool","value":true},{"key":"otel.status_code","type":"string","value":"ERROR"},{"key":"otel.status_description","type":"string","value":"CannotCreateTransactionException: Could not open JPA EntityManager for transaction"}],"logs":[],"processID":"p2","warnings":null},
        {"traceID":"9a197085d87a89b3502cce100aedab03","spanID":"96042d5091b57007","flags":1,"operationName":"HikariDataSource.getConnection","references":[{"refType":"CHILD_OF","traceID":"9a197085d87a89b3502cce100aedab03","spanID":"325c2c5e980877bd"}],"startTime":1791241272707596,"duration":30001448,"tags":[{"key":"span.kind","type":"string","value":"client"},{"key":"db.system","type":"string","value":"postgresql"},{"key":"db.name","type":"string","value":"orders"},{"key":"peer.service","type":"string","value":"orders-postgresql"},{"key":"error","type":"bool","value":true},{"key":"otel.status_code","type":"string","value":"ERROR"},{"key":"otel.status_description","type":"string","value":"HikariPool-1 - Connection is not available, request timed out after 30000ms (total=11, active=11, idle=0, waiting=39)"}],"logs":[{"timestamp":1791241302708165,"fields":[{"key":"event","type":"string","value":"exception"},{"key":"exception.type","type":"string","value":"java.sql.SQLTransientConnectionException"},{"key":"exception.message","type":"string","value":"HikariPool-1 - Connection is not available, request timed out after 30000ms (total=11, active=11, idle=0, waiting=39)"}]}],"processID":"p2","warnings":null}
      ],
      "processes": {
        "p1": {"serviceName":"storefront","tags":[{"key":"k8s.cluster.name","type":"string","value":"prod-us-east"},{"key":"k8s.namespace.name","type":"string","value":"web"},{"key":"k8s.pod.name","type":"string","value":"storefront-84b6d9c7f5-zt4qm"},{"key":"service.version","type":"string","value":"12.4.0"}]},
        "p2": {"serviceName":"orders-api","tags":[{"key":"k8s.cluster.name","type":"string","value":"prod-us-east"},{"key":"k8s.namespace.name","type":"string","value":"orders"},{"key":"k8s.pod.name","type":"string","value":"orders-api-6d8f7b9c54-x4c2b"},{"key":"service.version","type":"string","value":"3.3.0"}]}
      },
      "warnings": null
    }
  ],
  "total": 0,
  "limit": 0,
  "offset": 0,
  "errors": null
}`;

  const S4_ALERTS = `{
  "receiver": "orders-oncall",
  "status": "firing",
  "alerts": [
    {
      "status": "firing",
      "labels": {
        "alertname": "PostgresqlTooManyConnections",
        "cluster": "prod-us-east",
        "container": "metrics",
        "instance": "10.48.9.33:9187",
        "job": "data/orders-postgresql",
        "namespace": "data",
        "pod": "orders-postgresql-0",
        "severity": "critical",
        "team": "orders"
      },
      "annotations": {
        "summary": "PostgreSQL instance has too many connections (> 80%).",
        "description": "orders-postgresql-0 is using 99.3% of max_connections (397 of 400 non-reserved slots).",
        "runbook_url": "https://runbooks.example.com/postgres/too-many-connections"
      },
      "startsAt": "2026-10-05T22:37:52.604Z",
      "endsAt": "0001-01-01T00:00:00Z",
      "generatorURL": "https://thanos-query.observability.example.com/graph?g0.expr=sum+by+%28cluster%2C+namespace%2C+pod%29+%28pg_stat_activity_count%29+%3E+on+%28cluster%2C+namespace%2C+pod%29+pg_settings_max_connections+%2A+0.8&g0.tab=1",
      "fingerprint": "4ac01c5fac81671f"
    },
    {
      "status": "firing",
      "labels": {
        "alertname": "OrdersApiHighErrorRate",
        "cluster": "prod-us-east",
        "namespace": "orders",
        "service": "orders-api",
        "severity": "critical",
        "team": "orders"
      },
      "annotations": {
        "summary": "orders-api 5xx ratio above 5% for 2 minutes.",
        "description": "41.7% of orders-api requests in prod-us-east returned 5xx over the last 5 minutes.",
        "runbook_url": "https://runbooks.example.com/orders/orders-api-errors"
      },
      "startsAt": "2026-10-05T22:39:58.117Z",
      "endsAt": "0001-01-01T00:00:00Z",
      "generatorURL": "https://thanos-query.observability.example.com/graph?g0.expr=sum+by+%28cluster%2C+service%29+%28rate%28http_server_requests_seconds_count%7Bcluster%3D%22prod-us-east%22%2Cservice%3D%22orders-api%22%2Cstatus%3D~%225..%22%7D%5B5m%5D%29%29+%2F+sum+by+%28cluster%2C+service%29+%28rate%28http_server_requests_seconds_count%7Bcluster%3D%22prod-us-east%22%2Cservice%3D%22orders-api%22%7D%5B5m%5D%29%29+%3E+0.05&g0.tab=1",
      "fingerprint": "f8f95f4a5c1dee72"
    },
    {
      "status": "firing",
      "labels": {
        "alertname": "OrdersApiHighErrorRate",
        "cluster": "prod-us-west",
        "namespace": "orders",
        "service": "orders-api",
        "severity": "critical",
        "team": "orders"
      },
      "annotations": {
        "summary": "orders-api 5xx ratio above 5% for 2 minutes.",
        "description": "33.9% of orders-api requests in prod-us-west returned 5xx over the last 5 minutes.",
        "runbook_url": "https://runbooks.example.com/orders/orders-api-errors"
      },
      "startsAt": "2026-10-05T22:41:35.882Z",
      "endsAt": "0001-01-01T00:00:00Z",
      "generatorURL": "https://thanos-query.observability.example.com/graph?g0.expr=sum+by+%28cluster%2C+service%29+%28rate%28http_server_requests_seconds_count%7Bcluster%3D%22prod-us-west%22%2Cservice%3D%22orders-api%22%2Cstatus%3D~%225..%22%7D%5B5m%5D%29%29+%2F+sum+by+%28cluster%2C+service%29+%28rate%28http_server_requests_seconds_count%7Bcluster%3D%22prod-us-west%22%2Cservice%3D%22orders-api%22%7D%5B5m%5D%29%29+%3E+0.05&g0.tab=1",
      "fingerprint": "2cd3f1f2e5d289e2"
    },
    {
      "status": "firing",
      "labels": {
        "alertname": "ErrorBudgetBurn",
        "long_window": "1h",
        "service": "storefront",
        "severity": "critical",
        "short_window": "5m",
        "slo": "storefront-orders",
        "team": "orders"
      },
      "annotations": {
        "summary": "storefront-orders is burning its error budget 17.3x faster than sustainable.",
        "description": "1h burn rate 17.3 (5m: 38.6) against a 99.9% / 30-day objective, across prod-us-east and prod-us-west.",
        "burn_rate": "17.3",
        "error_ratio": "0.0173",
        "runbook_url": "https://runbooks.example.com/slo/error-budget-burn"
      },
      "startsAt": "2026-10-05T22:52:20.431Z",
      "endsAt": "0001-01-01T00:00:00Z",
      "generatorURL": "https://thanos-query.observability.example.com/graph?g0.expr=%28sum%28rate%28http_requests_total%7Bservice%3D%22storefront%22%2Croute%3D%22%2Fapi%2Forders%22%2Ccode%3D~%225..%22%7D%5B1h%5D%29%29+%2F+sum%28rate%28http_requests_total%7Bservice%3D%22storefront%22%2Croute%3D%22%2Fapi%2Forders%22%7D%5B1h%5D%29%29%29+%2F+0.001+%3E+14.4&g0.tab=1",
      "fingerprint": "a907a3c29bf51f4b"
    },
    {
      "status": "firing",
      "labels": {
        "alertname": "KubeHpaMaxedOut",
        "cluster": "prod-us-east",
        "horizontalpodautoscaler": "orders-api",
        "job": "kube-state-metrics",
        "namespace": "orders",
        "severity": "warning",
        "team": "orders"
      },
      "annotations": {
        "summary": "HPA is running at max replicas",
        "description": "HPA orders/orders-api has been running at max replicas for longer than 15 minutes.",
        "runbook_url": "https://runbooks.example.com/kubernetes/kubehpamaxedout"
      },
      "startsAt": "2026-10-05T22:56:52.009Z",
      "endsAt": "0001-01-01T00:00:00Z",
      "generatorURL": "https://thanos-query.observability.example.com/graph?g0.expr=kube_horizontalpodautoscaler_status_current_replicas%7Bjob%3D%22kube-state-metrics%22%7D+%3D%3D+kube_horizontalpodautoscaler_spec_max_replicas%7Bjob%3D%22kube-state-metrics%22%7D&g0.tab=1",
      "fingerprint": "af458c2be8f3c9d3"
    },
    {
      "status": "resolved",
      "labels": {
        "alertname": "CPUThrottlingHigh",
        "cluster": "prod-us-west",
        "container": "orders-api",
        "namespace": "orders",
        "pod": "orders-api-5f7d6c8b49-cl2tm",
        "severity": "info",
        "team": "orders"
      },
      "annotations": {
        "summary": "Processes experience elevated CPU throttling.",
        "description": "46.2% throttling of CPU in namespace orders for container orders-api in pod orders-api-5f7d6c8b49-cl2tm.",
        "runbook_url": "https://runbooks.example.com/kubernetes/cputhrottlinghigh"
      },
      "startsAt": "2026-10-05T22:53:12.330Z",
      "endsAt": "2026-10-05T23:01:42.330Z",
      "generatorURL": "https://thanos-query.observability.example.com/graph?g0.expr=sum%28increase%28container_cpu_cfs_throttled_periods_total%7Bcontainer%21%3D%22%22%7D%5B5m%5D%29%29+without+%28id%2C+metrics_path%2C+name%2C+image%2C+endpoint%2C+job%2C+node%29+%2F+sum%28increase%28container_cpu_cfs_periods_total%5B5m%5D%29%29+without+%28id%2C+metrics_path%2C+name%2C+image%2C+endpoint%2C+job%2C+node%29+%3E+%2825+%2F+100%29&g0.tab=1",
      "fingerprint": "6c101ff89d5fc21f"
    }
  ],
  "groupLabels": {
    "team": "orders"
  },
  "commonLabels": {
    "team": "orders"
  },
  "commonAnnotations": {},
  "externalURL": "https://alertmanager.observability.example.com",
  "version": "4",
  "groupKey": "{}/{team=\\"orders\\"}:{team=\\"orders\\"}",
  "truncatedAlerts": 0
}`;

  const S4_HELM = `[context: prod-us-east]
$ helm history orders -n orders --kube-context prod-us-east --max 4
REVISION\tUPDATED                 \tSTATUS    \tCHART       \tAPP VERSION\tDESCRIPTION     
21      \tThu Sep 10 10:12:44 2026\tsuperseded\torders-3.1.4\t3.1.4      \tUpgrade complete
22      \tTue Sep 22 09:48:09 2026\tsuperseded\torders-3.1.5\t3.1.5      \tUpgrade complete
23      \tWed Sep 30 13:05:18 2026\tsuperseded\torders-3.2.0\t3.2.0      \tUpgrade complete
24      \tMon Oct  5 15:31:40 2026\tdeployed  \torders-3.3.0\t3.3.0      \tUpgrade complete
# prod-us-west: same chart and values rolled out by the release pipeline at 15:33 PDT (revision 24 there too)

$ helm diff revision orders 23 24 -n orders --kube-context prod-us-east
orders, orders-api, HorizontalPodAutoscaler (autoscaling) has changed:
  # Source: orders/templates/hpa.yaml
  apiVersion: autoscaling/v2
  kind: HorizontalPodAutoscaler
  metadata:
    name: orders-api
    labels:
      app.kubernetes.io/name: orders-api
      app.kubernetes.io/instance: orders
-     helm.sh/chart: orders-3.2.0
+     helm.sh/chart: orders-3.3.0
  spec:
    scaleTargetRef:
      apiVersion: apps/v1
      kind: Deployment
      name: orders-api
    minReplicas: 3
-   maxReplicas: 6
+   maxReplicas: 20
    metrics:
      - type: Resource
        resource:
          name: cpu
          target:
            type: Utilization
            averageUtilization: 65
orders, orders-api-env, ConfigMap (v1) has changed:
  # Source: orders/templates/configmap-env.yaml
  apiVersion: v1
  kind: ConfigMap
  metadata:
    name: orders-api-env
    labels:
      app.kubernetes.io/instance: orders
-     helm.sh/chart: orders-3.2.0
+     helm.sh/chart: orders-3.3.0
  data:
    DB_HOST: "orders-postgresql.data.prod-us-east.internal.example.com"
    DB_NAME: "orders"
    DB_PASSWORD: "hunter2-not-real"
    DB_USER: "orders"
-   ORDERS_SPLIT_SHIPMENTS_ENABLED: "false"
+   ORDERS_SPLIT_SHIPMENTS_ENABLED: "true"
    SPRING_DATASOURCE_HIKARI_CONNECTION_TIMEOUT: "30000"
    SPRING_DATASOURCE_HIKARI_MAXIMUM_POOL_SIZE: "20"
orders, orders-api, Deployment (apps) has changed:
  # Source: orders/templates/deployment.yaml
  apiVersion: apps/v1
  kind: Deployment
  metadata:
    name: orders-api
    labels:
      app.kubernetes.io/name: orders-api
      app.kubernetes.io/instance: orders
-     app.kubernetes.io/version: "3.2.0"
+     app.kubernetes.io/version: "3.3.0"
-     helm.sh/chart: orders-3.2.0
+     helm.sh/chart: orders-3.3.0
  spec:
    selector:
      matchLabels:
        app.kubernetes.io/name: orders-api
        app.kubernetes.io/instance: orders
    template:
      metadata:
        labels:
          app.kubernetes.io/name: orders-api
          app.kubernetes.io/instance: orders
-         app.kubernetes.io/version: "3.2.0"
+         app.kubernetes.io/version: "3.3.0"
      spec:
        containers:
          - name: orders-api
-           image: "registry.example.com/orders/orders-api:3.2.0"
+           image: "registry.example.com/orders/orders-api:3.3.0"
            envFrom:
              - configMapRef:
                  name: orders-api-env
            resources:
              requests:
                cpu: "1"
                memory: 1536Mi
              limits:
                memory: 1536Mi
            readinessProbe:
              httpGet:
                path: /actuator/health/readiness
                port: 8080
              periodSeconds: 5`;

  WR.samples = [
    {
      id: 'bad-deploy-oom',
      title: 'Checkout failing after a payments release',
      blurb: 'Checkout started failing in prod-eu-west a few minutes after the payments Helm release went out. prod-us-east has not been upgraded yet and looks normal.',
      context: {
        now: '2026-10-05T22:12:00Z',
        defaultTz: '+02:00',
        year: 2026,
        cluster: 'prod-eu-west',
        slo: { target: 0.999, windowDays: 30, requestsPerMin: 1200, budgetSpentBeforePct: 18 }
      },
      logs: S1_LOGS,
      traces: S1_TRACES,
      alerts: S1_ALERTS,
      helm: S1_HELM,
      expected: {
        rootComponentName: 'payments-api',
        rootComponentAlternates: [],
        rootCluster: 'prod-eu-west',
        category: 'resource-limits',
        categories: ['resource-limits', 'bad-deploy'],
        recommendedKind: 'helm-rollback',
        recommendedKinds: ['helm-rollback'],
        release: 'payments',
        deployRevision: 42,
        previousRevision: 41,
        deployedAt: '2026-10-05T21:47:03Z',
        firstErrorAround: '2026-10-05T21:49:52Z',
        multiCluster: true,
        failingClusters: ['prod-eu-west'],
        healthyClusters: ['prod-us-east'],
        notes: 'Memory limit cut 512Mi to 256Mi plus cache warm-up; GOMEMLIMIT left at 460MiB. Alerts in UTC, app logs at +02:00, helm history zone-less local time.'
      }
    },
    {
      id: 'coredns-outage',
      title: 'Name lookups failing across the cluster',
      blurb: 'Services across prod-eu-central started timing out on DNS lookups early in the evening. A platform add-on release went out about half an hour ago.',
      context: {
        now: '2026-10-05T19:31:00Z',
        defaultTz: 'Z',
        year: 2026,
        cluster: 'prod-eu-central',
        slo: { target: 0.9995, windowDays: 28, requestsPerMin: 2600, budgetSpentBeforePct: 22 }
      },
      logs: S2_LOGS,
      traces: S2_TRACES,
      alerts: S2_ALERTS,
      helm: S2_HELM,
      expected: {
        rootComponentName: 'coredns',
        rootComponentAlternates: [],
        rootType: 'infra',
        rootCluster: 'prod-eu-central',
        category: 'dns',
        categories: ['dns'],
        recommendedKind: 'helm-rollback',
        recommendedKinds: ['helm-rollback', 'config-revert'],
        release: 'coredns',
        deployRevision: 14,
        previousRevision: 13,
        deployedAt: '2026-10-05T19:01:52Z',
        firstErrorAround: '2026-10-05T19:05:31Z',
        multiCluster: false,
        notes: 'Corefile forward switched to two on-prem resolvers with policy sequential and the cache removed; CoreDNS OOMs at its 170Mi limit and every lookup times out. Single cluster, all times UTC.'
      }
    },
    {
      id: 'cert-expiry',
      title: 'Sign-ins failing at the API gateway',
      blurb: 'Authenticated API calls through the gateway in prod-us-central began failing at the top of the hour. Anonymous pages still load. The only release today was recommendations, earlier this afternoon.',
      context: {
        now: '2026-10-05T21:34:00Z',
        defaultTz: '-04:00',
        year: 2026,
        cluster: 'prod-us-central',
        slo: { target: 0.999, windowDays: 30, requestsPerMin: 3400, budgetSpentBeforePct: 12 }
      },
      logs: S3_LOGS,
      traces: S3_TRACES,
      alerts: S3_ALERTS,
      helm: S3_HELM,
      expected: {
        rootComponentName: 'auth-service',
        rootComponentAlternates: ['api-gateway'],
        rootCluster: 'prod-us-central',
        category: 'tls-cert',
        categories: ['tls-cert'],
        recommendedKind: 'roll-forward',
        recommendedKinds: ['roll-forward'],
        release: 'recommendations',
        deployRevision: 18,
        previousRevision: 17,
        deployedAt: '2026-10-05T18:02:39Z',
        firstErrorAround: '2026-10-05T21:00:41Z',
        certificateNotAfter: '2026-10-05T21:00:00Z',
        notTopComponentName: 'recommendations',
        redHerringRelease: 'recommendations',
        multiCluster: false,
        notes: 'Certificate auth-service-mtls expired 21:00Z after 27 failed renewals (Vault 403). The recommendations release at 18:02Z is unrelated and shows no errors. Helm history is local time -04:00; everything else carries a zone.'
      }
    },
    {
      id: 'db-conn-exhaustion',
      title: 'Order errors in two regions at the evening peak',
      blurb: 'orders-api is returning 500s in both prod-us-east and prod-us-west as evening traffic climbs. The orders release went out to both clusters about half an hour ago.',
      context: {
        now: '2026-10-05T23:06:00Z',
        defaultTz: '-07:00',
        year: 2026,
        cluster: 'prod-us-east',
        slo: { target: 0.999, windowDays: 30, requestsPerMin: 1800, budgetSpentBeforePct: 31 }
      },
      logs: S4_LOGS,
      traces: S4_TRACES,
      alerts: S4_ALERTS,
      helm: S4_HELM,
      expected: {
        rootComponentName: 'orders-api',
        rootComponentAlternates: ['orders-postgresql', 'orders', 'postgresql'],
        rootCluster: 'prod-us-east',
        rootClusters: ['prod-us-east', 'prod-us-west'],
        category: 'connection-exhaustion',
        categories: ['connection-exhaustion'],
        recommendedKind: 'helm-rollback',
        recommendedKinds: ['helm-rollback', 'scale'],
        release: 'orders',
        deployRevision: 24,
        previousRevision: 23,
        deployedAt: '2026-10-05T22:31:40Z',
        firstErrorAround: '2026-10-05T22:36:52Z',
        multiCluster: true,
        failingClusters: ['prod-us-east', 'prod-us-west'],
        healthyClusters: [],
        notes: 'HPA max 6 -> 20 with a fixed Hikari pool of 20 per pod: 20 + 15 pods want 700 connections (800 at the new ceiling, 240 before) against 397 usable on the shared Postgres primary. Contains the one fake DB_PASSWORD (in the orders-api-env ConfigMap diff) for redaction tests.'
      }
    }
  ];
})(globalThis.WR = globalThis.WR || {});
