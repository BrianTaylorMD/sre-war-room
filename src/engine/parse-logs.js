/*
 * parse-logs.js — WR.parseLogs(text, ctx) → { signals, entities, stats, extras }
 *
 * One pane can hold anything an engineer copies out of a terminal during an incident: kubectl
 * tables, describe output, JSON app logs, stern/--prefix streams, klog, syslog, logfmt, plain text,
 * cluster markers and the command echoes themselves. The parser walks the pane once, line by line,
 * keeping a little state (current cluster, current table, current describe block, the pod named by
 * the last `kubectl logs` echo) so each line inherits the context a human reader would give it.
 *
 * Output signals use the closed kind vocabulary from util.js. Lines that matter (a kind matched, or
 * level error/fatal) become signals; every line still counts toward its component's error/warn/info
 * counts in extras.componentCounts.
 *
 * Time handling:
 *   - absolute stamps → epoch ms UTC via WR.time (zone-less stamps take ctx.defaultTz, tsInferred)
 *   - relative ages (events "3m12s", pods tables) → attrs.relative=true + attrs.ageMs; ts is computed
 *     from ctx.now, else from the latest absolute stamp in this pane, else left null. The analysis
 *     re-bases them on its global "now" with WR.time.rebase().
 *   - lines with no stamp at all inherit the previous stamped line (tsInferred, attrs.tsCarried).
 */
(function (WR) {
  'use strict';

  var T = WR.time;
  var E = WR.entities;

  // -------------------------------------------------------------------------------------------
  // Kind rules — ordered; the first match wins (SPEC §3.1). Specific failure modes sit above the
  // generic ones they would otherwise be swallowed by (DNS before timeout, pool exhaustion before
  // generic DB errors, connection refused before HTTP 5xx).
  // -------------------------------------------------------------------------------------------
  function is5xx(t) {
    if (/status(?:_?code|Code)?["']?\s*[=:]\s*["']?5\d\d\b/i.test(t)) return true;
    if (/\bHTTP\/\d(?:\.\d)?"?\s+5\d\d\b/.test(t)) return true;
    if (/\b5\d\d\s+(?:Internal Server Error|Not Implemented|Bad Gateway|Service Unavailable|Gateway Time-?out)/i.test(t)) return true;
    if (/\b(?:code|response|returned|responded|upstream_status|statusCode|got)[=: ]+5\d\d\b/i.test(t)) return true;
    // The bare " 503 " form (SPEC) only counts when the line is about HTTP, so "processed 500 rows"
    // and "took 512 ms" stay out.
    if (/ 5\d\d(?: |$)/.test(t) && /\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|HTTP|status|upstream|request|response)\b/i.test(t) &&
        !/ 5\d\d (?:ms|s|bytes|B|KB|MB|rows|records|items|requests|times|connections|events|messages)\b/i.test(t)) return true;
    return false;
  }

  function is429(t) {
    if (/Too Many Requests|rate[ _-]?limit|ratelimit|quota exceeded/i.test(t)) return true;
    if (/status(?:_?code|Code)?["']?\s*[=:]\s*["']?429\b/i.test(t) || /\bHTTP\/\d(?:\.\d)?"?\s+429\b/.test(t) || /\b(?:code|response|returned)[=: ]+429\b/i.test(t)) return true;
    return /(?:^|\s)429(?:\s|$)/.test(t) && /\b(GET|POST|PUT|PATCH|DELETE|HTTP|status|request)\b/i.test(t);
  }

  var RULES = [
    ['oom_killed', /OOMKill|Exit Code:\s*137|exit code 137|exit status 137|out of memory|Killed process|OutOfMemoryError|memory cgroup out of memory|oom-kill|oom_kill/i],
    ['crash_loop', /CrashLoopBackOff|Back-off restarting|back-off \S+ restarting failed/i],
    ['image_pull', /ImagePullBackOff|ErrImagePull|ErrImageNeverPull|InvalidImageName|manifest unknown|pull access denied|Back-off pulling image|Failed to pull image|repository does not exist/i],
    ['config_error', /CreateContainerConfigError|CreateContainerError|secrets? "[^"]*" not found|configmaps? "[^"]*" not found|invalid configuration|couldn't find key \S+ in (?:Secret|ConfigMap)|failed to (?:load|parse) config|missing required (?:env|environment|config)/i],
    ['probe_failed', /(?:Readiness|Liveness|Startup) probe failed|failed (?:liveness|readiness|startup) probe|probe failed|probe errored/i],
    ['evicted', /\bEvicted\b|The node was low on resource|evicting pod|\bEvicting\b/i],
    ['node_not_ready', /NodeNotReady|\bnode\b.{0,60}\bnot ready\b|Kubelet stopped posting node status|NodeStatusUnknown/i],
    ['node_pressure', /MemoryPressure|DiskPressure|PIDPressure|NodeHasInsufficientMemory|NodeHasDiskPressure|EvictionThresholdMet/i],
    ['scheduling_failed', /FailedScheduling|Insufficient (?:cpu|memory|nvidia|ephemeral-storage|pods)|0\/\d+ nodes are available|didn't match Pod's node affinity|untolerated taint|exceeded quota/i],
    ['pvc_pending', /unbound immediate PersistentVolumeClaims|ProvisioningFailed|FailedAttachVolume|persistentvolumeclaim "[^"]*" not found|waiting for a volume to be created|FailedMount/i],
    ['dns_failure', /no such host|lookup \S+.*(?:i\/o timeout|server misbehaving)|SERVFAIL|NXDOMAIN|Temporary failure in name resolution|getaddrinfo (?:ENOTFOUND|EAI_AGAIN)|EAI_AGAIN|Name or service not known|could not resolve host|UnknownHostException|dns (?:lookup|resolution|query) (?:failed|timed? ?out)/i],
    ['tls_error', /x509|certificate has expired|certificate is not yet valid|tls: handshake|tls: bad certificate|remote error: tls|certificate signed by unknown authority|SSL routines|certificate verify failed|SSLHandshakeException|CERT_HAS_EXPIRED|ERR_TLS|handshake failure/i],
    ['conn_exhaustion', /too many (?:connections|clients)|remaining connection slots are reserved|connection slots|pool exhausted|connection pool (?:timeout|exhausted|is full)|pool timeout|max_connections|could not obtain (?:a )?connection|Connection is not available, request timed out|HikariPool.*(?:timed out|Connection is not available)|ER_CON_COUNT_ERROR|maxclients/i],
    ['migration', /(?:migration|migrate|alembic|flyway|liquibase)\b.{0,120}(?:fail|error|abort|dirty|panic|could not)|(?:fail|error)\w*.{0,60}\b(?:migration|migrate)/i],
    ['db_error', /deadlock|SQLSTATE|\bpq: |ERROR:\s+(?:relation|column|duplicate key|could not|permission denied)|could not serialize access|lock wait timeout|database "[^"]*" does not exist|ORA-\d{5}/i],
    ['conn_refused', /connection refused|ECONNREFUSED|no healthy upstream|upstream connect error/i],
    ['timeout', /context deadline exceeded|i\/o timeout|timed out|ETIMEDOUT|upstream request timeout|deadline exceeded|timeout exceeded|Read timed out|504 Gateway Time-?out|request timeout/i],
    ['hpa_maxed', /ScalingLimited|reached max(?:imum)? replicas|desired replica count .*max|TooManyReplicas|maxReplicas reached|at max replicas/i],
    ['http_429', is429],
    ['throttled', /throttl/i],
    ['http_5xx', is5xx],
    ['panic', /panic:|Traceback \(most recent call last\)|\w*Exception\b|NullPointer|segfault|segmentation fault|SIGSEGV|fatal error:|unhandled (?:exception|rejection|error)|uncaught/i],
    ['rollout', /ScalingReplicaSet|Scaled (?:up|down) replica set|deployment "?\S+"? successfully rolled out|Created pod:|SuccessfulCreate|Waiting for deployment .* rollout/i],
    ['restart', /Started container|Restarting|Killing container|container restart/i]
  ];

  function classify(text) {
    if (!text) return null;
    for (var i = 0; i < RULES.length; i++) {
      var r = RULES[i][1];
      if (typeof r === 'function' ? r(text) : r.test(text)) return RULES[i][0];
    }
    return null;
  }

  // Minimum severity a kind implies when the line's own level says less (an info-level JSON line
  // carrying a 503 is still an error for blast-radius purposes).
  var FLOOR = {
    oom_killed: 'error', crash_loop: 'error', image_pull: 'error', config_error: 'error', probe_failed: 'warn',
    evicted: 'error', node_not_ready: 'error', node_pressure: 'warn', scheduling_failed: 'warn', pvc_pending: 'warn',
    dns_failure: 'error', conn_refused: 'error', timeout: 'warn', tls_error: 'error', http_5xx: 'error',
    http_429: 'warn', throttled: 'warn', hpa_maxed: 'warn', rollout: 'info', restart: 'info', panic: 'error',
    db_error: 'error', conn_exhaustion: 'error', migration: 'error', error_generic: 'error'
  };

  // Kinds whose message usually names the dependency that failed us.
  var DEP_KINDS = { conn_refused: 1, timeout: 1, dns_failure: 1, tls_error: 1, http_5xx: 1, conn_exhaustion: 1, db_error: 1, http_429: 1 };

  function normLevel(v) {
    if (v == null || v === '') return null;
    if (typeof v === 'number') {
      if (v >= 10) return v >= 60 ? 'critical' : v >= 50 ? 'error' : v >= 40 ? 'warn' : 'info'; // pino/bunyan
      return v <= 2 ? 'critical' : v === 3 ? 'error' : v === 4 ? 'warn' : 'info';               // syslog numbers
    }
    var s = String(v).trim().toLowerCase();
    if (/^(fatal|panic|crit|critical|emerg|emergency|alert|f|dpanic)$/.test(s)) return 'critical';
    if (/^(error|err|e|severe|failure|fail)$/.test(s)) return 'error';
    if (/^(warn|warning|w)$/.test(s)) return 'warn';
    if (/^(info|information|informational|notice|i|debug|trace|verbose|d|t|log|default|fine|finer|finest|config)$/.test(s)) return 'info';
    return null;
  }

  var RE_LEVEL_WORD = /(?:^|[\s\[(|:])(FATAL|PANIC|CRITICAL|CRIT|ERROR|ERR|SEVERE|WARNING|WARN|NOTICE|INFO|DEBUG|TRACE|LOG)(?=[\s\]):|,]|$)/;
  var RE_LEVEL_LOWER = /^\s*(?:\[(fatal|panic|error|err|warn|warning|info|debug|notice|crit)\]|(fatal|panic|error|err|warn|warning|info|debug)(?::\s|\s*\|))/i;
  function levelFromText(body) {
    var head = body.length > 90 ? body.slice(0, 90) : body;
    var m = RE_LEVEL_WORD.exec(head);
    if (m) return normLevel(m[1] === 'LOG' ? 'info' : m[1]);
    m = RE_LEVEL_LOWER.exec(head);
    if (m) return normLevel(m[1] || m[2]);
    return null;
  }

  // -------------------------------------------------------------------------------------------
  // Field access for JSON logs — flat dotted keys ("http.status_code") and nested objects both occur.
  // -------------------------------------------------------------------------------------------
  function get(o, path) {
    if (o == null) return undefined;
    if (o[path] !== undefined) return o[path];
    if (path.indexOf('.') < 0) return undefined;
    var parts = path.split('.');
    var cur = o;
    for (var i = 0; i < parts.length; i++) {
      if (cur == null || typeof cur !== 'object') return undefined;
      cur = cur[parts[i]];
    }
    return cur;
  }
  function pick(o, keys) {
    for (var i = 0; i < keys.length; i++) {
      var v = get(o, keys[i]);
      if (v !== undefined && v !== null && v !== '') return v;
    }
    return null;
  }
  function str(v) {
    if (v == null) return null;
    if (typeof v === 'string') return v;
    if (typeof v === 'number' || typeof v === 'boolean') return String(v);
    if (typeof v === 'object') {
      if (typeof v.message === 'string') return v.message;
      if (typeof v.name === 'string') return v.name;
      try { return JSON.stringify(v); } catch (e) { return null; }
    }
    return null;
  }

  var K_TS = ['ts', 'time', 'timestamp', '@timestamp', 't', 'date', 'datetime', 'eventTime'];
  var K_LEVEL = ['level', 'severity', 'lvl', 'log.level', 'levelname', 'loglevel', 'severity_text', 'SeverityText'];
  var K_MSG = ['msg', 'message', '@message', 'event', 'text', 'Body', 'body'];
  var K_ERR = ['error', 'err', 'exception', 'error.message', 'error.type', 'stack', 'stacktrace', 'reason', 'cause', 'detail'];
  var K_SERVICE = ['service', 'service.name', 'app', 'application', 'component', 'kubernetes.labels.app', 'k8s.deployment.name'];
  var K_POD = ['pod', 'pod_name', 'k8s.pod.name', 'kubernetes.pod_name', 'kubernetes.pod.name'];
  var K_NS = ['namespace', 'ns', 'k8s.namespace.name', 'kubernetes.namespace_name', 'kubernetes.namespace'];
  var K_CLUSTER = ['cluster', 'k8s.cluster.name', 'cluster_name', 'kubernetes.cluster'];
  var K_CONTAINER = ['container', 'container_name', 'k8s.container.name', 'kubernetes.container_name'];
  var K_TRACE = ['trace_id', 'traceId', 'trace.id', 'traceid', 'dd.trace_id', 'logging.googleapis.com/trace'];
  var K_STATUS = ['status', 'status_code', 'statusCode', 'http.status_code', 'http.response.status_code', 'http.status', 'response_code', 'code'];
  var K_LATENCY = ['latency_ms', 'duration_ms', 'duration', 'latency', 'elapsed_ms', 'took_ms', 'response_time', 'elapsed'];
  var K_TARGET = ['upstream', 'peer', 'peer.service', 'target', 'remote_service', 'dependency', 'upstream_host', 'server.address', 'db.host'];

  // Turn a JSON or logfmt object into the common record shape the rest of the parser uses.
  function recordFromObject(o, opts, st) {
    var r = { ts: null, tsInferred: false, tzAssumed: false, level: null, msg: '', err: null, service: null, pod: null, ns: null, cluster: null, container: null, traceId: null, status: null, latencyMs: null, target: null };
    var tsv = pick(o, K_TS);
    if (tsv != null) {
      var p = T.parse(typeof tsv === 'number' ? tsv : String(tsv), opts);
      if (p) { r.ts = p.ts; r.tsInferred = p.tsInferred; r.tzAssumed = p.tzAssumed; r.yearAssumed = p.yearAssumed; }
    }
    r.level = normLevel(pick(o, K_LEVEL));
    var logField = o.log;
    var msg = pick(o, K_MSG);
    if (msg == null && typeof logField === 'string') msg = logField; // docker json-file: {"log": "...", "stream": "stderr"}
    r.msg = str(msg) || '';
    var errv = pick(o, K_ERR);
    r.err = errv != null ? str(errv) : null;
    var svc = pick(o, K_SERVICE);
    r.service = typeof svc === 'string' ? svc : (svc && typeof svc === 'object' && typeof svc.name === 'string' ? svc.name : null);
    if (!r.service) {
      var lg = o.logger || o.logger_name;
      // Logger names are often class paths ("com.example.Pay"); only plain service-like names count.
      if (typeof lg === 'string' && /^[a-z][a-z0-9-]{2,62}$/.test(lg)) r.service = lg;
    }
    r.pod = str(pick(o, K_POD));
    r.ns = str(pick(o, K_NS));
    r.cluster = str(pick(o, K_CLUSTER));
    r.container = str(pick(o, K_CONTAINER));
    r.traceId = str(pick(o, K_TRACE));
    var stv = pick(o, K_STATUS);
    if (stv != null && /^\d{3}$/.test(String(stv))) r.status = Number(stv);
    var lat = pick(o, K_LATENCY);
    if (lat != null) {
      var n = typeof lat === 'number' ? lat : T.durationMs(String(lat), 'ms');
      if (typeof n === 'number' && isFinite(n)) r.latencyMs = n;
    }
    var tg = pick(o, K_TARGET);
    if (typeof tg === 'string') r.target = tg;
    if (!r.level && typeof o.stream === 'string' && o.stream === 'stderr' && /error|fail|exception/i.test(r.msg)) r.level = 'error';
    return r;
  }

  // -------------------------------------------------------------------------------------------
  // Dependency extraction — "dial tcp: lookup payments-api.shop.svc..." tells us checkout-api
  // depends on payments-api even when no traces were pasted.
  // -------------------------------------------------------------------------------------------
  var RE_T_SVC = /\b([a-z0-9][a-z0-9-]*)\.([a-z0-9][a-z0-9-]*)\.svc(?:\.cluster\.local)?\b/i;
  var RE_T_LOOKUP = /\blookup ([a-z0-9][a-z0-9.-]*[a-z0-9])/i;
  var RE_T_DIAL = /\bdial (?:tcp|udp)\d? ([a-z][a-z0-9.-]*[a-z0-9]):\d+/i;
  var RE_T_URL = /\b(?:https?|grpcs?|postgres(?:ql)?|mysql|redis|amqps?|mongodb(?:\+srv)?|nats|kafka):\/\/(?:[^@\s\/]+@)?([a-z0-9][a-z0-9.-]*[a-z0-9])/i;
  var RE_T_KEYED = /\b(?:upstream|host|server|peer|target|backend|calling|call to|connect(?:ing)? to|request to|requests to)[=: "']+([a-z][a-z0-9-]*(?:\.[a-z0-9-]+)*)/i;
  var RE_T_NAMEPORT = /\b([a-z][a-z0-9]*-[a-z0-9-]+|[a-z]+(?:sql|gres|redis|mongo|kafka|rabbitmq|db))(?:\.[a-z0-9-]+)*:\d{2,5}\b/i;
  var RE_NGINX_UPSTREAM = /\s\[([a-z0-9][a-z0-9-]*[a-z0-9])-\d{2,5}\]\s+\[[^\]]*\]\s+\S/;
  var RE_ACCESS_STATUS = /"(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) \S+ HTTP\/[\d.]+"\s+(\d{3})\b/;
  var CODE_FILE = /\.(go|py|js|ts|java|kt|rb|rs|c|cc|cpp|h|php|scala|cs|swift)$/i;
  // pgx and many drivers: "10.40.12.7:5432 (orders-postgresql.data.prod-us-east.internal.example.com)".
  var RE_T_IP_HOST = /\b\d{1,3}(?:\.\d{1,3}){3}:\d{2,5} \(([a-z0-9][a-z0-9.-]*[a-z0-9])\)/i;

  // Like E.fromHost, but a host shaped <service>.<namespace>.<cluster>.… names a component in a
  // cluster this paste knows about (cross-cluster DNS such as orders-postgresql.data.prod-us-east.internal…).
  function hostIn(c, clusters) {
    var h = E.fromHost(c);
    if (!h || !h.external || !clusters || !clusters.length) return h;
    var parts = h.name.split('.');
    if (parts.length >= 3 && clusters.indexOf(parts[2]) >= 0 && /^[a-z0-9][a-z0-9-]*$/.test(parts[0]) && /^[a-z0-9][a-z0-9-]*$/.test(parts[1])) {
      return { name: parts[0], namespace: parts[1], cluster: parts[2], external: false };
    }
    return h;
  }

  function extractTarget(text, explicit, clusters) {
    var cands = [];
    if (explicit) cands.push(explicit);
    var m;
    if ((m = RE_T_IP_HOST.exec(text))) cands.push(m[1]);
    if ((m = RE_T_SVC.exec(text))) cands.push(m[0]);
    if ((m = RE_T_LOOKUP.exec(text))) cands.push(m[1]);
    if ((m = RE_T_DIAL.exec(text))) cands.push(m[1]);
    if ((m = RE_T_URL.exec(text))) cands.push(m[1]);
    if ((m = RE_T_KEYED.exec(text))) cands.push(m[1]);
    if ((m = RE_T_NAMEPORT.exec(text))) cands.push(m[1]);
    for (var i = 0; i < cands.length; i++) {
      var c = cands[i];
      if (!c || CODE_FILE.test(c)) continue;
      var h = hostIn(c, clusters);
      // "server error: FATAL ..." would otherwise name a dependency called "error".
      if (h && h.name && h.name.length > 1 && !/^(localhost|tcp|udp|http|https|the|a|an|error|errors|err|fatal|failed|failure|closed|returned|responded|unavailable|timeout|not|is|was|with|for|from|to)$/.test(h.name)) return h;
    }
    return null;
  }

  // -------------------------------------------------------------------------------------------
  // Line shapes
  // -------------------------------------------------------------------------------------------
  var RE_ANSI = /\x1b\[[0-9;?]*[A-Za-z]/g;
  var RE_PREFIX = /^\[pod\/([^\/\]\s]+)\/([^\]\s]+)\]\s?(.*)$/;
  var RE_KLOG = /^([IWEF])(\d{4}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+(\d+)\s+([^\]\s]+)\]\s?(.*)$/;
  var RE_SYSLOG_BODY = /^([A-Za-z0-9][\w.-]*)\s+([^\s:\[]+)(?:\[(\d+)\])?:\s?(.*)$/;
  var RE_CRI = /^(stdout|stderr)\s+[FP]\s/;
  var RE_LOGFMT_HINT = /(?:^|\s)(?:level|lvl|msg|ts|time|severity)=/;
  var RE_REQUEST_LINE = /"(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) \S+ HTTP\/[\d.]+"\s+\d{3}\b|\b(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) \/\S*\s+(?:status[=: ]+)?\d{3}\b/;
  var RE_CONTINUATION = /^(?:\s+at\s|\s+\.\.\. \d+ more|Caused by:|\s+File "|goroutine \d+ \[|\s+\S+\.go:\d+|Traceback \(most recent call last\))/;

  var RE_H_EVENTS = /^\s*(NAMESPACE\s+)?LAST SEEN\s+TYPE\s+REASON\s+OBJECT\s+/;
  var RE_H_PODS = /^\s*(NAMESPACE\s+)?NAME\s+READY\s+STATUS\s+RESTARTS\s+AGE\b/;
  var RE_H_NODES = /^\s*NAME\s+STATUS\s+ROLES\s+AGE\s+VERSION\b/;
  var RE_H_HPA = /^\s*(NAMESPACE\s+)?NAME\s+REFERENCE\s+TARGETS\s+MINPODS\s+MAXPODS\s+REPLICAS\s+AGE\b/;
  var RE_H_DESC_EVENTS = /^\s*Type\s+Reason\s+Age\s+From\s+Message\s*$/;
  // Top-level keys of `kubectl describe pod|deployment|node`. A listed set (not "any Word:") so a
  // log line such as "FATAL:  sorry, too many clients" right after a describe block is still read.
  var RE_DESCRIBE_TOP = /^(Name|Namespace|Priority|Priority Class Name|Runtime Class Name|Service Account|Node|Start Time|Labels|Annotations|Status|Reason|Message|IP|IPs|Controlled By|Containers|Init Containers|Ephemeral Containers|Conditions|Volumes|QoS Class|Node-Selectors|Tolerations|Events|Nominated Node Name|SeccompProfile|CreationTimestamp|Selector|Replicas|StrategyType|MinReadySeconds|RollingUpdateStrategy|Pod Template|OldReplicaSets|NewReplicaSet|Roles|Taints|Unschedulable|Lease|Addresses|Capacity|Allocatable|System Info|PodCIDR|PodCIDRs|ProviderID|Non-terminated Pods|Allocated resources):(\s|$)/;

  // LAST SEEN is one token in `kubectl get events`, but `kubectl events` (kubectl ≥ 1.26,
  // pkg/cmd/events/event_printer.go) prints repeated events as "3m (x4 over 5m)".
  var AGE_CELL = '(?:\\S+(?:\\s+\\(x\\d+\\s+over\\s+[^)\\s]+\\))?)';
  var RE_ROW_EVENTS = new RegExp('^\\s*(' + AGE_CELL + ')\\s+(Normal|Warning)\\s+(\\S+)\\s+(\\S+)\\s+(.*)$');
  // Event rows pasted without their header line: an age, a type, a reason and a kind/name object.
  var AGE_TOKEN = '(?:<unknown>|\\d+(?:\\.\\d+)?(?:[smhdy]\\d*)+)(?:\\s+\\(x\\d+\\s+over\\s+[^)\\s]+\\))?';
  var RE_EVENTS_HEADERLESS = new RegExp('^\\s*' + AGE_TOKEN + '\\s+(?:Normal|Warning)\\s+\\S+\\s+[A-Za-z.]+\\/\\S+\\s');
  var RE_EVENTS_HEADERLESS_NS = new RegExp('^\\s*[a-z0-9][a-z0-9-]*\\s+' + AGE_TOKEN + '\\s+(?:Normal|Warning)\\s+\\S+\\s+[A-Za-z.]+\\/\\S+\\s');
  var RE_ROW_EVENTS_NS = new RegExp('^\\s*(\\S+)\\s+(' + AGE_CELL + ')\\s+(Normal|Warning)\\s+(\\S+)\\s+(\\S+)\\s+(.*)$');
  var RE_AGE_SERIES = /^(\S+)\s+\(x(\d+)\s+over\s+([^)\s]+)\)$/;
  var RE_ROW_PODS = /^\s*(\S+)\s+(\d+)\/(\d+)\s+(\S+)\s+(\d+)(?:\s+\(([^)]*)\))?\s+(\S+)(?:\s+(\S+)\s+(\S+))?/;
  var RE_ROW_PODS_NS = /^\s*(\S+)\s+(\S+)\s+(\d+)\/(\d+)\s+(\S+)\s+(\d+)(?:\s+\(([^)]*)\))?\s+(\S+)(?:\s+(\S+)\s+(\S+))?/;
  var RE_ROW_NODES = /^\s*(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(v\d\S*)/;
  var RE_ROW_HPA_TAIL = /^(.*?)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s*$/;
  var RE_ROW_DESC_EVENT = /^\s*(Normal|Warning)\s+(\S+)\s+(<unknown>|<invalid>|\S+(?:\s+\(x(\d+) over (\S+)\))?)\s+(\S+(?:,\s*\S+)?)\s+(.*)$/;

  var POD_STATUS = {
    crashloopbackoff: 'crash_loop', oomkilled: 'oom_killed', imagepullbackoff: 'image_pull', errimagepull: 'image_pull',
    invalidimagename: 'image_pull', errimageneverpull: 'image_pull', createcontainerconfigerror: 'config_error',
    createcontainererror: 'config_error', runcontainererror: 'config_error', pending: 'scheduling_failed',
    evicted: 'evicted', error: 'error_generic', terminating: 'restart', containerstatusunknown: 'error_generic',
    nodelost: 'node_not_ready', unknown: 'node_not_ready', outofmemory: 'evicted', outofcpu: 'scheduling_failed',
    nodeaffinity: 'scheduling_failed', unexpectedadmissionerror: 'error_generic'
  };

  // Header → [{name, start}] for fixed-width tables (columns are separated by 2+ spaces; names
  // like "LAST SEEN" contain a single space).
  function columns(header) {
    var cols = [];
    var re = /\S+(?: \S+)*/g, m;
    while ((m = re.exec(header)) !== null) cols.push({ name: m[0], start: m.index });
    return cols;
  }
  function sliceCols(line, cols) {
    var out = {};
    for (var i = 0; i < cols.length; i++) {
      var s = cols[i].start, e = i + 1 < cols.length ? cols[i + 1].start : line.length;
      out[cols[i].name] = line.slice(s, e).trim();
    }
    return out;
  }

  // Event OBJECT column ("pod/payments-api-7d9f8b6c5-x2k4p") → entity fields.
  function objectRef(obj) {
    var m = /^([A-Za-z.]+)\/(.+)$/.exec(obj || '');
    if (!m) return null;
    var kind = m[1].toLowerCase().replace(/\..*$/, '');
    var name = m[2].toLowerCase();
    switch (kind) {
      case 'pod': case 'pods': return { pod: name, objKind: 'Pod', objName: name };
      case 'replicaset': return { name: E.stripReplicaSet(name), objKind: 'ReplicaSet', objName: name };
      case 'node': return { node: name, objKind: 'Node', objName: name };
      case 'persistentvolumeclaim': case 'pvc': {
        // "data-postgres-0" (volumeClaimTemplate "data" + pod "postgres-0") → postgres
        var pm = /^[a-z0-9]+-(.+-\d+)$/.exec(name);
        return { name: pm ? E.stripPod(pm[1]).workload : name, objKind: 'PersistentVolumeClaim', objName: name };
      }
      case 'certificate': case 'certificaterequest':
        return { name: name.replace(/-(tls|cert|certificate)(-[a-z0-9]{5})?$/, ''), objKind: 'Certificate', objName: name };
      case 'horizontalpodautoscaler': case 'hpa':
        return { name: name, objKind: 'HorizontalPodAutoscaler', objName: name };
      default:
        return { name: name, objKind: m[1], objName: name };
    }
  }

  // Event objects in a JSON document: a List/EventList, a bare array (jq '.items'), or one Event.
  function k8sEvents(v) {
    if (!v || typeof v !== 'object') return null;
    var items = Array.isArray(v) ? v : Array.isArray(v.items) ? v.items : v.kind === 'Event' ? [v] : null;
    if (!items || !items.length) return null;
    var evs = items.filter(function (x) { return x && typeof x === 'object' && (x.involvedObject || x.regarding) && (x.reason != null || x.message != null || x.note != null); });
    return evs.length ? evs : null;
  }

  // -------------------------------------------------------------------------------------------
  // Main
  // -------------------------------------------------------------------------------------------
  var LATEST_KEPT = 5;
  // Keep the LATEST_KEPT largest distinct values, newest first (cheap: the list never grows).
  function noteLatest(list, ts) {
    if (list.length === LATEST_KEPT && ts <= list[LATEST_KEPT - 1]) return;
    if (list.indexOf(ts) >= 0) return;
    list.push(ts);
    list.sort(function (a, b) { return b - a; });
    if (list.length > LATEST_KEPT) list.pop();
  }

  function parseLogs(text, ctx) {
    ctx = ctx || {};
    var stats = WR.newStats('empty');
    var result = {
      signals: [], entities: [], stats: stats,
      extras: {
        minTs: null, maxTs: null, timedLines: 0, relativeCount: 0, componentCounts: {},
        dependencyHints: [], upstreams: {}, clusters: [], formats: {}, rollouts: [], podInfo: {},
        // Request-shaped lines (HTTP method or a status field) and how many were 5xx: the error
        // budget's last-resort error ratio. Non-error request lines never become signals, so the
        // analysis cannot count them afterwards.
        requests: { total: 0, errors: 0 },
        // The newest few distinct stamps of ANY line, info lines included. Info lines never become
        // signals, so without these a long healthy tail after the errors would look like one
        // isolated stamp to the clock's outlier check and be thrown away.
        latestTs: []
      }
    };
    try {
      run(String(text == null ? '' : text), ctx, result);
    } catch (e) {
      WR.addWarning(stats, 'Log parsing stopped early: ' + (e && e.message ? e.message : String(e)));
    }
    stats.signals = result.signals.length;
    return result;
  }

  function run(text, ctx, result) {
    var stats = result.stats, extras = result.extras;
    var lines = WR.splitLines(text);
    stats.lines = lines.length;
    if (!lines.length) return;

    var tzOpts = { defaultTz: ctx.defaultTz || 'Z', year: ctx.year, now: ctx.now };
    var ctxNow = T.resolveNow(ctx.now, tzOpts);
    var defaultCluster = ctx.cluster || E.DEFAULT_CLUSTER;
    // Every cluster this paste names (here or in the other panes), so a host such as
    // svc.ns.<cluster>.internal can be tied to that cluster's component.
    var knownClusters = (ctx.knownClusters || []).slice();
    if (ctx.cluster) knownClusters.push(ctx.cluster);
    for (var kc = 0; kc < lines.length && kc < 20000; kc++) {
      var kl = lines[kc];
      if (kl.length > 400) continue;
      var km = E.detectCluster(kl);
      if (km && knownClusters.indexOf(km) < 0) knownClusters.push(km);
    }
    var ents = E.collector();
    var depIndex = Object.create(null);
    var depSignals = Object.create(null);
    var yearAssumed = 0;
    var unknownTs = [];   // signals that had no stamp before the first stamped line

    var st = {
      cluster: defaultCluster, clusterKnown: !!ctx.cluster,
      ns: null, pod: null, container: null, workload: null,
      table: null, describe: null, last: null, lastTs: null, firstTs: null
    };

    function fmtSeen(name) { extras.formats[name] = (extras.formats[name] || 0) + 1; }

    // JSON documents that hold Kubernetes Events, by first line (only looked for when the pane
    // mentions an event's object field, so ordinary JSON log lines cost nothing).
    var jsonDocs = Object.create(null);
    if (/"(?:involvedObject|regarding)"\s*:/.test(text)) {
      WR.segmentJson(lines).forEach(function (sg) { if (sg.type === 'json') jsonDocs[sg.startLine] = sg; });
    }

    function noteTs(r) {
      if (r.tzAssumed) stats.tzAssumed++;
      if (r.yearAssumed) yearAssumed++;
    }

    function absTs(ts) {
      if (ts == null) return;
      extras.timedLines++;
      if (extras.minTs == null || ts < extras.minTs) extras.minTs = ts;
      if (extras.maxTs == null || ts > extras.maxTs) extras.maxTs = ts;
      noteLatest(extras.latestTs, ts);
      st.lastTs = ts;
      if (st.firstTs == null) st.firstTs = ts;
    }

    function entityFor(o) {
      // o: { pod, name, node, ns, cluster, container }
      var h = E.hint({
        pod: o.pod, name: o.name, node: o.node,
        namespace: o.ns || null,
        cluster: o.cluster || st.cluster,
        clusterKnown: o.cluster ? true : st.clusterKnown,
        defaultCluster: defaultCluster,
        source: 'logs'
      });
      if (!h) return null;
      ents.add(h);
      return h;
    }

    function countLevel(cid, level) {
      if (!cid) return;
      var c = extras.componentCounts[cid] || (extras.componentCounts[cid] = { error: 0, warn: 0, info: 0, lines: 0 });
      c.lines++;
      if (level === 'critical' || level === 'error') c.error++;
      else if (level === 'warn') c.warn++;
      else c.info++;
    }

    var perLine = Object.create(null);
    function addSignal(lineNo, raw, o) {
      // o: { kind, level, text, ts, tsInferred, relative, ageMs, entity, attrs }
      var kind = o.kind || 'error_generic';
      if (!WR.isKind(kind)) kind = 'error_generic';
      var sev = WR.maxSev(o.level || 'info', FLOOR[kind] || 'info');
      var k = perLine[lineNo] || 0;
      perLine[lineNo] = k + 1;
      var attrs = o.attrs || {};
      var sig = {
        id: 'log-' + lineNo + (k ? '.' + k : ''),
        source: 'logs',
        line: lineNo,
        ts: o.ts != null ? o.ts : null,
        tsInferred: !!o.tsInferred,
        severity: sev,
        kind: kind,
        componentId: o.entity ? o.entity.id : null,
        relatedIds: [],
        text: WR.truncate(o.text || raw.trim(), 400),
        raw: WR.truncate(raw, 2000),
        attrs: attrs
      };
      if (o.relative) {
        attrs.relative = true;
        attrs.ageMs = o.ageMs || 0;
        extras.relativeCount++;
        sig.tsInferred = true;
      } else if (sig.ts == null) {
        unknownTs.push(sig);
        sig.tsInferred = true;
      }
      result.signals.push(sig);

      if (DEP_KINDS[kind] && sig.componentId) {
        var self = o.entity;
        // An ingress access line names its upstream in brackets (handled per caller); the URLs in it
        // are the public host and the referer, not dependencies.
        var tgt = RE_NGINX_UPSTREAM.test(o.text || raw) ? null : extractTarget(o.text || raw, attrs.targetHost, knownClusters);
        if (tgt) {
          if (!(self && tgt.name === self.name)) {
            var th = E.hint({
              name: tgt.name, namespace: tgt.namespace, cluster: tgt.cluster || (self ? self.cluster : st.cluster),
              clusterKnown: tgt.cluster ? true : (self ? self.clusterKnown : st.clusterKnown), type: tgt.external ? 'external' : null,
              source: 'logs'
            });
            if (th) {
              ents.add(th);
              attrs.target = tgt.name;
              attrs.targetId = th.id;
              addDep(sig, th.id, kind);
            }
          }
        }
        if (kind === 'dns_failure') {
          var dns = E.hint({ name: 'coredns', cluster: self ? self.cluster : st.cluster, clusterKnown: self ? self.clusterKnown : st.clusterKnown, source: 'logs' });
          if (dns) { ents.add(dns); addDep(sig, dns.id, kind); }
        }
      }
      return sig;
    }

    function addDep(sig, to, kind) {
      if (!sig.componentId || sig.componentId === to) return;
      var key = sig.componentId + '->' + to;
      var d = depIndex[key];
      if (!d) {
        d = depIndex[key] = { from: sig.componentId, to: to, kinds: [], count: 0, firstTs: null, lastTs: null, signalIds: [] };
        depSignals[key] = [];
        extras.dependencyHints.push(d);
      }
      d.count++;
      if (d.kinds.indexOf(kind) < 0) d.kinds.push(kind);
      // Times are filled in at the end: relative (event-table) signals only get theirs then.
      depSignals[key].push(sig);
      if (d.signalIds.length < 20) d.signalIds.push(sig.id);
    }

    function resetContext() {
      st.table = null; st.describe = null; st.pod = null; st.container = null; st.workload = null; st.last = null;
    }

    // A `-n shop` on `kubectl get events` describes the table that follows, not every later line.
    // Only a `kubectl logs` echo (which names a pod/workload) keeps its namespace for the stream.
    function endBlock() {
      st.table = null; st.describe = null;
      if (!st.pod && !st.workload) st.ns = null;
    }

    // ---- table rows -----------------------------------------------------------------------
    function eventRow(line, lineNo, raw) {
      var t = st.table;
      var ns = null, lastSeen, type, reason, obj, message, firstSeen = null, count = null, subobject = null, source = null;
      if (t.wide) {
        var v = sliceCols(line, t.cols);
        if (v.TYPE === 'Normal' || v.TYPE === 'Warning') {
          ns = v.NAMESPACE || null; lastSeen = v['LAST SEEN']; type = v.TYPE; reason = v.REASON; obj = v.OBJECT;
          message = v.MESSAGE; firstSeen = v['FIRST SEEN'] || null; count = v.COUNT ? Number(v.COUNT) : null;
          subobject = v.SUBOBJECT || null; source = v.SOURCE || null;
        }
      }
      if (!type) {
        var hasNs = t.hasNs;
        var m = (hasNs ? RE_ROW_EVENTS_NS : RE_ROW_EVENTS).exec(line);
        // Rows pasted without a header may mix shapes (some from -A output, some not).
        if (!m && t.implicit) { hasNs = !hasNs; m = (hasNs ? RE_ROW_EVENTS_NS : RE_ROW_EVENTS).exec(line); }
        if (!m) return false;
        if (hasNs) { ns = m[1]; lastSeen = m[2]; type = m[3]; reason = m[4]; obj = m[5]; message = m[6]; }
        else { lastSeen = m[1]; type = m[2]; reason = m[3]; obj = m[4]; message = m[5]; }
        if (t.wide) {
          // Misaligned wide row: peel FIRST SEEN / COUNT / NAME off the end of the message.
          var tail = /\s+(\S+)\s+(\d+)\s+(\S+)\s*$/.exec(message);
          if (tail) { firstSeen = tail[1]; count = Number(tail[2]); message = message.slice(0, tail.index); }
        }
      }
      fmtSeen('kubectl events');
      // "3m (x4 over 5m)": seen 4 times, first 5 minutes ago — the "over" age is the onset.
      var series = RE_AGE_SERIES.exec(String(lastSeen || '').trim());
      if (series) {
        lastSeen = series[1];
        if (count == null) count = Number(series[2]);
        if (!firstSeen) firstSeen = series[3];
      }
      var ref = objectRef(obj) || { name: obj };
      var ent = entityFor({ pod: ref.pod, name: ref.name, node: ref.node, ns: ns || st.ns });
      // FIRST SEEN (wide) marks the onset, which is what the incident timeline needs.
      var ageStr = firstSeen && T.age(firstSeen) != null ? firstSeen : lastSeen;
      var ageMs = T.age(ageStr);
      var level = type === 'Warning' ? 'warn' : 'info';
      var ctext = reason + ': ' + message;
      var kind = classify(ctext);
      countLevel(ent && ent.id, level);
      if (!kind && type !== 'Warning') return true;
      var attrs = { reason: reason, eventType: type, object: obj, format: 'kubectl events' };
      if (ref.pod) attrs.pod = ref.pod;
      if (count != null) attrs.count = count;
      if (subobject) attrs.subobject = subobject;
      if (source) attrs.from = source;
      if (ageMs == null) attrs.ageUnknown = true;
      if (kind === 'rollout') rolloutAttrs(message, attrs, ent);
      addSignal(lineNo, raw, {
        kind: kind || 'error_generic', level: kind ? level : 'warn', text: reason + ': ' + message,
        relative: true, ageMs: ageMs || 0, entity: ent, attrs: attrs
      });
      return true;
    }

    // `kubectl get events -o json` (core/v1 Event: involvedObject, firstTimestamp, lastTimestamp,
    // count) and events.k8s.io/v1 (regarding, note, eventTime, series). Unlike the table, the JSON
    // carries absolute times, so the onset is exact.
    function readEventJson(sg) {
      var pj = WR.parseJsonLenient(sg.text);
      var evs = k8sEvents(pj.value);
      if (!evs) return false;
      var starts = WR.lineIndex(sg.text), cursor = 0;
      evs.forEach(function (ev) {
        var obj = ev.involvedObject || ev.regarding || {};
        var reason = String(ev.reason || ''), message = String(ev.message != null ? ev.message : ev.note != null ? ev.note : '').trim(), type = String(ev.type || 'Normal');
        // Point at the line holding this event's message, in document order.
        var re = /"(?:message|note)"\s*:/g;
        re.lastIndex = cursor;
        var mm = re.exec(sg.text);
        var lineNo = mm ? sg.startLine + WR.lineAt(starts, mm.index) - 1 : sg.startLine;
        if (mm) cursor = mm.index + 1;
        var ref = objectRef((obj.kind || 'Pod') + '/' + (obj.name || '')) || { name: obj.name };
        var ent = entityFor({ pod: ref.pod, name: ref.name, node: ref.node, ns: obj.namespace || (ev.metadata && ev.metadata.namespace) || st.ns });
        var level = type === 'Warning' ? 'warn' : 'info';
        var kind = classify(reason + ': ' + message);
        countLevel(ent && ent.id, level);
        fmtSeen('kubectl events JSON');
        if (!kind && type !== 'Warning') return;
        var series = ev.series || {};
        var firstStr = ev.firstTimestamp || ev.deprecatedFirstTimestamp || ev.eventTime || null;
        var lastStr = ev.lastTimestamp || ev.deprecatedLastTimestamp || series.lastObservedTime || ev.eventTime || firstStr;
        var p = firstStr ? T.parse(String(firstStr), tzOpts) : null;
        var lp = lastStr ? T.parse(String(lastStr), tzOpts) : null;
        if (!p) p = lp;
        var attrs = { reason: reason, eventType: type, object: (obj.kind || '') + '/' + (obj.name || ''), format: 'kubectl events JSON' };
        var count = ev.count || series.count || ev.deprecatedCount;
        if (count) attrs.count = Number(count);
        if (ref.pod) attrs.pod = ref.pod;
        if (obj.fieldPath) attrs.subobject = obj.fieldPath;
        if (lp) attrs.lastSeen = lp.ts;
        if (kind === 'rollout') rolloutAttrs(message, attrs, ent);
        if (p) { noteTs(p); absTs(p.ts); }
        if (lp && lp !== p) absTs(lp.ts);
        addSignal(lineNo, lines[lineNo - 1] || '', { kind: kind || 'error_generic', level: kind ? level : 'warn', text: reason + ': ' + message, ts: p ? p.ts : null, tsInferred: p ? p.tsInferred : false, entity: ent, attrs: attrs });
      });
      stats.parsed += sg.endLine - sg.startLine + 1;
      return true;
    }

    function rolloutAttrs(message, attrs, ent) {
      var m = /replica set (\S+) (?:to|from \d+ to) (\d+)/i.exec(message);
      if (m) {
        attrs.replicaSet = m[1].toLowerCase();
        attrs.replicas = Number(m[2]);
        attrs.direction = /Scaled down/i.test(message) ? 'down' : 'up';
      }
      var p = /Created pod: (\S+)/.exec(message);
      if (p) { attrs.pod = p[1].toLowerCase(); attrs.replicaSet = E.stripPod(p[1]).replicaSet; }
      if (attrs.replicaSet) extras.rollouts.push({ replicaSet: attrs.replicaSet, workload: E.stripReplicaSet(attrs.replicaSet), componentId: ent ? ent.id : null, direction: attrs.direction || 'up' });
    }

    function podRow(line, lineNo, raw) {
      var t = st.table;
      var m = (t.hasNs ? RE_ROW_PODS_NS : RE_ROW_PODS).exec(line);
      if (!m) return false;
      var o = t.hasNs ? 1 : 0;
      var ns = t.hasNs ? m[1] : null;
      var pod = m[1 + o], ready = Number(m[2 + o]), total = Number(m[3 + o]), status = m[4 + o];
      var restarts = Number(m[5 + o]), lastRestart = m[6 + o] || null, ageStr = m[7 + o];
      var node = t.wide ? (m[9 + o] || null) : null;
      fmtSeen('kubectl get pods');
      var ent = entityFor({ pod: pod, ns: ns || st.ns });
      var info = extras.podInfo[pod.toLowerCase()] || (extras.podInfo[pod.toLowerCase()] = {});
      info.status = status; info.restarts = restarts; info.ready = ready + '/' + total;
      if (node && node !== '<none>') info.node = node;
      var st0 = status.replace(/^Init:/, '').toLowerCase();
      var kind = POD_STATUS[st0] || null;
      var level = 'info';
      if (!kind && /^running$/i.test(status) && ready < total) { kind = 'probe_failed'; level = 'warn'; }
      if (!kind && restarts > 0 && /^(running|completed)$/i.test(status)) { kind = 'restart'; level = 'warn'; }
      if (kind === 'scheduling_failed') level = 'warn';
      if (kind && kind !== 'restart' && kind !== 'scheduling_failed' && kind !== 'probe_failed') level = 'error';
      countLevel(ent && ent.id, kind ? level : 'info');
      if (!kind) return true;
      var lastRestartAge = lastRestart ? T.age(lastRestart.replace(/\s*ago$/, '')) : null;
      var attrs = { pod: pod.toLowerCase(), podStatus: status, restarts: restarts, ready: ready + '/' + total, format: 'kubectl get pods' };
      if (node && node !== '<none>') attrs.node = node;
      var podAge = T.age(ageStr);
      if (podAge != null) attrs.podAgeMs = podAge;
      addSignal(lineNo, raw, {
        kind: kind, level: level, text: 'Pod ' + pod + ' is ' + status + (restarts ? ' (' + restarts + ' restarts)' : ''),
        relative: true, ageMs: lastRestartAge != null ? lastRestartAge : (kind === 'scheduling_failed' && podAge != null ? podAge : 0),
        entity: ent, attrs: attrs
      });
      return true;
    }

    function nodeRow(line, lineNo, raw) {
      var m = RE_ROW_NODES.exec(line);
      if (!m) return false;
      fmtSeen('kubectl get nodes');
      var ent = entityFor({ node: m[1] });
      if (/NotReady|Unknown/.test(m[2])) {
        countLevel(ent && ent.id, 'error');
        addSignal(lineNo, raw, { kind: 'node_not_ready', level: 'error', text: 'Node ' + m[1] + ' is ' + m[2], relative: true, ageMs: 0, entity: ent, attrs: { node: m[1], nodeStatus: m[2], format: 'kubectl get nodes' } });
      } else countLevel(ent && ent.id, 'info');
      return true;
    }

    function hpaRow(line, lineNo, raw) {
      var t = st.table;
      var tl = line.trim();
      var toks = tl.split(/\s+/);
      var o = t.hasNs ? 1 : 0;
      if (toks.length < 7 + o) return false;
      var tail = RE_ROW_HPA_TAIL.exec(tl);
      if (!tail) return false;
      var ns = t.hasNs ? toks[0] : null;
      var name = toks[o], ref = toks[1 + o];
      if (ref.indexOf('/') < 0) return false;
      var min = Number(tail[2]), max = Number(tail[3]), replicas = Number(tail[4]);
      fmtSeen('kubectl get hpa');
      var target = ref.split('/')[1] || name;
      var ent = entityFor({ name: target, ns: ns || st.ns });
      var targets = tail[1].split(/\s+/).slice(2 + o).join(' ');
      if (replicas >= max) {
        countLevel(ent && ent.id, 'warn');
        addSignal(lineNo, raw, {
          kind: 'hpa_maxed', level: 'warn', text: 'HorizontalPodAutoscaler ' + name + ' is at its maximum: ' + replicas + ' of ' + max + ' replicas' + (targets ? ' (' + targets + ')' : ''),
          relative: true, ageMs: 0, entity: ent, attrs: { hpa: name, minReplicas: min, maxReplicas: max, replicas: replicas, targets: targets, format: 'kubectl get hpa' }
        });
      } else countLevel(ent && ent.id, 'info');
      return true;
    }

    function describeEventRow(line, lineNo, raw) {
      var m = RE_ROW_DESC_EVENT.exec(line);
      if (!m) return false;
      var d = st.describe || {};
      var type = m[1], reason = m[2], ageField = m[3], count = m[4] ? Number(m[4]) : null, over = m[5] || null, from = m[6], message = m[7];
      fmtSeen('kubectl describe');
      var ent = d.entity || null;
      // "2m (x5 over 10m)": the first occurrence was 10 minutes ago — that is the onset we want.
      var ageMs = T.age(over || ageField);
      var level = type === 'Warning' ? 'warn' : 'info';
      var kind = classify(reason + ': ' + message);
      countLevel(ent && ent.id, level);
      if (!kind && type !== 'Warning') return true;
      var attrs = { reason: reason, eventType: type, from: from, format: 'kubectl describe' };
      if (d.pod) attrs.pod = d.pod;
      if (count != null) attrs.count = count;
      if (ageMs == null) attrs.ageUnknown = true;
      if (kind === 'rollout') rolloutAttrs(message, attrs, ent);
      addSignal(lineNo, raw, { kind: kind || 'error_generic', level: kind ? level : 'warn', text: reason + ': ' + message, relative: true, ageMs: ageMs || 0, entity: ent, attrs: attrs });
      return true;
    }

    // ---- describe pod block -------------------------------------------------------------------
    function describeLine(line, lineNo, raw) {
      var d = st.describe;
      var m;
      if ((m = /^Name:\s+(\S+)\s*$/.exec(line))) {
        st.describe = d = { pod: m[1].toLowerCase(), ns: st.ns, entity: null, section: null, container: null, block: null, containers: {} };
        d.entity = entityFor({ pod: d.pod, ns: d.ns });
        fmtSeen('kubectl describe');
        return true;
      }
      if (!d) return false;
      if (!/^\s/.test(line) && !RE_DESCRIBE_TOP.test(line)) return false; // not describe-shaped → leave the block
      fmtSeen('kubectl describe');
      if ((m = /^Namespace:\s+(\S+)/.exec(line))) {
        d.ns = m[1].toLowerCase();
        d.entity = entityFor({ pod: d.pod, ns: d.ns });
        return true;
      }
      if ((m = /^Node:\s+([^\s\/]+)/.exec(line))) { d.node = m[1]; podInfo(d).node = m[1]; return true; }
      if ((m = /^Controlled By:\s+(\w+)\/(\S+)/.exec(line))) { d.controller = m[1] + '/' + m[2]; return true; }
      if ((m = /^(Containers|Init Containers):\s*$/.exec(line))) { d.section = 'containers'; d.container = null; d.block = null; return true; }
      if ((m = /^Events:\s*(.*)$/.exec(line))) { d.section = 'events'; return true; }
      if ((m = /^Reason:\s+(\S+)/.exec(line))) {
        // Pod-level reason, e.g. "Reason: Evicted" with "Message: The node was low on resource: memory."
        var k0 = classify(m[1]) || (m[1] === 'Evicted' ? 'evicted' : null);
        if (k0) {
          countLevel(d.entity && d.entity.id, 'error');
          d.podSignal = addSignal(lineNo, raw, { kind: k0, level: 'error', text: 'Pod ' + d.pod + ' ' + m[1], relative: true, ageMs: 0, entity: d.entity, attrs: { pod: d.pod, reason: m[1], format: 'kubectl describe' } });
        }
        return true;
      }
      if ((m = /^Message:\s+(.*)$/.exec(line)) && d.podSignal) { d.podSignal.text += ': ' + m[1]; return true; }
      if (/^[A-Z]/.test(line)) { d.section = /^(Labels|Annotations|Conditions|Volumes|QoS Class|Node-Selectors|Tolerations|Status|IP|IPs|Start Time|Priority|Service Account)/.test(line) ? 'other' : d.section; return true; }

      if (d.section === 'containers') {
        if ((m = /^\s{2}([a-z0-9][a-z0-9-]*):\s*$/.exec(line))) {
          d.container = m[1]; d.block = null; d.limits = false;
          d.containers[d.container] = d.containers[d.container] || { signals: [] };
          return true;
        }
        var c = d.container ? d.containers[d.container] : null;
        if ((m = /^\s+(State|Last State):\s+(\w+)/.exec(line))) {
          d.block = { which: m[1], state: m[2], signal: null, exitCode: null };
          d.limits = false;
          return true;
        }
        if ((m = /^\s+Reason:\s+(\S+)/.exec(line)) && d.block) {
          var reason = m[1];
          var kind = classify(reason) || (reason === 'Error' ? 'error_generic' : null);
          if (kind) {
            countLevel(d.entity && d.entity.id, 'error');
            d.block.signal = addSignal(lineNo, raw, {
              kind: kind, level: 'error',
              text: 'Container ' + (d.container || '?') + ' in pod ' + d.pod + (d.block.which === 'Last State' ? ' last terminated: ' : ' is waiting: ') + reason,
              relative: true, ageMs: 0, entity: d.entity,
              attrs: { pod: d.pod, container: d.container, reason: reason, state: d.block.which, format: 'kubectl describe' }
            });
            if (c) c.signals.push(d.block.signal);
          }
          return true;
        }
        if ((m = /^\s+Exit Code:\s+(\d+)/.exec(line)) && d.block) {
          var code = Number(m[1]);
          d.block.exitCode = code;
          var s = d.block.signal;
          if (s) {
            s.attrs.exitCode = code;
            // 137 = SIGKILL; with reason "Error" it is almost always the OOM killer (SPEC §3.1).
            if (code === 137 && s.kind === 'error_generic') { s.kind = 'oom_killed'; s.text += ' (exit code 137)'; }
          } else if (code === 137) {
            countLevel(d.entity && d.entity.id, 'error');
            d.block.signal = addSignal(lineNo, raw, {
              kind: 'oom_killed', level: 'error', text: 'Container ' + (d.container || '?') + ' in pod ' + d.pod + ' exited with code 137 (killed)',
              relative: true, ageMs: 0, entity: d.entity, attrs: { pod: d.pod, container: d.container, exitCode: 137, format: 'kubectl describe' }
            });
            if (c) c.signals.push(d.block.signal);
          }
          return true;
        }
        if ((m = /^\s+(Started|Finished):\s+(.+)$/.exec(line)) && d.block && d.block.signal) {
          var p = T.parse(m[2], tzOpts);
          if (p && (m[1] === 'Finished' || d.block.signal.attrs.relative)) {
            // An absolute stamp beats the relative placeholder: undo the relative bookkeeping.
            var sg = d.block.signal;
            if (sg.attrs.relative) { delete sg.attrs.relative; delete sg.attrs.ageMs; extras.relativeCount--; }
            sg.ts = p.ts; sg.tsInferred = p.tsInferred; noteTs(p);
            sg.attrs[m[1] === 'Finished' ? 'finishedAt' : 'startedAt'] = p.ts;
          }
          return true;
        }
        if ((m = /^\s+Restart Count:\s+(\d+)/.exec(line))) {
          var rc = Number(m[1]);
          if (c) {
            c.restartCount = rc;
            c.signals.forEach(function (x) { x.attrs.restartCount = rc; });
            if (!c.signals.length && rc > 0) {
              countLevel(d.entity && d.entity.id, 'warn');
              c.signals.push(addSignal(lineNo, raw, { kind: 'restart', level: 'warn', text: 'Container ' + d.container + ' in pod ' + d.pod + ' restarted ' + rc + ' times', relative: true, ageMs: 0, entity: d.entity, attrs: { pod: d.pod, container: d.container, restartCount: rc, format: 'kubectl describe' } }));
            }
          }
          podInfo(d).restarts = rc;
          return true;
        }
        if (/^\s+Limits:\s*$/.test(line)) { d.limits = 'limits'; d.block = null; return true; }
        if (/^\s+Requests:\s*$/.test(line)) { d.limits = 'requests'; d.block = null; return true; }
        if ((m = /^\s+(memory|cpu):\s+(\S+)/.exec(line)) && d.limits && c) {
          var key = (d.limits === 'limits' ? 'limit' : 'request') + (m[1] === 'memory' ? 'Memory' : 'Cpu');
          c[key] = m[2];
          var pi = podInfo(d);
          (pi.containers || (pi.containers = {}))[d.container] = pi.containers[d.container] || {};
          pi.containers[d.container][key] = m[2];
          if (key === 'limitMemory') c.signals.forEach(function (x) { x.attrs.memoryLimit = m[2]; });
          return true;
        }
      }
      return true; // other describe detail lines (labels, mounts, conditions) carry no signal
    }

    function podInfo(d) {
      return extras.podInfo[d.pod] || (extras.podInfo[d.pod] = {});
    }

    // ---- line loop ------------------------------------------------------------------------------
    for (var i = 0; i < lines.length; i++) {
      var raw = lines[i];
      var lineNo = i + 1;
      try {
        var line = raw.indexOf('\x1b') >= 0 ? raw.replace(RE_ANSI, '') : raw;
        if (line.charCodeAt(line.length - 1) === 13) line = line.slice(0, -1);
        if (!line.trim()) {
          if (st.table && st.table.type !== 'describe-events') endBlock();
          continue;
        }

        // 1. command echoes and cluster markers set context for what follows
        var cmd = E.parseCommand(line);
        if (cmd) {
          stats.parsed++;
          resetContext();
          if (cmd.context) { st.cluster = cmd.context; st.clusterKnown = true; if (extras.clusters.indexOf(cmd.context) < 0) extras.clusters.push(cmd.context); }
          st.ns = cmd.namespace || null;
          if (cmd.pod) st.pod = cmd.pod;
          if (cmd.workload) st.workload = cmd.workload;
          if (cmd.container) st.container = cmd.container;
          if (cmd.pod && cmd.verb === 'describe') st.describe = null;
          continue;
        }
        var marker = E.detectCluster(line);
        if (marker) {
          stats.parsed++;
          resetContext();
          st.ns = null;
          st.cluster = marker; st.clusterKnown = true;
          if (extras.clusters.indexOf(marker) < 0) extras.clusters.push(marker);
          continue;
        }

        // 2. `kubectl get events -o json`
        var jd = jsonDocs[lineNo];
        if (jd && readEventJson(jd)) { resetContext(); i = jd.endLine - 1; continue; }

        // 3. table headers
        var hm;
        if ((hm = RE_H_EVENTS.exec(line))) {
          st.table = { type: 'events', hasNs: !!hm[1], wide: /SUBOBJECT|FIRST SEEN/.test(line), cols: columns(line) };
          st.describe = null; stats.parsed++; continue;
        }
        if ((hm = RE_H_PODS.exec(line))) {
          st.table = { type: 'pods', hasNs: !!hm[1], wide: /\bNODE\b/.test(line) };
          st.describe = null; stats.parsed++; continue;
        }
        if (RE_H_NODES.test(line)) { st.table = { type: 'nodes' }; st.describe = null; stats.parsed++; continue; }
        if ((hm = RE_H_HPA.exec(line))) { st.table = { type: 'hpa', hasNs: !!hm[1] }; st.describe = null; stats.parsed++; continue; }
        if (RE_H_DESC_EVENTS.test(line)) { st.table = { type: 'describe-events' }; stats.parsed++; continue; }

        // 3. table rows (a headerless run of event rows starts an implicit events table)
        if (!st.table && (RE_EVENTS_HEADERLESS.test(line) || RE_EVENTS_HEADERLESS_NS.test(line))) {
          st.table = { type: 'events', hasNs: !RE_EVENTS_HEADERLESS.test(line), wide: false, implicit: true };
        }
        if (st.table) {
          if (/^\s*-{3,}(\s+-{3,})*\s*$/.test(line)) { stats.parsed++; continue; }
          var ok = false;
          if (st.table.type === 'events') ok = eventRow(line, lineNo, raw);
          else if (st.table.type === 'pods') ok = podRow(line, lineNo, raw);
          else if (st.table.type === 'nodes') ok = nodeRow(line, lineNo, raw);
          else if (st.table.type === 'hpa') ok = hpaRow(line, lineNo, raw);
          else if (st.table.type === 'describe-events') ok = describeEventRow(line, lineNo, raw);
          if (ok) { stats.parsed++; continue; }
          var keepDescribe = st.table.type === 'describe-events' ? st.describe : null;
          endBlock();
          st.describe = keepDescribe;
        }

        // 4. describe pod blocks
        if (/^Name:\s/.test(line) || st.describe) {
          if (describeLine(line, lineNo, raw)) { stats.parsed++; continue; }
          endBlock();
        }

        // 5. comments
        if (/^\s*#/.test(line)) { stats.parsed++; continue; }

        parseLogLine(line, lineNo, raw);
      } catch (err) {
        stats.skipped++;
        WR.addWarning(stats, 'Line ' + lineNo + ' could not be read: ' + (err && err.message ? err.message : err));
      }
    }

    // ---- one application log line ---------------------------------------------------------------
    function parseLogLine(line, lineNo, raw) {
      var rec = { ts: null, tsInferred: false, level: null, msg: '', err: null, pod: null, ns: null, cluster: null, container: null, service: null, traceId: null, status: null, latencyMs: null, target: null, host: null };
      var format = null;
      var body = line;
      var m;

      // --prefix / stern prefixes name the pod
      if ((m = RE_PREFIX.exec(body))) {
        rec.pod = m[1]; rec.container = m[2]; body = m[3]; format = 'kubectl --prefix';
      } else {
        var sp = sternSplit(body);
        if (sp) { rec.pod = sp.pod; rec.container = sp.container; if (sp.ns) rec.ns = sp.ns; body = sp.rest; format = 'stern'; }
      }

      // leading stamp: klog, ISO / syslog / epoch
      if ((m = RE_KLOG.exec(body))) {
        var pk = T.parse(m[2], tzOpts);
        if (pk) { rec.ts = pk.ts; rec.tsInferred = true; noteTs(pk); }
        rec.level = { I: 'info', W: 'warn', E: 'error', F: 'critical' }[m[1]];
        rec.source = m[4];
        body = m[5];
        format = format || 'klog';
      } else {
        var ex = T.extract(body, tzOpts);
        if (ex) {
          rec.ts = ex.ts; rec.tsInferred = ex.tsInferred; noteTs(ex);
          body = ex.rest;
          if (RE_CRI.test(body)) body = body.replace(RE_CRI, '');
          if (ex.format === 'syslog') {
            var sm = RE_SYSLOG_BODY.exec(body);
            if (sm) { rec.host = sm[1]; rec.proc = sm[2]; body = sm[4]; }
            format = format || 'syslog';
          } else format = format || 'timestamped text';
        }
      }

      // body: JSON / logfmt / plain
      var trimmed = body.trim();
      if (trimmed[0] === '{' && trimmed[trimmed.length - 1] === '}') {
        var obj = null;
        try { obj = JSON.parse(trimmed); } catch (e) { obj = null; }
        if (obj && typeof obj === 'object') {
          var jr = recordFromObject(obj, tzOpts, st);
          if (jr.ts != null) { rec.ts = jr.ts; rec.tsInferred = jr.tsInferred; noteTs(jr); }
          rec.level = jr.level || rec.level;
          rec.msg = jr.msg; rec.err = jr.err; rec.service = jr.service;
          rec.pod = rec.pod || jr.pod; rec.ns = rec.ns || jr.ns; rec.cluster = jr.cluster;
          rec.container = rec.container || jr.container; rec.traceId = jr.traceId; rec.status = jr.status;
          rec.latencyMs = jr.latencyMs; rec.target = jr.target;
          format = format && format !== 'timestamped text' ? format + ' JSON' : 'JSON logs';
        }
      } else if (RE_LOGFMT_HINT.test(trimmed)) {
        var kv = WR.logfmt(trimmed);
        if (Object.keys(kv).length >= 2) {
          var lr = recordFromObject(kv, tzOpts, st);
          if (lr.ts != null) { rec.ts = lr.ts; rec.tsInferred = lr.tsInferred; noteTs(lr); }
          rec.level = lr.level || rec.level;
          rec.msg = lr.msg || trimmed; rec.err = lr.err; rec.service = lr.service;
          rec.pod = rec.pod || lr.pod; rec.ns = rec.ns || lr.ns; rec.cluster = lr.cluster;
          rec.traceId = lr.traceId; rec.status = lr.status; rec.latencyMs = lr.latencyMs; rec.target = lr.target;
          format = format && format !== 'timestamped text' ? format + ' logfmt' : 'logfmt';
        }
      }
      if (!rec.msg) rec.msg = trimmed;
      if (!rec.level) rec.level = levelFromText(trimmed);

      var continuation = !format && !!st.last && (RE_CONTINUATION.test(line) || /^\s+\S/.test(line));
      if (!format && st.last && !st.pod && !st.workload && (continuation || rec.ts == null)) {
        // Stack-trace frames and wrapped lines belong to the record above them; so does an
        // unstamped line that follows one (a multi-line message).
        rec.pod = rec.pod || st.last.pod; rec.ns = rec.ns || st.last.ns; rec.service = rec.service || st.last.service;
        rec.host = rec.host || st.last.host;
        if (rec.ts == null && st.last.ts != null) { rec.ts = st.last.ts; rec.tsInferred = true; rec.carried = true; }
        if (continuation) format = 'continuation';
      }
      if (!format && (st.pod || st.workload)) format = 'plain text';

      var ctext = rec.msg;
      if (rec.err && ctext.indexOf(rec.err) < 0) ctext += ' ' + rec.err;
      if (rec.status != null) ctext += ' status=' + rec.status;
      if (rec.target) ctext += ' upstream=' + rec.target;
      var kind = classify(ctext);
      // In a continuation, only a NEW failure mode (e.g. "Caused by: ... Connection refused") is news.
      if (format === 'continuation' && st.last && st.last.kind === kind) kind = null;
      if (format === 'continuation' && !kind) { stats.parsed++; fmtSeen('plain text'); return; }

      if (!format && !kind && !rec.level) {
        stats.skipped++;
        return;
      }
      stats.parsed++;
      fmtSeen(format === 'continuation' ? 'plain text' : (format || 'plain text'));

      if (rec.status != null || RE_REQUEST_LINE.test(ctext)) {
        extras.requests.total++;
        if ((rec.status != null && rec.status >= 500 && rec.status <= 599) || kind === 'http_5xx') extras.requests.errors++;
      }

      // component: pod (most specific) → service key → echoed pod/workload → syslog host (node)
      var ent = null;
      var ns = rec.ns || st.ns;
      var clusterName = rec.cluster || null;
      if (rec.pod) ent = entityFor({ pod: rec.pod, ns: ns, cluster: clusterName });
      else if (rec.service) ent = entityFor({ name: rec.service, ns: ns, cluster: clusterName });
      else if (st.pod) ent = entityFor({ pod: st.pod, ns: ns, cluster: clusterName });
      else if (st.workload) ent = entityFor({ name: st.workload, ns: ns, cluster: clusterName });
      else if (rec.host && rec.proc && /^(kubelet|kernel|containerd|dockerd|systemd|kube-proxy|crio)$/.test(rec.proc)) ent = entityFor({ node: rec.host, cluster: clusterName });

      if (rec.ts != null && !rec.carried) absTs(rec.ts);
      else if (rec.ts == null && st.lastTs != null) { rec.ts = st.lastTs; rec.tsInferred = true; rec.carried = true; }

      var level = rec.level || 'info';
      countLevel(ent && ent.id, kind ? WR.maxSev(level, FLOOR[kind]) : level);

      st.last = { pod: rec.pod || st.pod, ns: ns, service: rec.service, host: rec.host, ts: rec.ts, level: rec.level, kind: kind };

      // ingress-nginx access log: "[shop-frontend-3000]" is the upstream (<namespace>-<service>-<port>).
      // Kept per caller with every status code seen, so the analysis can draw ingress -> service
      // with a real share of failed requests once it knows which split of the name is a component.
      var up = ent ? RE_NGINX_UPSTREAM.exec(ctext) : null;
      if (up) {
        var code = rec.status != null ? rec.status : (function () { var sm = RE_ACCESS_STATUS.exec(ctext); return sm ? Number(sm[1]) : null; })();
        var uk = ent.id + '|' + up[1];
        var u = extras.upstreams[uk] || (extras.upstreams[uk] = { from: ent.id, token: up[1], calls: 0, errors: 0, firstErrorTs: null, line: lineNo });
        u.calls++;
        if (code != null && code >= 500) {
          u.errors++;
          if (rec.ts != null && (u.firstErrorTs == null || rec.ts < u.firstErrorTs)) u.firstErrorTs = rec.ts;
        }
      }

      if (!kind && WR.sevRank(level) < 2) return;
      var attrs = { format: format || 'plain text' };
      if (rec.level) attrs.level = rec.level;
      if (rec.pod || st.pod) attrs.pod = (rec.pod || st.pod).toLowerCase();
      if (rec.container || st.container) attrs.container = rec.container || st.container;
      if (rec.traceId) attrs.traceId = String(rec.traceId);
      if (rec.status != null) attrs.status = rec.status;
      if (rec.latencyMs != null) attrs.latencyMs = rec.latencyMs;
      if (rec.target) attrs.targetHost = rec.target;
      if (rec.carried) attrs.tsCarried = true;
      if (rec.host) attrs.host = rec.host;
      if (kind === 'rollout') rolloutAttrs(rec.msg, attrs, ent);
      var text = rec.msg;
      if (rec.err && text.indexOf(rec.err) < 0) text += ': ' + rec.err;
      if (rec.status != null && text.indexOf(String(rec.status)) < 0) text += ' (HTTP ' + rec.status + ')';
      addSignal(lineNo, raw, { kind: kind || 'error_generic', level: level, text: text, ts: rec.ts, tsInferred: rec.tsInferred, entity: ent, attrs: attrs });
    }

    // stern: "<pod> <container> <rest>" (or "<ns> <pod> <container> <rest>" with -A)
    function sternSplit(s) {
      var m = /^([a-z0-9][a-z0-9.-]*)\s+([a-z0-9][a-z0-9-]*)\s+(.*)$/.exec(s);
      if (!m) return null;
      if (m[1] === '+' || m[1] === '-') return null;
      if (looksPod(m[1], m[2])) return { pod: m[1], container: m[2], rest: m[3] };
      var m2 = /^([a-z0-9][a-z0-9-]*)\s+([a-z0-9][a-z0-9.-]*)\s+([a-z0-9][a-z0-9-]*)\s+(.*)$/.exec(s);
      if (m2 && looksPod(m2[2], m2[3])) return { ns: m2[1], pod: m2[2], container: m2[3], rest: m2[4] };
      return null;
    }
    function looksPod(pod, container) {
      var sp = E.stripPod(pod);
      if (sp.controller === 'Deployment') return true;
      // DaemonSet/StatefulSet suffixes are short enough to collide with prose ("step-2 done"), so
      // also require the container name to relate to the workload, as it does in practice.
      if (sp.controller && sp.workload && (sp.workload.indexOf(container) >= 0 || container.indexOf(sp.workload) >= 0)) return true;
      return false;
    }

    // ---- finish: settle relative and unknown times ------------------------------------------------
    var refNow = ctxNow != null ? ctxNow : extras.maxTs;
    if (extras.relativeCount > 0) {
      if (refNow != null) T.rebase(result.signals, refNow);
      else WR.addWarning(stats, 'Relative ages (like "3m12s") need a reference time: paste lines with timestamps or set the current time. They are placed at "now" once the analysis knows it.');
    }
    unknownTs.forEach(function (s) {
      if (st.firstTs != null) { s.ts = st.firstTs; s.tsInferred = true; s.attrs.tsCarried = true; }
      else {
        // No stamp anywhere in this pane: treat as "seen now" and say so.
        s.attrs.relative = true; s.attrs.ageMs = 0; s.attrs.tsUnknown = true;
        extras.relativeCount++;
        if (refNow != null) s.ts = refNow;
      }
    });

    extras.dependencyHints.forEach(function (d) {
      depSignals[d.from + '->' + d.to].forEach(function (sg) {
        if (sg.ts == null) return;
        if (d.firstTs == null || sg.ts < d.firstTs) d.firstTs = sg.ts;
        if (d.lastTs == null || sg.ts > d.lastTs) d.lastTs = sg.ts;
      });
    });

    if (stats.tzAssumed) {
      WR.addWarning(stats, stats.tzAssumed + ' log time' + (stats.tzAssumed === 1 ? '' : 's') + ' had no time zone; assumed ' + (T.fmtOffset(T.offsetMinutes(tzOpts.defaultTz)) || 'Z') + '.');
    }
    if (yearAssumed) WR.addWarning(stats, 'klog/syslog times have no year; assumed ' + T.inferYear(tzOpts) + '.');
    if (stats.skipped) WR.addWarning(stats, stats.skipped + ' line' + (stats.skipped === 1 ? ' was' : 's were') + ' not recognised and skipped.');
    if (!stats.parsed && stats.lines) WR.addWarning(stats, 'No recognisable Kubernetes or application log lines found.');

    var fmts = Object.keys(extras.formats).sort(function (a, b) { return extras.formats[b] - extras.formats[a]; });
    stats.format = fmts.length ? fmts.slice(0, 3).join(' + ') + (fmts.length > 3 ? ' + ' + (fmts.length - 3) + ' more' : '') : (stats.lines ? 'unrecognised' : 'empty');
    result.entities = ents.list();
  }

  WR.parseLogs = parseLogs;
  // Shared with the trace/alert parsers so a span status message or alert annotation that says
  // "connection refused" is classified by exactly the same rules as a log line.
  WR.classifyText = classify;
  WR.normLevel = normLevel;
})(globalThis.WR = globalThis.WR || {});
