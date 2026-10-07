/*
 * entities.js — WR.entities: turning the names that appear in pasted evidence into stable
 * component ids, so a pod in a log line, a Deployment in a Helm diff, a service.name in a trace
 * and a label in an alert all land on ONE node of the blast-radius map.
 *
 * Component id: `${type}:${cluster}/${namespace}/${name}`, type ∈ service | datastore | external |
 * node | infra. Cluster-scoped things (nodes) use an empty namespace: `node:prod-eu-west//ip-10-0-1-5`.
 *
 * Parsers emit EntityHints (one per thing they saw). WR.entities.reconcile() then collapses hints
 * whose namespace or cluster was not stated onto the one known match, and returns an alias map the
 * orchestrator applies to signals, edges and changes with WR.entities.remap().
 *
 * EntityHint = { id, type, name, cluster, namespace, nsKnown, clusterKnown, role, userFacing,
 *                pods: string[], release, controller, sources: string[], releaseGuess }
 * releaseGuess = the name is only a Helm release name standing in for a workload we never saw.
 */
(function (WR) {
  'use strict';

  var DEFAULT_CLUSTER = 'cluster-1';

  // Kubernetes generates pod and ReplicaSet suffixes from this alphabet (no vowels, no 0/1/3), so a
  // suffix made only of these letters, or containing a digit, is very likely generated. That check
  // keeps real names such as "redis-cache" or "orders-database" from being mistaken for pods.
  var SAFE_ALPHABET = /^[bcdfghjklmnpqrstvwxz2456789]+$/;
  function looksGenerated(s) { return SAFE_ALPHABET.test(s) || /\d/.test(s); }

  var RE_DEPLOY_POD = /^(.+)-([a-z0-9]{8,10})-([a-z0-9]{5})$/;
  var RE_DS_POD = /^(.+)-([a-z0-9]{5})$/;
  var RE_STS_POD = /^(.+)-(\d{1,4})$/;
  var RE_RS = /^(.+)-([a-z0-9]{8,10})$/;

  function norm(s) {
    if (s == null) return '';
    return String(s).trim().replace(/^["']|["']$/g, '').toLowerCase();
  }

  /*
   * Pod → workload (SPEC §3.1), tried in this order:
   *   `-<rs-hash 8-10>-<5>`  Deployment   (the hash must look generated; the 5-char tail may be anything,
   *                                        because hand-written fixtures often use "abcde")
   *   `-<5>`                 DaemonSet / Job pod (the 5 chars must look generated)
   *   `-<ordinal>`           StatefulSet
   * Returns { workload, controller, replicaSet }.
   */
  function stripPod(pod) {
    var p = norm(pod);
    if (!p) return { workload: '', controller: null, replicaSet: null };
    var m = RE_DEPLOY_POD.exec(p);
    if (m && looksGenerated(m[2])) {
      return { workload: m[1], controller: 'Deployment', replicaSet: m[1] + '-' + m[2] };
    }
    m = RE_DS_POD.exec(p);
    if (m && looksGenerated(m[2])) return { workload: m[1], controller: 'DaemonSet', replicaSet: null };
    m = RE_STS_POD.exec(p);
    if (m) return { workload: m[1], controller: 'StatefulSet', replicaSet: null };
    return { workload: p, controller: null, replicaSet: null };
  }

  // True when the name has a generated pod suffix (used to decide whether a token is a pod name).
  function isPodName(s) {
    var r = stripPod(s);
    return r.controller != null && r.workload !== norm(s);
  }

  // ReplicaSet "payments-api-7d9f8b6c5" → Deployment "payments-api".
  function stripReplicaSet(rs) {
    var p = norm(rs);
    var m = RE_RS.exec(p);
    if (m && looksGenerated(m[2])) return m[1];
    return p;
  }

  var RE_COREDNS = /^(coredns|kube-dns|core-dns)$/;
  var RE_INFRA = /^(kube-proxy|cilium|cilium-operator|calico-node|calico-kube-controllers|flannel|kube-flannel|aws-node|metrics-server|cluster-autoscaler|karpenter|kube-apiserver|kube-scheduler|kube-controller-manager|konnectivity-agent|node-local-dns|nodelocaldns)$/;
  var RE_DATASTORE = /(^|[-_.])(postgres|postgresql|pg|mysql|mariadb|redis|valkey|mongo|mongodb|cassandra|scylla|kafka|rabbitmq|elasticsearch|opensearch|etcd|memcache|memcached|clickhouse|cockroach|cockroachdb|zookeeper|nats|minio|dynamodb|cosmosdb|spanner|aurora|rds|db)(?=$|[-_.\d])/;
  var RE_INGRESS = /(ingress|gateway|(^|-)gw($|-)|envoy|traefik|(^|-)kong($|-)|haproxy|contour|edge-proxy|api-gw)/;

  /*
   * Decide the component type (and ingress role) from a workload name. Name heuristics are the
   * only signal every source shares, which is what makes the collapse rule in §3.6 work.
   */
  function classifyName(name, namespace) {
    var n = norm(name);
    if (RE_COREDNS.test(n)) return { type: 'infra', role: null, name: 'coredns', namespace: 'kube-system' };
    if (namespace === 'kube-system' && (RE_INFRA.test(n) || n === 'etcd')) return { type: 'infra', role: null, name: n, namespace: namespace };
    if (RE_INFRA.test(n)) return { type: 'infra', role: null, name: n, namespace: namespace };
    if (RE_INGRESS.test(n)) return { type: 'service', role: 'ingress', name: n, namespace: namespace };
    if (RE_DATASTORE.test(n) && !/migrat|exporter|operator|proxy|bouncer|backup|client/.test(n)) {
      return { type: 'datastore', role: null, name: n, namespace: namespace };
    }
    return { type: 'service', role: null, name: n, namespace: namespace };
  }

  function componentId(type, cluster, namespace, name) {
    var t = type || 'service';
    var c = cluster || DEFAULT_CLUSTER;
    if (t === 'infra' && RE_COREDNS.test(norm(name))) return 'infra:' + c + '/kube-system/coredns';
    var ns = t === 'node' ? '' : (namespace == null ? 'default' : namespace);
    return t + ':' + c + '/' + ns + '/' + norm(name);
  }

  function parseId(id) {
    var m = /^([a-z]+):([^/]*)\/([^/]*)\/(.*)$/.exec(String(id || ''));
    if (!m) return null;
    return { type: m[1], cluster: m[2], namespace: m[3], name: m[4] };
  }

  /*
   * In-cluster DNS names carry the namespace: "payments-api.shop.svc.cluster.local" →
   * { name:'payments-api', namespace:'shop' }. Bare names stay names; dotted names that are not
   * cluster DNS are treated as external hosts; IP addresses are not components.
   */
  function fromHost(host) {
    var h = norm(host).replace(/^[a-z][a-z0-9+.-]*:\/\//, '').replace(/[:/].*$/, '');
    if (!h) return null;
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.indexOf(':') >= 0) return null;
    var m = /^([a-z0-9][a-z0-9-]*)\.([a-z0-9][a-z0-9-]*)\.svc(\.[a-z0-9.-]+)?$/.exec(h);
    if (m) return { name: m[1], namespace: m[2], external: false };
    if (h === 'localhost') return null;
    if (h.indexOf('.') === -1) return { name: h, namespace: null, external: false };
    return { name: h, namespace: null, external: true };
  }

  /*
   * Build one EntityHint. Accepts { name | pod | node, namespace, cluster, clusterKnown, type,
   * role, userFacing, release, source, defaultCluster }.
   */
  function hint(o) {
    o = o || {};
    var cluster = o.cluster || o.defaultCluster || DEFAULT_CLUSTER;
    var clusterKnown = o.clusterKnown != null ? !!o.clusterKnown : !!o.cluster;
    var pod = o.pod ? norm(o.pod) : null;
    var controller = null;
    var name = o.name ? norm(o.name) : '';
    if (!name && pod) {
      var s = stripPod(pod);
      name = s.workload;
      controller = s.controller;
    }
    if (o.node && !name) name = norm(o.node);
    if (!name) return null;
    var nsGiven = o.namespace != null && o.namespace !== '' ? norm(o.namespace) : null;
    var type = o.type || null;
    var role = o.role || null;
    var namespace = nsGiven;
    if (o.node || type === 'node') {
      type = 'node';
      namespace = '';
    } else {
      var cls = classifyName(name, nsGiven);
      if (!type || (type === 'service' && cls.type === 'infra')) type = cls.type;
      else if (type === 'service' && cls.type === 'datastore' && !o.forceType) type = 'datastore';
      if (cls.type === 'infra' && cls.name === 'coredns') { name = 'coredns'; namespace = 'kube-system'; type = 'infra'; }
      if (!role && cls.role) role = cls.role;
    }
    var nsKnown = type === 'node' ? true : (namespace != null);
    if (namespace == null) namespace = 'default';
    return {
      id: componentId(type, cluster, namespace, name),
      type: type,
      name: name,
      cluster: cluster,
      namespace: namespace,
      nsKnown: nsKnown,
      clusterKnown: clusterKnown,
      role: role,
      userFacing: !!o.userFacing,
      pods: pod ? [pod] : [],
      release: o.release || null,
      controller: controller || o.controller || null,
      sources: o.source ? [o.source] : []
    };
  }

  /*
   * A small accumulator parsers use so one pod mentioned on 400 lines becomes one hint.
   */
  function collector() {
    var byId = Object.create(null);
    var order = [];
    return {
      add: function (h) {
        if (!h) return null;
        var cur = byId[h.id];
        if (!cur) {
          cur = byId[h.id] = {
            id: h.id, type: h.type, name: h.name, cluster: h.cluster, namespace: h.namespace,
            nsKnown: h.nsKnown, clusterKnown: h.clusterKnown, role: h.role || null, userFacing: !!h.userFacing,
            pods: [], release: h.release || null, controller: h.controller || null, sources: [],
            releaseGuess: !!h.releaseGuess
          };
          order.push(h.id);
        }
        mergeInto(cur, h);
        return cur;
      },
      get: function (id) { return byId[id] || null; },
      list: function () { return order.map(function (id) { return byId[id]; }); }
    };
  }

  function mergeInto(cur, h) {
    if (!h) return;
    cur.nsKnown = cur.nsKnown || !!h.nsKnown;
    cur.clusterKnown = cur.clusterKnown || !!h.clusterKnown;
    cur.userFacing = cur.userFacing || !!h.userFacing;
    // One real sighting of the name means it is not just a guess from a Helm release name.
    if (!h.releaseGuess) cur.releaseGuess = false;
    if (!cur.role && h.role) cur.role = h.role;
    if (!cur.release && h.release) cur.release = h.release;
    if (!cur.controller && h.controller) cur.controller = h.controller;
    var i;
    if (h.pods) for (i = 0; i < h.pods.length && cur.pods.length < 50; i++) {
      if (cur.pods.indexOf(h.pods[i]) === -1) cur.pods.push(h.pods[i]);
    }
    if (h.sources) for (i = 0; i < h.sources.length; i++) {
      if (cur.sources.indexOf(h.sources[i]) === -1) cur.sources.push(h.sources[i]);
    }
  }

  /*
   * Collapse rule (SPEC §3.6): a hint whose namespace (or cluster) was never stated matches a
   * known one when that name is unique in the cluster. "external" peers collapse onto a real
   * service/datastore of the same name. Returns { entities, alias } where alias maps raw id →
   * canonical id (only ids that moved are listed).
   */
  function reconcile(hints) {
    var col = collector();
    (hints || []).forEach(function (h) { col.add(h); });
    var all = col.list();
    var byName = Object.create(null);
    all.forEach(function (e) { (byName[e.name] || (byName[e.name] = [])).push(e); });
    var alias = Object.create(null);
    var TYPE_PREF = { service: 0, datastore: 1, infra: 2 };

    function score(e) { return (e.nsKnown ? 1 : 0) + (e.clusterKnown ? 1 : 0) + (e.type === 'external' ? 0 : 1); }
    // Best-known hints resolve first, so a half-known hint is already folded into its full match
    // before the vaguest hints look for candidates (otherwise they would see two "places").
    var order = all.slice().sort(function (a, b) { return score(b) - score(a); });

    order.forEach(function (e) {
      if (e.type === 'node') return;
      if (e.nsKnown && e.clusterKnown && e.type !== 'external') return;
      var cands = (byName[e.name] || []).filter(function (c) {
        if (c === e || alias[c.id] || c.type === 'node' || c.type === 'external') return false;
        if (e.clusterKnown ? c.cluster !== e.cluster : (!c.clusterKnown && c.cluster !== e.cluster)) return false;
        if (e.nsKnown ? c.namespace !== e.namespace : (!c.nsKnown && c.namespace !== e.namespace)) return false;
        // The candidate has to add something we lack; otherwise it is just as vague as we are.
        return (!e.nsKnown && c.nsKnown) || (!e.clusterKnown && c.clusterKnown) || e.type === 'external';
      });
      if (!cands.length) return;
      // "Unique in that cluster": every candidate must sit in one cluster + namespace.
      var places = WR.uniq(cands.map(function (c) { return c.cluster + '/' + c.namespace; }));
      if (places.length !== 1) return;
      cands.sort(function (a, b) {
        var sa = a.type === e.type ? -1 : TYPE_PREF[a.type];
        var sb = b.type === e.type ? -1 : TYPE_PREF[b.type];
        return sa - sb;
      });
      alias[e.id] = cands[0].id;
    });

    // A Helm release name used as a stand-in ("payments" when only `helm history payments` was
    // pasted) folds onto the one real workload named after it ("payments-api").
    all.forEach(function (e) {
      if (!e.releaseGuess || alias[e.id]) return;
      var cands = all.filter(function (c) {
        if (c === e || c.releaseGuess || alias[c.id] || c.type === 'node' || c.type === 'external') return false;
        if (c.name !== e.name && c.name.indexOf(e.name + '-') !== 0) return false;
        if (e.clusterKnown && c.cluster !== e.cluster) return false;
        if (e.nsKnown && c.nsKnown && c.namespace !== e.namespace) return false;
        return true;
      });
      var ids = WR.uniq(cands.map(function (c) { return c.id; }));
      if (ids.length === 1) alias[e.id] = ids[0];
    });

    // Resolve chains (a → b → c) so every alias points at a final id.
    Object.keys(alias).forEach(function (k) {
      var seen = {}, t = alias[k];
      while (alias[t] && !seen[t]) { seen[t] = true; t = alias[t]; }
      alias[k] = t;
    });

    var finalCol = collector();
    all.forEach(function (e) { if (!alias[e.id]) finalCol.add(e); });
    all.forEach(function (e) {
      if (!alias[e.id]) return;
      var target = finalCol.get(alias[e.id]);
      if (target) {
        var role = target.role;
        mergeInto(target, e);
        // An "external" peer never turns a known service into something else.
        target.role = role || (e.type !== 'external' ? e.role : null) || null;
      }
    });
    return { entities: finalCol.list(), alias: alias };
  }

  function canon(alias, id) {
    return id != null && alias && alias[id] ? alias[id] : id;
  }

  // Rewrite id fields in place (signals: componentId, attrs.targetId; edges: from/to; changes: componentId).
  function remap(items, alias, fields) {
    if (!items || !alias) return items;
    var fs = fields || ['componentId', 'from', 'to'];
    for (var i = 0; i < items.length; i++) {
      var it = items[i];
      if (!it) continue;
      for (var j = 0; j < fs.length; j++) {
        var f = fs[j];
        if (it[f] != null && alias[it[f]]) it[f] = alias[it[f]];
      }
      if (it.attrs && it.attrs.targetId && alias[it.attrs.targetId]) it.attrs.targetId = alias[it.attrs.targetId];
    }
    return items;
  }

  /*
   * After remapping, two edges can become the same from→to pair; combine them. p95 takes the
   * larger value (a conservative upper bound — the raw durations are no longer available).
   */
  function mergeEdges(edges) {
    var byKey = Object.create(null), out = [];
    (edges || []).forEach(function (e) {
      if (!e || e.from === e.to) return;
      var k = e.from + '->' + e.to;
      var cur = byKey[k];
      if (!cur) {
        cur = byKey[k] = { id: k, from: e.from, to: e.to, calls: 0, errors: 0, p95ms: null, firstErrorTs: null };
        out.push(cur);
      }
      cur.calls += e.calls || 0;
      cur.errors += e.errors || 0;
      if (e.p95ms != null) cur.p95ms = cur.p95ms == null ? e.p95ms : Math.max(cur.p95ms, e.p95ms);
      if (e.firstErrorTs != null) cur.firstErrorTs = cur.firstErrorTs == null ? e.firstErrorTs : Math.min(cur.firstErrorTs, e.firstErrorTs);
    });
    return out;
  }

  /*
   * Cluster markers (SPEC §2). Returns the cluster name or null. Recognised:
   *   # cluster: prod-eu-west      --- cluster=prod-eu-west ---      [context: prod-eu-west]
   *   kubectl --context prod-eu-west ...   kubectl config use-context prod-eu-west
   *   helm ... --kube-context prod-eu-west
   */
  var RE_MARK_HASH = /^\s*#\s*(?:cluster|context|kube-context)\s*[:=]\s*([A-Za-z0-9][\w.:@\/-]*)/i;
  var RE_MARK_DASH = /^\s*-{2,}\s*(?:cluster|context)\s*[=:]\s*([A-Za-z0-9][\w.:@\/-]*)\s*-{2,}\s*$/i;
  var RE_MARK_BRACKET = /^\s*\[\s*(?:context|cluster)\s*:\s*([A-Za-z0-9][\w.:@\/-]*)\s*\]\s*$/i;
  var RE_CMD = /^\s*(?:[$%>❯➜]\s*|PS [^>]*>\s*|\(\S+\)\s*[$%]\s*)?(kubectl|k|helm|stern|kubectx|oc)\s+(.*)$/;

  function cleanContext(c) {
    if (!c) return null;
    var s = String(c).trim().replace(/^["']|["']$/g, '');
    // EKS contexts are ARNs: arn:aws:eks:eu-west-1:123456789012:cluster/prod-eu-west
    var m = /cluster\/([\w.-]+)$/.exec(s);
    if (m) return m[1];
    return s || null;
  }

  function detectCluster(line) {
    if (!line) return null;
    var m = RE_MARK_HASH.exec(line) || RE_MARK_DASH.exec(line) || RE_MARK_BRACKET.exec(line);
    if (m) return cleanContext(m[1]);
    var cmd = parseCommand(line);
    if (cmd && cmd.context) return cmd.context;
    return null;
  }

  /*
   * Parse a pasted command echo ("$ kubectl logs payments-api-... -n shop --context prod-eu-west").
   * Returns { tool, verb, sub, positional[], context, namespace, allNamespaces, container,
   *           pod, workload, release } or null when the line is not a command.
   */
  /*
   * Only the first command of a pipeline describes the output that follows: in
   * "kubectl -n shop logs x | tail -n 3" the "-n 3" belongs to tail, and in
   * "kubectl exec pg-0 -- psql -c '...'" the "-c" belongs to psql. Cut at the first unquoted
   * |, ;, &, > or a bare "--" so those flags never reach the kubectl/helm reader.
   */
  function firstCommand(s) {
    var q = null;
    for (var i = 0; i < s.length; i++) {
      var c = s[i];
      if (q) { if (c === q) q = null; continue; }
      if (c === '"' || c === "'") { q = c; continue; }
      if (c === '|' || c === ';' || c === '&' || c === '>') return s.slice(0, i);
      if (c === '-' && s[i + 1] === '-' && (i === 0 || /\s/.test(s[i - 1])) && (i + 2 === s.length || /\s/.test(s[i + 2]))) return s.slice(0, i);
    }
    return s;
  }

  var DESCRIBE_WORKLOAD = /^(deploy|deployment|deployments|sts|statefulset|statefulsets|ds|daemonset|daemonsets|hpa|horizontalpodautoscaler|horizontalpodautoscalers|rollout|rollouts)$/i;

  function parseCommand(line) {
    if (!line) return null;
    var m = RE_CMD.exec(line);
    if (!m) return null;
    var tool = m[1] === 'k' ? 'kubectl' : m[1];
    var toks = firstCommand(m[2]).match(/"[^"]*"|'[^']*'|\S+/g) || [];
    var out = { tool: tool, verb: null, sub: null, positional: [], context: null, namespace: null, allNamespaces: false, container: null, pod: null, workload: null, release: null };
    for (var i = 0; i < toks.length; i++) {
      var t = toks[i];
      var eq = t.indexOf('=');
      var flag = t[0] === '-' ? (eq > 0 ? t.slice(0, eq) : t) : null;
      var val = function () { return eq > 0 ? t.slice(eq + 1) : toks[++i]; };
      if (flag) {
        if (flag === '--context' || flag === '--kube-context') out.context = cleanContext(val());
        else if (flag === '-n' || flag === '--namespace') out.namespace = norm(val());
        else if (flag === '-A' || flag === '--all-namespaces') out.allNamespaces = true;
        else if (flag === '-c' || flag === '--container') out.container = norm(val());
        else if (/^-(o|l|f|w|-output|-selector|-since|-tail|-sort-by|-field-selector|-max|-timeout|-revision|-values|-set|-version|-template|-kubeconfig|-max-log-requests)$/.test(flag) && eq < 0) {
          // flags that take a value we do not need; skip the value too (except boolean -f/-w/-p)
          if (flag !== '-f' && flag !== '-w') i++;
        }
        continue;
      }
      if (tool === 'kubectl' && t === 'config' && toks[i + 1] === 'use-context') { out.context = cleanContext(toks[i + 2]); out.verb = 'config'; i += 2; continue; }
      if (tool === 'kubectx' && !out.context) { out.context = cleanContext(t); continue; }
      out.positional.push(t.replace(/^["']|["']$/g, ''));
    }
    var p = out.positional;
    out.verb = out.verb || p[0] || null;
    if (tool === 'kubectl' || tool === 'oc') {
      if (out.verb === 'logs' && p[1]) {
        var target = p[1];
        var slash = target.indexOf('/');
        if (slash > 0) {
          var kind = target.slice(0, slash).toLowerCase();
          var nm = target.slice(slash + 1);
          if (kind === 'pod' || kind === 'pods' || kind === 'po') out.pod = norm(nm);
          else out.workload = norm(nm);
        } else out.pod = norm(target);
        if (p[2] && !out.container) out.container = norm(p[2]);
      } else if (out.verb === 'describe' && p[1]) {
        if (/^(pod|pods|po)$/i.test(p[1]) && p[2]) out.pod = norm(p[2]);
        else if (/^(pod|pods|po)\//i.test(p[1])) out.pod = norm(p[1].split('/')[1]);
        // "describe hpa orders-api" / "describe deploy/orders-api": the output that follows is
        // about that workload (an HPA is named after its target in practice).
        else if (DESCRIBE_WORKLOAD.test(p[1]) && p[2]) out.workload = norm(p[2]);
        else if (p[1].indexOf('/') > 0 && DESCRIBE_WORKLOAD.test(p[1].split('/')[0])) out.workload = norm(p[1].split('/')[1]);
        out.sub = p[1];
      } else if (out.verb === 'exec' && p[1]) {
        // Output of "kubectl exec orders-postgresql-0 -- psql ..." describes that pod.
        var et = p[1].indexOf('/') > 0 ? p[1].split('/') : ['pod', p[1]];
        if (/^(pod|pods|po)$/i.test(et[0])) out.pod = norm(et[1]);
        else out.workload = norm(et[1]);
      } else out.sub = p[1] || null;
    } else if (tool === 'helm') {
      out.sub = p[1] || null;
      if (/^(history|hist|status|get|rollback|upgrade|install|uninstall)$/.test(out.verb) && p[1]) out.release = p[1];
      if (out.verb === 'diff') {
        out.sub = p[1] || null;
        if ((p[1] === 'upgrade' || p[1] === 'release' || p[1] === 'revision' || p[1] === 'rollback') && p[2]) out.release = p[2];
      }
      if (out.verb === 'get' && p[2]) out.release = p[2];
    } else if (tool === 'stern') {
      if (p[0]) out.workload = norm(p[0]);
    }
    return out;
  }

  WR.entities = {
    DEFAULT_CLUSTER: DEFAULT_CLUSTER,
    stripPod: stripPod,
    stripReplicaSet: stripReplicaSet,
    isPodName: isPodName,
    classifyName: classifyName,
    componentId: componentId,
    parseId: parseId,
    fromHost: fromHost,
    hint: hint,
    collector: collector,
    reconcile: reconcile,
    canon: canon,
    remap: remap,
    mergeEdges: mergeEdges,
    detectCluster: detectCluster,
    parseCommand: parseCommand,
    norm: norm
  };
})(globalThis.WR = globalThis.WR || {});
