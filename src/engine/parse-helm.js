/*
 * parse-helm.js — WR.parseHelm(text, ctx) → { signals, entities, stats, extras: { changes, deploy, deploys, ... } }
 *
 * Recognises and combines (SPEC §3.4):
 *   - `helm diff upgrade` blocks: "<ns>, <name>, <Kind> (<group>) has changed: | has been added: | has been removed:"
 *     followed by the manifest with -/+ markers
 *   - unified diffs (diff --git / --- / +++ / @@) of values.yaml or rendered manifests
 *   - `helm history <release>` tables (UPDATED is zone-less local time → ctx.defaultTz, tsInferred)
 *   - `helm list` tables (UPDATED carries its zone)
 *
 * The diff reader tracks the YAML path by indentation, so a "-/+ memory:" pair three levels under a
 * container becomes field "spec.template.spec.containers[payments-api].resources.limits.memory",
 * category 'resources', before "512Mi", after "256Mi", risk high (a limit went down).
 *
 * Secrets: values under a Secret's data/stringData, env vars with secret-looking names and any
 * value WR.redact flags are stored as "(redacted)" — never echoed into changes or signals.
 */
(function (WR) {
  'use strict';

  var T = WR.time;
  var E = WR.entities;
  var REDACTED = '(redacted)';

  // helm-diff (diff/report.go) headers: "<ns>, <name>, <Kind> (<group>) has changed:" and its
  // "has been added:", "has been removed:", "changed ownership:" and "has changed, but diff is empty
  // after suppression." variants; `--output simple` prints "... to be changed." etc. instead.
  var RE_DIFF_HEADER = /^\s*([\w.-]*),\s*([\w.:@-]+),\s*([A-Za-z]+)(?:\s*\(([^)]*)\))?\s+(?:has\s+(changed|been added|been removed):|(changed ownership):|has changed, but diff is empty after suppression\.?)\s*$/;
  var RE_DIFF_SIMPLE = /^\s*([\w.-]*),\s*([\w.:@-]+),\s*([A-Za-z]+)(?:\s*\(([^)]*)\))?\s+(to be added|to be removed|to be changed|to change ownership)\.?\s*$/;
  var RE_DIFF_PLAN = /^\s*Plan:\s+\d+ to add, \d+ to change, \d+ to destroy/;
  var RE_H_HISTORY = /^\s*REVISION\s+UPDATED\s+STATUS\s+CHART\s+APP VERSION\s+DESCRIPTION\b/;
  var RE_H_LIST = /^\s*NAME\s+NAMESPACE\s+REVISION\s+UPDATED\s+STATUS\s+CHART\s+APP VERSION\b/;
  var RE_RELEASE_MARK = /^\s*#\s*release\s*[:=]\s*([\w.-]+)/i;
  var RE_SIBLING_NOTE = /^\s*#\s*([a-z0-9][a-z0-9.-]*-[a-z0-9.-]+)\s*:\s*(.+)$/i;
  var RE_HISTORY_ROW = /^\s*(\d+)\s+((?:[A-Z][a-z]{2}\s+)?[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\s+[A-Z]{2,5})?\s+\d{4}|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\S*(?:\s+[+-]\d{4})?(?:\s+[A-Z]{2,5})?)\s+(\S+)\s+(\S+)\s+(\S+)?\s+(.*)$/;
  var RE_LIST_ROW = /^\s*(\S+)\s+(\S+)\s+(\d+)\s+(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:\s*(?:Z|[+-]\d{2}:?\d{2}))?(?:\s+[A-Z]{2,5})?)\s+(\S+)\s+(\S+)\s*(\S*)\s*$/;
  var WORKLOAD_KINDS = { Deployment: 1, StatefulSet: 1, DaemonSet: 1, Rollout: 1, CronJob: 1 };
  var RBAC_KINDS = { Role: 1, ClusterRole: 1, RoleBinding: 1, ClusterRoleBinding: 1, ServiceAccount: 1 };
  var CANARY_KINDS = { Rollout: 1, Canary: 1, AnalysisTemplate: 1 };
  var MAX_CHANGES_PER_RESOURCE = 40;

  // ------------------------------------------------------------------------------------------
  // Small value helpers
  // ------------------------------------------------------------------------------------------
  function unquote(v) {
    if (v == null) return v;
    var s = String(v).trim();
    if (s.length >= 2 && ((s[0] === '"' && s[s.length - 1] === '"') || (s[0] === "'" && s[s.length - 1] === "'"))) return s.slice(1, -1);
    // trailing YAML comment on an unquoted scalar
    return s.replace(/\s+#.*$/, '');
  }

  // Kubernetes quantities → a comparable number ("512Mi" → bytes, "500m" → 0.5 cores).
  var QSUFFIX = { Ki: 1024, Mi: 1048576, Gi: 1073741824, Ti: 1099511627776, k: 1e3, K: 1e3, M: 1e6, G: 1e9, T: 1e12, m: 0.001, '': 1 };
  function quantity(v) {
    var m = /^\s*"?(\d+(?:\.\d+)?)\s*(Ki|Mi|Gi|Ti|k|K|M|G|T|m)?"?\s*$/.exec(String(v == null ? '' : v));
    if (!m) return null;
    return Number(m[1]) * QSUFFIX[m[2] || ''];
  }
  function numeric(v) {
    var n = Number(String(v == null ? '' : v).replace(/^"|"$/g, ''));
    return isFinite(n) && String(v).trim() !== '' ? n : null;
  }

  function keyValue(content) {
    var m = /^("(?:[^"\\]|\\.)*"|'[^']*'|[^\s#'"\[{][^:]*?)\s*:(?:[ \t]+(.*)|$)/.exec(content);
    if (!m) return null;
    return { key: unquote(m[1]), value: m[2] == null ? '' : m[2].trim() };
  }

  function pathOf(stack) {
    var s = '';
    for (var i = 0; i < stack.length; i++) s += stack[i].isItem ? stack[i].seg : (s ? '.' : '') + stack[i].seg;
    return s;
  }

  /*
   * Walk YAML lines (each with a diff marker) and emit one record per meaningful line, carrying the
   * path at that point. Removed and added lines share one stack: helm diff interleaves them at the
   * same positions, so the indentation context is the same for both sides.
   * entries: [{ marker: ' '|'+'|'-', text, line }]
   */
  function walkYaml(entries) {
    var stack = [];
    var recs = [];
    var afterGap = false;
    for (var i = 0; i < entries.length; i++) {
      var e = entries[i];
      if (e.gap) { stack = []; afterGap = true; continue; }
      var t = e.text.replace(/\t/g, '  ').replace(/\s+$/, '');
      var content = t.trim();
      if (!content) continue;
      var indent = t.length - t.replace(/^ +/, '').length;
      if (content === '---' || content === '...') { stack = []; continue; }
      if (content[0] === '#') {
        var src = /^#\s*Source:\s*(\S+)/.exec(content);
        if (src) { recs.push({ marker: e.marker, path: '', source: src[1], line: e.line }); stack = []; }
        continue;
      }
      var top = stack[stack.length - 1];
      if (top && top.block && indent > top.indent) {
        recs.push({ marker: e.marker, path: pathOf(stack), key: top.seg, value: content, scalar: true, line: e.line, raw: e.raw });
        continue;
      }
      var isItem = /^-( |$)/.test(content);
      while (stack.length) {
        top = stack[stack.length - 1];
        if (top.indent < indent) break;
        // "containers:\n- name: x" — YAML allows list items at the same indent as their key.
        if (isItem && top.indent === indent && top.open && !top.isItem) break;
        stack.pop();
      }
      if (isItem) {
        var parent = stack[stack.length - 1] || null;
        var rest = content.replace(/^-\s*/, '');
        var nm = /^(?:name|containerName)\s*:\s*["']?([^"'\s#]+)["']?\s*$/.exec(rest);
        var id;
        if (nm) id = nm[1];
        else if (parent) {
          if (e.marker !== '+') parent.oldIdx = (parent.oldIdx == null ? -1 : parent.oldIdx) + 1;
          if (e.marker !== '-') parent.newIdx = (parent.newIdx == null ? -1 : parent.newIdx) + 1;
          id = e.marker === '+' ? parent.newIdx : parent.oldIdx;
        } else id = 0;
        // After a --context gap the "env:" key above an item is gone; an UPPER_SNAKE item name is
        // an environment variable in practice, so keep it recognisable as one.
        var seg = '[' + id + ']';
        if (!parent && afterGap && nm && /^[A-Z][A-Z0-9_]*$/.test(String(id))) seg = 'env[' + id + ']';
        stack.push({ indent: indent, seg: seg, isItem: true });
        var itemPath = pathOf(stack);
        recs.push({ marker: e.marker, path: itemPath, itemStart: true, value: rest, line: e.line, raw: e.raw });
        if (rest) {
          var ikv = keyValue(rest);
          if (ikv) {
            if (ikv.value === '') stack.push({ indent: indent + 2, seg: ikv.key, open: true });
            else if (/^[|>][-+]?\d*$/.test(ikv.value)) stack.push({ indent: indent + 2, seg: ikv.key, block: true });
            else recs.push({ marker: e.marker, path: itemPath + '.' + ikv.key, key: ikv.key, value: unquote(ikv.value), line: e.line, raw: e.raw, inItemHead: true });
          } else recs.push({ marker: e.marker, path: itemPath, value: unquote(rest), scalarItem: true, line: e.line, raw: e.raw });
        }
        continue;
      }
      var kv = keyValue(content);
      if (!kv) {
        recs.push({ marker: e.marker, path: pathOf(stack), value: content, loose: true, line: e.line, raw: e.raw });
        continue;
      }
      if (kv.value === '' || kv.value === '{}' || kv.value === '[]') {
        if (kv.value === '') {
          stack.push({ indent: indent, seg: kv.key, open: true });
          recs.push({ marker: e.marker, path: pathOf(stack), key: kv.key, opens: true, line: e.line, raw: e.raw });
          continue;
        }
      }
      if (/^[|>][-+]?\d*$/.test(kv.value)) {
        stack.push({ indent: indent, seg: kv.key, block: true });
        recs.push({ marker: e.marker, path: pathOf(stack), key: kv.key, opens: true, block: true, line: e.line, raw: e.raw });
        continue;
      }
      var base = pathOf(stack);
      recs.push({ marker: e.marker, path: base ? base + '.' + kv.key : kv.key, key: kv.key, value: unquote(kv.value), line: e.line, raw: e.raw });
    }
    return recs;
  }

  // Context facts a block carries regardless of what changed (name, hook annotation, selectors).
  function blockFacts(recs) {
    var f = { kind: null, name: null, hook: null, hookWeight: null, instance: null, chart: null, appLabel: null, scaleTarget: null, containers: [], images: {}, canary: false };
    for (var i = 0; i < recs.length; i++) {
      var r = recs[i];
      if (r.marker === '-' ) continue; // describe the new state; removed-only blocks are handled by the caller
      var p = r.path;
      if (p === 'kind') f.kind = r.value;
      else if (p === 'metadata.name') f.name = r.value;
      else if (/^metadata\.annotations\.helm\.sh\/hook$/.test(p)) f.hook = r.value;
      else if (/^metadata\.annotations\.helm\.sh\/hook-weight$/.test(p)) f.hookWeight = r.value;
      else if (/^metadata\.labels\.(app\.kubernetes\.io\/instance|release)$/.test(p)) f.instance = f.instance || r.value;
      else if (/^metadata\.labels\.helm\.sh\/chart$/.test(p) || /^metadata\.labels\.chart$/.test(p)) f.chart = f.chart || r.value;
      else if (/podSelector\.matchLabels\.(app|app\.kubernetes\.io\/name)$/.test(p)) f.appLabel = f.appLabel || r.value;
      else if (/^spec\.scaleTargetRef\.name$/.test(p)) f.scaleTarget = r.value;
      else if (/containers\[[^\]]+\]\.name$/.test(p) || (r.itemStart && /containers\[[^\]]+\]$/.test(p))) {
        var cn = /containers\[([^\]]+)\]/.exec(p);
        if (cn && f.containers.indexOf(cn[1]) < 0) f.containers.push(cn[1]);
      }
      if (/\.image$/.test(p) && r.value) f.images[p] = r.value;
    }
    // Removed-only blocks: fall back to the old side for identity facts.
    if (!f.kind || !f.name) {
      recs.forEach(function (r) {
        if (!f.kind && r.path === 'kind') f.kind = r.value;
        if (!f.name && r.path === 'metadata.name') f.name = r.value;
        if (!f.hook && /^metadata\.annotations\.helm\.sh\/hook$/.test(r.path)) f.hook = r.value;
      });
    }
    return f;
  }

  /*
   * Group changed records into before/after pairs.
   *  - a changed line that opens a subtree (list item or "key:" with children) swallows its
   *    same-marker children, so an added env var is ONE change, not one per field
   *  - block-scalar lines (ConfigMap data: |) at one path merge into one change
   *  - everything else pairs the n-th removal with the n-th addition at the same path
   */
  function pairChanges(recs) {
    var units = [];
    var open = [];
    for (var i = 0; i < recs.length; i++) {
      var r = recs[i];
      if (r.marker !== '+' && r.marker !== '-') continue;
      if (r.source != null) continue;
      var host = null;
      for (var k = open.length - 1; k >= 0; k--) {
        var o = open[k];
        if (o.marker === r.marker && r.path !== o.path && (r.path.indexOf(o.path + '.') === 0 || r.path.indexOf(o.path + '[') === 0)) { host = o; break; }
        if (o.marker === r.marker && r.path === o.path && (r.inItemHead || r.scalarItem)) { host = o; break; }
      }
      if (host) { host.children.push(r); continue; }
      if (r.itemStart || (r.opens && !r.block)) {
        var u = { path: r.path, marker: r.marker, rec: r, children: [], subtree: true };
        open.push(u);
        units.push(u);
        continue;
      }
      units.push({ path: r.path, marker: r.marker, rec: r, children: [], subtree: false, scalar: !!r.scalar });
    }
    var byPath = Object.create(null), order = [];
    units.forEach(function (u) {
      var g = byPath[u.path];
      if (!g) { g = byPath[u.path] = { path: u.path, dels: [], adds: [] }; order.push(g); }
      (u.marker === '-' ? g.dels : g.adds).push(u);
    });
    var pairs = [];
    order.forEach(function (g) {
      var scalarGroup = g.dels.concat(g.adds).every(function (u) { return u.scalar; });
      if (scalarGroup) {
        pairs.push({ path: g.path, before: g.dels.length ? g.dels : null, after: g.adds.length ? g.adds : null, scalar: true });
        return;
      }
      var n = Math.max(g.dels.length, g.adds.length);
      for (var j = 0; j < n; j++) {
        pairs.push({ path: g.path, before: g.dels[j] ? [g.dels[j]] : null, after: g.adds[j] ? [g.adds[j]] : null, scalar: false });
      }
    });
    return pairs;
  }

  // What a unit "is" as a value: the scalar, an env var's value, or a compact field list.
  function unitValue(units, scalar) {
    if (!units) return null;
    if (scalar) return units.map(function (u) { return u.rec.value; }).join('\n');
    var u = units[0];
    if (!u.subtree) return u.rec.value != null ? u.rec.value : '';
    var kids = u.children;
    var val = kids.filter(function (c) { return c.key === 'value'; })[0];
    if (val) return val.value;
    var parts = [];
    // "- name: v1" is already a child record (name: v1); only a bare scalar item ("- v1") is added.
    if (u.rec.itemStart && u.rec.value && !keyValue(u.rec.value)) parts.push(u.rec.value);
    kids.forEach(function (c) { if (c.key && c.value != null && c.value !== '' && parts.length < 8) parts.push(c.key + ': ' + c.value); });
    return parts.join(', ') || '(object)';
  }

  function lastSeg(path) {
    var m = /(?:\.|^)([^.\[\]]+)$/.exec(path);
    return m ? m[1] : path;
  }

  // ------------------------------------------------------------------------------------------
  // Classification of one change
  // ------------------------------------------------------------------------------------------
  function classifyChange(c, facts) {
    var p = c.field || '';
    var pl = p.toLowerCase();
    var kind = c.resourceKind || '';
    var removed = c.after == null, added = c.before == null;
    var leaf = lastSeg(p).toLowerCase();

    // Every chart bump rewrites helm.sh/chart and app.kubernetes.io/version labels on every
    // resource. Those label edits say nothing about the resource kind they sit on, so they must not
    // inherit "ConfigMap in kube-system = high" or "HPA = high" below (hook annotations excepted).
    if (/^(spec\.template\.|spec\.jobtemplate\.spec\.template\.)?metadata\.(labels|annotations)(\.|$)/.test(pl) && !/helm\.sh\/hook/.test(pl)) {
      if (/helm\.sh\/chart|app\.kubernetes\.io\/version|(^|\.)labels\.chart$/.test(pl)) return { category: 'chart', risk: 'low' };
      return { category: 'other', risk: 'low' };
    }

    if (kind === 'CustomResourceDefinition' || /(^|\.)crds?(\.|$)|installcrds/.test(pl)) return { category: 'crd', risk: 'high' };
    if (kind === 'NetworkPolicy' || /networkpolic/.test(pl)) return { category: 'networkpolicy', risk: 'high' };
    if (facts && facts.migrationHook) return { category: 'migration-hook', risk: 'high' };
    if (/migrat/.test(pl) && kind === 'values') return { category: 'migration-hook', risk: 'high' };
    if (kind === 'Secret' || /(^|\.)secrets?(\.|\[|$)/.test(pl) && kind === 'values') return { category: 'secret', risk: removed ? 'high' : 'medium' };
    if (kind === 'HorizontalPodAutoscaler' || /maxreplicas|minreplicas|autoscaling\./.test(pl)) {
      return { category: 'hpa', risk: /maxreplicas|minreplicas|metrics|target/.test(pl) || added || removed ? 'high' : 'medium' };
    }
    if (/(^|\.)(replicas|replicacount)$/.test(pl)) return { category: 'replicas', risk: 'high' };
    if (/(liveness|readiness|startup)probe/.test(pl)) {
      if (added && /probe$/.test(pl)) return { category: 'probe', risk: 'high' };
      var b = numeric(c.before), a = numeric(c.after);
      var tighter = false;
      if (b != null && a != null) {
        if (/timeoutseconds|failurethreshold|initialdelayseconds|periodseconds/.test(leaf)) tighter = a < b;
        if (/successthreshold/.test(leaf)) tighter = a > b;
      }
      return { category: 'probe', risk: tighter || added ? 'high' : 'medium', tightened: tighter };
    }
    if (/(^|\.)resources(\.|$)|(^|\.)(limits|requests)\.(memory|cpu|ephemeral-storage)$/.test(pl)) {
      var qb = quantity(c.before), qa = quantity(c.after);
      var isLimit = /limits/.test(pl);
      if (isLimit && qb != null && qa != null) return { category: 'resources', risk: qa < qb ? 'high' : 'low', direction: qa < qb ? 'down' : qa > qb ? 'up' : 'same' };
      if (isLimit && removed) return { category: 'resources', risk: 'medium' };
      return { category: 'resources', risk: 'medium', direction: qb != null && qa != null ? (qa < qb ? 'down' : 'up') : null };
    }
    if (/(^|\.)image$|\.image\.(tag|repository|digest)$|^image\.(tag|repository|digest)$|^image$|(^|\.)tag$/.test(pl)) return { category: 'image', risk: 'medium' };
    if (/\.env\[|^env\[|\.env$|(^|\.)envfrom|^env\.|(^|\.)extraenv/.test(pl)) return { category: 'env', risk: removed ? 'high' : 'medium' };
    if (kind === 'ConfigMap' || /(^|\.)(config|configmap|configuration)(\.|$)/.test(pl)) {
      // A cluster-wide ConfigMap (coredns, kube-proxy) changes every workload's behaviour.
      return { category: 'configmap', risk: removed || c.namespace === 'kube-system' ? 'high' : 'medium' };
    }
    if (kind === 'Ingress' || /(^|\.)ingress(\.|$)|gateway|httproute/.test(pl) || kind === 'HTTPRoute' || kind === 'Gateway') return { category: 'ingress', risk: 'medium' };
    if (kind === 'Service' || /^service\./.test(pl)) return { category: 'service', risk: /selector|targetport|port$/.test(pl) ? 'high' : 'medium' };
    if (RBAC_KINDS[kind] || /(^|\.)rbac(\.|$)|serviceaccount/.test(pl)) return { category: 'rbac', risk: 'medium' };
    if (/helm\.sh\/chart|app\.kubernetes\.io\/version|(^|\.)labels\.chart$|^version$|^appversion$/.test(pl)) return { category: 'chart', risk: 'low' };
    if (/\.labels\.|\.annotations\.|(^|\.)labels$|(^|\.)annotations$/.test(pl)) return { category: 'other', risk: 'low' };
    if (/containers\[/.test(pl) || kind === 'values') return { category: 'other', risk: 'medium' };
    return { category: 'other', risk: 'low' };
  }

  function containerOf(path) {
    var m = /containers\[([^\]]+)\]/.exec(path || '');
    return m ? m[1] : null;
  }

  function imageTag(img) {
    var s = String(img || '');
    var at = s.indexOf('@');
    if (at >= 0) return s.slice(at + 1);
    var colon = s.lastIndexOf(':');
    return colon > s.lastIndexOf('/') ? s.slice(colon + 1) : 'latest';
  }

  function summarize(c, cls) {
    var b = c.before, a = c.after;
    var arrow = function (x, y) { return WR.truncate(x, 60) + ' → ' + WR.truncate(y, 60); };
    var what = c.resourceKind && c.resourceKind !== 'values' ? c.resourceKind + ' ' + c.resourceName : (c.resourceName || 'values');
    var ctr = containerOf(c.field);
    var leaf = lastSeg(c.field || '');
    if (c.changeType === 'resource-added') return what + ' added' + (cls.category === 'migration-hook' && c.hook ? ' (Helm ' + c.hook + ' hook)' : '');
    if (c.changeType === 'resource-removed') return what + ' removed';
    if (!c.field && c.before === '(current)') return what + ' changes (no field detail in `helm diff --output simple`)';
    if (c.aggregate) return what + ': ' + c.aggregate + ' more changed fields, not listed one by one';
    switch (cls.category) {
      case 'resources': {
        var m = /(limits|requests)\.([\w-]+)$/.exec(c.field || '');
        var label = m ? m[2] + ' ' + (m[1] === 'limits' ? 'limit' : 'request') : leaf;
        return (ctr ? ctr + ' ' : '') + label + ' ' + (b == null ? 'set to ' + a : a == null ? b + ' removed' : arrow(b, a));
      }
      case 'image':
        // A values-file key (global.image.tag) names no workload: say which key changed.
        if (b != null && a != null && /(^|\.)tag$/.test(c.field || '')) return (ctr ? ctr + ' image tag ' : (!c.resourceKind || c.resourceKind === 'values') && String(c.field).split('.').length > 2 ? 'values ' + c.field + ' ' : 'image tag ') + arrow(b, a);
        if (b != null && a != null && /[:@]/.test(b + a)) return (ctr ? ctr + ' ' : '') + 'image tag ' + arrow(imageTag(b), imageTag(a));
        return (ctr ? ctr + ' ' : '') + 'image ' + (b == null ? 'set to ' + a : a == null ? 'removed' : arrow(b, a));
      case 'env': {
        var en = /env\[([^\]]+)\]/.exec(c.field || '');
        var name = en ? en[1] : leaf;
        if (b == null) return 'env ' + name + ' added' + (a != null && a !== '' ? ' (' + WR.truncate(a, 40) + ')' : '') + (ctr ? ' to ' + ctr : '');
        if (a == null) return 'env ' + name + ' removed' + (ctr ? ' from ' + ctr : '');
        return 'env ' + name + ': ' + arrow(b, a);
      }
      case 'replicas': return what + ' replicas ' + arrow(b, a);
      case 'hpa': return 'HorizontalPodAutoscaler ' + (c.resourceKind === 'values' ? '' : c.resourceName + ' ') + leaf + ' ' + (b == null ? 'set to ' + a : a == null ? 'removed' : arrow(b, a));
      case 'probe': {
        var pm = /(liveness|readiness|startup)Probe/i.exec(c.field || '');
        var pn = pm ? pm[1].toLowerCase() + ' probe' : 'probe';
        if (b == null && /probe$/i.test(c.field)) return (ctr ? ctr + ' ' : '') + pn + ' added';
        return (ctr ? ctr + ' ' : '') + pn + ' ' + leaf + ' ' + (b == null ? 'set to ' + a : a == null ? 'removed' : arrow(b, a)) + (cls.tightened ? ' (tighter)' : '');
      }
      case 'secret': return what + ' ' + leaf + (b == null ? ' added' : a == null ? ' removed' : ' changed') + ' (value redacted)';
      case 'configmap': return what + ' ' + leaf + ': ' + (b == null ? 'added' : a == null ? 'removed' : arrow(String(b).split('\n')[0], String(a).split('\n')[0]));
      case 'chart':
        if (/app\.kubernetes\.io\/version$|(^|\.)appversion$/i.test(c.field || '')) return 'app version ' + arrow(b, a);
        return 'chart ' + arrow(b, a);
      default:
        return what + ' ' + (c.field || '') + ' ' + (b == null ? 'added' + (a ? ' (' + WR.truncate(a, 40) + ')' : '') : a == null ? 'removed' : arrow(b, a));
    }
  }

  // ------------------------------------------------------------------------------------------
  // Main
  // ------------------------------------------------------------------------------------------
  function parseHelm(text, ctx) {
    ctx = ctx || {};
    var stats = WR.newStats('empty');
    var result = {
      signals: [], entities: [], stats: stats,
      extras: { changes: [], deploy: null, deploys: [], releases: [], history: {}, clusters: [], siblings: [], canary: false, minTs: null, maxTs: null }
    };
    try {
      run(String(text == null ? '' : text), ctx, result);
    } catch (e) {
      WR.addWarning(stats, 'Helm parsing stopped early: ' + (e && e.message ? e.message : String(e)));
    }
    stats.signals = result.signals.length;
    return result;
  }

  function run(text, ctx, result) {
    var stats = result.stats, extras = result.extras;
    var lines = WR.splitLines(text);
    stats.lines = lines.length;
    if (!text.trim()) return;
    var tzOpts = { defaultTz: ctx.defaultTz || 'Z', year: ctx.year, now: ctx.now };
    var defaultCluster = ctx.cluster || E.DEFAULT_CLUSTER;
    var formats = {};
    var historyTz = 0;

    var st = { release: null, ns: null, cluster: defaultCluster, clusterKnown: !!ctx.cluster, mode: null, block: null, hunk: null, file: null, table: null };
    var blocks = [];     // { kind:'helm-diff'|'unified', header facts, entries, release, ns, cluster, clusterKnown }
    var histories = [];  // { release, ns, cluster, rows: [] }
    var lists = [];      // rows from helm list

    function closeBlock() {
      if (st.block && st.block.entries.some(function (e) { return !e.gap; })) blocks.push(st.block);
      st.block = null;
    }
    // JSON documents (`helm history -o json`, `helm list -o json`) by their first line.
    var jsonStarts = Object.create(null);
    WR.segmentJson(lines).forEach(function (sg) { if (sg.type === 'json') jsonStarts[sg.startLine] = sg; });
    function startBlock(o) {
      closeBlock();
      st.block = Object.assign({ entries: [], release: st.release, ns: st.ns, cluster: st.cluster, clusterKnown: st.clusterKnown }, o);
    }

    for (var i = 0; i < lines.length; i++) {
      var raw = lines[i];
      var lineNo = i + 1;
      var line = raw.indexOf('\x1b') >= 0 ? raw.replace(/\x1b\[[0-9;?]*[A-Za-z]/g, '') : raw;
      line = line.replace(/\r$/, '');
      try {
        if (!line.trim()) {
          if (st.mode === 'history' || st.mode === 'list') st.mode = null;
          continue;
        }

        var m;
        // command echoes / markers
        var cmd = E.parseCommand(line);
        if (cmd) {
          closeBlock(); st.mode = null;
          if (cmd.context) { st.cluster = cmd.context; st.clusterKnown = true; if (extras.clusters.indexOf(cmd.context) < 0) extras.clusters.push(cmd.context); }
          if (cmd.namespace) st.ns = cmd.namespace;
          if (cmd.release) st.release = cmd.release;
          stats.parsed++;
          continue;
        }
        if ((m = RE_RELEASE_MARK.exec(line))) { closeBlock(); st.mode = null; st.release = m[1]; stats.parsed++; continue; }
        // A note that the same release revision runs in another cluster, for example
        // "# prod-us-west: same chart and values rolled out by the pipeline (revision 24 there too)".
        // Rollback options use it to roll back every cluster that runs the bad revision.
        if ((m = RE_SIBLING_NOTE.exec(line)) && /\b(same|also|too|as well|rolled out|identical)\b/i.test(m[2])) {
          var rv = /\b(?:revision|rev\.?)\s*(\d+)\b|\br(\d+)\b/i.exec(m[2]);
          if (rv) extras.siblings.push({ cluster: m[1], revision: Number(rv[1] || rv[2]), release: st.release || null, fromCluster: st.clusterKnown ? st.cluster : null, line: lineNo });
        }
        var marker = E.detectCluster(line);
        if (marker) {
          closeBlock(); st.mode = null;
          st.cluster = marker; st.clusterKnown = true;
          if (extras.clusters.indexOf(marker) < 0) extras.clusters.push(marker);
          stats.parsed++;
          continue;
        }

        // helm diff block header
        if ((m = RE_DIFF_HEADER.exec(line))) {
          formats['helm diff'] = 1;
          stats.parsed++;
          if (!m[5]) {
            // Ownership-only or fully suppressed: nothing of the manifest follows.
            closeBlock(); st.mode = null;
            continue;
          }
          st.mode = 'helm-diff';
          startBlock({ type: 'helm-diff', ns: m[1] || st.ns || null, nsFromHeader: !!m[1], name: m[2], kind: m[3], group: m[4] || '', change: m[5], headerLine: lineNo });
          continue;
        }
        // `helm diff --output simple`: one line per resource, no field detail.
        if ((m = RE_DIFF_SIMPLE.exec(line))) {
          closeBlock(); st.mode = null;
          formats['helm diff (simple)'] = 1;
          stats.parsed++;
          if (m[5] !== 'to change ownership') {
            blocks.push({
              type: 'helm-diff-simple', entries: [], release: st.release, ns: m[1] || st.ns || null, nsFromHeader: !!m[1], cluster: st.cluster, clusterKnown: st.clusterKnown,
              name: m[2], kind: m[3], group: m[4] || '', headerLine: lineNo,
              change: m[5] === 'to be added' ? 'been added' : m[5] === 'to be removed' ? 'been removed' : 'changed'
            });
          }
          continue;
        }
        if (RE_DIFF_PLAN.test(line)) { closeBlock(); st.mode = null; stats.parsed++; continue; }
        // `helm history -o json` / `helm list -o json`
        var js = jsonStarts[lineNo];
        if (js && st.mode !== 'helm-diff' && st.mode !== 'unified') {
          var jr = readHelmJson(js, st, tzOpts);
          if (jr) {
            closeBlock(); st.mode = null;
            if (jr.history) { histories.push(jr.history); formats['helm history'] = 1; historyTz += jr.tzAssumed; }
            if (jr.list) { jr.list.forEach(function (x) { lists.push(x); }); formats['helm list'] = 1; stats.tzAssumed += jr.tzAssumed; }
            stats.parsed += js.endLine - js.startLine + 1;
            i = js.endLine - 1;
            continue;
          }
        }
        // unified diff
        if (/^diff --git /.test(line)) {
          closeBlock();
          var dg = /^diff --git a\/(\S+) b\/(\S+)/.exec(line);
          st.mode = 'unified'; st.file = dg ? winPath(dg[2]) : null;
          formats['unified diff'] = 1;
          stats.parsed++;
          continue;
        }
        if (/^--- /.test(line) && i + 1 < lines.length && /^\+\+\+ /.test(lines[i + 1])) {
          closeBlock();
          var plus = /^\+\+\+ (?:b\/)?(\S+)/.exec(lines[i + 1]);
          st.mode = 'unified'; st.file = winPath(plus && plus[1] !== '/dev/null' ? plus[1] : (/^--- (?:a\/)?(\S+)/.exec(line) || [])[1] || null);
          formats['unified diff'] = 1;
          stats.parsed += 2;
          i++;
          continue;
        }
        if (st.mode === 'unified' && /^@@ /.test(line)) {
          closeBlock();
          startBlock({ type: 'unified', file: st.file, headerLine: lineNo });
          stats.parsed++;
          continue;
        }
        // tables
        if (RE_H_HISTORY.test(line)) {
          closeBlock();
          st.mode = 'history';
          st.table = { cols: columnsOf(line), hist: { release: st.release, ns: st.ns, cluster: st.cluster, clusterKnown: st.clusterKnown, rows: [], headerLine: lineNo } };
          histories.push(st.table.hist);
          formats['helm history'] = 1;
          stats.parsed++;
          continue;
        }
        if (RE_H_LIST.test(line)) {
          closeBlock();
          st.mode = 'list';
          st.table = { cols: columnsOf(line) };
          formats['helm list'] = 1;
          stats.parsed++;
          continue;
        }

        if (st.mode === 'history') {
          var row = historyRow(line, st.table.cols, tzOpts);
          if (row) {
            row.line = lineNo;
            if (row.tzAssumed) historyTz++;
            st.table.hist.rows.push(row);
            stats.parsed++;
            continue;
          }
          st.mode = null;
        }
        if (st.mode === 'list') {
          var lr = listRow(line, st.table.cols, tzOpts);
          if (lr) {
            lr.line = lineNo; lr.cluster = st.cluster; lr.clusterKnown = st.clusterKnown;
            if (lr.tzAssumed) stats.tzAssumed++;
            lists.push(lr);
            stats.parsed++;
            continue;
          }
          st.mode = null;
        }

        if ((st.mode === 'helm-diff' || st.mode === 'unified') && st.block) {
          // `helm diff --context N` prints "..." where it skipped unchanged lines (diff/diff.go).
          // The lines after it lost their parent keys, so the YAML walker restarts its path there.
          if (st.mode === 'helm-diff' && /^\.\.\.\s*$/.test(line)) {
            st.block.entries.push({ marker: ' ', text: '', gap: true, line: lineNo, raw: raw });
            stats.parsed++;
            continue;
          }
          var c0 = line[0];
          if (c0 === '+' || c0 === '-' || c0 === ' ') {
            st.block.entries.push({ marker: c0, text: line.slice(1), line: lineNo, raw: raw });
            stats.parsed++;
            continue;
          }
          if (c0 === '\\') { stats.parsed++; continue; } // "\ No newline at end of file"
          if (st.mode === 'unified' && /^(index |new file mode|deleted file mode|similarity index|rename (from|to))/.test(line)) { stats.parsed++; continue; }
          closeBlock();
          st.mode = null;
        } else if (st.mode === 'unified' && /^(index |new file mode|deleted file mode|similarity index|rename (from|to))/.test(line)) { stats.parsed++; continue; }

        if (/^\s*#/.test(line)) { stats.parsed++; continue; }
        stats.skipped++;
      } catch (err) {
        stats.skipped++;
        WR.addWarning(stats, 'Line ' + lineNo + ' could not be read: ' + (err && err.message ? err.message : err));
      }
    }
    closeBlock();

    buildChanges(blocks, histories, lists, lines, ctx, tzOpts, result);

    if (historyTz) {
      stats.tzAssumed += historyTz;
      WR.addWarning(stats, 'Helm history times have no time zone; assumed ' + (T.fmtOffset(T.offsetMinutes(tzOpts.defaultTz) || 0)) + '.');
    }
    var fmtNames = Object.keys(formats);
    stats.format = fmtNames.length ? fmtNames.join(' + ') : (stats.lines ? 'unrecognised' : 'empty');
    if (stats.skipped) WR.addWarning(stats, stats.skipped + ' line' + (stats.skipped === 1 ? ' was' : 's were') + ' not recognised and skipped.');
    if (!fmtNames.length && stats.lines) WR.addWarning(stats, 'No Helm output found. Paste `helm diff upgrade` output, a unified diff of values.yaml, or `helm history <release>`.');
  }

  function columnsOf(header) {
    var cols = [];
    var re = /\S+(?: \S+)*/g, m;
    while ((m = re.exec(header)) !== null) cols.push({ name: m[0], start: m.index });
    return cols;
  }
  function slice(line, cols) {
    if (line.indexOf('\t') >= 0) {
      var parts = line.split(/\t/).map(function (s) { return s.trim(); });
      var o = {};
      cols.forEach(function (c, i) { o[c.name] = parts[i] != null ? parts[i] : ''; });
      return o;
    }
    var out = {};
    for (var i = 0; i < cols.length; i++) {
      var s = cols[i].start, e = i + 1 < cols.length ? cols[i + 1].start : line.length;
      out[cols[i].name] = line.slice(s, e).trim();
    }
    return out;
  }

  function historyRow(line, cols, tzOpts) {
    var v = slice(line, cols);
    var rev = v.REVISION, upd = v.UPDATED, status = v.STATUS, chart = v.CHART, app = v['APP VERSION'], desc = v.DESCRIPTION;
    var p = /^\d+$/.test(rev || '') ? T.parse(upd, tzOpts) : null;
    if (!p || !status || /\s/.test(status) || !chart || /\s/.test(chart)) {
      // Misaligned paste (spaces collapsed): fall back to a pattern anchored on the date shape.
      var m = RE_HISTORY_ROW.exec(line);
      if (!m) return null;
      rev = m[1]; upd = m[2]; status = m[3]; chart = m[4]; app = m[5] || ''; desc = m[6];
      p = T.parse(upd, tzOpts);
      if (!p) return null;
    }
    return { revision: Number(rev), updated: p.ts, tsInferred: p.tsInferred, tzAssumed: p.tzAssumed, status: String(status).toLowerCase(), chart: chart, appVersion: app || null, description: desc || '' };
  }

  function listRow(line, cols, tzOpts) {
    var m = RE_LIST_ROW.exec(line);
    var name, ns, rev, upd, status, chart, app;
    if (m) { name = m[1]; ns = m[2]; rev = m[3]; upd = m[4]; status = m[5]; chart = m[6]; app = m[7]; }
    else {
      var v = slice(line, cols);
      name = v.NAME; ns = v.NAMESPACE; rev = v.REVISION; upd = v.UPDATED; status = v.STATUS; chart = v.CHART; app = v['APP VERSION'];
      if (!/^\d+$/.test(rev || '')) return null;
    }
    // Go prints "2026-10-05 23:47:03.123456 +0200 CEST"; T.parse reads the numeric offset.
    var p = T.parse(goTime(upd), tzOpts);
    if (!p) return null;
    return { release: name, namespace: ns, revision: Number(rev), updated: p.ts, tsInferred: p.tsInferred, tzAssumed: p.tzAssumed, status: String(status || '').toLowerCase(), chart: chart, appVersion: app || null };
  }

  // Go's time.String() as helm list prints it: "2026-10-05 23:47:03.123456 +0200 CEST".
  function goTime(s) {
    return String(s == null ? '' : s).trim().replace(/\s+[A-Z]{2,5}$/, '').replace(/(\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+([+-]\d{4})$/, '$1$2');
  }

  /*
   * `helm history <release> -o json` → [{revision, updated (RFC 3339), status, chart, app_version,
   * description}]; `helm list -o json` → [{name, namespace, revision (a string), updated (Go
   * time.String()), status, chart, app_version}]. Returns null for any other JSON so the caller can
   * fall back to reading the lines.
   */
  function readHelmJson(seg, st, tzOpts) {
    var pj = WR.parseJsonLenient(seg.text);
    var v = pj.value;
    if (v && !Array.isArray(v) && typeof v === 'object' && Array.isArray(v.releases)) v = v.releases;
    if (!Array.isArray(v) || !v.length || !v.every(function (x) { return x && typeof x === 'object'; })) return null;
    var starts = WR.lineIndex(seg.text);
    function lineOf(rev, name) {
      var re = name ? new RegExp('"name"\\s*:\\s*"' + String(name).replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '"') : new RegExp('"revision"\\s*:\\s*"?' + rev + '\\b');
      var m = re.exec(seg.text);
      return m ? seg.startLine + WR.lineAt(starts, m.index) - 1 : seg.startLine;
    }
    var tz = 0;
    var isHistory = v.every(function (x) { return x.revision != null && x.updated != null && x.status != null && x.name == null; });
    var isList = v.every(function (x) { return x.name != null && x.revision != null && x.updated != null; });
    if (isHistory) {
      var rows = [];
      v.forEach(function (x) {
        var p = T.parse(String(x.updated), tzOpts);
        if (!p || !/^\d+$/.test(String(x.revision))) return;
        if (p.tzAssumed) tz++;
        rows.push({ revision: Number(x.revision), updated: p.ts, tsInferred: p.tsInferred, tzAssumed: p.tzAssumed, status: String(x.status).toLowerCase(),
          chart: x.chart || null, appVersion: x.app_version || x.appVersion || null, description: x.description || '', line: lineOf(x.revision) });
      });
      if (!rows.length) return null;
      return { history: { release: st.release, ns: st.ns, cluster: st.cluster, clusterKnown: st.clusterKnown, rows: rows, headerLine: seg.startLine }, tzAssumed: tz };
    }
    if (isList) {
      var list = [];
      v.forEach(function (x) {
        var p = T.parse(goTime(x.updated), tzOpts);
        if (!p || !/^\d+$/.test(String(x.revision))) return;
        if (p.tzAssumed) tz++;
        list.push({ release: String(x.name), namespace: x.namespace || st.ns || null, revision: Number(x.revision), updated: p.ts, tsInferred: p.tsInferred, tzAssumed: p.tzAssumed,
          status: String(x.status || '').toLowerCase(), chart: x.chart || null, appVersion: x.app_version || x.appVersion || null, line: lineOf(null, x.name), cluster: st.cluster, clusterKnown: st.clusterKnown });
      });
      return list.length ? { list: list, tzAssumed: tz } : null;
    }
    return null;
  }

  // GNU diff on Windows prints C:\work\charts\payments\values.yaml: use / so the chart and file
  // name read the same as from git.
  function winPath(p) { return p == null ? null : String(p).replace(/\\/g, '/').replace(/^[A-Za-z]:/, ''); }

  function chartRelease(chart) {
    if (!chart) return null;
    return String(chart).replace(/-v?\d+(?:\.\d+)+(?:[-+.][\w.]+)?$/, '') || null;
  }

  // ------------------------------------------------------------------------------------------
  // Changes, deploys, signals
  // ------------------------------------------------------------------------------------------
  function buildChanges(blocks, histories, lists, lines, ctx, tzOpts, result) {
    var extras = result.extras;
    var ents = E.collector();

    // Pass 1: walk every block, learn identities and which workloads each release ships.
    var walked = blocks.map(function (b) {
      var recs = walkYaml(b.entries);
      var facts = blockFacts(recs);
      var kind = b.kind || facts.kind || (b.type === 'unified' && /values[^/]*\.ya?ml$/.test(b.file || '') ? 'values' : null);
      if (b.type === 'unified' && !kind) kind = /\.ya?ml$/.test(b.file || '') && /values/.test(b.file || '') ? 'values' : (facts.kind || 'values');
      var name = b.name || facts.name || (b.file ? b.file.replace(/^.*\//, '') : null);
      var release = b.release || facts.instance || chartRelease(facts.chart) || (b.file ? (/charts\/([\w.-]+)\//.exec(b.file) || [])[1] : null) || null;
      var hookJob = facts.hook && /pre-|post-/.test(facts.hook) && (kind === 'Job' || kind === 'Pod');
      var migrationHook = !!(hookJob && (/migrat/i.test(name || '') || facts.containers.some(function (c) { return /migrat/i.test(c); })));
      if (CANARY_KINDS[kind]) extras.canary = true;
      return { b: b, recs: recs, facts: facts, kind: kind, name: name, release: release, migrationHook: migrationHook, hook: facts.hook };
    });

    var workloadsByRelease = Object.create(null);
    walked.forEach(function (w) {
      if (WORKLOAD_KINDS[w.kind] && w.name) {
        var key = w.release || '';
        var list = workloadsByRelease[key] || (workloadsByRelease[key] = []);
        if (list.indexOf(w.name) < 0) list.push(w.name);
      }
    });

    // Workloads that still exist after the upgrade (a removed Deployment is not the owner of anything).
    var liveWorkloads = Object.create(null);
    walked.forEach(function (w) {
      if (WORKLOAD_KINDS[w.kind] && w.name && w.b.change !== 'been removed') {
        var key = w.release || '';
        var list = liveWorkloads[key] || (liveWorkloads[key] = []);
        if (list.indexOf(w.name) < 0) list.push({ name: w.name, ns: w.b.ns });
      }
    });

    // The release's main workload: the one named after the release, else the first one seen.
    function primary(release, ns) {
      var wl = (liveWorkloads[release || ''] || []).filter(function (x) { return !ns || !x.ns || x.ns === ns; });
      if (!wl.length) return null;
      var named = wl.filter(function (x) { return x.name === release || x.name.indexOf(release + '-') === 0; })[0];
      return (named || wl[0]).name;
    }

    // Release-level resources (values, ConfigMaps, Secrets, hooks, HPAs) belong to the workload they
    // configure, so their changes land on that workload's map node.
    var RELEASE_LEVEL = { values: 1, ConfigMap: 1, Secret: 1, Job: 1, CustomResourceDefinition: 1, HorizontalPodAutoscaler: 1, PodDisruptionBudget: 1, Ingress: 1, Service: 1, NetworkPolicy: 1, ServiceAccount: 1, Role: 1, RoleBinding: 1 };
    function ownerName(name, release, w) {
      var ns = w ? w.b.ns : null;
      var wl = (workloadsByRelease[release || ''] || []).slice();
      if (w && w.facts.scaleTarget) return w.facts.scaleTarget;
      if (w && w.kind === 'NetworkPolicy' && w.facts.appLabel) return w.facts.appLabel;
      if (w && (w.kind === 'values' || w.kind === 'CustomResourceDefinition')) return primary(release, ns) || release || null;
      if (!name) return primary(release, ns) || release || null;
      var n = String(name).toLowerCase();
      if (wl.indexOf(n) >= 0) return n;
      var cls = E.classifyName(n, ns);
      if (cls.type === 'infra') return n; // coredns & friends are their own component
      var base = n.replace(/-(config|configmap|cm|env|settings|secret|secrets|credentials|creds|tls|hpa|pdb|netpol|networkpolicy|ingress|svc|service|db-migrate|migrate|migration|migrations)$/, '');
      if (wl.indexOf(base) >= 0) return base;
      var related = wl.filter(function (x) { return x.indexOf(base + '-') === 0 || base.indexOf(x + '-') === 0; });
      if (related.length === 1) return related[0];
      if (w && RELEASE_LEVEL[w.kind]) {
        var pr = primary(release, ns);
        if (pr) return pr;
      }
      return base;
    }

    var changes = [];
    var seen = Object.create(null);
    walked.forEach(function (w) {
      var b = w.b;
      var ns = b.ns || null;
      var ownerHint = null;
      var owner = w.kind === 'CustomResourceDefinition' ? ownerName(null, w.release, w) : ownerName(w.name, w.release, w);
      if (owner) {
        ownerHint = E.hint({ name: owner, namespace: ns, cluster: b.cluster, clusterKnown: b.clusterKnown, source: 'helm', release: w.release });
        if (ownerHint) {
          ownerHint.releaseGuess = owner === w.release && (workloadsByRelease[w.release] || []).indexOf(owner) < 0;
          ents.add(ownerHint);
        }
      }
      var base = {
        release: w.release, namespace: ns, resourceKind: w.kind || 'values', resourceName: w.name,
        componentId: ownerHint ? ownerHint.id : null, cluster: b.cluster
      };
      var facts = { migrationHook: w.migrationHook };
      var isSecretRes = w.kind === 'Secret';

      if (b.type === 'helm-diff-simple' && b.change === 'changed') {
        // `--output simple` says only that the resource changes, not which field.
        var sc = Object.assign({}, base, { field: '', before: '(current)', after: '(changed)', changeType: 'changed', line: b.headerLine });
        var scls = classifyChange(sc, facts);
        if (scls.category === 'other') scls.risk = WORKLOAD_KINDS[w.kind] ? 'medium' : 'low';
        pushChange(sc, scls, lines[b.headerLine - 1]);
        return;
      }
      if ((b.type === 'helm-diff' || b.type === 'helm-diff-simple') && (b.change === 'been added' || b.change === 'been removed')) {
        var added = b.change === 'been added';
        var c = Object.assign({}, base, {
          field: '', before: added ? null : '(resource)', after: added ? '(resource)' : null,
          changeType: added ? 'resource-added' : 'resource-removed', hook: w.hook,
          line: b.headerLine
        });
        var cls = classifyChange(c, facts);
        if (cls.category === 'other' && WORKLOAD_KINDS[w.kind]) cls.risk = added ? 'medium' : 'high';
        if (cls.category === 'configmap' || cls.category === 'secret' || cls.category === 'env') cls.risk = added ? 'medium' : 'high';
        if (cls.category === 'service' || cls.category === 'ingress' || cls.category === 'rbac') cls.risk = added ? 'medium' : 'high';
        if (cls.category === 'other' && !WORKLOAD_KINDS[w.kind]) cls.risk = added ? 'low' : 'medium';
        pushChange(c, cls, b.entries.length ? b.entries[0].raw : lines[b.headerLine - 1]);
        return;
      }

      var pairs = pairChanges(w.recs);
      var blockOut = [];
      pairs.forEach(function (p) {
        var before = unitValue(p.before, p.scalar);
        var after = unitValue(p.after, p.scalar);
        if (before != null && after != null && before === after) return; // whitespace-only move
        var refUnit = (p.after || p.before)[0];
        var c = Object.assign({}, base, {
          field: p.path, before: before, after: after,
          changeType: before == null ? 'added' : after == null ? 'removed' : 'changed',
          line: refUnit.rec.line
        });
        // Secrets never leave the parser in clear text.
        var envName = (/env\[([^\]]+)\]/.exec(p.path) || [])[1] || lastSeg(p.path);
        var secretish = isSecretRes ||
          (/(^|\.)(data|stringData)(\.|$)/.test(p.path) && isSecretRes) ||
          WR.redact.looksSecret(envName, null) ||
          (before != null && WR.redact.looksSecret(null, before)) || (after != null && WR.redact.looksSecret(null, after));
        if (secretish) {
          if (c.before != null) c.before = REDACTED;
          if (c.after != null) c.after = REDACTED;
          c.redacted = true;
        }
        var cls = classifyChange(c, facts);
        var rawLine = refUnit.rec.raw || lines[refUnit.rec.line - 1] || '';
        blockOut.push([c, cls, secretish ? redactLine(rawLine) : rawLine]);
      });
      // A CRD upgrade or a ConfigMap rewrite can change thousands of fields. Keep the riskiest
      // MAX_CHANGES_PER_RESOURCE (in diff order) and fold the rest into one "N more" change, so a
      // giant diff cannot bury the incident or the browser.
      if (blockOut.length > MAX_CHANGES_PER_RESOURCE) {
        var rank = { high: 0, medium: 1, low: 2 };
        var keep = blockOut.map(function (x, i) { return { x: x, i: i }; })
          .sort(function (a, b) { return rank[a.x[1].risk] - rank[b.x[1].risk] || a.i - b.i; })
          .slice(0, MAX_CHANGES_PER_RESOURCE).sort(function (a, b) { return a.i - b.i; }).map(function (k) { return k.x; });
        var rest = blockOut.filter(function (x) { return keep.indexOf(x) < 0; });
        var worst = rest.reduce(function (m, x) { return rank[x[1].risk] < rank[m] ? x[1].risk : m; }, 'low');
        var agg = Object.assign({}, base, { field: '(' + rest.length + ' more fields)', before: null, after: null, changeType: 'changed', line: rest[0][0].line, aggregate: rest.length });
        blockOut = keep.concat([[agg, { category: rest[0][1].category, risk: worst }, rest[0][2]]]);
      }
      blockOut.forEach(function (x) { pushChange(x[0], x[1], x[2]); });
    });

    function pushChange(c, cls, rawLine) {
      c.category = cls.category;
      c.risk = cls.risk;
      if (cls.direction) c.direction = cls.direction;
      c.summary = summarize(c, cls);
      c.id = 'chg-' + WR.hash([c.release, c.cluster, c.namespace, c.resourceKind, c.resourceName, c.field, c.line].join('|'));
      if (seen[c.id]) return;
      seen[c.id] = true;
      c.raw = WR.truncate(rawLine, 600);
      delete c.hook;
      changes.push(c);
    }

    // ---- deploys ------------------------------------------------------------------------------
    var deploys = [];
    histories.forEach(function (h) {
      if (!h.rows.length) return;
      var rows = h.rows.slice().sort(function (a, b) { return a.revision - b.revision; });
      var release = h.release || chartRelease(rows[rows.length - 1].chart);
      var latest = rows[rows.length - 1];
      var suspect = latest, rolledBack = null;
      var rb = /Rollback to (\d+)/i.exec(latest.description || '');
      if (rb && rows.length > 1 && rows[rows.length - 2].revision !== Number(rb[1])) {
        // Helm records a rollback as a new revision that re-applies revision N. The change the
        // incident lines up with is the upgrade that rollback undid (the row before it); "roll back
        // to the previous revision" from the rollback row would re-apply that very upgrade.
        suspect = rows[rows.length - 2];
        rolledBack = { revision: latest.revision, to: Number(rb[1]), at: latest.updated, tsInferred: !!latest.tsInferred, status: latest.status, line: latest.line };
      }
      var prev = null;
      if (rolledBack) {
        prev = rows.filter(function (r) { return r.revision === rolledBack.to; })[0] || { revision: rolledBack.to, chart: null, appVersion: null };
      } else {
        for (var i = rows.length - 2; i >= 0; i--) {
          if (/^(superseded|deployed)$/.test(rows[i].status)) { prev = rows[i]; break; }
        }
        if (!prev && rows.length > 1) prev = rows[rows.length - 2];
      }
      var d = {
        release: release, namespace: h.ns || null, revision: suspect.revision, previousRevision: prev ? prev.revision : null,
        chartFrom: prev ? prev.chart : null, chartTo: suspect.chart, appFrom: prev ? prev.appVersion : null, appTo: suspect.appVersion,
        deployedAt: suspect.updated, deployedAtSource: 'helm-history', tsInferred: !!suspect.tsInferred,
        cluster: h.cluster, clusterKnown: !!h.clusterKnown, status: suspect.status, description: suspect.description, line: suspect.line
      };
      if (rolledBack) {
        d.rolledBack = rolledBack;
        WR.addWarning(result.stats, 'Helm release ' + (release || '?') + ' was already rolled back: r' + rolledBack.revision + ' restored r' + rolledBack.to +
          ' at ' + T.fmt(rolledBack.at) + ' UTC, undoing r' + suspect.revision + '. Check whether errors continued after that.');
      } else if (rb) d.rolledBackTo = Number(rb[1]);
      extras.history[release || '?'] = rows;
      deploys.push(d);
    });
    lists.forEach(function (r) {
      if (deploys.some(function (d) { return d.release === r.release && (!d.namespace || d.namespace === r.namespace); })) {
        // history already known; the list row only confirms the namespace
        deploys.forEach(function (d) { if (d.release === r.release && !d.namespace) d.namespace = r.namespace; });
        return;
      }
      deploys.push({
        release: r.release, namespace: r.namespace, revision: r.revision, previousRevision: r.revision > 1 ? r.revision - 1 : null,
        previousRevisionAssumed: r.revision > 1, chartFrom: null, chartTo: r.chart, appFrom: null, appTo: r.appVersion,
        deployedAt: r.updated, deployedAtSource: 'helm-list', tsInferred: !!r.tsInferred, cluster: r.cluster, clusterKnown: !!r.clusterKnown, status: r.status, line: r.line
      });
    });
    // A diff on its own still names the release and the chart/app versions it moves between.
    var diffReleases = WR.uniq(walked.map(function (w) { return w.release; }).filter(Boolean));
    diffReleases.forEach(function (rel) {
      var d = deploys.filter(function (x) { return x.release === rel; })[0];
      var chartCh = changes.filter(function (c) { return c.release === rel && /helm\.sh\/chart$|labels\.chart$/.test(c.field || ''); })[0];
      var appCh = changes.filter(function (c) { return c.release === rel && /app\.kubernetes\.io\/version$/.test(c.field || ''); })[0];
      if (!d) {
        var w0 = walked.filter(function (w) { return w.release === rel; })[0];
        d = { release: rel, namespace: w0 ? w0.b.ns : null, revision: null, previousRevision: null, chartFrom: null, chartTo: null, appFrom: null, appTo: null, deployedAt: null, deployedAtSource: null, tsInferred: false, cluster: w0 ? w0.b.cluster : null, clusterKnown: w0 ? !!w0.b.clusterKnown : false, status: 'diff-only', line: w0 ? w0.b.headerLine : null };
        deploys.push(d);
      }
      if (chartCh) { d.chartFrom = d.chartFrom || chartCh.before; d.chartTo = d.chartTo || chartCh.after; }
      if (appCh) { d.appFrom = d.appFrom || appCh.before; d.appTo = d.appTo || appCh.after; }
      if (!d.namespace) {
        var wns = walked.filter(function (w) { return w.release === rel && w.b.nsFromHeader; })[0];
        if (wns) d.namespace = wns.b.ns;
      }
    });
    // Changes inherit their release's namespace when the diff itself had none (values.yaml).
    changes.forEach(function (c) {
      if (!c.namespace) {
        var d = deploys.filter(function (x) { return x.release === c.release; })[0];
        if (d && d.namespace) {
          c.namespace = d.namespace;
          if (c.componentId) {
            var pid = E.parseId(c.componentId);
            var h = pid ? E.hint({ name: pid.name, namespace: c.namespace, cluster: pid.cluster, clusterKnown: true, source: 'helm', release: c.release }) : null;
            if (h) {
              h.releaseGuess = pid.name === c.release && (workloadsByRelease[c.release] || []).indexOf(pid.name) < 0;
              ents.add(h);
              c.componentId = h.id;
            }
          }
        }
      }
    });
    // Manual "Deployed at" from the context form wins over anything parsed.
    var manual = ctx.deployedAt ? T.resolveNow(ctx.deployedAt, tzOpts) : null;
    if (manual != null) {
      if (!deploys.length) deploys.push({ release: null, namespace: null, revision: null, previousRevision: null, chartFrom: null, chartTo: null, appFrom: null, appTo: null, deployedAt: null, deployedAtSource: null, tsInferred: false, cluster: null, clusterKnown: false, status: null, line: null });
      deploys.forEach(function (d) { d.deployedAt = manual; d.deployedAtSource = 'manual'; d.tsInferred = false; });
    }
    deploys.forEach(function (d) {
      d.changeCount = changes.filter(function (c) { return c.release === d.release; }).length;
      if (d.release) {
        var known = (workloadsByRelease[d.release] || [])[0];
        var rh = E.hint({ name: primary(d.release, d.namespace) || known || d.release, namespace: d.namespace, cluster: d.cluster, clusterKnown: !!d.clusterKnown, defaultCluster: ctx.cluster, source: 'helm', release: d.release });
        if (rh) {
          rh.releaseGuess = !known;
          ents.add(rh);
          d.componentId = rh.id;
        }
      }
    });
    // The most recent deploy is the one an incident is most likely about; ties go to the one with changes.
    deploys.sort(function (a, b) {
      var at = a.deployedAt == null ? -Infinity : a.deployedAt, bt = b.deployedAt == null ? -Infinity : b.deployedAt;
      if (bt !== at) return bt - at;
      return (b.changeCount || 0) - (a.changeCount || 0);
    });
    extras.deploys = deploys;
    extras.deploy = deploys[0] || null;
    extras.releases = WR.uniq(deploys.map(function (d) { return d.release; }).concat(diffReleases).filter(Boolean));
    extras.changes = changes;

    // ---- signals: one per change, one per deploy --------------------------------------------------
    var perLine = Object.create(null);
    function sigId(line) {
      var k = perLine[line] || 0;
      perLine[line] = k + 1;
      return 'hlm-' + line + (k ? '.' + k : '');
    }
    deploys.forEach(function (d) {
      // Only deploys read from a history/list row have a line to point at.
      if (d.line == null || d.deployedAtSource == null) return;
      var failed = /failed/.test(d.status || '');
      var txt = 'Helm release ' + (d.release || '?') + (d.namespace ? ' (' + d.namespace + ')' : '') +
        (d.previousRevision != null ? ' revision ' + d.previousRevision + ' → ' + d.revision : d.revision != null ? ' revision ' + d.revision : '') +
        (d.chartFrom && d.chartTo && d.chartFrom !== d.chartTo ? ', chart ' + d.chartFrom + ' → ' + d.chartTo : d.chartTo ? ', chart ' + d.chartTo : '') +
        (d.status ? ', status ' + d.status : '') + (d.rolledBackTo ? ' (rollback to ' + d.rolledBackTo + ')' : '');
      result.signals.push({
        id: sigId(d.line), source: 'helm', line: d.line, ts: d.deployedAt, tsInferred: !!d.tsInferred,
        severity: failed ? 'error' : 'info', kind: 'change', componentId: d.componentId || null, relatedIds: [],
        text: txt, raw: WR.truncate(lines[d.line - 1] || '', 600),
        attrs: { isDeploy: true, release: d.release, revision: d.revision, previousRevision: d.previousRevision, status: d.status, deployedAtSource: d.deployedAtSource }
      });
      if (d.rolledBack && d.rolledBack.line != null) {
        var rbk = d.rolledBack;
        rbk.signalId = sigId(rbk.line);
        result.signals.push({
          id: rbk.signalId, source: 'helm', line: rbk.line, ts: rbk.at, tsInferred: !!rbk.tsInferred,
          severity: 'info', kind: 'change', componentId: d.componentId || null, relatedIds: [],
          text: 'Helm release ' + (d.release || '?') + ' rolled back to revision ' + rbk.to + ' (new revision ' + rbk.revision + ', status ' + rbk.status + ')',
          raw: WR.truncate(lines[rbk.line - 1] || '', 600),
          attrs: { isRollback: true, release: d.release, revision: rbk.revision, rolledBackTo: rbk.to, undid: d.revision }
        });
      }
    });
    changes.forEach(function (c) {
      var d = deploys.filter(function (x) { return x.release === c.release; })[0] || null;
      var ts = d ? d.deployedAt : null;
      var sig = {
        id: sigId(c.line), source: 'helm', line: c.line, ts: ts, tsInferred: true,
        severity: c.risk === 'high' ? 'warn' : 'info', kind: 'change', componentId: c.componentId, relatedIds: [],
        text: c.summary, raw: c.raw,
        attrs: { changeId: c.id, category: c.category, risk: c.risk, release: c.release, field: c.field, before: c.before, after: c.after, resourceKind: c.resourceKind, resourceName: c.resourceName, changeType: c.changeType }
      };
      if (c.redacted) sig.attrs.redacted = true;
      c.signalId = sig.id;
      result.signals.push(sig);
    });
    result.signals.forEach(function (s) {
      if (s.ts == null) return;
      if (extras.minTs == null || s.ts < extras.minTs) extras.minTs = s.ts;
      if (extras.maxTs == null || s.ts > extras.maxTs) extras.maxTs = s.ts;
    });
    if (changes.length && !deploys.some(function (d) { return d.deployedAt != null; })) {
      WR.addWarning(result.stats, 'No deploy time found — paste `helm history <release>` or set "Deployed at" so changes can be lined up with the first errors.');
    }
    result.entities = ents.list();
  }

  // Replace the value half of "key: value" so a secret line can be shown without its secret.
  function redactLine(line) {
    var m = /^([+\- ]?\s*(?:-\s+)?["']?[\w.\/-]+["']?\s*:\s*)(.+)$/.exec(line);
    if (m) return m[1] + REDACTED;
    return WR.redact(line).text;
  }

  WR.parseHelm = parseHelm;
  WR.parseHelm._walkYaml = walkYaml; // exposed for tests
})(globalThis.WR = globalThis.WR || {});
