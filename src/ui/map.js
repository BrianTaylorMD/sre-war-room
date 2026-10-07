/*
 * map.js — the blast-radius map (SPEC §6.3) and its replay scrubber.
 *
 *   WR.ui.map.render(containerEl, analysis, { onSelect(componentId), at })
 *     -> handle { setTime(ms|null), highlight(componentId|null), destroy(), getTime(), stats(ms?) }
 *   WR.ui.map.mountScrubber(containerEl, analysis, mapHandle, { defaultTz }?)
 *     -> handle { setTime(ms|null), play(), pause(), destroy() }
 *
 * Both are re-callable on every re-analysis: state lives per container (WeakMap), the <svg> element and
 * its delegated listeners are created once, and each update only replaces the svg's children. The
 * selected node, the focused node and the horizontal scroll position survive an update.
 *
 * Layout is deterministic and layered (no physics):
 *   - one horizontal lane per cluster (components with no cluster go to an "Unassigned" lane, last);
 *   - inside a lane, services, datastores and external dependencies sit in columns by longest path over
 *     the call edges (entry points first, datastores and external dependencies forced into the last
 *     column); cluster add-ons (CoreDNS) and Kubernetes nodes sit in a lower "Cluster infrastructure" row;
 *   - long edges get pass-through slots in the columns they cross (dummy nodes), the order inside each
 *     column comes from a barycentre pass that keeps the ordering with the fewest crossings, and vertical
 *     positions come from an isotonic (pool-adjacent-violators) fit so call chains run straight;
 *   - calls into the infrastructure row leave the caller on the right, drop down the gap after its
 *     column, and fan into the add-on from above, so they never cut through other components.
 *
 * Replay: a node shows healthy until its first error (firstErrorTs, else statusSince, else window.now),
 * then its final status; an edge shows ok until its firstErrorTs (else its target's reveal time). At
 * window.now everything equals the analysis.
 *
 * Every colour comes from CSS classes in map.css, which only reference the SPEC §6.1 tokens. Pasted and
 * engine text only ever reaches the DOM through textContent or attribute values.
 */
(function (WR) {
  'use strict';

  var SVGNS = 'http://www.w3.org/2000/svg';
  var ui = WR.ui = WR.ui || {};

  // ---------------------------------------------------------------------------------------------
  // Geometry (px). The svg renders at its natural size, or scaled down to fit its box when that
  // keeps the scale at MIN_SCALE or more (12px labels stay at 9.6px or larger); below that it
  // scrolls sideways instead, so text on phones never shrinks.
  // ---------------------------------------------------------------------------------------------
  var G = {
    nodeH: 54, nodeMinW: 150, nodeMaxW: 216, infraMaxW: 268, padL: 38, padR: 14, nodeRx: 8,
    gap: 88, gapMin: 64, gapMaxExtra: 72, rowGap: 24, dummyH: 8, rootExtra: 10,
    laneGap: 16, lanePadX: 18, entryPad: 36, laneHead: 84, lanePadB: 22,
    chanInset: 12, chanStep: 8,
    infraSepGap: 22, infraFan: 62, infraPlain: 34, infraGap: 18, infraRowGap: 26,
    labelH: 20, noteH: 18
  };

  var MIN_SCALE = 0.8;
  var RANK = { root: 0, failing: 1, degraded: 2, 'at-risk': 3, healthy: 4 };
  var EDGE_RANK = { ok: 0, degraded: 1, failing: 2 };
  var STATUS_WORD = { root: 'failing', failing: 'failing', degraded: 'degraded', 'at-risk': 'at risk', healthy: '' };
  var STATUS_LONG = {
    root: 'suspected root cause, failing', failing: 'failing', degraded: 'degraded',
    'at-risk': 'at risk (calls a failing component)', healthy: 'healthy'
  };
  var TYPE_LABEL = {
    service: 'Service', ingress: 'Ingress or gateway', datastore: 'Datastore', external: 'External dependency',
    infra: 'Cluster add-on', node: 'Kubernetes node'
  };
  var TYPE_ORDER = { service: 0, datastore: 1, external: 2, infra: 3, node: 4 };

  var instances = new WeakMap();
  var scrubbers = new WeakMap();
  var uid = 0;

  function reducedMotion() {
    try { return !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches); }
    catch (e) { return false; }
  }

  // ---------------------------------------------------------------------------------------------
  // Small helpers
  // ---------------------------------------------------------------------------------------------
  function num(v) { return typeof v === 'number' && isFinite(v) ? v : null; }
  function clamp(x, lo, hi) { return x < lo ? lo : x > hi ? hi : x; }
  function r1(x) { return Math.round(x * 10) / 10; }

  function svgEl(tag, attrs, parent) {
    var el = document.createElementNS(SVGNS, tag);
    if (attrs) for (var k in attrs) if (attrs[k] != null) el.setAttribute(k, String(attrs[k]));
    if (parent) parent.appendChild(el);
    return el;
  }
  function htmlEl(tag, attrs, parent, text) {
    var el = document.createElement(tag);
    if (attrs) for (var k in attrs) if (attrs[k] != null) el.setAttribute(k, String(attrs[k]));
    if (text != null) el.textContent = text;
    if (parent) parent.appendChild(el);
    return el;
  }
  function svgText(parent, attrs, text) { var t = svgEl('text', attrs, parent); t.textContent = text; return t; }
  function clear(el) { while (el && el.firstChild) el.removeChild(el.firstChild); }

  function pad2(n) { return (n < 10 ? '0' : '') + n; }
  function fmtClock(ts) {
    if (ts == null || !isFinite(ts)) return '--:--:--';
    if (WR.time && typeof WR.time.fmt === 'function') return WR.time.fmt(ts);
    var d = new Date(ts);
    return pad2(d.getUTCHours()) + ':' + pad2(d.getUTCMinutes()) + ':' + pad2(d.getUTCSeconds());
  }
  function fmtDur(ms) {
    if (typeof WR.fmtDuration === 'function') return WR.fmtDuration(ms);
    var m = Math.round(Math.abs(ms) / 60000);
    return m < 1 ? Math.round(Math.abs(ms) / 1000) + ' s' : m + ' min';
  }
  function fmtRate(r) {
    var p = r * 100;
    if (p >= 99.5) return '100%';
    if (p >= 10) return Math.round(p) + '%';
    var s = (Math.round(p * 10) / 10).toFixed(1).replace(/\.0$/, '');
    return s + '%';
  }

  // Text measurement on a canvas with the page's real font stacks (read from the SPEC tokens).
  var mctx;
  function measure(str, size, weight, family, spacingEm) {
    str = String(str == null ? '' : str);
    if (mctx === undefined) {
      try { mctx = document.createElement('canvas').getContext('2d') || null; } catch (e) { mctx = null; }
    }
    var w;
    if (mctx) { mctx.font = (weight || 400) + ' ' + size + 'px ' + family; w = mctx.measureText(str).width; }
    else w = str.length * size * 0.56;
    return w + (spacingEm ? str.length * spacingEm * size : 0);
  }
  function readFonts(el) {
    var body = '', display = '';
    try {
      var cs = getComputedStyle(el);
      body = cs.getPropertyValue('--font-body').trim();
      display = cs.getPropertyValue('--font-display').trim();
    } catch (e) { /* detached */ }
    return {
      body: body || "'Atkinson Hyperlegible Next','Atkinson Hyperlegible',system-ui,sans-serif",
      display: display || "'Barlow Condensed','Arial Narrow',sans-serif"
    };
  }
  // Shorten to fit; middle ellipsis keeps the distinguishing tail of node and host names.
  function fitText(str, maxW, widthOf, middle) {
    if (widthOf(str) <= maxW) return str;
    var lo = 1, hi = str.length - 1, best = str.charAt(0) + '…';
    while (lo <= hi) {
      var mid = (lo + hi) >> 1, cand;
      if (middle) cand = str.slice(0, Math.ceil(mid / 2)) + '…' + str.slice(str.length - Math.floor(mid / 2));
      else cand = str.slice(0, mid).replace(/[-_.\s]+$/, '') + '…';
      if (widthOf(cand) <= maxW) { best = cand; lo = mid + 1; } else hi = mid - 1;
    }
    return best;
  }

  // Component names: keep a fixed tail so siblings stay distinguishable. Kubernetes node names keep
  // their last 10 characters (the VM or instance suffix); other names keep their last dash segment
  // when it is short ("…-canary"). The head shrinks to fit.
  function fitName(str, maxW, widthOf, type) {
    if (widthOf(str) <= maxW) return str;
    var tail = '';
    if (type === 'external') return fitText(str, maxW, widthOf, true);
    var isNode = type === 'node';
    if (isNode) tail = str.indexOf('.') >= 0 ? '' : str.slice(-10);
    else {
      var cut = str.lastIndexOf('-');
      if (cut > 2 && str.length - cut - 1 >= 2 && str.length - cut - 1 <= 8) tail = str.slice(cut);
    }
    if (!tail) return fitText(str, maxW, widthOf, isNode);
    var head = str.slice(0, str.length - tail.length);
    var lo = 1, hi = head.length - 1, best = null;
    while (lo <= hi) {
      var mid = (lo + hi) >> 1;
      var cand = head.slice(0, mid).replace(/[-_.\s]+$/, '') + '…' + tail.replace(/^[-_.]/, '');
      if (widthOf(cand) <= maxW) { best = cand; lo = mid + 1; } else hi = mid - 1;
    }
    return best && best.length > tail.length + 3 ? best : fitText(str, maxW, widthOf, isNode);
  }

  // ---------------------------------------------------------------------------------------------
  // Model: components, edges and their reveal times for the replay
  // ---------------------------------------------------------------------------------------------
  function normStatus(s) { return Object.prototype.hasOwnProperty.call(RANK, s) ? s : 'healthy'; }
  function normEdge(s) { return s === 'failing' || s === 'degraded' ? s : 'ok'; }
  function kindOf(n) {
    if (n.type === 'datastore' || n.type === 'external' || n.type === 'infra' || n.type === 'node') return n.type;
    return n.role === 'ingress' ? 'ingress' : 'service';
  }

  function buildModel(analysis) {
    var a = analysis && typeof analysis === 'object' ? analysis : {};
    var comps = [], byId = new Map();
    (Array.isArray(a.components) ? a.components : []).forEach(function (c) {
      if (!c || c.id == null) return;
      var id = String(c.id);
      if (byId.has(id)) return;
      var type = TYPE_ORDER.hasOwnProperty(c.type) ? c.type : 'service';
      var n = {
        id: id, c: c, name: String(c.name || id), type: type, role: c.role === 'ingress' ? 'ingress' : null,
        cluster: c.cluster ? String(c.cluster) : '', ns: c.namespace ? String(c.namespace) : '',
        status: normStatus(c.status), userFacing: !!c.userFacing, infra: type === 'infra' || type === 'node',
        out: [], inn: [], reveal: null
      };
      n.kind = kindOf(n);
      byId.set(id, n);
      comps.push(n);
    });
    var edges = [];
    (Array.isArray(a.edges) ? a.edges : []).forEach(function (e, i) {
      if (!e) return;
      var f = byId.get(String(e.from)), t = byId.get(String(e.to));
      if (!f || !t || f === t) return;
      var rate = num(e.errorRate);
      var ed = {
        id: 'e' + i, e: e, from: f, to: t, status: normEdge(e.status), calls: num(e.calls), errors: num(e.errors),
        rate: rate, labelled: rate != null && rate > 0.01, reveal: null
      };
      edges.push(ed);
      f.out.push(ed);
      t.inn.push(ed);
    });

    var w = a.window || {};
    var end = num(w.now) != null ? num(w.now) : num(w.end);
    var start = num(w.start);
    var fa = num(w.firstAnomaly);
    if (start != null && end != null && end < start) { var tmp = start; start = end; end = tmp; }

    comps.forEach(function (n) {
      if (n.status === 'healthy') return;
      n.reveal = num(n.c.firstErrorTs) != null ? num(n.c.firstErrorTs) : num(n.c.statusSince);
    });
    // At-risk and other untimed statuses: when the failing thing they call (2 hops) first appeared.
    comps.forEach(function (n) {
      if (n.status === 'healthy' || n.reveal != null) return;
      var best = null, frontier = [n], seen = new Set([n]);
      for (var hop = 0; hop < 2; hop++) {
        var next = [];
        frontier.forEach(function (x) {
          x.out.forEach(function (ed) {
            var y = ed.to;
            if (seen.has(y)) return;
            seen.add(y);
            next.push(y);
            if ((y.status === 'failing' || y.status === 'root') && y.reveal != null && (best == null || y.reveal < best)) best = y.reveal;
          });
        });
        frontier = next;
      }
      n.reveal = best != null ? best : end;
    });
    edges.forEach(function (ed) {
      if (ed.status === 'ok' && !ed.labelled) return;
      var r = num(ed.e.firstErrorTs);
      if (r == null) r = ed.to.reveal != null ? ed.to.reveal : ed.from.reveal != null ? ed.from.reveal : end;
      ed.reveal = r;
    });

    var root = null;
    comps.forEach(function (n) { if (n.status === 'root' && !root) root = n; });
    return { a: a, comps: comps, byId: byId, edges: edges, start: start, end: end, fa: fa, root: root };
  }

  function nodeStatusAt(m, n, t) {
    if (n.status === 'healthy' || t == null || m.end == null || t >= m.end || n.reveal == null) return n.status;
    return n.reveal <= t ? n.status : 'healthy';
  }
  function edgeShownAt(m, ed, t) {
    // returns { status, label } for time t
    if (t == null || m.end == null || t >= m.end || ed.reveal == null) return { status: ed.status, label: ed.labelled };
    var on = ed.reveal <= t;
    return { status: on ? ed.status : 'ok', label: on && ed.labelled };
  }
  function statsAt(m, t, laneKey) {
    var affected = 0, total = 0;
    m.comps.forEach(function (n) {
      if (laneKey != null && n.cluster !== laneKey) return;
      total++;
      if (nodeStatusAt(m, n, t) !== 'healthy') affected++;
    });
    return { affected: affected, total: total };
  }

  // ---------------------------------------------------------------------------------------------
  // Layout
  // ---------------------------------------------------------------------------------------------
  function isEntry(n) { return n.role === 'ingress' || n.userFacing; }
  function isSinkType(n) { return n.type === 'datastore' || n.type === 'external'; }
  function nodeCmp(p, q) {
    return (isEntry(q) - isEntry(p)) || ((q.role === 'ingress') - (p.role === 'ingress')) ||
      (RANK[p.status] - RANK[q.status]) || (TYPE_ORDER[p.type] - TYPE_ORDER[q.type]) ||
      (p.name < q.name ? -1 : p.name > q.name ? 1 : 0) || (p.id < q.id ? -1 : p.id > q.id ? 1 : 0);
  }

  function buildLanes(m) {
    var order = [], byKey = new Map();
    function lane(name) {
      var key = name || '';
      if (!byKey.has(key)) {
        var L = { key: key, name: name || 'Unassigned', unassigned: !name, cluster: null, main: [], infra: [] };
        byKey.set(key, L);
        order.push(L);
      }
      return byKey.get(key);
    }
    (Array.isArray(m.a.clusters) ? m.a.clusters : []).forEach(function (cl) {
      if (cl && cl.name) lane(String(cl.name)).cluster = cl;
    });
    m.comps.forEach(function (n) {
      var L = lane(n.cluster);
      (n.infra ? L.infra : L.main).push(n);
      n.lane = L;
    });
    var lanes = order.filter(function (L) { return L.main.length + L.infra.length > 0; });
    var named = lanes.filter(function (L) { return !L.unassigned; });
    return named.concat(lanes.filter(function (L) { return L.unassigned; }));
  }

  // Structure of one lane's main area: layers, order, vertical positions (relative), column widths.
  function structureLane(L, ctx) {
    var nodes = L.main.slice().sort(nodeCmp);
    var set = new Set(nodes);
    var intra = [];
    nodes.forEach(function (n) { n.out.forEach(function (ed) { if (set.has(ed.to)) intra.push(ed); }); });

    // No calls at all inside this lane: a wrapped grid reads better than empty columns (and fits a phone).
    var hasChan = nodes.some(function (n) { return n.out.some(function (ed) { return ed.to.lane === L && ed.to.infra; }); });
    if (!intra.length && !hasChan && nodes.length) {
      var cw = G.nodeMinW;
      nodes.forEach(function (n) { cw = Math.max(cw, ctx.nodeW(n)); });
      return {
        grid: nodes, cellW: cw, layers: [], items: new Map(), chains: new Map(), back: new Set(), nL: 0, colW: [], mainH: 0,
        hasEntryStub: nodes.some(function (n) { return n.userFacing && !n.inn.length; })
      };
    }

    // 1. Break cycles: depth-first from entry points; an edge back into the current path is a back edge.
    var state = new Map(), back = new Set();
    function dfs(n) {
      state.set(n, 1);
      n.out.slice().sort(function (x, y) { return nodeCmp(x.to, y.to); }).forEach(function (ed) {
        if (!set.has(ed.to)) return;
        var s = state.get(ed.to);
        if (s === 1) back.add(ed);
        else if (!s) dfs(ed.to);
      });
      state.set(n, 2);
    }
    nodes.forEach(function (n) { if (!state.get(n)) dfs(n); });
    var fwd = intra.filter(function (ed) { return !back.has(ed); });

    // 2. Longest-path layering (Kahn's order over the acyclic edge set).
    var indeg = new Map(), outF = new Map(), layer = new Map();
    nodes.forEach(function (n) { indeg.set(n, 0); outF.set(n, []); });
    fwd.forEach(function (ed) { indeg.set(ed.to, indeg.get(ed.to) + 1); outF.get(ed.from).push(ed); });
    var queue = nodes.filter(function (n) { return indeg.get(n) === 0; });
    queue.forEach(function (n) { layer.set(n, 0); });
    for (var qi = 0; qi < queue.length; qi++) {
      var u = queue[qi];
      outF.get(u).forEach(function (ed) {
        var v = ed.to;
        layer.set(v, Math.max(layer.get(v) || 0, layer.get(u) + 1));
        indeg.set(v, indeg.get(v) - 1);
        if (indeg.get(v) === 0) queue.push(v);
      });
    }
    nodes.forEach(function (n) { if (!layer.has(n)) layer.set(n, 0); }); // unreachable safety net

    var connected = new Set();
    intra.forEach(function (ed) { connected.add(ed.from); connected.add(ed.to); });
    var maxL = -1;
    connected.forEach(function (n) { maxL = Math.max(maxL, layer.get(n)); });
    // Datastores and external dependencies that call nothing go to the last column.
    connected.forEach(function (n) {
      if (isSinkType(n) && outF.get(n).length === 0) layer.set(n, Math.max(layer.get(n), maxL));
    });

    // 3. Components with no calls inside this lane.
    var iso = nodes.filter(function (n) { return !connected.has(n); });
    if (maxL < 0) {
      iso.forEach(function (n) { layer.set(n, isEntry(n) ? 0 : isSinkType(n) ? 2 : 1); });
    } else {
      var counts = [];
      for (var i = 0; i <= maxL; i++) counts[i] = 0;
      connected.forEach(function (n) { counts[layer.get(n)]++; });
      iso.forEach(function (n) {
        var l;
        if (isEntry(n)) l = 0;
        else if (isSinkType(n)) l = maxL;
        else if (maxL >= 2) { l = 1; for (var k = 2; k < maxL; k++) if (counts[k] < counts[l]) l = k; }
        else l = maxL;
        layer.set(n, l);
        counts[l]++;
      });
    }
    var used = [];
    nodes.forEach(function (n) { if (used.indexOf(layer.get(n)) < 0) used.push(layer.get(n)); });
    used.sort(function (x, y) { return x - y; });
    nodes.forEach(function (n) { layer.set(n, used.indexOf(layer.get(n))); });
    var nL = used.length;

    // 4. Items per layer, with pass-through slots for edges that skip columns.
    var layers = [];
    for (var li = 0; li < nL; li++) layers.push([]);
    var items = new Map();
    var isoSet = new Set(iso);
    nodes.filter(function (n) { return !isoSet.has(n); }).concat(iso).forEach(function (n) {
      var it = { node: n, dummy: false, h: G.nodeH, up: [], down: [], layer: layer.get(n), fixed: isoSet.has(n) };
      items.set(n, it);
      layers[it.layer].push(it);
    });
    var chains = new Map();
    fwd.forEach(function (ed) {
      var a = items.get(ed.from), b = items.get(ed.to), prev = a, chain = [a];
      for (var l = a.layer + 1; l < b.layer; l++) {
        var d = { dummy: true, edge: ed, h: G.dummyH, up: [prev], down: [], layer: l };
        prev.down.push(d);
        layers[l].push(d);
        chain.push(d);
        prev = d;
      }
      prev.down.push(b);
      b.up.push(prev);
      chain.push(b);
      chains.set(ed, chain);
    });
    // Isolated components stay at the bottom of their column, below anything connected.
    layers.forEach(function (arr) {
      arr.sort(function (p, q) { return (p.fixed ? 1 : 0) - (q.fixed ? 1 : 0); });
    });

    // 5. Barycentre ordering; keep the ordering with the fewest crossings.
    function sweep(l, useUp) {
      var arr = layers[l], ref = useUp ? layers[l - 1] : layers[l + 1];
      if (!ref || arr.length < 2) return;
      var pos = new Map();
      ref.forEach(function (it, i) { pos.set(it, i); });
      var keyed = arr.map(function (it, i) {
        var nb = useUp ? it.up : it.down, k = null;
        if (nb.length && !it.fixed) { var s = 0; nb.forEach(function (x) { s += pos.get(x); }); k = s / nb.length; }
        return { it: it, i: i, k: k };
      });
      var movable = keyed.filter(function (x) { return x.k != null; })
        .sort(function (p, q) { return (p.k - q.k) || (p.i - q.i); });
      var out = new Array(arr.length), mi = 0;
      keyed.forEach(function (x) { if (x.k == null) out[x.i] = x.it; });
      for (var j = 0; j < out.length; j++) if (!out[j]) out[j] = movable[mi++].it;
      layers[l] = out;
    }
    function crossings() {
      var total = 0;
      for (var l = 0; l < nL - 1; l++) {
        var pa = new Map(), pb = new Map(), segs = [];
        layers[l].forEach(function (it, i) { pa.set(it, i); });
        layers[l + 1].forEach(function (it, i) { pb.set(it, i); });
        layers[l].forEach(function (it) { it.down.forEach(function (d) { segs.push([pa.get(it), pb.get(d)]); }); });
        for (var i = 0; i < segs.length; i++) {
          for (var j = i + 1; j < segs.length; j++) {
            if ((segs[i][0] - segs[j][0]) * (segs[i][1] - segs[j][1]) < 0) total++;
          }
        }
      }
      return total;
    }
    var best = layers.map(function (a) { return a.slice(); }), bestC = crossings();
    for (var iter = 0; iter < 6 && bestC > 0; iter++) {
      for (var l1 = 1; l1 < nL; l1++) sweep(l1, true);
      for (var l2 = nL - 2; l2 >= 0; l2--) sweep(l2, false);
      var c = crossings();
      if (c < bestC) { bestC = c; best = layers.map(function (a) { return a.slice(); }); }
    }
    layers = best;

    // 6. Vertical positions: isotonic fit to neighbour barycentres under minimum separations.
    function sep(a, b) {
      var g = (a.dummy && b.dummy) ? 8 : (a.dummy || b.dummy) ? 14 : G.rowGap;
      if (!b.dummy && b.node.status === 'root') g += G.rootExtra;
      if (!a.dummy && a.node.note) g += G.noteH;
      return a.h / 2 + g + b.h / 2;
    }
    layers.forEach(function (arr) {
      var y = 0;
      arr.forEach(function (it, i) { if (i) y += sep(arr[i - 1], it); it.y = y; });
    });
    function place(arr, desiredOf) {
      var n = arr.length;
      if (!n) return;
      var off = [0];
      for (var i = 1; i < n; i++) off[i] = off[i - 1] + sep(arr[i - 1], arr[i]);
      var blocks = [];
      for (var j = 0; j < n; j++) {
        var d = desiredOf(arr[j]);
        blocks.push({ w: d.w, wz: d.w * (d.v - off[j]), n: 1 });
        while (blocks.length > 1) {
          var B = blocks[blocks.length - 1], A = blocks[blocks.length - 2];
          if (A.wz / A.w <= B.wz / B.w) break;
          A.w += B.w; A.wz += B.wz; A.n += B.n;
          blocks.pop();
        }
      }
      var idx = 0;
      blocks.forEach(function (B) {
        var z = B.wz / B.w;
        for (var k = 0; k < B.n; k++, idx++) arr[idx].y = z + off[idx];
      });
    }
    function meanY(list) { var s = 0; list.forEach(function (x) { s += x.y; }); return s / list.length; }
    function desire(which) {
      return function (it) {
        var nb = which === 'up' ? it.up : which === 'down' ? it.down : it.up.concat(it.down);
        if (!nb.length) return { v: it.y, w: 0.01 };
        return { v: meanY(nb), w: it.dummy ? 2 : 1 };
      };
    }
    for (var pass = 0; pass < 4; pass++) {
      for (var a1 = 1; a1 < nL; a1++) place(layers[a1], desire('up'));
      for (var a2 = nL - 2; a2 >= 0; a2--) place(layers[a2], desire('down'));
    }
    for (var a3 = 0; a3 < nL; a3++) place(layers[a3], desire('both'));
    // Components with no calls in this lane sit directly under the connected ones, not adrift.
    layers.forEach(function (arr) {
      for (var i = 1; i < arr.length; i++) if (arr[i].fixed) arr[i].y = arr[i - 1].y + sep(arr[i - 1], arr[i]);
    });
    var minTop = Infinity, maxBot = -Infinity;
    layers.forEach(function (arr) {
      arr.forEach(function (it) {
        minTop = Math.min(minTop, it.y - it.h / 2 - (!it.dummy && it.node.status === 'root' ? G.rootExtra : 0));
        maxBot = Math.max(maxBot, it.y + it.h / 2 + (!it.dummy && it.node.note ? G.noteH : 0));
      });
    });
    if (!isFinite(minTop)) { minTop = 0; maxBot = 0; }
    layers.forEach(function (arr) { arr.forEach(function (it) { it.y -= minTop; }); });

    // 7. Column widths from measured names.
    var colW = layers.map(function (arr) {
      var w = G.nodeMinW;
      arr.forEach(function (it) { if (!it.dummy) w = Math.max(w, ctx.nodeW(it.node)); });
      return w;
    });
    // the narrowest each column may go without cutting a name
    var colFloor = layers.map(function (arr) {
      var w = 132;
      arr.forEach(function (it) { if (!it.dummy) w = Math.max(w, ctx.fitW(it.node)); });
      return w;
    });

    return {
      layers: layers, items: items, chains: chains, back: back, nL: nL, colW: colW, colFloor: colFloor,
      mainH: nodes.length ? maxBot - minTop : 0,
      hasEntryStub: layers.length > 0 && layers[0].some(function (it) { return !it.dummy && it.node.userFacing && !it.node.inn.length; })
    };
  }

  function laneNatural(L) {
    var mainW = 0;
    if (L.s.grid) mainW = L.s.cellW;
    else {
      L.s.colW.forEach(function (w) { mainW += w; });
      L.gaps.forEach(function (g) { mainW += g; });
    }
    L.mainW = mainW;
    var body = L.padLeft + Math.max(mainW, Math.min(L.infraW, Math.max(mainW, 3 * (G.nodeMinW + G.infraGap)))) + L.padRight;
    return Math.max(body, G.lanePadX + 8 + L.headNameW + 16 + 96 + G.lanePadX);
  }

  function layout(m, avail, fonts) {
    var nameW = function (s) { return measure(s, 14, 600, fonts.body); };
    var subW = function (s) { return measure(s, 12, 400, fonts.body); };

    var nodeInfo = new Map();
    function subText(n, status) {
      var base = n.type === 'node' ? 'node' : n.type === 'external' ? 'external' :
        n.type === 'datastore' ? 'database' + (n.ns ? ' \u00b7 ' + n.ns : '') : (n.ns || 'no namespace');
      var word = STATUS_WORD[status] || '';
      return { base: base, word: word };
    }
    m.comps.forEach(function (n) {

      // the infrastructure row has room, and Kubernetes node names differ only at the end
      var maxW = n.infra ? G.infraMaxW : G.nodeMaxW, nameMax = maxW - G.padL - G.padR;
      var label = fitName(n.name, nameMax, nameW, n.type);
      var st = subText(n, n.status);
      var sw = subW(st.base) + (st.word ? measure(' · ' + st.word, 12, 700, fonts.body) : 0);
      var w = Math.ceil(G.padL + Math.max(nameW(label), Math.min(sw, nameMax)) + G.padR + 1);
      nodeInfo.set(n, { label: label, base: fitText(st.base, nameMax - 70, subW, false), w: clamp(w, G.nodeMinW, maxW), fit: clamp(w, 132, maxW) });
    });
    var ctx = { nodeW: function (n) { return nodeInfo.get(n).w; }, fitW: function (n) { return nodeInfo.get(n).fit; } };

    var lanes = buildLanes(m);

    // Calls between clusters are not drawn as lines across other lanes; both ends get a short note.
    m.comps.forEach(function (n) { n.xOut = []; n.xIn = []; n.note = null; });
    m.edges.forEach(function (ed) {
      if (ed.from.lane === ed.to.lane) return;
      ed.cross = true;
      ed.from.xOut.push(ed);
      ed.to.xIn.push(ed);
    });
    m.comps.forEach(function (n) {
      var parts = [];
      function where(x) { return x.cluster ? ' in ' + x.cluster : ' (no cluster)'; }
      if (n.xOut.length) parts.push('Calls ' + n.xOut[0].to.name + where(n.xOut[0].to) + (n.xOut.length > 1 ? ' and ' + (n.xOut.length - 1) + ' more' : ''));
      if (n.xIn.length) parts.push('Called by ' + n.xIn[0].from.name + where(n.xIn[0].from) + (n.xIn.length > 1 ? ' and ' + (n.xIn.length - 1) + ' more' : ''));
      if (!parts.length) return;
      n.note = parts.join('; ');
      n.noteFull = n.xOut.map(function (e) { return 'Calls ' + e.to.name + where(e.to) + ' (' + e.status + ')'; })
        .concat(n.xIn.map(function (e) { return 'Called by ' + e.from.name + where(e.from) + ' (' + e.status + ')'; }));
      n.noteBad = n.xOut.concat(n.xIn).some(function (e) { return e.status !== 'ok'; });
    });
    var anyBad = lanes.some(function (L) { return L.cluster && L.cluster.status && L.cluster.status !== 'healthy'; });

    // Pass 1: structure + natural widths.
    lanes.forEach(function (L) {
      L.s = structureLane(L, ctx);
      // calls into this lane's infrastructure row, grouped by the caller's column
      var infraSet = new Set(L.infra), runs = [];
      for (var i = 0; i < L.s.nL; i++) runs.push([]);
      L.chan = [];
      L.main.forEach(function (n) {
        n.out.forEach(function (ed) {
          if (infraSet.has(ed.to)) { var col = L.s.items.get(n).layer; runs[col].push(ed); L.chan.push(ed); ed.chanCol = col; }
        });
      });
      L.runs = runs;
      // Each gap must fit its error labels and its drops into the infrastructure row.
      var need = [];
      for (var g = 0; g < L.s.nL - 1; g++) need.push(Math.max(G.gapMin, G.chanInset + runs[g].length * G.chanStep + 30));
      L.s.chains.forEach(function (ch, ed) {
        if (!ed.labelled) return;
        var lw = measure(fmtRate(ed.rate) + ' errors', 12, 700, fonts.body) + 14;
        var col = ch[0].layer;
        if (col < need.length) need[col] = Math.max(need[col], Math.ceil(lw + 16));
      });
      L.gapNeed = need;
      L.gaps = need.map(function (n) { return Math.max(n, G.gap); });
      L.padLeft = G.lanePadX + 4 + (L.s.hasEntryStub ? G.entryPad : 0);
      var lastRuns = L.s.nL ? runs[L.s.nL - 1].length : 0;
      L.padRight = Math.max(G.lanePadX, lastRuns ? G.chanInset + lastRuns * G.chanStep + 14 : 0);
      var mainW = 0;
      L.s.colW.forEach(function (w) { mainW += w; });
      L.gaps.forEach(function (g2) { mainW += g2; });
      if (L.s.grid) mainW = L.s.cellW;
      L.mainW = mainW;
      var infraW = 0;
      L.infra.forEach(function (n, i) { infraW += nodeInfo.get(n).w + (i ? G.infraGap : 0); });
      L.infraW = infraW;
      var headName = L.name.toUpperCase();
      L.headName = headName;
      L.headNameW = measure(headName, 20, 600, fonts.display, 0.06);
      L.natural = laneNatural(L);
      L.sib = null;
      if (L.unassigned) L.sib = 'no cluster named in the evidence';
      else if (L.cluster && L.cluster.status === 'healthy') {
        var names = new Set(L.main.map(function (n) { return n.name; }));
        var other = lanes.filter(function (F) {
          return F !== L && F.cluster && F.cluster.status && F.cluster.status !== 'healthy' &&
            F.main.some(function (n) { return names.has(n.name); });
        })[0];
        if (other) L.sib = 'healthy sibling of ' + other.name;
      }
    });
    // Slightly too wide for the box: give back gap space down to what labels and drops need, then,
    // when it is still a little over, narrow the widest columns (names are re-fitted when drawn).
    if (avail > 0) {
      lanes.forEach(function (L) {
        var over = L.natural - avail;
        if (over > 0 && L.gaps.length) {
          var spare = 0;
          L.gaps.forEach(function (g, i) { spare += g - L.gapNeed[i]; });
          if (spare > 0) {
            var f = Math.min(1, over / spare);
            L.gaps = L.gaps.map(function (g, i) { return g - (g - L.gapNeed[i]) * f; });
            L.natural = laneNatural(L);
          }
        }
        over = L.natural - avail;
        if (over > 0 && L.s.colW.length) {
          var room = 0, fl = L.s.colFloor;
          L.s.colW.forEach(function (w, i) { room += Math.max(0, w - fl[i]); });
          if (room > 0) {
            var f2 = Math.min(1, over / room);
            L.s.colW = L.s.colW.map(function (w, i) { return w - Math.max(0, w - fl[i]) * f2; });
            L.natural = laneNatural(L);
          }
        }
        // A few pixels over: take them from the right padding rather than scroll the whole map.
        over = L.natural - avail;
        if (over > 0 && over <= 8 && L.padRight - over >= 10) {
          L.padRight -= over;
          L.natural = laneNatural(L);
        }
      });
    }
    var W = Math.max(Math.floor(avail || 0), 320);
    // Round the shrunk width, not up: float residue (982.0001) must not add a 1px sideways scroll.
    lanes.forEach(function (L) { W = Math.max(W, Math.ceil(L.natural - 0.5)); });

    // Pass 2: positions.
    var pos = new Map(); // node -> {x,y,w,h}
    var y = 0, laneOut = [];
    lanes.forEach(function (L, li) {
      if (li) y += G.laneGap;
      var top = y, s = L.s;
      // spread spare width across the column gaps (capped), keep left alignment
      var extra = W - L.natural;
      if (extra > 0 && L.gaps.length) {
        var add = Math.min(extra / L.gaps.length, G.gapMaxExtra);
        L.gaps = L.gaps.map(function (g) { return g + add; });
      }
      var colX = [], x = L.padLeft;
      for (var c = 0; c < s.nL; c++) { colX.push(x); x += s.colW[c] + (c < s.nL - 1 ? L.gaps[c] : 0); }
      L.colX = colX;
      // Header: name + pill, then the count; a long note drops to its own line on narrow maps.
      L.headH = G.laneHead;
      L.sibLine = false;
      var visibleW = avail > 0 ? Math.min(W, avail) : W;
      if (L.sib && measure('99 of 99 components affected \u00b7 ' + L.sib, 13, 400, fonts.body) > visibleW - 2 * G.lanePadX - 12) {
        L.sibLine = true;
        L.headH += 18;
      }
      var mainTop = top + L.headH;
      var hasMain = L.main.length > 0;
      if (s.grid) {
        var gx = 24, cw = s.cellW, anyRoot = s.grid.some(function (n) { return n.status === 'root'; });
        var noteX = s.grid.some(function (n) { return n.note; }) ? G.noteH : 0;
        var perRow = Math.max(1, Math.floor((W - L.padLeft - L.padRight + gx) / (cw + gx)));
        var step = G.nodeH + G.rowGap + noteX + (anyRoot ? G.rootExtra : 0);
        var top0 = mainTop + (anyRoot ? G.rootExtra : 0);
        s.grid.forEach(function (n, i) {
          var r = Math.floor(i / perRow), c = i % perRow;
          pos.set(n, { x: L.padLeft + c * (cw + gx), y: top0 + r * step, w: cw, h: G.nodeH, col: c, row: 'main' });
        });
        var rows = Math.ceil(s.grid.length / perRow);
        s.mainH = (anyRoot ? G.rootExtra : 0) + rows * step - G.rowGap;
        colX = [];
        L.gridRight = L.padLeft + Math.min(perRow, s.grid.length) * (cw + gx) - gx;
      }
      s.layers.forEach(function (arr, c) {
        arr.forEach(function (it) {
          it.absY = mainTop + it.y;
          if (!it.dummy) pos.set(it.node, { x: colX[c], y: mainTop + it.y - G.nodeH / 2, w: s.colW[c], h: G.nodeH, col: c, row: 'main' });
        });
      });
      var mainBottom = hasMain ? mainTop + s.mainH : top + L.headH - 20;
      L.mainBottom = mainBottom;
      L.mainRight = s.grid ? L.gridRight : colX.length ? colX[colX.length - 1] + s.colW[s.nL - 1] : L.padLeft;
      laneOut.push({ L: L, top: top });
      L.top = top;
      L.mainTop = mainTop;
      y = mainBottom;

      // right-side ports of main nodes: calls to later columns sorted by where they go, infra calls last
      L.main.forEach(function (n) {
        var p = pos.get(n), list = [];
        n.out.forEach(function (ed) {
          var ch = s.chains.get(ed);
          if (ch) list.push({ ed: ed, k: ch[1].absY });
          else if (ed.chanCol != null && ed.to.lane === L) list.push({ ed: ed, k: 1e9 });
        });
        list.sort(function (a, b) { return a.k - b.k; });
        var n2 = list.length, step = n2 > 1 ? Math.min(10, (G.nodeH - 18) / (n2 - 1)) : 0;
        list.forEach(function (o, i) { o.ed.sp = { x: p.x + p.w, y: p.y + G.nodeH / 2 + (i - (n2 - 1) / 2) * step }; });
      });
      // run x for infrastructure calls: the lowest caller takes the lane nearest its column
      L.runs.forEach(function (list, c) {
        var colRight = colX[c] + s.colW[c];
        list.slice().sort(function (a, b) { return b.sp.y - a.sp.y; }).forEach(function (ed, k) {
          ed.runX = colRight + G.chanInset + k * G.chanStep;
        });
      });

      // infrastructure row
      if (L.infra.length) {
        var sepY = hasMain ? mainBottom + G.infraSepGap : top + L.headH - 8;
        var rowTop = hasMain ? sepY + (L.chan.length ? G.infraFan : G.infraPlain) : sepY + 14;
        L.sepY = hasMain ? sepY : null;
        var want = L.infra.map(function (n) {
          var xs = n.inn.filter(function (ed) { return ed.runX != null; }).map(function (ed) { return ed.runX; });
          var d = xs.length ? xs.reduce(function (a, b) { return a + b; }, 0) / xs.length : null;
          return { n: n, d: d };
        });
        want.sort(function (p, q) {
          if ((p.d == null) !== (q.d == null)) return p.d == null ? 1 : -1;
          if (p.d != null && p.d !== q.d) return p.d - q.d;
          return nodeCmp(p.n, q.n);
        });
        var right = W - L.padRight, placed = [], cx = L.padLeft, ry = rowTop, extra2 = [];
        var infraNotes = L.infra.some(function (n) { return n.note; }) ? G.noteH : 0;
        // 1. components called from the main area: under their callers, left to right
        want.forEach(function (o) {
          if (o.d == null) return;
          var w = nodeInfo.get(o.n).w;
          var x0 = Math.max(cx, Math.min(o.d - w / 2, right - w));
          if (x0 + w > right && placed.length) { extra2.push(o); return; }
          placed.push({ x: x0, w: w });
          pos.set(o.n, { x: x0, y: ry, w: w, h: G.nodeH, row: 'infra' });
          cx = x0 + w + G.infraGap;
        });
        // 2. everything else: first free slot in the row, then further rows
        var rest = want.filter(function (o) { return o.d == null; }).concat(extra2);
        var rowX = null;
        rest.forEach(function (o) {
          var w = nodeInfo.get(o.n).w;
          if (rowX == null) {
            var cands = [L.padLeft].concat(placed.map(function (b) { return b.x + b.w + G.infraGap; }));
            cands.sort(function (a, b) { return a - b; });
            for (var i = 0; i < cands.length; i++) {
              var x1 = cands[i];
              if (x1 + w > right) continue;
              var clash = placed.some(function (b) { return x1 < b.x + b.w + G.infraGap && x1 + w + G.infraGap > b.x; });
              if (!clash) {
                placed.push({ x: x1, w: w });
                pos.set(o.n, { x: x1, y: ry, w: w, h: G.nodeH, row: 'infra' });
                return;
              }
            }
            rowX = L.padLeft;
            ry += G.nodeH + G.infraRowGap + infraNotes;
          }
          if (rowX > L.padLeft && rowX + w > right) { rowX = L.padLeft; ry += G.nodeH + G.infraRowGap + infraNotes; }
          pos.set(o.n, { x: rowX, y: ry, w: w, h: G.nodeH, row: 'infra' });
          rowX += w + G.infraGap;
        });
        y = ry + G.nodeH + infraNotes;
        if (L.infra.some(function (n) { return n.status === 'root'; }) && L.chan.length) y += 14; // root tag sits below
      }
      y += G.lanePadB;
      L.bottom = y;
    });
    var H = Math.ceil(y);

    // Ports on the receiving side.
    var leftIn = new Map(), topIn = new Map();
    m.edges.forEach(function (ed) {
      var L = ed.from.lane, ch = L === ed.to.lane && L.s ? L.s.chains.get(ed) : null;
      if (ch) {
        var k = ch[ch.length - 2];
        var ky = k.dummy ? k.absY : pos.get(k.node).y + G.nodeH / 2;
        if (!leftIn.has(ed.to)) leftIn.set(ed.to, []);
        leftIn.get(ed.to).push({ ed: ed, k: ky });
      } else if (ed.runX != null) {
        if (!topIn.has(ed.to)) topIn.set(ed.to, []);
        topIn.get(ed.to).push({ ed: ed, k: ed.runX });
      }
    });
    leftIn.forEach(function (list, n) {
      var p = pos.get(n), cnt = list.length, step = cnt > 1 ? Math.min(10, (G.nodeH - 18) / (cnt - 1)) : 0;
      list.sort(function (a, b) { return a.k - b.k; });
      list.forEach(function (o, i) { o.ed.tp = { x: p.x, y: p.y + G.nodeH / 2 + (i - (cnt - 1) / 2) * step }; });
    });
    topIn.forEach(function (list, n) {
      var p = pos.get(n), cnt = list.length, step = cnt > 1 ? Math.min(18, (p.w - 28) / (cnt - 1)) : 0;
      list.sort(function (a, b) { return a.k - b.k; });
      list.forEach(function (o, i) { o.ed.tp = { x: p.x + p.w / 2 + (i - (cnt - 1) / 2) * step, y: p.y }; });
    });

    // Edge paths.
    var ARROW = 9;
    function cubic(a, b, c, d) { return 'C' + r1(b.x) + ' ' + r1(b.y) + ' ' + r1(c.x) + ' ' + r1(c.y) + ' ' + r1(d.x) + ' ' + r1(d.y); }
    function bez(p0, p1, p2, p3, t) {
      var u = 1 - t;
      return {
        x: u * u * u * p0.x + 3 * u * u * t * p1.x + 3 * u * t * t * p2.x + t * t * t * p3.x,
        y: u * u * u * p0.y + 3 * u * u * t * p1.y + 3 * u * t * t * p2.y + t * t * t * p3.y
      };
    }
    var edgesOut = [], maxCalls = 1;
    m.edges.forEach(function (ed) { if (ed.calls > maxCalls) maxCalls = ed.calls; });
    m.edges.forEach(function (ed) {
      if (ed.cross) return;
      var L = ed.from.lane, s = L.s, ch = L === ed.to.lane ? s.chains.get(ed) : null;
      var d, seg = null, kind;
      if (ch && ed.sp && ed.tp) {
        kind = 'flow';
        var pts = [ed.sp];
        for (var i = 1; i < ch.length - 1; i++) {
          var it = ch[i];
          pts.push({ x: L.colX[it.layer], y: it.absY, straight: false });
          pts.push({ x: L.colX[it.layer] + s.colW[it.layer], y: it.absY, straight: true });
        }
        var end = { x: ed.tp.x - ARROW, y: ed.tp.y };
        pts.push(end);
        d = 'M' + r1(pts[0].x) + ' ' + r1(pts[0].y);
        for (var j = 1; j < pts.length; j++) {
          var A = pts[j - 1], B = pts[j];
          if (B.straight) { d += 'L' + r1(B.x) + ' ' + r1(B.y); continue; }
          var dx = Math.max(16, (B.x - A.x) / 2);
          var c1 = { x: A.x + dx, y: A.y }, c2 = { x: B.x - dx, y: B.y };
          d += cubic(A, c1, c2, B);
          if (!seg) seg = [A, c1, c2, B];
        }
      } else if (ed.runX != null && ed.sp && ed.tp) {
        kind = 'chan';
        var sp = ed.sp, xr = ed.runX, yb = L.mainBottom + 4, tp = ed.tp, rr = 6;
        var endY = tp.y - ARROW;
        d = 'M' + r1(sp.x) + ' ' + r1(sp.y) + 'H' + r1(xr - rr) + 'Q' + r1(xr) + ' ' + r1(sp.y) + ' ' + r1(xr) + ' ' + r1(sp.y + rr);
        d += 'V' + r1(yb);
        var k2 = Math.max(16, (endY - yb) * 0.55);
        d += cubic(null, { x: xr, y: yb + k2 }, { x: tp.x, y: endY - k2 }, { x: tp.x, y: endY });
        seg = [{ x: xr, y: sp.y + rr }, { x: xr, y: sp.y + rr }, { x: xr, y: yb }, { x: xr, y: yb }];
      } else {
        kind = 'generic';
        var fp = pos.get(ed.from), tq = pos.get(ed.to);
        var fc = { x: fp.x + fp.w / 2, y: fp.y + fp.h / 2 }, tc = { x: tq.x + tq.w / 2, y: tq.y + tq.h / 2 };
        var P0, P1, P2, P3;
        if (s.back.has(ed)) {
          // a call back up the chain (a cycle): dashed arc over the top of both
          kind = 'back';
          P0 = { x: fc.x + 14, y: fp.y }; P3 = { x: tc.x + 14, y: tq.y - ARROW };
          var lift = 34 + 0.1 * Math.abs(P0.x - P3.x);
          var topY = Math.max(L.top + 66, Math.min(fp.y, tq.y) - lift);
          P1 = { x: P0.x, y: topY }; P2 = { x: P3.x, y: topY };
        } else if (tq.x > fp.x + fp.w + 24) {
          P0 = { x: fp.x + fp.w, y: fc.y }; P3 = { x: tq.x - ARROW, y: tc.y };
          var gx = Math.max(24, (P3.x - P0.x) / 2);
          P1 = { x: P0.x + gx, y: P0.y }; P2 = { x: P3.x - gx, y: P3.y };
        } else if (tq.y > fp.y + fp.h + 8) {
          P0 = { x: fc.x, y: fp.y + fp.h }; P3 = { x: tc.x, y: tq.y - ARROW };
          var gy = Math.max(24, (P3.y - P0.y) / 2);
          P1 = { x: P0.x, y: P0.y + gy }; P2 = { x: P3.x, y: P3.y - gy };
        } else if (tq.y + tq.h < fp.y - 8) {
          P0 = { x: fc.x, y: fp.y }; P3 = { x: tc.x, y: tq.y + tq.h + ARROW };
          var gu = Math.max(24, (P0.y - P3.y) / 2);
          P1 = { x: P0.x, y: P0.y - gu }; P2 = { x: P3.x, y: P3.y + gu };
        } else {
          // same row, pointing backwards: arc underneath both
          var sag = 46;
          P0 = { x: fc.x + 12, y: fp.y + fp.h }; P3 = { x: tc.x - 12, y: tq.y + tq.h + ARROW };
          P1 = { x: P0.x, y: P0.y + sag }; P2 = { x: P3.x, y: P3.y + sag };
        }
        d = 'M' + r1(P0.x) + ' ' + r1(P0.y) + cubic(P0, P1, P2, P3);
        seg = [P0, P1, P2, P3];
      }
      var width = 1.5 + 2.5 * Math.log(1 + Math.max(0, ed.calls || 0)) / Math.log(1 + maxCalls);
      edgesOut.push({ ed: ed, d: d, kind: kind, seg: seg, width: width, bez: bez });
    });

    // Edge labels: share of calls that failed, kept clear of nodes and of each other.
    var boxes = [];
    pos.forEach(function (p, n) {
      var rt = n.status === 'root';
      boxes.push({ x: p.x - (rt ? 7 : 4), y: p.y - (rt ? 17 : 4), w: p.w + (rt ? 14 : 8), h: p.h + (rt ? 34 : 8) });
    });
    function hit(b) {
      for (var i = 0; i < boxes.length; i++) {
        var o = boxes[i];
        if (b.x < o.x + o.w && b.x + b.w > o.x && b.y < o.y + o.h && b.y + b.h > o.y) return true;
      }
      return false;
    }
    edgesOut.slice().sort(function (a, b) { return EDGE_RANK[b.ed.status] - EDGE_RANK[a.ed.status]; }).forEach(function (eo) {
      if (!eo.ed.labelled || !eo.seg) return;
      var text = fmtRate(eo.ed.rate) + ' errors';
      var w = Math.ceil(measure(text, 12, 700, fonts.body)) + 14, h = G.labelH;
      var tries = [0.5, 0.38, 0.62, 0.28, 0.72, 0.2, 0.8], chosen = null, first = null;
      for (var i = 0; i < tries.length; i++) {
        var p = bez(eo.seg[0], eo.seg[1], eo.seg[2], eo.seg[3], tries[i]);
        var b = { x: p.x - w / 2, y: p.y - h / 2, w: w, h: h };
        if (!first) first = b;
        if (!hit(b)) { chosen = b; break; }
      }
      chosen = chosen || first;
      boxes.push(chosen);
      eo.label = { x: chosen.x, y: chosen.y, w: w, h: h, text: text };
    });

    return { W: W, H: H, lanes: lanes, pos: pos, nodeInfo: nodeInfo, edges: edgesOut, anyBad: anyBad, fonts: fonts };
  }

  // ---------------------------------------------------------------------------------------------
  // Drawing
  // ---------------------------------------------------------------------------------------------
  var GEAR = (function () {
    var pts = [];
    for (var i = 0; i < 8; i++) {
      var a = i * Math.PI / 4;
      [[-0.26, 5.1], [-0.14, 7.1], [0.14, 7.1], [0.26, 5.1]].forEach(function (p) {
        pts.push((8 + p[1] * Math.cos(a + p[0])).toFixed(2) + ' ' + (8 + p[1] * Math.sin(a + p[0])).toFixed(2));
      });
    }
    return 'M' + pts.join('L') + 'Z';
  })();
  var GLYPH = {
    service: [['path', { d: 'M8 1.6l5.5 3.2v6.4L8 14.4l-5.5-3.2V4.8z' }]],
    ingress: [['path', { d: 'M7 2.5h5a1.5 1.5 0 0 1 1.5 1.5v8a1.5 1.5 0 0 1-1.5 1.5H7M1.5 8h8M6.8 5.2L9.6 8l-2.8 2.8' }]],
    datastore: [['ellipse', { cx: 8, cy: 4, rx: 5.5, ry: 2.3 }],
      ['path', { d: 'M2.5 4v8c0 1.3 2.5 2.3 5.5 2.3s5.5-1 5.5-2.3V4M2.5 8c0 1.3 2.5 2.3 5.5 2.3s5.5-1 5.5-2.3' }]],
    external: [['circle', { cx: 8, cy: 8, r: 6.5 }], ['ellipse', { cx: 8, cy: 8, rx: 2.8, ry: 6.5 }], ['path', { d: 'M1.5 8h13' }]],
    infra: [['path', { d: GEAR }], ['circle', { cx: 8, cy: 8, r: 2.2 }]],
    node: [['rect', { x: 3.5, y: 3.5, width: 9, height: 9, rx: 1.5 }],
      ['path', { d: 'M6 1v2.5M10 1v2.5M6 12.5V15M10 12.5V15M1 6h2.5M1 10h2.5M12.5 6H15M12.5 10H15' }]]
  };
  function drawGlyph(parent, kind, x, y) {
    var g = svgEl('g', { 'class': 'n-glyph', transform: 'translate(' + x + ' ' + y + ')', 'aria-hidden': 'true' }, parent);
    (GLYPH[kind] || GLYPH.service).forEach(function (spec) {
      var attrs = { fill: 'none', stroke: 'currentColor', 'stroke-width': 1.5, 'stroke-linejoin': 'round', 'stroke-linecap': 'round' };
      for (var k in spec[1]) attrs[k] = spec[1][k];
      svgEl(spec[0], attrs, g);
    });
    return g;
  }
  function drawCrosshair(parent, x, y, cls) {
    var g = svgEl('g', { 'class': cls, transform: 'translate(' + x + ' ' + y + ')', 'aria-hidden': 'true' }, parent);
    svgEl('circle', { cx: 0, cy: 0, r: 4.2, fill: 'none', 'stroke-width': 1.5 }, g);
    svgEl('path', { d: 'M0 -7V-2.5M0 2.5V7M-7 0H-2.5M2.5 0H7', fill: 'none', 'stroke-width': 1.5, 'stroke-linecap': 'round' }, g);
    return g;
  }

  function nodeTitle(m, n) {
    var lines = [n.name];
    var where = TYPE_LABEL[n.kind] || 'Component';
    if (n.ns && n.type !== 'node') where += ' in namespace ' + n.ns;
    where += n.cluster ? ', cluster ' + n.cluster : ', no cluster named in the evidence';
    lines.push(where);
    lines.push('Status: ' + STATUS_LONG[n.status] + (n.userFacing ? ' · user-facing' : ''));
    var fe = num(n.c.firstErrorTs);
    if (fe != null) lines.push('First error ' + fmtClock(fe) + ' UTC');
    var cnt = n.c.counts || {};
    if (num(cnt.error) != null || num(cnt.warn) != null) lines.push((cnt.error || 0) + ' errors, ' + (cnt.warn || 0) + ' warnings in the evidence');
    if (n.noteFull) n.noteFull.forEach(function (x) { lines.push(x); });
    lines.push('Select to list its signals.');
    return lines.join('\n');
  }
  function edgeTitle(ed) {
    var s = ed.from.name + ' calls ' + ed.to.name;
    var parts = [];
    if (ed.calls != null) parts.push(ed.calls + (ed.calls === 1 ? ' call' : ' calls'));
    if (ed.errors != null) parts.push(ed.errors + ' failed' + (ed.rate != null ? ' (' + fmtRate(ed.rate) + ')' : ''));
    var p95 = num(ed.e.p95ms);
    if (p95 != null) parts.push('95th-percentile latency ' + fmtDur(p95));
    return s + (parts.length ? ': ' + parts.join(', ') : '') + '.';
  }
  function ariaFor(n, status) {
    return n.name + ', ' + STATUS_LONG[status] + (n.userFacing ? ', user-facing' : '') + ', ' +
      (TYPE_LABEL[n.kind] || 'component').toLowerCase() + (n.ns && n.type !== 'node' ? ' in ' + n.ns : '');
  }

  function drawMap(inst, lay, k) {
    var m = inst.model, svg = inst.svg, pfx = 'wrm' + inst.id + '-';
    clear(svg);
    var sw = k < 1 ? Math.floor(lay.W * k) : lay.W, sh = k < 1 ? Math.round(lay.H * k) : lay.H;
    svg.setAttribute('width', sw);
    svg.setAttribute('height', sh);
    svg.setAttribute('viewBox', '0 0 ' + lay.W + ' ' + lay.H);
    svg.style.width = sw + 'px';
    svg.style.height = sh + 'px';
    var affected = statsAt(m, null).affected;
    svg.setAttribute('aria-label', 'Blast radius map: ' + m.comps.length + ' components in ' + lay.lanes.length +
      (lay.lanes.length === 1 ? ' lane' : ' lanes') + ', ' + affected + ' affected' +
      (m.root ? '. Suspected root: ' + m.root.name : '') + '. Use the arrow keys to move between components, Home and End for the first and last.');
    var title = svgEl('title', null, svg);
    title.textContent = 'Blast radius map';

    var defs = svgEl('defs', null, svg);
    ['ok', 'degraded', 'failing', 'entry'].forEach(function (k) {
      var mk = svgEl('marker', {
        id: pfx + 'mk-' + k, viewBox: '0 0 10 10', refX: 1, refY: 5, markerWidth: 10, markerHeight: 10,
        markerUnits: 'userSpaceOnUse', orient: 'auto', 'class': 'wr-mk wr-mk-' + k
      }, defs);
      svgEl('path', { d: 'M0 0.6L9.6 5L0 9.4z' }, mk);
    });

    var gLanes = svgEl('g', { 'class': 'wr-lanes' }, svg);
    var gEdges = svgEl('g', { 'class': 'wr-edges' }, svg);
    var gNodes = svgEl('g', { 'class': 'wr-nodes' }, svg);
    var gOver = svgEl('g', { 'class': 'wr-overlay', 'aria-hidden': 'true' }, svg);

    // Lanes
    inst.laneEls = [];
    lay.lanes.forEach(function (L, i) {
      var g = svgEl('g', { 'class': 'wr-lane', 'data-cluster': L.key }, gLanes);
      var h = L.bottom - L.top;
      var cid = pfx + 'clip-' + i;
      var cp = svgEl('clipPath', { id: cid }, defs);
      svgEl('rect', { x: 0.5, y: L.top + 0.5, width: lay.W - 1, height: h - 1, rx: 10 }, cp);
      svgEl('rect', { 'class': 'l-band', x: 0.5, y: L.top + 0.5, width: lay.W - 1, height: h - 1, rx: 10 }, g);
      svgEl('rect', { 'class': 'l-stripe', x: 0, y: L.top, width: 5, height: h, 'clip-path': 'url(#' + cid + ')' }, g);
      var nx = G.lanePadX + 4;
      var nameT = svgText(g, { 'class': 'l-name', x: nx, y: L.top + 34 }, L.headName);
      var pill = svgEl('g', { 'class': 'l-pill' }, g);
      var pr = svgEl('rect', { x: nx + L.headNameW + 14, y: L.top + 16, height: 22, rx: 11 }, pill);
      var pt = svgText(pill, { y: L.top + 31.5, 'text-anchor': 'middle' }, '');
      var count = svgText(g, { 'class': 'l-count', x: nx, y: L.top + 60 }, '');
      var sib = L.sib;
      if (sib && L.sibLine) { svgText(g, { 'class': 'l-count l-sib', x: nx, y: L.top + 78 }, sib.charAt(0).toUpperCase() + sib.slice(1)); sib = null; }
      if (L.sepY != null) {
        svgEl('line', { 'class': 'l-sep', x1: G.lanePadX + 4, x2: lay.W - G.lanePadX, y1: L.sepY, y2: L.sepY }, g);
        svgText(gOver, { 'class': 'l-seplabel', x: G.lanePadX + 4, y: L.sepY + 17 }, 'CLUSTER INFRASTRUCTURE');
      } else if (L.infra.length && !L.main.length) {
        // infra-only lane: no separator, the header says it all
      }
      inst.laneEls.push({ L: L, g: g, nameT: nameT, pr: pr, pt: pt, count: count, sib: sib, x0: nx + L.headNameW + 14, shown: null });
    });

    // Entry stubs: traffic from users into user-facing components in the first column.
    lay.lanes.forEach(function (L) {
      if (!L.s.hasEntryStub) return;
      var first = L.s.grid ? L.s.grid.map(function (n) { return { node: n }; }) : L.s.layers[0];
      first.forEach(function (it) {
        if (it.dummy || !it.node.userFacing || it.node.inn.length) return;
        var p = lay.pos.get(it.node), cy = p.y + G.nodeH / 2;
        if (L.s.grid && p.x > L.padLeft + 1) return;
        var g = svgEl('g', { 'class': 'wr-entry', 'aria-hidden': 'true' }, gEdges);
        var t = svgEl('title', null, g);
        t.textContent = 'Traffic from users enters at ' + it.node.name;
        var ux = p.x - 36;
        svgEl('circle', { 'class': 'u-head', cx: ux, cy: cy - 5, r: 2.6 }, g);
        svgEl('path', { 'class': 'u-body', d: 'M' + (ux - 4.6) + ' ' + (cy + 4.5) + 'a4.6 4.4 0 0 1 9.2 0' }, g);
        svgEl('path', { 'class': 'u-line', d: 'M' + (ux + 8) + ' ' + cy + 'H' + (p.x - 10), 'marker-end': 'url(#' + pfx + 'mk-entry)' }, g);
      });
    });

    // Edges: quiet first, failing on top.
    inst.edgeEls = new Map();
    lay.edges.slice().sort(function (a, b) { return EDGE_RANK[a.ed.status] - EDGE_RANK[b.ed.status]; }).forEach(function (eo) {
      var ed = eo.ed;
      var extra = eo.kind === 'back' ? ' ed-back' : '';
      var g = svgEl('g', { 'class': 'wr-edge ed-' + ed.status + extra, 'data-edge': ed.id, 'data-from': ed.from.id, 'data-to': ed.to.id }, gEdges);
      var t = svgEl('title', null, g);
      t.textContent = edgeTitle(ed);
      var pulse = null;
      if (ed.to.status === 'root' && ed.status !== 'ok') {
        pulse = svgEl('path', { 'class': 'e-pulse', d: eo.d, 'stroke-width': r1(eo.width + 5) }, g);
        pulse.style.animationDelay = '-' + Math.round((typeof performance !== 'undefined' ? performance.now() : 0) % 2400) + 'ms';
      }
      svgEl('path', { 'class': 'e-hit', d: eo.d }, g);
      var line = svgEl('path', { 'class': 'e-line', d: eo.d, 'stroke-width': r1(eo.width), 'marker-end': 'url(#' + pfx + 'mk-' + ed.status + ')' }, g);
      var lab = null;
      if (eo.label) {
        lab = svgEl('g', { 'class': 'wr-elabel ed-' + ed.status, transform: 'translate(' + r1(eo.label.x) + ' ' + r1(eo.label.y) + ')' }, gOver);
        svgEl('rect', { width: eo.label.w, height: eo.label.h, rx: eo.label.h / 2 }, lab);
        svgText(lab, { x: eo.label.w / 2, y: 14.2, 'text-anchor': 'middle' }, eo.label.text);
      }
      inst.edgeEls.set(ed.id, { ed: ed, g: g, line: line, pulse: pulse, label: lab, shown: null, pfx: pfx, extra: extra });
    });

    // Nodes, in reading order (lane, row, column, top to bottom) so Tab order follows the picture.
    inst.nodeEls = new Map();
    inst.order = [];
    var ordered = [];
    lay.lanes.forEach(function (L) {
      if (L.s.grid) L.s.grid.forEach(function (n) { ordered.push(n); });
      L.s.layers.forEach(function (arr) { arr.forEach(function (it) { if (!it.dummy) ordered.push(it.node); }); });
      L.infra.slice().sort(function (a, b) {
        var pa = lay.pos.get(a), pb = lay.pos.get(b);
        return (pa.y - pb.y) || (pa.x - pb.x);
      }).forEach(function (n) { ordered.push(n); });
    });
    ordered.forEach(function (n) {
      var p = lay.pos.get(n), info = lay.nodeInfo.get(n);
      var g = svgEl('g', {
        'class': 'wr-node st-' + n.status + ' k-' + n.kind, 'data-component': n.id, tabindex: -1, role: 'button',
        'aria-label': ariaFor(n, n.status), transform: 'translate(' + r1(p.x) + ' ' + r1(p.y) + ')'
      }, gNodes);
      var t = svgEl('title', null, g);
      t.textContent = nodeTitle(m, n);
      svgEl('rect', { 'class': 'n-focus', x: -7.5, y: -7.5, width: p.w + 15, height: p.h + 15, rx: G.nodeRx + 6 }, g);
      if (n.status === 'root') svgEl('rect', { 'class': 'n-ring', x: -4.5, y: -4.5, width: p.w + 9, height: p.h + 9, rx: G.nodeRx + 4 }, g);
      var box = svgEl('rect', { 'class': 'n-box', width: p.w, height: p.h, rx: G.nodeRx }, g);
      drawGlyph(g, n.kind, 13, p.h / 2 - 8);
      var room = p.w - G.padL - G.padR;
      var label = fitName(n.name, room, function (x) { return measure(x, 14, 600, lay.fonts.body); }, n.type);
      svgText(g, { 'class': 'n-name', x: G.padL, y: 23 }, label);
      var sub = svgEl('text', { 'class': 'n-sub', x: G.padL, y: 41 }, g);
      var tb = svgEl('tspan', { 'class': 'n-ns' }, sub);
      var word = STATUS_WORD[n.status] ? ' \u00b7 ' + STATUS_WORD[n.status] : '';
      tb.textContent = fitText(info.base, room - measure(word, 12, 700, lay.fonts.body), function (x) { return measure(x, 12, 400, lay.fonts.body); }, false);
      var ts = svgEl('tspan', { 'class': 'n-st' }, sub);
      if (n.status === 'root') {
        var below = n.infra && n.inn.some(function (ed) { return ed.runX != null; });
        var tag = svgEl('g', { 'class': 'n-tag', transform: 'translate(10 ' + (below ? p.h - 6 : -14) + ')' }, g);
        var tw = Math.ceil(measure('SUSPECTED ROOT', 12, 700, lay.fonts.body, 0.06)) + 34;
        svgEl('rect', { width: tw, height: 20, rx: 10 }, tag);
        drawCrosshair(tag, 13, 10, 'n-cross');
        svgText(tag, { x: 24, y: 14.3 }, 'SUSPECTED ROOT');
      }
      if (n.note) {
        var nw = function (str) { return measure(str, 12, 400, lay.fonts.body); };
        svgText(g, { 'class': 'n-note' + (n.noteBad ? ' is-bad' : ''), x: 2, y: p.h + 15 }, fitText(n.note, p.w + 24, nw, false));
      }
      inst.nodeEls.set(n.id, { n: n, g: g, box: box, st: ts, shown: null });
      inst.order.push(n.id);
    });

    inst.pos = new Map();
    lay.pos.forEach(function (p, n) { inst.pos.set(n.id, { cx: p.x + p.w / 2, cy: p.y + p.h / 2 }); });
  }

  // Apply the replay time to every node, edge and lane header (class toggles only).
  function applyTime(inst, animate) {
    var m = inst.model, t = inst.time;
    if (!m || !inst.nodeEls) return;
    animate = animate && !reducedMotion();
    inst.nodeEls.forEach(function (o) {
      var s = nodeStatusAt(m, o.n, t);
      if (s === o.shown) return;
      if (o.shown) o.g.classList.remove('st-' + o.shown);
      o.g.classList.add('st-' + s);
      o.st.textContent = STATUS_WORD[s] ? ' · ' + STATUS_WORD[s] : '';
      o.g.setAttribute('aria-label', ariaFor(o.n, s));
      if (animate && o.shown && s !== 'healthy') {
        o.g.classList.add('is-revealing');
        clearTimeout(o.timer);
        o.timer = setTimeout(function () { o.g.classList.remove('is-revealing'); }, 800);
      }
      o.shown = s;
    });
    inst.edgeEls.forEach(function (o) {
      var r = edgeShownAt(m, o.ed, t);
      var intoRoot = r.status !== 'ok' && o.ed.to.status === 'root' && nodeStatusAt(m, o.ed.to, t) === 'root';
      var key = r.status + (r.label ? '+l' : '') + (intoRoot ? '+r' : '');
      if (key === o.shown) return;
      o.g.setAttribute('class', 'wr-edge ed-' + r.status + o.extra + (intoRoot ? ' ed-into-root' : '') +
        (o.g.classList.contains('is-near') ? ' is-near' : ''));
      o.line.setAttribute('marker-end', 'url(#' + o.pfx + 'mk-' + r.status + ')');
      if (o.label) {
        o.label.style.display = r.label ? '' : 'none';
        o.label.setAttribute('class', 'wr-elabel ed-' + r.status + (o.label.classList.contains('is-near') ? ' is-near' : ''));
      }
      o.shown = key;
    });
    inst.laneEls.forEach(function (o) {
      var L = o.L, st = statsAt(m, t, L.key);
      var worst = 'healthy';
      if (L.cluster && L.cluster.status && (t == null || m.end == null || t >= m.end)) worst = L.cluster.status;
      else {
        L.main.concat(L.infra).forEach(function (n) {
          var s = nodeStatusAt(m, n, t);
          if (s === 'root' || s === 'failing') worst = 'failing';
          else if ((s === 'degraded' || s === 'at-risk') && worst !== 'failing') worst = 'degraded';
        });
      }
      if (worst !== 'failing' && worst !== 'degraded') worst = 'healthy';
      var key = worst + st.affected;
      if (key === o.shown) return;
      o.g.setAttribute('class', 'wr-lane lane-' + worst);
      var label = worst.toUpperCase();
      o.pt.textContent = label;
      var pw = Math.ceil(measure(label, 12, 700, inst.fonts.body, 0.06)) + 24;
      o.pr.setAttribute('width', pw);
      o.pt.setAttribute('x', o.x0 + pw / 2);
      o.count.textContent = st.affected + ' of ' + st.total + (st.total === 1 ? ' component' : ' components') + ' affected' +
        (o.sib ? ' · ' + o.sib : '');
      o.shown = key;
    });
  }

  // ---------------------------------------------------------------------------------------------
  // Legend
  // ---------------------------------------------------------------------------------------------
  function swatchNode(parent, status) {
    var s = svgEl('svg', { 'class': 'lg-sw', width: 34, height: 22, viewBox: '0 0 34 22', 'aria-hidden': 'true' }, parent);
    var g = svgEl('g', { 'class': 'wr-node st-' + status }, s);
    if (status === 'root') svgEl('rect', { 'class': 'n-ring', x: 2, y: 2, width: 30, height: 18, rx: 6 }, g);
    svgEl('rect', { 'class': 'n-box', x: 5, y: 5, width: 24, height: 12, rx: 4 }, g);
    return s;
  }
  function renderLegend(inst) {
    var m = inst.model, el = inst.legend;
    clear(el);
    if (!m || !m.comps.length) { el.hidden = true; return; }
    el.hidden = false;
    function group(title) {
      var g = htmlEl('div', { 'class': 'lg-group' }, el);
      htmlEl('span', { 'class': 'lg-title' }, g, title);
      return g;
    }
    function item(g, text) { var it = htmlEl('span', { 'class': 'lg-item' }, g); return { it: it, done: function () { htmlEl('span', null, it, text); } }; }

    var gs = group('Status');
    [['root', 'Suspected root'], ['failing', 'Failing'], ['degraded', 'Degraded'], ['at-risk', 'At risk (calls a failing one)'], ['healthy', 'Healthy']]
      .forEach(function (p) { var i = item(gs, p[1]); swatchNode(i.it, p[0]); i.done(); });

    var kinds = new Set(m.comps.map(function (n) { return n.kind; }));
    var gk = group('Components');
    [['service', 'Service'], ['ingress', 'Ingress or gateway'], ['datastore', 'Datastore'], ['external', 'External dependency'],
      ['infra', 'Cluster add-on, such as CoreDNS'], ['node', 'Kubernetes node']].forEach(function (p) {
      if (!kinds.has(p[0])) return;
      var i = item(gk, p[1]);
      var s = svgEl('svg', { 'class': 'lg-sw lg-glyph', width: 18, height: 18, viewBox: '0 0 16 16', 'aria-hidden': 'true' }, i.it);
      drawGlyph(s, p[0], 0, 0);
      i.done();
    });

    var hasEdges = m.edges.length > 0, hasUsers = m.comps.some(function (n) { return n.userFacing; });
    if (!hasEdges && !hasUsers) return;
    var gc = group('Calls');
    if (hasEdges) {
    var i1 = item(gc, 'Line width = call volume');
    var s1 = svgEl('svg', { 'class': 'lg-sw', width: 34, height: 22, viewBox: '0 0 34 22', 'aria-hidden': 'true' }, i1.it);
    svgEl('path', { 'class': 'lg-line', d: 'M2 7H32', 'stroke-width': 1.5 }, s1);
    svgEl('path', { 'class': 'lg-line', d: 'M2 15H32', 'stroke-width': 4.5 }, s1);
    i1.done();
    var i2 = item(gc, 'Failing calls');
    var s2 = svgEl('svg', { 'class': 'lg-sw', width: 34, height: 22, viewBox: '0 0 34 22', 'aria-hidden': 'true' }, i2.it);
    svgEl('path', { 'class': 'lg-line lg-fail', d: 'M2 11H32', 'stroke-width': 3 }, s2);
    i2.done();
    var i3 = item(gc, 'share of calls that failed');
    htmlEl('span', { 'class': 'lg-chip', 'aria-hidden': 'true' }, i3.it, '40% errors');
    i3.done();
    }
    if (hasUsers) {
      var i4 = item(gc, 'Traffic from users');
      var s4 = svgEl('svg', { 'class': 'lg-sw', width: 34, height: 22, viewBox: '0 0 34 22', 'aria-hidden': 'true' }, i4.it);
      var ge = svgEl('g', { 'class': 'wr-entry' }, s4);
      svgEl('circle', { 'class': 'u-head', cx: 6, cy: 6.5, r: 2.6 }, ge);
      svgEl('path', { 'class': 'u-body', d: 'M1.4 16a4.6 4.4 0 0 1 9.2 0' }, ge);
      svgEl('path', { 'class': 'u-line', d: 'M14 11H27' }, ge);
      svgEl('path', { 'class': 'u-tip', d: 'M26 6.6L32.5 11L26 15.4z' }, ge);
      i4.done();
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Instance lifecycle
  // ---------------------------------------------------------------------------------------------
  function createInstance(container) {
    var inst = { id: ++uid, container: container, analysis: null, opts: {}, model: null, time: null, selected: null, hover: null };
    var root = htmlEl('div', { 'class': 'wr-map' });
    var hint = htmlEl('p', { 'class': 'wr-map-hint', hidden: '' }, root);
    var hintIcon = svgEl('svg', { width: 16, height: 16, viewBox: '0 0 16 16', 'aria-hidden': 'true' }, hint);
    svgEl('path', { d: 'M2 8h11M9.5 4.5L13 8l-3.5 3.5', fill: 'none', stroke: 'currentColor', 'stroke-width': 1.6, 'stroke-linecap': 'round', 'stroke-linejoin': 'round' }, hintIcon);
    var hintText = htmlEl('span', null, hint, '');
    var jump = htmlEl('button', { type: 'button', 'class': 'wr-map-jump', hidden: '' }, hint, '');
    var scroll = htmlEl('div', { 'class': 'wr-map-scroll', 'data-scroll-x': '' }, root);
    var svg = svgEl('svg', { 'class': 'wr-map-svg', role: 'group', 'aria-roledescription': 'blast radius map', focusable: 'false' }, scroll);
    var empty = htmlEl('div', { 'class': 'wr-map-empty', hidden: '' }, root);
    var legend = htmlEl('div', { 'class': 'wr-map-legend', role: 'group', 'aria-label': 'Map legend' }, root);
    container.appendChild(root);
    inst.root = root; inst.hint = hint; inst.hintText = hintText; inst.jump = jump; inst.scroll = scroll; inst.svg = svg;
    inst.onJump = function () {
      var r = inst.rootBox;
      if (!r) return;
      var left = Math.max(0, r.x + r.w / 2 - scroll.clientWidth / 2);
      try { scroll.scrollTo({ left: left, behavior: reducedMotion() ? 'auto' : 'smooth' }); } catch (e) { scroll.scrollLeft = left; }
    };
    inst.onScroll = function () { updateHint(inst); };
    jump.addEventListener('click', inst.onJump);
    scroll.addEventListener('scroll', inst.onScroll, { passive: true });
    inst.empty = empty; inst.legend = legend;
    buildEmpty(empty);

    function nodeFrom(ev) {
      var t = ev.target;
      var g = t && t.closest ? t.closest('[data-component]') : null;
      return g && svg.contains(g) ? g : null;
    }
    inst.onClick = function (ev) {
      var g = nodeFrom(ev);
      if (g) select(inst, g.getAttribute('data-component'), true);
    };
    inst.onKey = function (ev) {
      var g = nodeFrom(ev);
      if (!g) return;
      var id = g.getAttribute('data-component');
      var k = ev.key;
      if (k === 'Enter' || k === ' ' || k === 'Spacebar') { ev.preventDefault(); select(inst, id, true); return; }
      var dir = k === 'ArrowRight' ? [1, 0] : k === 'ArrowLeft' ? [-1, 0] : k === 'ArrowDown' ? [0, 1] : k === 'ArrowUp' ? [0, -1] : null;
      var next = null;
      if (dir) next = spatialNext(inst, id, dir);
      else if (k === 'Home') next = inst.order[0];
      else if (k === 'End') next = inst.order[inst.order.length - 1];
      else return;
      ev.preventDefault();
      if (next && inst.nodeEls.has(next)) inst.nodeEls.get(next).g.focus();
    };
    inst.onOver = function (ev) {
      var g = nodeFrom(ev);
      if (g) emphasise(inst, g.getAttribute('data-component'));
    };
    inst.onOut = function (ev) {
      var g = nodeFrom(ev);
      var to = ev.relatedTarget && ev.relatedTarget.closest ? ev.relatedTarget.closest('[data-component]') : null;
      if (g && to !== g) emphasise(inst, focusedVisibleId(inst));
    };
    inst.onFocusIn = function (ev) {
      var g = nodeFrom(ev);
      if (g) setRoving(inst, g.getAttribute('data-component'));
      var vis = false;
      try { vis = g && g.matches(':focus-visible'); } catch (e) { vis = false; }
      if (g && vis) emphasise(inst, g.getAttribute('data-component'));
    };
    inst.onFocusOut = function () {
      setTimeout(function () { if (!inst.destroyed) emphasise(inst, focusedVisibleId(inst)); }, 0);
    };
    svg.addEventListener('click', inst.onClick);
    svg.addEventListener('keydown', inst.onKey);
    svg.addEventListener('pointerover', inst.onOver);
    svg.addEventListener('pointerout', inst.onOut);
    svg.addEventListener('focusin', inst.onFocusIn);
    svg.addEventListener('focusout', inst.onFocusOut);

    inst.schedule = function () {
      if (inst.raf || inst.destroyed) return;
      inst.raf = requestAnimationFrame(function () { inst.raf = 0; if (!inst.destroyed && inst.analysis) draw(inst); });
    };
    inst.lastW = -1;
    if (typeof ResizeObserver === 'function') {
      inst.ro = new ResizeObserver(function () {
        var w = scroll.clientWidth;
        if (Math.abs(w - inst.lastW) >= 1) inst.schedule();
      });
      inst.ro.observe(scroll);
    }
    try {
      if (document.fonts && document.fonts.addEventListener) {
        inst.onFonts = function () { inst.schedule(); };
        document.fonts.addEventListener('loadingdone', inst.onFonts);
      }
    } catch (e) { /* no font loading API */ }

    inst.handle = {
      setTime: function (ms, animate) { inst.time = num(ms); applyTime(inst, !!animate); },
      getTime: function () { return inst.time; },
      highlight: function (id) { setSelected(inst, id == null ? null : String(id)); },
      stats: function (ms) { return inst.model ? statsAt(inst.model, arguments.length ? num(ms) : inst.time) : { affected: 0, total: 0 }; },
      destroy: function () { destroy(inst); },
      element: root
    };
    return inst;
  }

  function buildEmpty(el) {
    var s = svgEl('svg', { 'class': 'wr-map-empty-art', width: 220, height: 92, viewBox: '0 0 220 92', 'aria-hidden': 'true' }, el);
    svgEl('rect', { 'class': 'em-lane', x: 1, y: 1, width: 218, height: 90, rx: 10 }, s);
    svgEl('path', { 'class': 'em-edge', d: 'M62 34C80 34 80 28 98 28M62 34C80 34 80 62 98 62M146 28C160 28 160 45 172 45' }, s);
    [[16, 22], [98, 16], [98, 50], [172, 33]].forEach(function (p, i) {
      svgEl('rect', { 'class': i === 3 ? 'em-node em-root' : 'em-node', x: p[0], y: p[1], width: i === 3 ? 34 : 48, height: 24, rx: 6 }, s);
    });
    htmlEl('p', { 'class': 'wr-map-empty-title' }, el, 'No blast radius yet');
    htmlEl('p', { 'class': 'wr-map-empty-text' }, el, 'Paste logs, traces, alerts or a Helm diff to draw the blast radius.');
  }

  function focusedVisibleId(inst) {
    var a = document.activeElement;
    if (!a || !inst.svg.contains(a) || !a.getAttribute) return null;
    var vis = false;
    try { vis = a.matches(':focus-visible'); } catch (e) { vis = false; }
    return vis ? a.getAttribute('data-component') : null;
  }

  function emphasise(inst, id) {
    if (inst.hover === id) return;
    inst.hover = id;
    (inst.nearEls || []).forEach(function (el) { el.classList.remove('is-near'); });
    inst.nearEls = [];
    if (!id || !inst.nodeEls || !inst.nodeEls.has(id)) { inst.svg.classList.remove('is-focusing'); return; }
    var n = inst.nodeEls.get(id).n, keep = [inst.nodeEls.get(id).g];
    n.out.concat(n.inn).forEach(function (ed) {
      var eo = inst.edgeEls.get(ed.id);
      if (eo) { keep.push(eo.g); if (eo.label) keep.push(eo.label); }
      var other = ed.from === n ? ed.to : ed.from;
      if (inst.nodeEls.has(other.id)) keep.push(inst.nodeEls.get(other.id).g);
    });
    keep.forEach(function (el) { el.classList.add('is-near'); });
    inst.nearEls = keep;
    inst.svg.classList.add('is-focusing');
  }

  function spatialNext(inst, id, dir) {
    var cur = inst.pos.get(id);
    if (!cur) return null;
    var best = null, bestScore = Infinity;
    inst.pos.forEach(function (p, oid) {
      if (oid === id) return;
      var dx = p.cx - cur.cx, dy = p.cy - cur.cy;
      var along = dx * dir[0] + dy * dir[1];
      if (along <= 4) return;
      var across = Math.abs(dir[0] ? dy : dx);
      var score = along + across * 2.5;
      if (score < bestScore) { bestScore = score; best = oid; }
    });
    return best;
  }

  function setRoving(inst, id) {
    if (!inst.nodeEls || !inst.nodeEls.size) return;
    if (id == null || !inst.nodeEls.has(id)) {
      id = inst.selected && inst.nodeEls.has(inst.selected) ? inst.selected :
        inst.model && inst.model.root && inst.nodeEls.has(inst.model.root.id) ? inst.model.root.id : inst.order[0];
    }
    inst.nodeEls.forEach(function (o, oid) { o.g.setAttribute('tabindex', oid === id ? '0' : '-1'); });
  }
  function setSelected(inst, id) {
    if (id != null && !(inst.nodeEls && inst.nodeEls.has(id))) id = id != null && inst.model && inst.model.byId.has(id) ? id : null;
    inst.selected = id;
    if (!inst.nodeEls) return;
    inst.nodeEls.forEach(function (o, oid) {
      var on = oid === id;
      o.g.classList.toggle('is-selected', on);
      if (on) o.g.setAttribute('aria-current', 'true'); else o.g.removeAttribute('aria-current');
    });
    var a = document.activeElement;
    if (!(a && inst.svg.contains(a))) setRoving(inst, id);
  }
  function select(inst, id, notify) {
    setSelected(inst, id);
    if (notify && inst.opts && typeof inst.opts.onSelect === 'function') {
      try { inst.opts.onSelect(id); } catch (e) { if (typeof console !== 'undefined') console.error(e); }
    }
  }

  function draw(inst) {
    var model = buildModel(inst.analysis);
    inst.model = model;
    inst.fonts = readFonts(inst.container);
    var focusedId = null;
    var a = document.activeElement;
    if (a && inst.svg.contains(a) && a.getAttribute) focusedId = a.getAttribute('data-component');
    inst.hover = null;
    inst.nearEls = [];
    inst.svg.classList.remove('is-focusing');
    (inst.nodeEls || new Map()).forEach(function (o) { clearTimeout(o.timer); });

    if (!model.comps.length) {
      clear(inst.svg);
      inst.nodeEls = new Map(); inst.edgeEls = new Map(); inst.laneEls = []; inst.order = []; inst.pos = new Map();
      inst.scroll.hidden = true;
      inst.empty.hidden = false;
      inst.hint.hidden = true;
      renderLegend(inst);
      inst.lastW = inst.scroll.clientWidth;
      return;
    }
    inst.scroll.hidden = false;
    inst.empty.hidden = true;
    var avail = inst.scroll.clientWidth || inst.container.clientWidth || 0;
    inst.lastW = inst.scroll.clientWidth;
    var scrollLeft = inst.scroll.scrollLeft;
    var lay = layout(model, avail, inst.fonts);
    // Slightly too wide: scale the picture down to fit rather than make the reader scroll.
    var k = 1;
    if (avail > 0 && lay.W > avail + 0.5 && avail / lay.W >= MIN_SCALE) k = avail / lay.W;
    inst.k = k;
    drawMap(inst, lay, k);
    renderLegend(inst);
    applyTime(inst, false);
    if (inst.selected && !model.byId.has(inst.selected)) inst.selected = null;
    setSelected(inst, inst.selected);
    if (focusedId && inst.nodeEls.has(focusedId)) {
      try { inst.nodeEls.get(focusedId).g.focus({ preventScroll: true }); } catch (e) { /* old browser */ }
    }
    inst.scroll.scrollLeft = scrollLeft;
    var rp = model.root ? lay.pos.get(model.root) : null;
    inst.rootBox = rp ? { x: rp.x * k, w: rp.w * k, name: model.root.name + (lay.lanes.length > 1 && model.root.cluster ? ' in ' + model.root.cluster : '') } : null;
    setRoving(inst, focusedId);
    // A new picture (different components or root) that needs sideways scrolling opens centred on
    // the suspected root; redraws of the same picture (resize, fonts) keep the reader's position.
    var pictureKey = (model.root ? model.root.id : '') + '|' + model.comps.map(function (n) { return n.id; }).join(',');
    if (pictureKey !== inst.pictureKey) {
      inst.pictureKey = pictureKey;
      var sc = inst.scroll;
      if (inst.rootBox && sc.scrollWidth > sc.clientWidth + 1) {
        sc.scrollLeft = Math.max(0, inst.rootBox.x + inst.rootBox.w / 2 - sc.clientWidth / 2);
      }
    }
    updateHint(inst);
  }

  // When the map is wider than its box: say so, and offer a jump to the suspected root while it is out of view.
  function updateHint(inst) {
    var sc = inst.scroll;
    var over = !sc.hidden && sc.scrollWidth > sc.clientWidth + 1;
    inst.hint.hidden = !over;
    if (!over) return;
    var r = inst.rootBox;
    var inView = !!r && !(r.x + r.w > sc.scrollLeft + sc.clientWidth - 8 || r.x < sc.scrollLeft);
    inst.hintText.textContent = r ? (inView ? 'Scroll sideways for the rest of the map.' : 'The suspected root is off to the side.') : 'Scroll sideways to see the whole map.';
    inst.jump.hidden = !r;
    if (r) {
      inst.jump.textContent = 'Suspected root: ' + r.name;
      inst.jump.setAttribute('aria-label', 'Scroll the map to the suspected root, ' + r.name);
      inst.jump.classList.toggle('is-here', inView);
    }
  }

  function destroy(inst) {
    if (inst.destroyed) return;
    inst.destroyed = true;
    if (inst.raf) cancelAnimationFrame(inst.raf);
    var svg = inst.svg;
    svg.removeEventListener('click', inst.onClick);
    svg.removeEventListener('keydown', inst.onKey);
    svg.removeEventListener('pointerover', inst.onOver);
    svg.removeEventListener('pointerout', inst.onOut);
    svg.removeEventListener('focusin', inst.onFocusIn);
    svg.removeEventListener('focusout', inst.onFocusOut);
    inst.jump.removeEventListener('click', inst.onJump);
    inst.scroll.removeEventListener('scroll', inst.onScroll);
    if (inst.ro) inst.ro.disconnect();
    try { if (inst.onFonts) document.fonts.removeEventListener('loadingdone', inst.onFonts); } catch (e) { /* ignore */ }
    (inst.nodeEls || new Map()).forEach(function (o) { clearTimeout(o.timer); });
    if (inst.root.parentNode) inst.root.parentNode.removeChild(inst.root);
    instances.delete(inst.container);
  }

  function render(containerEl, analysis, opts) {
    if (!containerEl) throw new Error('WR.ui.map.render needs a container element');
    var inst = instances.get(containerEl);
    if (!inst || inst.destroyed) { inst = createInstance(containerEl); instances.set(containerEl, inst); }
    inst.analysis = analysis || null;
    inst.opts = opts || {};
    inst.time = num(inst.opts.at);
    draw(inst);
    return inst.handle;
  }

  // ---------------------------------------------------------------------------------------------
  // Timeline scrubber
  // ---------------------------------------------------------------------------------------------
  var PLAY_MS = 8000;
  var PANES = { logs: 'logs', traces: 'traces', alerts: 'alerts', helm: 'Helm' };

  function zoneNote(analysis, tzOpt) {
    var a = analysis || {}, stats = a.stats || {}, panes = [], zones = [];
    Object.keys(PANES).forEach(function (k) {
      var st = stats[k];
      if (!st || !(st.tzAssumed > 0)) return;
      panes.push(PANES[k]);
      (st.warnings || []).forEach(function (w) {
        var mm = /assumed\s+([+\-−]\d{2}:?\d{2}|Z|UTC)\b/i.exec(String(w));
        if (mm) zones.push(mm[1].replace('−', '-'));
      });
    });
    // What the engine actually did (its warnings) wins; the context field is only a fallback.
    if (!zones.length && tzOpt) zones = [String(tzOpt)];
    zones = zones.filter(function (z, i) { return zones.indexOf(z) === i; });
    var text = 'All times are Coordinated Universal Time (UTC).';
    if (panes.length) {
      var list = panes.length > 1 ? panes.slice(0, -1).join(', ') + ' and ' + panes[panes.length - 1] : panes[0];
      var zone = zones.length === 1 ? (/^(Z|UTC|[+-]00:?00)$/i.test(zones[0]) ? 'UTC' : zones[0]) : null;
      text += ' Some ' + list + ' times had no time zone' + (zone ? ' and were read as ' + zone + '.' : '; see the pane notes.');
    }
    return text;
  }

  function createScrubber(container) {
    var s = { container: container, playing: false, raf: 0, value: null, max: 0, step: 1, start: null, end: null };
    var root = htmlEl('div', { 'class': 'wr-scrub', role: 'group', 'aria-label': 'Replay how the incident spread' });
    var row = htmlEl('div', { 'class': 'wr-scrub-row' }, root);
    s.row = row;
    var btn = htmlEl('button', { type: 'button', 'class': 'wr-scrub-play' }, row);
    var icon = svgEl('svg', { width: 14, height: 14, viewBox: '0 0 14 14', 'aria-hidden': 'true' }, btn);
    var iconPath = svgEl('path', { fill: 'currentColor' }, icon);
    var btnText = htmlEl('span', null, btn, 'Play');
    var track = htmlEl('div', { 'class': 'wr-scrub-track' }, row);
    var range = htmlEl('input', { type: 'range', 'class': 'wr-scrub-range', min: 0, max: 0, step: 1, value: 0, 'aria-label': 'Time shown on the map' }, track);
    var marks = htmlEl('div', { 'class': 'wr-scrub-marks', 'aria-hidden': 'true' }, track);
    var ends = htmlEl('div', { 'class': 'wr-scrub-ends', 'aria-hidden': 'true' }, track);
    var endA = htmlEl('span', null, ends, '');
    var endB = htmlEl('span', null, ends, '');
    var read = htmlEl('div', { 'class': 'wr-scrub-readout' }, root);
    var timeEl = htmlEl('strong', { 'class': 'wr-scrub-time' }, read, '');
    var relEl = htmlEl('span', { 'class': 'wr-scrub-rel' }, read, '');
    var affEl = htmlEl('span', { 'class': 'wr-scrub-aff' }, read, '');
    var key = htmlEl('ul', { 'class': 'wr-scrub-key' }, root);
    var note = htmlEl('p', { 'class': 'wr-scrub-note' }, root, '');

    // Same container as the map: sit right under the picture, above the legend, like player controls.
    var mapRoot = null, legend = null;
    for (var c = container.firstElementChild; c; c = c.nextElementSibling) if (c.classList && c.classList.contains('wr-map')) mapRoot = c;
    if (mapRoot) for (var l = mapRoot.firstElementChild; l; l = l.nextElementSibling) if (l.classList && l.classList.contains('wr-map-legend')) legend = l;
    if (mapRoot) mapRoot.insertBefore(root, legend || null);
    else container.appendChild(root);

    s.root = root; s.btn = btn; s.btnText = btnText; s.iconPath = iconPath; s.range = range; s.marks = marks;
    s.endA = endA; s.endB = endB; s.timeEl = timeEl; s.relEl = relEl; s.affEl = affEl; s.key = key; s.note = note;

    s.onInput = function () { pauseScrub(s); s.value = Number(range.value); pushTime(s); };
    s.onBtn = function () { if (s.playing) pauseScrub(s); else playScrub(s); };
    range.addEventListener('input', s.onInput);
    btn.addEventListener('click', s.onBtn);
    try {
      s.mql = window.matchMedia ? window.matchMedia('(prefers-reduced-motion: reduce)') : null;
      if (s.mql) {
        s.onMql = function () { if (s.mql.matches) pauseScrub(s); refreshButton(s); };
        if (s.mql.addEventListener) s.mql.addEventListener('change', s.onMql);
        else if (s.mql.addListener) s.mql.addListener(s.onMql);
      }
    } catch (e) { s.mql = null; }

    s.handle = {
      setTime: function (ms) {
        if (s.start == null) return;
        var v = ms == null ? s.max : Math.round((ms - s.start) / 1000);
        s.value = clamp(v, 0, s.max);
        range.value = String(s.value);
        pushTime(s);
      },
      play: function () { playScrub(s); },
      pause: function () { pauseScrub(s); },
      destroy: function () { destroyScrub(s); },
      element: root
    };
    return s;
  }

  function timeOf(s) {
    if (s.start == null) return null;
    if (s.value >= s.max) return s.end;
    return Math.min(s.end, s.start + s.value * 1000);
  }

  function pushTime(s) {
    var t = timeOf(s);
    var atEnd = s.start == null || s.value >= s.max;
    if (s.map && typeof s.map.setTime === 'function') {
      try { s.map.setTime(atEnd ? null : t, s.playing); } catch (e) { if (typeof console !== 'undefined') console.error(e); }
    }
    readout(s, t, atEnd);
    refreshButton(s);
  }

  function readout(s, t, atEnd) {
    if (s.start == null) {
      s.timeEl.textContent = 'No timeline';
      s.relEl.textContent = 'The evidence has no usable timestamps, so the map shows the final state only.';
      s.affEl.textContent = '';
      s.range.setAttribute('aria-valuetext', 'No timeline');
      return;
    }
    var fa = s.fa, rel = '';
    if (fa != null) {
      var d = t - fa;
      if (Math.abs(d) < 30000) rel = 'at the first anomaly';
      else rel = fmtDur(Math.abs(d)) + (d > 0 ? ' after' : ' before') + ' the first anomaly';
    }
    var clock = fmtClock(t) + ' UTC';
    s.timeEl.textContent = (atEnd ? 'Now · ' : '') + clock;
    s.relEl.textContent = rel;
    var st = s.map && typeof s.map.stats === 'function' ? s.map.stats(atEnd ? null : t) : null;
    s.affEl.textContent = st ? st.affected + ' of ' + st.total + ' components affected' : '';
    s.range.setAttribute('aria-valuetext', clock + (rel ? ', ' + rel : '') + (st ? ', ' + st.affected + ' of ' + st.total + ' affected' : ''));
  }

  function refreshButton(s) {
    var reduce = s.mql ? s.mql.matches : false;
    var disabled = s.start == null || s.max <= 0 || reduce;
    s.btn.disabled = disabled;
    var atEnd = s.value >= s.max;
    var label = s.playing ? 'Pause' : (atEnd ? 'Replay' : 'Play');
    s.btnText.textContent = label;
    s.btn.classList.toggle('is-playing', s.playing);
    s.iconPath.setAttribute('d', s.playing ? 'M3 2h3v10H3zM8 2h3v10H8z' : 'M3.5 1.8v10.4L12 7z');
    setNote(s);
    if (reduce) s.btn.title = 'Automatic replay is off because your system asks for reduced motion. Drag the slider to step through time.';
    else if (s.start == null) s.btn.title = 'Nothing to replay yet.';
    else s.btn.title = s.playing ? 'Pause the replay' : 'Replay how the failure spread, from the start of the window to now';
  }

  // The time-zone note, plus why Play is off under reduced motion (a disabled button's tooltip
  // is out of reach for keyboard and screen-reader users).
  function setNote(s) {
    var reduce = s.mql ? s.mql.matches : false;
    var why = reduce && s.start != null ? 'Automatic replay is off because your device asks for reduced motion; drag the slider to step through time.' : '';
    s.note.textContent = [s.zone || '', why].filter(Boolean).join(' ');
  }
  function playScrub(s) {
    if (s.playing || s.btn.disabled) return;
    if (s.value >= s.max) { s.value = 0; s.range.value = '0'; }
    s.playing = true;
    var v0 = s.value, t0 = null;
    var total = PLAY_MS * (1 - v0 / s.max);
    function frame(now) {
      if (!s.playing) return;
      if (t0 == null) t0 = now;
      var f = total > 0 ? Math.min(1, (now - t0) / total) : 1;
      s.value = Math.round(v0 + (s.max - v0) * f);
      s.range.value = String(s.value);
      pushTime(s);
      if (f >= 1) { pauseScrub(s); return; }
      s.raf = requestAnimationFrame(frame);
    }
    refreshButton(s);
    s.raf = requestAnimationFrame(frame);
  }
  function pauseScrub(s) {
    if (s.raf) cancelAnimationFrame(s.raf);
    s.raf = 0;
    if (!s.playing) return;
    s.playing = false;
    refreshButton(s);
  }
  function destroyScrub(s) {
    pauseScrub(s);
    s.range.removeEventListener('input', s.onInput);
    s.btn.removeEventListener('click', s.onBtn);
    if (s.mql && s.onMql) {
      if (s.mql.removeEventListener) s.mql.removeEventListener('change', s.onMql);
      else if (s.mql.removeListener) s.mql.removeListener(s.onMql);
    }
    if (s.root.parentNode) s.root.parentNode.removeChild(s.root);
    scrubbers.delete(s.container);
  }

  function updateScrubber(s, analysis, mapHandle, opts) {
    var w = (analysis && analysis.window) || {};
    var start = num(w.start), end = num(w.now) != null ? num(w.now) : num(w.end);
    var prevStart = s.start, prevEnd = s.end, prevAtEnd = s.value == null || s.value >= s.max, prevT = timeOf(s);
    if (s.playing && (start !== prevStart || end !== prevEnd)) pauseScrub(s);
    s.map = mapHandle || null;
    if (start == null || end == null || end <= start) {
      s.start = null; s.end = null; s.max = 0; s.value = 0; s.fa = null;
      s.range.disabled = true;
      s.range.min = '0'; s.range.max = '0'; s.range.value = '0';
      s.endA.textContent = ''; s.endB.textContent = '';
      clear(s.marks); clear(s.key); s.key.hidden = true;
      s.zone = '';
      s.root.classList.remove('has-ticks');
      setNote(s);
      s.root.classList.add('is-empty');
      // Nothing pasted at all: the map's own empty state says it; keep the scrubber out of the way.
      s.root.hidden = !(analysis && analysis.components && analysis.components.length);
      s.row.hidden = true;
      pushTime(s);
      return s.handle;
    }
    s.root.classList.remove('is-empty');
    s.root.hidden = false;
    s.row.hidden = false;
    s.start = start; s.end = end; s.fa = num(w.firstAnomaly);
    var secs = Math.max(1, Math.ceil((end - start) / 1000));
    s.step = Math.max(1, Math.round(secs / 150));
    s.max = Math.ceil(secs / s.step) * s.step;
    s.range.disabled = false;
    s.range.min = '0';
    s.range.max = String(s.max);
    s.range.step = String(s.step);
    if (prevAtEnd || prevT == null) s.value = s.max;
    else s.value = clamp(Math.round((prevT - start) / 1000 / s.step) * s.step, 0, s.max);
    s.range.value = String(s.value);
    s.endA.textContent = fmtClock(start);
    s.endB.textContent = fmtClock(end) + ' now';

    // Marks on the track: deploys and the first anomaly, inside the window only.
    clear(s.marks);
    clear(s.key);
    var items = [];
    var seenDeploy = {};
    var deploys = Array.isArray(analysis.deploys) && analysis.deploys.length ? analysis.deploys : (analysis.deploy ? [analysis.deploy] : []);
    var before = [];
    deploys.forEach(function (d) {
      var ts = d && num(d.deployedAt);
      if (ts == null || ts > end) return;
      var label = 'Helm ' + (d.release || 'release') + (d.revision != null ? ' revision ' + d.revision : '') + ' deployed';
      if (seenDeploy[label + ts]) return;
      seenDeploy[label + ts] = true;
      if (ts < start) before.push({ ts: ts, label: label });
      else items.push({ ts: ts, cls: 'mk-deploy', label: label, short: 'Deploy' + (d.revision != null ? ' r' + d.revision : '') });
    });
    if (s.fa != null && s.fa >= start && s.fa <= end) items.push({ ts: s.fa, cls: 'mk-anomaly', label: 'First anomaly', short: 'First anomaly' });
    items.sort(function (a, b) { return a.ts - b.ts; });
    var labs = [];
    items.slice(0, 4).forEach(function (it) {
      var f = (it.ts - start) / (end - start);
      var mk = htmlEl('span', { 'class': 'wr-scrub-mark ' + it.cls }, s.marks);
      mk.style.left = 'calc(9px + (100% - 18px) * ' + f.toFixed(4) + ')';
      // A short label on the track itself. Two marks close together split: the first reads to the
      // left of its tick, the second to the right; a third crowded one is left to the key below.
      var align = f < 0.12 ? 'start' : f > 0.88 ? 'end' : 'mid';
      var prev = labs[labs.length - 1];
      if (prev && f - prev.f < 0.3) {
        if (prev.align === 'mid' && f <= 0.88) { prev.el.className = 'wr-scrub-mlabel al-end'; prev.align = 'end'; align = 'start'; }
        else align = 'skip';
      }
      if (align !== 'skip') labs.push({ f: f, align: align, el: htmlEl('span', { 'class': 'wr-scrub-mlabel al-' + align }, mk, it.short) });
      var li = htmlEl('li', { 'class': it.cls }, s.key);
      htmlEl('span', { 'class': 'k-sw', 'aria-hidden': 'true' }, li);
      htmlEl('span', null, li, it.label + ' ' + fmtClock(it.ts) + ' UTC');
    });
    before.slice(0, 2).forEach(function (b) {
      var li = htmlEl('li', { 'class': 'mk-before' }, s.key);
      htmlEl('span', { 'class': 'k-sw', 'aria-hidden': 'true' }, li);
      htmlEl('span', null, li, b.label + ' ' + fmtClock(b.ts) + ' UTC, ' + fmtDur(start - b.ts) + ' before this timeline starts');
    });
    s.key.hidden = !items.length && !before.length;
    s.root.classList.toggle('has-ticks', items.length > 0);
    s.zone = zoneNote(analysis, opts && opts.defaultTz);
    setNote(s);
    pushTime(s);
    return s.handle;
  }

  function mountScrubber(containerEl, analysis, mapHandle, opts) {
    if (!containerEl) throw new Error('WR.ui.map.mountScrubber needs a container element');
    var s = scrubbers.get(containerEl);
    if (!s) { s = createScrubber(containerEl); scrubbers.set(containerEl, s); }
    return updateScrubber(s, analysis, mapHandle, opts || {});
  }

  ui.map = {
    render: render,
    mountScrubber: mountScrubber,
    // exposed for tests and the harness; not part of the app contract
    _buildModel: buildModel,
    _statsAt: statsAt
  };
})(globalThis.WR = globalThis.WR || {});
