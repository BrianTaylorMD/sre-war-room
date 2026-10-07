/*
 * app.js — WR.ui.app: the application shell of the SRE War Room.
 *
 * Owns the page state (four evidence panes, the Context fields, the stack scale fields), runs
 * WR.analyze live (debounced 250 ms), and draws everything on the board except the map internals
 * (WR.ui.map) and the Claude panel internals (WR.ui.investigate). Those two modules and the data
 * modules (WR.stacks, WR.stackFit) are optional here: every call is guarded, so the page
 * works with any of them missing.
 *
 * Safety rules kept throughout: pasted and engine text only ever reaches the DOM through
 * textContent / createTextNode (the h() helper below), never innerHTML. localStorage is wrapped in
 * try/catch and is only a convenience (theme, last tab, an unsent draft). No network calls.
 */
(function (WR) {
  'use strict';

  WR.ui = WR.ui || {};

  var doc = document;
  var PANES = [
    { key: 'logs', label: 'Logs & events' },
    { key: 'traces', label: 'Traces' },
    { key: 'alerts', label: 'Alerts' },
    { key: 'helm', label: 'Helm diff & history' }
  ];
  var PANE_KEYS = PANES.map(function (p) { return p.key; });
  var STORE_KEYS = { theme: 'wr.theme', tab: 'wr.tab', draft: 'wr.draft.v1' };
  var DEFAULT_SAMPLE = 'bad-deploy-oom';
  var SECTION_IDS = ['map', 'causes', 'rollback', 'budget', 'claude', 'stacks', 'evidence'];
  var SCALE_DEFAULTS = { nodes: 40, logsGbPerDay: 50, activeSeries: 500000, apmHosts: 20 };
  var SRE_WORKBOOK = 'https://sre.google/workbook/alerting-on-slos/';

  var SEV = {
    SEV1: { short: 'users affected, budget burning fast',
      long: 'Severity 1: a user-facing component is failing and the error budget is burning at 14.4 times the sustainable rate or faster.' },
    SEV2: { short: 'users see degraded service',
      long: 'Severity 2: users see degraded service, or the error budget is burning at 6 times the sustainable rate or faster.' },
    SEV3: { short: 'failing, but not user-facing',
      long: 'Severity 3: something is failing, but not on a path users call directly.' },
    SEV4: { short: 'no user impact found',
      long: 'Severity 4: no user impact found in the evidence so far.' }
  };
  var KIND_LABEL = {
    oom_killed: 'Out of memory', crash_loop: 'Crash loop', image_pull: 'Image pull', config_error: 'Config error',
    probe_failed: 'Probe failed', evicted: 'Evicted', node_not_ready: 'Node not ready', node_pressure: 'Node pressure',
    scheduling_failed: 'Cannot schedule', pvc_pending: 'Volume pending', dns_failure: 'Name lookup failed',
    conn_refused: 'Connection refused', timeout: 'Timeout', tls_error: 'Certificate', http_5xx: 'Server error (5xx)',
    http_429: 'Rate limited (429)', throttled: 'Throttled', hpa_maxed: 'Autoscaler at max', rollout: 'Rollout', restart: 'Restart',
    panic: 'Crash / exception', db_error: 'Database error', conn_exhaustion: 'Connections exhausted', migration: 'Migration',
    error_generic: 'Error', span_error: 'Failed span', span_slow: 'Slow span', alert_firing: 'Alert firing',
    alert_resolved: 'Alert resolved', slo_burn: 'Budget burn', change: 'Change'
  };
  var CATEGORY_LABEL = {
    'bad-deploy': 'Bad deploy', 'resource-limits': 'Resource limits', 'config-error': 'Config error', 'image-pull': 'Image pull',
    'dependency-failure': 'Dependency failure', dns: 'Name lookups', 'tls-cert': 'Certificate', 'node-pressure': 'Node pressure',
    'scheduling-capacity': 'Scheduling capacity', 'probe-misconfig': 'Probe settings', 'network-policy': 'Network policy',
    'connection-exhaustion': 'Connection exhaustion', 'rate-limiting': 'Rate limiting', unknown: 'Unclear'
  };
  var RB_KIND_LABEL = {
    'helm-rollback': 'Helm rollback', 'rollout-undo': 'Rollout undo', 'set-image': 'Set image', 'resource-restore': 'Restore resources',
    'config-revert': 'Revert config', 'canary-abort': 'Abort canary', 'traffic-shift': 'Shift traffic', scale: 'Scale',
    'roll-forward': 'Roll forward', restart: 'Restart (stop-gap)'
  };
  var STATUS_LABEL = { root: 'Suspected root', failing: 'Failing', degraded: 'Degraded', 'at-risk': 'At risk', healthy: 'Healthy' };
  var STATUS_PILL = { root: 'pill--root', failing: 'pill--fail', degraded: 'pill--degraded', 'at-risk': 'pill--risk', healthy: 'pill--ok' };
  var TYPE_LABEL = { service: 'Service', datastore: 'Datastore', external: 'External dependency', node: 'Kubernetes node', infra: 'Cluster add-on' };
  var SOURCE_LABEL = { logs: 'Logs', traces: 'Traces', alerts: 'Alerts', helm: 'Helm' };
  var KC_KIND = { announced: 'Announced', released: 'Released', talk: 'Talk', doc: 'Docs', 'documented-limit': 'Documented limit' };
  var ERROR_SOURCE = {
    override: 'set by hand in Context', alert: 'from the burn-rate alert', traces: 'from the pasted traces',
    logs: 'from request lines in the logs', default: 'assumed'
  };

  var state = {
    analysis: null,
    ms: 0,
    example: null,        // { id, title, blurb, texts } while a sample's evidence is on the page
    hidden: {},           // sample context with no visible control: now, year, cluster
    tab: 'logs',
    theme: 'system',
    openHyps: {},
    openRbs: {},
    drawerId: null,
    drawerReturn: null,
    dialogReturn: null,
    mapHandle: null,
    inv: null,
    invTried: false,
    downloads: undefined, // undefined while resolving, null when unavailable, else the namespace
    stacksKey: null,
    stacksDetail: false,
    protectDraft: false,  // a saved draft exists while an example is on screen: do not overwrite it
    chartWidth: 0,
    timer: 0,
    draftTimer: 0,
    scaleTimer: 0,
    backTimer: 0,
    booted: false,
    errors: []
  };

  /* ------------------------------------------------------------------ storage (per viewer, optional) */
  var store = {
    get: function (k) { try { return window.localStorage.getItem(k); } catch (e) { return null; } },
    set: function (k, v) { try { window.localStorage.setItem(k, v); } catch (e) { /* blocked or full: fine */ } },
    del: function (k) { try { window.localStorage.removeItem(k); } catch (e) { /* blocked: fine */ } }
  };

  /* ------------------------------------------------------------------ DOM helpers */
  function $(sel, root) { return (root || doc).querySelector(sel); }
  function $$(sel, root) { return Array.prototype.slice.call((root || doc).querySelectorAll(sel)); }
  function clear(node) { while (node && node.firstChild) node.removeChild(node.firstChild); return node; }

  function add(node, c) {
    if (c == null || c === false) return;
    if (Array.isArray(c)) { for (var i = 0; i < c.length; i++) add(node, c[i]); return; }
    if (typeof c === 'string' || typeof c === 'number') node.appendChild(doc.createTextNode(String(c)));
    else node.appendChild(c);
  }

  // h('div', {class, text, on:{click}, ...attrs}, ...children). Text goes in as text nodes only.
  function h(tag, props) {
    var node = doc.createElement(tag);
    setProps(node, props);
    for (var i = 2; i < arguments.length; i++) add(node, arguments[i]);
    return node;
  }
  var SVGNS = 'http://www.w3.org/2000/svg';
  function s(tag, props) {
    var node = doc.createElementNS(SVGNS, tag);
    setProps(node, props);
    for (var i = 2; i < arguments.length; i++) add(node, arguments[i]);
    return node;
  }
  function setProps(node, props) {
    if (!props) return;
    Object.keys(props).forEach(function (k) {
      var v = props[k];
      if (v == null || v === false) return;
      if (k === 'class') node.setAttribute('class', v);
      else if (k === 'text') node.textContent = String(v);
      else if (k === 'on') Object.keys(v).forEach(function (ev) { node.addEventListener(ev, v[ev]); });
      else if (k === 'hidden') node.hidden = true;
      else if (k === 'disabled') node.disabled = true;
      else node.setAttribute(k, v === true ? '' : String(v));
    });
  }

  function reducedMotion() {
    try { return window.matchMedia('(prefers-reduced-motion: reduce)').matches; } catch (e) { return false; }
  }
  function isPhone() {
    try { return window.matchMedia('(max-width: 760px)').matches; } catch (e) { return false; }
  }
  function cssEscape(v) {
    if (window.CSS && CSS.escape) return CSS.escape(v);
    return String(v).replace(/["\\]/g, '\\$&');
  }

  /* ------------------------------------------------------------------ formatting */
  function pad2(n) { return (n < 10 ? '0' : '') + n; }
  function fmtClock(ts) {
    if (ts == null || !isFinite(ts)) return '—';
    var d = new Date(ts);
    return pad2(d.getUTCHours()) + ':' + pad2(d.getUTCMinutes()) + ':' + pad2(d.getUTCSeconds());
  }
  function fmtDay(ts) {
    var d = new Date(ts == null || !isFinite(ts) ? Date.now() : ts);
    return d.getUTCFullYear() + '-' + pad2(d.getUTCMonth() + 1) + '-' + pad2(d.getUTCDate());
  }
  function fmtStamp(ts) {
    if (ts == null || !isFinite(ts)) return '—';
    return fmtDay(ts) + ' ' + fmtClock(ts).slice(0, 5) + ' UTC';
  }
  function offsetMin(tz) {
    try { return WR.time && WR.time.offsetMinutes ? WR.time.offsetMinutes(tz) : null; } catch (e) { return null; }
  }
  function fmtLocal(ts, tz) {
    var off = offsetMin(tz);
    if (ts == null || !isFinite(ts) || !off) return null;
    return fmtClock(ts + off * 60000).slice(0, 5) + ' ' + tz;
  }
  // "6 hours" → "6-hour", for "6-hour window".
  function hyph(w) { return String(w || '').replace(/^(\d+) (minute|hour|day)s?$/, '$1-$2'); }
  function fmtInt(n) { return n == null || !isFinite(n) ? '—' : Math.round(n).toLocaleString('en-US'); }
  function fmtBurn(b) {
    if (b == null || !isFinite(b)) return '—';
    // Small burns keep two decimals so rescaled thresholds read as computed (2.88x, 3.36x, 0.23x).
    return b >= 100 ? String(Math.round(b)) : b >= 10 ? String(Math.round(b * 10) / 10) : String(Math.round(b * 100) / 100);
  }
  function pct(n, d) { return WR.fmtPct ? WR.fmtPct(n, d) : (n == null ? '—' : n.toFixed(1) + '%'); }
  function ratio(r) {
    if (r == null || !isFinite(r)) return '—';
    var v = r * 100;
    return pct(v, v === 0 ? 0 : v < 0.1 ? 3 : v < 10 ? 2 : 1);
  }
  function dur(ms) { return WR.fmtDuration ? WR.fmtDuration(ms) : Math.round(ms / 60000) + ' min'; }
  function plural(n, one, many) { return fmtInt(n) + ' ' + (n === 1 ? one : (many || one + 's')); }
  function targetPct(t) { return t == null ? '—' : String(+(t * 100).toFixed(4)) + '%'; }
  function srcLine(source, line) {
    var s = SOURCE_LABEL[source] || source || 'Evidence';
    return line != null ? s + ' · line ' + line : s;
  }
  function kindLabel(k) { return KIND_LABEL[k] || String(k || '').replace(/_/g, ' '); }

  /* ------------------------------------------------------------------ analysis lookups */
  function compById(a, id) {
    if (!a || !id) return null;
    var list = a.components || [];
    for (var i = 0; i < list.length; i++) if (list[i].id === id) return list[i];
    return null;
  }
  function compName(a, id) {
    var c = compById(a, id);
    if (c) return c.name;
    if (!id) return 'unassigned';
    var tail = String(id).split('/').pop();
    return tail || String(id);
  }
  function signalById(a, id) {
    if (!a || !id) return null;
    var list = a.signals || [];
    for (var i = 0; i < list.length; i++) if (list[i].id === id) return list[i];
    return null;
  }
  function hasInput(a) {
    var p = (a && a.inputsPresent) || {};
    return !!(p.logs || p.traces || p.alerts || p.helm);
  }
  function statusCounts(a) {
    var c = { failing: 0, degraded: 0, risk: 0, total: 0 };
    (a.components || []).forEach(function (x) {
      c.total++;
      if (x.status === 'root' || x.status === 'failing') c.failing++;
      else if (x.status === 'degraded') c.degraded++;
      else if (x.status === 'at-risk') c.risk++;
    });
    return c;
  }

  /* ------------------------------------------------------------------ inputs */
  function ta(key) { return doc.getElementById('in-' + key); }
  function getPaneTexts() {
    var o = {};
    PANE_KEYS.forEach(function (k) { o[k] = ta(k) ? ta(k).value : ''; });
    return o;
  }
  function anyText() {
    return PANE_KEYS.some(function (k) { return ta(k) && ta(k).value.trim() !== ''; });
  }
  function numOrNull(v) {
    if (v == null || String(v).trim() === '') return null;
    var n = Number(v);
    return isFinite(n) ? n : null;
  }
  function readFields() {
    return {
      target: $('#ctx-target').value, window: $('#ctx-window').value, rpm: $('#ctx-rpm').value,
      spent: $('#ctx-spent').value, ratio: $('#ctx-ratio').value, tz: $('#ctx-tz').value, deployed: $('#ctx-deployed').value
    };
  }
  function setFields(f) {
    f = f || {};
    ensureOption($('#ctx-target'), f.target || '99.9', function (v) { return v + '%'; });
    ensureOption($('#ctx-window'), f.window || '30', function (v) { return v + ' days'; });
    $('#ctx-rpm').value = f.rpm != null ? f.rpm : '';
    $('#ctx-spent').value = f.spent != null ? f.spent : '';
    $('#ctx-ratio').value = f.ratio != null ? f.ratio : '';
    ensureOption($('#ctx-tz'), f.tz || 'Z', tzLabel);
    $('#ctx-deployed').value = f.deployed || '';
  }
  function ensureOption(sel, value, labelFn) {
    var v = String(value);
    var found = $$('option', sel).some(function (o) { return o.value === v; });
    if (!found) sel.appendChild(h('option', { value: v }, labelFn(v)));
    sel.value = v;
  }
  // A sample's context (engine shape) → the visible fields.
  function fieldsFromContext(ctx) {
    var slo = (ctx && ctx.slo) || {};
    var t = slo.target != null ? (slo.target < 1 ? slo.target * 100 : slo.target) : 99.9;
    var dep = '';
    if (ctx && ctx.deployedAt) {
      var ms = Date.parse(ctx.deployedAt);
      if (isFinite(ms)) dep = new Date(ms).toISOString().slice(0, 19);
    }
    return {
      target: String(+Number(t).toFixed(4)),
      window: String(slo.windowDays || 30),
      rpm: slo.requestsPerMin != null ? String(slo.requestsPerMin) : '',
      spent: slo.budgetSpentBeforePct != null ? String(slo.budgetSpentBeforePct) : '',
      ratio: slo.errorRatioOverride != null ? String(+(slo.errorRatioOverride * 100).toFixed(4)) : '',
      tz: (ctx && ctx.defaultTz) || 'Z',
      deployed: dep
    };
  }
  function readContext() {
    var f = readFields();
    var c = {};
    var hid = state.hidden || {};
    if (hid.now) c.now = hid.now;
    if (hid.year) c.year = hid.year;
    if (hid.cluster) c.cluster = hid.cluster;
    c.defaultTz = f.tz || 'Z';
    if (f.deployed) c.deployedAt = (f.deployed.length === 16 ? f.deployed + ':00' : f.deployed) + 'Z';
    var slo = { target: Number(f.target) / 100, windowDays: Number(f.window) };
    var rpm = numOrNull(f.rpm); if (rpm != null) slo.requestsPerMin = rpm;
    var spent = numOrNull(f.spent); if (spent != null) slo.budgetSpentBeforePct = spent;
    var r = numOrNull(f.ratio); if (r != null) slo.errorRatioOverride = r / 100;
    c.slo = slo;
    return c;
  }
  function readInputs() {
    var t = getPaneTexts();
    return { logs: t.logs, traces: t.traces, alerts: t.alerts, helm: t.helm, context: readContext() };
  }
  function readScale() {
    function v(id, d) { var n = numOrNull($(id) && $(id).value); return n == null || n < 0 ? d : n; }
    return {
      nodes: v('#scale-nodes', SCALE_DEFAULTS.nodes),
      logsGbPerDay: v('#scale-logs-gb', SCALE_DEFAULTS.logsGbPerDay),
      activeSeries: v('#scale-series', SCALE_DEFAULTS.activeSeries),
      apmHosts: v('#scale-apm-hosts', SCALE_DEFAULTS.apmHosts)
    };
  }

  /* ------------------------------------------------------------------ zones */
  function tzLabel(v) {
    if (v === 'Z') return 'UTC (Z)';
    return 'UTC' + String(v).replace('-', '−');
  }
  function buildTzOptions() {
    var sel = $('#ctx-tz');
    clear(sel);
    var mins = [];
    for (var hr = -12; hr <= 14; hr++) mins.push(hr * 60);
    [-570, -210, 210, 270, 330, 345, 390, 570, 630].forEach(function (m) { mins.push(m); });
    mins.sort(function (x, y) { return x - y; });
    mins.forEach(function (m) {
      var v = m === 0 ? 'Z' : (m < 0 ? '-' : '+') + pad2(Math.floor(Math.abs(m) / 60)) + ':' + pad2(Math.abs(m) % 60);
      sel.appendChild(h('option', { value: v }, tzLabel(v)));
    });
    sel.value = 'Z';
  }

  /* ------------------------------------------------------------------ analysis loop */
  function analyzeNow() {
    clearTimeout(state.timer);
    state.timer = 0;
    var a = null;
    var t0 = (window.performance && performance.now) ? performance.now() : Date.now();
    try { a = WR.analyze(readInputs()); } catch (e) { a = null; recordError('analysis', e); }
    var t1 = (window.performance && performance.now) ? performance.now() : Date.now();
    state.ms = t1 - t0;
    if (a && a.version) state.analysis = a;          // keep the previous good analysis otherwise
    if (!state.analysis) return;
    renderAll();
  }
  function scheduleAnalyze() {
    setLive(true);
    clearTimeout(state.timer);
    state.timer = setTimeout(analyzeNow, 250);
  }
  function setLive(busy) {
    var l = $('#live');
    if (!l) return;
    l.classList.toggle('is-busy', !!busy);
    l.textContent = busy ? 'Updating…' : 'Live · analyzed in ' + Math.max(1, Math.round(state.ms)) + ' ms';
  }

  function renderAll() {
    var a = state.analysis;
    guard('strip', renderStrip, a);
    guard('rail', renderRail, a);
    guard('map', renderMap, a);
    guard('causes', renderCauses, a);
    guard('rollback', renderRollbacks, a);
    guard('budget', renderBudget, a);
    guard('claude', updateClaude, a);
    guard('stacks', renderStacks, a);
    guard('drawer', refreshDrawer, a);
    setLive(false);
  }
  var SECTION_HOST = {
    map: '#map-canvas', causes: '#causes-body', rollback: '#rollback-body', budget: '#budget-body',
    claude: '#claude-body', stacks: '#stacks-body'
  };
  function guard(name, fn, a) {
    try { fn(a); } catch (e) {
      recordError(name, e);
      var host = SECTION_HOST[name] && $(SECTION_HOST[name]);
      if (host) {
        clear(host);
        host.appendChild(h('p', { class: 'sec-err', role: 'status' },
          'This part of the board could not be drawn (' + (e && e.message ? e.message : String(e)) + '). The rest of the page still works.'));
      }
    }
  }
  function recordError(where, e) {
    state.errors.push({ where: where, message: e && e.message ? e.message : String(e), at: Date.now() });
    if (state.errors.length > 50) state.errors.shift();
  }

  /* ------------------------------------------------------------------ status strip */
  function renderStrip(a) {
    var has = hasInput(a);
    var sev = has && SEV[a.severity] ? a.severity : 'none';
    var meaning = sev === 'none'
      ? { short: 'waiting for evidence', long: 'No severity yet. Paste evidence to assess the incident.' }
      : SEV[sev];
    $('#strip').setAttribute('data-sev', sev);
    $('#minibar').setAttribute('data-sev', sev);
    $('#sev-n').textContent = sev === 'none' ? '–' : sev.replace('SEV', '');
    var sevEl = $('#sev');
    sevEl.title = meaning.long;
    sevEl.setAttribute('aria-label', meaning.long);
    $('#headline').textContent = a.headline || '';
    announceSeverity(sev, a.headline || '');
    $('#headline').title = a.headline || '';
    $('#tag-example').hidden = !state.example;

    var b = a.budget || {};
    var ev = !!b.hasEvidence;
    var w = a.window || {};
    var page = (b.alertRows && b.alertRows[0] && b.alertRows[0].burnThreshold) || 14.4;
    var slow = (b.alertRows && b.alertRows[1] && b.alertRows[1].burnThreshold) || 6;
    setMetric('#m-elapsed', w.firstAnomaly != null && w.now != null ? dur(Math.max(0, w.now - w.firstAnomaly)) : '—');
    setMetric('#m-burn', ev ? fmtBurn(b.burnRate) + '×' : '—', ev ? (b.burnRate >= page ? 'hot' : b.burnRate >= slow ? 'warm' : '') : 'none');
    setMetric('#m-used', ev ? pct(b.consumedPct) : '—', ev ? '' : 'none');
    var cl = a.clusters || [];
    var hit = cl.filter(function (c) { return c.status && c.status !== 'healthy'; }).length;
    setMetric('#m-clusters', cl.length ? hit + ' of ' + cl.length : '—', cl.length ? (hit ? '' : '') : 'none');

    var mb = $('#mb-sev');
    mb.textContent = sev === 'none' ? 'No data' : sev;
    mb.className = 'pill mb-sev ' + (sev === 'SEV1' ? 'pill--fail' : sev === 'SEV2' ? 'pill--warn-solid' : sev === 'SEV3' ? 'pill--warn-line' : 'pill--muted');
    $('#mb-head').textContent = a.headline || '';
    $('#mb-burn').textContent = ev ? fmtBurn(b.burnRate) + '×' : '';
  }
  // Screen readers hear a change of severity or headline, at most once every few seconds, instead
  // of every debounced re-analysis while someone types.
  function announceSeverity(sev, headline) {
    var key = sev + '|' + headline;
    if (state.sevKey === undefined) { state.sevKey = key; return; }
    if (key === state.sevKey) return;
    state.sevKey = key;
    var say = function () {
      state.sevAt = Date.now();
      state.sevTimer = 0;
      var cur = state.sevKey.split('|');
      announce(cur[0] === 'none' ? 'No severity yet.' : 'Severity ' + cur[0].replace('SEV', '') + ': ' + cur.slice(1).join('|'));
    };
    var wait = 4000 - (Date.now() - (state.sevAt || 0));
    clearTimeout(state.sevTimer);
    if (wait <= 0) say(); else state.sevTimer = setTimeout(say, wait);
  }
  function setMetric(sel, text, tone) {
    var n = $(sel);
    n.textContent = text;
    n.className = 'metric-v' + (tone ? ' is-' + tone : '') + (text === '—' ? ' is-none' : '');
  }

  /* ------------------------------------------------------------------ evidence rail */
  function statsText(st, tz) {
    var parts = [plural(st.lines || 0, 'line'), plural(st.signals || 0, 'signal')];
    if (st.format && st.format !== 'empty') parts.push(st.format);
    if (st.tzAssumed) parts.push(plural(st.tzAssumed, 'time') + ' assumed ' + (tz === 'Z' ? 'UTC' : tz));
    if (st.skipped) parts.push(fmtInt(st.skipped) + ' skipped');
    return parts.join(' · ');
  }
  function renderRail(a) {
    var tz = $('#ctx-tz').value || 'Z';
    var shown = {};
    PANES.forEach(function (p) {
      var st = (a.stats || {})[p.key] || {};
      var hasText = ta(p.key).value.trim() !== '';
      var tab = $('#tab-' + p.key);
      var pane = $('#pane-' + p.key);
      $('.tab-c', tab).textContent = hasText ? plural(st.signals || 0, 'signal') : 'Empty';
      $('.dot', tab).className = 'dot' + (hasText ? ' is-on' : '');
      var stat = $('[data-stat]', pane);
      stat.textContent = hasText ? statsText(st, tz) : 'Nothing pasted yet.';
      stat.classList.toggle('is-empty', !hasText);
      var wl = clear($('[data-warn]', pane));
      var warns = hasText ? (st.warnings || []) : [];
      warns.forEach(function (w) { shown[w] = true; wl.appendChild(h('li', { text: w })); });
      wl.hidden = !warns.length;
      $('[data-clear]', pane).disabled = !hasText;
    });
    var notes = (a.warnings || []).filter(function (w) { return !shown[w]; });
    var list = clear($('#rail-notes-list'));
    notes.forEach(function (w) { list.appendChild(h('li', { text: w })); });
    $('#rail-notes').hidden = !notes.length;
  }

  function selectTab(key, opts) {
    if (PANE_KEYS.indexOf(key) < 0) key = 'logs';
    state.tab = key;
    PANES.forEach(function (p) {
      var on = p.key === key;
      var t = $('#tab-' + p.key);
      t.setAttribute('aria-selected', on ? 'true' : 'false');
      t.tabIndex = on ? 0 : -1;
      $('#pane-' + p.key).hidden = !on;
    });
    if (!opts || opts.save !== false) store.set(STORE_KEYS.tab, key);
    if (opts && opts.focusTab) $('#tab-' + key).focus();
  }

  /* ------------------------------------------------------------------ jump to a pasted line */
  function paneBySource(source) {
    return PANE_KEYS.indexOf(source) >= 0 ? source : null;
  }
  function lineStarts(text) {
    if (WR.lineIndex) return WR.lineIndex(text);
    var starts = [0], i = -1;
    while ((i = text.indexOf('\n', i + 1)) !== -1) starts.push(i + 1);
    return starts;
  }
  function jumpTo(source, line, opts) {
    var key = paneBySource(source);
    if (!key) return false;
    var from = opts && opts.from;
    selectTab(key);
    var t = ta(key);
    var text = t.value;
    var starts = lineStarts(text);
    var n = Number(line);
    var note = $('#pane-' + key + ' [data-jumpnote]');
    var smooth = reducedMotion() ? 'auto' : 'smooth';
    var rail = $('#evidence');
    if (getComputedStyle(rail).position === 'sticky') {
      // Wide screens: the rail stays in view, so scroll only inside it and leave the board where it is.
      var rr = rail.getBoundingClientRect(), tr = t.getBoundingClientRect();
      if (tr.top < rr.top || tr.bottom > rr.bottom) rail.scrollTop += tr.top - rr.top - 56;
    } else {
      try { t.scrollIntoView({ block: 'center', behavior: smooth }); } catch (e) { t.scrollIntoView(); }
    }
    if (!(n >= 1 && n <= starts.length)) {
      note.textContent = '';
      t.focus({ preventScroll: true });
      return true;
    }
    var start = starts[n - 1];
    var end = n < starts.length ? starts[n] - 1 : text.length;
    if (end > start && text.charCodeAt(end - 1) === 13) end--;
    var coarse = false;
    try { coarse = window.matchMedia('(pointer: coarse)').matches; } catch (e) { coarse = false; }
    if (coarse) {
      // Select without opening the on-screen keyboard; the next tap makes it editable again.
      t.readOnly = true;
      var undo = function () { t.readOnly = false; t.removeEventListener('blur', undo); t.removeEventListener('pointerdown', undo); };
      t.addEventListener('blur', undo);
      t.addEventListener('pointerdown', undo);
    }
    t.focus({ preventScroll: true });
    try { t.setSelectionRange(start, end, 'forward'); } catch (e) { /* old engines */ }
    var lh = parseFloat(getComputedStyle(t).lineHeight) || 19;
    t.scrollTop = Math.max(0, (n - 1) * lh - (t.clientHeight - lh) / 2);
    t.scrollLeft = 0;
    flashLine(t, n, lh);
    note.textContent = 'Line ' + n + ' selected' + (from ? ' · Esc to go back' : '');
    clearTimeout(state.noteTimer);
    state.noteTimer = setTimeout(function () { note.textContent = ''; }, from ? 12000 : 6000);
    if (from) offerBack(from, key);
    return true;
  }
  function flashLine(t, n, lh) {
    var wrap = t.parentNode;
    $$('.ta-flash', wrap).forEach(function (x) { x.remove(); });
    var cs = getComputedStyle(t);
    var top = t.offsetTop + t.clientTop + (parseFloat(cs.paddingTop) || 0) + (n - 1) * lh - t.scrollTop;
    if (top < 0 || top > t.clientHeight) return;
    var mark = h('div', { class: 'ta-flash', 'aria-hidden': 'true' });
    mark.style.top = top + 'px';
    wrap.appendChild(mark);
    var gone = function () { mark.remove(); t.removeEventListener('scroll', gone); t.removeEventListener('input', gone); };
    t.addEventListener('scroll', gone);
    t.addEventListener('input', gone);
    setTimeout(gone, reducedMotion() ? 3000 : 2300);
  }
  function jumpToSignal(id, opts) {
    var sig = signalById(state.analysis, id);
    if (!sig) return false;
    return jumpTo(sig.source, sig.line, opts);
  }
  // After a jump to a pasted line: Escape in that pane, or the "Back to …" pill, returns to the
  // control the jump came from. The pill stays while focus is still in the pane.
  function isFocusable(el) {
    return !!el && (el.getAttribute && el.getAttribute('tabindex') != null || /^(BUTTON|A|INPUT|SELECT|TEXTAREA|SUMMARY)$/.test(el.tagName));
  }
  function goBack() {
    var from = state.backFrom;
    state.backFrom = null;
    state.backPane = null;
    clearTimeout(state.backTimer);
    $('#backpill').hidden = true;
    if (!from) return;
    if (!doc.contains(from) && state.backComp) {
      try { from = $('#map-canvas [data-component="' + cssEscape(state.backComp) + '"]'); } catch (e) { from = null; }
    }
    if (!from || !doc.contains(from)) return;
    if (!isFocusable(from)) from.setAttribute('tabindex', '-1');
    try { from.scrollIntoView({ block: 'center', behavior: reducedMotion() ? 'auto' : 'smooth' }); } catch (e) { from.scrollIntoView(); }
    try { from.focus({ preventScroll: true }); } catch (e) { from.focus(); }
  }
  function offerBack(from, paneKey) {
    clearTimeout(state.backTimer);
    state.backFrom = from;
    state.backPane = paneKey || null;
    state.backComp = from && from.getAttribute ? from.getAttribute('data-component') : null;
    var pill = $('#backpill');
    setTimeout(function () {
      if (state.backFrom !== from || !doc.contains(from)) return;
      var r = from.getBoundingClientRect();
      var visible = r.bottom > 0 && r.top < window.innerHeight;
      if (visible) { pill.hidden = true; return; }
      var sec = from.closest('section');
      var title = sec && $('.sec-title', sec) ? $('.sec-title', sec).textContent : 'where you were';
      var btn = $('#backpill-btn');
      btn.textContent = 'Back to ' + title;
      btn.onclick = goBack;
      pill.hidden = false;
      var hide = function () {
        // Still reading or editing the line it jumped to: keep the way back on screen.
        if (state.backPane && doc.activeElement === ta(state.backPane)) { state.backTimer = setTimeout(hide, 4000); return; }
        pill.hidden = true;
      };
      state.backTimer = setTimeout(hide, 12000);
    }, 650);
  }

  /* ------------------------------------------------------------------ copy */
  function announce(msg) {
    var r = $('#sr-live');
    if (!r) { r = h('div', { id: 'sr-live', class: 'sr-only', 'aria-live': 'polite' }); doc.body.appendChild(r); }
    r.textContent = '';
    setTimeout(function () { r.textContent = msg; }, 30);
  }
  function legacyCopy(text) {
    var t = h('textarea', { class: 'sr-only', 'aria-hidden': 'true', readonly: true });
    t.value = text;
    doc.body.appendChild(t);
    t.select();
    var ok = false;
    try { ok = doc.execCommand && doc.execCommand('copy'); } catch (e) { ok = false; }
    t.remove();
    return !!ok;
  }
  function selectContents(node) {
    if (!node) return;
    if (node.tagName === 'TEXTAREA' || node.tagName === 'INPUT') { node.focus(); node.select(); return; }
    try {
      var range = doc.createRange();
      range.selectNodeContents(node);
      var sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
    } catch (e) { /* nothing to do */ }
  }
  function flashButton(btn, text, ok) {
    if (!btn) return;
    if (!btn.dataset.label) btn.dataset.label = btn.textContent;
    btn.textContent = text;
    btn.classList.toggle('is-done', !!ok);
    clearTimeout(btn._t);
    btn._t = setTimeout(function () { btn.textContent = btn.dataset.label; btn.classList.remove('is-done'); }, 1800);
  }
  // Clipboard call stays inside the click handler (user activation); fallbacks keep it usable.
  function copyText(text, btn, selectEl) {
    var finish = function (ok) {
      if (ok) { flashButton(btn, 'Copied', true); announce('Copied to the clipboard.'); return; }
      selectContents(selectEl);
      flashButton(btn, 'Selected', false);
      announce('Copying is blocked here. The text is selected: press Control+C or Command+C.');
    };
    try {
      if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
        navigator.clipboard.writeText(text).then(function () { finish(true); }, function () { finish(legacyCopy(text)); });
        return;
      }
    } catch (e) { /* fall through */ }
    finish(legacyCopy(text));
  }
  function codeBlock(text, label) {
    var name = label || 'Command';
    var pre = h('pre', { role: 'group', 'aria-label': name }, h('code', { text: text }));
    var short = String(text).length > 48 ? String(text).slice(0, 47) + '…' : String(text);
    var btn = h('button', { type: 'button', class: 'btn btn--sm btn-copy', 'aria-label': 'Copy ' + name.toLowerCase() + ': ' + short }, 'Copy');
    btn.addEventListener('click', function () { copyText(text, btn, pre); });
    return h('div', { class: 'code' }, pre, btn);
  }

  /* ------------------------------------------------------------------ empty states */
  function emptyState(title, text, items) {
    var box = h('div', { class: 'empty' }, h('p', { class: 'empty-t', text: title }), h('p', { text: text }));
    if (items && items.length) {
      var ul = h('ul');
      items.forEach(function (it) { ul.appendChild(h('li', { text: it })); });
      box.appendChild(ul);
    }
    return box;
  }

  /* ------------------------------------------------------------------ 01 map */
  function onMapSelect(id) {
    var node = null;
    try { node = $('#map-canvas [data-component="' + cssEscape(id) + '"]'); } catch (e) { node = null; }
    openDrawer(id, node || doc.activeElement);
  }
  function renderMap(a) {
    var canvas = $('#map-canvas');
    var c = statusCounts(a);
    var parts = [];
    if (c.failing) parts.push(c.failing + ' failing');
    if (c.degraded) parts.push(c.degraded + ' degraded');
    if (c.risk) parts.push(c.risk + ' at risk');
    if (c.total) parts.push(plural(c.total, 'component'));
    $('#map-meta').textContent = parts.join(' · ');
    var M = WR.ui.map;
    if (M && typeof M.render === 'function') {
      state.mapHandle = M.render(canvas, a, { onSelect: onMapSelect, at: null }) || null;
      if (typeof M.mountScrubber === 'function') M.mountScrubber(canvas, a, state.mapHandle, { defaultTz: $('#ctx-tz').value || 'Z' });
      if (state.drawerId && state.mapHandle && typeof state.mapHandle.highlight === 'function') state.mapHandle.highlight(state.drawerId);
      return;
    }
    renderMapFallback(canvas, a);
  }
  // Used only when the map module is not in the bundle: a plain list of components by cluster.
  function renderMapFallback(canvas, a) {
    clear(canvas);
    var comps = a.components || [];
    if (!comps.length) {
      canvas.appendChild(emptyState('Nothing to map yet',
        'The blast-radius map draws each cluster, its components and the calls between them, shaded by impact.',
        ['Logs or kubectl events name the failing pods', 'Traces show who calls whom', 'Alerts add cluster and service labels']));
      return;
    }
    var order = { root: 0, failing: 1, degraded: 2, 'at-risk': 3, healthy: 4 };
    var byCluster = {};
    comps.forEach(function (x) { (byCluster[x.cluster || 'Unassigned'] = byCluster[x.cluster || 'Unassigned'] || []).push(x); });
    var wrap = h('div', { class: 'map-fallback' });
    Object.keys(byCluster).forEach(function (cl) {
      var info = (a.clusters || []).filter(function (k) { return k.name === cl; })[0];
      var list = h('div', { class: 'mf-list' });
      byCluster[cl].sort(function (x, y) { return (order[x.status] - order[y.status]) || (y.impact - x.impact); }).forEach(function (x) {
        list.appendChild(h('button', {
          type: 'button', class: 'mf-node st-' + x.status, 'data-component': x.id,
          'aria-label': x.name + ', ' + (STATUS_LABEL[x.status] || x.status),
          on: { click: function (e) { openDrawer(x.id, e.currentTarget); } }
        }, h('b', { text: x.name }), h('span', { text: (STATUS_LABEL[x.status] || x.status) + ' · ' + (x.namespace || '') })));
      });
      wrap.appendChild(h('div', { class: 'mf-lane' },
        h('h3', null, cl, info ? h('span', { class: 'pill ' + (STATUS_PILL[info.status] || 'pill--muted'), text: STATUS_LABEL[info.status] || info.status }) : null),
        list));
    });
    canvas.appendChild(wrap);
  }

  /* ------------------------------------------------------------------ component drawer */
  function openDrawer(id, returnEl) {
    var a = state.analysis;
    var c = compById(a, id);
    if (!c) return;
    closeBrief(true);
    state.drawerId = id;
    state.drawerReturn = returnEl || doc.activeElement;
    fillDrawer(c, a);
    setInert(true);
    $('#scrim').hidden = false;
    $('#drawer').hidden = false;
    $('#drawer-body').scrollTop = 0;
    $('#drawer-close').focus();
    if (state.mapHandle && typeof state.mapHandle.highlight === 'function') {
      try { state.mapHandle.highlight(id); } catch (e) { recordError('map.highlight', e); }
    }
  }
  function closeDrawer(opts) {
    if (!state.drawerId) return;
    var id = state.drawerId;
    state.drawerId = null;
    $('#drawer').hidden = true;
    $('#scrim').hidden = true;
    setInert(false);
    if (state.mapHandle && typeof state.mapHandle.highlight === 'function') {
      try { state.mapHandle.highlight(null); } catch (e) { recordError('map.highlight', e); }
    }
    if (opts && opts.noFocus) return;
    var r = state.drawerReturn;
    if (!r || !doc.contains(r)) {
      try { r = $('#map-canvas [data-component="' + cssEscape(id) + '"]'); } catch (e) { r = null; }
    }
    if (r && r.focus) r.focus();
  }
  function refreshDrawer(a) {
    if (!state.drawerId) return;
    var c = compById(a, state.drawerId);
    if (!c) { closeDrawer({ noFocus: true }); return; }
    fillDrawer(c, a);
  }
  function fillDrawer(c, a) {
    var stripe = c.status === 'root' || c.status === 'failing' ? 'stripe-crit' : c.status === 'degraded' ? 'stripe-warn'
      : c.status === 'at-risk' ? 'stripe-warn' : 'stripe-ok';
    $('#drawer-head').className = 'dr-head ' + stripe;
    $('#drawer-title').textContent = c.name;
    var where = [TYPE_LABEL[c.type] || c.type];
    if (c.role === 'ingress') where.push('ingress');
    if (c.cluster) where.push('cluster ' + c.cluster);
    if (c.namespace) where.push('namespace ' + c.namespace);
    $('#drawer-where').textContent = where.join(' · ');
    var tags = clear($('#drawer-tags'));
    tags.appendChild(h('span', { class: 'pill ' + (STATUS_PILL[c.status] || 'pill--muted'), text: STATUS_LABEL[c.status] || c.status }));
    if (c.userFacing) tags.appendChild(h('span', { class: 'chip chip--plain', text: 'User-facing' }));
    if (c.release) tags.appendChild(h('span', { class: 'chip chip--plain', text: 'Helm release ' + c.release }));

    var body = clear($('#drawer-body'));
    var counts = c.counts || {};
    body.appendChild(h('dl', { class: 'dr-facts' },
      h('div', null, h('dt', { text: 'First error' }), h('dd', { text: c.firstErrorTs != null ? fmtClock(c.firstErrorTs) + ' UTC' : 'None' })),
      h('div', null, h('dt', { text: 'Impact' }), h('dd', { text: c.impact != null ? Math.round(c.impact * 100) + '%' : '—' })),
      h('div', null, h('dt', { text: 'Errors · warnings' }), h('dd', { text: fmtInt(counts.error || 0) + ' · ' + fmtInt(counts.warn || 0) }))
    ));
    if (c.kinds && c.kinds.length) {
      body.appendChild(h('h3', { class: 'sub-h', text: 'What the evidence shows' }));
      var k = h('div', { class: 'kinds' });
      c.kinds.forEach(function (x) { k.appendChild(h('span', { class: 'chip', text: kindLabel(x) })); });
      body.appendChild(k);
    }
    var edges = a.edges || [];
    var callers = edges.filter(function (e) { return e.to === c.id; });
    var callees = edges.filter(function (e) { return e.from === c.id; });
    if (callers.length || callees.length) {
      body.appendChild(h('h3', { class: 'sub-h', text: 'Calls' }));
      var ul = h('ul', { class: 'bul' });
      callers.forEach(function (e) { ul.appendChild(h('li', { text: 'Called by ' + compName(a, e.from) + edgeNote(e) })); });
      callees.forEach(function (e) { ul.appendChild(h('li', { text: 'Calls ' + compName(a, e.to) + edgeNote(e) })); });
      body.appendChild(ul);
    }
    if (c.pods && c.pods.length) {
      body.appendChild(h('h3', { class: 'sub-h', text: 'Pods (' + c.pods.length + ')' }));
      var pods = h('ul', { class: 'pods' });
      c.pods.slice(0, 8).forEach(function (p) { pods.appendChild(h('li', null, h('code', { text: p }))); });
      if (c.pods.length > 8) pods.appendChild(h('li', { class: 'muted', text: 'and ' + (c.pods.length - 8) + ' more' }));
      body.appendChild(pods);
    }
    var sigs = (a.signals || []).filter(function (x) { return x.componentId === c.id; });
    sigs.sort(function (x, y) { return (x.ts == null ? Infinity : x.ts) - (y.ts == null ? Infinity : y.ts); });
    body.appendChild(h('h3', { class: 'sub-h', text: 'Signals (' + fmtInt(sigs.length) + ')' }));
    if (!sigs.length) { body.appendChild(h('p', { class: 'none', text: 'No individual signals point at this component; it appears through calls from other components.' })); return; }
    var LIMIT = 120;
    var list = h('ul', { class: 'sigs' });
    sigs.slice(0, LIMIT).forEach(function (x) {
      var btn = h('button', { type: 'button', class: 'btn btn--sm', disabled: x.line == null, 'aria-label': 'Show ' + srcLine(x.source, x.line) }, 'Show line');
      btn.addEventListener('click', function () {
        var back = state.drawerReturn && doc.contains(state.drawerReturn) ? state.drawerReturn : null;
        if (!back) { try { back = $('#map-canvas [data-component="' + cssEscape(c.id) + '"]'); } catch (e) { back = null; } }
        closeDrawer({ noFocus: true });
        jumpTo(x.source, x.line, { from: back || $('#map') });
      });
      list.appendChild(h('li', { class: 'sig-sev-' + x.severity },
        h('span', { class: 'sig-time', title: x.tsInferred ? 'Time assumed or estimated' : null, text: fmtClock(x.ts) + (x.tsInferred ? '*' : '') }),
        h('div', { class: 'sig-main' },
          h('span', { class: 'chip' }, h('i', { class: 'sig-dot', 'aria-hidden': 'true' }), kindLabel(x.kind)),
          h('p', { class: 'sig-text', text: x.text || x.raw || '' })),
        btn));
    });
    body.appendChild(list);
    var foot = 'Times in UTC.' + (sigs.some(function (x) { return x.tsInferred; }) ? ' * time assumed from a relative age or a zone-less stamp.' : '');
    if (sigs.length > LIMIT) foot = 'Showing the first ' + LIMIT + ' of ' + fmtInt(sigs.length) + '. ' + foot;
    body.appendChild(h('p', { class: 'dr-more', text: foot }));
  }
  function edgeNote(e) {
    var bits = [];
    if (e.calls) bits.push(plural(e.calls, 'call'));
    if (e.errorRate) bits.push(ratio(e.errorRate) + ' failed');
    return bits.length ? ' (' + bits.join(', ') + ')' : '';
  }
  // While the drawer or the brief dialog is open, the page behind it is out of reach for touch
  // screen readers and virtual cursors too (trapKeys stays as the keyboard fallback).
  function setInert(on) {
    ['.layout', '#strip', '#minibar', '#backpill'].forEach(function (sel) {
      var n = $(sel);
      if (!n) return;
      if (on) n.setAttribute('inert', ''); else n.removeAttribute('inert');
    });
  }
  function trapKeys(ev, container, onEscape) {
    if (ev.key === 'Escape') { ev.preventDefault(); onEscape(); return; }
    if (ev.key !== 'Tab') return;
    var f = $$('button:not([disabled]), [href], input:not([disabled]), select, textarea, [tabindex]:not([tabindex="-1"])', container)
      .filter(function (x) { return x.offsetParent !== null || x === doc.activeElement; });
    if (!f.length) return;
    var first = f[0], last = f[f.length - 1];
    if (ev.shiftKey && (doc.activeElement === first || !container.contains(doc.activeElement))) { ev.preventDefault(); last.focus(); }
    else if (!ev.shiftKey && (doc.activeElement === last || !container.contains(doc.activeElement))) { ev.preventDefault(); first.focus(); }
  }

  /* ------------------------------------------------------------------ 02 causes */
  function confBand(c) { return c >= 0.75 ? 'strong' : c >= 0.5 ? 'likely' : c >= 0.35 ? 'possible' : 'weak'; }
  var BAND_WORD = { strong: 'Strong', likely: 'Likely', possible: 'Possible', weak: 'Weak' };
  function renderCauses(a) {
    var body = clear($('#causes-body'));
    var hyps = a.hypotheses || [];
    $('#causes-meta').textContent = hyps.length ? plural(hyps.length, 'cause') + ' ranked' : '';
    if (!hyps.length) {
      body.appendChild(emptyState(hasInput(a) ? 'No clear cause yet' : 'No causes yet',
        hasInput(a)
          ? 'The evidence so far does not point at one component strongly enough. More context usually settles it.'
          : 'Ranked root causes appear here, each with the exact lines that support it and the checks to run next.',
        ['Error logs or kubectl get events from the failing pods', 'helm history <release> and the helm diff, so changes line up against the first error',
          'Firing alerts with their cluster and service labels']));
      return;
    }
    var rbByHyp = {};
    (a.rollbacks || []).forEach(function (r, i) {
      (r.fixes || []).forEach(function (id) { (rbByHyp[id] = rbByHyp[id] || []).push({ r: r, i: i }); });
    });
    hyps.forEach(function (hy, i) { body.appendChild(hypCard(hy, i, a, rbByHyp[hy.id] || [])); });
  }
  function hypCard(hy, i, a, fixes) {
    var conf = hy.confidence || 0;
    var band = confBand(conf);
    var stripe = band === 'strong' ? 'stripe-crit' : band === 'likely' ? 'stripe-warn' : 'stripe-muted';
    var key = (hy.rule || '') + '|' + (hy.componentId || '') + '|' + (hy.category || '');
    var open = state.openHyps[key] != null ? state.openHyps[key] : i === 0;
    var comp = compById(a, hy.componentId);
    var card = h('article', { class: 'card hyp ' + stripe + (i === 0 ? ' is-top' : ''), 'data-hypothesis': hy.id, id: 'hyp-' + hy.id, 'aria-labelledby': 'hyp-t-' + hy.id });

    var tags = h('div', { class: 'hyp-tags' }, h('span', { class: 'chip', text: CATEGORY_LABEL[hy.category] || hy.category || 'Unclear' }));
    if (comp) tags.appendChild(h('span', { class: 'chip chip--plain', text: comp.name + (comp.cluster ? ' · ' + comp.cluster : '') }));
    var meter = h('div', { class: 'meter is-' + band, role: 'meter', 'aria-valuemin': '0', 'aria-valuemax': '100', 'aria-valuenow': String(Math.round(conf * 100)), 'aria-label': 'Confidence' }, h('i'));
    meter.firstChild.style.width = Math.round(conf * 100) + '%';
    card.appendChild(h('div', { class: 'hyp-top' },
      h('span', { class: 'rank', 'aria-hidden': 'true', text: String(i + 1) }),
      h('div', { class: 'min0' }, h('h3', { class: 'hyp-title', id: 'hyp-t-' + hy.id }, h('span', { class: 'sr-only', text: 'Cause ' + (i + 1) + ': ' }), hy.title), tags),
      h('div', { class: 'conf' },
        h('span', { class: 'conf-v' }, String(Math.round(conf * 100)), h('small', { text: '%' })),
        meter,
        h('span', { class: 'conf-w', text: BAND_WORD[band] + ' confidence' }))));
    if (hy.summary) card.appendChild(h('p', { class: 'hyp-sum', text: hy.summary }));

    var details = h('div', { class: 'hyp-body', id: 'hyp-b-' + hy.id, hidden: !open });
    var chain = h('ol', { class: 'chain' });
    (hy.evidence || []).forEach(function (ev) {
      var can = ev.line != null && !!paneBySource(ev.source);
      var b = h('button', { type: 'button', class: 'ev', disabled: !can, title: can ? 'Show this line in ' + (SOURCE_LABEL[ev.source] || 'the evidence') : null },
        h('span', { class: 'ev-t', text: ev.text }), h('span', { class: 'ev-src', text: srcLine(ev.source, ev.line) }));
      b.addEventListener('click', function () { jumpTo(ev.source, ev.line, { from: b }); });
      chain.appendChild(h('li', null, b));
    });
    var against = h('ul', { class: 'against' });
    (hy.against || []).forEach(function (x) { against.appendChild(h('li', { text: x.text })); });
    details.appendChild(h('div', { class: 'hyp-cols' },
      h('div', null, h('h4', { class: 'sub-h', text: 'Evidence chain' }), (hy.evidence || []).length ? chain : h('p', { class: 'none', text: 'No direct evidence lines.' })),
      h('div', null, h('h4', { class: 'sub-h', text: 'What argues against it' }),
        (hy.against || []).length ? against : h('p', { class: 'none', text: 'Nothing in the pasted evidence argues against it.' }))));
    if ((hy.nextChecks || []).length) {
      details.appendChild(h('h4', { class: 'sub-h', text: 'Next checks' }));
      var cmds = h('ul', { class: 'cmds' });
      hy.nextChecks.forEach(function (nc) {
        cmds.appendChild(h('li', null, nc.why ? h('p', { class: 'cmd-why', text: nc.why }) : null, codeBlock(nc.cmd, 'Command')));
      });
      details.appendChild(cmds);
    }
    card.appendChild(details);

    var nEv = (hy.evidence || []).length, nCk = (hy.nextChecks || []).length;
    var toggle = h('button', { type: 'button', class: 'toggle', 'aria-expanded': open ? 'true' : 'false', 'aria-controls': 'hyp-b-' + hy.id });
    var label = function (o) {
      return o ? 'Hide evidence and checks' : 'Show evidence (' + nEv + ')' + (nCk ? ' and next checks (' + nCk + ')' : '');
    };
    toggle.textContent = label(open);
    toggle.addEventListener('click', function () {
      var now = details.hidden;
      details.hidden = !now;
      state.openHyps[key] = now;
      toggle.setAttribute('aria-expanded', now ? 'true' : 'false');
      toggle.textContent = label(now);
    });
    var foot = h('div', { class: 'hyp-foot' }, toggle);
    if (fixes.length) {
      var f = h('span', { class: 'fixedby' }, 'Fixed by: ');
      fixes.slice(0, 2).forEach(function (x) {
        var lb = h('button', { type: 'button', class: 'linkbtn', text: x.r.title + (x.r.recommended ? ' (recommended)' : '') });
        lb.addEventListener('click', function () { focusCard('#rb-' + cssEscape(x.r.id)); });
        // The separator is drawn by CSS on the item, so it never ends up alone on a wrapped line.
        f.appendChild(h('span', { class: 'fix' }, lb));
      });
      foot.appendChild(f);
    }
    card.appendChild(foot);
    return card;
  }
  function focusCard(sel) {
    var n = $(sel);
    if (!n) return;
    // An option inside the closed "Unlikely to help" group has no box until the group opens.
    var d = n.parentNode && n.parentNode.closest ? n.parentNode.closest('details') : null;
    if (d && !d.open) d.open = true;
    n.setAttribute('tabindex', '-1');
    try { n.scrollIntoView({ block: 'start', behavior: reducedMotion() ? 'auto' : 'smooth' }); } catch (e) { n.scrollIntoView(); }
    n.focus({ preventScroll: true });
  }

  /* ------------------------------------------------------------------ 03 rollback */
  var RISK_PILL = { low: 'pill--ok', medium: 'pill--degraded', high: 'pill--fail' };
  function renderRollbacks(a) {
    var body = clear($('#rollback-body'));
    var rbs = a.rollbacks || [];
    $('#rollback-meta').textContent = rbs.length ? plural(rbs.length, 'option') : '';
    if (!rbs.length) {
      body.appendChild(emptyState('No rollback options yet',
        'Options appear once a cause is found: Helm rollback, rollout undo, restoring a limit, shifting traffic between clusters, or rolling forward.',
        ['helm history <release>, so the exact revision to go back to is known', 'The helm diff of the last upgrade', 'kubectl get events showing the rollout']));
      return;
    }
    body.appendChild(h('p', { class: 'gate' }, h('b', { text: 'Nothing here runs by itself.' }),
      'Review each command and run it yourself, one step at a time.'));
    var hypIndex = {};
    (a.hypotheses || []).forEach(function (hy, i) { hypIndex[hy.id] = { i: i, hy: hy }; });
    var likely = [], unlikely = [];
    rbs.forEach(function (r) { (unlikelyWhy(r, a, hypIndex) ? unlikely : likely).push(r); });
    likely.forEach(function (r, i) { body.appendChild(rbCard(r, i, a, hypIndex)); });
    if (unlikely.length) {
      // Options that only address weak causes (or a component that shows no errors) stay out of the
      // way: a tired reader scanning for "Low risk, 6 min" should not land on the wrong release.
      var box = h('details', { class: 'rb-unlikely' },
        h('summary', null, h('span', { class: 'rb-unlikely-t', text: 'Unlikely to help (' + unlikely.length + ')' }),
          h('span', { class: 'rb-unlikely-s', text: 'Options for causes the evidence barely supports' })));
      unlikely.forEach(function (r) { box.appendChild(rbUnlikelyCard(r, a, hypIndex)); });
      body.appendChild(box);
    }
  }
  // Why an option is unlikely to help, or null. Never the recommended one.
  function unlikelyWhy(r, a, hypIndex) {
    if (r.recommended) return null;
    var fx = (r.fixes || []).map(function (id) { return hypIndex[id]; }).filter(Boolean);
    if (!fx.length) return null;
    var weak = fx.every(function (x) {
      var c = compById(a, x.hy.componentId);
      return (x.hy.confidence || 0) < 0.35 || (c && c.status === 'healthy');
    });
    if (!weak) return null;
    return fx.map(function (x) {
      var c = compById(a, x.hy.componentId);
      return 'Addresses cause ' + (x.i + 1) + ' (' + Math.round((x.hy.confidence || 0) * 100) + '% likely)' +
        (c && c.status === 'healthy' ? '; ' + c.name + ' shows no errors' : '');
    }).join('; ') + '.';
  }
  function rbUnlikelyCard(r, a, hypIndex) {
    var key = (r.kind || '') + '|' + (r.title || '');
    var open = !!state.openRbs[key];
    var card = h('article', { class: 'card rb rb--unlikely stripe-muted', 'data-rollback': r.id, id: 'rb-' + r.id, 'aria-labelledby': 'rb-t-' + r.id });
    card.appendChild(h('div', { class: 'rb-top' }, h('span', { class: 'chip', text: RB_KIND_LABEL[r.kind] || r.kind })));
    card.appendChild(h('h3', { class: 'rb-title', id: 'rb-t-' + r.id, text: r.title }));
    card.appendChild(h('p', { class: 'rb-why', text: unlikelyWhy(r, a, hypIndex) }));
    var more = h('div', { class: 'rb-more', id: 'rb-b-' + r.id, hidden: !open });
    if ((r.commands || []).length) {
      var ol = h('ul', { class: 'cmds' });
      r.commands.forEach(function (cmd, j) { ol.appendChild(h('li', null, codeBlock(cmd, 'Step ' + (j + 1) + ' command'))); });
      more.appendChild(ol);
    }
    if ((r.caveats || []).length) {
      var cav = h('ul', { class: 'against' });
      r.caveats.forEach(function (x) { cav.appendChild(h('li', { text: x })); });
      more.appendChild(h('h4', { class: 'sub-h', text: 'Caveats' }));
      more.appendChild(cav);
    }
    card.appendChild(more);
    var toggle = h('button', { type: 'button', class: 'toggle', 'aria-expanded': open ? 'true' : 'false', 'aria-controls': 'rb-b-' + r.id });
    var label = function (o) { return o ? 'Hide commands' : 'Show commands anyway'; };
    toggle.textContent = label(open);
    toggle.addEventListener('click', function () {
      var now = more.hidden;
      more.hidden = !now;
      state.openRbs[key] = now;
      toggle.setAttribute('aria-expanded', now ? 'true' : 'false');
      toggle.textContent = label(now);
    });
    card.appendChild(h('div', { class: 'hyp-foot' }, toggle));
    return card;
  }
  function rbCard(r, i, a, hypIndex) {
    var rec = !!r.recommended;
    var key = (r.kind || '') + '|' + (r.title || '');
    var open = state.openRbs[key] != null ? state.openRbs[key] : rec;
    var card = h('article', { class: 'card rb ' + (rec ? 'is-rec stripe-accent' : 'stripe-muted'), 'data-rollback': r.id, id: 'rb-' + r.id, 'aria-labelledby': 'rb-t-' + r.id });
    var top = h('div', { class: 'rb-top' });
    if (rec) top.appendChild(h('span', { class: 'pill pill--accent', text: 'Recommended' }));
    top.appendChild(h('span', { class: 'chip', text: RB_KIND_LABEL[r.kind] || r.kind }));
    card.appendChild(top);
    card.appendChild(h('h3', { class: 'rb-title', id: 'rb-t-' + r.id, text: r.title }));

    var ev = !!(a.budget && a.budget.hasEvidence);
    var facts = h('dl', { class: 'facts' },
      h('div', { class: 'fact' }, h('dt', { text: 'Time to recover' }), h('dd', null, r.etaMinutes != null ? h('span', { class: 'big', text: 'about ' + r.etaMinutes + ' min' }) : '—')),
      h('div', { class: 'fact' }, h('dt', { text: 'Risk' }), h('dd', null, h('span', { class: 'pill ' + (RISK_PILL[r.risk] || 'pill--muted'), text: r.risk ? r.risk.charAt(0).toUpperCase() + r.risk.slice(1) : 'Unknown' }))),
      h('div', { class: 'fact', title: 'Error budget this saves compared with waiting two hours, at the current burn rate.' },
        h('dt', { text: 'Budget saved' }), h('dd', null, ev && r.budgetSavedPct != null ? h('span', { class: 'big', text: pct(r.budgetSavedPct) }) :
          h('span', { class: 'fact-none', text: !ev ? 'Not estimated: no measured error rate' : 'Not estimated: does not address the likely cause' }),
          ev && r.budgetSavedPct != null ? h('span', { class: 'muted', text: ' vs. waiting 2 h' }) : null)));
    var fx = (r.fixes || []).map(function (id) { return hypIndex[id]; }).filter(Boolean);
    if (fx.length) {
      var dd = h('dd');
      fx.forEach(function (x, j) {
        if (j) dd.appendChild(doc.createTextNode(', '));
        var lb = h('button', { type: 'button', class: 'linkbtn', title: x.hy.title, text: 'cause ' + (x.i + 1) });
        lb.addEventListener('click', function () { focusCard('#hyp-' + cssEscape(x.hy.id)); });
        dd.appendChild(lb);
      });
      facts.appendChild(h('div', { class: 'fact' }, h('dt', { text: 'Addresses' }), dd));
    }
    card.appendChild(facts);

    var more = h('div', { class: 'rb-more', id: 'rb-b-' + r.id, hidden: !open });
    if ((r.commands || []).length) {
      more.appendChild(h('h4', { class: 'sub-h', text: r.commands.length > 1 ? 'Commands, in order' : 'Command' }));
      var ol = h('ul', { class: 'cmds' });
      r.commands.forEach(function (cmd, j) { ol.appendChild(h('li', null, codeBlock(cmd, 'Step ' + (j + 1) + ' command'))); });
      more.appendChild(ol);
    }
    var cav = h('ul', { class: 'against' });
    (r.caveats || []).forEach(function (x) { cav.appendChild(h('li', { text: x })); });
    var pre = h('ul', { class: 'bul' });
    (r.prerequisites || []).forEach(function (x) { pre.appendChild(h('li', { text: x })); });
    more.appendChild(h('div', { class: 'rb-cols' },
      h('div', null, h('h4', { class: 'sub-h', text: 'Caveats' }), (r.caveats || []).length ? cav : h('p', { class: 'none', text: 'None noted.' })),
      h('div', null, h('h4', { class: 'sub-h', text: 'Before you run it' }), (r.prerequisites || []).length ? pre : h('p', { class: 'none', text: 'Nothing extra needed.' }))));
    card.appendChild(more);
    var toggle = h('button', { type: 'button', class: 'toggle', 'aria-expanded': open ? 'true' : 'false', 'aria-controls': 'rb-b-' + r.id });
    var label = function (o) { return o ? 'Hide commands and caveats' : 'Show commands and caveats'; };
    toggle.textContent = label(open);
    toggle.addEventListener('click', function () {
      var now = more.hidden;
      more.hidden = !now;
      state.openRbs[key] = now;
      toggle.setAttribute('aria-expanded', now ? 'true' : 'false');
      toggle.textContent = label(now);
    });
    card.appendChild(h('div', { class: 'hyp-foot' }, toggle));
    return card;
  }

  /* ------------------------------------------------------------------ 04 budget */
  function renderBudget(a) {
    var body = clear($('#budget-body'));
    var b = a.budget || {};
    $('#budget-meta').textContent = 'SLO ' + targetPct(b.sloTarget) + ' over ' + (b.windowDays || '—') + ' days';
    if (!b.hasEvidence) {
      body.appendChild(emptyState('No error-budget estimate yet',
        'The estimate needs a measured error rate, so no numbers are shown until there is one. Any of these will do:',
        ['A firing burn-rate alert in Alerts (its burn rate gives the error rate)', 'Traces that include failed requests',
          'Request logs with status codes (20 lines or more)', 'Or type the error rate into "Error rate override" in Context']));
      var rp = rulesPanel(b, a);
      rp.style.marginTop = '14px';
      body.appendChild(rp);
      return;
    }
    var notes = b.notes || [];
    var under = notes.filter(function (n) { return /undercount|fired sooner than the Workbook/i.test(n); });
    under.forEach(function (n) {
      body.appendChild(h('p', { class: 'callout', role: 'note' }, h('b', { text: /fired sooner/.test(n) ? 'Your alert fired early.' : 'Likely undercounted.' }), h('span', { text: n })));
    });

    var win = b.windowDays + '-day';
    var big = h('div', { class: 'bignums' });
    var page = (b.alertRows && b.alertRows[0] && b.alertRows[0].burnThreshold) || 14.4;
    big.appendChild(bigNum('Burn rate', fmtBurn(b.burnRate), '×', b.burnRate >= page,
      'Error rate ' + ratio(b.errorRatio) + ' (' + (ERROR_SOURCE[b.errorRatioSource] || b.errorRatioSource) + ') against ' + ratio(1 - b.sloTarget) + ' allowed.'));
    big.appendChild(bigNum('Used by this incident', pct(b.consumedPct), '', false,
      'Of the ' + win + ' budget, about ' + fmtInt(b.badRequests) + ' failed requests.'));
    big.appendChild(bigNum('Budget left', pct(b.remainingPct), '', b.remainingPct != null && b.remainingPct < 25,
      b.budgetSpentBeforePct ? 'After ' + pct(b.budgetSpentBeforePct) + ' spent before this incident.' : 'Of the ' + win + ' budget.'));
    big.appendChild(bigNum('Runs out in', b.minutesToExhaustion != null ? dur(b.minutesToExhaustion * 60000) : 'Not at this rate', '',
      b.minutesToExhaustion != null && b.minutesToExhaustion < 24 * 60, 'If this burn rate holds.'));
    body.appendChild(big);

    var chartPanel = h('div', { class: 'panel' },
      h('div', { class: 'panel-h' }, h('h3', { text: 'Budget left if nothing changes' }), h('span', { class: 'muted', text: '% of the ' + win + ' budget' })));
    var wrap = h('div', { class: 'chart-wrap', id: 'budget-chart' });
    chartPanel.appendChild(wrap);
    var proj = h('ol', { class: 'proj', 'aria-label': 'Projection' });
    (b.projection || []).forEach(function (p, j) {
      proj.appendChild(h('li', { class: j === 0 ? 'is-first' : null },
        h('span', { class: 'p-l', text: p.label }),
        h('span', { class: 'p-v', text: pct(p.remainingPct) + ' left' }),
        h('span', { class: 'p-s', text: pct(p.consumedPct) + ' used by the incident' })));
    });
    chartPanel.appendChild(proj);
    body.appendChild(h('div', { class: 'budget-grid' }, chartPanel, rulesPanel(b, a)));
    drawChart(wrap, b);

    // the formula in words, with this incident's numbers
    var mins = b.windowDays * 1440;
    var f = h('div', { class: 'formula' },
      h('p', null, h('b', { text: 'Burn rate' }), ' = error rate ÷ allowed error rate = ' + ratio(b.errorRatio) + ' ÷ ' + ratio(1 - b.sloTarget) + ' = ' + fmtBurn(b.burnRate) + '×.'),
      h('p', null, h('b', { text: 'Budget used' }), ' = burn rate × minutes since the first anomaly ÷ minutes in the window = ' +
        fmtBurn(b.burnRate) + ' × ' + fmtBurn(b.incidentMinutes) + ' ÷ ' + fmtInt(mins) + ' = ' + pct(b.consumedPct) + '.'),
      h('p', null, h('b', { text: 'Runs out in' }), ' = budget left × minutes in the window ÷ burn rate' +
        (b.minutesToExhaustion != null ? ' = ' + pct(b.remainingPct) + ' × ' + fmtInt(mins) + ' ÷ ' + fmtBurn(b.burnRate) + ' = ' + dur(b.minutesToExhaustion * 60000) + '.' : '.')),
      h('p', { class: 'src' }, 'Method and alert thresholds: ',
        h('a', { href: b.source || SRE_WORKBOOK, target: '_blank', rel: 'noopener noreferrer', text: 'Google SRE Workbook, “Alerting on SLOs”' }), '.'));
    body.appendChild(f);
    var rest = notes.filter(function (n) { return under.indexOf(n) < 0; });
    if (rest.length) {
      var ul = h('ul', { class: 'bul' });
      rest.forEach(function (n) { ul.appendChild(h('li', { text: n })); });
      body.appendChild(h('div', { class: 'assume' }, h('h3', { class: 'sub-h', text: 'Assumptions' }), ul));
    }
  }
  function bigNum(label, value, unit, hot, sub) {
    return h('div', { class: 'bn' },
      h('div', { class: 'bn-l', text: label }),
      h('div', { class: 'bn-v' + (hot ? ' is-hot' : '') }, value, unit ? h('small', { text: unit }) : null),
      h('p', { class: 'bn-s', text: sub }));
  }
  function rulesPanel(b, a) {
    var scaled = b.windowDays && b.windowDays !== 30;
    var panel = h('div', { class: 'panel' },
      h('div', { class: 'panel-h' }, h('h3', { text: 'Burn-rate alerts' }), h('span', { class: 'muted', text: 'Workbook Table 5-8' + (scaled ? ', scaled to ' + b.windowDays + ' days' : '') })));
    // A firing burn alert from the paste, on its own line: it is matched to a row below only when
    // its labels give that row's window.
    if (b.hasEvidence && b.observedAlert) {
      var matched = (b.alertRows || []).filter(function (r) { return r.observedFiring; })[0];
      var obs = h('div', { class: 'obs-alert' },
        h('p', null, h('span', { class: 'state state--firing-observed', text: 'Firing' }), ' ',
          h('b', { text: 'Your alert: ' + b.observedAlert }), ', ' + fmtBurn(b.observedBurnRate) + '× burn. ',
          h('span', { class: 'muted', text: matched ? 'It stands for the ' + hyph(matched.longWindow) + ' ' + matched.severity.toLowerCase() + ' row below.' : 'Its labels give no window, so it is not matched to a row below.' })));
      if (b.observedSignalId) {
        var osig = signalById(a, b.observedSignalId);
        var olink = h('button', { type: 'button', class: 'linkbtn state-link', text: 'Show ' + b.observedAlert + ' in Alerts' });
        olink.addEventListener('click', function () { if (osig) jumpTo(osig.source, osig.line, { from: olink }); else jumpTo('alerts', null, { from: olink }); });
        obs.appendChild(olink);
      }
      panel.appendChild(obs);
    }
    var table = h('table', { class: 'rules' });
    table.appendChild(h('thead', null, h('tr', null,
      h('th', { scope: 'col', text: 'Alert' }), h('th', { scope: 'col', text: 'Burn at least' }),
      h('th', { scope: 'col', text: 'Budget used when it fires' }))));
    var tb = h('tbody');
    (b.alertRows || []).forEach(function (row) {
      var state_ = row.state || (row.firing ? 'firing-estimate' : 'no-evidence');
      var stateCell = h('td', { class: 'r-state', colspan: '3' },
        h('span', { class: 'state state--' + state_, text: row.stateText || state_ }));
      if (b.hasEvidence && row.firesAfterMinutes != null) {
        stateCell.appendChild(h('p', { class: 'r-det', text: 'At this burn the long window needs about ' + dur(row.firesAfterMinutes * 60000) + ' of errors to fire (Workbook detection time).' }));
      } else if (b.hasEvidence && state_ === 'not-at-this-burn') {
        stateCell.appendChild(h('p', { class: 'r-det', text: 'This alert needs a burn of ' + fmtBurn(row.burnThreshold) + '× or more.' }));
      }
      tb.appendChild(h('tr', { class: 'r-main' },
        h('td', { 'data-l': 'Alert' }, h('div', { class: 'r-sev', text: row.severity === 'Page' ? 'Page' : 'Ticket' }),
          h('div', { class: 'r-win', text: hyph(row.longWindow) + ' window, confirmed over ' + row.shortWindow })),
        h('td', { 'data-l': 'Burn at least' }, h('span', { class: 'r-num', text: fmtBurn(row.burnThreshold) + '×' })),
        h('td', { 'data-l': 'Budget used' }, h('span', { class: 'r-num', text: row.consumedPctAtFire + '%' }))));
      tb.appendChild(h('tr', { class: 'r-staterow' }, stateCell));
    });
    table.appendChild(tb);
    panel.appendChild(table);
    panel.appendChild(h('p', { class: 'panel-foot', text: 'A page wakes someone up; a ticket can wait for working hours. Each alert fires when both its long and short window burn faster than the threshold.' +
      (scaled ? ' The Workbook table is for 30 days; the thresholds here are scaled so each alert still fires at the same share of the budget (2%, 5%, 10%), which gives lower thresholds for shorter windows.' : '') }));
    return panel;
  }

  function niceStep(raw) {
    if (!(raw > 0)) return 1;
    var p = Math.pow(10, Math.floor(Math.log10(raw)));
    var n = raw / p;
    return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 2.5 ? 2.5 : n <= 5 ? 5 : 10) * p;
  }
  // One unit style on the time axis: 0, 30 min, 1 h, 1 h 30, 2 h.
  function axisMinutes(t) {
    if (!t) return '0';
    if (t < 60) return t + ' min';
    return Math.floor(t / 60) + ' h' + (t % 60 ? ' ' + (t % 60) : '');
  }
  function drawChart(wrap, b) {
    if (!wrap) return;
    clear(wrap);
    var series = (b.series || []).filter(function (p) { return isFinite(p.t) && isFinite(p.remainingPct); });
    if (series.length < 2) { wrap.appendChild(h('p', { class: 'none', text: 'Not enough time in the evidence to draw a projection.' })); return; }
    var W = Math.max(260, Math.round(wrap.clientWidth || 520));
    state.chartWidth = W;
    var H = W < 420 ? 200 : 228;
    var m = { l: 44, r: 14, t: 24, b: 38 };
    var t0 = b.incidentMinutes || 0;
    var proj = (b.projection || []).map(function (p) { return { t: t0 + (p.extraMinutes || 0), v: p.remainingPct, label: p.label }; })
      .filter(function (p) { return isFinite(p.v); });
    var xmax = Math.max(series[series.length - 1].t, proj.length ? proj[proj.length - 1].t : 0) || 1;
    var vals = series.map(function (p) { return p.remainingPct; }).concat(proj.map(function (p) { return p.v; }));
    var lo = Math.min.apply(null, vals), hi = Math.max.apply(null, vals);
    if (hi - lo < 0.5) { lo -= 0.25; hi += 0.25; }
    var ystep = niceStep((hi - lo) / 4);
    var y0 = Math.max(0, Math.floor(lo / ystep) * ystep), y1 = Math.min(100, Math.ceil(hi / ystep) * ystep);
    if (y1 <= y0) y1 = y0 + ystep;
    var X = function (t) { return m.l + (t / xmax) * (W - m.l - m.r); };
    var Y = function (v) { return m.t + (1 - (v - y0) / (y1 - y0)) * (H - m.t - m.b); };
    var dec = ystep < 1 ? 1 : 0;
    var svgEl = s('svg', { class: 'chart', width: W, height: H, viewBox: '0 0 ' + W + ' ' + H, role: 'img',
      'aria-label': 'Budget left falls from ' + pct(series[0].remainingPct) + ' to ' + pct(series[series.length - 1].remainingPct) + ' over ' + Math.round(xmax) + ' minutes if the burn continues.' });
    // horizontal grid + y labels
    for (var v = y0; v <= y1 + 1e-9; v += ystep) {
      svgEl.appendChild(s('line', { class: 'c-grid', x1: m.l, x2: W - m.r, y1: Y(v), y2: Y(v) }));
      svgEl.appendChild(s('text', { x: m.l - 6, y: Y(v) + 4, 'text-anchor': 'end' }, v.toFixed(dec) + '%'));
    }
    if (y0 === 0) svgEl.appendChild(s('line', { class: 'c-zero', x1: m.l, x2: W - m.r, y1: Y(0), y2: Y(0) }));
    // x axis + ticks
    var xstep = [5, 10, 15, 20, 30, 60, 120, 180, 240, 360, 720, 1440].filter(function (st) { return xmax / st <= (W < 420 ? 4 : 6); })[0] || 1440;
    svgEl.appendChild(s('line', { class: 'c-axis', x1: m.l, x2: W - m.r, y1: H - m.b, y2: H - m.b }));
    for (var t = 0; t <= xmax + 1e-9; t += xstep) {
      svgEl.appendChild(s('line', { class: 'c-axis', x1: X(t), x2: X(t), y1: H - m.b, y2: H - m.b + 4 }));
      svgEl.appendChild(s('text', { x: X(t), y: H - m.b + 16, 'text-anchor': t === 0 ? 'start' : 'middle' }, axisMinutes(t)));
    }
    svgEl.appendChild(s('text', { class: 'c-title', x: W - m.r, y: H - 4, 'text-anchor': 'end' }, 'Time since the first anomaly'));
    svgEl.appendChild(s('text', { class: 'c-title', x: 4, y: 12, 'text-anchor': 'start' }, 'Budget left'));
    // the line: solid up to now, dashed after
    var past = [], future = [];
    var interp = function (t) {
      for (var i = 1; i < series.length; i++) {
        if (series[i].t >= t) {
          var a0 = series[i - 1], a1 = series[i];
          var k = a1.t === a0.t ? 0 : (t - a0.t) / (a1.t - a0.t);
          return a0.remainingPct + k * (a1.remainingPct - a0.remainingPct);
        }
      }
      return series[series.length - 1].remainingPct;
    };
    series.forEach(function (p) { if (p.t <= t0) past.push(p); else future.push(p); });
    var nowPt = { t: t0, remainingPct: interp(t0) };
    past.push(nowPt);
    future.unshift(nowPt);
    var path = function (pts) { return pts.map(function (p, i) { return (i ? 'L' : 'M') + X(p.t).toFixed(1) + ' ' + Y(p.remainingPct).toFixed(1); }).join(' '); };
    if (past.length > 1) {
      svgEl.appendChild(s('path', { class: 'c-area', d: path(past) + ' L' + X(t0).toFixed(1) + ' ' + Y(y0) + ' L' + X(past[0].t).toFixed(1) + ' ' + Y(y0) + ' Z' }));
      svgEl.appendChild(s('path', { class: 'c-past', d: path(past) }));
    }
    if (future.length > 1) svgEl.appendChild(s('path', { class: 'c-future', d: path(future) }));
    // now marker
    svgEl.appendChild(s('line', { class: 'c-now', x1: X(t0), x2: X(t0), y1: m.t - 6, y2: H - m.b }));
    svgEl.appendChild(s('text', { class: 'c-mlabel', x: X(t0) + (X(t0) > W - 60 ? -4 : 4), y: m.t - 10, 'text-anchor': X(t0) > W - 60 ? 'end' : 'start' }, 'Now'));
    // mitigation markers
    proj.forEach(function (p, i) {
      var cx = X(p.t), cy = Y(p.v);
      svgEl.appendChild(s('circle', { class: 'c-mark' + (i === 0 ? ' is-first' : ''), cx: cx, cy: cy, r: 4.5 }));
      var right = i > 0 && cx < W - 70;
      var anchor = i === 0 ? 'end' : right ? 'start' : 'end';
      var lx = i === 0 ? cx - 8 : right ? cx + 8 : cx - 8;
      // The projection falls left to right, so a label left of a later point goes under the line, not on it.
      var ly = i === 0 ? cy + 16 : right ? cy - 9 : (cy + 15 <= H - m.b - 1 ? cy + 15 : cy - 12);
      svgEl.appendChild(s('text', { class: 'c-mlabel', x: lx, y: ly, 'text-anchor': anchor }, pct(p.v)));
    });
    wrap.appendChild(svgEl);
  }
  function redrawChartIfResized() {
    var wrap = $('#budget-chart');
    if (!wrap || !state.analysis || !state.analysis.budget || !state.analysis.budget.hasEvidence) return;
    var w = Math.round(wrap.clientWidth);
    if (Math.abs(w - state.chartWidth) > 2) drawChart(wrap, state.analysis.budget);
  }

  /* ------------------------------------------------------------------ 05 Claude */
  function updateClaude(a) {
    var host = $('#claude-body');
    var I = WR.ui.investigate;
    if (I && typeof I.mount === 'function') {
      if (!state.invTried) {
        state.invTried = true;
        state.inv = I.mount(host, {
          getAnalysis: function () { return state.analysis; },
          getInputs: getPaneTexts,
          onJumpToSignal: function (id, btnEl) { return jumpToSignal(id, { from: btnEl && doc.contains(btnEl) ? btnEl : $('#claude') }); }
        }) || null;
      } else if (state.inv && typeof state.inv.update === 'function') {
        state.inv.update(a);
      }
      return;
    }
    if (!host.firstChild) {
      host.appendChild(h('div', { class: 'quiet' },
        h('p', { text: 'Claude investigation is available when this page is opened in Claude.' })));
    }
  }

  /* ------------------------------------------------------------------ 06 stacks */
  function sourceLinks(ids) {
    var srcs = (WR.stacks && WR.stacks.sources) || {};
    var box = h('div', { class: 'srcs' });
    (ids || []).forEach(function (id) {
      var src = srcs[id];
      if (!src || !src.url) return;
      box.appendChild(h('span', null, h('a', { href: src.url, target: '_blank', rel: 'noopener noreferrer', text: src.title || src.url }),
        src.asOf ? h('span', { class: 'as-of', text: ' · ' + src.asOf }) : null));
    });
    return box.childNodes.length ? box : null;
  }
  function reasonChip(withSources) {
    return h('span', { class: 'chip chip--reason', title: withSources
      ? 'Part of this is a judgment drawn from the sources next to it, not a published figure.'
      : 'Reasoning from how the product works, not a sourced figure.' }, 'Reasoning');
  }
  // Sourced facts keep their links even when the line also carries a judgment (reasoning:true).
  function sourcesAndReason(ids, reasoning) {
    var box = sourceLinks(ids);
    if (!reasoning) return box;
    var chip = reasonChip(!!box);
    if (!box) return h('div', { class: 'srcs' }, chip);
    box.insertBefore(chip, box.firstChild);
    return box;
  }
  var STACK_ROWS = [
    ['shows', 'How incidents show up here'],
    ['correlate', 'Correlating logs, traces and metrics'],
    ['multicluster', 'Multi-cluster view'],
    ['ai', 'AI-assisted diagnosis']
  ];
  var VERDICT = { 'Good fit': ['pill--ok', 'stripe-ok'], Workable: ['pill--degraded', 'stripe-warn'], Strained: ['pill--crit-line', 'stripe-crit'] };
  var FLAG_ORDER = { breaks: 0, strain: 1, ok: 2 };
  var FLAG_WORD = { breaks: 'Breaks', strain: 'Strains', ok: 'Fine' };
  function fmtUsd(n) {
    if (n == null || !isFinite(n)) return null;
    return '$' + (n >= 100 ? Math.round(n).toLocaleString('en-US') : (Math.round(n * 100) / 100).toLocaleString('en-US'));
  }
  function stackToggleLabel(open) {
    return open ? 'Hide details' : 'How each setup works';
  }
  function renderStacks(a, force) {
    var body = $('#stacks-body');
    var S = WR.stacks;
    if (!S || !Array.isArray(S.stacks) || typeof WR.stackFit !== 'function') {
      if (body.getAttribute('data-state') !== 'missing') {
        clear(body).appendChild(emptyState('Stack comparison not loaded',
          'The comparison of Datadog, Grafana, OpenTelemetry and hosted cloud monitoring appears here when its data module is part of the page.'));
        body.setAttribute('data-state', 'missing');
      }
      $('#stacks-meta').textContent = '';
      return;
    }
    var scale = readScale();
    var k = JSON.stringify(a.traits || {}) + '|' + JSON.stringify(scale);
    if (!force && k === state.stacksKey && body.getAttribute('data-state') === 'ok') return;
    state.stacksKey = k;
    body.setAttribute('data-state', 'ok');
    var fit = WR.stackFit(a.traits || {}, scale) || {};
    clear(body);
    $('#stacks-meta').textContent = S.asOf ? 'Sources checked ' + S.asOf : '';
    if (!hasInput(a)) {
      body.appendChild(h('p', { class: 'sec-note' }, h('b', { text: 'No incident evidence yet.' }), ' The flags below react to your scale only. Paste evidence to see where each setup would strain on this incident.'));
    }
    body.appendChild(h('p', { class: 'stacks-hint', text: 'Each column starts with its verdict. Select a flag to see why it applies and its source.' }));
    var grid = h('div', { class: 'stack-grid' });
    S.stacks.forEach(function (st) {
      var f = fit[st.id] || { verdict: '', flags: [], costLines: [] };
      var vd = VERDICT[f.verdict] || ['pill--muted', 'stripe-muted'];
      var flags = (f.flags || []).slice().sort(function (x, y) { return (FLAG_ORDER[x.level] || 0) - (FLAG_ORDER[y.level] || 0); });
      var nb = flags.filter(function (x) { return x.level === 'breaks'; }).length;
      var ns = flags.filter(function (x) { return x.level === 'strain'; }).length;
      var card = h('article', { class: 'card stack ' + vd[1], 'data-stack': st.id, 'aria-labelledby': 'st-' + st.id });
      var nf = flags.filter(function (x) { return x.level === 'ok'; }).length;
      card.appendChild(h('header', { class: 'st-head' },
        h('h3', { class: 'st-name', id: 'st-' + st.id, text: st.name }),
        st.tagline ? h('p', { class: 'st-tag', text: st.tagline }) : null));
      // One verdict line per column, in its own row so the four line up side by side.
      card.appendChild(h('div', { class: 'st-verdict' }, f.verdict ? h('span', { class: 'pill ' + vd[0], text: f.verdict }) : null,
        h('span', { class: 'st-count' },
          h('b', { text: nb + (nb === 1 ? ' break' : ' breaks') + ', ' + ns + (ns === 1 ? ' strain' : ' strains') }),
          (hasInput(a) ? ' for this incident' : ' at your scale') + (nf ? ' · ' + nf + ' fine' : ''))));
      // "Breaks down when" leads: it is the part that reacts to this incident. Every flag opens to
      // its reasons; the ones that are fine sit together in one closed group.
      var fl = h('ul', { class: 'flags' });
      var flagEl = function (x) {
        return h('details', { class: 'flag flag--' + x.level },
          h('summary', { class: 'flag-h' }, h('span', { class: 'flag-lv', text: FLAG_WORD[x.level] || x.level }), h('span', { class: 'flag-t', text: x.text })),
          h('div', { class: 'flag-more' }, x.because ? h('p', { class: 'flag-b', text: x.because }) : null,
            sourcesAndReason(x.sourceIds, x.reasoning)));
      };
      flags.filter(function (x) { return x.level !== 'ok'; }).forEach(function (x) { fl.appendChild(h('li', null, flagEl(x))); });
      var fine = flags.filter(function (x) { return x.level === 'ok'; });
      if (fine.length) {
        var fl2 = h('ul', { class: 'flags flags--fine' });
        fine.forEach(function (x) { fl2.appendChild(h('li', null, flagEl(x))); });
        fl.appendChild(h('li', null, h('details', { class: 'flag flag--ok flag-group' },
          h('summary', { class: 'flag-h' }, h('span', { class: 'flag-lv', text: 'Fine' }), h('span', { class: 'flag-t', text: plural(fine.length, 'thing') + (fine.length === 1 ? ' that holds up here' : ' that hold up here') })),
          h('div', { class: 'flag-more' }, fl2))));
      }
      card.appendChild(h('div', { class: 'st-row' }, h('h4', { text: 'Breaks down when' }),
        flags.length ? fl : h('p', { class: 'none', text: 'Nothing flagged for this incident at this scale.' })));
      var costs = h('ul', { class: 'costs' });
      (f.costLines || []).forEach(function (c) {
        var src = c.sourceId && S.sources ? S.sources[c.sourceId] : null;
        var usd = fmtUsd(c.monthlyUsd);
        var val = usd ? h('span', { class: 'cost-v', text: usd + '/mo' })
          : (src && src.url ? h('a', { class: 'cost-see', href: src.url, target: '_blank', rel: 'noopener noreferrer', text: 'See pricing page' }) : h('span', { class: 'muted', text: 'No list price' }));
        // The figure and its label stay in view; the arithmetic behind it opens on demand.
        costs.appendChild(h('li', null, h('span', { text: c.label }), val,
          c.basis || (usd && src) ? h('details', { class: 'cost-how' }, h('summary', { text: 'How this is figured' }),
            h('span', { class: 'cost-b' }, c.basis || '', usd && src && src.url ? [' · ', h('a', { href: src.url, target: '_blank', rel: 'noopener noreferrer', text: 'source' })] : null)) : null));
      });
      card.appendChild(h('div', { class: 'st-row' }, h('h4', { text: 'Cost at your scale' }),
        (f.costLines || []).length ? costs : h('p', { class: 'none', text: 'No list price to estimate from.' })));
      // The four descriptive rows are reference material, so they start closed; one toggle opens
      // them in every column at once, because they are read side by side.
      var more = h('div', { class: 'st-detail', id: 'st-d-' + st.id });
      more.hidden = !state.stacksDetail;
      STACK_ROWS.forEach(function (r) {
        var row = (st.rows || {})[r[0]] || {};
        more.appendChild(h('div', { class: 'st-row' }, h('h4', { text: r[1] }),
          h('p', { text: row.text || '—' }), sourcesAndReason(row.sourceIds, row.reasoning)));
      });
      var tg = h('button', { type: 'button', class: 'toggle st-toggle', 'aria-expanded': state.stacksDetail ? 'true' : 'false', 'aria-controls': 'st-d-' + st.id });
      tg.textContent = stackToggleLabel(state.stacksDetail);
      tg.addEventListener('click', function () {
        state.stacksDetail = !state.stacksDetail;
        $$('#stacks .st-detail').forEach(function (d) { d.hidden = !state.stacksDetail; });
        $$('#stacks .st-toggle').forEach(function (b) {
          b.setAttribute('aria-expanded', state.stacksDetail ? 'true' : 'false');
          b.textContent = stackToggleLabel(state.stacksDetail);
        });
      });
      card.appendChild(h('div', { class: 'st-more' }, tg, more));
      grid.appendChild(card);
    });
    body.appendChild(grid);
    body.appendChild(h('p', { class: 'stacks-foot', text: 'Prices and limits come from public pages on the dates shown. "Reasoning" marks a judgment from how the product works, not a published figure.' }));
  }

  /* ------------------------------------------------------------------ export brief (§6.7) */
  function briefName(a) {
    return 'incident-brief-' + fmtDay(a && a.window && a.window.now) + '.md';
  }
  function buildBrief(a) {
    a = a || state.analysis;
    var L = [];
    var has = hasInput(a);
    var w = a.window || {};
    var b = a.budget || {};
    L.push('# Incident brief: ' + a.headline, '');
    if (state.example) L.push('> Example incident from SRE War Room ("' + state.example.title + '"), not live data.', '');
    L.push('- **Severity:** ' + (has && SEV[a.severity] ? a.severity + ' — ' + SEV[a.severity].long.replace(/^Severity \d: /, '') : 'not assessed (no evidence pasted)'));
    L.push('- **Evidence up to:** ' + fmtStamp(w.now));
    if (w.firstAnomaly != null) L.push('- **First anomaly:** ' + fmtStamp(w.firstAnomaly) + (w.now != null ? ' (' + dur(w.now - w.firstAnomaly) + ' before)' : ''));
    var cl = a.clusters || [];
    if (cl.length) L.push('- **Clusters:** ' + cl.map(function (c) { return c.name + ' (' + c.status + ')'; }).join(', '));
    if (a.deploy && a.deploy.release) {
      var d = a.deploy;
      L.push('- **Last deploy:** Helm release ' + d.release + (d.revision != null ? ' r' + d.revision : '') +
        (d.previousRevision != null ? ' (from r' + d.previousRevision + ')' : '') + (d.deployedAt != null ? ' at ' + fmtStamp(d.deployedAt) : ''));
    }
    L.push('- **Made by:** SRE War Room rule engine, read-only. Review before acting.');

    L.push('', '## Timeline (UTC)', '');
    var tl = (a.timeline || []).slice(0, 30);
    if (!tl.length) L.push('No timed events found.');
    tl.forEach(function (t) {
      var sig = signalById(a, t.signalId);
      var txt = sig && sig.text ? (WR.truncate ? WR.truncate(sig.text, 180) : sig.text) : '';
      L.push('- ' + fmtClock(t.ts) + ' — ' + compName(a, t.componentId) + ' — ' + kindLabel(t.kind) + (txt ? ': ' + txt : ''));
    });
    if ((a.timeline || []).length > 30) L.push('- … ' + ((a.timeline || []).length - 30) + ' more');

    L.push('', '## Probable root causes', '');
    var hyps = (a.hypotheses || []).slice(0, 3);
    if (!hyps.length) L.push('No cause found yet.');
    hyps.forEach(function (hy, i) {
      L.push('### ' + (i + 1) + '. ' + hy.title, '', '_' + Math.round((hy.confidence || 0) * 100) + '% confidence · ' + (CATEGORY_LABEL[hy.category] || hy.category) + '_', '');
      if (hy.summary) L.push(hy.summary, '');
      if ((hy.evidence || []).length) {
        L.push('Evidence:');
        hy.evidence.forEach(function (ev) { L.push('- ' + ev.text + (ev.line != null ? ' (' + srcLine(ev.source, ev.line) + ')' : '')); });
        L.push('');
      }
      if ((hy.against || []).length) {
        L.push('What argues against it:');
        hy.against.forEach(function (x) { L.push('- ' + x.text); });
        L.push('');
      }
      if ((hy.nextChecks || []).length) {
        L.push('Next checks:', '', '```');
        hy.nextChecks.forEach(function (nc) { L.push(nc.cmd); });
        L.push('```', '');
      }
    });

    var rbs = a.rollbacks || [];
    var rec = rbs.filter(function (r) { return r.recommended; })[0] || rbs[0];
    L.push('## Recommended action', '');
    if (!rec) L.push('No rollback option yet.');
    else {
      L.push('**' + rec.title + '** (' + (RB_KIND_LABEL[rec.kind] || rec.kind) + ') — about ' + rec.etaMinutes + ' min to recover, ' + rec.risk + ' risk.', '');
      if ((rec.commands || []).length) { L.push('```bash'); rec.commands.forEach(function (c) { L.push(c); }); L.push('```', ''); }
      if ((rec.caveats || []).length) { L.push('Caveats:'); rec.caveats.forEach(function (c) { L.push('- ' + c); }); L.push(''); }
      if ((rec.prerequisites || []).length) { L.push('Before running:'); rec.prerequisites.forEach(function (c) { L.push('- ' + c); }); L.push(''); }
      var others = rbs.filter(function (r) { return r !== rec; });
      var hypIdx = {};
      (a.hypotheses || []).forEach(function (hy, i) { hypIdx[hy.id] = { i: i, hy: hy }; });
      if (others.length) {
        L.push('Other options:');
        others.forEach(function (r) {
          var why = unlikelyWhy(r, a, hypIdx);
          L.push('- ' + r.title + ' (' + (RB_KIND_LABEL[r.kind] || r.kind) + ', ' + r.risk + ' risk, about ' + r.etaMinutes + ' min)' + (why ? ' — unlikely to help: ' + why : ''));
        });
        L.push('');
      }
      L.push('Commands are for a person to review and run; nothing was executed.', '');
    }

    L.push('## Error budget', '');
    L.push('- SLO: ' + targetPct(b.sloTarget) + ' over ' + b.windowDays + ' days');
    if (!b.hasEvidence) {
      L.push('- No measured error rate in the evidence, so no estimate was made.');
    } else {
      L.push('- Burn rate: ' + fmtBurn(b.burnRate) + '× (error rate ' + ratio(b.errorRatio) + ', ' + (ERROR_SOURCE[b.errorRatioSource] || b.errorRatioSource) + ')');
      L.push('- Used by this incident: ' + pct(b.consumedPct) + ' of the budget, about ' + fmtInt(b.badRequests) + ' failed requests');
      L.push('- Budget left: ' + pct(b.remainingPct));
      L.push('- Runs out in: ' + (b.minutesToExhaustion != null ? dur(b.minutesToExhaustion * 60000) : 'not at this rate') + ' if the burn holds');
      (b.projection || []).forEach(function (p) { L.push('- ' + p.label + ': ' + pct(p.remainingPct) + ' left'); });
    }
    (b.alertRows || []).forEach(function (r) {
      L.push('- ' + r.severity + ' alert, ' + hyph(r.longWindow) + ' window confirmed over ' + r.shortWindow + ', burn ≥ ' + fmtBurn(r.burnThreshold) + '×: ' + (r.stateText || r.state));
    });
    if (b.observedAlert) L.push('- Your alert: ' + b.observedAlert + ', ' + fmtBurn(b.observedBurnRate) + '× burn, firing');
    (b.notes || []).forEach(function (n) { L.push('- Note: ' + n); });
    L.push('- Method: ' + (b.source || SRE_WORKBOOK));

    L.push('', '## Open questions', '');
    var q = [];
    var top = (a.hypotheses || [])[0];
    if (top) (top.against || []).forEach(function (x) { q.push(x.text); });
    var tr = a.traits || {};
    if (!tr.hasDeployTime && (a.changes || []).length) q.push('When exactly did the change roll out? Paste helm history or set "Deployed at".');
    if (tr.errorTracesMissing) {
      q.push('Some failing components have errors in logs or alerts but no failed spans; were the error traces dropped by sampling?');
    }
    PANES.forEach(function (p) { if (!(a.inputsPresent || {})[p.key]) q.push('No ' + p.label.toLowerCase() + ' were pasted.'); });
    (a.warnings || []).forEach(function (wn) { q.push(wn); });
    if (!q.length) q.push('None recorded.');
    q.forEach(function (x) { L.push('- ' + x); });
    L.push('');
    return L.join('\n');
  }
  function onExport(ev) {
    var btn = ev.currentTarget;
    var a = state.analysis;
    if (!a) return;
    var md = buildBrief(a);
    var dl = state.downloads;
    if (dl && typeof dl.save === 'function') {
      // aria-disabled, not disabled: a disabled button drops keyboard focus to the page.
      if (state.savePending) { announce('A save prompt is already open.'); return; }
      state.savePending = true;
      btn.setAttribute('aria-disabled', 'true');
      var p;
      try { p = dl.save({ filename: briefName(a), data: md }); } catch (e) { p = Promise.reject({ code: 'unavailable' }); }
      var done = function () {
        state.savePending = false;
        btn.removeAttribute('aria-disabled');
        if (doc.activeElement === doc.body) btn.focus();
      };
      Promise.resolve(p).then(function () {
        done();
        flashButton(btn, 'Saved', true);
        announce('Brief saved.');
      }, function (err) {
        done();
        var code = err && err.code;
        if (code === 'rate_limited') { announce('A save prompt is already open.'); return; }
        if (code === 'declined') { openBrief(md, 'Not saved. You can copy the brief instead.', btn); return; }
        if (code !== 'too_large' && code !== 'bad_request') state.downloads = null;
        openBrief(md, 'Saving files is not available here, so copy the brief instead.', btn);
      });
      return;
    }
    openBrief(md, null, btn);
  }
  function openBrief(md, msg, returnEl) {
    closeDrawer({ noFocus: true });
    state.dialogReturn = returnEl || doc.activeElement;
    $('#brief-text').value = md;
    $('#brief-msg').textContent = msg || 'Markdown, ready to paste into a ticket, chat or postmortem document.';
    $('#brief-status').textContent = '';
    $('#brief-save').hidden = !(state.downloads && typeof state.downloads.save === 'function');
    setInert(true);
    $('#scrim').hidden = false;
    $('#brief').hidden = false;
    $('#brief-copy').focus();
  }
  function closeBrief(silent) {
    if ($('#brief').hidden) return;
    $('#brief').hidden = true;
    if (!state.drawerId) { $('#scrim').hidden = true; setInert(false); }
    if (!silent && state.dialogReturn && doc.contains(state.dialogReturn)) state.dialogReturn.focus();
  }

  /* ------------------------------------------------------------------ samples, blank, drafts */
  function sampleById(id) {
    var list = WR.samples || [];
    for (var i = 0; i < list.length; i++) if (list[i].id === id) return list[i];
    return null;
  }
  // Short names fit the closed picker in the status strip; the banner carries each example's full title.
  var SAMPLE_SHORT = {
    'bad-deploy-oom': 'Bad payments deploy',
    'coredns-outage': 'Name lookups failing',
    'cert-expiry': 'Expired certificate',
    'db-conn-exhaustion': 'Database out of connections'
  };
  function fillScenarioPicker() {
    var sel = $('#scenario');
    clear(sel);
    var grp = h('optgroup', { label: 'Example incidents' });
    (WR.samples || []).forEach(function (sm) {
      grp.appendChild(h('option', { value: sm.id, title: sm.title }, SAMPLE_SHORT[sm.id] || sm.title));
    });
    if (grp.childNodes.length) sel.appendChild(grp);
    sel.appendChild(h('option', { value: 'blank' }, 'Blank incident'));
  }
  // 'Your evidence' exists only while it is the current value: Safari ignores hidden on <option>.
  function setScenarioValue(v) {
    var sel = $('#scenario');
    var custom = sel.querySelector('option[value="custom"]');
    if (v === 'custom' && !custom) sel.appendChild(h('option', { value: 'custom', disabled: true }, 'Your evidence'));
    if (v !== 'custom' && custom) custom.parentNode.removeChild(custom);
    sel.value = v;
  }
  function resetViewState() {
    state.openHyps = {};
    state.openRbs = {};
    closeDrawer({ noFocus: true });
    $('#backpill').hidden = true;
  }
  function loadSample(id) {
    var sm = sampleById(id);
    if (!sm) return false;
    var texts = {};
    PANE_KEYS.forEach(function (k) { texts[k] = sm[k] || ''; ta(k).value = texts[k]; ta(k).scrollTop = 0; });
    setFields(fieldsFromContext(sm.context || {}));
    var c = sm.context || {};
    state.hidden = { now: c.now || null, year: c.year || null, cluster: c.cluster || null };
    state.example = { id: sm.id, title: sm.title, blurb: sm.blurb, texts: texts };
    state.protectDraft = !!readDraft();
    resetViewState();
    setScenarioValue(sm.id);
    updateBanner();
    analyzeNow();
    return true;
  }
  function loadBlank() {
    PANE_KEYS.forEach(function (k) { ta(k).value = ''; });
    setFields({});
    state.hidden = {};
    state.example = null;
    state.protectDraft = false;
    resetViewState();
    setScenarioValue('blank');
    updateBanner();
    analyzeNow();
  }
  function updateBanner() {
    var ex = state.example;
    $('#banner').hidden = !ex;
    if (ex) $('#banner-b').textContent = ex.title + ': ' + ex.blurb;
    $('#btn-restore').hidden = !(ex && readDraft());
  }
  // The page stays an "example" while at least one pane still holds the sample text unchanged.
  function trackExample() {
    if (state.example) {
      var t = state.example.texts;
      var still = PANE_KEYS.some(function (k) { return t[k] && ta(k).value === t[k]; });
      if (still) return;
      state.example = null;
      state.protectDraft = false;
      updateBanner();
    }
    if (!anyText()) state.hidden = {};
    setScenarioValue(anyText() ? 'custom' : 'blank');
  }
  function readDraft() {
    var raw = store.get(STORE_KEYS.draft);
    if (!raw) return null;
    try {
      var d = JSON.parse(raw);
      if (!d || d.v !== 1 || !d.panes) return null;
      var any = PANE_KEYS.some(function (k) { return typeof d.panes[k] === 'string' && d.panes[k].trim() !== ''; });
      return any ? d : null;
    } catch (e) { return null; }
  }
  function saveDraft() {
    if (state.protectDraft && state.example) return;
    var panes = getPaneTexts();
    if (!PANE_KEYS.some(function (k) { return panes[k].trim() !== ''; })) { store.del(STORE_KEYS.draft); return; }
    var hid = state.hidden || {};
    store.set(STORE_KEYS.draft, JSON.stringify({
      v: 1, savedAt: Date.now(), panes: panes, fields: readFields(),
      hidden: { now: hid.now || null, year: hid.year || null, cluster: hid.cluster || null },
      sampleId: state.example ? state.example.id : null
    }));
  }
  function restoreDraft(d) {
    PANE_KEYS.forEach(function (k) { ta(k).value = typeof d.panes[k] === 'string' ? d.panes[k] : ''; });
    setFields(d.fields || {});
    var hid = d.hidden || {};
    state.hidden = {
      now: typeof hid.now === 'string' ? hid.now : null,
      year: typeof hid.year === 'number' ? hid.year : null,
      cluster: typeof hid.cluster === 'string' ? hid.cluster : null
    };
    state.example = null;
    state.protectDraft = false;
    resetViewState();
    setScenarioValue('custom');
    updateBanner();
    analyzeNow();
  }
  function onUserEdit() {
    trackExample();
    scheduleAnalyze();
    clearTimeout(state.draftTimer);
    state.draftTimer = setTimeout(saveDraft, 500);
  }

  /* ------------------------------------------------------------------ theme */
  var THEME_NEXT = { system: 'light', light: 'dark', dark: 'system' };
  var THEME_WORD = { system: 'System', light: 'Light', dark: 'Dark' };
  function applyTheme(t) {
    if (!THEME_WORD[t]) t = 'system';
    state.theme = t;
    var root = doc.documentElement;
    if (t === 'system') root.removeAttribute('data-theme'); else root.setAttribute('data-theme', t);
    var b = $('#btn-theme');
    if (b) {
      b.textContent = 'Theme: ' + THEME_WORD[t];
      b.setAttribute('aria-label', 'Theme: ' + THEME_WORD[t] + (t === 'system' ? ' (follows your device)' : '') + '. Activate to change.');
    }
  }

  /* ------------------------------------------------------------------ sticky strip + phone minibar */
  function observeStrip() {
    var strip = $('#strip');
    var setH = function () {
      var sticky = getComputedStyle(strip).position === 'sticky';
      doc.documentElement.style.setProperty('--strip-h', (sticky ? strip.offsetHeight : 0) + 'px');
      redrawChartIfResized();
    };
    setH();
    if (window.ResizeObserver) new ResizeObserver(setH).observe(strip);
    window.addEventListener('resize', setH);
    if (window.ResizeObserver) {
      new ResizeObserver(function () { redrawChartIfResized(); }).observe($('#budget-body'));
    }
    if (window.IntersectionObserver) {
      new IntersectionObserver(function (es) {
        $('#minibar').classList.toggle('is-on', !es[0].isIntersecting);
      }).observe(strip);
    }
  }

  /* ------------------------------------------------------------------ events */
  function wire() {
    PANE_KEYS.forEach(function (k) {
      ta(k).addEventListener('keydown', function (e) {
        if (e.key !== 'Escape' || !state.backFrom || state.backPane !== k) return;
        e.preventDefault();
        e.stopPropagation();
        goBack();
      });
      ta(k).addEventListener('input', onUserEdit);
      $('#pane-' + k + ' [data-clear]').addEventListener('click', function () {
        ta(k).value = '';
        onUserEdit();
        ta(k).focus();
      });
    });
    ['#ctx-target', '#ctx-window', '#ctx-rpm', '#ctx-spent', '#ctx-ratio', '#ctx-tz', '#ctx-deployed'].forEach(function (sel) {
      $(sel).addEventListener('input', onUserEdit);
      $(sel).addEventListener('change', onUserEdit);
    });
    ['#scale-nodes', '#scale-logs-gb', '#scale-series', '#scale-apm-hosts'].forEach(function (sel) {
      $(sel).addEventListener('input', function () {
        clearTimeout(state.scaleTimer);
        state.scaleTimer = setTimeout(function () { if (state.analysis) guard('stacks', function (a) { renderStacks(a, true); }, state.analysis); }, 200);
      });
    });
    // tabs: click + arrow keys (roving tab index)
    $$('.tab').forEach(function (t) {
      t.addEventListener('click', function () { selectTab(t.getAttribute('data-pane')); });
    });
    $('#tabs').addEventListener('keydown', function (e) {
      var i = PANE_KEYS.indexOf(state.tab);
      var next = null;
      if (e.key === 'ArrowRight' || e.key === 'ArrowDown') next = PANE_KEYS[(i + 1) % PANE_KEYS.length];
      else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') next = PANE_KEYS[(i + PANE_KEYS.length - 1) % PANE_KEYS.length];
      else if (e.key === 'Home') next = PANE_KEYS[0];
      else if (e.key === 'End') next = PANE_KEYS[PANE_KEYS.length - 1];
      if (next) { e.preventDefault(); selectTab(next, { focusTab: true }); }
    });
    $('#scenario').addEventListener('change', function (e) {
      var v = e.target.value;
      if (v === 'blank') loadBlank();
      else if (v !== 'custom') loadSample(v);
    });
    $('#btn-blank').addEventListener('click', function () { loadBlank(); ta(state.tab).focus(); });
    $('#btn-restore').addEventListener('click', function () { var d = readDraft(); if (d) restoreDraft(d); });
    $('#btn-theme').addEventListener('click', function () {
      var t = THEME_NEXT[state.theme] || 'system';
      applyTheme(t);
      store.set(STORE_KEYS.theme, t);
    });
    $('#btn-export').addEventListener('click', onExport);
    $('#brief-close').addEventListener('click', function () { closeBrief(); });
    $('#brief-copy').addEventListener('click', function (e) { copyText($('#brief-text').value, e.currentTarget, $('#brief-text')); });
    $('#brief-save').addEventListener('click', function () {
      var dl = state.downloads;
      if (!dl || state.savePending) { if (state.savePending) $('#brief-status').textContent = 'A save prompt is already open.'; return; }
      state.savePending = true;
      Promise.resolve().then(function () { return dl.save({ filename: briefName(state.analysis), data: $('#brief-text').value }); }).then(function () {
        state.savePending = false;
        $('#brief-status').textContent = 'Saved.';
      }, function (err) {
        state.savePending = false;
        var code = err && err.code;
        if (code === 'rate_limited') { $('#brief-status').textContent = 'A save prompt is already open.'; return; }
        if (code === 'declined') { $('#brief-status').textContent = 'Not saved.'; return; }
        if (code === 'too_large' || code === 'bad_request') { $('#brief-status').textContent = 'This brief could not be saved as a file; copy it instead.'; return; }
        // unavailable, not_granted, capability_* or anything unknown: saving is off here.
        state.downloads = null;
        $('#brief-save').hidden = true;
        $('#brief-status').textContent = 'Saving files is not available here; copy the brief instead.';
        $('#brief-copy').focus();
      });
    });
    $('#brief').addEventListener('keydown', function (e) { trapKeys(e, $('#brief'), function () { closeBrief(); }); });
    $('#drawer').addEventListener('keydown', function (e) { trapKeys(e, $('#drawer'), function () { closeDrawer(); }); });
    $('#drawer-close').addEventListener('click', function () { closeDrawer(); });
    $('#scrim').addEventListener('click', function () { if (!$('#brief').hidden) closeBrief(); else closeDrawer(); });
    doc.addEventListener('keydown', function (e) {
      if (e.key !== 'Escape') return;
      if (!$('#brief').hidden) closeBrief();
      else if (state.drawerId) closeDrawer();
    });
    window.addEventListener('hashchange', function () {
      var hsh = (location.hash || '').replace(/^#/, '');
      if (/^sample-/.test(hsh)) {
        var id = hsh.slice(7);
        if (id === 'blank') loadBlank(); else loadSample(id);
      }
    });
  }
  function initDownloads() {
    try {
      if (window.claude && typeof window.claude.use === 'function') {
        Promise.resolve(window.claude.use('downloads')).then(function (ns) { state.downloads = ns || null; }, function () { state.downloads = null; });
      } else state.downloads = null;
    } catch (e) { state.downloads = null; }
  }

  /* ------------------------------------------------------------------ boot */
  function boot() {
    if (state.booted || !$('#app')) return;
    state.booted = true;
    if (!doc.documentElement.getAttribute('lang')) doc.documentElement.setAttribute('lang', 'en');
    applyTheme(store.get(STORE_KEYS.theme) || 'system');
    buildTzOptions();
    fillScenarioPicker();
    wire();
    initDownloads();
    selectTab(store.get(STORE_KEYS.tab) || 'logs', { save: false });
    var hsh = (location.hash || '').replace(/^#/, '');
    var draft = readDraft();
    var loaded = false;
    if (/^sample-/.test(hsh)) {
      var id = hsh.slice(7);
      if (id === 'blank') { loadBlank(); loaded = true; } else loaded = loadSample(id);
    } else if (draft) { restoreDraft(draft); loaded = true; }
    if (!loaded && !loadSample(DEFAULT_SAMPLE)) loadBlank();
    observeStrip();
    if (SECTION_IDS.indexOf(hsh) >= 0) {
      var target = doc.getElementById(hsh);
      if (target) requestAnimationFrame(function () { target.scrollIntoView({ block: 'start' }); });
    }
  }

  WR.ui.app = {
    jumpTo: jumpTo,
    jumpToSignal: jumpToSignal,
    loadSample: loadSample,
    loadBlank: loadBlank,
    reanalyze: analyzeNow,
    getAnalysis: function () { return state.analysis; },
    getInputs: getPaneTexts,
    openDrawer: openDrawer,
    closeDrawer: closeDrawer,
    buildBrief: function () { return buildBrief(state.analysis); },
    errors: state.errors
  };

  // The bundle's script sits after the markup, so boot at once when the shell is already parsed
  // (first paint then shows the loaded sample); otherwise wait for DOMContentLoaded.
  if (doc.getElementById('app')) boot();
  else doc.addEventListener('DOMContentLoaded', boot);
})(globalThis.WR = globalThis.WR || {});
