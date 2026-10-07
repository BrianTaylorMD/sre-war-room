/*
 * parse-traces.js — WR.parseTraces(text, ctx) → { signals, entities, stats, extras }
 *
 * Formats (SPEC §3.2): OTLP JSON (proto3 JSON encoding: attribute lists of {key, value:{stringValue|
 * intValue|...}}, nanosecond times as strings, status.code 2 / "STATUS_CODE_ERROR"), Jaeger JSON
 * (API `data[]` or a single trace), Zipkin v2 JSON, and one-span-per-line text:
 *   2026-10-05T21:52:10.120Z trace=4bf9 span=a1 parent=- service=frontend op="GET /checkout" dur=2304ms
 *     status=ERROR code=502 peer=checkout-api cluster=prod-eu-west ns=shop
 *
 * Every format is first normalised to one span shape, then a single pass derives:
 *   - signals: span_error (one per errored span), span_slow (> 3× median of its service+operation,
 *     and at least 1 s)
 *   - extras.edges: caller → callee between components, with calls / errors / p95 / first error
 *   - extras.traceStats: { traces, spans, errorTraces, services, entryErrorRatio }
 *   - entry ("user-facing") components: root spans, or SERVER spans whose parent is not in the paste
 */
(function (WR) {
  'use strict';

  var T = WR.time;
  var E = WR.entities;

  var KIND_NAMES = { 0: null, 1: 'internal', 2: 'server', 3: 'client', 4: 'producer', 5: 'consumer' };

  function spanKind(k) {
    if (k == null || k === '') return null;
    if (typeof k === 'number') return KIND_NAMES[k] || null;
    var s = String(k).toLowerCase().replace(/^span_kind_/, '');
    if (/^\d$/.test(s)) return KIND_NAMES[Number(s)] || null;
    return /^(internal|server|client|producer|consumer)$/.test(s) ? s : null;
  }

  // OTLP AnyValue → plain JS value.
  function anyValue(v) {
    if (v == null || typeof v !== 'object') return v;
    if ('stringValue' in v) return v.stringValue;
    if ('intValue' in v) return Number(v.intValue);       // int64 arrives as a string in proto3 JSON
    if ('boolValue' in v) return v.boolValue === true || v.boolValue === 'true';
    if ('doubleValue' in v) return Number(v.doubleValue);
    if ('arrayValue' in v) return ((v.arrayValue && v.arrayValue.values) || []).map(anyValue);
    if ('kvlistValue' in v) return attrList((v.kvlistValue && v.kvlistValue.values) || []);
    if ('bytesValue' in v) return v.bytesValue;
    return null;
  }

  // Attributes arrive as [{key, value}] (OTLP), [{key, type, value}] (Jaeger tags) or a plain map.
  function attrList(list) {
    var out = {};
    if (!list) return out;
    if (Array.isArray(list)) {
      for (var i = 0; i < list.length; i++) {
        var a = list[i];
        if (!a || a.key == null) continue;
        out[a.key] = a.value != null && typeof a.value === 'object' ? anyValue(a.value) : a.value;
      }
      return out;
    }
    if (typeof list === 'object') {
      Object.keys(list).forEach(function (k) {
        var v = list[k];
        out[k] = v != null && typeof v === 'object' && !Array.isArray(v) ? anyValue(v) : v;
      });
    }
    return out;
  }

  function first(o, keys) {
    for (var i = 0; i < keys.length; i++) {
      var v = o[keys[i]];
      if (v !== undefined && v !== null && v !== '') return v;
    }
    return null;
  }

  function nanosToMs(v) {
    if (v == null || v === '') return null;
    var n = Number(v);
    return isFinite(n) ? n / 1e6 : null;
  }

  function isErrorCode(c) {
    if (c == null) return false;
    if (c === 2) return true;
    var s = String(c).toUpperCase();
    return s === '2' || s === 'STATUS_CODE_ERROR' || s === 'ERROR';
  }

  function httpStatusOf(a) {
    var v = first(a, ['http.response.status_code', 'http.status_code', 'http.status']);
    if (v == null) return null;
    var n = Number(v);
    return isFinite(n) && n >= 100 && n < 600 ? n : null;
  }

  // Fields shared by every format once its attributes are known.
  function finishSpan(sp, a) {
    sp.httpStatus = httpStatusOf(a);
    sp.dbSystem = first(a, ['db.system', 'db.type']);
    sp.dbName = first(a, ['db.name', 'db.namespace', 'db.instance']);
    sp.peer = first(a, ['peer.service', 'server.address', 'net.peer.name', 'peer.hostname', 'net.host.name', 'rpc.service']);
    if (sp.peer === sp.service) sp.peer = null;
    var et = first(a, ['error.type', 'exception.type']);
    var em = first(a, ['exception.message', 'error.message', 'error.msg']);
    if (!sp.errMsg && (em || et)) sp.errMsg = String(em || et);
    if (!sp.error && sp.httpStatus != null && sp.httpStatus >= 500) sp.error = true;
    sp.attrs = a;
    return sp;
  }

  // ------------------------------------------------------------------------------------------
  // Format readers → normalised spans
  // ------------------------------------------------------------------------------------------
  function readOtlp(doc, out, base) {
    var rs = doc.resourceSpans || doc.resource_spans || doc.batches || [];
    for (var i = 0; i < rs.length; i++) {
      var r = rs[i] || {};
      var res = attrList(r.resource && r.resource.attributes);
      var service = res['service.name'] || 'unknown-service';
      var cluster = res['k8s.cluster.name'] || null;
      var ns = res['k8s.namespace.name'] || null;
      var pod = res['k8s.pod.name'] || null;
      var scopes = r.scopeSpans || r.scope_spans || r.instrumentationLibrarySpans || [];
      for (var j = 0; j < scopes.length; j++) {
        var spans = (scopes[j] && scopes[j].spans) || [];
        for (var k = 0; k < spans.length; k++) {
          var s = spans[k];
          if (!s || typeof s !== 'object') continue;
          var a = attrList(s.attributes);
          var start = nanosToMs(s.startTimeUnixNano);
          var end = nanosToMs(s.endTimeUnixNano);
          var st = s.status || {};
          out.push(finishSpan({
            traceId: String(s.traceId || ''), spanId: String(s.spanId || ''),
            parentId: s.parentSpanId ? String(s.parentSpanId) : null,
            service: String(service), op: s.name || '(unnamed)', kind: spanKind(s.kind),
            startMs: start, durMs: start != null && end != null ? Math.max(0, end - start) : null,
            error: isErrorCode(st.code), errMsg: st.message || null,
            cluster: cluster || base.cluster, clusterKnown: !!cluster || base.clusterKnown,
            namespace: ns, pod: pod, line: null, format: 'OTLP JSON'
          }, a));
        }
      }
    }
  }

  function readJaegerTrace(t, out, base) {
    var procs = t.processes || {};
    var spans = t.spans || [];
    for (var i = 0; i < spans.length; i++) {
      var s = spans[i];
      if (!s || typeof s !== 'object') continue;
      var proc = (s.processID && procs[s.processID]) || s.process || {};
      var ptags = attrList(proc.tags);
      var a = attrList(s.tags);
      var parent = null;
      var refs = s.references || [];
      for (var r = 0; r < refs.length; r++) {
        if (refs[r] && refs[r].refType === 'CHILD_OF') { parent = refs[r].spanID; break; }
      }
      if (!parent && refs.length && refs[0]) parent = refs[0].spanID;
      if (!parent && s.parentSpanID && s.parentSpanID !== '0') parent = s.parentSpanID;
      var start = s.startTime != null ? Number(s.startTime) / 1000 : null; // µs → ms
      var cluster = ptags['k8s.cluster.name'] || a['k8s.cluster.name'] || null;
      var err = a.error === true || a.error === 'true' || String(a['otel.status_code'] || '').toUpperCase() === 'ERROR';
      out.push(finishSpan({
        traceId: String(s.traceID || t.traceID || ''), spanId: String(s.spanID || ''), parentId: parent ? String(parent) : null,
        service: String(proc.serviceName || 'unknown-service'), op: s.operationName || '(unnamed)',
        kind: spanKind(a['span.kind']), startMs: start, durMs: s.duration != null ? Number(s.duration) / 1000 : null,
        error: err, errMsg: a['otel.status_description'] || a['error.message'] || null,
        cluster: cluster || base.cluster, clusterKnown: !!cluster || base.clusterKnown,
        namespace: ptags['k8s.namespace.name'] || a['k8s.namespace.name'] || null,
        pod: ptags['k8s.pod.name'] || ptags.hostname || null, line: null, format: 'Jaeger JSON'
      }, a));
    }
  }

  function readZipkin(arr, out, base) {
    for (var i = 0; i < arr.length; i++) {
      var s = arr[i];
      if (!s || typeof s !== 'object') continue;
      var tags = s.tags || {};
      var a = attrList(tags);
      var le = s.localEndpoint || {}, re = s.remoteEndpoint || {};
      if (re.serviceName && !a['peer.service']) a['peer.service'] = re.serviceName;
      var cluster = a['k8s.cluster.name'] || null;
      out.push(finishSpan({
        traceId: String(s.traceId || ''), spanId: String(s.id || ''), parentId: s.parentId ? String(s.parentId) : null,
        service: String(le.serviceName || 'unknown-service'), op: s.name || '(unnamed)', kind: spanKind(s.kind),
        startMs: s.timestamp != null ? Number(s.timestamp) / 1000 : null, durMs: s.duration != null ? Number(s.duration) / 1000 : null,
        error: tags.error != null, errMsg: tags.error && tags.error !== 'true' ? String(tags.error) : null,
        cluster: cluster || base.cluster, clusterKnown: !!cluster || base.clusterKnown,
        namespace: a['k8s.namespace.name'] || null, pod: null, line: null, format: 'Zipkin JSON'
      }, a));
    }
  }

  // Dispatch on document shape. Returns true when the document was a trace format we know.
  function readDoc(doc, out, base) {
    if (!doc || typeof doc !== 'object') return false;
    // Tempo's /api/v2/traces/<id> wraps the OTLP document: {"trace": {"resourceSpans": [...]}}.
    if (!Array.isArray(doc) && doc.trace && typeof doc.trace === 'object' && !doc.resourceSpans && !doc.batches) return readDoc(doc.trace, out, base);
    if (Array.isArray(doc)) {
      if (!doc.length) return true;
      var f = doc[0] || {};
      if (f.resourceSpans || f.resource_spans) { doc.forEach(function (d) { readOtlp(d, out, base); }); return true; }
      if (f.spans && (f.processes || f.traceID)) { doc.forEach(function (d) { readJaegerTrace(d, out, base); }); return true; }
      if (f.traceId && f.id && (f.localEndpoint || f.timestamp != null)) { readZipkin(doc, out, base); return true; }
      if (f.traceId && f.spanId) { readOtlp({ resourceSpans: [{ resource: {}, scopeSpans: [{ spans: doc }] }] }, out, base); return true; }
      return false;
    }
    if (doc.resourceSpans || doc.resource_spans || doc.batches) { readOtlp(doc, out, base); return true; }
    if (Array.isArray(doc.data) && doc.data.length && doc.data[0] && doc.data[0].spans) { doc.data.forEach(function (t) { readJaegerTrace(t, out, base); }); return true; }
    if (doc.spans && (doc.processes || doc.traceID)) { readJaegerTrace(doc, out, base); return true; }
    if (doc.data && Array.isArray(doc.data) && !doc.data.length) return true;
    return false;
  }

  // Name of a recognised document that held no spans, for the pane chip and the warning.
  function docFormat(doc) {
    if (!doc || typeof doc !== 'object') return 'trace JSON';
    if (!Array.isArray(doc) && doc.trace && typeof doc.trace === 'object') return docFormat(doc.trace);
    if (Array.isArray(doc)) return doc.length && doc[0] && (doc[0].resourceSpans || doc[0].resource_spans) ? 'OTLP JSON' : 'trace JSON';
    if (doc.resourceSpans || doc.resource_spans || doc.batches) return 'OTLP JSON';
    if (doc.data || doc.processes || doc.traceID) return 'Jaeger JSON';
    return 'trace JSON';
  }

  // One-span-per-line text format.
  function readTextLine(line, lineNo, out, base, tzOpts, stats) {
    var body = line;
    var ts = null, tsInferred = false;
    var ex = T.extract(body, tzOpts);
    if (ex) { ts = ex.ts; tsInferred = ex.tsInferred; if (ex.tzAssumed) stats.tzAssumed++; body = ex.rest; }
    var kv = WR.logfmt(body);
    var service = kv.service || kv.svc || kv['service.name'];
    var traceId = kv.trace || kv.trace_id || kv.traceId;
    var spanId = kv.span || kv.span_id || kv.spanId;
    if (!service || !traceId || !spanId) return false;
    if (ts == null && kv.start) {
      var p = T.parse(kv.start, tzOpts);
      if (p) { ts = p.ts; tsInferred = p.tsInferred; if (p.tzAssumed) stats.tzAssumed++; }
    }
    var parent = kv.parent || kv.parent_id || kv.parentId || null;
    if (parent === '-' || parent === '' || parent === '0' || parent === 'none') parent = null;
    var status = String(kv.status || '').toUpperCase();
    var code = kv.code != null && /^\d{3}$/.test(kv.code) ? Number(kv.code) : (kv.http != null && /^\d{3}$/.test(kv.http) ? Number(kv.http) : null);
    var a = {};
    Object.keys(kv).forEach(function (k) { a[k] = kv[k]; });
    if (code != null) a['http.status_code'] = code;
    if (kv.peer) a['peer.service'] = kv.peer;
    if (kv.db) a['db.system'] = kv.db;
    if (kv['db.name']) a['db.name'] = kv['db.name'];
    var cluster = kv.cluster || null;
    var sp = finishSpan({
      traceId: String(traceId), spanId: String(spanId), parentId: parent ? String(parent) : null,
      service: String(service), op: kv.op || kv.name || kv.operation || '(unnamed)', kind: spanKind(kv.kind),
      startMs: ts, durMs: T.durationMs(kv.dur || kv.duration || kv.latency, 'ms'),
      error: status === 'ERROR' || status === 'STATUS_CODE_ERROR' || status === '2',
      errMsg: kv.msg || kv.error || kv.message || null,
      cluster: cluster || base.cluster, clusterKnown: !!cluster || base.clusterKnown,
      namespace: kv.ns || kv.namespace || null, pod: kv.pod || null, line: lineNo, format: 'span text'
    }, a);
    sp.tsInferred = tsInferred;
    out.push(sp);
    return true;
  }

  // ------------------------------------------------------------------------------------------
  // Main
  // ------------------------------------------------------------------------------------------
  function parseTraces(text, ctx) {
    ctx = ctx || {};
    var stats = WR.newStats('empty');
    var result = {
      signals: [], entities: [], stats: stats,
      extras: { edges: [], traceStats: { traces: 0, spans: 0, errorTraces: 0, services: 0, entryErrorRatio: null }, services: [], entryStats: {}, clusters: [], minTs: null, maxTs: null }
    };
    try {
      run(String(text == null ? '' : text), ctx, result);
    } catch (e) {
      WR.addWarning(stats, 'Trace parsing stopped early: ' + (e && e.message ? e.message : String(e)));
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
    var base = { cluster: ctx.cluster || E.DEFAULT_CLUSTER, clusterKnown: !!ctx.cluster };
    var spans = [];
    var formats = {};
    var emptyDocs = [];
    var lineStarts = null;

    var segs = WR.segmentJson(lines);
    for (var i = 0; i < segs.length; i++) {
      var sg = segs[i];
      if (sg.type === 'json') {
        var pj = WR.parseJsonLenient(sg.text);
        if (pj.value != null) {
          var before = spans.length;
          if (readDoc(pj.value, spans, base)) {
            stats.parsed += sg.endLine - sg.startLine + 1;
            if (pj.repaired) WR.addWarning(stats, 'Trace JSON starting on line ' + sg.startLine + ' looked cut off; read the complete part.');
            // Point each span at the line where its span id appears in this document.
            locateSpans(spans, before, sg, lines);
            for (var q = before; q < spans.length; q++) formats[spans[q].format] = 1;
            if (spans.length === before) { var ef = docFormat(pj.value); formats[ef] = 1; emptyDocs.push(ef + ' on line ' + sg.startLine); }
            continue;
          }
          if (sg.startLine === sg.endLine && readTextLine(sg.text, sg.startLine, spans, base, tzOpts, stats)) { stats.parsed++; formats['span text'] = 1; continue; }
          stats.skipped += sg.endLine - sg.startLine + 1;
          WR.addWarning(stats, 'JSON on line ' + sg.startLine + ' is not a trace format this page knows (OTLP, Jaeger, Zipkin).');
          continue;
        }
        if (sg.startLine !== sg.endLine || /^\s*\{/.test(sg.text)) {
          stats.skipped += sg.endLine - sg.startLine + 1;
          WR.addWarning(stats, 'Trace JSON starting on line ' + sg.startLine + ' could not be read (' + WR.truncate(pj.error || 'invalid JSON', 80) + ').');
          continue;
        }
        // single-line non-JSON starting with "[" → treat as a text line below
        sg = { type: 'line', lineNo: sg.startLine, text: sg.text };
      }
      var line = sg.text;
      if (!line.trim()) continue;
      var marker = E.detectCluster(line);
      if (marker) {
        base = { cluster: marker, clusterKnown: true };
        if (extras.clusters.indexOf(marker) < 0) extras.clusters.push(marker);
        stats.parsed++;
        continue;
      }
      if (/^\s*#/.test(line) || /^\s*(?:[$%>]\s*)?(curl|kubectl|jq)\b/.test(line)) { stats.parsed++; continue; }
      if (readTextLine(line, sg.lineNo, spans, base, tzOpts, stats)) { stats.parsed++; formats['span text'] = 1; }
      else stats.skipped++;
    }

    var fmtNames = Object.keys(formats);
    stats.format = fmtNames.length ? fmtNames.join(' + ') : (stats.lines ? 'unrecognised' : 'empty');
    if (!spans.length) {
      if (emptyDocs.length) WR.addWarning(stats, 'The pasted ' + emptyDocs.join(', ') + ' contains no spans (the query may have matched no traces).');
      else if (stats.lines) WR.addWarning(stats, 'No spans found. Paste OTLP JSON, Jaeger JSON, or one span per line (trace=… span=… service=…).');
      return;
    }
    if (stats.skipped) WR.addWarning(stats, stats.skipped + ' line' + (stats.skipped === 1 ? ' was' : 's were') + ' not recognised as spans.');
    if (stats.tzAssumed) WR.addWarning(stats, stats.tzAssumed + ' span time' + (stats.tzAssumed === 1 ? '' : 's') + ' had no time zone; assumed ' + T.fmtOffset(T.offsetMinutes(tzOpts.defaultTz) || 0) + '.');
    analyzeSpans(spans, result, lines);
  }

  /*
   * Map spans to source lines without a JSON parser that tracks positions: one regex pass over the
   * segment collects where each span id is declared, and each span takes that line.
   */
  var RE_SPAN_ID_DECL = /"(?:spanId|spanID|span_id|id)"\s*:\s*"([^"]+)"/g;
  function locateSpans(spans, from, seg, lines) {
    var starts = WR.lineIndex(seg.text);
    var pos = Object.create(null);
    RE_SPAN_ID_DECL.lastIndex = 0;
    var m;
    while ((m = RE_SPAN_ID_DECL.exec(seg.text)) !== null) {
      if (pos[m[1]] == null) pos[m[1]] = m.index;
    }
    for (var i = from; i < spans.length; i++) {
      var p = pos[spans[i].spanId];
      spans[i].line = p != null ? seg.startLine + WR.lineAt(starts, p) - 1 : seg.startLine;
    }
  }

  function analyzeSpans(spans, result, lines) {
    var extras = result.extras;
    var ents = E.collector();
    var byKey = Object.create(null);
    var childCount = Object.create(null);
    var serviceNames = Object.create(null);
    var traces = Object.create(null);
    var i, s;

    for (i = 0; i < spans.length; i++) {
      s = spans[i];
      byKey[s.traceId + '/' + s.spanId] = s;
      serviceNames[s.service.toLowerCase()] = true;
      var h = E.hint({ name: s.service, namespace: s.namespace, cluster: s.cluster, clusterKnown: s.clusterKnown, source: 'traces' });
      if (h && s.pod) h.pods = [String(s.pod).toLowerCase()];
      s.entity = h ? ents.add(h) : null;
      var tr = traces[s.traceId] || (traces[s.traceId] = { error: false, spans: [] });
      tr.spans.push(s);
      if (s.error) tr.error = true;
      if (s.startMs != null) {
        var ms = Math.round(s.startMs);
        if (extras.minTs == null || ms < extras.minTs) extras.minTs = ms;
        if (extras.maxTs == null || ms > extras.maxTs) extras.maxTs = ms;
      }
    }
    for (i = 0; i < spans.length; i++) {
      s = spans[i];
      if (s.parentId) {
        var pk = s.traceId + '/' + s.parentId;
        s.parent = byKey[pk] || null;
        if (s.parent) childCount[pk] = (childCount[pk] || 0) + 1;
      } else s.parent = null;
    }

    // ---- edges --------------------------------------------------------------------------------
    var edges = Object.create(null), edgeList = [];
    function edge(from, to, sp) {
      if (!from || !to || from === to) return;
      var k = from + '->' + to;
      var e = edges[k];
      if (!e) { e = edges[k] = { id: k, from: from, to: to, calls: 0, errors: 0, p95ms: null, firstErrorTs: null, _d: [] }; edgeList.push(e); }
      e.calls++;
      if (sp.durMs != null) e._d.push(sp.durMs);
      if (sp.error) {
        e.errors++;
        if (sp.startMs != null && (e.firstErrorTs == null || sp.startMs < e.firstErrorTs)) e.firstErrorTs = Math.round(sp.startMs);
      }
    }

    var entryRoots = 0, entryErrors = 0;
    for (i = 0; i < spans.length; i++) {
      s = spans[i];
      if (!s.entity) continue;
      // Rule 1: a child in another service means the parent's service called it.
      if (s.parent && s.parent.entity && s.parent.entity.id !== s.entity.id) edge(s.parent.entity.id, s.entity.id, s);

      var hasChild = !!childCount[s.traceId + '/' + s.spanId];
      // Rule 2: client spans to a database end at a datastore component. The database server is
      // named by peer.service, else server.address / net.peer.name; db.name (the logical database
      // inside it, often the same word as the service) is only the fallback.
      if ((s.kind === 'client' || s.kind == null) && (s.dbSystem || s.dbName) && !hasChild) {
        var peerSvc = s.attrs && s.attrs['peer.service'] && s.attrs['peer.service'] !== s.service ? s.attrs['peer.service'] : null;
        var host = s.attrs && (peerSvc || s.attrs['server.address'] || s.attrs['net.peer.name']);
        var hh = host ? E.fromHost(host) : null;
        var dbName = hh && !hh.external ? hh.name : String(s.dbName || s.dbSystem);
        // A bare peer.service says nothing about the database's namespace (it is usually not the
        // caller's), so leave it open for the entity reconciler to match the real workload.
        var dbNs = (hh && hh.namespace) || (peerSvc && hh && !hh.external ? null : s.namespace);
        var dh = E.hint({ name: dbName, namespace: dbNs, cluster: s.cluster, clusterKnown: s.clusterKnown, type: 'datastore', forceType: true, source: 'traces' });
        if (dh) { dh = ents.add(dh); edge(s.entity.id, dh.id, s); s.targetId = dh.id; }
      } else if ((s.kind === 'client' || s.kind === 'producer' || (s.kind == null && s.format === 'span text')) && s.peer && !hasChild) {
        // (One-span-per-line text rarely carries a span kind: a span that names a peer and has no
        // child span is the client side of that call.)
        // Rule 3: an uninstrumented callee named by peer.service / server.address.
        var ph = E.fromHost(s.peer);
        if (ph && ph.name !== s.entity.name) {
          var known = serviceNames[ph.name];
          var th = E.hint({
            name: ph.name, namespace: ph.namespace, cluster: s.cluster, clusterKnown: s.clusterKnown,
            type: ph.external || (!known && !ph.namespace) ? 'external' : null, source: 'traces'
          });
          if (th) { th = ents.add(th); edge(s.entity.id, th.id, s); s.targetId = th.id; }
        }
      }

      // Entry spans: no parent at all, or a SERVER span whose parent is outside the paste.
      var isRoot = !s.parentId;
      var isEntry = isRoot || (s.kind === 'server' && !s.parent);
      if (isEntry) {
        s.entity.userFacing = true;
        var es = extras.entryStats[s.entity.id] || (extras.entryStats[s.entity.id] = { roots: 0, errors: 0 });
        es.roots++;
        if (s.error) es.errors++;
      }
      if (isRoot) { entryRoots++; if (s.error) entryErrors++; }
    }
    // When every pasted span has a parent (a partial trace), fall back to the entry spans.
    if (!entryRoots) {
      Object.keys(extras.entryStats).forEach(function (k) { entryRoots += extras.entryStats[k].roots; entryErrors += extras.entryStats[k].errors; });
    }

    edgeList.forEach(function (e) {
      e.p95ms = e._d.length ? Math.round(WR.percentile(e._d, 95) * 10) / 10 : null;
      delete e._d;
    });

    // ---- slow spans: > 3× the median of the same service + operation, and ≥ 1 s ----------------
    var groups = Object.create(null);
    for (i = 0; i < spans.length; i++) {
      s = spans[i];
      if (s.durMs == null) continue;
      var gk = s.service + '\u0000' + s.op;
      (groups[gk] || (groups[gk] = [])).push(s.durMs);
    }
    var medians = Object.create(null);
    Object.keys(groups).forEach(function (k) { medians[k] = WR.median(groups[k]); });

    // ---- signals ---------------------------------------------------------------------------------
    var sigByTrace = Object.create(null);
    var perLine = Object.create(null);
    for (i = 0; i < spans.length; i++) {
      s = spans[i];
      var med = medians[s.service + '\u0000' + s.op];
      var slow = s.durMs != null && med != null && s.durMs > 3 * med && s.durMs >= 1000;
      if (!s.error && !slow) continue;
      var kind = s.error ? 'span_error' : 'span_slow';
      var lineNo = s.line || 1;
      var k = perLine[lineNo] || 0;
      perLine[lineNo] = k + 1;
      var why = s.error
        ? (s.errMsg || (s.httpStatus ? 'HTTP ' + s.httpStatus : 'error status'))
        : 'took ' + WR.fmtDuration(s.durMs) + ' (typical ' + WR.fmtDuration(med) + ')';
      var attrs = { traceId: s.traceId, spanId: s.spanId, op: s.op, durMs: s.durMs != null ? Math.round(s.durMs * 10) / 10 : null, spanKind: s.kind, format: s.format };
      if (s.parentId) attrs.parentId = s.parentId;
      if (s.httpStatus != null) attrs.httpStatus = s.httpStatus;
      if (s.errMsg) attrs.statusMessage = s.errMsg;
      if (s.peer) attrs.peer = s.peer;
      if (s.dbSystem) attrs.dbSystem = s.dbSystem;
      if (s.targetId) attrs.targetId = s.targetId;
      if (slow) attrs.slow = true;
      if (med != null) attrs.medianMs = Math.round(med * 10) / 10;
      if (s.error && s.errMsg && WR.classifyText) {
        var ck = WR.classifyText(s.errMsg);
        if (ck) attrs.causeKind = ck;
      }
      var sig = {
        id: 'trc-' + lineNo + (k ? '.' + k : ''),
        source: 'traces', line: lineNo, ts: s.startMs != null ? Math.round(s.startMs) : null,
        tsInferred: !!s.tsInferred, severity: s.error ? 'error' : 'warn', kind: kind,
        componentId: s.entity ? s.entity.id : null, relatedIds: [],
        text: WR.truncate(s.service + ': ' + s.op + (s.error ? ' failed — ' : ' slow — ') + why, 400),
        raw: s.format === 'span text' ? WR.truncate(lines[lineNo - 1] || '', 2000) : WR.truncate(s.service + ' ' + s.op + ' trace=' + s.traceId + ' span=' + s.spanId, 400),
        attrs: attrs
      };
      result.signals.push(sig);
      (sigByTrace[s.traceId] || (sigByTrace[s.traceId] = [])).push(sig);
    }
    // Errors in the same trace are one causal chain; let the UI walk it.
    Object.keys(sigByTrace).forEach(function (t) {
      var list = sigByTrace[t];
      if (list.length < 2) return;
      for (var a = 0; a < list.length; a++) {
        for (var b = 0; b < list.length && list[a].relatedIds.length < 10; b++) {
          if (a !== b) list[a].relatedIds.push(list[b].id);
        }
      }
    });

    var traceIds = Object.keys(traces);
    extras.edges = edgeList;
    extras.services = Object.keys(serviceNames);
    extras.traceStats = {
      traces: traceIds.length,
      spans: spans.length,
      errorTraces: traceIds.filter(function (t) { return traces[t].error; }).length,
      services: extras.services.length,
      entryErrorRatio: entryRoots ? entryErrors / entryRoots : null
    };
    result.entities = ents.list();
  }

  WR.parseTraces = parseTraces;
})(globalThis.WR = globalThis.WR || {});
