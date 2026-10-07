/*
 * util.js — small shared helpers used by every engine module and the UI.
 *
 * Kept dependency-free and DOM-free so the whole engine runs unchanged in Node (tests) and in the
 * browser (the single-file Artifact). Everything hangs off the global WR namespace.
 */
(function (WR) {
  'use strict';

  // ---------------------------------------------------------------------------------------------
  // Closed vocabularies. Other modules validate against these so a typo in one parser cannot
  // silently invent a new signal kind that the hypothesis rules never look at.
  // ---------------------------------------------------------------------------------------------
  var KINDS = [
    'oom_killed', 'crash_loop', 'image_pull', 'config_error', 'probe_failed', 'evicted', 'node_not_ready',
    'node_pressure', 'scheduling_failed', 'pvc_pending', 'dns_failure', 'conn_refused', 'timeout', 'tls_error',
    'http_5xx', 'http_429', 'throttled', 'hpa_maxed', 'rollout', 'restart', 'panic', 'db_error',
    'conn_exhaustion', 'migration', 'error_generic',
    'span_error', 'span_slow',
    'alert_firing', 'alert_resolved', 'slo_burn',
    'change'
  ];
  var KIND_SET = Object.create(null);
  KINDS.forEach(function (k) { KIND_SET[k] = true; });

  var SEVERITIES = ['info', 'warn', 'error', 'critical'];
  var SEV_RANK = { info: 0, warn: 1, error: 2, critical: 3 };

  function sevRank(s) { return SEV_RANK[s] == null ? 0 : SEV_RANK[s]; }
  function maxSev(a, b) { return sevRank(a) >= sevRank(b) ? a : b; }
  function isKind(k) { return KIND_SET[k] === true; }

  // ---------------------------------------------------------------------------------------------
  // HTML escaping. The UI must never put pasted text into innerHTML unescaped (SPEC §0).
  // ---------------------------------------------------------------------------------------------
  var ESC_MAP = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  function esc(s) {
    if (s == null) return '';
    return String(s).replace(/[&<>"']/g, function (c) { return ESC_MAP[c]; });
  }

  // FNV-1a 32-bit. Cheap, deterministic ids for changes/edges; not a security hash.
  function hash(str) {
    var h = 0x811c9dc5;
    var s = String(str);
    for (var i = 0; i < s.length; i++) {
      h ^= s.charCodeAt(i);
      h = Math.imul(h, 0x01000193);
    }
    return (h >>> 0).toString(36);
  }

  function clamp(x, lo, hi) {
    if (typeof x !== 'number' || isNaN(x)) return lo;
    return x < lo ? lo : x > hi ? hi : x;
  }

  // Order-preserving de-duplication; keyFn lets callers dedupe objects by a field.
  function uniq(arr, keyFn) {
    var seen = new Set();
    var out = [];
    if (!arr) return out;
    for (var i = 0; i < arr.length; i++) {
      var k = keyFn ? keyFn(arr[i]) : arr[i];
      if (seen.has(k)) continue;
      seen.add(k);
      out.push(arr[i]);
    }
    return out;
  }

  // Returns a plain object { key: [items] }; insertion order of keys follows first appearance.
  function groupBy(arr, keyFn) {
    var out = {};
    if (!arr) return out;
    for (var i = 0; i < arr.length; i++) {
      var k = typeof keyFn === 'function' ? keyFn(arr[i]) : arr[i][keyFn];
      (out[k] || (out[k] = [])).push(arr[i]);
    }
    return out;
  }

  // Human duration in plain English: "850 ms", "45 s", "3 min 12 s", "42 min", "2 h 5 min", "3 d 4 h".
  function fmtDuration(ms) {
    if (ms == null || typeof ms !== 'number' || isNaN(ms)) return '—';
    var neg = ms < 0;
    var a = Math.abs(ms);
    var out;
    if (a < 1000) out = Math.round(a) + ' ms';
    else if (a < 60000) out = (a < 10000 ? Math.round(a / 100) / 10 : Math.round(a / 1000)) + ' s';
    else if (a < 3600000) {
      var m = Math.floor(a / 60000);
      var s = Math.round((a % 60000) / 1000);
      if (s === 60) { m += 1; s = 0; }
      out = m < 10 && s ? m + ' min ' + s + ' s' : Math.round(a / 60000) + ' min';
    } else if (a < 48 * 3600000) {
      var h = Math.floor(a / 3600000);
      var mm = Math.round((a % 3600000) / 60000);
      if (mm === 60) { h += 1; mm = 0; }
      out = mm ? h + ' h ' + mm + ' min' : h + ' h';
    } else {
      var d = Math.floor(a / 86400000);
      var hh = Math.round((a % 86400000) / 3600000);
      if (hh === 24) { d += 1; hh = 0; }
      out = hh ? d + ' d ' + hh + ' h' : d + ' d';
    }
    return neg ? '−' + out : out;
  }

  /*
   * fmtPct takes a value that is ALREADY in percent units (12.5 → "12.5%"), because every *Pct
   * field in the Analysis contract (consumedPct, remainingPct, budgetSavedPct) is a percent.
   * Use fmtRatio for 0..1 fractions such as errorRatio.
   */
  function fmtPct(pct, digits) {
    if (pct == null || typeof pct !== 'number' || isNaN(pct)) return '—';
    var a = Math.abs(pct);
    var d = digits;
    if (d == null) d = a === 0 ? 0 : a >= 100 ? 0 : a >= 10 ? 1 : a >= 1 ? 1 : a >= 0.1 ? 2 : 3;
    var s = pct.toFixed(d);
    // Trim "12.0" → "12" so big numbers stay quiet.
    if (s.indexOf('.') >= 0) s = s.replace(/0+$/, '').replace(/\.$/, '');
    if (a > 0 && Number(s) === 0) return (pct < 0 ? '>−' : '<') + (1 / Math.pow(10, d)) + '%';
    return s + '%';
  }

  function fmtRatio(r, digits) {
    if (r == null || typeof r !== 'number' || isNaN(r)) return '—';
    return fmtPct(r * 100, digits);
  }

  function median(nums) {
    if (!nums || !nums.length) return null;
    var a = nums.slice().sort(function (x, y) { return x - y; });
    var mid = a.length >> 1;
    return a.length % 2 ? a[mid] : (a[mid - 1] + a[mid]) / 2;
  }

  // Nearest-rank percentile (p in 0..100) — the definition most dashboards use for p95.
  function percentile(nums, p) {
    if (!nums || !nums.length) return null;
    var a = nums.slice().sort(function (x, y) { return x - y; });
    var rank = Math.ceil((p / 100) * a.length);
    return a[clamp(rank - 1, 0, a.length - 1)];
  }

  function truncate(s, n) {
    if (s == null) return '';
    s = String(s);
    return s.length > n ? s.slice(0, Math.max(0, n - 1)) + '…' : s;
  }

  // Split into lines without losing 1-based numbering. Every parser reads lines through here, so
  // terminal debris is cleaned once: \r\n from Windows terminals, a lone \r (the browser's textarea
  // also turns that into a line break, so line numbers still match what the engineer sees), and
  // ANSI colour/cursor codes from kubectl, helm diff, stern or `git diff --color` output.
  var RE_ANSI = /\x1b\[[0-9;?]*[ -\/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]/g;
  function splitLines(text) {
    if (!text) return [];
    var s = String(text);
    if (s.charCodeAt(0) === 0xfeff) s = s.slice(1);                 // byte-order mark from a saved file
    if (s.indexOf('\x1b') >= 0) s = s.replace(RE_ANSI, '');
    // Non-breaking spaces arrive when a diff or table is copied out of a chat or web page; the
    // indentation-sensitive readers (helm diff YAML, fixed-width tables) need plain spaces.
    if (s.indexOf(' ') >= 0) s = s.replace(/ /g, ' ');
    var lines = s.split(/\r\n|\r|\n/);
    // A trailing newline is not a line the engineer pasted.
    if (lines.length && lines[lines.length - 1] === '') lines.pop();
    return lines;
  }
  function stripAnsi(s) { return String(s == null ? '' : s).replace(RE_ANSI, ''); }

  // Offsets of each line start, so a character index found by searching JSON can be turned into
  // a 1-based line number for "jump to source line".
  function lineIndex(text) {
    var starts = [0];
    var s = String(text || '');
    var i = -1;
    while ((i = s.indexOf('\n', i + 1)) !== -1) starts.push(i + 1);
    return starts;
  }

  function lineAt(starts, offset) {
    var lo = 0, hi = starts.length - 1;
    while (lo < hi) {
      var mid = (lo + hi + 1) >> 1;
      if (starts[mid] <= offset) lo = mid; else hi = mid - 1;
    }
    return lo + 1;
  }

  /*
   * Parse logfmt-style "k=v k2="quoted value"" pairs. Returns a plain object; the order of keys is
   * the order they appeared. Values keep their string form — callers coerce what they need.
   */
  var LOGFMT_RE = /([A-Za-z_@][\w.@/-]*)=("(?:[^"\\]|\\.)*"|'[^']*'|[^\s]*)/g;
  function logfmt(str) {
    var out = {};
    if (!str) return out;
    LOGFMT_RE.lastIndex = 0;
    var m;
    while ((m = LOGFMT_RE.exec(str)) !== null) {
      var v = m[2];
      if (v.length >= 2 && ((v[0] === '"' && v[v.length - 1] === '"') || (v[0] === "'" && v[v.length - 1] === "'"))) {
        v = v.slice(1, -1).replace(/\\(["\\])/g, '$1').replace(/\\n/g, '\n');
      }
      out[m[1]] = v;
    }
    return out;
  }

  /*
   * Lenient JSON: engineers paste traces and alert payloads that were cut off by a terminal
   * scrollback or a chat message limit. Rather than reject the whole pane, we cut back to the last
   * complete value and close the open brackets, then report that we did so.
   * Returns { value, error, repaired }.
   */
  function parseJsonLenient(text) {
    var src = String(text == null ? '' : text).trim();
    if (!src) return { value: null, error: 'empty', repaired: false };
    // Strip a UTF-8 BOM and a leading "$ curl ..." style echo line if someone pasted the command too.
    src = src.replace(/^\uFEFF/, '');
    try {
      return { value: JSON.parse(src), error: null, repaired: false };
    } catch (e) {
      var firstErr = e && e.message ? e.message : String(e);
      var start = src.search(/[\[{]/);
      if (start < 0) return { value: null, error: firstErr, repaired: false };
      var body = src.slice(start);
      var repaired = closeJson(body);
      if (repaired != null) {
        try {
          return { value: JSON.parse(repaired), error: firstErr, repaired: true };
        } catch (e2) { /* fall through */ }
      }
      return { value: null, error: firstErr, repaired: false };
    }
  }

  // Walk the text outside strings, remember the bracket stack right after each complete value (a
  // closing bracket, or just before a comma), and rebuild a closed document from the last such point.
  function closeJson(s) {
    var stack = [];
    var inStr = false, escNext = false;
    var bestEnd = -1, bestStack = null;
    for (var i = 0; i < s.length; i++) {
      var c = s[i];
      if (inStr) {
        if (escNext) escNext = false;
        else if (c === '\\') escNext = true;
        else if (c === '"') inStr = false;
        continue;
      }
      if (c === '"') { inStr = true; continue; }
      if (c === '{' || c === '[') stack.push(c);
      else if (c === ',' && stack.length) {
        // Everything before a comma is a complete element: cutting here keeps it.
        bestEnd = i;
        bestStack = stack.slice();
      } else if (c === '}' || c === ']') {
        var open = stack.pop();
        if ((c === '}' && open !== '{') || (c === ']' && open !== '[')) return null; // malformed, not just cut
        bestEnd = i + 1;
        bestStack = stack.slice();
        if (!stack.length) break; // a complete document — nothing to repair beyond this point
      }
    }
    if (bestEnd < 0) return null;
    var out = s.slice(0, bestEnd);
    for (var j = bestStack.length - 1; j >= 0; j--) out += bestStack[j] === '{' ? '}' : ']';
    return out;
  }

  /*
   * Split a pane into JSON documents and plain lines. Engineers paste "# cluster: x" above a JSON
   * payload, several payloads one after another, or NDJSON; a single JSON.parse of the whole pane
   * would reject all of those. A document starts on a line beginning with { or [ and ends where its
   * brackets balance (or at the end of the pane, when it was cut off).
   * Returns [{ type:'json', startLine, endLine, text } | { type:'line', lineNo, text }] (1-based).
   * Callers still fall back to line handling when JSON.parse rejects a single-line segment.
   */
  function segmentJson(lines) {
    var out = [];
    var i = 0;
    while (i < lines.length) {
      var t = lines[i].replace(/^\s+/, '');
      // Only a plausible JSON start opens a document; "[FIRING:2] ..." or "[pod/x" must not
      // swallow the rest of the pane while we wait for brackets that never balance.
      var jsonStart = (t[0] === '{' && /^\{\s*("|\}|$)/.test(t)) ||
        (t[0] === '[' && /^\[\s*([\[{"\d\]-]|true|false|null|$)/.test(t));
      if (!jsonStart) {
        out.push({ type: 'line', lineNo: i + 1, text: lines[i] });
        i++;
        continue;
      }
      var depth = 0, start = i, done = false, opened = false;
      while (i < lines.length && !done) {
        var s = lines[i];
        var inStr = false, escNext = false; // JSON strings cannot span lines
        for (var j = 0; j < s.length; j++) {
          var c = s[j];
          if (inStr) {
            if (escNext) escNext = false;
            else if (c === '\\') escNext = true;
            else if (c === '"') inStr = false;
            continue;
          }
          if (c === '"') inStr = true;
          else if (c === '{' || c === '[') { depth++; opened = true; }
          else if (c === '}' || c === ']') {
            depth--;
            if (opened && depth <= 0) { done = true; break; }
          }
        }
        i++;
      }
      out.push({ type: 'json', startLine: start + 1, endLine: i, text: lines.slice(start, i).join('\n') });
    }
    return out;
  }

  // Stats object shared by all parsers so the pane status chip can render any of them the same way.
  function newStats(format) {
    return { lines: 0, parsed: 0, skipped: 0, signals: 0, format: format || 'empty', tzAssumed: 0, warnings: [] };
  }

  function addWarning(stats, msg) {
    if (stats.warnings.indexOf(msg) === -1 && stats.warnings.length < 20) stats.warnings.push(msg);
  }

  WR.KINDS = KINDS;
  WR.SEVERITIES = SEVERITIES;
  WR.isKind = isKind;
  WR.sevRank = sevRank;
  WR.maxSev = maxSev;
  WR.esc = esc;
  WR.hash = hash;
  WR.clamp = clamp;
  WR.uniq = uniq;
  WR.groupBy = groupBy;
  WR.fmtDuration = fmtDuration;
  WR.fmtPct = fmtPct;
  WR.fmtRatio = fmtRatio;
  WR.median = median;
  WR.percentile = percentile;
  WR.truncate = truncate;
  WR.splitLines = splitLines;
  WR.stripAnsi = stripAnsi;
  WR.lineIndex = lineIndex;
  WR.lineAt = lineAt;
  WR.logfmt = logfmt;
  WR.parseJsonLenient = parseJsonLenient;
  WR.segmentJson = segmentJson;
  WR.newStats = newStats;
  WR.addWarning = addWarning;
})(globalThis.WR = globalThis.WR || {});
