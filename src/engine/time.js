/*
 * time.js — WR.time: every timestamp format the parsers meet, normalised to epoch ms UTC.
 *
 * The single most common way an incident timeline lies is a time zone silently assumed. So every
 * parse reports tsInferred=true whenever we had to supply a zone (defaultTz) or a year, and the
 * parsers count those so the pane chip can say "3 times assumed +02:00".
 *
 * We deliberately never call Date.parse(): its handling of zone-less strings differs between
 * engines and the host machine's zone, which would make the analysis depend on where it runs.
 */
(function (WR) {
  'use strict';

  var MONTHS = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };

  // Zone abbreviations that show up in Go's time.String() (helm list) and UnixDate output.
  // Ambiguous ones (IST, CST in Asia) are left out on purpose; they fall back to defaultTz.
  var ZONE_ABBR = {
    UTC: 0, GMT: 0, Z: 0, UT: 0,
    WET: 0, WEST: 60, BST: 60, CET: 60, CEST: 120, EET: 120, EEST: 180, MSK: 180,
    EST: -300, EDT: -240, CDT: -300, MST: -420, MDT: -360, PST: -480, PDT: -420,
    AKST: -540, AKDT: -480, HST: -600, JST: 540, KST: 540, AEST: 600, AEDT: 660, NZST: 720, NZDT: 780
  };

  /*
   * Offset in minutes east of UTC for "Z", "UTC", "+02:00", "+0200", "+02", "-05:30", "UTC+2",
   * or a known abbreviation. Returns null when the string is not a zone we can trust.
   */
  function offsetMinutes(tz) {
    if (tz == null) return null;
    var s = String(tz).trim();
    if (s === '' || /^(z|utc|gmt|ut)$/i.test(s)) return 0;
    var m = /^(?:utc|gmt)?\s*([+\-\u2212])\s*(\d{1,2})(?::?(\d{2}))?$/i.exec(s);
    if (m) {
      var sign = m[1] === '+' ? 1 : -1;
      var h = Number(m[2]), mm = Number(m[3] || 0);
      if (h > 14 || mm > 59) return null;
      return sign * (h * 60 + mm);
    }
    var up = s.toUpperCase();
    if (Object.prototype.hasOwnProperty.call(ZONE_ABBR, up)) return ZONE_ABBR[up];
    return null;
  }

  // "+02:00" label for an offset — used in warnings and the UI offset chip.
  function fmtOffset(min) {
    if (min == null) return '';
    if (min === 0) return 'Z';
    var sign = min < 0 ? '-' : '+';
    var a = Math.abs(min);
    var h = Math.floor(a / 60), m = a % 60;
    return sign + (h < 10 ? '0' : '') + h + ':' + (m < 10 ? '0' : '') + m;
  }

  // Accepts epoch ms, an ISO string, or anything parse() understands. null when unknown.
  function resolveNow(now, opts) {
    if (now == null || now === '') return null;
    if (typeof now === 'number') return isFinite(now) ? now : null;
    var r = parse(String(now), opts || {});
    return r ? r.ts : null;
  }

  function fracToMs(frac) {
    if (!frac) return 0;
    // Only the first three digits matter for ms; pad so ".5" means 500 ms, not 5 ms.
    return Number((frac + '000').slice(0, 3));
  }

  function defaultOffset(opts) {
    var off = offsetMinutes(opts && opts.defaultTz != null ? opts.defaultTz : 'Z');
    return off == null ? 0 : off;
  }

  /*
   * Year for stamps that carry none (klog, syslog). Priority: explicit ctx.year, then the year of
   * ctx.now, then the current UTC year (last resort — only reached when nothing else is known).
   */
  function inferYear(opts) {
    if (opts && opts.year) return Number(opts.year);
    var now = opts ? resolveNow(opts.now) : null;
    if (now != null) return new Date(now).getUTCFullYear();
    return new Date().getUTCFullYear();
  }

  function build(y, mo, d, h, mi, s, ms, offMin) {
    if (mo < 0 || mo > 11 || d < 1 || d > 31 || h > 24 || mi > 59 || s > 60) return null;
    var t = Date.UTC(y, mo, d, h, mi, s, ms);
    if (!isFinite(t)) return null;
    return t - (offMin || 0) * 60000;
  }

  // A stamp without a year that lands well in the future of "now" belongs to last year
  // (a December syslog line read in January).
  function rollYear(ts, opts, y, mo, d, h, mi, s, ms, off) {
    var now = opts ? resolveNow(opts.now) : null;
    if (now != null && ts > now + 86400000 && !(opts && opts.year)) {
      return build(y - 1, mo, d, h, mi, s, ms, off);
    }
    return ts;
  }

  var RE_EPOCH = /^-?\d{9,19}(?:\.\d+)?$/;
  // RFC3339 / ISO 8601, also "2026-10-05 23:51:02,123" and Go's "2026-10-05 23:47:03.1 +0200 CEST".
  var RE_ISO = /^(\d{4})[-\/](\d{2})[-\/](\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:[.,](\d+))?)?)?\s*(Z|[+-]\d{2}(?::?\d{2})?|UTC|GMT)?(?:\s+\(?([A-Za-z]{2,5})\)?)?(?:\s+m=[+-][\d.]+)?$/i;
  // RFC 1123 / 2822: "Mon, 05 Oct 2026 23:51:02 +0200" (kubectl describe Started/Finished).
  var RE_RFC1123 = /^(?:[A-Za-z]{3},?\s+)?(\d{1,2})\s+([A-Za-z]{3})\s+(\d{4})\s+(\d{2}):(\d{2})(?::(\d{2})(?:\.(\d+))?)?\s*(Z|[+-]\d{2}:?\d{2}|[A-Za-z]{1,5})?$/;
  // ANSIC / UnixDate: "Mon Oct  5 23:47:03 2026", "Mon Oct  5 23:47:03 CEST 2026" (helm history).
  var RE_ANSIC = /^(?:[A-Za-z]{3}\s+)?([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?\s+(?:([A-Za-z]{2,5}|[+-]\d{4})\s+)?(\d{4})$/;
  // Syslog: "Oct  5 23:51:02" (no year, no zone).
  var RE_SYSLOG = /^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?$/;
  // klog header stamp without the severity letter: "1005 23:51:02.123456".
  var RE_KLOG = /^(\d{2})(\d{2})\s+(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?$/;

  /*
   * parse(str, {defaultTz, year, now}) → { ts, tsInferred, tzAssumed, yearAssumed } | null
   * tzAssumed: a zone was supplied from defaultTz; yearAssumed: the year came from context.
   */
  function parse(str, opts) {
    if (str == null) return null;
    if (typeof str === 'number') return epoch(str);
    var s = String(str).trim();
    if (!s) return null;
    opts = opts || {};
    var m, off, ts;

    if (RE_EPOCH.test(s)) return epoch(Number(s));

    if ((m = RE_ISO.exec(s))) {
      var tzTok = m[8] || null;
      var abbr = m[9] || null;
      off = tzTok ? offsetMinutes(tzTok) : (abbr ? offsetMinutes(abbr) : null);
      var assumed = off == null;
      if (assumed) off = defaultOffset(opts);
      ts = build(+m[1], +m[2] - 1, +m[3], +(m[4] || 0), +(m[5] || 0), +(m[6] || 0), fracToMs(m[7]), off);
      if (ts == null) return null;
      return { ts: ts, tsInferred: assumed, tzAssumed: assumed, yearAssumed: false };
    }

    if ((m = RE_RFC1123.exec(s))) {
      var mo = MONTHS[m[2].toLowerCase()];
      if (mo == null) return null;
      off = m[8] ? offsetMinutes(m[8]) : null;
      var a1 = off == null;
      if (a1) off = defaultOffset(opts);
      ts = build(+m[3], mo, +m[1], +m[4], +m[5], +(m[6] || 0), fracToMs(m[7]), off);
      if (ts == null) return null;
      return { ts: ts, tsInferred: a1, tzAssumed: a1, yearAssumed: false };
    }

    if ((m = RE_ANSIC.exec(s))) {
      var mo2 = MONTHS[m[1].toLowerCase()];
      if (mo2 == null) return null;
      off = m[7] ? offsetMinutes(m[7]) : null;
      var a2 = off == null;
      if (a2) off = defaultOffset(opts);
      ts = build(+m[8], mo2, +m[2], +m[3], +m[4], +m[5], fracToMs(m[6]), off);
      if (ts == null) return null;
      return { ts: ts, tsInferred: a2, tzAssumed: a2, yearAssumed: false };
    }

    if ((m = RE_SYSLOG.exec(s))) {
      var mo3 = MONTHS[m[1].toLowerCase()];
      if (mo3 == null) return null;
      off = defaultOffset(opts);
      var y = inferYear(opts);
      ts = build(y, mo3, +m[2], +m[3], +m[4], +m[5], fracToMs(m[6]), off);
      if (ts == null) return null;
      ts = rollYear(ts, opts, y, mo3, +m[2], +m[3], +m[4], +m[5], fracToMs(m[6]), off);
      return { ts: ts, tsInferred: true, tzAssumed: true, yearAssumed: true };
    }

    if ((m = RE_KLOG.exec(s))) {
      off = defaultOffset(opts);
      var y2 = inferYear(opts);
      var mo4 = +m[1] - 1, d4 = +m[2];
      ts = build(y2, mo4, d4, +m[3], +m[4], +m[5], fracToMs(m[6]), off);
      if (ts == null) return null;
      ts = rollYear(ts, opts, y2, mo4, d4, +m[3], +m[4], +m[5], fracToMs(m[6]), off);
      return { ts: ts, tsInferred: true, tzAssumed: true, yearAssumed: true };
    }

    return null;
  }

  // Epoch numbers: magnitude decides the unit (s, ms, µs, ns). Epochs are UTC by definition.
  function epoch(n) {
    if (typeof n !== 'number' || !isFinite(n)) return null;
    var a = Math.abs(n);
    var ms;
    if (a < 1e11) ms = n * 1000;            // seconds (covers years 1973–5138)
    else if (a < 1e14) ms = n;              // milliseconds
    else if (a < 1e17) ms = n / 1000;       // microseconds
    else ms = n / 1e6;                      // nanoseconds
    return { ts: Math.round(ms), tsInferred: false, tzAssumed: false, yearAssumed: false };
  }

  /*
   * Leading-timestamp extraction for log lines. Returns { ts, tsInferred, tzAssumed, rest, format }
   * or null. Order matters: the most specific shapes are tried first so "2026-10-05 ..." is not
   * mistaken for something looser.
   */
  var RE_LEAD_ISO = /^\[?(\d{4}[-\/]\d{2}[-\/]\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2}|\s?UTC|\s?GMT)?)\]?(?:\s+|$)/;
  var RE_LEAD_SYSLOG = /^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+/;
  var RE_LEAD_EPOCH = /^(\d{10}(?:\.\d{1,9})?|\d{13})\s+/;
  function extract(line, opts) {
    if (!line) return null;
    var m = RE_LEAD_ISO.exec(line);
    var fmt = 'iso';
    if (!m) { m = RE_LEAD_SYSLOG.exec(line); fmt = 'syslog'; }
    if (!m) { m = RE_LEAD_EPOCH.exec(line); fmt = 'epoch'; }
    if (!m) return null;
    var r = parse(m[1], opts);
    if (!r) return null;
    return { ts: r.ts, tsInferred: r.tsInferred, tzAssumed: r.tzAssumed, yearAssumed: r.yearAssumed, rest: line.slice(m[0].length), format: fmt };
  }

  /*
   * age("3m12s") → 192000. Understands kubectl ages (45s, 3m12s, 2h, 5d4h, 2y), Go durations
   * (1.5s, 300ms, 2h45m0s, 12µs) and "2m (x5 over 10m)" by reading the leading token only.
   * "<unknown>", "<invalid>" and garbage → null.
   */
  var AGE_UNITS = { y: 31536000000, w: 604800000, d: 86400000, h: 3600000, m: 60000, s: 1000, ms: 1, us: 0.001, 'µs': 0.001, 'μs': 0.001, ns: 0.000001 };
  var AGE_RE = /(\d+(?:\.\d+)?)(ms|us|µs|μs|ns|y|w|d|h|m|s)/g;
  function age(str) {
    if (str == null) return null;
    var s = String(str).trim().split(/\s+/)[0];
    if (!s || s[0] === '<') return null;
    if (!/^(\d+(?:\.\d+)?(ms|us|µs|μs|ns|y|w|d|h|m|s))+$/.test(s)) return null;
    AGE_RE.lastIndex = 0;
    var total = 0, m;
    while ((m = AGE_RE.exec(s)) !== null) total += Number(m[1]) * AGE_UNITS[m[2]];
    return Math.round(total);
  }

  // Duration with a unit as written in traces/logs ("2304ms", "2.3s", "1500us", "87") → ms.
  function durationMs(str, defaultUnit) {
    if (str == null || str === '') return null;
    if (typeof str === 'number') return str;
    var s = String(str).trim();
    var m = /^(\d+(?:\.\d+)?)\s*(ms|us|µs|μs|ns|s|m|h)?$/.exec(s);
    if (!m) return age(s);
    var unit = m[2] || defaultUnit || 'ms';
    return Number(m[1]) * AGE_UNITS[unit];
  }

  function pad(n, w) { var s = String(n); while (s.length < (w || 2)) s = '0' + s; return s; }

  // "HH:MM:SS" in UTC — the UI's canonical clock (SPEC §3.5). Pass an offset to show local time.
  function fmt(ts, tz) {
    if (ts == null || !isFinite(ts)) return '--:--:--';
    var off = tz != null ? offsetMinutes(tz) || 0 : 0;
    var d = new Date(ts + off * 60000);
    return pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes()) + ':' + pad(d.getUTCSeconds());
  }

  // "2026-10-05 21:49:30Z" — dated form for briefs and drawers.
  function fmtDateTime(ts, tz) {
    if (ts == null || !isFinite(ts)) return '—';
    var off = tz != null ? offsetMinutes(tz) || 0 : 0;
    var d = new Date(ts + off * 60000);
    return d.getUTCFullYear() + '-' + pad(d.getUTCMonth() + 1) + '-' + pad(d.getUTCDate()) + ' ' +
      pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes()) + ':' + pad(d.getUTCSeconds()) + (off ? fmtOffset(off) : 'Z');
  }

  function iso(ts) {
    if (ts == null || !isFinite(ts)) return null;
    return new Date(ts).toISOString();
  }

  /*
   * Relative-age signals (kubectl events "3m12s", pods tables) are stored with attrs.ageMs and
   * attrs.relative=true. When the analysis settles on a global "now" (latest absolute timestamp
   * across all panes) it calls rebase() so every relative time hangs off the same clock.
   * Idempotent: running it twice with the same now gives the same result.
   */
  function rebase(signals, now) {
    if (now == null || !signals) return 0;
    var n = 0;
    for (var i = 0; i < signals.length; i++) {
      var s = signals[i];
      if (s && s.attrs && s.attrs.relative && typeof s.attrs.ageMs === 'number') {
        s.ts = now - s.attrs.ageMs;
        s.tsInferred = true;
        n++;
      }
    }
    return n;
  }

  WR.time = {
    parse: parse,
    extract: extract,
    age: age,
    durationMs: durationMs,
    fmt: fmt,
    fmtDateTime: fmtDateTime,
    iso: iso,
    offsetMinutes: offsetMinutes,
    fmtOffset: fmtOffset,
    resolveNow: resolveNow,
    inferYear: inferYear,
    rebase: rebase
  };
})(globalThis.WR = globalThis.WR || {});
