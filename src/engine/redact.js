/*
 * redact.js — WR.redact(text) → { text, count, kinds, byKind }
 *
 * Runs over everything before it leaves the page for Claude, and over Helm Secret/env values so
 * the analysis never echoes a credential. Replacements look like "[REDACTED:jwt]" so a reader can
 * still see WHAT was there (a token, a password) without seeing the value.
 *
 * Passes run from most to least specific, and later passes skip anything already redacted, so a
 * JWT inside "token=eyJ..." is counted once.
 */
(function (WR) {
  'use strict';

  var MARK = '[REDACTED:';
  function tag(kind) { return MARK + kind + ']'; }
  function alreadyRedacted(v) { return v.indexOf(MARK) === 0 || v === '(redacted)'; }

  // Values that are references or placeholders, not secrets; redacting them only adds noise.
  function isHarmlessValue(v) {
    var s = v.replace(/^["']|["']$/g, '');
    if (!s) return true;
    if (alreadyRedacted(s)) return true;
    if (/^(true|false|null|none|nil|yes|no|on|off|~|\*+|x+|<[^>]*>|\{\{.*\}\}|\$\{[^}]*\}|\$\(.*\)|\$[A-Z_][A-Z0-9_]*|changeme|redacted|\(redacted\))$/i.test(s)) return true;
    if (/^\d{1,5}$/.test(s)) return true;             // counts like max_tokens=4096
    if (/^(secretKeyRef|valueFrom|configMapKeyRef|\|-?|>-?)$/.test(s)) return true; // YAML structure, not a value
    return false;
  }

  // Key names whose value is a secret. Covers compound env names (DB_PASSWORD, STRIPE_API_KEY).
  var SECRET_KEY = '[A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|client[_-]?secret|private[_-]?key|access[_-]?key|auth[_-]?key|credentials?)[A-Za-z0-9_.-]*';

  var PASSES = [
    {
      kind: 'private-key',
      // A truncated paste may have BEGIN without END; redact to the end in that case.
      re: /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|$)/g,
      fn: function () { return tag('private-key'); }
    },
    {
      kind: 'jwt',
      re: /\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/g,
      fn: function () { return tag('jwt'); }
    },
    {
      kind: 'bearer',
      re: /\b(Bearer|Basic)(\s+)([A-Za-z0-9._~+\/=-]{8,})/g,
      fn: function (m, scheme, sp, v) { return alreadyRedacted(v) ? m : scheme + sp + tag(scheme.toLowerCase() === 'basic' ? 'basic-auth' : 'bearer'); }
    },
    {
      kind: 'aws-key',
      re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
      fn: function () { return tag('aws-key'); }
    },
    {
      kind: 'url-credential',
      // scheme://user:pass@host — keep the user (useful when debugging auth), drop the password.
      re: /\b([a-z][a-z0-9+.-]*:\/\/)([^:\/@\s]+):([^@\s\/]+)@/gi,
      fn: function (m, scheme, user, pass) { return alreadyRedacted(pass) ? m : scheme + user + ':' + tag('url-credential') + '@'; }
    },
    {
      kind: 'secret-value',
      // Kubernetes env entries put the name and the value on separate lines:
      //   - name: DB_PASSWORD
      //     value: hunter2
      // The optional leading +/- keeps this working inside diffs.
      re: new RegExp('(name:[ \\t]*["\']?' + SECRET_KEY + '["\']?[ \\t]*\\r?\\n[ \\t+\\-]*value:[ \\t]*)(["\']?)([^\\s"\']+)\\2', 'gi'),
      fn: function (m, head, q, v) { return isHarmlessValue(v) ? m : head + q + tag('secret-value') + q; }
    },
    {
      kind: 'secret-value',
      // key: value / key=value / "key": "value" on one line. [ \t] (not \s) so a key at the end of a
      // line never swallows the next line.
      re: new RegExp('(["\']?\\b' + SECRET_KEY + '["\']?[ \\t]*[:=][ \\t]*)(["\']?)([^\\s"\',;&}]+)\\2', 'gi'),
      fn: function (m, head, q, v) {
        // secretName / secretRef / tokenFile point AT a secret; they are not one.
        if (/(name|ref|refs|path|file|type|kind|id)["']?[ \t]*[:=][ \t]*$/i.test(head)) return m;
        return isHarmlessValue(v) ? m : head + q + tag('secret-value') + q;
      }
    },
    {
      kind: 'email',
      re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b/g,
      fn: function () { return tag('email'); }
    },
    {
      kind: 'base64',
      // Long base64 blobs (Secret data, keys). Pure hex (image digests, git SHAs, trace ids) and
      // single-case strings (paths, identifiers) are left alone: real random base64 of this length
      // practically always mixes upper case, lower case and digits.
      re: /(^|[^A-Za-z0-9+\/=_-])([A-Za-z0-9+\/]{40,}={0,2})(?![A-Za-z0-9+\/=_-])/g,
      fn: function (m, pre, v) {
        if (/^[0-9a-f]+$/i.test(v) || v[0] === '/' || v.indexOf('//') >= 0) return m;
        if (!/[A-Z]/.test(v) || !/[a-z]/.test(v) || !/[0-9]/.test(v)) return m;
        return pre + tag('base64');
      }
    }
  ];

  function redact(text) {
    var out = text == null ? '' : String(text);
    var byKind = {};
    var count = 0;
    for (var i = 0; i < PASSES.length; i++) {
      var p = PASSES[i];
      p.re.lastIndex = 0;
      out = out.replace(p.re, function () {
        var r = p.fn.apply(null, arguments);
        if (r !== arguments[0]) {
          count++;
          byKind[p.kind] = (byKind[p.kind] || 0) + 1;
        }
        return r;
      });
    }
    return { text: out, count: count, kinds: Object.keys(byKind).sort(), byKind: byKind };
  }

  // Quick test for "does this one value look like a secret?" — used by the Helm parser to decide
  // whether an env value may be shown as before/after.
  function looksSecret(key, value) {
    if (key && new RegExp('^' + SECRET_KEY + '$', 'i').test(String(key))) return true;
    if (value == null || value === '') return false;
    var r = redact(String(value));
    return r.count > 0;
  }

  WR.redact = redact;
  WR.redact.looksSecret = looksSecret;
})(globalThis.WR = globalThis.WR || {});
