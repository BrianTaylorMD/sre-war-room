/*
 * budget.js — WR.budget(slo, { errorRatio, errorRatioSource, firstAnomaly, now }) → Budget
 *
 * Error-budget impact using the method in the Google SRE Workbook, "Alerting on SLOs"
 * (https://sre.google/workbook/alerting-on-slos/):
 *   - burn rate = error ratio / (1 − SLO). A burn rate of 1 spends exactly the whole budget over
 *     the SLO window; burn 1,000 spends a 30-day budget in 43.2 minutes (Table 5-4).
 *   - budget consumed by a stretch of time = burn rate × minutes / window minutes.
 *   - Table 5-8 (99.9 % over 30 days) recommends three multiwindow burn-rate alerts:
 *       Page   1 hour long / 5 minutes short,  burn 14.4, 2 % of the budget consumed when it fires
 *       Page   6 hours     / 30 minutes,       burn 6,    5 %
 *       Ticket 3 days      / 6 hours,          burn 1,    10 %
 *     The short window is 1/12 of the long one. For other SLO windows we keep the consumed
 *     percentages and rescale the threshold (SPEC §4): threshold = consumed% × window / long window.
 *
 * Everything here is an estimate that assumes steady traffic and that the current error ratio
 * held since the first anomaly; the UI says so, and `notes` carries the plain-English caveats.
 */
(function (WR) {
  'use strict';

  var SOURCE = 'https://sre.google/workbook/alerting-on-slos/';
  var DEFAULTS = { target: 0.999, windowDays: 30, requestsPerMin: 1000, budgetSpentBeforePct: 0 };
  var DEFAULT_ERROR_RATIO = 0.01;

  // Google SRE Workbook Table 5-8. consumedPctAtFire is the fixed quantity; burn thresholds derive
  // from it so the rows stay right for 7- and 28-day windows too.
  var WORKBOOK_ROWS = [
    { severity: 'Page', longWindow: '1 hour', shortWindow: '5 minutes', longMinutes: 60, shortMinutes: 5, consumedPctAtFire: 2 },
    { severity: 'Page', longWindow: '6 hours', shortWindow: '30 minutes', longMinutes: 360, shortMinutes: 30, consumedPctAtFire: 5 },
    { severity: 'Ticket', longWindow: '3 days', shortWindow: '6 hours', longMinutes: 4320, shortMinutes: 360, consumedPctAtFire: 10 }
  ];

  var PROJECTIONS = [
    { label: 'Mitigate now', extraMinutes: 0 },
    { label: 'In 30 minutes', extraMinutes: 30 },
    { label: 'In 2 hours', extraMinutes: 120 }
  ];

  // Round for output only. JSON.stringify turns NaN/Infinity into null silently, so every number
  // that leaves this module goes through here (non-finite → null, then callers decide).
  function round(x, d) {
    if (typeof x !== 'number' || !isFinite(x)) return null;
    var f = Math.pow(10, d == null ? 3 : d);
    return Math.round(x * f) / f;
  }

  function num(v) {
    if (v == null || v === '') return null;
    var n = typeof v === 'number' ? v : Number(String(v).replace(/[%\s,]/g, ''));
    return isFinite(n) ? n : null;
  }

  /*
   * Accepts what the context form sends: target as 0.999 or as 99.9 (percent), window 7/28/30,
   * an optional error ratio override as 0.02 or 2 (percent). Returns the cleaned SLO plus warnings
   * for anything we had to reinterpret, so a typo never silently changes the math.
   */
  function normalizeSlo(slo) {
    var s = slo || {};
    var warnings = [];
    var target = num(s.target);
    if (target != null && target > 1 && target < 100) {
      target = target / 100;
      warnings.push('SLO target was given as a percent; read it as ' + round(target * 100, 3) + '%.');
    }
    if (target == null || !(target > 0 && target < 1)) {
      if (s.target != null && s.target !== '') warnings.push('SLO target "' + s.target + '" is not between 0 and 100%; used 99.9%.');
      target = DEFAULTS.target;
    }
    var windowDays = num(s.windowDays);
    if (windowDays == null || !(windowDays > 0) || windowDays > 366) {
      if (s.windowDays != null && s.windowDays !== '') warnings.push('SLO window "' + s.windowDays + '" days is not usable; used 30 days.');
      windowDays = DEFAULTS.windowDays;
    }
    var rpm = num(s.requestsPerMin);
    var rpmAssumed = false;
    if (rpm == null || rpm < 0) { rpm = DEFAULTS.requestsPerMin; rpmAssumed = true; }
    var spent = num(s.budgetSpentBeforePct);
    if (spent == null) spent = DEFAULTS.budgetSpentBeforePct;
    spent = WR.clamp(spent, 0, 100);
    var override = num(s.errorRatioOverride);
    if (override != null) {
      if (override > 1 && override <= 100) {
        override = override / 100;
        warnings.push('Error ratio override was given as a percent; read it as ' + round(override * 100, 3) + '%.');
      }
      if (!(override >= 0 && override <= 1)) {
        warnings.push('Error ratio override "' + s.errorRatioOverride + '" is not between 0 and 1; ignored.');
        override = null;
      }
    }
    return {
      target: target, windowDays: windowDays, requestsPerMin: rpm, requestsPerMinAssumed: rpmAssumed,
      budgetSpentBeforePct: spent, errorRatioOverride: override, warnings: warnings
    };
  }

  /*
   * Error ratio priority (SPEC §4 / task): manual override > SLO burn alert (its error ratio, or its
   * burn rate × (1 − SLO)) > traces (errored root spans / root spans) > logs (5xx share of
   * request-shaped lines) > 1 % default. Returns { errorRatio, source, note }.
   * sources = { alertBurn: {errorRatio, maxBurnRate} | null, traceStats | null, requests | null }
   */
  function resolveErrorRatio(slo, sources) {
    var n = slo && slo.target != null ? slo : normalizeSlo(slo);
    var src = sources || {};
    if (n.errorRatioOverride != null) {
      return { errorRatio: n.errorRatioOverride, source: 'override', note: 'Error ratio set by hand.' };
    }
    var b = src.alertBurn;
    if (b && (b.errorRatio != null || b.maxBurnRate != null)) {
      var er = b.errorRatio != null ? b.errorRatio : b.maxBurnRate * (1 - n.target);
      if (isFinite(er) && er >= 0) {
        return {
          errorRatio: Math.min(1, er), source: 'alert',
          note: 'Error ratio from the burn-rate alert' + (b.alertname ? ' ' + b.alertname : '') +
            (b.errorRatio == null ? ' (its burn rate × (1 − SLO))' : '') + '.'
        };
      }
    }
    var ts = src.traceStats;
    if (ts && ts.entryErrorRatio != null && ts.spans > 0 && isFinite(ts.entryErrorRatio)) {
      return {
        errorRatio: ts.entryErrorRatio, source: 'traces',
        note: 'Error ratio from the pasted traces (' + WR.fmtRatio(ts.entryErrorRatio) + ' of entry requests failed). Pasted traces usually over-represent failures, so set the error ratio if you know the real one.'
      };
    }
    var rq = src.requests;
    if (rq && rq.total >= 20) {
      return {
        errorRatio: rq.errors / rq.total, source: 'logs',
        note: 'Error ratio from request lines in the logs (' + rq.errors + ' of ' + rq.total + ' returned 5xx). A filtered paste (for example grep ERROR) overstates it.'
      };
    }
    return {
      errorRatio: DEFAULT_ERROR_RATIO, source: 'default',
      note: 'No burn-rate alert, traces or request logs to measure the error ratio; assumed 1%. Set the error ratio for a real estimate.'
    };
  }

  function windowMinutes(windowDays) { return windowDays * 1440; }
  // "6 hours" → "6-hour", for "the 6-hour window".
  function hyph(w) { return String(w || '').replace(/^(\d+) (minute|hour|day)s?$/, '$1-$2'); }

  // Percent of the whole SLO-window budget spent by `minutes` at `burnRate`.
  function consumedPct(burnRate, minutes, windowDays) {
    if (!(burnRate >= 0) || !(minutes >= 0)) return 0;
    return burnRate * minutes / windowMinutes(windowDays) * 100;
  }

  function alertRows(windowDays, burnRate, incidentMinutes, observed, hasEvidence) {
    // A burn rate on a pasted alert was measured over that alert's own window. It stands for a
    // Workbook row only when its labels or name give that row's long window (long_window="1h") and
    // its burn clears the row's threshold; an alert of unknown window is shown on its own line
    // instead (16x over an unknown window says nothing about the 6-hour or 3-day average).
    var observedRow = -1;
    if (observed && observed.longWindowMinutes != null) {
      for (var i = 0; i < WORKBOOK_ROWS.length; i++) {
        var thr = WORKBOOK_ROWS[i].consumedPctAtFire / 100 * windowMinutes(windowDays) / WORKBOOK_ROWS[i].longMinutes;
        if (Math.abs(observed.longWindowMinutes - WORKBOOK_ROWS[i].longMinutes) < 1 && observed.burnRate >= thr - 1e-9) { observedRow = i; break; }
      }
    }
    return WORKBOOK_ROWS.map(function (r, idx) {
      var threshold = r.consumedPctAtFire / 100 * windowMinutes(windowDays) / r.longMinutes;
      var above = burnRate != null && burnRate > 0 && burnRate >= threshold - 1e-9;
      // The Workbook's detection time from a clean start: the long window's average reaches the
      // threshold after window × threshold / burn rate minutes ("(1 − SLO) / error ratio × alerting
      // window size × burn rate"). The short window (1/12 as long) always crosses earlier, so the
      // long window decides when the multiwindow alert fires. Null when this burn never reaches it.
      var firesAfter = above ? round(r.longMinutes * threshold / burnRate, 2) : null;
      var row = {
        severity: r.severity, longWindow: r.longWindow, shortWindow: r.shortWindow,
        longMinutes: r.longMinutes, shortMinutes: r.shortMinutes, consumedPctAtFire: r.consumedPctAtFire,
        burnThreshold: round(threshold, 4),
        // This burn rate is above the row's threshold, so the alert fires if it holds long enough.
        wouldFire: above,
        firesAfterMinutes: firesAfter,
        // Minutes still to go before it fires at this burn (0 when already firing, null when it never will).
        firesInMinutes: above ? round(Math.max(0, firesAfter - incidentMinutes), 2) : null
      };
      // Estimate: the current burn started at the first anomaly with no errors before it; firing once
      // both windows' averages are above the threshold.
      var modelFiring = above && incidentMinutes >= firesAfter - 1e-9;
      // Observed: a burn-rate alert in the paste is firing at or above this row's threshold.
      var observedFiring = idx === observedRow;
      row.modelFiring = modelFiring;
      row.observedFiring = observedFiring;
      row.firing = modelFiring || observedFiring;
      row.firingSource = observedFiring ? 'alerts' : modelFiring ? 'estimate' : null;
      // One display state per row so every view words it the same way.
      if (hasEvidence === false) { row.state = 'no-evidence'; row.stateText = 'No evidence yet'; }
      else if (observedFiring) { row.state = 'firing-observed'; row.stateText = 'Firing (in your alerts)'; }
      else if (modelFiring) { row.state = 'firing-estimate'; row.stateText = 'Firing (estimate)'; }
      else if (above) { row.state = 'pending'; row.stateText = 'Fires in about ' + WR.fmtDuration(Math.max(1, Math.round(row.firesInMinutes)) * 60000) + ' at this burn'; }
      else { row.state = 'not-at-this-burn'; row.stateText = 'Not at this burn rate'; }
      return row;
    });
  }

  /*
   * budget(slo, { errorRatio, errorRatioSource, firstAnomaly, now, note })
   * errorRatio may be omitted: the override, then the 1 % default, apply.
   */
  function budget(slo, o) {
    var n = normalizeSlo(slo);
    o = o || {};
    var errorRatio = num(o.errorRatio);
    var source = o.errorRatioSource || null;
    var notes = n.warnings.slice();
    if (n.errorRatioOverride != null) { errorRatio = n.errorRatioOverride; source = 'override'; }
    if (errorRatio == null || !(errorRatio >= 0)) { errorRatio = DEFAULT_ERROR_RATIO; source = 'default'; }
    errorRatio = Math.min(1, errorRatio);
    if (!source) source = 'default';
    if (o.note) notes.push(o.note);
    if (n.requestsPerMinAssumed) notes.push('Requests per minute not set; assumed ' + DEFAULTS.requestsPerMin.toLocaleString('en-US') + '.');

    var budgetFraction = 1 - n.target;
    var burnRate = errorRatio / budgetFraction;
    var incidentMinutes = 0;
    if (o.firstAnomaly != null && o.now != null && isFinite(o.firstAnomaly) && isFinite(o.now)) {
      incidentMinutes = Math.max(0, (o.now - o.firstAnomaly) / 60000);
    }
    var wMin = windowMinutes(n.windowDays);
    var consumed = consumedPct(burnRate, incidentMinutes, n.windowDays);
    var remaining = Math.max(0, 100 - n.budgetSpentBeforePct - consumed);
    var minutesToExhaustion = burnRate > 0 ? remaining / 100 * wMin / burnRate : null;

    var projection = PROJECTIONS.map(function (p) {
      var c = consumedPct(burnRate, incidentMinutes + p.extraMinutes, n.windowDays);
      return {
        label: p.label, extraMinutes: p.extraMinutes,
        consumedPct: round(c, 4), remainingPct: round(Math.max(0, 100 - n.budgetSpentBeforePct - c), 4)
      };
    });

    // 25 points from the first anomaly to two hours past now, assuming the burn continues.
    var span = incidentMinutes + 120;
    var series = [];
    for (var i = 0; i < 25; i++) {
      var t = span * i / 24;
      series.push({ t: round(t, 2), remainingPct: round(Math.max(0, 100 - n.budgetSpentBeforePct - consumedPct(burnRate, t, n.windowDays)), 4) });
    }

    notes.push('Assumes steady traffic of ' + Math.round(n.requestsPerMin).toLocaleString('en-US') + ' requests per minute and that the current error ratio has held since the first anomaly.');
    var hasEvidence = o.hasEvidence != null ? !!o.hasEvidence : o.firstAnomaly != null;
    var observed = o.observedBurn && o.observedBurn.burnRate > 0 ? o.observedBurn : null;
    var rows = alertRows(n.windowDays, burnRate, incidentMinutes, observed, hasEvidence);
    var page = rows[0];
    // The row a firing alert would be if it followed the Workbook: its own row when the window is
    // known, else the most severe row its burn clears.
    var early = null;
    if (observed && hasEvidence) {
      early = rows.filter(function (r) { return r.observedFiring; })[0] ||
        rows.filter(function (r) { return observed.longWindowMinutes == null && observed.burnRate >= r.burnThreshold - 1e-9; })[0] || null;
      if (early && early.modelFiring) early = null;
    }
    var changeAt = num(o.changeAt);
    var nowMs = num(o.now);
    // Errors cannot have begun before the change that caused them; when that change is too recent
    // for the Workbook rule to have fired, the alert itself must be built differently.
    var changeTooRecent = early && changeAt != null && nowMs != null && (nowMs - changeAt) / 60000 < early.firesAfterMinutes;
    if (early && changeTooRecent) {
      notes.push('Your alert ' + (observed.alertname || '') + ' fired sooner than the Workbook rule would at ' + Math.round(observed.burnRate * 10) / 10 +
        '×: its ' + hyph(early.longWindow) + ' window needs about ' + Math.round(early.firesAfterMinutes) + ' minutes of errors, and the change behind this incident went out only ' +
        Math.round((nowMs - changeAt) / 60000) + ' minutes ago. The alert probably uses ' +
        (observed.longWindowMinutes != null ? 'a lower threshold' : 'a shorter window or a lower threshold') + ', or its value is a short-window reading, so the real current burn (and the budget numbers here) may differ in either direction. Check the alert rule.');
    } else if (early) {
      notes.push((observed.alertname || 'A burn-rate alert') + ' is already firing at ' + Math.round(observed.burnRate * 10) / 10 + '× in your alerts, but at that burn the ' +
        hyph(early.longWindow) + ' window needs about ' + Math.round(early.firesAfterMinutes) + ' minutes of errors to fire. Errors probably started before the first anomaly found ' +
        Math.round(incidentMinutes) + ' minutes ago, so the elapsed time and budget spent here are likely undercounted.');
    } else if (hasEvidence && page.wouldFire && !page.firing) {
      notes.push('At this burn rate the ' + hyph(page.longWindow) + ' page alert reaches its threshold about ' + Math.round(page.firesAfterMinutes) +
        ' minutes after the errors start (window × threshold ÷ burn rate), so it has not paged yet if errors began at the first anomaly. ' +
        'An alert already firing in your paste means errors started earlier or the burn is higher.');
    }

    return {
      sloTarget: n.target,
      windowDays: n.windowDays,
      requestsPerMin: n.requestsPerMin,
      budgetSpentBeforePct: n.budgetSpentBeforePct,
      errorRatio: round(errorRatio, 6),
      errorRatioSource: source,
      burnRate: round(burnRate, 3),
      incidentMinutes: round(incidentMinutes, 2),
      consumedPct: round(consumed, 4),
      remainingPct: round(remaining, 4),
      minutesToExhaustion: minutesToExhaustion == null ? null : round(minutesToExhaustion, 2),
      badRequests: Math.round(errorRatio * n.requestsPerMin * incidentMinutes),
      budgetRequests: Math.round(budgetFraction * n.requestsPerMin * wMin),
      alertRows: rows,
      hasEvidence: hasEvidence,
      observedBurnRate: observed ? round(observed.burnRate, 3) : null,
      observedAlert: observed ? (observed.alertname || null) : null,
      observedSignalId: observed ? (observed.signalId || null) : null,
      projection: projection,
      series: series,
      notes: notes,
      source: SOURCE
    };
  }

  /*
   * Budget a mitigation avoids compared with mitigating two hours from now (the slowest projection
   * row), at the current burn. `effect` (0..1) scales partial mitigations such as a restart.
   */
  function savedPct(b, etaMinutes, effect) {
    if (!b || b.burnRate == null || etaMinutes == null) return null;
    var e = effect == null ? 1 : effect;
    return round(consumedPct(b.burnRate, Math.max(0, 120 - etaMinutes), b.windowDays) * e, 3);
  }

  budget.normalizeSlo = normalizeSlo;
  budget.resolveErrorRatio = resolveErrorRatio;
  budget.consumedPct = consumedPct;
  budget.alertRows = alertRows;
  budget.savedPct = savedPct;
  budget.round = round;
  budget.SOURCE = SOURCE;
  budget.DEFAULT_ERROR_RATIO = DEFAULT_ERROR_RATIO;
  WR.budget = budget;
})(globalThis.WR = globalThis.WR || {});
