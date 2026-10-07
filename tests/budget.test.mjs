// Error budget math against the Google SRE Workbook, "Alerting on SLOs"
// (https://sre.google/workbook/alerting-on-slos/): Table 5-4 (time to exhaust a 30-day budget) and
// Table 5-8 (recommended multiwindow burn-rate alerts for a 99.9 % SLO over 30 days).
import test from 'node:test';
import assert from 'node:assert/strict';
import load from './load.mjs';

const WR = load || globalThis.WR;
const MIN = 60000;
const close = (a, b, eps = 1e-6, msg) => assert.ok(Math.abs(a - b) <= eps, `${msg || ''} expected ${b}, got ${a}`);
const slo999 = { target: 0.999, windowDays: 30, requestsPerMin: 1200, budgetSpentBeforePct: 0 };
// Burn rate b on a 99.9 % SLO means error ratio b × 0.001.
const run = (slo, burn, minutes, extra = {}) => WR.budget(slo, { errorRatio: burn * (1 - (slo.target > 1 ? slo.target / 100 : slo.target)), errorRatioSource: 'override', firstAnomaly: 0, now: minutes * MIN, ...extra });

test('burn rate = error ratio / (1 − SLO)', () => {
  const b = WR.budget(slo999, { errorRatio: 0.0162, errorRatioSource: 'alert', firstAnomaly: 0, now: 0 });
  close(b.burnRate, 16.2, 1e-9);
  assert.equal(b.errorRatioSource, 'alert');
  assert.equal(b.source, 'https://sre.google/workbook/alerting-on-slos/');
});

test('Table 5-8: burn 14.4 sustained for 1 hour consumes 2 % of a 30-day budget', () => {
  const b = run(slo999, 14.4, 60);
  close(b.consumedPct, 2, 1e-6);
  close(b.remainingPct, 98, 1e-6);
  assert.equal(b.alertRows[0].firing, true, '1 h / 5 min page fires');
});

test('Table 5-8: burn 6 sustained for 6 hours consumes 5 %', () => {
  const b = run(slo999, 6, 360);
  close(b.consumedPct, 5, 1e-6);
  assert.equal(b.alertRows[1].firing, true, '6 h / 30 min page fires');
  assert.equal(b.alertRows[0].firing, false, 'burn 6 is below the 14.4 page');
});

test('Table 5-8: burn 1 for 3 days consumes 10 %, and burn 1 spends the whole budget in 30 days (Table 5-4)', () => {
  close(run(slo999, 1, 3 * 1440).consumedPct, 10, 1e-6);
  close(run(slo999, 1, 30 * 1440).consumedPct, 100, 1e-6);
  close(run(slo999, 1, 0).minutesToExhaustion, 30 * 1440, 1e-6);
});

test('Table 5-4: burn 1,000 exhausts a full 30-day budget in 43.2 minutes', () => {
  const b = run(slo999, 1000, 0);
  close(b.minutesToExhaustion, 43.2, 1e-6);
});

test('alert rows reproduce Table 5-8 for 99.9 % over 30 days', () => {
  const rows = run(slo999, 0, 0).alertRows;
  assert.deepEqual(rows.map((r) => r.severity), ['Page', 'Page', 'Ticket']);
  assert.deepEqual(rows.map((r) => r.longWindow), ['1 hour', '6 hours', '3 days']);
  assert.deepEqual(rows.map((r) => r.shortWindow), ['5 minutes', '30 minutes', '6 hours']);
  assert.deepEqual(rows.map((r) => r.consumedPctAtFire), [2, 5, 10]);
  rows.forEach((r, i) => close(r.burnThreshold, [14.4, 6, 1][i], 1e-9));
  // The workbook's short window is 1/12 of the long window.
  rows.forEach((r) => assert.equal(r.shortMinutes * 12, r.longMinutes));
});

test('other SLO windows keep the consumed percentages and rescale the thresholds (28 days, 7 days)', () => {
  const r28 = run({ ...slo999, windowDays: 28 }, 0, 0).alertRows;
  [13.44, 5.6, 0.9333].forEach((t, i) => close(r28[i].burnThreshold, t, 1e-4));
  assert.deepEqual(r28.map((r) => r.consumedPctAtFire), [2, 5, 10]);
  const r7 = run({ ...slo999, windowDays: 7 }, 0, 0).alertRows;
  [3.36, 1.4, 0.2333].forEach((t, i) => close(r7[i].burnThreshold, t, 1e-4));
  // A 28-day window: burn 13.44 for 1 hour is again 2 %.
  close(run({ ...slo999, windowDays: 28 }, 13.44, 60).consumedPct, 2, 1e-6);
});

test('firing waits for the long window average to reach the threshold (Workbook detection time)', () => {
  // burn 100 against threshold 14.4 on the 1-hour row: fires after 60 x 14.4 / 100 = 8.64 minutes.
  const early = run(slo999, 100, 8).alertRows[0];
  assert.equal(early.wouldFire, true);
  assert.equal(early.firing, false, '8 minutes < 8.64-minute detection time');
  close(early.firesInMinutes, 0.64, 1e-6);
  const late = run(slo999, 100, 9).alertRows[0];
  assert.equal(late.firing, true);
  assert.equal(late.firesInMinutes, 0);
  // A burn below the threshold never fires that row.
  const low = run(slo999, 10, 600).alertRows[0];
  assert.equal(low.wouldFire, false);
  assert.equal(low.firing, false);
  assert.equal(low.firesInMinutes, null);
});

test('remaining budget, requests and projections', () => {
  const b = WR.budget({ ...slo999, budgetSpentBeforePct: 18 }, { errorRatio: 0.0162, errorRatioSource: 'alert', firstAnomaly: 0, now: 22 * MIN });
  close(b.consumedPct, 16.2 * 22 / 43200 * 100, 1e-3);
  close(b.remainingPct, 100 - 18 - b.consumedPct, 1e-3);
  close(b.minutesToExhaustion, b.remainingPct / 100 * 43200 / 16.2, 0.01);
  assert.equal(b.badRequests, Math.round(0.0162 * 1200 * 22));
  assert.equal(b.budgetRequests, Math.round(0.001 * 1200 * 43200));
  assert.deepEqual(b.projection.map((p) => p.label), ['Mitigate now', 'In 30 minutes', 'In 2 hours']);
  assert.deepEqual(b.projection.map((p) => p.extraMinutes), [0, 30, 120]);
  close(b.projection[2].consumedPct, 16.2 * (22 + 120) / 43200 * 100, 1e-3);
  assert.equal(b.series.length, 25);
  assert.equal(b.series[0].t, 0);
  close(b.series[24].t, 22 + 120, 1e-6);
  close(b.series[0].remainingPct, 82, 1e-6);
  for (let i = 1; i < b.series.length; i++) assert.ok(b.series[i].remainingPct <= b.series[i - 1].remainingPct);
});

test('remaining budget never goes below zero', () => {
  const b = WR.budget({ ...slo999, budgetSpentBeforePct: 90 }, { errorRatio: 0.5, firstAnomaly: 0, now: 600 * MIN });
  assert.equal(b.remainingPct, 0);
  assert.equal(b.minutesToExhaustion, 0);
  b.series.forEach((p) => assert.ok(p.remainingPct >= 0));
});

test('form values: a percent target, a percent override, and bad values never produce NaN', () => {
  const b = WR.budget({ target: 99.9, windowDays: 30, errorRatioOverride: 2 }, { errorRatio: 0.5, errorRatioSource: 'alert', firstAnomaly: 0, now: 60 * MIN });
  close(b.sloTarget, 0.999, 1e-12);
  close(b.errorRatio, 0.02, 1e-12);
  assert.equal(b.errorRatioSource, 'override');
  assert.ok(b.notes.some((n) => /percent/.test(n)));
  for (const slo of [{ target: 1 }, { target: 0 }, { target: 'abc', windowDays: -3 }, { target: 150 }, null, undefined]) {
    const x = WR.budget(slo, { firstAnomaly: null, now: null });
    // firesAfterMinutes / firesInMinutes are null by design when the burn never reaches that row's threshold.
    const nums = JSON.stringify(x).replace(/"(fires(After|In)Minutes|observed(BurnRate|Alert|SignalId)|firingSource)":null/g, '').match(/null/g) || [];
    assert.equal(x.sloTarget, 0.999);
    assert.ok(Number.isFinite(x.burnRate) && Number.isFinite(x.consumedPct) && Number.isFinite(x.remainingPct));
    assert.ok(nums.length === 0, 'no field silently became null: ' + JSON.stringify(x));
  }
});

test('error ratio priority: override > alert > traces > logs > default', () => {
  const R = WR.budget.resolveErrorRatio;
  const sources = {
    alertBurn: { maxBurnRate: 16.2, errorRatio: null, alertname: 'ErrorBudgetBurn' },
    traceStats: { spans: 40, entryErrorRatio: 0.57 },
    requests: { total: 200, errors: 10 }
  };
  const o = R({ target: 0.999, errorRatioOverride: 0.03 }, sources);
  assert.deepEqual([o.source, o.errorRatio], ['override', 0.03]);
  const a = R({ target: 0.999 }, sources);
  assert.equal(a.source, 'alert');
  close(a.errorRatio, 16.2 * 0.001, 1e-12); // burn rate × (1 − SLO)
  const a2 = R({ target: 0.999 }, { ...sources, alertBurn: { maxBurnRate: 16.2, errorRatio: 0.02 } });
  assert.equal(a2.errorRatio, 0.02, 'an explicit error ratio on the alert wins over its burn rate');
  const t = R({ target: 0.999 }, { ...sources, alertBurn: null });
  assert.deepEqual([t.source, t.errorRatio], ['traces', 0.57]);
  assert.match(t.note, /over-represent/);
  const l = R({ target: 0.999 }, { requests: { total: 200, errors: 10 } });
  assert.deepEqual([l.source, l.errorRatio], ['logs', 0.05]);
  assert.equal(R({ target: 0.999 }, { requests: { total: 5, errors: 5 } }).source, 'default', 'too few request lines to trust');
  const d = R({ target: 0.999 }, {});
  assert.deepEqual([d.source, d.errorRatio], ['default', 0.01]);
  assert.match(d.note, /assumed 1%/);
});

test('budget saved by mitigating in eta minutes instead of two hours', () => {
  const b = WR.budget(slo999, { errorRatio: 0.0162, firstAnomaly: 0, now: 22 * MIN });
  close(WR.budget.savedPct(b, 6), 16.2 * 114 / 43200 * 100, 1e-3);
  assert.equal(WR.budget.savedPct(b, 200), 0);
  close(WR.budget.savedPct(b, 3, 0.3), 16.2 * 117 / 43200 * 100 * 0.3, 1e-3);
});

// Workbook detection time for a burn-rate alert: (1 − SLO) / error ratio × window × threshold, which
// is window × threshold / burn rate. Its worked example: a 1-hour window alerting at burn 36 fires
// after about 2 minutes of a complete outage (burn 1,000 on 99.9 %): 60 × 36 / 1000 = 2.16.
test('detection time: firesAfterMinutes = long window × threshold / burn rate', () => {
  const full = run(slo999, 1000, 1);
  close(full.alertRows[0].firesAfterMinutes, 60 * 14.4 / 1000, 1e-2, '1 h row at a full outage');
  close(full.alertRows[1].firesAfterMinutes, 360 * 6 / 1000, 1e-2, '6 h row');
  close(full.alertRows[2].firesAfterMinutes, 4320 * 1 / 1000, 1e-2, '3 d row');
  close(60 * 36 / 1000, 2.16, 1e-9, 'the Workbook example');
  const b = run(slo999, 16.2, 22);
  close(b.alertRows[0].firesAfterMinutes, 53.33, 1e-2, 'burn 16.2 reaches the 1 h page after 53 minutes');
  assert.equal(b.alertRows[1].firesAfterMinutes, 360 * 6 / 16.2 > 0 ? Math.round(360 * 6 / 16.2 * 100) / 100 : null);
  assert.ok(b.notes.some((n) => /53 minutes/.test(n)), b.notes.join(' | '));
  assert.equal(run(slo999, 6, 60).alertRows[0].firesAfterMinutes, null, 'burn 6 never reaches the 14.4 page');
  assert.equal(run(slo999, 0, 60).alertRows[2].firesAfterMinutes, null, 'no burn, no alert');
});

test('a firing burn alert in the paste marks only the row it can stand for', () => {
  // 16.2x observed, 22 minutes in: the 1-hour page row (threshold 14.4) is the alert; 6-hour and 3-day stay modelled.
  // Review fix: the alert stands for a row only when its labels give that row's long window.
  const b = WR.budget(slo999, { errorRatio: 0.0162, errorRatioSource: 'alert', firstAnomaly: 0, now: 22 * MIN,
    observedBurn: { burnRate: 16.2, alertname: 'ErrorBudgetBurn', signalId: 'alr-3', longWindowMinutes: 60 }, hasEvidence: true });
  assert.deepEqual(b.alertRows.map((r) => r.state), ['firing-observed', 'pending', 'pending']);
  assert.equal(b.alertRows[0].firingSource, 'alerts');
  assert.equal(b.alertRows[0].modelFiring, false);
  assert.ok(b.notes.some((n) => /undercounted/.test(n)));
  // Same alert with no window in its labels: no row claims it; it is reported on its own line.
  const nw = WR.budget(slo999, { errorRatio: 0.0162, errorRatioSource: 'alert', firstAnomaly: 0, now: 22 * MIN,
    observedBurn: { burnRate: 16.2, alertname: 'ErrorBudgetBurn' }, hasEvidence: true });
  assert.ok(nw.alertRows.every((r) => !r.observedFiring));
  assert.equal(nw.observedAlert, 'ErrorBudgetBurn');
  // The change went out 25 minutes ago but the 1-hour rule needs 53: never claim errors began earlier.
  const recent = WR.budget(slo999, { errorRatio: 0.0162, errorRatioSource: 'alert', firstAnomaly: 3 * MIN, now: 25 * MIN, changeAt: 0,
    observedBurn: { burnRate: 16.2, alertname: 'ErrorBudgetBurn', longWindowMinutes: 60 }, hasEvidence: true });
  assert.ok(!recent.notes.some((n) => /probably started before/.test(n)), recent.notes.join(' | '));
  assert.ok(recent.notes.some((n) => /fired sooner than the Workbook rule/.test(n)));
  // 7x observed over 6 hours clears only the 6-hour row's threshold of 6.
  const c = WR.budget(slo999, { errorRatio: 0.007, firstAnomaly: 0, now: 10 * MIN, observedBurn: { burnRate: 7, longWindowMinutes: 360 }, hasEvidence: true });
  assert.deepEqual(c.alertRows.map((r) => r.observedFiring), [false, true, false]);
  // No evidence: every row says so.
  const d = WR.budget(slo999, { firstAnomaly: null, now: null });
  assert.equal(d.hasEvidence, false);
  assert.ok(d.alertRows.every((r) => r.state === 'no-evidence'));
});
