// Runs WR.analyze on every sample and writes fixtures/analysis-<sampleId>.json (pretty JSON), plus
// fixtures/analysis-blank.json for the "Blank incident" scenario (all panes empty). UI builders
// build against these files, so they are the Analysis contract of SPEC §4 as the engine emits it.
//
// Usage: node scripts/make-fixtures.mjs
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const WR = (await import(join(ROOT, 'tests/load.mjs'))).default;
const OUT = join(ROOT, 'fixtures');
mkdirSync(OUT, { recursive: true });

function write(name, analysis) {
  const file = join(OUT, `analysis-${name}.json`);
  writeFileSync(file, JSON.stringify(analysis, null, 2) + '\n');
  const top = analysis.hypotheses[0];
  const rec = analysis.rollbacks.find((r) => r.recommended);
  console.log(`${name.padEnd(20)} ${analysis.severity}  ${top ? `${top.category} ${(top.confidence * 100).toFixed(0)}%` : 'no hypothesis'}  ` +
    `${rec ? rec.kind : 'no rollback'}  ${analysis.components.length} components  ${analysis.signals.length} signals  -> ${file}`);
}

for (const s of WR.samples) {
  write(s.id, WR.analyze({ logs: s.logs, traces: s.traces, alerts: s.alerts, helm: s.helm, context: s.context }));
}

// The blank scenario has no evidence and so no "now"; pin generatedAt so the file is stable.
write('blank', WR.analyze({
  logs: '', traces: '', alerts: '', helm: '',
  context: { slo: { target: 0.999, windowDays: 30, requestsPerMin: 1200, budgetSpentBeforePct: 0 } },
  generatedAt: Date.parse('2026-10-06T00:00:00Z')
}));
