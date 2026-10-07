/*
 * load.mjs — loads the engine into Node the same way the browser build concatenates it.
 *
 * Imports every engine / samples / data script that exists, in the SPEC §1 build order, then any
 * extra *.js files in those folders that the order does not list yet (alphabetically), and exports
 * the resulting global WR namespace. UI scripts are skipped on purpose: they need a DOM.
 *
 * Files that do not exist yet are skipped, so other builders can add theirs without editing this.
 */
import { existsSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const BUILD_ORDER = [
  'src/engine/util.js',
  'src/engine/time.js',
  'src/engine/entities.js',
  'src/engine/redact.js',
  'src/engine/parse-logs.js',
  'src/engine/parse-traces.js',
  'src/engine/parse-alerts.js',
  'src/engine/parse-helm.js',
  'src/engine/budget.js',
  'src/engine/hypotheses.js',
  'src/engine/rollbacks.js',
  'src/engine/traits.js',
  'src/engine/analyze.js',
  'src/samples/samples.js',
  'src/data/stacks.js'
];

const FOLDERS = ['src/engine', 'src/samples', 'src/data'];

function extrasNotInOrder() {
  const listed = new Set(BUILD_ORDER);
  const out = [];
  for (const dir of FOLDERS) {
    const abs = path.join(root, dir);
    if (!existsSync(abs)) continue;
    for (const f of readdirSync(abs).sort()) {
      const rel = dir + '/' + f;
      if (f.endsWith('.js') && !listed.has(rel)) out.push(rel);
    }
  }
  return out;
}

for (const rel of [...BUILD_ORDER, ...extrasNotInOrder()]) {
  const abs = path.join(root, rel);
  if (existsSync(abs)) await import(pathToFileURL(abs).href);
}

export default globalThis.WR;
