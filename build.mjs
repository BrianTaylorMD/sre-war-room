// Bundles the app into one self-contained page: dist/index.html.
// The Artifact host wraps the file in its own <!doctype><head><body> skeleton,
// so shell.html carries only <title>, font links, <style> and body markup.
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = dirname(fileURLToPath(import.meta.url));

// Concatenation order is the contract in SPEC.md section 1.
export const ORDER = [
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
  'src/data/stacks.js',
  'src/ui/map.js',
  'src/ui/investigate.js',
  'src/ui/app.js',
];

function build() {
  // --allow-missing lets one builder bundle while sibling modules are still being written.
  const allowMissing = process.argv.includes('--allow-missing');
  const missing = ORDER.filter((f) => !existsSync(join(ROOT, f)));
  if (missing.length && !allowMissing) throw new Error('Missing source files:\n  ' + missing.join('\n  '));
  if (missing.length) console.warn('Skipping missing (--allow-missing): ' + missing.join(', '));

  // A literal "</script" inside any JS string would end the inline script early.
  const js = ORDER.filter((f) => existsSync(join(ROOT, f))).map((f) => `/* ---- ${f} ---- */\n` + readFileSync(join(ROOT, f), 'utf8'))
    .join('\n;\n')
    .replace(/<\/script/gi, '<\\/script');
  // styles.css owns the tokens and must come first; component sheets follow.
  const css = ['src/ui/styles.css', 'src/ui/map.css', 'src/ui/investigate.css']
    .filter((f) => existsSync(join(ROOT, f)))
    .map((f) => `/* ---- ${f} ---- */\n` + readFileSync(join(ROOT, f), 'utf8'))
    .join('\n');
  const shell = readFileSync(join(ROOT, 'src/ui/shell.html'), 'utf8');

  for (const marker of ['/*INLINE:src/ui/styles.css*/', '/*INLINE:ALL_JS*/']) {
    if (!shell.includes(marker)) throw new Error('shell.html is missing marker ' + marker);
  }
  if (/<!doctype|<html[\s>]|<head[\s>]|<body[\s>]/i.test(shell)) {
    throw new Error('shell.html must not contain doctype/html/head/body tags (the host adds them)');
  }
  if (!/^\s*<title>[^<]+<\/title>/i.test(shell)) {
    throw new Error('shell.html must start with its <title> (only the first 8KB is scanned)');
  }

  // Function replacers so "$&" etc. inside the code are not treated as patterns.
  const out = shell
    .replace('/*INLINE:src/ui/styles.css*/', () => css)
    .replace('/*INLINE:ALL_JS*/', () => js);

  mkdirSync(join(ROOT, 'dist'), { recursive: true });
  writeFileSync(join(ROOT, 'dist/index.html'), out);
  // A local preview copy with the skeleton the host would add, for browser checks.
  const preview = '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><link rel="icon" href="data:,"><style>:root{color-scheme:light;padding-top:env(safe-area-inset-top);padding-bottom:env(safe-area-inset-bottom)}body{margin:0;font:14px system-ui;background:#fafafa}img{max-width:100%}[hidden]{display:none!important}</style></head><body>' + out + '</body></html>';
  writeFileSync(join(ROOT, 'dist/preview.html'), preview);
  // The same standalone page is what GitHub Pages serves (docs/ is the Pages folder).
  mkdirSync(join(ROOT, 'docs'), { recursive: true });
  writeFileSync(join(ROOT, 'docs/index.html'), preview);
  const kb = (Buffer.byteLength(out) / 1024).toFixed(0);
  console.log(`dist/index.html ${kb} KB (${ORDER.length} scripts)`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) build();
