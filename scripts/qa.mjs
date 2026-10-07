// Renders dist/preview.html in headless Chrome for every scenario / viewport / theme,
// saves full-page screenshots to /tmp/playwright/war-room/, and reports console errors,
// page errors and horizontal overflow as JSON. Usage:
//   node scripts/qa.mjs                 -> full matrix
//   node scripts/qa.mjs --quick         -> scenario 1 only, desktop+phone, light+dark
//   node scripts/qa.mjs --only cert-expiry
import { createServer } from 'node:http';
import { readFileSync, mkdirSync, existsSync, readdirSync, unlinkSync } from 'node:fs';
import { join, dirname, extname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const OUT = '/tmp/playwright/war-room';
mkdirSync(OUT, { recursive: true });

const args = process.argv.slice(2);
const quick = args.includes('--quick');
const only = args.includes('--only') ? args[args.indexOf('--only') + 1] : null;

const SCENARIOS = ['bad-deploy-oom', 'coredns-outage', 'cert-expiry', 'db-conn-exhaustion', 'blank'];
const VIEWPORTS = { desktop: { width: 1440, height: 900 }, phone: { width: 390, height: 844 } };
const THEMES = ['light', 'dark'];

const server = createServer((req, res) => {
  const path = join(ROOT, 'dist', decodeURIComponent(new URL(req.url, 'http://x').pathname));
  if (!existsSync(path) || !path.startsWith(join(ROOT, 'dist'))) { res.writeHead(404); return res.end(); }
  res.writeHead(200, { 'content-type': extname(path) === '.html' ? 'text/html; charset=utf-8' : 'application/octet-stream' });
  res.end(readFileSync(path));
}).listen(0, '127.0.0.1');
await new Promise((r) => server.once('listening', r));
const base = `http://127.0.0.1:${server.address().port}/preview.html`;

const browser = await chromium.launch({
  executablePath: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  headless: true,
});

const matrix = [];
for (const s of SCENARIOS) {
  if (only && s !== only) continue;
  for (const [vp, size] of Object.entries(VIEWPORTS)) {
    for (const theme of THEMES) {
      const full = s === 'bad-deploy-oom' || (vp === 'desktop' && theme === 'light');
      if (quick && s !== 'bad-deploy-oom') continue;
      if (!full && !only) continue;
      matrix.push({ s, vp, size, theme });
    }
  }
}

const report = [];
for (const { s, vp, size, theme } of matrix) {
  const ctx = await browser.newContext({ viewport: size, colorScheme: theme, deviceScaleFactor: vp === 'phone' ? 2 : 1 });
  const page = await ctx.newPage();
  const errors = [];
  page.on('console', (m) => { if (m.type() === 'error' || m.type() === 'warning') errors.push(`${m.type()}: ${m.text()}`); });
  page.on('pageerror', (e) => errors.push('pageerror: ' + e.message));
  page.on('requestfailed', (r) => errors.push('requestfailed: ' + r.url()));
  const t0 = Date.now();
  await page.goto(`${base}#sample-${s}`, { waitUntil: 'load' });
  await page.waitForTimeout(1200); // fonts + debounce + first analysis
  const metrics = await page.evaluate(() => {
    const se = document.scrollingElement;
    const wide = [...document.querySelectorAll('body *')].filter((el) => {
      const r = el.getBoundingClientRect();
      return r.right > innerWidth + 1 && getComputedStyle(el).position !== 'fixed' && !el.closest('[data-scroll-x]');
    }).slice(0, 5).map((el) => `${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}.${[...el.classList].join('.')}`);
    return {
      overflowX: se.scrollWidth > innerWidth + 1, scrollWidth: se.scrollWidth, innerWidth,
      height: se.scrollHeight, wideElements: wide,
      title: document.title,
      mapNodes: document.querySelectorAll('#map svg [data-component]').length,
      causes: document.querySelectorAll('#causes [data-hypothesis]').length,
      rollbacks: document.querySelectorAll('#rollback [data-rollback]').length,
    };
  });
  // Chrome cannot capture more than 16,384 device pixels in one image: past that the page repeats
  // from the top. Tall pages are saved in parts: <name>.png is the top, then <name>--part2.png, ...
  const name = `${s}--${vp}--${theme}`;
  for (const f of readdirSync(OUT)) if (f.startsWith(name + '--part') && f.endsWith('.png')) unlinkSync(join(OUT, f));
  const dpr = vp === 'phone' ? 2 : 1;
  const partH = Math.floor(16000 / dpr);
  const files = [];
  for (let y = 0, i = 1; y < metrics.height; y += partH, i++) {
    const file = join(OUT, i === 1 ? `${name}.png` : `${name}--part${i}.png`);
    await page.screenshot({ path: file, fullPage: true, clip: { x: 0, y, width: size.width, height: Math.min(partH, metrics.height - y) } });
    files.push(file);
  }
  report.push({ scenario: s, viewport: vp, theme, ms: Date.now() - t0, file: files[0], parts: files.length, errors, ...metrics });
  await ctx.close();
}
await browser.close();
server.close();
console.log(JSON.stringify(report, null, 1));
const bad = report.filter((r) => r.errors.length || r.overflowX);
if (bad.length) { console.error(`\n${bad.length} run(s) with errors or horizontal overflow`); process.exitCode = 1; }
