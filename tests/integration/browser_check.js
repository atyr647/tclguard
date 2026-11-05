// Drives a real Chromium (Playwright) through a running TclGuard and prints one JSON line per check:
//   node browser_check.js '{"phase":"basic","port":8080}'
// phases: basic (page, 30 parallel keep-alive fetches, WebSocket, 5 MB upload), challenge (the cookie challenge a browser follows by itself), tls (HTTPS with the guard's own certificate)
const { chromium } = require('playwright');
const cfg = JSON.parse(process.argv[2]);
const out = (name, ok, detail) => console.log(JSON.stringify({ name, ok: !!ok, detail: String(detail === undefined ? '' : detail).slice(0, 300) }));
(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await ctx.newPage();
  const base = (cfg.phase === 'tls' ? 'https' : 'http') + '://127.0.0.1:' + cfg.port;
  try {
    const resp = await page.goto(base + '/hello', { timeout: 20000 });
    const body = await page.evaluate(() => document.body.innerText);
    if (cfg.phase === 'challenge') {
      const cookies = await ctx.cookies();
      out('a browser follows the challenge redirect by itself and is served', resp.status() === 200 && /ok:GET \/hello/.test(body), 'status ' + resp.status() + ' body ' + body);
      out('...and keeps the challenge cookie', cookies.some(c => c.name === 'tg_ok'), JSON.stringify(cookies.map(c => c.name)));
      const again = await page.evaluate(async () => { const r = await fetch('/again', { redirect: 'manual' }); return [r.type, r.status]; });
      out('...and later requests are served without a new challenge', again[0] === 'basic' && again[1] === 200, JSON.stringify(again));
    } else {
      out('page loads through the guard' + (cfg.phase === 'tls' ? ' over HTTPS' : ''), resp.status() === 200 && /ok:GET \/hello/.test(body), 'status ' + resp.status() + ' body ' + body);
    }
    if (cfg.phase === 'basic' || cfg.phase === 'tls') {
      const codes = await page.evaluate(async () => (await Promise.all(Array.from({ length: 30 }, (_, i) => fetch('/r' + i).then(r => r.status))))) ;
      out('30 parallel fetches all served', codes.length === 30 && codes.every(c => c === 200), JSON.stringify(codes.filter(c => c !== 200)));
      const up = await page.evaluate(async () => { const b = new Uint8Array(5 * 1024 * 1024); for (let i = 0; i < b.length; i += 4096) b[i] = i & 255; const r = await fetch('/up', { method: 'POST', body: b }); return [r.status, await r.text()]; });
      out('a 5 MB upload from the browser is served', up[0] === 200 && /ok:POST \/up HTTP\/1\.1:5242880/.test(up[1]), JSON.stringify(up));
    }
    if (cfg.phase === 'basic') {
      const ws = await page.evaluate(() => new Promise(res => {
        const s = new WebSocket('ws://127.0.0.1:' + location.port + '/ws'); const t = setTimeout(() => res('timeout'), 8000);
        s.onopen = () => s.send('hi'); s.onmessage = e => { clearTimeout(t); res(String(e.data)); s.close(); }; s.onerror = () => { clearTimeout(t); res('error'); };
      }));
      out('a browser WebSocket works through the guard', ws === 'echo:hi', ws);
    }
  } catch (e) { out('browser phase ' + cfg.phase + ' ran without an exception', false, e.message); }
  await browser.close();
})();
