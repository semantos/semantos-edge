/**
 * light.ts — the bridge's HTTP surface, plus a phone page that pays it.
 *
 *   GET  /, /light               the "turn the light on" page (same origin,
 *                                so the page itself needs no CORS)
 *   GET  /light.js               its client, bundled from web/light-client.ts
 *   GET  /.well-known/x402-info  free discovery (price, payTo)
 *   POST /actuator/activate      402 challenge → pay → queued activation;
 *                                ?async=1 answers 202 + ticket at once
 *   GET  /queue[?ticket=<txid>]  where a ticket is in the queue
 *   OPTIONS *                    CORS preflight (204)
 *
 * Every answer carries CORS headers and exposes the x-bsv-payment-* headers,
 * so an agent on another origin can read the 402 challenge too.
 */

import { join } from 'node:path';
import type { X402CellBridge, BridgeResponse } from './bridge.js';

const CORS: Record<string, string> = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, POST, OPTIONS',
  'access-control-allow-headers': 'content-type, x-bsv-payment',
  'access-control-expose-headers': [
    'x-bsv-payment-version',
    'x-bsv-payment-satoshis-required',
    'x-bsv-payment-derivation-prefix',
    'x-bsv-payment-transports',
    'x-bsv-payment-satoshis-paid',
    'x-bsv-payment-txid',
  ].join(', '),
  'access-control-max-age': '600',
};

export interface LightHandlerOptions {
  /** The bundled client script. Default: buildLightClient(). */
  clientJs?: () => Promise<string>;
}

let clientCache: Promise<string> | undefined;

/** Bundle web/light-client.ts (+ @bsv/sdk) for the browser, once. */
export function buildLightClient(): Promise<string> {
  clientCache ??= (async () => {
    const r = await Bun.build({
      entrypoints: [join(import.meta.dir, 'web', 'light-client.ts')],
      target: 'browser',
      minify: true,
    });
    if (!r.success || r.outputs.length === 0) {
      clientCache = undefined;
      throw new Error(`light client build failed: ${r.logs.map((l) => String(l)).join('; ')}`);
    }
    return r.outputs[0].text();
  })();
  return clientCache;
}

function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...CORS, ...headers },
  });
}

function send(r: BridgeResponse): Response {
  return json(r.status, r.body, r.headers);
}

/** The payment: the x-bsv-payment header, or (for big txs) a JSON body. */
async function paymentFrom(req: Request): Promise<string | null> {
  const h = req.headers.get('x-bsv-payment');
  if (h) return h;
  const text = await req.text().catch(() => '');
  if (!text.trim()) return null;
  try {
    const obj = JSON.parse(text);
    if (obj && typeof obj === 'object') {
      const inner = (obj as Record<string, unknown>)['x-bsv-payment'];
      if (typeof inner === 'string') return inner;
      if ('transaction' in obj) return JSON.stringify(obj);
    }
  } catch { /* not JSON — treat as no payment */ }
  return null;
}

export function makeLightHandler(bridge: X402CellBridge, opts: LightHandlerOptions = {}) {
  const clientJs = opts.clientJs ?? buildLightClient;
  const price = (bridge.discover().body as { offer: { costSats: number; durationMs: number } }).offer;
  const html = pageHtml(price.costSats, price.durationMs);
  let gz: { src: string; bytes: Uint8Array } | undefined;

  return async function handle(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const path = url.pathname;
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });

    if (req.method === 'GET' && (path === '/' || path === '/light' || path === '/light/')) {
      return new Response(html, { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', ...CORS } });
    }
    if (req.method === 'GET' && path === '/light.js') {
      try {
        const js = await clientJs();
        const headers: Record<string, string> = {
          'content-type': 'text/javascript; charset=utf-8', 'cache-control': 'no-store', vary: 'accept-encoding', ...CORS,
        };
        // ~900 KB with @bsv/sdk inside; gzip takes it to a fraction for phones.
        if ((req.headers.get('accept-encoding') ?? '').includes('gzip')) {
          if (gz?.src !== js) gz = { src: js, bytes: Bun.gzipSync(js) };
          return new Response(gz.bytes, { headers: { ...headers, 'content-encoding': 'gzip' } });
        }
        return new Response(js, { headers });
      } catch (e) {
        return json(500, { error: (e as Error).message });
      }
    }
    if (req.method === 'GET' && path === '/.well-known/x402-info') return send(bridge.discover());
    if (req.method === 'GET' && path === '/queue') return json(200, bridge.queueStatus(url.searchParams.get('ticket')));
    if (req.method === 'POST' && path === '/actuator/activate') {
      const isAsync = ['1', 'true', 'yes'].includes(url.searchParams.get('async') ?? '');
      return send(await bridge.activate(await paymentFrom(req), { async: isAsync }));
    }
    return json(404, { error: 'not found' });
  };
}

function pageHtml(sats: number, durationMs: number): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Turn the light on</title>
<style>
  :root { --bg:#0e0f12; --fg:#f3f1ea; --muted:#9a978e; --accent:#ffd23f; --ok:#5fd38d; --err:#ff6b6b; }
  * { box-sizing:border-box; }
  html,body { margin:0; background:var(--bg); color:var(--fg);
    font:17px/1.4 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
  main { max-width:480px; margin:0 auto; padding:32px 16px; min-height:100svh;
    display:flex; flex-direction:column; gap:20px; justify-content:center; }
  h1 { font-size:26px; margin:0; }
  p.lede { margin:0; color:var(--muted); }
  button { width:100%; min-height:96px; border:0; border-radius:20px; background:var(--accent);
    color:#1a1600; font-size:24px; font-weight:700; padding:16px; cursor:pointer;
    -webkit-tap-highlight-color:transparent; }
  button:active { transform:scale(.98); }
  button:disabled { opacity:.5; }
  #status { font-size:22px; font-weight:600; min-height:1.4em; margin:0; }
  #status.ok { color:var(--ok); font-size:34px; }
  #status.err { color:var(--err); }
  #detail { margin:0; color:var(--muted); word-break:break-word; min-height:1.4em; }
</style>
</head>
<body>
<main>
  <h1>Turn the light on</h1>
  <p class="lede">Pay ${sats} sats from your wallet and the board on stage lights for ${Math.round(durationMs / 1000)} seconds. One at a time — you'll see your place in the queue.</p>
  <button id="go" type="button" data-sats="${sats}">Turn the light on — ${sats} sats</button>
  <p id="status" aria-live="polite">Ready.</p>
  <p id="detail"></p>
</main>
<script src="/light.js"></script>
</body>
</html>
`;
}
