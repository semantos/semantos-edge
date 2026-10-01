/**
 * light-client.ts — the phone side of "turn the light on".
 *
 * Runs inside a BRC-100 wallet browser (BSV Browser injects window.CWI).
 * Tap → read the price + pay-to script from /.well-known/x402-info → the
 * wallet's createAction pays it (the wallet broadcasts) → hand the signed tx
 * to POST /actuator/activate?async=1 → poll /queue until the board lights.
 *
 * Bundled for the browser by light.ts (Bun.build) at server start.
 */
import { WalletClient, Transaction, Utils } from '@bsv/sdk';

type Wallet = {
  createAction(args: unknown, originator?: string): Promise<{ txid?: string; tx?: number[] | Uint8Array }>;
};

const $ = (id: string) => document.getElementById(id)!;
// Blink mode has one #go button; metered mode has one .amt button per amount.
const buttons = Array.from(document.querySelectorAll<HTMLButtonElement>('#go, button.amt'));
const btn = buttons[0];
const setBusy = (busy: boolean) => { for (const b of buttons) b.disabled = busy; };
const statusEl = $('status');
const detailEl = $('detail');
const STORE = 'light.ticket';

function say(text: string, kind: 'info' | 'ok' | 'err' = 'info', detail = ''): void {
  statusEl.textContent = text;
  statusEl.className = kind;
  detailEl.textContent = detail;
}

function remember(ticket: string | null): void {
  try {
    if (ticket) localStorage.setItem(STORE, ticket);
    else localStorage.removeItem(STORE);
  } catch { /* private mode — fine */ }
}

/**
 * Prefer the injected wallet. WalletClient('auto') probes every substrate and
 * waits for all of them, so a stalled localhost probe on a phone can hide a
 * working window.CWI for a long time.
 */
function wallet(): Wallet {
  const cwi = (window as unknown as { CWI?: Wallet }).CWI;
  if (cwi && typeof cwi.createAction === 'function') return cwi;
  return new WalletClient('auto', location.hostname) as unknown as Wallet;
}

function withTimeout<T>(p: Promise<T>, ms: number, what: string): Promise<T> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`${what} did not answer within ${Math.round(ms / 1000)} s`)), ms);
    p.then((v) => { clearTimeout(t); resolve(v); }, (e) => { clearTimeout(t); reject(e); });
  });
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Turn whatever the wallet returned into raw tx hex (the bridge parses raw or BEEF). */
function txHex(tx: number[] | Uint8Array): string {
  const bytes = Array.from(tx);
  try {
    return Transaction.fromAtomicBEEF(bytes).toHex();
  } catch {
    try {
      return Transaction.fromBEEF(bytes).toHex();
    } catch {
      return Utils.toHex(bytes); // let the bridge try
    }
  }
}

async function poll(ticket: string): Promise<void> {
  for (;;) {
    let q: { state: string; ahead: number; litAt?: string; error?: string; message?: string };
    try {
      const r = await fetch(`/queue?ticket=${encodeURIComponent(ticket)}`, { cache: 'no-store' });
      q = await r.json();
    } catch {
      say('Waiting for the board… (connection blip, retrying)');
      await sleep(1500);
      continue;
    }
    if (q.state === 'lit') {
      const at = q.litAt ? new Date(q.litAt).toLocaleTimeString() : '';
      say('LIT ✓', 'ok', `Your payment turned the light on${at ? ` at ${at}` : ''}. txid ${ticket.slice(0, 16)}…`);
      remember(null);
      setBusy(false);
      if (btn.id === 'go') btn.textContent = `Again — ${btn.dataset.sats ?? ''} sats`;
      if (q.message) say('LIT \u2713', 'ok', `${q.message}. txid ${ticket.slice(0, 16)}…`);
      return;
    }
    if (q.state === 'failed') {
      say('The board did not light', 'err', q.error ?? 'unknown error');
      remember(null);
      setBusy(false);
      return;
    }
    if (q.state === 'unknown') {
      say('The bridge has forgotten this payment', 'err', 'It may have restarted. Tell the speaker.');
      remember(null);
      setBusy(false);
      return;
    }
    if (q.state === 'lighting') say('Lighting now — look at the board!');
    else say(`Queued — ${q.ahead} ahead of you`, 'info', 'Keep this page open.');
    await sleep(1000);
  }
}

async function go(chosen?: number): Promise<void> {
  setBusy(true);
  try {
    say('Reading the price…');
    const info = await (await fetch('/.well-known/x402-info', { cache: 'no-store' })).json();
    const payTo = info.payTo as { scriptHex: string; satoshis: number } | undefined;
    if (!payTo) throw new Error('the bridge is not taking real payments (no payTo) — it is in dry-run');
    const sats = chosen ?? payTo.satoshis;

    say('Approve the payment in your wallet…', 'info', `${sats} sats`);
    const res = await withTimeout(
      wallet().createAction({
        description: 'turn the light on',
        outputs: [{ lockingScript: payTo.scriptHex, satoshis: sats, outputDescription: 'light the C6 board' }],
      }),
      90_000,
      'the wallet',
    );
    if (!res || !res.tx) throw new Error(`the wallet returned no transaction${res?.txid ? ` (txid ${res.txid})` : ''}`);
    const hex = txHex(res.tx);

    say('Paid — sending to the board…');
    const payment = JSON.stringify({ transaction: hex });
    // Big transactions go in the body; headers have size limits on the way in.
    const init: RequestInit = payment.length <= 6000
      ? { method: 'POST', headers: { 'x-bsv-payment': payment } }
      : { method: 'POST', headers: { 'content-type': 'application/json' }, body: payment };
    const r = await fetch(`/actuator/activate?async=1${chosen ? `&sats=${chosen}` : ''}`, init);
    const body = await r.json().catch(() => ({}));
    if (r.status !== 202 && r.status !== 200) {
      throw new Error(`${r.status}: ${body.error ?? r.statusText}`);
    }
    const ticket: string = body.ticket ?? body.txid;
    remember(ticket);
    say(body.ahead > 0 ? `Queued — ${body.ahead} ahead of you` : 'You are next…');
    await poll(ticket);
  } catch (e) {
    const msg = e instanceof Error ? e.message : typeof e === 'string' ? e : JSON.stringify(e);
    say('Something went wrong', 'err', msg);
    setBusy(false);
  }
}

for (const b of buttons) {
  b.addEventListener('click', () => { void go(b.classList.contains('amt') ? Number(b.dataset.sats) : undefined); });
}

// Metered: everyone sees the seconds the room has bought, from the bridge's tally.
const meterEl = document.getElementById('meter');
if (meterEl) {
  const tick = async () => {
    try {
      const m = await (await fetch('/meter', { cache: 'no-store' })).json();
      if (m.metered) {
        const left = Math.floor(m.secondsLeft);
        meterEl.textContent = left > 0 ? `Light: ON — ${left} s left` : 'Light: off — pay to turn it on';
        meterEl.className = left > 0 ? 'on' : '';
      }
    } catch { /* blip */ }
  };
  void tick();
  setInterval(() => { void tick(); }, 1000);
}

// Came back to the page mid-queue? Pick the ticket up again.
let saved: string | null = null;
try { saved = localStorage.getItem(STORE); } catch { /* ignore */ }
if (saved) {
  setBusy(true);
  say('Checking on your earlier payment…');
  void poll(saved);
}
