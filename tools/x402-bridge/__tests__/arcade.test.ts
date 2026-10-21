/**
 * The bridge broadcasts through ARCADE, the project's own rail, not a
 * third-party ARC. ARCADE takes the transaction in extended format as raw
 * bytes at POST <base>/tx, and answers 202 with a body whose `txStatus` is
 * the verdict. The HTTP status is not the verdict: a 200 with
 * `txStatus: "REJECTED"` is a refusal, and a 202 with `SEEN_ON_NETWORK` is an
 * acceptance. These tests hold the client to that contract with a fetch
 * double; nothing here touches the network.
 */
import { afterEach, describe, expect, test } from 'bun:test';
import { P2PKH, PrivateKey, Transaction, Utils } from '@bsv/sdk';

import { DEFAULT_ARCADE_URL, broadcastTxHex } from '../arc';

type Call = { url: string; method: string; contentType: string | null; body: Uint8Array };

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
});

/** Install a fetch double that records the request and answers `status` with `body`. */
function answerWith(status: number, body: string | object): Call[] {
  const calls: Call[] = [];
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const headers = new Headers(init?.headers);
    const raw = init?.body;
    const bytes =
      raw instanceof Uint8Array ? raw
      : raw instanceof ArrayBuffer ? new Uint8Array(raw)
      : typeof raw === 'string' ? new TextEncoder().encode(raw)
      : new Uint8Array();
    calls.push({ url: String(input), method: init?.method ?? 'GET', contentType: headers.get('content-type'), body: bytes });
    const text = typeof body === 'string' ? body : JSON.stringify(body);
    return new Response(text, { status, headers: { 'content-type': 'application/json' } });
  }) as typeof fetch;
  return calls;
}

/** A two-transaction chain: a funding tx, and a spend that knows its source, so BEEF and EF both serialize. */
function spendWithAncestry(): Transaction {
  const key = PrivateKey.fromRandom();
  const funding = new Transaction();
  funding.addOutput({ lockingScript: new P2PKH().lock(key.toPublicKey().toHash()), satoshis: 10_000 });
  const spend = new Transaction();
  spend.addInput({ sourceTransaction: funding, sourceOutputIndex: 0, unlockingScriptTemplate: new P2PKH().unlock(key) });
  spend.addOutput({ lockingScript: new P2PKH().lock(key.toPublicKey().toHash()), satoshis: 9_000 });
  return spend;
}

describe('the bridge broadcasts to ARCADE, in extended format, judged by txStatus', () => {
  test('the default rail is ARCADE, not a third-party ARC', () => {
    expect(DEFAULT_ARCADE_URL).toBe('https://arcade.gorillapool.io');
  });

  test('a BEEF transaction goes to POST <base>/tx as raw EF bytes', async () => {
    const spend = spendWithAncestry();
    await spend.sign();
    const calls = answerWith(202, { txid: spend.id('hex'), status: 202, txStatus: 'RECEIVED' });

    const r = await broadcastTxHex(spend.toHexBEEF(), { arcUrl: 'https://rail.example/' });

    expect(r).toEqual({ ok: true, txid: spend.id('hex') });
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe('https://rail.example/tx');
    expect(calls[0]!.method).toBe('POST');
    expect(calls[0]!.contentType).toBe('application/octet-stream');
    expect(Utils.toHex(Array.from(calls[0]!.body))).toBe(spend.toHexEF());
  });

  test('a 200 whose txStatus is REJECTED is a refusal, and the reason carries ARCADE\'s detail', async () => {
    const spend = spendWithAncestry();
    await spend.sign();
    answerWith(200, { txid: spend.id('hex'), txStatus: 'REJECTED', error: 'transaction failed validation', detail: 'fee too low' });

    const r = await broadcastTxHex(spend.toHexBEEF());

    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain('fee too low');
  });

  test('a 400 with no txid is a refusal that names the error', async () => {
    const spend = spendWithAncestry();
    await spend.sign();
    answerWith(400, { error: 'transaction failed validation', detail: 'Missing input scripts' });

    const r = await broadcastTxHex(spend.toHexBEEF());

    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain('Missing input scripts');
  });

  test('an unreadable reply is a refusal, not a crash', async () => {
    const spend = spendWithAncestry();
    await spend.sign();
    answerWith(502, '<html>bad gateway</html>');

    const r = await broadcastTxHex(spend.toHexBEEF());

    expect(r.ok).toBe(false);
  });

  test('raw hex without ancestry is sent as given, since EF needs the source outputs', async () => {
    const spend = spendWithAncestry();
    await spend.sign();
    const rawHex = spend.toHex();
    const calls = answerWith(400, { error: 'transaction failed validation', detail: 'could not be transformed to extended format' });

    const r = await broadcastTxHex(rawHex);

    expect(calls).toHaveLength(1);
    expect(Utils.toHex(Array.from(calls[0]!.body))).toBe(rawHex);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain('extended format');
  });

  test('garbage is refused before any request is made', async () => {
    const calls = answerWith(202, {});
    const r = await broadcastTxHex('zz');
    expect(r.ok).toBe(false);
    expect(calls).toHaveLength(0);
  });
});
