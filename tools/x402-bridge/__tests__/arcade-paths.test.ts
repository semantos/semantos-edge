/**
 * Every path that broadcasts must hand ARCADE the transaction in extended
 * format (BRC-30 EF): each input carries its source output. ARCADE refuses a
 * raw transaction ("Missing input scripts"), where the third-party ARC the
 * bridge used before accepted one. These tests follow each path from what it
 * starts with to the bytes that reach the rail, with a fetch double; nothing
 * touches the network.
 */
import { afterEach, describe, expect, test } from 'bun:test';
import { P2PKH, PrivateKey, Transaction, Utils } from '@bsv/sdk';

import { X402CellBridge, type MeshPort } from '../bridge.js';
import { type ActuatorOffer, sha256 } from '../cell-codec.js';
import { settleChannel, type ChannelState } from '../channel-anchor.js';
import { makeLightHandler } from '../light.js';
import { Brc29OnchainVerifier } from '../onchain-payment.js';
import { walletTxHex } from '../web/wallet-tx.js';

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
});

/** A fetch double that accepts every broadcast and records the bytes it was sent. */
function arcadeAccepts(txid: string): Uint8Array[] {
  const bodies: Uint8Array[] = [];
  globalThis.fetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
    const raw = init?.body;
    bodies.push(raw instanceof Uint8Array ? raw : new Uint8Array(raw as ArrayBuffer));
    return new Response(JSON.stringify({ txid, status: 202, txStatus: 'RECEIVED' }), { status: 202 });
  }) as typeof fetch;
  return bodies;
}

const RECEIVE_ADDR = PrivateKey.fromRandom().toPublicKey().toAddress();
const RECEIVE_SCRIPT = new P2PKH().lock(RECEIVE_ADDR).toHex();
const WALLET = new PrivateKey('0000000000000000000000000000000000000000000000000000000000000042', 16);
const WP = new Uint8Array(Buffer.from(WALLET.toPublicKey().toString(), 'hex'));
const LOCK = (() => { const b = new Uint8Array(35); b[0] = 0x21; b.set(WP, 1); b[34] = 0xac; return b; })();
const OFFER: ActuatorOffer = {
  version: 1, costSats: 100, durationMs: 5000, lockScript: LOCK,
  txTemplate: new Uint8Array([1, 0, 0, 0, 0, 0, 0, 0, 0, 0]), inputIdx: 0, inputValue: 50000n,
  offerId: sha256(new TextEncoder().encode('cellmesh.rentable-device.offer.v0')).slice(0, 16),
};
const quietMesh: MeshPort = { async broadcast() {}, async awaitActivation() { return true; } };

/** What a BRC-100 wallet's createAction hands back: Atomic BEEF of a signed payment, ancestry included. */
async function walletPayment(): Promise<{ atomic: number[]; spend: Transaction }> {
  const payer = PrivateKey.fromRandom();
  const funding = new Transaction();
  funding.addOutput({ lockingScript: new P2PKH().lock(payer.toPublicKey().toHash()), satoshis: 5_000 });
  const spend = new Transaction();
  spend.addInput({ sourceTransaction: funding, sourceOutputIndex: 0, unlockingScriptTemplate: new P2PKH().unlock(payer) });
  spend.addOutput({ lockingScript: new P2PKH().lock(RECEIVE_ADDR), satoshis: 100 });
  spend.addOutput({ lockingScript: new P2PKH().lock(payer.toPublicKey().toHash()), satoshis: 4_800 });
  await spend.sign();
  return { atomic: spend.toAtomicBEEF(), spend };
}

describe('the light page: wallet → bridge → ARCADE', () => {
  test('the page sends the wallet\'s transaction with its ancestry, not as raw hex', async () => {
    const { atomic, spend } = await walletPayment();
    const hex = walletTxHex(atomic);
    const back = Transaction.fromHexBEEF(hex);
    expect(back.id('hex')).toBe(spend.id('hex'));
    expect(Utils.toHex(back.toEF())).toBe(spend.toHexEF());
  });

  test('in broadcast mode the bridge hands ARCADE the payment as EF', async () => {
    const { atomic, spend } = await walletPayment();
    const bodies = arcadeAccepts(spend.id('hex'));
    const bridge = new X402CellBridge({
      offer: OFFER,
      walletKey: WALLET,
      mesh: quietMesh,
      verifier: new Brc29OnchainVerifier(RECEIVE_SCRIPT, { maxSats: 500 }),
      receiveScriptHex: RECEIVE_SCRIPT,
      holdMs: 0,
      broadcastOnVerify: true,
      arc: { arcUrl: 'https://rail.example' },
    });
    const handler = makeLightHandler(bridge, { clientJs: async () => '' });

    const res = await handler(new Request('http://bridge.test/actuator/activate', {
      method: 'POST',
      headers: { 'x-bsv-payment': JSON.stringify({ transaction: walletTxHex(atomic) }) },
    }));

    expect(res.status).toBe(200);
    expect(bodies).toHaveLength(1);
    expect(Utils.toHex(Array.from(bodies[0]!))).toBe(spend.toHexEF());
  });
});

describe('the channel settle → ARCADE', () => {
  test('the settlement goes out as EF, its input carrying the funding output the state records', async () => {
    const lockHex = new P2PKH().lock(WALLET.toPublicKey().toHash()).toHex();
    const state: ChannelState = {
      txid: 'ab'.repeat(32),
      vout: 1,
      fundingSats: 10_000,
      channelId: new Uint8Array(16),
      fundingLockHex: lockHex,
      refundTxHex: '',
      openedAtMs: 0,
      deviceShareAccum: 1_000,
      userShareAccum: 0,
      finalSeq: 0,
      settled: false,
    };
    const bodies = arcadeAccepts('cd'.repeat(32));

    const txid = await settleChannel(state, WALLET, { arcUrl: 'https://rail.example' });

    expect(txid).toBe('cd'.repeat(32));
    expect(bodies).toHaveLength(1);
    const ef = Transaction.fromEF(Array.from(bodies[0]!));
    const input = ef.inputs[0]!;
    expect(input.sourceTXID).toBe(state.txid);
    expect(input.sourceOutputIndex).toBe(state.vout);
    expect(input.sourceTransaction!.outputs[state.vout]!.satoshis).toBe(state.fundingSats);
    expect(input.sourceTransaction!.outputs[state.vout]!.lockingScript.toHex()).toBe(lockHex);
    expect(ef.outputs.map((o) => o.satoshis)).toEqual([1_000, 10_000 - 1_000 - 200]);
  });
});
