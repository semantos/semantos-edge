/**
 * bridge.ts — the HTTP↔cell x402 bridge orchestrator.
 *
 * A Dolphin Milk-style agent pays this bridge over BSV-native x402; once
 * paid, the bridge actuates a rentable cell-mesh device by broadcasting a
 * wallet-signed actuator_activate.v0 cell and waiting for the device's
 * "*** ACTUATOR ACTIVATED ***" acknowledgement.
 *
 *   agent                         bridge (this)                 C6 device
 *   ─────                         ─────────────                 ─────────
 *   GET /.well-known/x402-info ─► manifest (price = offer.cost)
 *   POST /actuator/activate    ─► 402 + x-bsv-payment-* headers
 *   (build BRC-29 payment)
 *   POST + x-bsv-payment       ─► verify payment
 *                                 build actuator_activate.v0
 *                                 broadcast ───────────────────► verify sig,
 *                                                                run cell-engine,
 *                                 ◄─────────────────────────────  ACTUATOR ACTIVATED
 *                                 200 + receipt
 *
 * The crypto vocabulary is identical on both legs — the same wallet signs
 * the BSV-script unlock the device's cell-engine checks. The bridge is a
 * transport adapter (plus it fronts the payment: the agent pays the
 * bridge; the bridge pays the device's lock).
 */

import { PrivateKey } from '@bsv/sdk';
import { randomBytes } from 'node:crypto';
import {
  type ActuatorOffer,
  buildActuatorActivate,
} from './cell-codec.js';
import {
  buildChallengeHeaders,
  parsePaymentHeader,
  DefaultPaymentVerifier,
  type PaymentVerifier,
} from './x402.js';
import { broadcastTxHex, type ArcOptions } from './arc.js';

/** A transport to the cell mesh — broadcast a signed cell, await device ACK. */
export interface MeshPort {
  /** Broadcast a full 1024-byte cell + its 64-byte frame sig. */
  broadcast(cell: Uint8Array, sig: Uint8Array): Promise<void>;
  /**
   * Resolve true when the device acknowledges activation of `offerId`
   * within `timeoutMs` (e.g. by reading "*** ACTUATOR ACTIVATED ***" off
   * the device's USB-CDC), false on timeout.
   */
  awaitActivation(offerId: Uint8Array, timeoutMs: number): Promise<boolean>;
}

export interface BridgeConfig {
  /** The rentable device's provisioned offer terms (what it broadcasts). */
  offer: ActuatorOffer;
  /** Wallet that signs the actuator unlock (same identity as sign-cell-deck). */
  walletKey: PrivateKey;
  mesh: MeshPort;
  /** How long to wait for the device ACK after broadcasting. Default 8000. */
  activationTimeoutMs?: number;
  /** Payment verifier. Default checks amount + funded output. */
  verifier?: PaymentVerifier;
  /** Service name for the discovery manifest. */
  serviceName?: string;
  /**
   * REAL-PAYMENT mode: the P2PKH (or other) locking-script hex the payer
   * must pay (a Metanet-Desktop-derived, recoverable receive key). Advertised
   * in discovery + the 402 so the agent funds the right output.
   */
  receiveScriptHex?: string;
  /**
   * If set, the bridge broadcasts the payer's (signed, un-broadcast) tx to
   * chain via ARC on successful verify and returns that network txid — the
   * same path that anchored the MNCA cell. If false, the bridge trusts the
   * verifier-derived txid (the payer already broadcast).
   */
  broadcastOnVerify?: boolean;
  arc?: ArcOptions;
}

export interface BridgeResponse {
  status: number;
  headers: Record<string, string>;
  body: unknown;
}

const toHex = (b: Uint8Array) => Buffer.from(b).toString('hex');

export class X402CellBridge {
  private readonly offer: ActuatorOffer;
  private readonly walletKey: PrivateKey;
  private readonly mesh: MeshPort;
  private readonly timeoutMs: number;
  private readonly verifier: PaymentVerifier;
  private readonly serviceName: string;
  private readonly ownerId: Uint8Array;
  private readonly receiveScriptHex?: string;
  private readonly broadcastOnVerify: boolean;
  private readonly arc?: ArcOptions;
  private counter = 0;

  constructor(cfg: BridgeConfig) {
    this.offer = cfg.offer;
    this.walletKey = cfg.walletKey;
    this.mesh = cfg.mesh;
    this.timeoutMs = cfg.activationTimeoutMs ?? 8000;
    this.verifier = cfg.verifier ?? new DefaultPaymentVerifier();
    this.serviceName = cfg.serviceName ?? 'cellmesh-actuator';
    this.receiveScriptHex = cfg.receiveScriptHex;
    this.broadcastOnVerify = cfg.broadcastOnVerify ?? false;
    this.arc = cfg.arc;
    // owner_id tag = first 16 bytes of the compressed wallet pubkey.
    this.ownerId = new Uint8Array(Buffer.from(this.walletKey.toPublicKey().toString(), 'hex')).subarray(0, 16);
  }

  /** GET /.well-known/x402-info — free discovery of the service + price. */
  discover(): BridgeResponse {
    return {
      status: 200,
      headers: { 'content-type': 'application/json' },
      body: {
        service: this.serviceName,
        protocol: 'bsv-x402',
        version: '1.0',
        endpoints: [
          {
            path: '/actuator/activate',
            method: 'POST',
            description: `Activate the rentable device for ${this.offer.durationMs} ms`,
            price: { satoshis: this.offer.costSats, asset: 'BSV' },
            input: {},
          },
        ],
        offer: {
          offerId: toHex(this.offer.offerId),
          costSats: this.offer.costSats,
          durationMs: this.offer.durationMs,
          lockScriptHex: toHex(this.offer.lockScript),
        },
        ...(this.receiveScriptHex
          ? { payTo: { scriptHex: this.receiveScriptHex, satoshis: this.offer.costSats, network: 'mainnet' } }
          : {}),
      },
    };
  }

  /**
   * POST /actuator/activate. With no `x-bsv-payment` header → 402 challenge.
   * With a valid payment → verify, actuate over the mesh, 200 + receipt.
   */
  async activate(paymentHeader: string | null | undefined): Promise<BridgeResponse> {
    if (!paymentHeader) {
      const derivationPrefix = randomBytes(16).toString('base64');
      return {
        status: 402,
        headers: {
          ...buildChallengeHeaders(this.offer.costSats, derivationPrefix),
          'content-type': 'application/json',
        },
        body: {
          error: 'payment required',
          satoshisRequired: this.offer.costSats,
          offerId: toHex(this.offer.offerId),
          ...(this.receiveScriptHex ? { payToScriptHex: this.receiveScriptHex } : {}),
        },
      };
    }

    // Parse + verify the BRC-29 payment.
    let payment;
    try {
      payment = parsePaymentHeader(paymentHeader);
    } catch (e) {
      return this.error(400, `malformed x-bsv-payment: ${(e as Error).message}`);
    }
    const v = this.verifier.verify(payment, this.offer.costSats);
    if (!v.ok) return this.error(402, `payment rejected: ${v.reason}`);

    // Settle on-chain. Metanet Desktop's createAction returns a SIGNED but
    // UN-broadcast tx (+ a computed txid) — like wallet.html, the app must
    // broadcast. So in broadcast mode the bridge actually posts to ARC and
    // captures the network txid; the payer's computed txid is NOT trusted as
    // proof of settlement. Only when broadcast is disabled (a wallet that
    // pre-broadcasts) do we fall back to the payer/verifier txid.
    let txid: string | undefined;
    if (this.broadcastOnVerify && typeof payment.transaction === 'string') {
      console.log(`[bridge] broadcasting payment to ARC (${this.offer.costSats} sats)…`);
      const b = await broadcastTxHex(payment.transaction, this.arc);
      if (!b.ok) {
        console.error(`[bridge] payment broadcast FAILED: ${b.reason}`);
        return this.error(502, `payment broadcast failed: ${b.reason}`);
      }
      console.log(`[bridge] payment ON-CHAIN → ${b.txid}`);
      txid = b.txid;
    } else {
      txid = (typeof payment.txid === 'string' && payment.txid) || v.txid;
    }

    // Paid → build + broadcast the actuator_activate.v0 cell.
    const { cell, sig } = buildActuatorActivate(
      this.offer,
      this.walletKey,
      this.ownerId,
      BigInt(Date.now()),
      this.counter++,
    );
    await this.mesh.broadcast(cell, sig);
    const activated = await this.mesh.awaitActivation(this.offer.offerId, this.timeoutMs);
    if (!activated) {
      // Paid but the device never confirmed — surface 504 so the agent's
      // refund flow can kick in (Dolphin Milk auto-refunds on excess/failure).
      return this.error(504, 'device did not acknowledge activation before timeout');
    }

    return {
      status: 200,
      headers: {
        'content-type': 'application/json',
        'x-bsv-payment-satoshis-paid': String(v.satoshisPaid),
        ...(txid ? { 'x-bsv-payment-txid': txid } : {}),
      },
      body: {
        activated: true,
        offerId: toHex(this.offer.offerId),
        durationMs: this.offer.durationMs,
        satoshisPaid: v.satoshisPaid,
        ...(txid ? { txid } : {}),
        activatedAt: new Date().toISOString(),
      },
    };
  }

  private error(status: number, message: string): BridgeResponse {
    return { status, headers: { 'content-type': 'application/json' }, body: { error: message } };
  }
}
