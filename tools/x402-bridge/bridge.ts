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
import { parseTx } from './onchain-payment.js';
import type { ChannelMeter, MeterStatus } from './meter.js';
import { createHash } from 'node:crypto';

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
  /**
   * After an activation is acknowledged, hold the queue this long before the
   * next one starts, so each payer sees their own light. Default: the offer's
   * duration + 500 ms.
   */
  holdMs?: number;
  /**
   * Upper bound on one activation (inject + ack). A mesh that never answers
   * gets a 504 rather than wedging the queue. Default: activationTimeoutMs + 10 s.
   */
  queueTimeoutMs?: number;
  /**
   * METERED mode: a payment buys seconds. The price is the amount the payer
   * chose; a verified payment becomes one channel commitment and the boards
   * meter it themselves. Without a meter, a payment is one 5 s activation.
   */
  meter?: ChannelMeter;
  /** The amounts the phone page offers (sats). Default [12, 36, 72]. */
  meterOptions?: number[];
  /** Largest amount one payment may choose. Default: the largest option. */
  maxSats?: number;
}

/** Where one paid activation is: waiting, being lit, done, or failed. */
export type TicketState = 'queued' | 'lighting' | 'lit' | 'failed';
export interface TicketStatus {
  ticket: string;
  state: TicketState | 'unknown';
  /** Activations ahead of this one that have not finished (0 = you are next / lit now). */
  ahead: number;
  /** Activations waiting or lighting, in total. */
  length: number;
  litAt?: string;
  error?: string;
  secondsAdded?: number;
  message?: string;
}
interface Ticket {
  state: TicketState;
  litAt?: string;
  error?: string;
  secondsAdded?: number;
  message?: string;
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
  private readonly holdMs: number;
  private readonly queueTimeoutMs: number;
  /** Serial activation queue: each activation chains onto the last. */
  private tail: Promise<unknown> = Promise.resolve();
  /** Tickets not yet finished (queued, lighting, or holding), in order. */
  private readonly pending: string[] = [];
  private readonly tickets = new Map<string, Ticket>();
  /** Payments already spent on an activation — a replay never re-lights. */
  private readonly used = new Set<string>();
  private readonly meter?: ChannelMeter;
  readonly meterOptions: number[];
  private readonly maxSats: number;

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
    this.meter = cfg.meter;
    this.meterOptions = cfg.meterOptions ?? [12, 36, 72];
    this.maxSats = cfg.maxSats ?? Math.max(...this.meterOptions);
    // Metered payments add up on the chip; there is nothing to wait out.
    this.holdMs = cfg.holdMs ?? (this.meter ? 0 : this.offer.durationMs + 500);
    this.queueTimeoutMs = cfg.queueTimeoutMs ?? this.timeoutMs + 10_000;
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
          ? { payTo: { scriptHex: this.receiveScriptHex, satoshis: this.meter ? this.meterOptions[0] : this.offer.costSats, network: 'mainnet' } }
          : {}),
        ...(this.meter
          ? { meter: { satsPerSecond: this.meter.status().satsPerSecond, options: this.meterOptions, minSats: Math.min(...this.meterOptions), maxSats: this.maxSats } }
          : {}),
      },
    };
  }

  /** GET /meter — seconds of light left, from the bridge's own tally. */
  meterStatus(): MeterStatus | { metered: false } {
    return this.meter ? this.meter.status() : { metered: false };
  }

  /**
   * POST /actuator/activate. With no `x-bsv-payment` header → 402 challenge.
   * With a valid payment → verify, queue, actuate over the mesh, 200 + receipt.
   *
   * Activations run one at a time. A payment (by txid) lights once: a replay
   * answers 409. With `async`, the answer is 202 + a ticket as soon as the
   * payment is queued; poll queueStatus(ticket) for the outcome.
   */
  async activate(
    paymentHeader: string | null | undefined,
    opts: { async?: boolean; sats?: number } = {},
  ): Promise<BridgeResponse> {
    // Metered: the price is what the payer chose, within bounds.
    let price = this.offer.costSats;
    if (this.meter) {
      const min = Math.min(...this.meterOptions);
      const chosen = opts.sats ?? this.meterOptions[0];
      if (!Number.isInteger(chosen) || chosen < min || chosen > this.maxSats) {
        return this.error(400, `choose between ${min} and ${this.maxSats} sats`);
      }
      price = chosen;
    }
    if (!paymentHeader) {
      const derivationPrefix = randomBytes(16).toString('base64');
      return {
        status: 402,
        headers: {
          ...buildChallengeHeaders(price, derivationPrefix),
          'content-type': 'application/json',
        },
        body: {
          error: 'payment required',
          satoshisRequired: price,
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
    const v = this.verifier.verify(payment, price);
    if (!v.ok) return this.error(402, `payment rejected: ${v.reason}`);

    // One payment, one light. Claim the txid before anything awaits, so two
    // copies of the same tx racing in cannot both pass.
    const ticket = paymentKey(payment.transaction, v.txid);
    if (this.used.has(ticket)) {
      return this.error(409, `payment already used (txid ${ticket}) — it has already turned the light on once`);
    }
    this.used.add(ticket);

    // Settle on-chain. Metanet Desktop's createAction returns a SIGNED but
    // UN-broadcast tx (+ a computed txid) — like wallet.html, the app must
    // broadcast. So in broadcast mode the bridge actually posts to ARC and
    // captures the network txid; the payer's computed txid is NOT trusted as
    // proof of settlement. Only when broadcast is disabled (a wallet that
    // pre-broadcasts) do we fall back to the payer/verifier txid.
    let txid: string | undefined;
    if (this.broadcastOnVerify && typeof payment.transaction === 'string') {
      console.log(`[bridge] broadcasting payment to ARC (${price} sats)…`);
      const b = await broadcastTxHex(payment.transaction, this.arc);
      if (!b.ok) {
        console.error(`[bridge] payment broadcast FAILED: ${b.reason}`);
        this.used.delete(ticket); // never settled — let the payer retry
        return this.error(502, `payment broadcast failed: ${b.reason}`);
      }
      console.log(`[bridge] payment ON-CHAIN → ${b.txid}`);
      txid = b.txid;
    } else {
      txid = (typeof payment.txid === 'string' && payment.txid) || v.txid;
    }

    const ahead = this.pending.length;
    const result = this.enqueue(ticket, v.satoshisPaid, txid);
    if (opts.async) {
      return {
        status: 202,
        headers: { 'content-type': 'application/json' },
        body: { queued: true, ticket, ahead, ...(txid ? { txid } : {}) },
      };
    }
    return result;
  }

  /** Metered: one commitment adding the paid sats; the boards meter it. */
  private async actuateMetered(t: Ticket, satoshisPaid: number, txid: string | undefined): Promise<BridgeResponse> {
    const meter = this.meter!;
    let r: Awaited<ReturnType<ChannelMeter['addSats']>> | 'timeout';
    try {
      r = await withTimeout(meter.addSats(satoshisPaid), this.queueTimeoutMs * 3);
    } catch (e) {
      t.state = 'failed';
      t.error = `mesh error: ${(e as Error).message}`;
      return this.error(502, t.error);
    }
    if (r === 'timeout' || !r.ok) {
      t.state = 'failed';
      t.error = r === 'timeout' ? 'the injector board did not answer before timeout' : (r.error ?? 'commitment failed');
      return this.error(504, t.error);
    }
    t.state = 'lit';
    t.litAt = new Date().toISOString();
    t.secondsAdded = r.secondsAdded;
    t.message = `≈${Math.round(r.secondsAdded)} s of light added`;
    return {
      status: 200,
      headers: {
        'content-type': 'application/json',
        'x-bsv-payment-satoshis-paid': String(satoshisPaid),
        ...(txid ? { 'x-bsv-payment-txid': txid } : {}),
      },
      body: {
        activated: true,
        metered: true,
        satoshisPaid,
        secondsAdded: r.secondsAdded,
        secondsLeft: r.secondsLeft,
        message: t.message,
        ...(txid ? { txid } : {}),
        activatedAt: t.litAt,
      },
    };
  }

  /** GET /queue — where a ticket is, or the queue's length with no ticket. */
  queueStatus(ticket?: string | null): TicketStatus | { length: number; lighting: boolean } {
    if (!ticket) {
      return { length: this.pending.length, lighting: [...this.tickets.values()].some((t) => t.state === 'lighting') };
    }
    const t = this.tickets.get(ticket);
    const i = this.pending.indexOf(ticket);
    return {
      ticket,
      state: t ? t.state : 'unknown',
      ahead: i >= 0 ? i : 0,
      length: this.pending.length,
      ...(t?.litAt ? { litAt: t.litAt } : {}),
      ...(t?.error ? { error: t.error } : {}),
      ...(t?.secondsAdded !== undefined ? { secondsAdded: t.secondsAdded } : {}),
      ...(t?.message ? { message: t.message } : {}),
    };
  }

  /** Chain one activation onto the queue; resolve with its own outcome. */
  private enqueue(ticket: string, satoshisPaid: number, txid: string | undefined): Promise<BridgeResponse> {
    const t: Ticket = { state: 'queued' };
    this.tickets.set(ticket, t);
    this.pending.push(ticket);
    const done = () => {
      const i = this.pending.indexOf(ticket);
      if (i >= 0) this.pending.splice(i, 1);
    };
    const run = this.tail.then(() => this.actuate(t, satoshisPaid, txid));
    // The next activation waits for this one's ack AND its hold, so each
    // payer sees their own light; a failure releases the queue at once.
    this.tail = run
      .then((r) => (r.status === 200 && this.holdMs > 0 ? sleep(this.holdMs) : undefined))
      .catch(() => undefined)
      .finally(done);
    return run;
  }

  private async actuate(t: Ticket, satoshisPaid: number, txid: string | undefined): Promise<BridgeResponse> {
    t.state = 'lighting';
    if (this.meter) return this.actuateMetered(t, satoshisPaid, txid);
    let activated: boolean | 'timeout';
    try {
      activated = await withTimeout(
        (async () => {
          // Paid → build + broadcast the actuator_activate.v0 cell.
          const { cell, sig } = buildActuatorActivate(
            this.offer,
            this.walletKey,
            this.ownerId,
            BigInt(Date.now()),
            this.counter++,
          );
          await this.mesh.broadcast(cell, sig);
          return this.mesh.awaitActivation(this.offer.offerId, this.timeoutMs);
        })(),
        this.queueTimeoutMs,
      );
    } catch (e) {
      t.state = 'failed';
      t.error = `mesh error: ${(e as Error).message}`;
      return this.error(502, t.error);
    }
    if (activated === 'timeout') {
      t.state = 'failed';
      t.error = 'device did not answer before timeout';
      return this.error(504, t.error);
    }
    if (!activated) {
      // Paid but the device never confirmed — surface 504 so the agent's
      // refund flow can kick in (Dolphin Milk auto-refunds on excess/failure).
      t.state = 'failed';
      t.error = 'device did not acknowledge activation before timeout';
      return this.error(504, t.error);
    }

    t.state = 'lit';
    t.litAt = new Date().toISOString();
    return {
      status: 200,
      headers: {
        'content-type': 'application/json',
        'x-bsv-payment-satoshis-paid': String(satoshisPaid),
        ...(txid ? { 'x-bsv-payment-txid': txid } : {}),
      },
      body: {
        activated: true,
        offerId: toHex(this.offer.offerId),
        durationMs: this.offer.durationMs,
        satoshisPaid,
        ...(txid ? { txid } : {}),
        activatedAt: t.litAt,
      },
    };
  }

  private error(status: number, message: string): BridgeResponse {
    return { status, headers: { 'content-type': 'application/json' }, body: { error: message } };
  }
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/** Resolve with the promise's value, or 'timeout' if it takes longer than ms. */
function withTimeout<T>(p: Promise<T>, ms: number): Promise<T | 'timeout'> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const t = new Promise<'timeout'>((r) => { timer = setTimeout(() => r('timeout'), ms); });
  return Promise.race([p, t]).finally(() => clearTimeout(timer));
}

/**
 * The identity of a payment for replay purposes: its txid. Prefer the
 * verifier's (it parsed the tx); else parse it here; else hash the bytes, so
 * a dry-run payment that is not a real tx still dedupes. A payer-claimed
 * `txid` field is never the key — it could differ on every replay.
 */
function paymentKey(transaction: unknown, txid: string | undefined): string {
  if (txid) return txid.toLowerCase();
  if (typeof transaction === 'string') {
    const tx = parseTx(transaction);
    if (tx) return tx.id('hex');
    return createHash('sha256').update(transaction.toLowerCase()).digest('hex');
  }
  return createHash('sha256').update(JSON.stringify(transaction ?? null)).digest('hex');
}
