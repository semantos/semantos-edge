/**
 * meter.ts — pay-per-second light, metered BY THE CHIP.
 *
 * The boards run metered-rental's payment channel: a channel_open, then
 * channel_commitments that raise device_share. Each actuator meters its own
 * consumption at ~1.2 sats/s from the first commitment and turns its LED off
 * by itself the moment consumed > device_share (+1 sat tolerance). Nothing
 * off-device decides when the light goes out.
 *
 * The bridge keeps the books so it can say "≈N s added" and show seconds
 * left. Facts learned on the bench (2026-10-01):
 *
 *  - The chip's meter keeps draining while dark. A payment after the light
 *    went out must commit device_share ≥ what the chip has consumed by the
 *    time the commitment lands, plus the new sats ("catch-up"); otherwise the
 *    new sats are swallowed by the idle drain.
 *  - A board accepts channel_open only from CLOSED. A rebooted board is
 *    CLOSED; one already in the channel answers apply_open rc=-1 and carries
 *    on. So re-sending channel_open with the SAME id is harmless and rejoins a
 *    board someone unplugged. A new id would be refused by every running
 *    board — so the id lives in a state file and survives bridge restarts.
 *  - But a board that rejoins that way starts a FRESH meter against the
 *    whole cumulative share, so it would stay lit far longer than the rest.
 *    Hence one channel per lit stretch: when the bridge's tally says dark,
 *    the next payment re-sends the last commitment (a board that missed it
 *    catches up — close needs every board on the same seq/share), closes the
 *    channel, and opens a new one. Shares stay small. A bridge restart does
 *    the same with the channel remembered in the state file.
 *  - The injector (board A) stages each injected cell for 1.8 s before it
 *    broadcasts, and a newer inject replaces a staged one. Cells therefore go
 *    one at a time, each waiting for A's "*** CELL BROADCAST ***" line.
 */

import { PrivateKey } from '@bsv/sdk';
import { readFileSync, writeFileSync, renameSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { mintCell, signCell, typeHash, writeU32LE, writeU64LE } from './cell-codec.js';
import { domainForType } from './cell-domains.js';
import type { MeshPort } from './bridge.js';

const OPEN_TYPE = typeHash('cellmesh.channel_open.v0');
const COMMITMENT_TYPE = typeHash('cellmesh.channel_commitment.v0');
const CLOSE_TYPE = typeHash('cellmesh.channel_close.v0');
const CAPACITY = 1_000_000;
/** Commitment expiry, relative to open. Long enough never to lapse mid-talk. */
const EXPIRY_MS = 7n * 24n * 3_600_000n;

export interface ChannelMeterConfig {
  /** Injects a cell and resolves awaitActivation() when the injector broadcast it. */
  mesh: MeshPort;
  /** The fleet signing key (the boards' trust anchor), as metered-rental uses. */
  key: PrivateKey;
  /** Where the channel id / seq / share live between runs. */
  statePath?: string;
  now?: () => number;
  /** The chip's rate. Firmware: CM_METER_RATE_MSAT_PER_SEC = 1200. */
  satsPerSecond?: number;
  /** Re-send channel_open (same id) before a commitment if the last is older. */
  reopenEveryMs?: number;
  /** How long to wait for the injector's broadcast line. */
  ackTimeoutMs?: number;
  /** Time from deciding a commitment to the chip applying it (A's staging + air). */
  inFlightMs?: number;
}

interface MeterState {
  channelIdHex: string;
  seq: number;
  /** device_share last committed (includes catch-up for idle drain). */
  share: number;
  /** Real sats paid by the room. */
  satsPaid: number;
  /** When the chip's meter started (first commitment broadcast), ms epoch. */
  meterStartAt: number | null;
}

export interface MeterStatus {
  metered: true;
  channelId: string;
  seq: number;
  share: number;
  satsPaid: number;
  satsPerSecond: number;
  secondsLeft: number;
  lit: boolean;
}

export class ChannelMeter {
  private readonly mesh: MeshPort;
  private readonly key: PrivateKey;
  private readonly owner: Uint8Array;
  private readonly pub: Uint8Array;
  private readonly now: () => number;
  private readonly rate: number;
  private readonly reopenEveryMs: number;
  private readonly ackTimeoutMs: number;
  private readonly inFlightMs: number;
  private readonly statePath?: string;
  private state: MeterState;
  private lastOpenAt: number | null = null;

  constructor(cfg: ChannelMeterConfig) {
    this.mesh = cfg.mesh;
    this.key = cfg.key;
    this.pub = new Uint8Array(Buffer.from(cfg.key.toPublicKey().toString(), 'hex'));
    this.owner = this.pub.subarray(0, 16);
    this.now = cfg.now ?? Date.now;
    this.rate = cfg.satsPerSecond ?? 1.2;
    this.reopenEveryMs = cfg.reopenEveryMs ?? 30_000;
    this.ackTimeoutMs = cfg.ackTimeoutMs ?? 6_000;
    this.inFlightMs = cfg.inFlightMs ?? 2_600;
    this.statePath = cfg.statePath;
    this.state = this.load() ?? {
      channelIdHex: randomBytes(16).toString('hex'),
      seq: 0,
      share: 0,
      satsPaid: 0,
      meterStartAt: null,
    };
    this.save();
  }

  get channelIdHex(): string {
    return this.state.channelIdHex;
  }

  /**
   * Announce the channel. If a previous run left a channel with commitments,
   * close it first (boards still in it would refuse a new open).
   */
  async start(): Promise<boolean> {
    if (this.state.seq > 0) return this.newSession();
    return this.sendOpen();
  }

  /** Re-sync, close the current channel, open a fresh one. */
  private async newSession(): Promise<boolean> {
    const { seq, share } = this.state;
    if (seq > 0) {
      // Best-effort: a board that rebooted is CLOSED and ignores both.
      await this.send(COMMITMENT_TYPE, this.encodeCommitment(seq, share));
      await this.send(CLOSE_TYPE, this.encodeClose(seq, share));
    }
    this.state = {
      channelIdHex: randomBytes(16).toString('hex'),
      seq: 0,
      share: 0,
      satsPaid: this.state.satsPaid,
      meterStartAt: null,
    };
    this.save();
    return this.sendOpen();
  }

  /** What the chip has consumed by time t (ms epoch), in sats. */
  private consumedAt(t: number): number {
    if (this.state.meterStartAt === null) return 0;
    return Math.max(0, ((t - this.state.meterStartAt) / 1000) * this.rate);
  }

  status(): MeterStatus {
    const left = Math.max(0, (this.state.share - this.consumedAt(this.now())) / this.rate);
    return {
      metered: true,
      channelId: this.state.channelIdHex,
      seq: this.state.seq,
      share: this.state.share,
      satsPaid: this.state.satsPaid,
      satsPerSecond: this.rate,
      secondsLeft: Math.round(left * 10) / 10,
      lit: left > 0,
    };
  }

  /** Commit `sats` more to the boards. One commitment; cumulative share. */
  async addSats(sats: number): Promise<{ ok: boolean; secondsAdded: number; secondsLeft: number; error?: string }> {
    const secondsAdded = Math.round((sats / this.rate) * 10) / 10;
    if (this.state.seq > 0 && this.consumedAt(this.now()) >= this.state.share) {
      await this.newSession(); // dark: start a fresh, small channel
    } else if (this.lastOpenAt === null || this.now() - this.lastOpenAt > this.reopenEveryMs) {
      await this.sendOpen(); // rejoin any board that rebooted; best-effort
    }
    // Catch-up: if the chip has drained past what was committed (dark), the
    // new sats must start from what it will have consumed when this lands.
    const landing = this.consumedAt(this.now() + this.inFlightMs);
    const base = Math.max(this.state.share, Math.ceil(landing));
    const share = base + sats;
    const seq = this.state.seq + 1;
    const ok = await this.send(COMMITMENT_TYPE, this.encodeCommitment(seq, share));
    if (!ok) {
      return { ok: false, secondsAdded: 0, secondsLeft: this.status().secondsLeft, error: 'the injector board did not broadcast the commitment' };
    }
    this.state.seq = seq;
    this.state.share = share;
    this.state.satsPaid += sats;
    if (this.state.meterStartAt === null) this.state.meterStartAt = this.now();
    this.save();
    return { ok: true, secondsAdded, secondsLeft: this.status().secondsLeft };
  }

  private async sendOpen(): Promise<boolean> {
    const ok = await this.send(OPEN_TYPE, this.encodeOpen());
    if (ok) this.lastOpenAt = this.now();
    return ok;
  }

  private async send(type: Uint8Array, payload: Uint8Array): Promise<boolean> {
    const cell = mintCell(type, payload, this.owner, BigInt(this.now()), domainForType(type));
    const sig = signCell(cell, this.key);
    await this.mesh.broadcast(cell, sig);
    return this.mesh.awaitActivation(new Uint8Array(16), this.ackTimeoutMs);
  }

  // Byte layouts match metered-rental.ts (the Zig cell_channel ABI).
  private encodeOpen(): Uint8Array {
    const b = new Uint8Array(61);
    b.set(Buffer.from(this.state.channelIdHex, 'hex'), 0);
    b.set(this.pub, 16);
    writeU64LE(b, 49, BigInt(this.now()));
    writeU32LE(b, 57, CAPACITY);
    return b;
  }

  private encodeCommitment(seq: number, share: number): Uint8Array {
    const b = new Uint8Array(68);
    b.set(Buffer.from(this.state.channelIdHex, 'hex'), 0);
    writeU32LE(b, 16, seq);
    writeU32LE(b, 20, share);
    writeU32LE(b, 24, 0);
    writeU64LE(b, 28, EXPIRY_MS);
    return b;
  }

  private encodeClose(seq: number, share: number): Uint8Array {
    const b = new Uint8Array(24);
    b.set(Buffer.from(this.state.channelIdHex, 'hex'), 0);
    writeU32LE(b, 16, seq);
    writeU32LE(b, 20, share);
    return b;
  }

  private load(): MeterState | null {
    if (!this.statePath) return null;
    try {
      const s = JSON.parse(readFileSync(this.statePath, 'utf8')) as MeterState;
      return typeof s.channelIdHex === 'string' && s.channelIdHex.length === 32 ? s : null;
    } catch {
      return null;
    }
  }

  private save(): void {
    if (!this.statePath) return;
    const tmp = `${this.statePath}.tmp`;
    writeFileSync(tmp, JSON.stringify(this.state, null, 2));
    renameSync(tmp, this.statePath);
  }
}
