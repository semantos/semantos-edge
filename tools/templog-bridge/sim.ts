/**
 * sim.ts — a synthetic node and gateway for `bridge.ts --sim` and the tests.
 *
 * SimNode keeps what examples/temp_logger's node keeps: the flash ring (with
 * cm_tlog_append's sector recycling, so oldest_seq and lost_through behave as
 * on the board), the delivery pointer an ack sets, and the boot starts it
 * learns from acks. It builds batches the way the firmware's send_batch does —
 * from the first pending seq, up to 91, stopping at a boot boundary, with a
 * placeholder for an unreadable record. The gateway half frames each batch as
 * a TL line and turns the bridge's AK line back into an ack cell for the node.
 *
 * Every batch goes through the bridge's handleLine: the path a serial line
 * takes, not a shortcut around it.
 */

import { mintCell } from '../x402-bridge/cell-codec.js';
import { DOMAIN } from '../domains.js';
import {
  BATCH_MAX_SAMPLES,
  SF,
  TEMP_INVALID,
  TYPE_ACK,
  TYPE_BATCH,
  decodeAck,
  encodeAck,
  encodeBatch,
  formatTlLine,
  macToBytes,
  parseAkLine,
  parseCell,
  type SampleFields,
} from './codec.js';

const RECORDS_PER_SECTOR = 256;
const GATEWAY_MAC = '02:00:5e:c0:1d:00';

/** Anything that takes one gateway line and may answer with an AK line. */
export interface LineHandler {
  handleLine(line: string): string | null;
}

interface FlashRecord {
  bootId: number;
  uptimeS: number;
  centiC: number;
  flags: number;
}

function ownerId(mac: string): Uint8Array {
  const o = new Uint8Array(16);
  o.set(macToBytes(mac));
  return o;
}

// ── The node ─────────────────────────────────────────────────────────

export interface SimNodeOptions {
  mac: string;
  logId: number;
  /** Unix time the first boot began */
  bootUnixS: number;
  /** ring size in records: whole 256-record sectors, at least two */
  capacity?: number;
  intervalS?: number;
  band?: { min: number; max: number };
}

export class SimNode {
  readonly mac: string;
  readonly logId: number;
  readonly capacity: number;
  readonly intervalS: number;
  readonly band: { min: number; max: number };
  bootId = 1;
  nextSeq = 1;
  oldestSeq = 1;
  ackedThrough = 0;
  private bootUnixS: number;
  private readonly flash = new Map<number, FlashRecord>();
  /** boot → its start in Unix time, once an ack has said */
  private readonly epochs = new Map<number, number>();

  constructor(o: SimNodeOptions) {
    const capacity = o.capacity ?? 512;
    if (capacity % RECORDS_PER_SECTOR !== 0 || capacity < 2 * RECORDS_PER_SECTOR) {
      throw new RangeError(`capacity must be whole sectors of ${RECORDS_PER_SECTOR}, at least two: ${capacity}`);
    }
    this.mac = o.mac;
    this.logId = o.logId;
    this.capacity = capacity;
    this.intervalS = o.intervalS ?? 60;
    this.band = o.band ?? { min: -200, max: 2800 };
    this.bootUnixS = o.bootUnixS;
  }

  uptimeS(nowUnixS: number): number {
    return nowUnixS - this.bootUnixS;
  }

  /** A reading (null: the probe did not answer), judged against the band. Returns its seq. */
  sample(nowUnixS: number, centiC: number | null): number {
    const seq = this.append();
    const flags =
      centiC === null ? SF.SENSOR_ERROR : centiC >= this.band.min && centiC <= this.band.max ? 0 : SF.POLICY_REJECT;
    this.flash.set(seq, { bootId: this.bootId, uptimeS: this.uptimeS(nowUnixS), centiC: centiC ?? TEMP_INVALID, flags });
    return seq;
  }

  /** Power fails mid-write: the seq is spent and its record unreadable. */
  burn(): number {
    return this.append();
  }

  reboot(nowUnixS: number): void {
    this.bootId++;
    this.bootUnixS = nowUnixS;
  }

  lostThrough(): number {
    return this.ackedThrough + 1 < this.oldestSeq ? this.oldestSeq - 1 : 0;
  }

  pendingFirst(): number {
    return Math.max(this.ackedThrough + 1, this.oldestSeq);
  }

  pending(): number {
    const first = this.pendingFirst();
    return this.nextSeq > first ? this.nextSeq - first : 0;
  }

  /** The next batch payload, built as send_batch builds it, or null when nothing is pending. */
  buildBatch(nowUnixS: number): Uint8Array | null {
    if (this.pending() === 0) return null;
    const first = this.pendingFirst();
    const head = this.flash.get(first);
    const bootId = head ? head.bootId : this.bootId;
    const samples: SampleFields[] = [];
    for (let seq = first; seq < this.nextSeq && samples.length < BATCH_MAX_SAMPLES; seq++) {
      const r = this.flash.get(seq);
      if (!r) {
        samples.push({ uptimeS: 0, centiC: TEMP_INVALID, flags: SF.RECORD_LOST | SF.SENSOR_ERROR });
        continue;
      }
      if (r.bootId !== bootId) break; // one header's clock covers every sample
      samples.push({ uptimeS: r.uptimeS, centiC: r.centiC, flags: r.flags });
    }
    return encodeBatch(
      {
        firstSeq: first,
        bootId,
        bootNow: this.bootId,
        uptimeNowS: this.uptimeS(nowUnixS),
        bootEpochS: this.epochs.get(bootId) ?? 0,
        lostThrough: this.lostThrough(),
        sampleIntervalS: this.intervalS,
        policyMinCenti: this.band.min,
        policyMaxCenti: this.band.max,
        logId: this.logId,
      },
      samples,
    );
  }

  /** handle_ack: set the pointer (lower is a replay request), clamped to what exists; learn this boot's start. */
  applyAck(ackedThrough: number, hostUnixS: number, nowUnixS: number): void {
    this.ackedThrough = Math.min(ackedThrough, this.nextSeq - 1);
    const up = this.uptimeS(nowUnixS);
    if (hostUnixS > up) this.epochs.set(this.bootId, hostUnixS - up);
  }

  /** cm_tlog_append: writing a sector's first slot erases it, and the oldest 256 records go. */
  private append(): number {
    const seq = this.nextSeq;
    const lap = this.capacity - RECORDS_PER_SECTOR;
    if (((seq - 1) % this.capacity) % RECORDS_PER_SECTOR === 0 && seq > lap) {
      const survivor = seq - lap;
      for (let s = this.oldestSeq; s < survivor; s++) this.flash.delete(s);
      if (survivor > this.oldestSeq) this.oldestSeq = survivor;
    }
    this.nextSeq = seq + 1;
    return seq;
  }
}

// ── The world: a clock, the node, the radio and the gateway ──────────

export interface SimWorldOptions {
  startUnixS: number;
  mac: string;
  logId: number;
  capacity?: number;
  intervalS?: number;
}

export class SimWorld {
  nowUnixS: number;
  readonly node: SimNode;
  /** seq → the Unix second it was really taken, to check placement against */
  readonly truth = new Map<number, number>();
  sends = 0;
  acksLost = 0;
  private readings = 0;

  constructor(o: SimWorldOptions) {
    this.nowUnixS = o.startUnixS;
    this.node = new SimNode({ mac: o.mac, logId: o.logId, bootUnixS: o.startUnixS, capacity: o.capacity, intervalS: o.intervalS });
  }

  /** A fridge at about 4 °C with a slow wobble. */
  fridge(k: number): number {
    return 400 + Math.round(120 * Math.sin(k / 15));
  }

  /** `n` readings, one interval apart; `reading(i)` overrides the i-th (null: no reading). */
  take(n: number, reading?: (i: number) => number | null | undefined): void {
    for (let i = 0; i < n; i++) {
      this.nowUnixS += this.node.intervalS;
      const k = this.readings++;
      const r = reading?.(i);
      const seq = this.node.sample(this.nowUnixS, r === undefined ? this.fridge(k) : r);
      this.truth.set(seq, this.nowUnixS);
    }
  }

  burn(): number {
    this.nowUnixS += this.node.intervalS;
    this.readings++;
    return this.node.burn();
  }

  reboot(): void {
    this.nowUnixS += 20;
    this.node.reboot(this.nowUnixS);
  }

  /** Another gateway's bridge acks through `seq`; this bridge never sees those batches. */
  foreignAck(seq: number): void {
    this.node.applyAck(seq, this.nowUnixS, this.nowUnixS);
  }

  /** Send batches until nothing is pending. The first `dropAcks` acks are lost on the radio. */
  deliver(bridge: LineHandler, opts: { dropAcks?: number; narrate?: (m: string) => void } = {}): void {
    let drop = opts.dropAcks ?? 0;
    for (let guard = 0; guard < 10_000; guard++) {
      const payload = this.node.buildBatch(this.nowUnixS);
      if (!payload) return;
      const cell = mintCell(
        TYPE_BATCH,
        payload,
        ownerId(this.node.mac),
        BigInt(this.node.uptimeS(this.nowUnixS)) * 1000n,
        DOMAIN.meshTelemetry,
      );
      this.sends++;
      const ak = bridge.handleLine(formatTlLine(this.node.mac, cell).trimEnd());
      if (ak === null) throw new Error('the bridge did not acknowledge a well-formed batch');
      if (drop > 0) {
        drop--;
        this.acksLost++;
        opts.narrate?.('that ack is lost on the radio, so the node sends the same batch again');
        continue;
      }
      this.gatewayToNode(ak);
    }
    throw new Error('delivery did not settle');
  }

  /** The gateway builds an ack cell from the AK line, and the node reads it as main.c does. */
  private gatewayToNode(akLine: string): void {
    const ak = parseAkLine(akLine);
    if (!ak) throw new Error(`the gateway cannot read ${JSON.stringify(akLine)}`);
    const cell = mintCell(TYPE_ACK, encodeAck(ak.mac, ak.ackedThrough, ak.hostUnixS), ownerId(GATEWAY_MAC), 0n, DOMAIN.meshTelemetry);
    const parsed = parseCell(cell);
    const got = parsed?.kind === 'ack' ? decodeAck(parsed.payload.subarray(0, parsed.payloadTotal)) : null;
    if (!got) throw new Error('the node cannot read the ack cell');
    if (got.targetMac !== this.node.mac) return; // another node's
    this.node.applyAck(got.ackedThrough, got.hostUnixS, this.nowUnixS);
  }
}

// ── The scenario ─────────────────────────────────────────────────────

export interface SimReport {
  mac: string;
  logId: number;
  /** the node's newest seq */
  lastSeq: number;
  /** where the node's pointer ended: what it may now let go of */
  nodeAckedThrough: number;
  sends: number;
  acksLost: number;
  burnedSeq: number;
  truth: Map<number, number>;
}

/**
 * One node's life in five acts: first contact; a lost ack (so a duplicate);
 * another gateway acking some readings (so a gap, then a replay); two reboots
 * (so all three ways of placing a sample in time); and ten hours out of range
 * (so the ring wraps and the node reports the loss).
 */
export function runScenario(world: SimWorld, bridge: LineHandler, narrate: (m: string) => void = () => {}): SimReport {
  const node = world.node;

  narrate('5 readings, then the node sends them');
  world.take(5);
  world.deliver(bridge, { narrate });

  narrate('5 more readings, sent');
  world.take(5);
  world.deliver(bridge, { dropAcks: 1, narrate });

  narrate(`5 readings go to another gateway, whose bridge acks them through ${node.nextSeq + 4}; then 5 more come here`);
  world.take(5);
  world.foreignAck(node.nextSeq - 1);
  world.take(5);
  world.deliver(bridge, { narrate });

  narrate('2 readings, a reboot, 2 readings, another reboot before any ack, 1 reading, then send');
  world.take(2);
  world.reboot();
  world.take(2);
  world.reboot();
  world.take(1);
  world.deliver(bridge, { narrate });

  const first = node.nextSeq;
  narrate(
    `out of range for 600 readings (${(600 * node.intervalS) / 3600} h): the ${node.capacity}-record ring wraps over ` +
      `the oldest unsent ones; a 31 °C excursion, a probe dropout and a torn write along the way`,
  );
  // Indexes are placed where they survive the wrap (seq 257 onwards).
  world.take(300, (i) => (i >= 250 && i < 260 ? 3100 : i === 280 ? null : undefined));
  const burnedSeq = world.burn();
  world.take(299);
  narrate(`back in range with ${node.nextSeq - first} readings taken, the oldest now ${node.oldestSeq}`);
  world.deliver(bridge, { narrate });

  return {
    mac: node.mac,
    logId: node.logId,
    lastSeq: node.nextSeq - 1,
    nodeAckedThrough: node.ackedThrough,
    sends: world.sends,
    acksLost: world.acksLost,
    burnedSeq,
    truth: world.truth,
  };
}
