/**
 * store.ts — what the bridge holds, and what it may acknowledge.
 *
 * For each node log, keyed by (mac, log_id), the bridge keeps `through`: it
 * holds every seq from where it first joined that log up to `through`, except
 * seqs the node reported overwritten. The ack sends `through`, and the node may
 * then let those readings go — so `through` moves only when that is true:
 *
 *   - contiguously, over samples actually stored;
 *   - to a batch's lost_through, which the node sends only for seqs it
 *     overwrote before any host acknowledged them. That is recorded as a loss
 *     event, never absorbed silently.
 *
 * A gap (a batch starting past through + 1) is stored but leaves `through`
 * where it is; the ack's lower value is how the host asks the node to replay.
 *
 * Every new sample, every loss, and the first sight of each log is a JSON
 * line in the journal, written (and fsynced) before the ack is returned. On
 * startup the journal is read back to rebuild the dedupe sets and `through`.
 *
 * The clock is an argument: nothing here reads the wall clock.
 */

import { closeSync, existsSync, fsyncSync, openSync, readFileSync, writeSync } from 'node:fs';
import { SF, macToBytes, macToString, type BatchHeader, type DecodedBatch } from './codec.js';

// ── Records (one JSON line each) ─────────────────────────────────────

/** Which rule placed a sample in time (docs/TEMP-LOGGER.md, "Placing samples in time"). */
export type Anchor = 'receipt' | 'epoch' | 'unplaced';

/** The first batch this bridge saw from a log: its pointer starts at firstSeq - 1. */
export interface StartRecord {
  kind: 'start';
  mac: string;
  logId: string;
  firstSeq: number;
  receivedUnixS: number;
}

export interface SampleRecord {
  kind: 'sample';
  mac: string;
  /** 8 lowercase hex digits */
  logId: string;
  seq: number;
  bootId: number;
  uptimeS: number;
  /** centi-°C as sent; -32768 means no reading */
  centiC: number;
  flags: number;
  /** Unix seconds, or null when nothing places the sample */
  tUnix: number | null;
  anchor: Anchor;
  /** the safe band the node judged this sample against, inclusive */
  policyMinCenti: number;
  policyMaxCenti: number;
  receivedUnixS: number;
}

/** The node overwrote fromSeq..throughSeq before any host acknowledged them. */
export interface LossRecord {
  kind: 'loss';
  mac: string;
  logId: string;
  /** null when the loss began before this bridge first saw the log */
  fromSeq: number | null;
  throughSeq: number;
  /** seqs in the range this bridge does not hold; null when fromSeq is */
  missing: number | null;
  receivedUnixS: number;
}

export type JournalRecord = StartRecord | SampleRecord | LossRecord;

// ── Results ──────────────────────────────────────────────────────────

export interface AckToSend {
  mac: string;
  ackedThrough: number;
  hostUnixS: number;
}

export interface IngestResult {
  mac: string;
  logId: number;
  /** the first batch this bridge has seen from this log */
  firstContact: boolean;
  newSamples: SampleRecord[];
  duplicates: number;
  loss: LossRecord | null;
  /** through before this batch; null on first contact */
  previousThrough: number | null;
  through: number;
  /** the highest seq held above `through` — a gap the ack asks the node to replay — else null */
  heldAbove: number | null;
  ack: AckToSend;
}

/** Where records go. `append` must be durable when it returns, and throw when it is not. */
export interface Journal {
  append(text: string): void;
  close?(): void;
}

export interface LogSummary {
  mac: string;
  logId: number;
  through: number;
  held: number;
  heldAbove: number | null;
}

// ── The pure part ────────────────────────────────────────────────────

interface LogState {
  mac: string;
  logId: number;
  through: number;
  seen: Set<number>;
  maxSeq: number;
}

export const logIdHex = (logId: number) => (logId >>> 0).toString(16).padStart(8, '0');
const keyOf = (mac: string, logIdHexStr: string) => `${mac}/${logIdHexStr}`;

function anchorOf(h: BatchHeader, nowUnixS: number): { rule: Anchor; epoch: number | null } {
  if (h.bootId === h.bootNow) return { rule: 'receipt', epoch: nowUnixS - h.uptimeNowS };
  if (h.bootEpochS !== 0) return { rule: 'epoch', epoch: h.bootEpochS };
  return { rule: 'unplaced', epoch: null };
}

interface Plan {
  records: JournalRecord[];
  added: number[];
  maxSeq: number;
  result: IngestResult;
}

/** What one batch changes. Reads `prev`, mutates nothing. */
function planBatch(prev: LogState | undefined, mac: string, batch: DecodedBatch, nowUnixS: number): Plan {
  const h = batch.header;
  const logId = logIdHex(h.logId);
  const seen: ReadonlySet<number> = prev?.seen ?? new Set<number>();
  const firstContact = prev === undefined;
  let through = prev ? prev.through : Math.max(h.firstSeq - 1, 0);
  const records: JournalRecord[] = [];
  if (firstContact) records.push({ kind: 'start', mac, logId, firstSeq: h.firstSeq, receivedUnixS: nowUnixS });

  const inBatch = new Set(batch.samples.map((s) => s.seq));
  let loss: LossRecord | null = null;
  if (h.lostThrough > through) {
    // Count what is held in the range by walking what is held, not the range:
    // an unsigned batch can claim any lost_through, up to 2^32 - 1.
    let held = 0;
    for (const q of seen) if (q > through && q <= h.lostThrough) held++;
    for (const q of inBatch) if (q > through && q <= h.lostThrough && !seen.has(q)) held++;
    loss = {
      kind: 'loss',
      mac,
      logId,
      fromSeq: through + 1,
      throughSeq: h.lostThrough,
      missing: h.lostThrough - through - held,
      receivedUnixS: nowUnixS,
    };
    through = h.lostThrough;
  } else if (firstContact && h.lostThrough > 0) {
    // The node wrapped before this bridge ever heard from it. Where the loss
    // began is unknowable from here, but that it happened is not.
    loss = { kind: 'loss', mac, logId, fromSeq: null, throughSeq: h.lostThrough, missing: null, receivedUnixS: nowUnixS };
  }
  if (loss) records.push(loss);

  const anchor = anchorOf(h, nowUnixS);
  const added: number[] = [];
  const addedSet = new Set<number>();
  const newSamples: SampleRecord[] = [];
  let duplicates = 0;
  for (const s of batch.samples) {
    if (seen.has(s.seq) || addedSet.has(s.seq)) {
      duplicates++;
      continue;
    }
    addedSet.add(s.seq);
    added.push(s.seq);
    // A lost-record placeholder's uptime is a 0 filler, not a reading of the
    // clock, so it has no time to place.
    const placed = anchor.epoch !== null && (s.flags & SF.RECORD_LOST) === 0;
    newSamples.push({
      kind: 'sample',
      mac,
      logId,
      seq: s.seq,
      bootId: h.bootId,
      uptimeS: s.uptimeS,
      centiC: s.centiC,
      flags: s.flags,
      tUnix: placed ? anchor.epoch! + s.uptimeS : null,
      anchor: placed ? anchor.rule : 'unplaced',
      policyMinCenti: h.policyMinCenti,
      policyMaxCenti: h.policyMaxCenti,
      receivedUnixS: nowUnixS,
    });
  }
  records.push(...newSamples);

  while (seen.has(through + 1) || addedSet.has(through + 1)) through++;
  const maxSeq = added.reduce((m, q) => Math.max(m, q), prev?.maxSeq ?? 0);

  return {
    records,
    added,
    maxSeq,
    result: {
      mac,
      logId: h.logId,
      firstContact,
      newSamples,
      duplicates,
      loss,
      previousThrough: prev ? prev.through : null,
      through,
      heldAbove: maxSeq > through ? maxSeq : null,
      ack: { mac, ackedThrough: through, hostUnixS: Math.min(nowUnixS, 0xffffffff) },
    },
  };
}

// ── Rebuilding from the journal ──────────────────────────────────────

const MAC_RE = /^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$/;
const LOG_RE = /^[0-9a-f]{8}$/;
const isCount = (v: unknown): v is number => typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= 0xffffffff;

function asRecord(v: unknown): JournalRecord | null {
  if (typeof v !== 'object' || v === null) return null;
  const r = v as Record<string, unknown>;
  if (typeof r.mac !== 'string' || !MAC_RE.test(r.mac)) return null;
  if (typeof r.logId !== 'string' || !LOG_RE.test(r.logId)) return null;
  if (r.kind === 'start' && isCount(r.firstSeq)) return r as unknown as StartRecord;
  if (r.kind === 'sample' && isCount(r.seq)) return r as unknown as SampleRecord;
  if (r.kind === 'loss' && isCount(r.throughSeq)) return r as unknown as LossRecord;
  return null;
}

/**
 * `through` after any sequence of batches is the least seq that is at least
 * the log's start and every loss it reported, with nothing held just above
 * it — so it can be recomputed from the start, the losses and the held seqs,
 * whatever order they were written in.
 */
function rebuild(lines: Iterable<string>): { logs: Map<string, LogState>; skipped: number } {
  interface Acc {
    mac: string;
    logId: number;
    start?: number;
    firstSampleSeq?: number;
    lossMax: number;
    seen: Set<number>;
    maxSeq: number;
  }
  const accs = new Map<string, Acc>();
  let skipped = 0;
  for (const line of lines) {
    if (line.trim() === '') continue;
    let rec: JournalRecord | null;
    try {
      rec = asRecord(JSON.parse(line));
    } catch {
      rec = null;
    }
    if (!rec) {
      skipped++;
      continue;
    }
    const key = keyOf(rec.mac, rec.logId);
    let acc = accs.get(key);
    if (!acc) {
      acc = { mac: rec.mac, logId: parseInt(rec.logId, 16), lossMax: 0, seen: new Set(), maxSeq: 0 };
      accs.set(key, acc);
    }
    if (rec.kind === 'start') acc.start ??= Math.max(rec.firstSeq - 1, 0);
    else if (rec.kind === 'sample') {
      acc.seen.add(rec.seq);
      acc.firstSampleSeq ??= rec.seq;
      acc.maxSeq = Math.max(acc.maxSeq, rec.seq);
    } else acc.lossMax = Math.max(acc.lossMax, rec.throughSeq);
  }
  const logs = new Map<string, LogState>();
  for (const [key, a] of accs) {
    // A start line is always written with a log's first batch; the fallbacks
    // only matter for a journal edited by hand.
    const start = a.start ?? (a.firstSampleSeq !== undefined ? a.firstSampleSeq - 1 : a.lossMax);
    let through = Math.max(start, a.lossMax);
    while (a.seen.has(through + 1)) through++;
    logs.set(key, { mac: a.mac, logId: a.logId, through, seen: a.seen, maxSeq: a.maxSeq });
  }
  return { logs, skipped };
}

// ── The file journal ─────────────────────────────────────────────────

class FileJournal implements Journal {
  private fd: number | null;

  constructor(path: string) {
    this.fd = openSync(path, 'a');
  }

  append(text: string): void {
    if (this.fd === null) throw new Error('the journal is closed');
    const buf = Buffer.from(text, 'utf8');
    let off = 0;
    while (off < buf.length) off += writeSync(this.fd, buf, off, buf.length - off);
    fsyncSync(this.fd);
  }

  close(): void {
    if (this.fd !== null) closeSync(this.fd);
    this.fd = null;
  }
}

// ── The store ────────────────────────────────────────────────────────

export class TempLogStore {
  /** journal lines that could not be read back (a torn last line, say) */
  readonly skippedLines: number;
  readonly path: string | null;
  private readonly logs: Map<string, LogState>;
  private readonly journal: Journal | null;

  constructor(opts: { journal?: Journal | null; lines?: Iterable<string>; path?: string | null } = {}) {
    const { logs, skipped } = rebuild(opts.lines ?? []);
    this.logs = logs;
    this.skippedLines = skipped;
    this.journal = opts.journal ?? null;
    this.path = opts.path ?? null;
  }

  /** A store backed by a JSONL file, rebuilt from whatever the file already holds. */
  static open(path: string): TempLogStore {
    const text = existsSync(path) ? readFileSync(path, 'utf8') : '';
    const journal = new FileJournal(path);
    // A torn last line stays in the file, but on a line of its own, so the
    // next record is not glued to it.
    if (text.length > 0 && !text.endsWith('\n')) journal.append('\n');
    return new TempLogStore({ journal, lines: text.split('\n'), path });
  }

  /** A store that keeps nothing on disk. */
  static inMemory(): TempLogStore {
    return new TempLogStore();
  }

  /**
   * Take one decoded batch from `mac`, heard at `nowUnixS`. The new records
   * are written before this returns, and the returned ack is the one to send.
   * If the write fails this throws, and nothing is committed or acked.
   */
  ingest(mac: string, batch: DecodedBatch, nowUnixS: number): IngestResult {
    if (!Number.isFinite(nowUnixS) || nowUnixS < 0) throw new RangeError(`nowUnixS must be Unix seconds, got ${nowUnixS}`);
    const canon = macToString(macToBytes(mac));
    const key = keyOf(canon, logIdHex(batch.header.logId));
    const prev = this.logs.get(key);
    const plan = planBatch(prev, canon, batch, Math.floor(nowUnixS));

    if (plan.records.length > 0 && this.journal) {
      this.journal.append(plan.records.map((r) => JSON.stringify(r)).join('\n') + '\n');
    }

    const st = prev ?? { mac: canon, logId: batch.header.logId, through: 0, seen: new Set<number>(), maxSeq: 0 };
    for (const q of plan.added) st.seen.add(q);
    st.through = plan.result.through;
    st.maxSeq = plan.maxSeq;
    this.logs.set(key, st);
    return plan.result;
  }

  /** The acked-through point for a log, or undefined if the bridge has never seen it. */
  through(mac: string, logId: number): number | undefined {
    return this.logs.get(keyOf(macToString(macToBytes(mac)), logIdHex(logId)))?.through;
  }

  /** Every log the store knows, for status lines. */
  summary(): LogSummary[] {
    return [...this.logs.values()].map((s) => ({
      mac: s.mac,
      logId: s.logId,
      through: s.through,
      held: s.seen.size,
      heldAbove: s.maxSeq > s.through ? s.maxSeq : null,
    }));
  }

  close(): void {
    this.journal?.close?.();
  }
}
