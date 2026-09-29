/**
 * store.test.ts — the bridge's delivery state machine and its JSONL record.
 *
 * `through` is the host's claim that it holds every seq up to that point; the
 * ack sends it to the node, which may then let those readings go. These tests
 * pin when it may move (contiguous delivery, a reported loss) and when it must
 * not (a gap), how each sample is placed in time, and that a restart from the
 * JSONL picks up exactly where the last run stopped.
 *
 * Run: bun test tools/templog-bridge/store.test.ts
 */
import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { appendFileSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SF, TEMP_INVALID, type BatchHeader, type BatchSample, type DecodedBatch } from './codec.js';
import { TempLogStore, type IngestResult, type Journal, type JournalRecord } from './store.js';

const MAC = '58:e6:c5:1a:8b:28';
const LOG = 0xa1b2c3d4;
const LOG_HEX = 'a1b2c3d4';
const T0 = 1_790_000_000;

/**
 * A decoded batch of `n` samples starting at `firstSeq`, one a minute, all in
 * boot 1 which is also the node's current boot (so they anchor by receipt).
 */
function batch(
  firstSeq: number,
  n: number,
  over: Partial<BatchHeader> = {},
  sample: (seq: number) => Partial<BatchSample> = () => ({}),
): DecodedBatch {
  const header: BatchHeader = {
    version: 0,
    flags: 0,
    count: n,
    firstSeq,
    bootId: 1,
    bootNow: 1,
    uptimeNowS: 60 * (firstSeq + n),
    bootEpochS: 0,
    lostThrough: 0,
    sampleIntervalS: 60,
    policyMinCenti: -200,
    policyMaxCenti: 2800,
    logId: LOG,
    ...over,
  };
  const samples = Array.from({ length: n }, (_, i) => {
    const seq = firstSeq + i;
    return { seq, uptimeS: 60 * seq, centiC: 400 + i, flags: 0, ...sample(seq) };
  });
  return { header, samples };
}

const range = (a: number, b: number) => Array.from({ length: b - a + 1 }, (_, i) => a + i);
const seqs = (r: IngestResult) => r.newSamples.map((s) => s.seq);

// ── Delivery ─────────────────────────────────────────────────────────

describe('delivery', () => {
  test('the first batch starts the log at first_seq - 1 and acks all of it', () => {
    const s = TempLogStore.inMemory();
    const r = s.ingest(MAC, batch(100, 5), T0);
    expect(r.firstContact).toBe(true);
    expect(r.previousThrough).toBeNull();
    expect(seqs(r)).toEqual(range(100, 104));
    expect(r.duplicates).toBe(0);
    expect(r.through).toBe(104);
    expect(r.loss).toBeNull();
    expect(r.heldAbove).toBeNull();
    expect(r.ack).toEqual({ mac: MAC, ackedThrough: 104, hostUnixS: T0 });
    expect(s.through(MAC, LOG)).toBe(104);
  });

  test('a duplicate batch stores nothing and acks the same point again, at the new time', () => {
    const s = TempLogStore.inMemory();
    s.ingest(MAC, batch(100, 5), T0);
    const r = s.ingest(MAC, batch(100, 5), T0 + 7);
    expect(r.firstContact).toBe(false);
    expect(r.newSamples).toEqual([]);
    expect(r.duplicates).toBe(5);
    expect(r.previousThrough).toBe(104);
    expect(r.through).toBe(104);
    expect(r.ack).toEqual({ mac: MAC, ackedThrough: 104, hostUnixS: T0 + 7 });
  });

  test('an overlapping batch stores only the samples it has not seen', () => {
    const s = TempLogStore.inMemory();
    s.ingest(MAC, batch(100, 5), T0);
    const r = s.ingest(MAC, batch(102, 7), T0 + 60);
    expect(seqs(r)).toEqual(range(105, 108));
    expect(r.duplicates).toBe(3);
    expect(r.through).toBe(108);
  });

  test('a contiguous batch extends through', () => {
    const s = TempLogStore.inMemory();
    s.ingest(MAC, batch(100, 5), T0);
    const r = s.ingest(MAC, batch(105, 5), T0 + 300);
    expect(seqs(r)).toEqual(range(105, 109));
    expect(r.through).toBe(109);
    expect(r.ack.ackedThrough).toBe(109);
  });

  test('a gap keeps what arrived but leaves through where it was, so the ack asks for a replay', () => {
    const s = TempLogStore.inMemory();
    s.ingest(MAC, batch(100, 5), T0);
    const r = s.ingest(MAC, batch(110, 5), T0 + 600);
    expect(seqs(r)).toEqual(range(110, 114)); // stored, not dropped
    expect(r.through).toBe(104);
    expect(r.ack.ackedThrough).toBe(104);
    expect(r.heldAbove).toBe(114);
    expect(r.loss).toBeNull();
  });

  test('the replay fills the gap and through jumps past what was already held', () => {
    const s = TempLogStore.inMemory();
    s.ingest(MAC, batch(100, 5), T0);
    s.ingest(MAC, batch(110, 5), T0 + 600);
    const r = s.ingest(MAC, batch(105, 10), T0 + 610);
    expect(seqs(r)).toEqual(range(105, 109));
    expect(r.duplicates).toBe(5);
    expect(r.previousThrough).toBe(104);
    expect(r.through).toBe(114);
    expect(r.heldAbove).toBeNull();
  });

  test('lost_through beyond through is a loss event, and through moves to it', () => {
    const s = TempLogStore.inMemory();
    s.ingest(MAC, batch(100, 5), T0);
    const r = s.ingest(MAC, batch(301, 3, { lostThrough: 300 }), T0 + 9000);
    expect(r.loss).toEqual({
      kind: 'loss',
      mac: MAC,
      logId: LOG_HEX,
      fromSeq: 105,
      throughSeq: 300,
      missing: 196,
      receivedUnixS: T0 + 9000,
    });
    expect(seqs(r)).toEqual(range(301, 303));
    expect(r.through).toBe(303);
    expect(r.ack.ackedThrough).toBe(303);
  });

  test('a loss counts only the seqs the bridge does not already hold', () => {
    const s = TempLogStore.inMemory();
    s.ingest(MAC, batch(100, 5), T0);
    s.ingest(MAC, batch(110, 5), T0 + 600); // held above a gap
    const r = s.ingest(MAC, batch(301, 1, { lostThrough: 300 }), T0 + 9000);
    expect(r.loss?.fromSeq).toBe(105);
    expect(r.loss?.missing).toBe(196 - 5);
    expect(r.through).toBe(301);
  });

  test('lost_through at or below through is old news, not a new loss', () => {
    const s = TempLogStore.inMemory();
    s.ingest(MAC, batch(100, 5), T0);
    const r = s.ingest(MAC, batch(105, 5, { lostThrough: 104 }), T0 + 300);
    expect(r.loss).toBeNull();
    expect(r.through).toBe(109);
  });

  test('a node that wrapped before the bridge first saw it reports the loss on first contact, once', () => {
    const s = TempLogStore.inMemory();
    const r = s.ingest(MAC, batch(257, 5, { lostThrough: 256 }), T0);
    expect(r.loss).toEqual({
      kind: 'loss',
      mac: MAC,
      logId: LOG_HEX,
      fromSeq: null, // where the loss began is from before this bridge's time
      throughSeq: 256,
      missing: null,
      receivedUnixS: T0,
    });
    expect(r.through).toBe(261);
    const again = s.ingest(MAC, batch(257, 5, { lostThrough: 256 }), T0 + 5);
    expect(again.loss).toBeNull();
  });

  test('a lost-record placeholder counts toward through like any sample', () => {
    const s = TempLogStore.inMemory();
    const lost = (seq: number) =>
      seq === 102 ? { uptimeS: 0, centiC: TEMP_INVALID, flags: SF.RECORD_LOST | SF.SENSOR_ERROR } : {};
    const r = s.ingest(MAC, batch(100, 5, {}, lost), T0);
    expect(r.through).toBe(104);
    const placeholder = r.newSamples.find((x) => x.seq === 102)!;
    expect(placeholder.centiC).toBe(TEMP_INVALID);
    expect(placeholder.flags).toBe(SF.RECORD_LOST | SF.SENSOR_ERROR);
  });

  test('two logs of one node, and two nodes, are kept apart', () => {
    const s = TempLogStore.inMemory();
    const OTHER = '58:e6:c5:1a:8b:29';
    s.ingest(MAC, batch(100, 5), T0);
    const newLog = s.ingest(MAC, batch(1, 3, { logId: 0x01020304 }), T0 + 1);
    const otherNode = s.ingest(OTHER, batch(100, 2), T0 + 2);
    expect(newLog.firstContact).toBe(true);
    expect(newLog.through).toBe(3);
    expect(otherNode.firstContact).toBe(true);
    expect(otherNode.through).toBe(101);
    expect(s.through(MAC, LOG)).toBe(104);
    expect(s.through(MAC, 0x01020304)).toBe(3);
    expect(s.through(OTHER, LOG)).toBe(101);
  });
});

// ── Placing samples in time ──────────────────────────────────────────

describe('placing samples in time', () => {
  test('same boot: the boot began at receipt - uptime_now_s', () => {
    const s = TempLogStore.inMemory();
    const r = s.ingest(MAC, batch(100, 2, { bootId: 5, bootNow: 5, uptimeNowS: 7200 }), T0);
    expect(r.newSamples.map((x) => [x.anchor, x.tUnix])).toEqual([
      ['receipt', T0 - 7200 + 6000],
      ['receipt', T0 - 7200 + 6060],
    ]);
  });

  test('same boot wins even when the node also knows the epoch', () => {
    const s = TempLogStore.inMemory();
    const r = s.ingest(MAC, batch(100, 1, { bootId: 5, bootNow: 5, uptimeNowS: 7200, bootEpochS: 1_700_000_000 }), T0);
    expect(r.newSamples[0].anchor).toBe('receipt');
    expect(r.newSamples[0].tUnix).toBe(T0 - 7200 + 6000);
  });

  test('an earlier boot whose start the node learned is placed from boot_epoch_s', () => {
    const s = TempLogStore.inMemory();
    const r = s.ingest(MAC, batch(100, 2, { bootId: 3, bootNow: 4, bootEpochS: 1_789_990_000 }), T0);
    expect(r.newSamples.map((x) => [x.anchor, x.tUnix])).toEqual([
      ['epoch', 1_789_990_000 + 6000],
      ['epoch', 1_789_990_000 + 6060],
    ]);
  });

  test('an earlier boot with no epoch is kept, unplaced, and still moves through', () => {
    const s = TempLogStore.inMemory();
    const r = s.ingest(MAC, batch(100, 2, { bootId: 3, bootNow: 4, bootEpochS: 0 }), T0);
    expect(r.newSamples.map((x) => [x.anchor, x.tUnix])).toEqual([
      ['unplaced', null],
      ['unplaced', null],
    ]);
    expect(r.newSamples.map((x) => x.uptimeS)).toEqual([6000, 6060]); // kept, so a later process could place them
    expect(r.through).toBe(101);
  });

  test('a sample with no reading still has a time; its centi stays -32768', () => {
    const s = TempLogStore.inMemory();
    const r = s.ingest(MAC, batch(100, 1, {}, () => ({ centiC: TEMP_INVALID, flags: SF.SENSOR_ERROR })), T0);
    expect(r.newSamples[0].centiC).toBe(TEMP_INVALID);
    expect(r.newSamples[0].anchor).toBe('receipt');
    expect(r.newSamples[0].tUnix).not.toBeNull();
  });

  test('a lost-record placeholder has no time to place, so it is unplaced', () => {
    // Its uptime is a 0 filler, not a clock reading; placing it would be a guess.
    const s = TempLogStore.inMemory();
    const r = s.ingest(
      MAC,
      batch(100, 1, {}, () => ({ uptimeS: 0, centiC: TEMP_INVALID, flags: SF.RECORD_LOST | SF.SENSOR_ERROR })),
      T0,
    );
    expect(r.newSamples[0].anchor).toBe('unplaced');
    expect(r.newSamples[0].tUnix).toBeNull();
  });

  test('each sample carries the band it was judged against', () => {
    const s = TempLogStore.inMemory();
    const r = s.ingest(MAC, batch(100, 1, { policyMinCenti: 200, policyMaxCenti: 800 }), T0);
    expect(r.newSamples[0].policyMinCenti).toBe(200);
    expect(r.newSamples[0].policyMaxCenti).toBe(800);
  });

  test('the logic takes its clock as an argument and never reads the wall clock', () => {
    const s = TempLogStore.inMemory();
    const realNow = Date.now;
    Date.now = () => {
      throw new Error('the store read Date.now()');
    };
    try {
      const r = s.ingest(MAC, batch(100, 3), T0);
      expect(r.ack.hostUnixS).toBe(T0);
      s.ingest(MAC, batch(103, 3, { bootId: 1, bootNow: 2, bootEpochS: 0 }), T0 + 1);
    } finally {
      Date.now = realNow;
    }
  });
});

// ── Persistence ──────────────────────────────────────────────────────

describe('persistence', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'templog-store-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  const readLines = (path: string) =>
    readFileSync(path, 'utf8')
      .split('\n')
      .filter((l) => l.length > 0);

  test('a start line, then one JSON line per new sample', () => {
    const path = join(dir, 'readings.jsonl');
    const s = TempLogStore.open(path);
    const r = s.ingest(MAC, batch(100, 3, { bootId: 3, bootNow: 4, bootEpochS: 1_789_990_000 }), T0);
    s.close();
    const lines = readLines(path).map((l) => JSON.parse(l) as JournalRecord);
    expect(lines.map((l) => l.kind)).toEqual(['start', 'sample', 'sample', 'sample']);
    expect(lines[0]).toEqual({ kind: 'start', mac: MAC, logId: LOG_HEX, firstSeq: 100, receivedUnixS: T0 });
    expect(lines[1]).toEqual({
      kind: 'sample',
      mac: MAC,
      logId: LOG_HEX,
      seq: 100,
      bootId: 3,
      uptimeS: 6000,
      centiC: 400,
      flags: 0,
      tUnix: 1_789_990_000 + 6000,
      anchor: 'epoch',
      policyMinCenti: -200,
      policyMaxCenti: 2800,
      receivedUnixS: T0,
    });
    expect(lines.slice(1)).toEqual(r.newSamples);
  });

  test('duplicates add no lines; a loss adds one', () => {
    const path = join(dir, 'readings.jsonl');
    const s = TempLogStore.open(path);
    s.ingest(MAC, batch(100, 3), T0);
    s.ingest(MAC, batch(100, 3), T0 + 5);
    expect(readLines(path).length).toBe(4);
    s.ingest(MAC, batch(301, 1, { lostThrough: 300 }), T0 + 9000);
    s.close();
    const kinds = readLines(path).map((l) => (JSON.parse(l) as JournalRecord).kind);
    expect(kinds).toEqual(['start', 'sample', 'sample', 'sample', 'loss', 'sample']);
  });

  test('a restart picks up exactly where the last run stopped', () => {
    // The same deliveries into two stores, one of them restarted halfway:
    // every ack, and the file itself, must come out identical.
    const steps: DecodedBatch[] = [
      batch(100, 5),
      batch(110, 5), // gap
      batch(100, 5), // duplicate
      batch(105, 10), // replay fills the gap
      batch(301, 3, { lostThrough: 300 }), // the node wrapped: loss
      batch(304, 2, { bootId: 1, bootNow: 2, bootEpochS: 0 }), // unplaced
      batch(306, 2, { bootId: 2, bootNow: 2 }),
    ];
    const straightPath = join(dir, 'straight.jsonl');
    const restartedPath = join(dir, 'restarted.jsonl');
    const straight = TempLogStore.open(straightPath);
    const acksStraight = steps.map((b, i) => straight.ingest(MAC, b, T0 + i).ack);
    straight.close();

    let restarted = TempLogStore.open(restartedPath);
    const acksRestarted = steps.map((b, i) => {
      if (i === 2 || i === 5) {
        restarted.close();
        restarted = TempLogStore.open(restartedPath);
      }
      return restarted.ingest(MAC, b, T0 + i).ack;
    });
    restarted.close();

    expect(acksRestarted).toEqual(acksStraight);
    expect(acksStraight.map((a) => a.ackedThrough)).toEqual([104, 104, 104, 114, 303, 305, 307]);
    expect(readFileSync(restartedPath, 'utf8')).toBe(readFileSync(straightPath, 'utf8'));
  });

  test('after a restart the dedupe set is intact and a gap is still a gap', () => {
    const path = join(dir, 'readings.jsonl');
    const first = TempLogStore.open(path);
    first.ingest(MAC, batch(100, 5), T0);
    first.ingest(MAC, batch(110, 5), T0 + 1);
    first.close();

    const s = TempLogStore.open(path);
    expect(s.through(MAC, LOG)).toBe(104);
    const dup = s.ingest(MAC, batch(110, 5), T0 + 2);
    expect(dup.newSamples).toEqual([]);
    expect(dup.firstContact).toBe(false);
    expect(dup.heldAbove).toBe(114);
    expect(dup.ack.ackedThrough).toBe(104);
    const replay = s.ingest(MAC, batch(105, 5), T0 + 3);
    expect(replay.through).toBe(114);
    s.close();
    expect(readLines(path).filter((l) => l.includes('"start"')).length).toBe(1);
  });

  test('a torn last line is skipped, and the next write starts on a line of its own', () => {
    const path = join(dir, 'readings.jsonl');
    const first = TempLogStore.open(path);
    first.ingest(MAC, batch(100, 2), T0);
    first.close();
    appendFileSync(path, '{"kind":"sample","mac":"58:e6'); // the process died mid-write

    const s = TempLogStore.open(path);
    expect(s.skippedLines).toBe(1);
    expect(s.through(MAC, LOG)).toBe(101);
    s.ingest(MAC, batch(102, 2), T0 + 1);
    s.close();

    const again = TempLogStore.open(path);
    expect(again.skippedLines).toBe(1); // still only the torn one
    expect(again.through(MAC, LOG)).toBe(103);
    again.close();
  });

  test('the ack waits for the write: a failed write stores nothing and acks nothing', () => {
    const written: string[] = [];
    let fail = true;
    const journal: Journal = {
      append(text) {
        if (fail) throw new Error('disk full');
        written.push(text);
      },
    };
    const s = new TempLogStore({ journal });
    expect(() => s.ingest(MAC, batch(100, 5), T0)).toThrow('disk full');
    expect(s.through(MAC, LOG)).toBeUndefined();

    fail = false;
    const r = s.ingest(MAC, batch(100, 5), T0 + 1);
    expect(r.firstContact).toBe(true);
    expect(seqs(r)).toEqual(range(100, 104));
    expect(written.join('').split('\n').filter(Boolean).length).toBe(6);
  });

  test('a batch that stores nothing new writes nothing', () => {
    const written: string[] = [];
    const s = new TempLogStore({ journal: { append: (t) => void written.push(t) } });
    s.ingest(MAC, batch(100, 2), T0);
    const before = written.length;
    s.ingest(MAC, batch(100, 2), T0 + 1);
    expect(written.length).toBe(before);
  });
});
