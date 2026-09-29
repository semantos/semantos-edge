/**
 * bridge.test.ts — serial lines in, stored readings and AK lines out.
 *
 * Covers TempLogBridge (what one gateway line does), the --post body, the
 * serial read loop minus the OS (lines split across USB packets), the --sim
 * scenario end to end through the same line handler, and the CLI itself.
 *
 * Run: bun test tools/templog-bridge/bridge.test.ts
 */
import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mintCell } from '../x402-bridge/cell-codec.js';
import { DOMAIN } from '../domains.js';
import {
  SF,
  TEMP_INVALID,
  TYPE_ACK,
  TYPE_BATCH,
  encodeBatch,
  formatTlLine,
  macToBytes,
  type BatchHeaderFields,
  type SampleFields,
} from './codec.js';
import { TempLogStore, type JournalRecord, type SampleRecord } from './store.js';
import { TempLogBridge, httpPoster, pump, splitLines, type PostBody } from './bridge.js';
import { SimWorld, runScenario } from './sim.js';

const MAC = '58:e6:c5:1a:8b:28';
const LOG = 0xa1b2c3d4;
const T0 = 1_790_000_000;

const HEADER: BatchHeaderFields = {
  firstSeq: 100,
  bootId: 3,
  bootNow: 3,
  uptimeNowS: 7200,
  bootEpochS: 0,
  lostThrough: 0,
  sampleIntervalS: 60,
  policyMinCenti: -200,
  policyMaxCenti: 2800,
  logId: LOG,
};

const TWO_SAMPLES: SampleFields[] = [
  { uptimeS: 6000, centiC: 2506, flags: 0 },
  { uptimeS: 6060, centiC: 3100, flags: SF.POLICY_REJECT },
];

/** The TL line a gateway would print for a batch cell built from these parts. */
function tlLine(
  opts: {
    header?: Partial<BatchHeaderFields>;
    samples?: SampleFields[];
    owner?: string;
    from?: string;
    type?: Uint8Array;
    payload?: (p: Uint8Array) => void;
    cell?: (c: Uint8Array) => void;
  } = {},
): string {
  const payload = encodeBatch({ ...HEADER, ...opts.header }, opts.samples ?? TWO_SAMPLES);
  opts.payload?.(payload); // before minting: domain_payload_root still matches
  const owner = new Uint8Array(16);
  owner.set(macToBytes(opts.owner ?? MAC));
  const cell = mintCell(opts.type ?? TYPE_BATCH, payload, owner, 1n, DOMAIN.meshTelemetry);
  opts.cell?.(cell); // after minting: the TL CRC still holds, the cell's own checks may not
  return formatTlLine(opts.from ?? MAC, cell).trimEnd();
}

function harness(opts: { store?: TempLogStore; post?: (b: PostBody) => Promise<void>; now?: () => number } = {}) {
  const logs: string[] = [];
  const store = opts.store ?? TempLogStore.inMemory();
  const bridge = new TempLogBridge({ store, now: opts.now ?? (() => T0), log: (m) => logs.push(m), post: opts.post });
  return { bridge, store, logs };
}

const range = (a: number, b: number) => Array.from({ length: b - a + 1 }, (_, i) => a + i);

// ── One line at a time ───────────────────────────────────────────────

describe('a serial line in, an AK line out', () => {
  test('a batch is stored, then acked with the bare MAC, through and the host clock', () => {
    const { bridge, store, logs } = harness();
    expect(bridge.handleLine(tlLine())).toBe('AK 58e6c51a8b28 101 1790000000\n');
    expect(store.through(MAC, LOG)).toBe(101);
    expect(logs).toHaveLength(1);
    for (const part of [MAC, 'log a1b2c3d4', 'seqs 100..101', '2 new, 0 dup', 'through 101', 'lost none', 'unplaced 0', 'AK 101']) {
      expect(logs[0]).toContain(part);
    }
  });

  test('the per-batch line names out-of-band readings, gaps, losses and unplaced samples', () => {
    const { bridge, logs } = harness();
    bridge.handleLine(tlLine());
    expect(logs[0]).toContain('1 out of band');
    bridge.handleLine(tlLine({ header: { firstSeq: 110 } })); // gap above 101
    expect(logs[1]).toContain('through 101');
    expect(logs[1]).toContain('gap');
    bridge.handleLine(tlLine({ header: { firstSeq: 301, lostThrough: 300, bootId: 2, bootNow: 3 } }));
    expect(logs[2]).toContain('lost 102..300');
    expect(logs[2]).toContain('unplaced 2');
  });

  test('ESP-IDF log lines are ignored without a word', () => {
    const { bridge, logs } = harness();
    for (const l of ['I (1234) temp_logger: gateway up. mac=58:e6:c5:1a:8b:28 — TL lines out, AK lines in', '', 'ESP-ROM:esp32c6-20220919']) {
      expect(bridge.handleLine(l)).toBeNull();
    }
    expect(logs).toEqual([]);
  });

  test('a TL line whose CRC fails is logged, not stored and not acked', () => {
    const { bridge, store, logs } = harness();
    const line = tlLine();
    const bad = line.slice(0, -1) + (line.endsWith('0') ? '1' : '0');
    expect(bridge.handleLine(bad)).toBeNull();
    expect(store.through(MAC, LOG)).toBeUndefined();
    expect(logs.join('\n')).toContain('CRC');
  });

  test('a batch whose owner is not the radio sender is not stored or acked', () => {
    const { bridge, store, logs } = harness();
    expect(bridge.handleLine(tlLine({ owner: '58:e6:c5:1a:8b:29' }))).toBeNull();
    expect(store.through(MAC, LOG)).toBeUndefined();
    expect(store.through('58:e6:c5:1a:8b:29', LOG)).toBeUndefined();
    expect(logs.join('\n')).toContain('58:e6:c5:1a:8b:29');
  });

  test('a payload that no longer matches domain_payload_root is not stored or acked', () => {
    const { bridge, store, logs } = harness();
    expect(bridge.handleLine(tlLine({ cell: (c) => (c[256 + 40 + 4] ^= 1) }))).toBeNull();
    expect(store.through(MAC, LOG)).toBeUndefined();
    expect(logs.join('\n')).toContain('domain_payload_root');
  });

  test('a cell that is not a templog batch is ignored', () => {
    const { bridge, store, logs } = harness();
    expect(bridge.handleLine(tlLine({ type: TYPE_ACK }))).toBeNull();
    expect(store.through(MAC, LOG)).toBeUndefined();
    expect(logs).toHaveLength(1);
  });

  test('a batch that does not decode is logged and not acked', () => {
    const { bridge, store, logs } = harness();
    const badVersion = tlLine({ payload: (p) => (p[0] = 1) });
    // payload_total says 40 bytes: too short for the two samples the header counts.
    const shortTotal = tlLine({ cell: (c) => ((c[90] = 40), (c[91] = 0), (c[92] = 0), (c[93] = 0)) });
    for (const line of [badVersion, shortTotal]) expect(bridge.handleLine(line)).toBeNull();
    expect(store.through(MAC, LOG)).toBeUndefined();
    expect(logs).toHaveLength(2);
  });

  test('a batch the store cannot write is logged and not acked', () => {
    const store = new TempLogStore({
      journal: {
        append() {
          throw new Error('disk full');
        },
      },
    });
    const { bridge, logs } = harness({ store });
    expect(bridge.handleLine(tlLine())).toBeNull();
    expect(logs.join('\n')).toContain('disk full');
  });

  test('the ack carries the clock at receipt', () => {
    let now = T0;
    const { bridge } = harness({ now: () => now });
    bridge.handleLine(tlLine());
    now = T0 + 42;
    expect(bridge.handleLine(tlLine())).toBe('AK 58e6c51a8b28 101 1790000042\n');
  });
});

// ── --post ───────────────────────────────────────────────────────────

describe('--post', () => {
  test('posts the new samples in the agreed shape, and only after the ack is out', async () => {
    const posted: PostBody[] = [];
    const { bridge } = harness({ post: async (b) => void posted.push(b) });
    const ak = bridge.handleLine(tlLine({ header: { bootId: 2, bootNow: 3, bootEpochS: 1_789_990_000 } }));
    expect(ak).toBe('AK 58e6c51a8b28 101 1790000000\n');
    expect(posted).toHaveLength(0); // the ack is returned first; the POST starts after
    await bridge.settle();
    expect(posted).toHaveLength(1);
    expect(JSON.stringify(posted[0])).toBe(
      JSON.stringify({
        mac: '58:e6:c5:1a:8b:28',
        logId: 'a1b2c3d4',
        lostThrough: 0,
        samples: [
          { seq: 100, bootId: 2, uptimeS: 6000, centiC: 2506, flags: 0, tUnix: 1_789_996_000, anchor: 'epoch' },
          { seq: 101, bootId: 2, uptimeS: 6060, centiC: 3100, flags: 1, tUnix: 1_789_996_060, anchor: 'epoch' },
        ],
      }),
    );
  });

  test("sends -32768 untouched, a null tUnix when unplaced, and the header's lost_through", async () => {
    const posted: PostBody[] = [];
    const { bridge } = harness({ post: async (b) => void posted.push(b) });
    bridge.handleLine(
      tlLine({
        header: { bootId: 2, bootNow: 3, bootEpochS: 0, lostThrough: 50 },
        samples: [{ uptimeS: 60, centiC: TEMP_INVALID, flags: SF.SENSOR_ERROR }],
      }),
    );
    await bridge.settle();
    expect(posted[0].lostThrough).toBe(50);
    expect(posted[0].samples).toEqual([{ seq: 100, bootId: 2, uptimeS: 60, centiC: -32768, flags: SF.SENSOR_ERROR, tUnix: null, anchor: 'unplaced' }]);
  });

  test('posts nothing for a batch that was all duplicates', async () => {
    const posted: PostBody[] = [];
    const { bridge } = harness({ post: async (b) => void posted.push(b) });
    bridge.handleLine(tlLine());
    bridge.handleLine(tlLine());
    await bridge.settle();
    expect(posted).toHaveLength(1);
  });

  test('a failed POST is logged and never blocks the ack', async () => {
    const failures = [
      async () => {
        throw new Error('HTTP 503 Service Unavailable');
      },
      () => {
        throw new Error('fetch failed: connection refused'); // even a synchronous throw
      },
    ];
    for (const post of failures) {
      const { bridge, logs } = harness({ post: post as () => Promise<void> });
      expect(bridge.handleLine(tlLine())).toBe('AK 58e6c51a8b28 101 1790000000\n');
      await bridge.settle();
      expect(logs.some((l) => l.includes('POST') && (l.includes('503') || l.includes('connection refused')))).toBe(true);
    }
  });

  test('httpPoster sends JSON and treats a non-2xx answer as a failure', async () => {
    const received: { type: string | null; body: unknown }[] = [];
    let status = 200;
    const server = Bun.serve({
      port: 0,
      async fetch(req) {
        received.push({ type: req.headers.get('content-type'), body: await req.json() });
        return new Response(status === 200 ? 'ok' : 'nope', { status });
      },
    });
    try {
      const post = httpPoster(`http://127.0.0.1:${server.port}/readings`);
      const body: PostBody = { mac: MAC, logId: 'a1b2c3d4', lostThrough: 0, samples: [] };
      await post(body);
      expect(received).toEqual([{ type: 'application/json', body }]);
      status = 503;
      await expect(post(body)).rejects.toThrow('503');
    } finally {
      server.stop(true);
    }
  });
});

// ── The serial read loop, minus the OS ───────────────────────────────

describe('the serial path', () => {
  async function* chunked(text: string, size: number): AsyncGenerator<Uint8Array> {
    const bytes = new TextEncoder().encode(text);
    for (let i = 0; i < bytes.length; i += size) yield bytes.subarray(i, i + size);
  }

  test('lines split across 64-byte USB packets are put back together, and each AK goes to the port', async () => {
    const { bridge } = harness();
    const text = `I (10) temp_logger: gateway up\r\n${tlLine()}\r\nI (12) temp_logger: RX batch\r\n${tlLine({ header: { firstSeq: 102 } })}\n`;
    const writes: string[] = [];
    const acks = await pump(splitLines(chunked(text, 64)), bridge, (s) => writes.push(s));
    expect(acks).toBe(2);
    expect(writes).toEqual(['AK 58e6c51a8b28 101 1790000000\n', 'AK 58e6c51a8b28 103 1790000000\n']);
  });

  test('a last line with no newline is still read when the port closes', async () => {
    const { bridge } = harness();
    const writes: string[] = [];
    await pump(splitLines(chunked(tlLine(), 100)), bridge, (s) => writes.push(s));
    expect(writes).toEqual(['AK 58e6c51a8b28 101 1790000000\n']);
  });

  test('a multi-byte character split across packets is decoded whole', async () => {
    const lines: string[] = [];
    // '→' is bytes 26..28, so a 27-byte packet ends inside it.
    for await (const l of splitLines(chunked('I (1) temp_logger: TX ack → 58:e6\nnext\n', 27))) lines.push(l);
    expect(lines).toEqual(['I (1) temp_logger: TX ack → 58:e6', 'next']);
  });
});

// ── --sim ────────────────────────────────────────────────────────────

describe('--sim', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'templog-bridge-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  const SIM_MAC = '02:00:5e:c0:1d:01';
  const SIM_LOG = 0x3f2a9c01;
  const records = (path: string) =>
    readFileSync(path, 'utf8')
      .split('\n')
      .filter(Boolean)
      .map((l) => JSON.parse(l) as JournalRecord);

  test('a synthetic node: first contact, a lost ack, a gap, two reboots and a wrap, all through handleLine', () => {
    const path = join(dir, 'sim.jsonl');
    const store = TempLogStore.open(path);
    const world = new SimWorld({ startUnixS: T0, mac: SIM_MAC, logId: SIM_LOG });
    const logs: string[] = [];
    const bridge = new TempLogBridge({ store, now: () => world.nowUnixS, log: (m) => logs.push(m) });
    const report = runScenario(world, bridge, (m) => logs.push(m));
    store.close();

    expect(report.lastSeq).toBe(625);
    expect(report.acksLost).toBe(1);
    expect(report.nodeAckedThrough).toBe(625); // the node let go of everything
    expect(store.through(SIM_MAC, SIM_LOG)).toBe(625);
    expect(logs.some((l) => l.includes('0 new, 5 dup'))).toBe(true); // the duplicate
    expect(logs.some((l) => l.includes('gap'))).toBe(true); // the gap, then its replay
    expect(logs.some((l) => l.includes('5 new, 5 dup') && l.includes('through 20'))).toBe(true);

    const recs = records(path);
    const samples = recs.filter((r): r is SampleRecord => r.kind === 'sample');
    expect(samples.map((s) => s.seq).sort((a, b) => a - b)).toEqual([...range(1, 25), ...range(257, 625)]);
    expect(recs.filter((r) => r.kind === 'start')).toHaveLength(1);
    expect(recs.filter((r) => r.kind === 'loss').map((r) => [r.kind === 'loss' && r.fromSeq, r.kind === 'loss' && r.throughSeq, r.kind === 'loss' && r.missing])).toEqual([[26, 256, 231]]);

    // All three placing rules happen, each where the scenario says it should.
    const bySeq = new Map(samples.map((s) => [s.seq, s]));
    expect([21, 22].map((q) => bySeq.get(q)!.anchor)).toEqual(['epoch', 'epoch']); // boot 1, learned from an ack
    expect([23, 24].map((q) => bySeq.get(q)!.anchor)).toEqual(['unplaced', 'unplaced']); // boot 2 never heard an ack
    expect(bySeq.get(25)!.anchor).toBe('receipt');
    expect(bySeq.get(report.burnedSeq)!.flags).toBe(SF.RECORD_LOST | SF.SENSOR_ERROR);
    expect(bySeq.get(report.burnedSeq)!.anchor).toBe('unplaced');
    expect(samples.some((s) => s.flags & SF.POLICY_REJECT)).toBe(true);
    expect(samples.some((s) => s.flags === SF.SENSOR_ERROR && s.centiC === TEMP_INVALID)).toBe(true);

    // Every placed sample lands on the second it was really taken.
    const placed = samples.filter((s) => s.tUnix !== null);
    expect(placed.length).toBe(samples.length - 3);
    for (const s of placed) expect(s.tUnix).toBe(report.truth.get(s.seq)!);

    // And a restart reads the same state back.
    expect(TempLogStore.open(path).through(SIM_MAC, SIM_LOG)).toBe(625);
  });

  test('the CLI runs the sim end to end', () => {
    const path = join(dir, 'cli-sim.jsonl');
    const run = Bun.spawnSync([process.execPath, join(import.meta.dir, 'bridge.ts'), '--sim', '--out', path], { stdout: 'pipe', stderr: 'pipe' });
    const out = run.stdout.toString();
    expect(run.exitCode).toBe(0);
    expect(out).toContain('through 625');
    expect(out).toContain('AK ');
    expect(records(path).length).toBe(394 + 2); // samples, one start, one loss
  });

  test('the CLI refuses to start with neither --port nor --sim', () => {
    const run = Bun.spawnSync([process.execPath, join(import.meta.dir, 'bridge.ts')], { stdout: 'pipe', stderr: 'pipe' });
    expect(run.exitCode).toBe(2);
    expect(run.stderr.toString()).toContain('--port');
  });
});
