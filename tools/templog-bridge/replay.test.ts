// --replay: re-POST what the bridge stored.
//
// The bridge acks a batch before POSTing it, so a POST that fails (the server
// was down) never costs the node its readings — but it does leave them only in
// the bridge's JSONL. Replay sends them again; the server drops what it already
// has by (mac, logId, seq), so replaying twice is harmless.

import { describe, expect, test } from 'bun:test';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { replayBodies, replayFile } from './replay';
import { main } from './bridge';
import type { PostBody } from './bridge';

const MAC_A = '58:e6:c5:1a:8b:28';
const MAC_B = '58:e6:c5:1a:8b:99';

const sample = (mac: string, logId: string, seq: number, centiC = 1600) => JSON.stringify({
  kind: 'sample', mac, logId, seq, bootId: 1, uptimeS: seq * 60, centiC, flags: 0,
  tUnix: 1_790_000_000 + seq * 60, anchor: 'receipt', policyMinCenti: -200, policyMaxCenti: 2800,
  receivedUnixS: 1_790_000_000 + seq * 60,
});
const start = (mac: string, logId: string, firstSeq: number) =>
  JSON.stringify({ kind: 'start', mac, logId, firstSeq, receivedUnixS: 1_790_000_000 });
const loss = (mac: string, logId: string, throughSeq: number) =>
  JSON.stringify({ kind: 'loss', mac, logId, fromSeq: null, throughSeq, missing: null, receivedUnixS: 1_790_000_000 });

describe('replayBodies', () => {
  test('groups samples by log, oldest first, with the fields the server takes', () => {
    const lines = [
      start(MAC_A, 'a1b2c3d4', 1), sample(MAC_A, 'a1b2c3d4', 2), sample(MAC_A, 'a1b2c3d4', 1),
      start(MAC_B, '0000beef', 5), sample(MAC_B, '0000beef', 5),
    ];
    const { bodies, skipped } = replayBodies(lines);
    expect(skipped).toBe(0);
    expect(bodies).toHaveLength(2);
    expect(bodies[0]).toEqual({
      mac: MAC_A, logId: 'a1b2c3d4', lostThrough: 0,
      samples: [
        { seq: 1, bootId: 1, uptimeS: 60, centiC: 1600, flags: 0, tUnix: 1_790_000_060, anchor: 'receipt' },
        { seq: 2, bootId: 1, uptimeS: 120, centiC: 1600, flags: 0, tUnix: 1_790_000_120, anchor: 'receipt' },
      ],
    } satisfies PostBody);
    expect(bodies[1].mac).toBe(MAC_B);
  });

  test("carries the node's own report of what it lost before delivery", () => {
    const { bodies } = replayBodies([loss(MAC_A, 'a1b2c3d4', 256), sample(MAC_A, 'a1b2c3d4', 257)]);
    expect(bodies[0].lostThrough).toBe(256);
  });

  test('keeps each POST to a bounded size', () => {
    const lines = Array.from({ length: 1201 }, (_, i) => sample(MAC_A, 'a1b2c3d4', i + 1));
    const { bodies } = replayBodies(lines, 500);
    expect(bodies.map(b => b.samples.length)).toEqual([500, 500, 201]);
    expect(bodies[2].samples[0].seq).toBe(1001);
  });

  test('a line it cannot read is counted, not guessed at, and the rest still go', () => {
    const { bodies, skipped } = replayBodies(['{broken', sample(MAC_A, 'a1b2c3d4', 1), '']);
    expect(skipped).toBe(1);
    expect(bodies[0].samples).toHaveLength(1);
  });

  test('a sample stored twice is sent once', () => {
    const { bodies } = replayBodies([sample(MAC_A, 'a1b2c3d4', 1), sample(MAC_A, 'a1b2c3d4', 1)]);
    expect(bodies[0].samples).toHaveLength(1);
  });
});

describe('replayFile', () => {
  test('posts every body, and a failed POST is reported without stopping the rest', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'templog-replay-'));
    try {
      const path = join(dir, 'readings.jsonl');
      writeFileSync(path, [sample(MAC_A, 'a1b2c3d4', 1), sample(MAC_B, '0000beef', 1)].join('\n') + '\n');
      const seen: string[] = [];
      const report = await replayFile(path, async (b) => {
        seen.push(b.mac);
        if (b.mac === MAC_A) throw new Error('HTTP 503');
      });
      expect(seen).toEqual([MAC_A, MAC_B]);
      expect(report).toEqual({ bodies: 2, samples: 2, posted: 1, failed: 1, skipped: 0 });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

test('the CLI refuses --replay without somewhere to send it', async () => {
  expect(await main(['--replay', '--out', 'x.jsonl'])).toBe(2);
});
