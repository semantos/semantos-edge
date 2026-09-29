/**
 * replay.ts — send what the bridge stored to the server again.
 *
 * The bridge acks a batch before it POSTs it, so a POST that fails never costs
 * a node its readings; they are safe in the JSONL. But a server that was down
 * never got them. `bridge.ts --replay` reads the JSONL and POSTs every sample
 * again, grouped by log, oldest first, in bounded bodies. The server drops
 * what it already holds by (mac, logId, seq), so replaying twice is harmless.
 */

import { readFileSync } from 'node:fs';
import type { PostBody, Poster, PostSample } from './bridge';
import type { LossRecord, SampleRecord } from './store';

export interface ReplayReport {
  bodies: number;
  samples: number;
  posted: number;
  failed: number;
  /** lines that were not a readable record */
  skipped: number;
}

/** Group stored samples into POST bodies: per log, by seq, at most `max` samples each. */
export function replayBodies(lines: Iterable<string>, max = 500): { bodies: PostBody[]; skipped: number } {
  const logs = new Map<string, { mac: string; logId: string; lostThrough: number; bySeq: Map<number, PostSample> }>();
  const logFor = (mac: string, logId: string) => {
    const key = `${mac}|${logId}`;
    let l = logs.get(key);
    if (!l) logs.set(key, (l = { mac, logId, lostThrough: 0, bySeq: new Map() }));
    return l;
  };

  let skipped = 0;
  for (const line of lines) {
    if (line.trim() === '') continue;
    let rec: SampleRecord | LossRecord | { kind?: unknown };
    try {
      rec = JSON.parse(line);
    } catch {
      skipped++;
      continue;
    }
    if (rec.kind === 'sample') {
      const s = rec as SampleRecord;
      logFor(s.mac, s.logId).bySeq.set(s.seq, {
        seq: s.seq, bootId: s.bootId, uptimeS: s.uptimeS, centiC: s.centiC,
        flags: s.flags, tUnix: s.tUnix, anchor: s.anchor,
      });
    } else if (rec.kind === 'loss') {
      const l = logFor((rec as LossRecord).mac, (rec as LossRecord).logId);
      l.lostThrough = Math.max(l.lostThrough, (rec as LossRecord).throughSeq);
    } else if (rec.kind !== 'start') {
      skipped++;
    }
  }

  const bodies: PostBody[] = [];
  for (const l of logs.values()) {
    const samples = [...l.bySeq.values()].sort((a, b) => a.seq - b.seq);
    for (let i = 0; i < samples.length; i += max) {
      bodies.push({ mac: l.mac, logId: l.logId, lostThrough: l.lostThrough, samples: samples.slice(i, i + max) });
    }
  }
  return { bodies, skipped };
}

/** POST every body from `path`; a failure is counted and the rest still go. */
export async function replayFile(path: string, post: Poster, log: (m: string) => void = () => {}): Promise<ReplayReport> {
  const { bodies, skipped } = replayBodies(readFileSync(path, 'utf8').split('\n'));
  const report: ReplayReport = { bodies: bodies.length, samples: 0, posted: 0, failed: 0, skipped };
  for (const body of bodies) {
    report.samples += body.samples.length;
    try {
      await post(body);
      report.posted++;
    } catch (e) {
      report.failed++;
      log(`${body.mac} log ${body.logId} seqs ${body.samples[0]?.seq}..${body.samples.at(-1)?.seq}: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  return report;
}
