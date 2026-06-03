/**
 * Validates the telemetry metrics core against synthetic ground truth:
 * inject a known latency/jitter/drop profile via the emulator, replay it
 * through the same parsers + StreamStats the observer uses, and assert the
 * recovered numbers match what was injected.
 *
 * Run: bun test tools/mesh-observer/telemetry.test.ts
 */
import { expect, test, describe } from 'bun:test';
import {
  parseTelemTx, parseTelemRx, StreamStats, percentile, type StreamMetrics,
} from './telemetry';
import { generateFleet, Speeder } from './telemetry-sim';

describe('wire-format parsers', () => {
  test('round-trips a TX line', () => {
    const tx = parseTelemTx('TX *** TELEM #42 *** spd=1 x=-1234 y=5678 hdg=3141 v=9000 t=123456');
    expect(tx).toEqual({
      kind: 'telem_tx', seq: 42, spd: 1,
      pose: { x: -1234, y: 5678, hdg: 3141, v: 9000 }, txUs: 123456,
    });
  });

  test('round-trips a plain RX line', () => {
    const rx = parseTelemRx('RX [02:00:00:00:00:01] telem #7 spd=1 x=10 y=20 hdg=30 v=40 tx_t=999 (rx_total=5)');
    expect(rx?.predicted).toBe(false);
    expect(rx?.seq).toBe(7);
    expect(rx?.rxTotal).toBe(5);
    expect(rx?.pose).toEqual({ x: 10, y: 20, hdg: 30, v: 40 });
  });

  test('recognises a transform-on-hop predicted RX line', () => {
    const rx = parseTelemRx('RX [02:00:00:00:00:01] telem-pred #7 spd=1 x=10 y=20 hdg=30 v=40 tx_t=999 dt=8000 (rx_total=5)');
    expect(rx?.predicted).toBe(true);
    expect(rx?.extrapUs).toBe(8000);
  });

  test('ignores non-telemetry lines', () => {
    expect(parseTelemTx('TX heartbeat #3 (deck)')).toBeNull();
    expect(parseTelemRx('RX [aa:bb] heartbeat verified (rx_total=2)')).toBeNull();
  });
});

describe('percentile', () => {
  test('nearest-rank', () => {
    const s = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    expect(percentile(s, 0.5)).toBe(5);
    expect(percentile(s, 0.99)).toBe(10);
    expect(percentile(s, 1.0)).toBe(10);
  });
});

describe('StreamStats recovers injected transport profile', () => {
  // Inject a known profile, feed RX arrivals through StreamStats, assert match.
  const HZ = 20;
  const BASE = 12;   // ms
  const JITTER = 4;  // ms
  const events = generateFleet({
    speeders: [{ id: 1, sizeMm: 5000, lapSeconds: 8 }],
    hz: HZ,
    durationSec: 30,
    transport: { baseLatencyMs: BASE, jitterMs: JITTER, dropProb: 0 },
    seed: 0xC0FFEE,
  });

  test('emulator produced both TX and RX streams', () => {
    const tx = events.filter(e => e.port === '/dev/sim-origin').length;
    const rx = events.filter(e => e.port === '/dev/sim-sideline').length;
    expect(tx).toBeGreaterThan(500);
    expect(rx).toBe(tx); // dropProb 0
  });

  test('recovers Hz, jitter, and latency from the RX stream', () => {
    // Single sim clock → tx/rx share a timebase → offset is exactly 0.
    const stats = new StreamStats(/*windowMs*/ 60_000);
    for (const e of events) {
      if (e.port !== '/dev/sim-sideline') continue;
      const rx = parseTelemRx(e.msg)!;
      stats.push(e.atMs, rx.seq, rx.txUs);
    }
    const m: StreamMetrics = stats.metrics(/*txClockOffsetUs*/ 0);

    // Hz: ~20 (arrival rate, jitter averages out over 30s).
    expect(m.hz).toBeGreaterThan(19);
    expect(m.hz).toBeLessThan(21);

    // Jitter: stddev of inter-arrival. Differencing two iid gaussian-delayed
    // arrivals inflates stddev by ~√2, so expect ≈ JITTER*√2 ≈ 5.7ms.
    expect(m.jitterMs).toBeGreaterThan(3);
    expect(m.jitterMs).toBeLessThan(9);

    // Latency: should recover the injected BASE within a couple ms.
    expect(m.latencyMeanMs).not.toBeNull();
    expect(Math.abs((m.latencyMeanMs as number) - BASE)).toBeLessThan(2);

    // No offset supplied → latency unknowable, jitter/Hz still real.
    const noOffset = stats.metrics(null);
    expect(noOffset.latencyMeanMs).toBeNull();
    expect(noOffset.hz).toBeGreaterThan(19);
  });

  test('drop rate is detected from seq gaps', () => {
    const dropEvents = generateFleet({
      speeders: [{ id: 1, sizeMm: 5000, lapSeconds: 8 }],
      hz: HZ, durationSec: 30,
      transport: { baseLatencyMs: BASE, jitterMs: JITTER, dropProb: 0.1 },
      seed: 0xBEEF,
    });
    const stats = new StreamStats(60_000);
    for (const e of dropEvents) {
      if (e.port !== '/dev/sim-sideline') continue;
      const rx = parseTelemRx(e.msg)!;
      stats.push(e.atMs, rx.seq, rx.txUs);
    }
    const m = stats.metrics(0);
    // Injected 10% drop — expect recovered drop rate in a sane band.
    expect(m.dropRate).toBeGreaterThan(0.05);
    expect(m.dropRate).toBeLessThan(0.16);
  });
});

describe('figure-8 path', () => {
  test('is closed (returns to start after one lap)', () => {
    const s = new Speeder({ id: 1, sizeMm: 5000, lapSeconds: 8 });
    const p0 = s.poseAt(0);
    const p1 = s.poseAt(8); // one full lap
    expect(Math.abs(p0.x - p1.x)).toBeLessThan(5);
    expect(Math.abs(p0.y - p1.y)).toBeLessThan(5);
  });

  test('speed is non-zero and bounded', () => {
    const s = new Speeder({ id: 1, sizeMm: 5000, lapSeconds: 8 });
    for (let t = 0; t < 8; t += 0.5) {
      const p = s.poseAt(t);
      expect(p.v).toBeGreaterThanOrEqual(0);
      expect(p.v).toBeLessThan(10_000); // < 10 m/s for these params
    }
  });
});
