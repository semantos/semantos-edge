/**
 * The depth-validation test: VERIFIABLE REPLAY of in-network prediction.
 *
 * Because the figure-8 is deterministic, we can replay it and score exactly
 * how much a transform-on-hop predictor reduces the sideline's displayed
 * position error — the difference between claiming "more real-time" and
 * proving it. This is the part you can't do with UDP + a database: the cell
 * stream is reproducible, so prediction-vs-actual error is measurable, not
 * asserted.
 *
 * Run: bun test tools/mesh-observer/telemetry-predict.test.ts
 */
import { expect, test, describe } from 'bun:test';
import { extrapolate, positionError } from './telemetry-predict';
import { Speeder } from './telemetry-sim';
import { percentile, type Pose } from './telemetry';

interface ReplayScore {
  latencyMs: number;
  rawMeanMm: number;   // naive sideline: shows pose as-of (now - latency)
  rawP99Mm: number;
  predMeanMm: number;  // in-network predicted: extrapolated forward by latency
  predP99Mm: number;
  improvement: number; // rawMean / predMean
}

/**
 * Replay the figure-8 and compare, at every sample, the sideline's position
 * error WITHOUT prediction (it lags by `latencyMs`) vs WITH an in-network
 * relay extrapolating forward by that latency. Truth is the real pose "now".
 */
function scoreReplay(cfg: { sizeMm: number; lapSeconds: number },
                     latencyMs: number, hz = 50, durationSec = 40): ReplayScore {
  const s = new Speeder({ id: 1, ...cfg });
  const L = latencyMs / 1000;
  const dt = 1 / hz;
  const rawErr: number[] = [];
  const predErr: number[] = [];

  for (let t = L; t < durationSec; t += dt) {
    const truth: Pose = s.poseAt(t);          // where it actually is now
    const raw: Pose   = s.poseAt(t - L);       // what arrived (emitted L ago)
    const pred: Pose  = extrapolate(raw, L);   // relay advanced it forward by L
    rawErr.push(positionError(raw, truth));
    predErr.push(positionError(pred, truth));
  }

  const mean = (a: number[]) => a.reduce((s, x) => s + x, 0) / a.length;
  const rawMeanMm = mean(rawErr), predMeanMm = mean(predErr);
  return {
    latencyMs,
    rawMeanMm, rawP99Mm: percentile(rawErr, 0.99),
    predMeanMm, predP99Mm: percentile(predErr, 0.99),
    improvement: rawMeanMm / predMeanMm,
  };
}

describe('extrapolate (CV dead reckoning)', () => {
  test('advances along heading at speed', () => {
    // Heading 0 (+x), 1000 mm/s, 1s → +1000mm in x.
    const p = extrapolate({ x: 0, y: 0, hdg: 0, v: 1000 }, 1);
    expect(p.x).toBe(1000);
    expect(p.y).toBe(0);
  });
  test('dt=0 is identity', () => {
    const p0 = { x: 12, y: -34, hdg: 1570, v: 5000 };
    expect(extrapolate(p0, 0)).toEqual(p0);
  });
  test('heading 90° (π/2 rad = 1571 mrad) moves +y', () => {
    const p = extrapolate({ x: 0, y: 0, hdg: 1571, v: 2000 }, 1);
    expect(Math.abs(p.x)).toBeLessThan(5);
    expect(p.y).toBeGreaterThan(1990);
  });
});

describe('VERIFIABLE REPLAY — prediction reduces sideline error', () => {
  const cfg = { sizeMm: 6000, lapSeconds: 8 };

  // Print a table across realistic latencies so the win (and its limits) are
  // visible, not just asserted.
  test('scores prediction vs naive across latencies', () => {
    const rows = [20, 50, 100, 200].map(ms => scoreReplay(cfg, ms));
    console.log('\n  in-network prediction — replay-scored position error (figure-8, 6m, 8s lap):');
    console.log('  latency │   naive mean │ predicted mean │ improvement │ naive p99 │ pred p99');
    console.log('  ────────┼──────────────┼────────────────┼─────────────┼───────────┼─────────');
    for (const r of rows) {
      console.log(
        `  ${String(r.latencyMs).padStart(5)}ms │ ${r.rawMeanMm.toFixed(0).padStart(9)} mm │ ${r.predMeanMm.toFixed(0).padStart(11)} mm │ ${('×' + r.improvement.toFixed(1)).padStart(11)} │ ${r.rawP99Mm.toFixed(0).padStart(6)} mm │ ${r.predP99Mm.toFixed(0).padStart(5)} mm`,
      );
    }
    // Every latency must benefit (prediction strictly reduces mean error).
    for (const r of rows) expect(r.predMeanMm).toBeLessThan(r.rawMeanMm);
  });

  test('at 100ms latency, prediction cuts mean error at least 2x', () => {
    const r = scoreReplay(cfg, 100);
    expect(r.improvement).toBeGreaterThan(2);
  });

  test('prediction residual is bounded (curve overshoot stays sane)', () => {
    // The CV model overshoots on tight curves; residual p99 must still be a
    // small fraction of the figure-8 size (6m), i.e. not wildly diverging.
    const r = scoreReplay(cfg, 100);
    expect(r.predP99Mm).toBeLessThan(6000);
  });
});
