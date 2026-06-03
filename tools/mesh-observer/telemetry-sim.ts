/**
 * telemetry-sim.ts — synthetic speeder emulator.
 *
 * Produces the EXACT mesh_demo TELEM log-line format (see telemetry.ts) so the
 * whole pipeline — parse → metrics → WebSocket → browser — is exercisable with
 * zero C6 hardware plugged in. The firmware (staged separately) emits the same
 * lines; this is the laptop-side stand-in for bring-up and for validating the
 * metrics math against known ground truth.
 *
 * A speeder flies a deterministic figure-8 (lemniscate of Gerono) so the path
 * is closed, smooth, and obviously "moving" in a viewer. Poses are emitted in
 * the integer fixed-point units the wire format uses.
 *
 * The emulator can also model the transport: each emitted pose yields an
 * originator TX line at sim-time T and a receiver RX line at T + latency, where
 * latency = base + jitter (gaussian) and an optional drop probability skips the
 * RX entirely. That lets us inject a KNOWN latency/jitter/drop profile and
 * confirm the metrics core recovers it.
 */

import { extrapolate } from './telemetry-predict';

const TWO_PI = Math.PI * 2;

export interface SpeederConfig {
  id: number;
  /** Half-width / half-height of the figure-8 in millimetres. */
  sizeMm: number;
  /** Seconds for one full lap of the figure-8. */
  lapSeconds: number;
  /** Phase offset (radians) so multiple speeders don't overlap. */
  phase?: number;
}

export interface TransportProfile {
  /** One-hop base latency, milliseconds (originator TX → receiver RX). */
  baseLatencyMs: number;
  /** Gaussian stddev of latency, milliseconds (the jitter we inject). */
  jitterMs: number;
  /** Probability [0,1] a given cell is dropped (no RX line). */
  dropProb: number;
}

export interface Pose {
  x: number;   // mm
  y: number;   // mm
  hdg: number; // milliradians [0, 2π*1000)
  v: number;   // mm/s
}

/** Box-Muller gaussian with a seedable LCG so sims are reproducible. */
export class Rng {
  private state: number;
  constructor(seed = 0x1234abcd) { this.state = seed >>> 0; }
  next(): number {
    // Numerical Recipes LCG.
    this.state = (Math.imul(this.state, 1664525) + 1013904223) >>> 0;
    return this.state / 0x100000000;
  }
  gauss(mean: number, std: number): number {
    const u1 = Math.max(1e-9, this.next());
    const u2 = this.next();
    return mean + std * Math.sqrt(-2 * Math.log(u1)) * Math.cos(TWO_PI * u2);
  }
}

export class Speeder {
  constructor(public cfg: SpeederConfig) {}

  /** Pose at sim time `tSec`. Velocity/heading from an analytic derivative. */
  poseAt(tSec: number): Pose {
    const A = this.cfg.sizeMm;
    const w = TWO_PI / this.cfg.lapSeconds;
    const ph = this.cfg.phase ?? 0;
    const a = w * tSec + ph;
    // Lemniscate of Gerono: x = A sin a, y = A sin a cos a.
    const x = A * Math.sin(a);
    const y = A * Math.sin(a) * Math.cos(a);
    // Derivatives wrt time.
    const dx = A * Math.cos(a) * w;
    const dy = A * (Math.cos(a) * Math.cos(a) - Math.sin(a) * Math.sin(a)) * w;
    const speed = Math.hypot(dx, dy);          // mm/s
    let hdg = Math.atan2(dy, dx);              // rad
    if (hdg < 0) hdg += TWO_PI;
    return {
      x: Math.round(x),
      y: Math.round(y),
      hdg: Math.round(hdg * 1000),
      v: Math.round(speed),
    };
  }
}

export function txLine(seq: number, spd: number, pose: Pose, txUs: number): string {
  return `TX *** TELEM #${seq} *** spd=${spd} x=${pose.x} y=${pose.y} hdg=${pose.hdg} v=${pose.v} t=${txUs}`;
}

export function rxLine(
  seq: number, spd: number, pose: Pose, txUs: number, rxTotal: number,
  opts: { predicted?: boolean; extrapUs?: number } = {},
): string {
  const tag = opts.predicted ? 'telem-pred' : 'telem';
  const dt = opts.extrapUs != null ? ` dt=${opts.extrapUs}` : '';
  return `RX [02:00:00:00:00:0${spd}] ${tag} #${seq} spd=${spd} x=${pose.x} y=${pose.y} hdg=${pose.hdg} v=${pose.v} tx_t=${txUs}${dt} (rx_total=${rxTotal})`;
}

export interface SimEvent {
  /** Sim wall time the line "arrives" at the observer, milliseconds. */
  atMs: number;
  /** Which device's serial port this line came from. */
  port: string;
  /** Full message body (without the `I (ts) mesh_demo:` framing). */
  msg: string;
}

/**
 * Generate a flat, time-ordered list of TX + RX events for `durationSec` of a
 * fleet flying figure-8s, at `hz` updates/sec, under a transport profile.
 *
 * Originator TX lines appear on port `/dev/sim-origin`; received lines on
 * `/dev/sim-sideline`. Because we control one sim clock, txUs and the RX
 * arrival share a timebase: clock offset is exactly 0, so recovered latency
 * should equal the injected latency. That is the ground truth the test checks.
 */
export function generateFleet(opts: {
  speeders: SpeederConfig[];
  hz: number;
  durationSec: number;
  transport: TransportProfile;
  seed?: number;
  /** Tick index to start at — lets a caller emit a continuous, monotonic
   *  stream across successive chunks (seq + txUs keep climbing). */
  startTick?: number;
  /** Running rx-counter seed per speeder id (for continuous rx_total). */
  rxTotals?: Map<number, number>;
  /** When true, a relay runs the transform-on-hop predictor: it extrapolates
   *  each pose forward by that cell's transport latency and emits telem-pred,
   *  so the sideline sees state advanced to ~now (see telemetry-predict.ts). */
  predict?: boolean;
}): SimEvent[] {
  const { speeders, hz, durationSec, transport } = opts;
  const rng = new Rng(opts.seed ?? 0x1234abcd);
  const periodMs = 1000 / hz;
  const sims = speeders.map(c => new Speeder(c));
  const events: SimEvent[] = [];
  const rxTotals = opts.rxTotals ?? new Map<number, number>();
  const startTick = opts.startTick ?? 0;

  const ticks = Math.floor((durationSec * 1000) / periodMs);
  for (let k = 0; k < ticks; k++) {
    const i = startTick + k;            // monotonic seq across chunks
    const txMs = i * periodMs;          // absolute sim ms from epoch 0
    const txUs = Math.round(txMs * 1000); // single sim clock → offset 0
    for (let s = 0; s < sims.length; s++) {
      const cfg = speeders[s];
      const pose = sims[s].poseAt(txMs / 1000);
      events.push({ atMs: txMs, port: '/dev/sim-origin', msg: txLine(i, cfg.id, pose, txUs) });

      if (rng.next() < transport.dropProb) continue; // dropped cell
      const lat = Math.max(0, rng.gauss(transport.baseLatencyMs, transport.jitterMs));
      const rxMs = txMs + lat;
      const rt = (rxTotals.get(cfg.id) ?? 0) + 1;
      rxTotals.set(cfg.id, rt);
      // Relay transform-on-hop: extrapolate forward by the transport latency
      // so the sideline pose is advanced to ~now, and re-type to telem-pred.
      const outPose = opts.predict ? extrapolate(pose, lat / 1000) : pose;
      const rxOpts = opts.predict
        ? { predicted: true, extrapUs: Math.round(lat * 1000) }
        : {};
      events.push({ atMs: rxMs, port: '/dev/sim-sideline', msg: rxLine(i, cfg.id, outPose, txUs, rt, rxOpts) });
    }
  }
  events.sort((a, b) => a.atMs - b.atMs);
  return events;
}
