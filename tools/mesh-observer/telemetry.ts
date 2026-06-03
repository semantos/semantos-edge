/**
 * telemetry.ts — pure, testable core for the speeder-telemetry harness.
 *
 * Defines the TELEM log-line wire format (emitted by mesh_demo firmware and
 * by the synthetic emulator), parsers for it, and the latency/jitter/Hz/drop
 * statistics that answer "what real-time performance does the C6 mesh give us?"
 *
 * No transport, no I/O — operates on strings and numbers so it can be unit
 * tested against synthetic ground truth.
 *
 * ── Wire format ──────────────────────────────────────────────────────────
 * Fixed-point, integer-only (matches the MNCA integer/fixed-point discipline):
 *   x, y    : position in millimetres        (int32)
 *   hdg     : heading in milliradians         (int32, 0..6283)
 *   v       : speed in mm/s                    (int32)
 *   t / tx_t: originator monotonic micros      (uint32, wraps — deltas only)
 *
 * Originator TX line:
 *   TX *** TELEM #<seq> *** spd=<id> x=<x> y=<y> hdg=<hdg> v=<v> t=<tx_us>
 * Receiver (relay or sideline) RX line:
 *   RX [<mac>] telem #<seq> spd=<id> x=<x> y=<y> hdg=<hdg> v=<v> tx_t=<tx_us> (rx_total=<n>)
 * Relay that ran the transform-on-hop prediction re-types the cell:
 *   RX [<mac>] telem-pred #<seq> spd=<id> x=<x> y=<y> hdg=<hdg> v=<v> tx_t=<tx_us> dt=<extrap_us> (rx_total=<n>)
 */

export const MM_PER_M = 1000;
export const MRAD_PER_RAD = 1000;

export interface Pose {
  x: number;   // mm
  y: number;   // mm
  hdg: number; // milliradians
  v: number;   // mm/s
}

export interface TelemTx {
  kind: 'telem_tx';
  seq: number;
  spd: number;
  pose: Pose;
  txUs: number;
}

export interface TelemRx {
  kind: 'telem_rx';
  seq: number;
  spd: number;
  pose: Pose;
  txUs: number;
  predicted: boolean;   // true if this hop re-typed it to telem-pred (transform-on-hop)
  extrapUs?: number;    // how far forward the relay extrapolated, micros
  rxTotal?: number;
}

const TX_RE =
  /^TX \*\*\* TELEM #(\d+) \*\*\* spd=(\d+) x=(-?\d+) y=(-?\d+) hdg=(-?\d+) v=(-?\d+) t=(\d+)/;
const RX_RE =
  /^RX \[[0-9a-f:]+\] telem(-pred)? #(\d+) spd=(\d+) x=(-?\d+) y=(-?\d+) hdg=(-?\d+) v=(-?\d+) tx_t=(\d+)(?: dt=(\d+))?(?: \(rx_total=(\d+)\))?/;

export function parseTelemTx(msg: string): TelemTx | null {
  const m = msg.match(TX_RE);
  if (!m) return null;
  return {
    kind: 'telem_tx',
    seq: +m[1],
    spd: +m[2],
    pose: { x: +m[3], y: +m[4], hdg: +m[5], v: +m[6] },
    txUs: +m[7],
  };
}

export function parseTelemRx(msg: string): TelemRx | null {
  const m = msg.match(RX_RE);
  if (!m) return null;
  return {
    kind: 'telem_rx',
    predicted: m[1] === '-pred',
    seq: +m[2],
    spd: +m[3],
    pose: { x: +m[4], y: +m[5], hdg: +m[6], v: +m[7] },
    txUs: +m[8],
    extrapUs: m[9] != null ? +m[9] : undefined,
    rxTotal: m[10] != null ? +m[10] : undefined,
  };
}

/** Percentile from an unsorted sample (nearest-rank). p in [0,1]. */
export function percentile(samples: number[], p: number): number {
  if (samples.length === 0) return NaN;
  const s = [...samples].sort((a, b) => a - b);
  const idx = Math.min(s.length - 1, Math.max(0, Math.ceil(p * s.length) - 1));
  return s[idx];
}

export interface StreamMetrics {
  count: number;          // arrivals in window
  hz: number;             // effective arrival rate over the window
  meanIntervalMs: number; // mean inter-arrival
  jitterMs: number;       // stddev of inter-arrival (the "real-time feel" killer)
  p99IntervalMs: number;  // worst-case-ish inter-arrival
  dropRate: number;       // fraction of expected seqs missing (0..1)
  // Latency stats — only populated when a clock offset is supplied (tx clock
  // vs rx clock related). Without it, latency is unknowable from one stream
  // and these stay null. Jitter/Hz/drop need NO offset and are always real.
  latencyMeanMs: number | null;
  latencyP99Ms: number | null;
}

/**
 * Per-(receiver, speeder) arrival statistics. Feed it RX arrivals stamped with
 * the receiver's own wall-clock; it derives jitter, Hz and drop with no clock
 * sync at all (single clock). Latency additionally needs `txClockOffsetUs`:
 * the value to ADD to a tx micros reading to express it on the receiver clock.
 */
export class StreamStats {
  private arrivals: { wallMs: number; seq: number; txUs?: number }[] = [];
  private windowMs: number;

  constructor(windowMs = 3000) {
    this.windowMs = windowMs;
  }

  push(wallMs: number, seq: number, txUs?: number): void {
    this.arrivals.push({ wallMs, seq, txUs });
    const cutoff = wallMs - this.windowMs;
    while (this.arrivals.length && this.arrivals[0].wallMs < cutoff) {
      this.arrivals.shift();
    }
  }

  /**
   * Best-effort clock offset for live hardware (no handshake): assume the
   * fastest-arriving cell in the window had ~zero transport delay, so
   * offset = min(wallMs*1000 - txUs). Latency computed with this is
   * "above-floor" (relative), NOT absolute — absolute needs a real two-device
   * clock exchange. Returns null if no txUs samples are present.
   */
  floorOffsetUs(): number | null {
    let best: number | null = null;
    for (const ev of this.arrivals) {
      if (ev.txUs == null) continue;
      const o = ev.wallMs * 1000 - ev.txUs;
      if (best == null || o < best) best = o;
    }
    return best;
  }

  /** txClockOffsetUs: add to a txUs reading to convert to receiver wall micros. */
  metrics(txClockOffsetUs: number | null = null): StreamMetrics {
    const a = this.arrivals;
    const n = a.length;
    if (n === 0) {
      return {
        count: 0, hz: 0, meanIntervalMs: NaN, jitterMs: NaN,
        p99IntervalMs: NaN, dropRate: NaN, latencyMeanMs: null, latencyP99Ms: null,
      };
    }

    const intervals: number[] = [];
    for (let i = 1; i < n; i++) intervals.push(a[i].wallMs - a[i - 1].wallMs);

    const mean = intervals.length
      ? intervals.reduce((s, x) => s + x, 0) / intervals.length
      : NaN;
    const variance = intervals.length
      ? intervals.reduce((s, x) => s + (x - mean) ** 2, 0) / intervals.length
      : NaN;
    const jitter = Math.sqrt(variance);

    const spanMs = a[n - 1].wallMs - a[0].wallMs;
    const hz = spanMs > 0 ? ((n - 1) / spanMs) * 1000 : 0;

    // Drop rate from seq gaps across the window.
    const seqSpan = a[n - 1].seq - a[0].seq;
    const expected = seqSpan + 1;
    const dropRate = expected > 0 ? Math.max(0, (expected - n) / expected) : 0;

    let latencyMeanMs: number | null = null;
    let latencyP99Ms: number | null = null;
    if (txClockOffsetUs != null) {
      const lat: number[] = [];
      for (const ev of a) {
        if (ev.txUs == null) continue;
        const txOnRxClockMs = (ev.txUs + txClockOffsetUs) / 1000;
        lat.push(ev.wallMs - txOnRxClockMs);
      }
      if (lat.length) {
        latencyMeanMs = lat.reduce((s, x) => s + x, 0) / lat.length;
        latencyP99Ms = percentile(lat, 0.99);
      }
    }

    return {
      count: n,
      hz,
      meanIntervalMs: mean,
      jitterMs: jitter,
      p99IntervalMs: percentile(intervals, 0.99),
      dropRate,
      latencyMeanMs,
      latencyP99Ms,
    };
  }
}
