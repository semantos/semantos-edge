/**
 * telemetry-predict.ts — in-network pose prediction (transform-on-hop oracle).
 *
 * This is the TS oracle for a cell-engine `TransformFn` (cell_transform.zig):
 * a handler registered as input_type `cellmesh.telem.v0` → output_type
 * `cellmesh.telem-pred.v0`. On a forwarding hop, a node that holds this
 * handler decodes the inbound pose, extrapolates it forward by the transport
 * latency it's compensating, and writes the predicted pose to the outbound
 * payload — rotating the cell type to telem-pred. "Compute rides the routing."
 *
 * Why it matters: every existing telemetry system dead-reckons at the
 * ENDPOINT. Doing it at a relay means the sideline receives state already
 * advanced to ~now, so the displayed lag shrinks from "one transport latency"
 * to "the dead-reckoning residual" — which, on smooth motion, is far smaller.
 * Because the figure-8 is deterministic, we can REPLAY and score exactly how
 * much it helps (and where it hurts — tight curves), instead of just claiming
 * "more real-time".
 *
 * Pure over the Pose struct; no transport, no chain. Units match the wire
 * format: x/y mm, hdg milliradians, v mm/s.
 */

import type { Pose } from './telemetry';

/**
 * Constant-velocity, constant-heading dead reckoning — the baseline predictor
 * everyone uses. Advances position along the current heading at the current
 * speed for `dtSec`. Heading and speed are carried unchanged (a CTRV model
 * that also integrates heading-rate would track curves better; CV is the
 * honest baseline and its curve residual is the thing the replay scorer
 * surfaces).
 */
export function extrapolate(pose: Pose, dtSec: number): Pose {
  const hdgRad = pose.hdg / 1000;
  return {
    x: Math.round(pose.x + pose.v * Math.cos(hdgRad) * dtSec),
    y: Math.round(pose.y + pose.v * Math.sin(hdgRad) * dtSec),
    hdg: pose.hdg,
    v: pose.v,
  };
}

/** Euclidean position error between two poses, millimetres. */
export function positionError(a: Pose, b: Pose): number {
  return Math.hypot(a.x - b.x, a.y - b.y);
}
