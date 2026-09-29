// The temp logger's heat policy, run through the same cell-engine WASM the
// C6 loads (components/semantos/wasm/cell-engine-embedded.wasm).
//
// The node trusts the engine's verdict and cross-checks it natively; a
// disagreement is logged as a fault. This proves, before any board, that
// they agree across the band's edges — inclusive at both ends, negative
// numbers included — for the exact script bytes the firmware builds.

import { describe, expect, test } from 'bun:test';
import { openEngine } from './engine';

// cm_tlog_policy_lock(-200, 2800): <-200> <2801> OP_WITHIN. These bytes are
// pinned by the Zig test "the policy lock accepts min through max inclusive".
const LOCK = Uint8Array.from([0x02, 0xc8, 0x80, 0x02, 0xf1, 0x0a, 0xa5]);

// Minimal script-number push, as cm_script_num_push writes it.
function push(v: number): Uint8Array {
  if (v === 0) return Uint8Array.of(0x00);
  if (v === -1) return Uint8Array.of(0x4f);
  if (v >= 1 && v <= 16) return Uint8Array.of(0x50 + v);
  let mag = Math.abs(v);
  const bytes: number[] = [];
  while (mag > 0) {
    bytes.push(mag & 0xff);
    mag = Math.floor(mag / 256);
  }
  if (bytes[bytes.length - 1] & 0x80) bytes.push(v < 0 ? 0x80 : 0x00);
  else if (v < 0) bytes[bytes.length - 1] |= 0x80;
  return Uint8Array.from([bytes.length, ...bytes]);
}

describe('heat policy in the cell engine', async () => {
  const engine = await openEngine();

  test('the engine is really judging: a trivially true script passes and a false one fails', () => {
    expect(engine.run(Uint8Array.of(0x51), new Uint8Array())).toBe(true);   // OP_1
    expect(engine.run(Uint8Array.of(0x00), new Uint8Array())).toBe(false);  // OP_0
  });

  const cases: Array<[number, boolean]> = [
    [-5500, false],
    [-201, false],
    [-200, true],  // low edge is inside
    [-1, true],
    [0, true],
    [16, true],
    [1800, true],
    [2506, true],
    [2800, true],  // high edge is inside
    [2801, false],
    [3500, false],
    [12500, false],
  ];
  for (const [centi, inBand] of cases) {
    test(`${(centi / 100).toFixed(2)} °C is ${inBand ? 'in band' : 'out of band'}`, () => {
      expect(engine.run(LOCK, push(centi))).toBe(inBand);
    });
  }
});
