/**
 * Generate the OP_CHECKDOMAINFLAG truth table by RUNNING THE REAL OPCODE.
 *
 *   node gen-domainflag-vectors.mjs
 *
 * The oracle is not a spec, a comment, or my reading of plexus.zig — it is
 * `components/semantos/wasm/cell-engine-embedded.wasm`, the exact blob this
 * firmware embeds and flashes. The script we execute is the canonical shape:
 *
 *     <1024-byte cell> <expected_flag> OP_CHECKDOMAINFLAG
 *
 * and we record whether the engine accepted (rc 0) or refused (rc 28,
 * domain_flag_mismatch). test_cell_capability.c then drives cm_domain_flag_matches
 * from this table, so the native fast path is held to the opcode's own
 * behaviour rather than to a second opinion about it.
 *
 * If someone rebuilds the WASM engine and the opcode's semantics change, this
 * regenerates and the C test fails — which is the point.
 */
import { readFileSync, writeFileSync } from 'node:fs';

const WASM = new URL('../../../semantos/wasm/cell-engine-embedded.wasm', import.meta.url);
const OP_CHECKDOMAINFLAG = 0xC6;
const ERR_DOMAIN_FLAG_MISMATCH = 28;

const { instance: I } = await WebAssembly.instantiate(
  readFileSync(WASM),
  { host: new Proxy({}, { get: () => () => 0 }) },
);
const E = I.exports;
E.kernel_init();

const makeCell = (flag) => {
  const c = new Uint8Array(1024);
  const w32 = (o, v) => { c[o] = v & 255; c[o+1] = (v>>>8) & 255; c[o+2] = (v>>>16) & 255; c[o+3] = (v>>>24) & 255; };
  w32(0, 0xDEADBEEF); w32(4, 0xCAFEBABE); w32(8, 0x13371337); w32(12, 0x42424242);
  w32(16, 1);    // linearity: affine
  w32(20, 2);    // version
  w32(24, flag); // the field under test
  return c;
};
const push = (b) => b.length <= 75 ? [b.length, ...b]
                                   : [0x4d, b.length & 255, (b.length>>>8) & 255, ...b];

/**
 * Encode a domain flag the way the opcode actually reads it.
 *
 * ⚠ THE TRAP, measured against the live engine, not assumed:
 * OP_CHECKDOMAINFLAG does NOT read a raw little-endian u32 off the stack. It
 * reads a BSV SCRIPT NUMBER — sign-magnitude, little-endian, bit 7 of the most
 * significant byte is the SIGN. So a naive 4-byte LE push of 0x80000000 is the
 * byte string 00 00 00 80, which is script-number NEGATIVE ZERO, and the engine
 * compares it as 0. Verified: a cell declaring domain 0 ACCEPTS against an
 * "expected" of 0x80000000 pushed that way. Same for 0xffffffff.
 *
 * That is a real bypass for any flag with bit 31 set, and the reason
 * `domains.zig` now refuses to allocate one.
 *
 * Minimal script-number encoding appends a 0x00 pad when the top byte would
 * otherwise read as a sign bit — which is why 0x00f10001 is FOUR bytes
 * (01 00 f1 00) and 0x0e is ONE (0e).
 */
const scriptNum = (v) => {
  if (v === 0) return new Uint8Array(0);   // script number zero is the empty push
  const out = [];
  let x = v >>> 0;
  while (x > 0) { out.push(x & 0xff); x = Math.floor(x / 256); }
  if (out[out.length - 1] & 0x80) out.push(0x00);
  return new Uint8Array(out);
};

const runOpcode = (cellFlag, expectedFlag) => {
  const script = Uint8Array.from([...push(makeCell(cellFlag)), ...push(scriptNum(expectedFlag)), OP_CHECKDOMAINFLAG]);
  E.kernel_reset();
  const at = E.memory.buffer.byteLength - script.length - 64;
  new Uint8Array(E.memory.buffer).set(script, at);
  if (E.kernel_load_script(at, script.length) !== 0) throw new Error('load_script failed');
  const rc = E.kernel_execute();
  if (rc !== 0 && rc !== ERR_DOMAIN_FLAG_MISMATCH) {
    throw new Error(`unexpected engine rc=${rc} for (${cellFlag}, ${expectedFlag})`);
  }
  return rc === 0;
};

// Values chosen to cover: the undeclared default, the semantos-core canonical
// zone flag, the Plexus well-known neighbour, this layer's sovereign pair, an
// adjacent-by-one-bit neighbour, and the largest flag that is still SAFE to
// allocate. Every ordered pair is exercised, so both the diagonal (accept) and
// every off-diagonal cell (refuse) is a real observation, not an assumption.
//
// Nothing with bit 31 set appears here. Those are covered separately below, as
// hazards rather than as legal flags — see HIGH_BIT_HAZARDS.
const FLAGS = [
  { name: 'UNDECLARED',   value: 0x00000000 },
  { name: 'ZONE',         value: 0x0000000e },
  { name: 'CHILD_CREATE', value: 0x00000006 },
  { name: 'PAD_BOUNDARY', value: 0x00000080 }, // first value needing a pad byte
  { name: 'FLEET_DEVICE', value: 0x00f10001 },
  { name: 'ORG_MEMBER',   value: 0x00f10002 },
  { name: 'NEIGHBOUR',    value: 0x00f10003 },
  { name: 'SAFE_MAX',     value: 0x7fffffff },
];

const rows = [];
for (const a of FLAGS) for (const b of FLAGS) {
  rows.push({ actual: a, expected: b, accept: runOpcode(a.value, b.value) });
}

// Sanity: the opcode must be exact equality and nothing else. If this ever
// trips, the generator is wrong about the oracle and must not emit a header.
for (const r of rows) {
  if (r.accept !== (r.actual.value === r.expected.value)) {
    throw new Error(`opcode is not exact equality at ${r.actual.name}/${r.expected.name}`);
  }
}

// ── The bit-31 hazard, measured ─────────────────────────────────────────────
// A flag with bit 31 set cannot be expressed as a plain 4-byte LE push: the
// engine reads that as a negative script number. We record what the engine
// ACTUALLY does so the claim in the comments is evidence, not folklore.
const le32 = (v) => new Uint8Array([v & 255, (v>>>8) & 255, (v>>>16) & 255, (v>>>24) & 255]);
const runRawLE32 = (cellFlag, expectedFlag) => {
  const script = Uint8Array.from([...push(makeCell(cellFlag)), ...push(le32(expectedFlag)), OP_CHECKDOMAINFLAG]);
  E.kernel_reset();
  const at = E.memory.buffer.byteLength - script.length - 64;
  new Uint8Array(E.memory.buffer).set(script, at);
  E.kernel_load_script(at, script.length);
  return E.kernel_execute() === 0;
};
const HIGH_BIT_HAZARDS = [0x80000000, 0xffffffff, 0xfffffffe].map((v) => ({
  value: v,
  // Does a cell declaring domain ZERO wrongly satisfy this expected flag?
  zeroCellAccepted: runRawLE32(0x00000000, v),
  // Does the CORRECT cell fail to satisfy it?
  matchingCellRejected: !runRawLE32(v, v),
}));
for (const h of HIGH_BIT_HAZARDS) {
  if (!h.zeroCellAccepted || !h.matchingCellRejected) {
    throw new Error(`bit-31 hazard not reproduced for 0x${h.value.toString(16)} — ` +
      'the engine changed; re-read the encoding rules before trusting the header.');
  }
}

const hex = (v) => '0x' + (v >>> 0).toString(16).padStart(8, '0') + 'u';
const out = `/*
 * domainflag_vectors.h — GENERATED. Do not hand-edit.
 *
 * Produced by test/vectors/gen-domainflag-vectors.mjs, which runs the REAL
 * OP_CHECKDOMAINFLAG (opcode 198) inside the WASM cell engine this firmware
 * embeds — components/semantos/wasm/cell-engine-embedded.wasm — over the
 * canonical script <cell> <expected_flag> OP_CHECKDOMAINFLAG.
 *
 * accept = the engine returned 0. reject = the engine returned 28
 * (domain_flag_mismatch). Nothing here is asserted from a spec or a comment;
 * every row is an observation of the binary that ships.
 *
 * ${rows.length} rows, ${FLAGS.length} flags, every ordered pair.
 *
 * ⚠ ENCODING, measured not assumed: the opcode reads the expected flag as a BSV
 * SCRIPT NUMBER, not a raw u32. Bit 7 of the top byte is the SIGN. A 4-byte LE
 * push of 0x80000000 is 00 00 00 80 = script-number negative zero, and the
 * engine compares it as 0 — so a cell declaring domain 0 ACCEPTS against it.
 * Confirmed against the live engine for 0x80000000, 0xffffffff and 0xfffffffe:
 * in every case the zero cell was accepted AND the matching cell was rejected.
 * Domain flags must therefore stay below 0x80000000; domains.zig enforces it.
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    uint32_t    actual;
    uint32_t    expected;
    bool        accept;
    const char *label;
} cm_domainflag_vector_t;

#define CM_DOMAINFLAG_VECTOR_COUNT ${rows.length}

static const cm_domainflag_vector_t CM_DOMAINFLAG_VECTORS[CM_DOMAINFLAG_VECTOR_COUNT] = {
${rows.map((r) => `    { ${hex(r.actual.value)}, ${hex(r.expected.value)}, ${r.accept ? 'true ' : 'false'}, "${r.actual.name} vs ${r.expected.name}" },`).join('\n')}
};
`;

const dest = new URL('./domainflag_vectors.h', import.meta.url);
writeFileSync(dest, out);
const accepted = rows.filter((r) => r.accept).length;
console.log(`wrote ${dest.pathname}\n  ${rows.length} rows from the live engine: ${accepted} accept, ${rows.length - accepted} reject`);
