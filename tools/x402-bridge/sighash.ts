/**
 * sighash.ts — BSV sighash type flag constants.
 *
 * Sighash types are composed of orthogonal flag bits.  Keep them
 * decomposed rather than hardcoding magic numbers so that:
 *   • Adding the Chronicle algo flag is a one-constant change.
 *   • BRC-115 (SINGLE | FORKID | ANYONECANPAY) reads as intent,
 *     not as a hex literal.
 *   • The cell-engine script layer (interlock / actuator) and the
 *     BSV tx layer share the same constants.
 *
 * ─── Bit layout ───────────────────────────────────────────────────────
 *
 *   bit   mask   name
 *   0-1   0x03   base type  (ALL=1, NONE=2, SINGLE=3)
 *   5     0x20   SIGHASH_CHRONICLE_ALGO  ← placeholder, TBD
 *   6     0x40   SIGHASH_FORKID          BSV BIP-143 replay-protection
 *   7     0x80   SIGHASH_ANYONECANPAY
 *
 * ─── Chronicle note ──────────────────────────────────────────────────
 *
 * The Chronicle node release is expected to introduce a new/restored
 * sighash algorithm flag.  Its exact bit position is not yet published
 * in the BSV spec.  SIGHASH_CHRONICLE_ALGO is defined here as 0x00
 * (no-op) so all consumers can already compose it in:
 *
 *   SIGHASH_SINGLE | SIGHASH_FORKID | SIGHASH_ANYONECANPAY | SIGHASH_CHRONICLE_ALGO
 *
 * When the Chronicle spec ships, update this one constant.  Nothing
 * else in the codebase needs to change.
 */

// ── Base sighash types (bits 0-1) ─────────────────────────────────────────────
/** Commits to all inputs and all outputs. Standard default. */
export const SIGHASH_ALL    = 0x01 as const;
/** Commits to all inputs, no outputs. Rare; allows output malleability. */
export const SIGHASH_NONE   = 0x02 as const;
/** Commits to all inputs and the output at the same index as the input. */
export const SIGHASH_SINGLE = 0x03 as const;

// ── Modifier flags ────────────────────────────────────────────────────────────
/**
 * BSV SIGHASH_FORKID (0x40) — instructs the engine to use the BIP-143
 * digest algorithm (commitment of input value, quadratic-hashing fix).
 * Required for standard P2PKH on BSV mainnet since the BCH/BSV fork.
 */
export const SIGHASH_FORKID = 0x40 as const;

/**
 * SIGHASH_ANYONECANPAY (0x80) — only commits to the current input;
 * other inputs can be added by third parties.  Required by BRC-115 for
 * identity-linked transfers.
 */
export const SIGHASH_ANYONECANPAY = 0x80 as const;

/**
 * Chronicle sighash algo flag — PLACEHOLDER (currently 0x00, no-op).
 *
 * The Chronicle BSV node release is expected to expose a new/restored
 * sighash algorithm via a dedicated flag bit.  Update this constant
 * when the spec publishes the bit.  Because every pre-built combination
 * below ORs this in, a single change here propagates everywhere.
 *
 * TODO: set to the correct bit once the Chronicle spec is published.
 */
export const SIGHASH_CHRONICLE_ALGO = 0x00 as const;

// ── Pre-built combinations ────────────────────────────────────────────────────

/**
 * Standard BSV P2PKH / actuator-activate default.
 * Commits to all inputs and all outputs; uses BIP-143 algorithm.
 *   0x41 = SIGHASH_ALL | SIGHASH_FORKID
 */
export const SIGHASH_ALL_FORKID =
  (SIGHASH_ALL | SIGHASH_FORKID | SIGHASH_CHRONICLE_ALGO) as number;

/**
 * BRC-115 identity-linked transfer.
 * Commits to this input + the corresponding output only; any other
 * inputs can be added (e.g. fee bump by a coordinator).  Uses BIP-143.
 *   0xc3 = SIGHASH_SINGLE | SIGHASH_ANYONECANPAY | SIGHASH_FORKID
 */
export const SIGHASH_SINGLE_ACP_FORKID =
  (SIGHASH_SINGLE | SIGHASH_ANYONECANPAY | SIGHASH_FORKID | SIGHASH_CHRONICLE_ALGO) as number;

/**
 * BRC-115 + Chronicle algo (forward-compat alias).
 * Same as SIGHASH_SINGLE_ACP_FORKID for now; will change when
 * SIGHASH_CHRONICLE_ALGO is non-zero.
 */
export const SIGHASH_SINGLE_ACP_FORKID_CHRONICLE = SIGHASH_SINGLE_ACP_FORKID;
