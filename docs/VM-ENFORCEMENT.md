# VM enforcement

The cell engine is a Bitcoin Script-compatible VM with Semantos extension
opcodes. It is not just a parser or telemetry format.

## What the engine enforces

`kernel_execute()` runs the unlock script and lock script through the embedded
cell-engine WASM. It returns `0` only when:

- both scripts execute without opcode/runtime error;
- all `OP_VERIFY`, `OP_EQUALVERIFY`, `OP_CHECKSIGVERIFY`, and related checks
  pass;
- conditionals are balanced;
- stack/resource bounds are respected;
- the final stack is non-empty and the top item is truthy.

Non-zero return means reject. The firmware should treat non-zero as "do not
actuate."

The core executor also bounds execution and rejects malformed scripts: invalid
opcodes, stack underflow/overflow, invalid pushdata, unbalanced conditionals,
failed sighash / missing tx context, failed linearity checks, failed capability
checks, budget failures, and host/storage failures all reject the script.

## What physical enforcement means

The VM enforces the script decision. Physical enforcement happens when firmware
gates an action on that decision.

For example, `examples/mesh_demo` does this:

1. Decode a `cellmesh.scripted.v0` payload into unlock script, lock script, and
   optional BIP143 transaction context.
2. Call `semantos_kernel_load_tx_context()` if `OP_CHECKSIG` is needed.
3. Call `semantos_kernel_load_script()` and `semantos_kernel_load_unlock()`.
4. Call `semantos_kernel_execute()`.
5. Only actuate/blink when the VM accepted.

So the script is the interlock, but the application still decides what physical
effect to bind to an accepted script.

## Bitcoin Script surface

The embedded engine implements the Bitcoin Script / BSV-restored opcode surface
through `OP_CHECKMULTISIGVERIFY` (`0xAF`), including:

- pushdata and small integer pushes;
- flow control: `OP_IF`, `OP_NOTIF`, `OP_ELSE`, `OP_ENDIF`, `OP_VERIFY`,
  `OP_RETURN`;
- alt stack and stack manipulation: `OP_TOALTSTACK`, `OP_FROMALTSTACK`,
  `OP_DUP`, `OP_DROP`, `OP_SWAP`, `OP_ROT`, `OP_PICK`, `OP_ROLL`, and related
  multi-item operations;
- restored string/splice and bitwise operations: `OP_CAT`, `OP_SPLIT`,
  `OP_NUM2BIN`, `OP_BIN2NUM`, `OP_INVERT`, `OP_AND`, `OP_OR`, `OP_XOR`;
- equality, arithmetic, comparison, min/max/within;
- hashing and signature checks: `OP_SHA1`, `OP_RIPEMD160`, `OP_SHA256`,
  `OP_HASH160`, `OP_HASH256`, `OP_CHECKSIG`, `OP_CHECKSIGVERIFY`,
  `OP_CHECKMULTISIG`, `OP_CHECKMULTISIGVERIFY`.

Reserved/version opcodes fail. This is a Bitcoin Script-compatible embedded VM,
not a claim of consensus-identical node behavior.

## Semantos extensions

Semantos adds extension families above the core Bitcoin Script range:

- `0xB0..0xB8`: Craig macro opcodes such as `XSWAP`, `XDROP`, `XROT`, `HASHCAT`.
- `0xC0..0xCF`: Plexus opcodes for linear/affine/relevant type checks,
  capability checks, identity checks, payload/header access, signing, and
  budget debit/refill.
- `0xD0`: `OP_CALLHOST` for named host functions.
- `0xD1`: `OP_WRITEPAYLOAD`.
- `0xE0`: `OP_BRANCHONOUTPUT` for output-index-aware routing scripts.

See `docs/OPCODE-PARITY.md` for the current extension table and parity check.

## How to describe it

Good wording:

> Semantos Edge embeds a Bitcoin Script-compatible VM on ESP32-C6: original /
> BSV-restored script opcodes plus Semantos linear-type, capability, hostcall,
> and routing extensions. The VM returns accept/reject, and firmware gates
> physical actions on that result.

Avoid:

> Consensus-identical Bitcoin node on a microcontroller.

That is not what this kit claims.
