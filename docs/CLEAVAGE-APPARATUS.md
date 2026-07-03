# Cleavage apparatus

Short answer: the full Semantos lockscript cleavage apparatus is not present as
a first-class subsystem in this edge kit.

The edge kit contains the embedded VM and several lower-level primitives the
apparatus depends on. It does not currently contain the core Semantos workflow
that compiles cartridge manifests into separate `.lockScript`, `.unlockScript`,
and `.handler` sections, assembles BSV transactions, computes the exact sighash
boundary, asks the wallet to sign, and broadcasts through the broker layer.

## What "cleavage" means in core

In `semantos-core`, lockscript cleavage is the discipline that keeps Semantos
handler bytecode out of Bitcoin sighashes.

The invariant is:

```text
No byte authored in the .handler section ever appears in any Bitcoin sighash.
```

Core enforces that by separating a cell type into regions:

- `.lockScript`: consensus Bitcoin Script only; becomes the output script.
- `.unlockScript`: consensus Bitcoin Script only; becomes the input witness.
- `.handler`: full Semantos VM vocabulary; runs before signing and is never
  broadcast.
- cell payload: application state, committed by hash through the lock script.

The wallet should see the digest and derivation context it is being asked to
sign, not the handler script that produced the request.

## What exists in edge today

The edge kit does include:

- the embedded cell-engine WASM with Bitcoin Script and Semantos extension
  opcodes;
- cell construction and mutation primitives such as `OP_CELLCREATE`,
  `OP_DEMOTE`, `OP_READPAYLOAD`, and `OP_WRITEPAYLOAD`;
- output-index-aware routing via `OP_BRANCHONOUTPUT`;
- a BIP143 transaction-context loader for on-device `OP_CHECKSIG` verification;
- host-import bindings for hashing, signature verification, signing, host calls,
  cursor scans, block time, and sequence;
- a fail-closed `host_sign` default so boards do not hold wallet-tier keys by
  accident;
- cell framing, signing, routing, capability, and forwarding machinery for the
  ESP-NOW mesh.

That is enough for edge devices to verify pre-authored or pre-signed cells and
gate physical behavior on VM accept/reject.

## What does not exist in edge today

The edge kit does not currently include:

- a cartridge manifest compiler with `.lockScript`, `.unlockScript`, and
  `.handler` sections;
- a consensus-subset assembler that rejects Semantos-only opcodes in broadcast
  scripts;
- the full transaction assembly and sighash hostcall path from core;
- `bsv.tx.sign.request` style wallet handoff cells;
- a broker / ARC broadcast loop;
- the adversarial cleavage conformance tests or TLA+ model from core.

Those belong upstream today, in the core / gateway / wallet side of the system.

## Not the same thing

Several edge features look like "splitting" and can be confused with cleavage:

- `cell_frame_split()` breaks one signed 1024-byte cell plus signature into
  ESP-NOW frames and reassembles it on receipt. This is radio fragmentation.
- `forward.v2` sends two correlated cells: one application payload cell and one
  routing-continuation cell. This is routing payload management.
- `OP_SPLIT` is the restored Bitcoin Script byte-string split operation.

None of those are the lockscript cleavage apparatus. They are useful lower-level
mechanisms, but they do not by themselves prove that handler bytes stayed out of
the Bitcoin sighash.

## How to use this kit safely

For current public-edge experiments, treat the ESP32 as a verifier and actuator:

1. Author policy, transaction, and wallet-signing flows off-device.
2. Keep private keys and wallet-tier signing upstream by default.
3. Send the edge device pre-authored cells, pre-signed frames, or scripts with a
   loaded transaction context.
4. Gate physical behavior on `semantos_kernel_execute() == 0`.

If a collaborator wants the full cleavage workflow on or near the edge, the next
open-source milestone is a small "cleavage bridge" example:

1. Compile a minimal manifest off-device into lock/unlock/handler byte slices.
2. Prove the consensus sections reject Semantos-only opcodes.
3. Emit a sign-request cell that contains only digest plus derivation context.
4. Verify the returned signature on the ESP32 or a gateway.
5. Document exactly which stage runs on the board, gateway, wallet, and chain.

Until that exists, say that edge has the VM substrate and mesh transport, while
core has the full lockscript cleavage apparatus.
