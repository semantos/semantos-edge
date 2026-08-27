# fleet-zig

Plexus key derivation in Zig, on [bsvz](https://github.com/b-open-io/bsvz).

```bash
zig build test --summary all     # 33 conformance tests against the SDK's oracle
```

**M1–M3 of the Zig control plane: derivation, certificate ids, and the store.** The port
reproduces the Plexus SDK byte-for-byte, checked against the SDK's own vectors
rather than against expectations written here. From `(rootEmail, rootSalt)` alone
it recomputes the root certificate id and every id in the vector's counter
sequence.

## Why Zig, and why here

The TypeScript fleet plane in `tools/fleet/` runs on a laptop. This one is meant
to run on the substrate — a brain, a Pi, anywhere the rest of semantos runs.

It lives in `tools/` rather than `components/cell-mesh-zig` on purpose.
`cell-mesh-zig` has **no `build.zig.zon` at all** and stays dependency-free
because it targets a chip where the cell engine and Wi-Fi already do not both fit
in 329 KB. Keeping the code that *can derive* in a host-only tree makes "no
private keys on device" structural rather than remembered.

## What is implemented

| | |
|---|---|
| `deriveRootKey(email, salt)` | PBKDF2-HMAC-SHA512, 100k iterations, 32 bytes |
| `buildInvoiceNumber(resourceId, flag, index)` | `resourceId:flag:index`, flag DECIMAL |
| `deriveChildV1(parent, invoice)` | `plexus-kdf-v1` — BRC-42, self-counterparty |
| `derivePrivateKeyAtPath(email, salt, path)` | walks `root/inbox:2:0/sub:3:2` |
| `encodeDomainFlag(flag)` | `0x1fe02` — HEX, lowercase, unpadded, for cert fields |
| `ChildCounters` | monotonic index per `(parentCertId, resourceId, domainFlag)` |
| `canonicalJson(preimage)` | the exact bytes `computeCertId` hashes |
| `computeCertId(preimage)` | `sha256hex(canonicalJson(...))` |
| `rootIdentity(email, salt)` | the root's pubkey, serialNumber and certId |
| `deriveChildIdentity(...)` | a child's key, path, serialNumber and certId |
| `Store.allocateIndex(...)` | consume the next free index at a context |
| `Store.burnSlot(...)` | rotation — consume without issuing, return the new mark |
| `Store.restoreCounter(...)` | recovery restore; refuses to rewind |
| `Store.putNode` / `getNode` / `children` | the provisioned fleet |

`plexus-kdf-v2` and `v3` are in the vector and deliberately not ported — v1 is
what a fleet uses. The 66-byte cert encoding and signing are M4.

## The store: one counter, not two

The SDK has `child_counters.next_index` AND `derivation_state.current_index`.
That is not a design, it is a repair: the two tables were written by different
code paths and nothing reconciled them, so `rotateContext` advanced a counter
`deriveChild` never read and rotation changed no key at all.

This store has **one** counter, and `highWaterMark` is a read of it. A port
should reproduce the SDK's behaviour, not the shape of its bug — and the
equivalence is checked rather than asserted, because
`vectors/gen-rotation-vector.mjs` drives the SDK's *real* `MemoryKeyStore`
through a scripted sequence of allocations, burns and restores and records every
return value. M3's gate was "port the SDK's rotation tests"; replaying its actual
trace is stronger, because a ported test re-states what I believe the semantics
are while a trace states what they are.

Persistence is an **append-only log**, which buys two properties structurally
rather than by a check: an allocation cannot be un-issued, and replay takes the
maximum so reopening is idempotent and order-independent. **The newline is the
commit marker** — a record whose bytes all landed but whose terminator did not is
dropped, which is the torn write that would otherwise be invisible, since the
fragment is perfectly valid JSON.

## Two shapes, and the ways they fork silently

A certificate preimage has exactly two shapes. A root is **self-certified**
(subject == certifier) with `fields = {email}`; a derived node is certified by
its **immediate parent** — at depth 2 the certifier is the depth-1 child, not the
root. Certifying against the root produces a valid-looking id that no other
implementation agrees with, and every descendant inherits the fork.

The same certificate carries the domain flag **twice, in two encodings**: the
invoice number uses DECIMAL (`inbox:130562:7`) while `fields.domainFlag` uses
unpadded lowercase HEX (`0x1fe02`). Both are pinned by tests.

## The confusion this port exists to avoid

semantos-core already derives BRC-42 keys in Zig via `host.deriveLeaf`. It is
**not reusable here**, and both call the same `bsvz` primitive, which is what
makes the trap expensive:

| | `host.deriveLeaf` | this |
|---|---|---|
| invoice | `protocol_hash[16] ‖ index_le[8]` — 24 binary bytes | `resourceId:flag:index` — ASCII |
| counterparty | an **external** public key | the parent's **own** public key |
| context key | `(protocol, counterparty)` — BRC-43 shaped | `(parentCertId, resourceId, domainFlag)` |

Same primitive, different derivation, different keys. A test in
`test/conformance.zig` derives the same invoice against a *different*
counterparty and asserts it does **not** match the vector, so the distinction
stays enforced rather than remembered.

## The tests are real

Conformance suites are easy to write so they cannot fail. This one was
mutation-tested — each of these was applied and the suite caught it:

| mutation | caught |
|---|---|
| invoice separator `:` → `-` | yes |
| PBKDF2 iterations 100,000 → 99,999 | yes |
| counter keyed on parent alone | yes — "expected 0, found 2" |
| certifier = child instead of parent | yes |
| serialNumber template `child:` → `derived:` | yes |
| `fields.domainFlag` decimal instead of hex | yes |
| sort keys by UTF-8 bytes instead of UTF-16 | yes |
| `0x0B` → `\v` instead of `\u000b` | yes |
| uppercase hex in `\u00XX` | yes |
| escape `/`, or escape DEL, or `\u`-escape non-ASCII | yes |
| burn does not consume an index | yes |
| restore allowed to rewind | yes |
| replay sets instead of raising | yes — *after* a test was added |
| torn record accepted | yes — *after* a test was added |

Two of those rows say "after a test was added", and they are the honest part of
this table. Both store mutations initially survived: `raise`-vs-`set` was
invisible because a log this store writes is always ordered, and the torn-record
guard was only ever exercised by fragments that fail to parse. Neither gap was
visible from reading the tests — only from breaking the code and watching them
stay green.

**The first run of that table is why the escaping vector exists.** Against the
SDK's derivation vector alone, four of those escaping mutations passed
undetected — because its three certId cases contain no quote, no backslash, no
control character, no non-ASCII and no slash. Every value is hex, an email, or a
dotted type name. An encoder can pass the whole vector and still be wrong for any
`resourceId` a human typed, which is the one field a fleet lets them name.

The counter row is why the SDK's vector carries `wrongIfKeyedOnParentAlone`.
Keyed on the parent alone, a five-call sequence yields `0,1,2,3,4`; keyed
correctly it yields `0,1,0,0,2`. Both look like working code.

So `vectors/gen-escaping-vector.mjs` generates 49 escaping cases and 5 sort cases
**from the SDK's own `canonicalJson`** — expected values captured from the oracle,
not written from a reading of the ECMAScript spec. Two of the 49 are marked
unrepresentable and skipped: a lone surrogate has no well-formed UTF-8 encoding,
so a Zig `[]const u8` cannot carry one in, and the divergence is unreachable
rather than merely untested.

Every assertion reads its expected value from a vector, so a drifting port fails
rather than a drifting test passing. Several tests guard the guards — asserting
the vectors still reach a colon, a control character, non-ASCII, and a
byte-vs-UTF-16 sort disagreement, so coverage cannot quietly evaporate.

## The sort is UTF-16, not bytes

The SDK sorts `fields` keys with JS `<`, which is **UTF-16 code-unit order**.
Sorting by UTF-8 bytes — the obvious thing in Zig, and what this port did at
first — disagrees for every pair of an astral character against one in
U+E000..U+FFFF: an emoji leads with a surrogate in `0xD800..0xDBFF` and sorts
FIRST in UTF-16, but leads with byte `0xF0` and sorts LAST by bytes. Different
key order, different canonical JSON, different certId, for two perfectly valid
keys.

Unreachable through this port's own callers, whose field keys are fixed ASCII.
Implemented correctly anyway, because `canonicalJson` is public here exactly as
it is in the SDK, and "our callers happen not to do that" is not a property the
type system enforces.

## Known behaviour that is preserved, not fixed

`resourceId` is not escaped, and the invoice is colon-delimited — so
`resourceId = "a:b"` renders `a:b:2:0`, which a different tuple could also
render. **The golden vector pins this case**, so the port reproduces it
deliberately. A port that rejected colons would diverge from every shipped
Plexus universe. Fix it in the SDK first, then here.

## Notes

- Zig 0.15.2. bsvz pinned to `b57fc31` — the same commit semantos-core pins,
  because a silent bump would move derivation under every provisioned fleet.
- The suite takes ~13 s in Debug and ~12 s in ReleaseFast. It is PBKDF2, not the
  test harness — 100k iterations, dozens of times. Not worth optimising; worth
  memoizing in anything that provisions at scale, as the SDK now does.
- `spike/` is the original 40-line conformance spike that scoped this work. It is
  superseded by these tests and kept because it is the smallest possible answer
  to "does bsvz reproduce Plexus derivation".
