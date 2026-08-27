# fleet-zig

Plexus key derivation in Zig, on [bsvz](https://github.com/b-open-io/bsvz).

```bash
zig build test --summary all     # 63 conformance tests against the SDK's oracle
zig build hw                     # drive two real ESP32-C6 boards
```

**The Zig control plane, complete.** Derivation, certificate ids, the store,
cert issuance, the hardware proof re-run end to end from Zig, recovery recipes in
both directions, and SCIM mirroring from an existing IdP. The port
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
| `cert.buildPayload(...)` | the 66 bytes `cm_cap_install` reads |
| `cert.mintCell(...)` | the 1 KB cell the radio carries |
| `cert.signCell` / `verifyCell` | raw r‖s, low-S, over a single SHA-256 |
| `recovery.exportRecipe(...)` | paths + high-water marks, no key material |
| `recovery.importRecipe(...)` | rebuild a fleet from a recipe and the root |
| `scim.Mirror` | an IdP's directory projected onto the derivation tree |
| `scim_wire.parse(...)` | what Okta and Entra actually send, in either dialect |

`plexus-kdf-v2` and `v3` are in the vector and deliberately not ported — v1 is
what a fleet uses.

## SCIM mirroring

The fleet is **not** the source of truth. Okta or Entra is, and this mirrors what
it pushes — nobody rips out their directory, and a control plane that demanded to
own identity would never get deployed. What it adds is the half SCIM cannot do.

When an IdP deactivates someone it sends `active: false`. That is **advisory**: a
flag every downstream app has to be trusted to honour, which sessions and tokens
already issued survive. Here it **burns the seat** — the index is consumed, so the
next person into it derives a different key and the departing holder's position
is never reissued. Reactivation therefore gives a **new** seat, not the old one
back; SCIM has no opinion on this and returning the old index would un-retire a
burned one.

What burning does *not* do is reach access already in the field. Spending the
departing holder's capability grants is a separate act. Burning governs who comes
next.

| SCIM | fleet |
|---|---|
| Group | a zone, `deriveChild(root, "zone", …)` |
| User | a member, `deriveChild(zone, "member", …)` |
| `externalId` | the stable handle a position is remembered by |

Identity is keyed on `externalId`, never `userName` — people change their names,
and a rename must not move anyone's key.

### The trap this module exists for

Okta deactivates with **no `path`** and `value` as an **object**:

```json
{"Operations":[{"op":"replace","value":{"active":false}}]}
```

Entra sends the other shape — `path` present, `value` a bare boolean, `op`
capitalised. Both are RFC-legal: §3.5.2.3 makes `path` optional. A provider
written for one dialect does not *error* on the other; it parses the request,
recognises nothing, and returns **200 with the user still active**. Every
offboarding fails silently while the IdP reports success.

Both dialects are parsed here, and the tests carry both payloads verbatim. Two
more that bite the same way: Okta **never** sends `DELETE /Users` (deprovisioning
is always the soft delete), and integrations built with the App Integration
Wizard send **PUT for everything** including deactivation, with no way to
reconfigure them.

**Deliberately not implemented:** filtering beyond the `userName eq "…"`
existence probe, pagination, bulk, ETags, `/Schemas`, `/ResourceTypes`,
`/ServiceProviderConfig` (Okta does not call it). Stated rather than stubbed — a
stub that returns 200 is exactly how the trap above happens. An unsupported
filter is *refused*, because answering it with an empty list tells the IdP the
user does not exist and it will cheerfully create a duplicate.

There is no HTTP server here yet: `scim_wire` parses and renders, and binding it
to `std.http.Server` is the remaining step. Zig 0.15's server has no request
timeout, which is worth knowing before it faces the internet.

## Recovery, in both directions

```bash
bun run fleet:zig:interop     # from the repo root
```

A recipe carries derivation paths and per-slot high-water marks, never key
material — every key is a function of the operator root, which stays out of the
recipe by construction.

The conformance suite proves this plane can **consume** what the SDK emits, by
replaying five payloads through the SDK's real `reconstituteFromRecoveryExport`
and matching what the rebuilt allocator hands out. The interop script proves the
other direction, which cannot live in a Zig test because the oracle is a
TypeScript function:

```
SDK <- Zig recovery recipe
  ok   root certId round-trips            got 8607c26f...
  ok   next zone index                    got 1
  ok   next device index (issued + burned) got 4
```

That last line is the one worth reading: three units were issued and one slot was
burned, and the SDK — reading a recipe this plane wrote — hands out 4. **A fact
only the store knew survived the language boundary.** A plane that could only
import would be a plane that cannot back anything up.

**The counter in a recipe is not trusted.** It arrives from a service that does
not authenticate its callers, so a value below the paths replayed beside it is a
reachable input, not a malformed-payload hypothesis — and trusting it rewinds the
allocator under live certificates, reproducing a live holder's key exactly. Every
counter is floored against the payload's own paths; a triple the paths prove but
the domains never mention gets one anyway, because a rewind by omission is the
same rewind; and a counter *above* the paths is preserved, because that is what a
rotation's burn leaves behind. `importRecipe` reports how many counters it had to
floor, so a payload that would have rewound says so rather than being quietly
corrected.

**Paths are verified, not believed.** Each declares the certId it should arrive
at; import re-derives the ancestry and refuses one that does not reproduce it, so
a recipe cannot introduce a node the operator root would never have derived.

A recipe does **not** carry labels. A rebuilt fleet knows a unit is `member:2`
under a given zone and does not know it was called "cold-chain-01". Re-attaching
human names wants a separate, non-cryptographic backup.

## On real hardware, from Zig

```bash
zig build hw     # discovers two boards; needs USE_FLEET_ANCHOR 1 firmware
```

```
1. Provision a unit - every byte derived by this process
   operator anchor  0245ad80f7eb6d2222ad6741fe6aa6a9b51d5571c6945a43813cf4b71b5441e6d6
   device path      root/zone:6:0/device:6:0
   device pubkey    03e7b74fb9e2ce55b32e996215d4f51aa667f882a27c249adb330a6a533e3b18d5
   channel          9fce30f7673e30ac308300a93412c760

2. Inject the cert - the board must accept and install it
   I mesh_demo: CAP cert installed: ch=9fce30f7... edge=03e7b74f...
   ACCEPTED - echoed ch=9fce30f7... edge=03e7b74f... (matches what Zig derived)

3. Flip one byte - the board must refuse it
   W mesh_demo: RX [58:e6:c5:1a:8b:28] signature INVALID (wallet pubkey)
   REJECTED - the tamper did not survive cm_sig_verify

4. Sign with the OLD demo key - the board must refuse that too
   W mesh_demo: RX [58:e6:c5:1a:8b:28] signature INVALID (wallet pubkey)
   REJECTED - the boards trust the fleet root, not the key they shipped with
```

Derivation, certificate, signature, CRC framing and serial I/O all happen in that
one process. Nothing is borrowed from the TypeScript plane except the boards.

**The device key and channel are byte-identical to what the TypeScript plane
produced** for the same fleet — and since the channel is the device certId's
first 16 bytes, matching it also proves the canonical-JSON certId agrees. That
parity is pinned as a test (`hardware parity: ...`), so it is checked in CI
rather than noticed by eye during a hardware run.

## "Byte-identical" holds for the cert, not the signature

M4's stated gate was that a cert issued here is byte-identical to the TypeScript
plane's. That holds for **the 66-byte payload and the 1 KB cell**, and tests
assert exactly that.

It does **not** hold for the signature, and cannot. Both planes are deterministic
and neither uses randomness, but they derive the ECDSA nonce differently:
`@bsv/sdk` runs its own HMAC-DRBG, bsvz delegates to Zig's
`std.crypto.sign.ecdsa`. Same key, same digest, two different valid signatures —
measured in `spike/src/sigcmp.zig`, not assumed.

That is not a defect, because the nonce is not part of any contract. What is
contractual is that the signature verifies against the operator key and is low-S,
so the tests assert **interoperability in both directions**: Zig verifies what
TypeScript signed, TypeScript's anchor verifies what Zig signed, and the two
signatures are asserted to *differ* — so if a future toolchain quietly converges
on one nonce scheme, the suite says so rather than passing on a stale assumption.

**Low-S has to be applied deliberately.** bsvz returns whatever `std.crypto`
produced, which is above half-n about half the time, while `@bsv/sdk` forces
low-S by default. A high-S signature still verifies through mbedTLS on the
device, so this would never have failed loudly — the two planes would simply have
disagreed about what they emit. The test signs 24 cells, because one sample
passes an unnormalised signer by luck.

The cell layout is **not re-declared** here. It is imported from
`components/cell-mesh-zig/src/cell_wire.zig` — the same file the firmware builds
against — so a wire-format change cannot leave the control plane behind. The
66-byte payload offsets are checked against `cell_capability.h` by parsing it.

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
| drop low-S normalisation | yes |
| payload root over the used prefix, not the full region | yes |
| cert offsets, route type, linearity, owner-id length | yes |
| expiry written big-endian | yes — *after* a test was added |
| recovery trusts the declared counter | yes |
| recovery skips triples the domains omit | yes |
| recovery takes the last sibling row, not the max | yes |
| recovery does not verify a path re-derives | yes |
| recovery floor off by one | yes |
| drop Okta's pathless PATCH branch | yes |
| drop Entra's path-addressed branch | yes |
| match `op` case-sensitively | yes |
| key identity on userName not externalId | yes |
| PUT not treated as a replacement | yes |
| ListResponse totals as strings | yes |
| error `status` as an integer | yes |
| deactivate does not burn | yes |
| reactivation reuses the old seat | yes |

Three of those rows say "after a test was added", and they are the honest part of
this table. Two store mutations and one cert mutation initially survived: `raise`-vs-`set` was
invisible because a log this store writes is always ordered, and the torn-record
guard was only ever exercised by fragments that fail to parse. The third is the
neatest: **expiry written big-endian was invisible because the only expiry in the
vector was `UINT64_MAX`** — eight `0xff` bytes, which read identically either
way. Fixed by generating a second cert with a real expiry whose every octet
differs. None of the three was visible from reading the tests; only from breaking
the code and watching them stay green.

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
