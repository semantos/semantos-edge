# fleet-zig

Plexus key derivation in Zig, on [bsvz](https://github.com/b-open-io/bsvz).

```bash
zig build test --summary all     # 12 conformance tests against the SDK's oracle
```

**M1 of the Zig control plane: derivation conformance.** The port reproduces the
Plexus SDK's derivation byte-for-byte, checked against the SDK's own pinned
golden vector rather than against expectations written here.

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

`plexus-kdf-v2` and `v3` are in the vector and deliberately not ported — v1 is
what a fleet uses. Rotation, the fleet store, cert encoding and signing are M3–M4.

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

| mutation | caught by |
|---|---|
| invoice separator `:` → `-` | 2 tests |
| PBKDF2 iterations 100,000 → 99,999 | 4 tests |
| counter keyed on parent alone | 2 tests, "expected 0, found 2" |

That last one is why the vector carries `wrongIfKeyedOnParentAlone`. Keyed on the
parent alone, a five-call sequence yields `0,1,2,3,4`; keyed correctly it yields
`0,1,0,0,2`. Both look like working code.

Every assertion reads its expected value from the vector, so a drifting port
fails rather than a drifting test passing.

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
