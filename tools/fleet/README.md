# Fleet identity

Plexus derivation wired in as the identity control plane for a device fleet.
The firmware is unchanged.

```bash
bun run fleet:demo     # walk the whole lifecycle
bun run fleet:test     # 10 tests
```

## The split

**Plexus is the control plane.** It runs off-device, holds the operator root,
and derives every zone and unit. **semantos-edge is the device runtime**, exactly
as it is today: a unit installs a 66-byte `cellmesh.capability.v0` cert into
`cm_cap_table_t` and verifies it against the operator public key it was flashed
with.

The seam between them is **one 33-byte compressed public key**. No Plexus code
runs on the MCU, no BEEF crosses the boundary, and no unit is handed a private
key — the same rule the mesh already follows (`devices verify + act; wallets
sign`), reached from the other side.

```
operator root                    ← off-device, never leaves the control plane
  └─ zone:0    "North Depot"
       ├─ device:0  "cold-chain-01"   ─┐
       └─ device:1  "cold-chain-02"    │  33-byte pubkey → edge_pubkey
  └─ zone:1    "South Depot"           │  in a 66-byte cert, signed by
       └─ device:0  "gate-controller"  ─┘  the operator, verified on-device
```

## Why not the derivation that was already there

The bridge derived relay keys with an ad-hoc HMAC tweak —
`HMAC-SHA256(master_sk, "cell-routing-relay/" + channel_id)`, then
`child = (master + tweak) mod N`. It works, but it derives into nowhere: no
recorded path, no index, no way to retire a position, and nothing to rebuild
from if the machine holding the master key is lost.

Plexus gives the same shape a real BRC-42 derivation plus three things the HMAC
tweak cannot have:

| | HMAC tweak | Plexus |
|---|---|---|
| Reproducible from the root alone | no | yes — the path is recorded |
| Unit's position is an identity | no | yes — monotonic index per slot |
| Retire a position | no | `decommission()` burns the slot |
| Rebuild after losing the server | no | re-derive from the operator root |

## Lifecycle

```ts
const fleet = new Fleet({
  deriver: await openPlexusDeriver({ rootEmail, rootSalt }),
});

const anchor = await fleet.operatorPublicKey();   // flash this into every unit
const zone   = await fleet.addZone("North Depot");
const unit   = await fleet.addDevice(zone, "cold-chain-01");
// unit.certPayload  → 66 bytes, straight into cm_cap_install
// unit.certCell     → the 1 KB cell the radio carries
// unit.certSig      → raw r||s, what cm_sig_verify checks
```

**Decommissioning** burns the slot, so the replacement cannot be issued the key
the returned unit held:

```ts
const mark = await fleet.decommission(zone);   // burns the next free index
const rma  = await fleet.addDevice(zone, "cold-chain-01-rma");
// rma.node.index === mark, and its key differs from the returned unit's
```

What that does **not** do is reach the returned unit. Its cert stays installed
in whatever hardware still holds it until the cert expires, or until the meter
it drains runs out. A disconnected device cannot be told about a revocation, so
cutting one off is the expiry and metering path's job — see `cell_meter.h`. Burn
governs who comes next; it is not a remote kill.

## Recovery

Lose the provisioning server and the fleet re-derives from the operator root:
same zone keys, same device keys, same channel ids, so the certs already on
hardware still verify and nothing needs re-flashing. Step 6 of the demo does
exactly this with a control plane that has never seen the fleet.

`deriver.recipe()` returns the paths and per-slot high-water marks — never key
material — which is what a rebuilt fleet needs so it does not reissue a live
unit's index.

## Setup

The Plexus SDK is a private package, so it is imported dynamically from a path
you supply. This repo does not depend on it, and everything else here builds and
runs without it.

```bash
cd /path/to/plexus-sdk-ts && npx tsc -p tsconfig.build.json
export PLEXUS_SDK=/path/to/plexus-sdk-ts/dist/index.js
```

Without it, `fleet:demo` prints how to fix it and the derivation tests report as
**skipped** rather than passing:

```
[fleet] Plexus SDK not found — the derivation tests below are SKIPPED, not passing.
 2 pass   8 skip   0 fail
```

The two that still run are the firmware-header cross-checks, which need no SDK.
A suite that says "pass" without ever exercising the derivation reads as proof
and is not, so the skip count is the signal.

## Files

| | |
|---|---|
| `deriver.ts` | The port. Every method returns public material or signs; none returns a private key. |
| `plexus-deriver.ts` | The Plexus implementation. Swap it for an HSM or k-of-n root without touching `fleet.ts`. |
| `fleet.ts` | The control plane. Reuses the existing 66-byte encoder in `x402-bridge/capability-cert.ts` rather than duplicating the wire format. |
| `provision.ts` | The lifecycle demo. |

## Tests

Ten, against the real SDK. The two worth knowing about:

- **`no private key reaches a device`** — serializes everything in a provisioning
  packet and asserts the operator's private scalar appears nowhere in it.
- **`the cert layout tracks the firmware header`** — parses
  `cell_capability.h` and checks every offset against what the encoder produces,
  so a firmware layout change fails here rather than on a board.

## Known limits

- `cm_cap_table_t` holds **4** certs per unit (`CM_CAP_TABLE_MAX`). Fine for one
  cert per route type; a unit relaying many channels at once will hit it.
- Certs are stamped `expiry_ms = UINT64_MAX` (no expiry) by default, because the
  firmware has no RTC. Pass a real expiry once units have wall-clock time —
  until then expiry cannot do the revocation work described above.
- Provisioning costs one derivation per unit (~6.5 ms). A 10,000-unit fleet is
  about a minute.
