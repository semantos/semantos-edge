# x402-over-cells

Cell-mesh mapping of the [x402](https://x402.org) HTTP-402-payment-required
pattern. Lets IoT devices charge per-actuation in BSV, verifiable on
the device by the cell-engine (BSV-script), with no server in the loop.

In the broader [BRC ecosystem](https://brc.dev) the equivalent is BRC-120;
this document is the cell-mesh transport binding for the same flow.

## Two cell types

### `cellmesh.actuator_offer.v0`

The device's advertisement: *"this resource costs N to use for D ms; here
is the lock script that any payment must satisfy."*

Broadcast periodically by the rentable device (the **x402 server** in
the analogy). Plays the same role as an HTTP `402 Payment Required`
response — but it's pushed proactively, not request-response, because
the radio is broadcast-medium.

Payload layout (little-endian):

| offset | size | field |
|---|---|---|
| 0 | 4 | `version` (= 1) |
| 4 | 4 | `cost_sats` — price per activation |
| 8 | 4 | `duration_ms` — how long the resource stays active per accepted payment |
| 12 | 2 | `lock_len` |
| 14 | `lock_len` | `lock_script` — BSV-script bytes the payment must satisfy |
| 14 + `lock_len` | 2 | `tx_template_len` |
| 16 + `lock_len` | `tx_template_len` | `tx_template` — raw BSV tx skeleton the payment must build on (BIP-143 prevTxid + outputs etc. for sighash) |
| 16 + `lock_len` + `tx_template_len` | 4 | `input_idx` |
| 20 + `lock_len` + `tx_template_len` | 8 | `input_value` (sats; BIP-143 sighash field) |
| 28 + `lock_len` + `tx_template_len` | 16 | `offer_id` (random, for correlation) |

### `cellmesh.actuator_activate.v0`

The wallet's payment: *"here is a signed unlock that satisfies the offer's
lock; please activate."*

Constructed by a wallet (or a Dolphin Milk-style agent) that observed
an `actuator_offer.v0`. The unlock is a BSV-script witness — for the
demo, a `<DER_sig || SIGHASH_ALL|FORKID>` produced by ECDSA-signing the
BIP-143 sighash of (offer's tx_template + offer's lock_script + offer's
input_value) with a wallet privkey.

Payload layout (little-endian):

| offset | size | field |
|---|---|---|
| 0 | 2 | `lock_len` |
| 2 | `lock_len` | `lock_script` — must match the offer's lock_script (echoed for engine convenience) |
| 2 + `lock_len` | 2 | `unlock_len` |
| 4 + `lock_len` | `unlock_len` | `unlock_script` — `PUSH(N)` of `(DER_sig \|\| sighash_byte)` |
| 4 + `lock_len` + `unlock_len` | 2 | `tx_len` |
| 6 + `lock_len` + `unlock_len` | `tx_len` | `tx_bytes` — raw BSV tx the wallet computed sighash over |
| 6 + `lock_len` + `unlock_len` + `tx_len` | 4 | `input_idx` |
| 10 + `lock_len` + `unlock_len` + `tx_len` | 8 | `input_value` |
| 18 + `lock_len` + `unlock_len` + `tx_len` | 16 | `offer_id` — matches the offer this activates |
| 34 + `lock_len` + `unlock_len` + `tx_len` | 4 | `counter` — per-cell uniqueness (cell-hash dedup) |

## The flow

```
device (rentable, x402-server)              wallet / agent (x402-client)
───────────────────────────────             ────────────────────────────
broadcast actuator_offer.v0  ───────────►   observe; parse cost + lock + tx_template
(periodic, every 5–10 s)                    ▼
                                            decide to pay
                                            ▼
                                            build payment:
                                              1. compute BIP-143 sighash over
                                                 (tx_template, lock_script,
                                                  input_idx, input_value)
                                              2. ECDSA-sign with wallet priv
                                              3. append sighash_byte (0x41)
                                              4. wrap as unlock script
                                            ▼
observe actuator_activate.v0   ◄─────────   broadcast actuator_activate.v0
verify wallet sig at frame level
▼
hand to cell-engine:
  kernel_load_tx_context(tx_bytes, ...)
  kernel_load_script(lock_script)
  kernel_load_unlock(unlock_script)
  kernel_execute()
▼
if ACCEPT (script returned 1):
  led_active_until_ms += duration_ms
  log "*** ACTUATOR ACTIVATED ***"
if REJECT:
  drop, log "actuator REJECTED"
```

## For a Dolphin Milk bridge

A Dolphin Milk agent could pay this device with no custom code, given
a tiny HTTP-↔-cell bridge (~100 LOC, one of the C6s + a bun process):

1. **HTTP discovery** — bridge exposes `GET /actuator` which returns a
   JSON description of the active `actuator_offer.v0` it last heard:
   `{ cost_sats, duration_ms, lock_script_hex, tx_template_hex, input_idx, input_value, offer_id }`.

2. **HTTP 402 challenge** — bridge exposes `POST /actuator/activate`.
   First call returns `402 Payment Required` with the lock + tx_template
   in the `WWW-Authenticate`-shaped header (matching x402's envelope).

3. **Payment** — Dolphin Milk constructs the BSV payment (it already
   knows how — same `@bsv/sdk` we used in `sign-cell-deck.ts`), retries
   the POST with the signed payment in `X-Payment` header.

4. **Bridge wraps + broadcasts** — bridge constructs the
   `actuator_activate.v0` cell from the agent's payment, broadcasts on
   the mesh, waits for the device's `*** ACTUATOR ACTIVATED ***` log
   line (read via USB-CDC), returns `200 OK` with the offer_id +
   timestamp as the activation receipt.

5. **On-chain proof** — Dolphin Milk separately anchors the activation
   on chain via its normal proof flow, since the wallet sig it produced
   is already a valid BSV-script witness.

The crypto + script vocabulary is identical on both sides — the bridge
is purely a transport adapter, no protocol translation. Same wallet
signs HTTP-x402 payments and cell-mesh payments interchangeably.
