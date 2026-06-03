# x402↔cell bridge

A tiny HTTP↔cell-mesh adapter that lets a **Dolphin Milk-style agent**
([calhooon/dolphinmilk](https://github.com/calhooon/dolphinmilk)) pay a
rentable cell-mesh device over BSV-native x402. The agent already knows how
to pay any x402 endpoint; this bridge turns "I got paid" into "actuate the
physical device" by broadcasting a wallet-signed `actuator_activate.v0`
cell and waiting for the device's `*** ACTUATOR ACTIVATED ***` ack.

It's the third leg of the Metered Flow Protocol work:
- **#543** consumer flow-adapter + BRC-43 protocolID
- **#546** iframe-wallet `WalletPort` binding
- **#550** device-side draining meter (on-C6)
- **this** HTTP↔cell x402 bridge — the agent on-ramp

## The flow

```
agent (Dolphin Milk)              bridge (this)                 C6 device
────────────────────              ─────────────                 ─────────
GET /.well-known/x402-info  ────► manifest (price = offer.cost)
POST /actuator/activate     ────► 402 + x-bsv-payment-* headers
build BRC-29 payment
POST + x-bsv-payment        ────► verify payment
                                  build actuator_activate.v0
                                  broadcast ───────────────────► verify frame sig,
                                                                  cell-engine ACCEPT,
                                  ◄───────────────────────────── *** ACTUATOR ACTIVATED ***
                                  200 + receipt
```

The same wallet key signs the BSV-script unlock the device's cell-engine
checks — the crypto vocabulary is identical on both legs. The bridge is a
transport adapter that also *fronts the payment*: the agent pays the
bridge over x402; the bridge pays the device's lock over the mesh.

## Wire (Dolphin Milk's BSV x402, not Coinbase/EVM)

402 response headers:

| header | value |
|---|---|
| `x-bsv-payment-version` | `1.0` |
| `x-bsv-payment-satoshis-required` | price in sats |
| `x-bsv-payment-derivation-prefix` | base64 nonce (BRC-29/42 derivation) |
| `x-bsv-payment-transports` | `header,multipart` (BRC-105) |

Payment request header: `x-bsv-payment` = BRC-29 payment JSON
(`{ derivationPrefix, derivationSuffix, transaction }`), raw or base64.
Success: `200` + `x-bsv-payment-satoshis-paid` and a JSON receipt.

## Run it

```bash
bun tools/x402-bridge/server.ts --port 4021
```

```bash
# discovery (free)
curl -s localhost:4021/.well-known/x402-info | jq

# 402 challenge
curl -i -X POST localhost:4021/actuator/activate

# pay (a funded tx with an output >= price)
curl -i -X POST localhost:4021/actuator/activate \
  -H "x-bsv-payment: {\"transaction\":\"<rawtx-hex>\"}"
```

## Test

```bash
bun test tools/x402-bridge/__tests__/
```

11 tests: actuator cell build/round-trip, the x402 challenge + payment
parse/verify, and the full discovery → 402 → pay → 200 round-trip against
a mock mesh (incl. underpayment-rejected and device-timeout→504).

## Modules

- `cell-codec.ts` — the 1024-byte cell wire + `actuator_offer/activate.v0`
  payloads + BIP-143 sighash + ECDSA, mirroring `sign-cell-deck.ts` and
  `docs/x402-over-cells.md` byte-for-byte.
- `x402.ts` — the BSV x402 dialect: challenge headers, payment parsing, and
  a pluggable `PaymentVerifier` (default: amount + funded-output check).
- `bridge.ts` — `X402CellBridge`: discovery / 402 / verify / actuate state
  machine over a `MeshPort` interface.
- `server.ts` — bun HTTP server wiring the endpoints.

## Hardware leg (next step)

The bridge is host-validated end-to-end with a dry-run mesh (it logs the
`actuator_activate.v0` cell and auto-acks). The live mesh leg needs **one
firmware addition not yet in `main.c`**: a USB-CDC command that reads a
framed cell off the bridge C6's serial and calls `cm_radio_send` to
broadcast it (the ack half — reading `*** ACTUATOR ACTIVATED ***` from the
destination C6's log — already works). With that command, a `SerialMeshPort`
drops into the same `MeshPort` seam and the full agent→bridge→device path
runs on real XIAOs. The produced cell bytes are already exactly what the
firmware's actuator handler parses (verified against the wire in tests).

## Real payment — MAINNET (`--real-payment`)

Makes the payment leg real, reusing the exact path that anchored the MNCA
cell on mainnet (`wallet.html`): **Metanet Desktop holds the keys** (BRC-42
derivation + recovery), funds via `createAction`, and ARC broadcasts.

```bash
# 1. Metanet Desktop running + funded on localhost:3321
# 2. bridge in real-payment mode (derives a recoverable receive key from MD,
#    verifies the agent's tx pays it ≤ --max-sats, broadcasts via ARC):
bun server.ts --port 4021 --real-payment --max-sats 1000 \
  --inject-port /dev/cu.usbmodemB --ack-port /dev/cu.usbmodemC --ack-from-mac <B-MAC>
# 3. the agent pays (funds via MD createAction → bridge verifies + broadcasts):
bun pay-demo.ts --bridge http://localhost:4021
```

Flow: discovery advertises `payTo.scriptHex` (MD-derived P2PKH) → agent funds
that output via MD `createAction` → POST `x-bsv-payment {transaction}` →
bridge `Brc29OnchainVerifier` confirms an output pays the bridge ≥ price
(≤ cap) → broadcasts via ARC (`arc.ts`) → actuates the C6 → `200` with the
real `txid` (+ `x-bsv-payment-txid` header). `whatsonchain.com/tx/<txid>`.

Guardrails: `--max-sats` caps accepted/broadcast value; without `--real-payment`
the bridge uses the simulated verifier (no real money).

**Hardening still open:** per-payment counterparty key rotation (full BRC-29
invoice derivation) for payer-unlinkability; right now the receive key is a
single recoverable MD-derived leaf per offer. Plugs into the same
`getPublicKey(protocolID,keyID,counterparty)` call.
