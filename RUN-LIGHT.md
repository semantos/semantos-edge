# Turn the light on — meetup run sheet

Phones open one https URL inside BSV Browser, tap the button, and the wallet
pays 100 sats. Each payment then lights the board once, one person at a time.
The page tells each phone its place in the queue, then shows `LIT ✓` or the
error text.

## The bench, as found on 2026-10-01

| port | MAC | firmware |
|---|---|---|
| `/dev/cu.usbmodem11201` | `58:e6:c5:1a:8b:28` (A) | **mesh_demo** (accepts `IJ` inject frames) |
| `/dev/cu.usbmodem11301` | `58:e6:c5:1a:8c:54` (B) | cold_chain `temp_logger` gateway |
| `/dev/cu.usbmodem11401` | `58:e6:c5:1a:8c:f8` (C) | cold_chain `temp_logger` sensor |

The 5-second actuation needs two boards. One board, the injector, broadcasts
the cell, and a *second* mesh_demo board runs it and lights its LED. A board
never hears its own broadcast. Only A runs mesh_demo, so choose one of these:

### Option 1: a 5 s light (flash mesh_demo onto B first; NOT tested)

```sh
cd examples/mesh_demo && idf.py -p /dev/cu.usbmodem11301 flash   # B becomes the actuator
cd ../..
bun tools/x402-bridge/server.ts --port 4021 --real-payment --max-sats 500 --no-bridge-broadcast \
  --inject-port /dev/cu.usbmodem11201 --ack-port /dev/cu.usbmodem11301 \
  --ack-from-mac 58:e6:c5:1a:8b:28
```

### Option 2: the bench as it is (TESTED in dry-run against A)

The bridge acks on A's own `*** CELL INJECTED ***` line. A blinks its LED
three times for each send, and the bridge sends each activation three
times.

```sh
bun tools/x402-bridge/server.ts --port 4021 --real-payment --max-sats 500 --no-bridge-broadcast \
  --inject-port /dev/cu.usbmodem11201 --ack-port /dev/cu.usbmodem11201 \
  --ack-match "CELL INJECTED"
```

`--real-payment` asks Metanet Desktop (`localhost:3321`) for the receive
key at startup. **Answer its permission dialog.** If you leave it
unanswered, Metanet Desktop hangs rather than failing. The startup log
should then print `payment: MAINNET — pay-to 76a914…`.

## The https URL for phones

In a second terminal:

```sh
cloudflared tunnel --url http://localhost:4021
```

It prints `https://<words>.trycloudflare.com`. Phones open that URL in BSV
Browser. A QR code of it on the slide is easiest. Every new tunnel URL is a
new origin, so each phone's wallet asks for permission again.

## While it runs

- `curl localhost:4021/queue` shows the queue length and whether the board
  is lighting now.
- `curl localhost:4021/queue?ticket=<txid>` shows one payment's state.
- Ctrl-C stops the server and frees the serial port.

## How it behaves

- Activations run one at a time. Each one waits for **its own** device ack.
  After an ack, the queue holds for the light's duration plus 0.5 s, so each
  payer sees their own light.
- If the device stays silent past the timeout, that payment answers 504 and
  the queue moves on.
- A payment lights once. Sending the same txid again answers
  `409 payment already used`. The used-txid list is kept in memory and is
  lost on restart.
- The phone page uses `POST /actuator/activate?async=1`, which returns 202
  plus a ticket, and then polls `/queue`. No request stays open long, so the
  tunnel's 100 s limit is never hit.
