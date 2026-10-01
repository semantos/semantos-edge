# Turn the light on — meetup run sheet

Phones open one https URL inside BSV Browser, tap the button, and the wallet
pays 100 sats. Each payment then lights the board once, one person at a time.
The page tells each phone its place in the queue, then shows `LIT ✓` or the
error text.

## At the venue

1. Plug **board A** (`58:e6:c5:1a:8b:28`) into the Mac by USB. It is the injector.
2. Power **B** and **C** from USB power packs. Nothing else is plugged into them.
   Plugging them in also resets them, which clears any old channel.
3. Run `./start-light.sh`, then **approve the Metanet Desktop dialog** when the
   script tells you to.
4. The script prints `LIVE` once `https://todriguez.com/cfb/light` points at
   the tunnel. Ctrl-C stops everything and unpublishes the URL.

`./start-light.sh --blink` is the fallback. It needs only board A, and each
payment makes A's LED pulse three times.

**Power banks:** a C6 with its radio always listening probably draws about
80–100 mA (estimated, not measured). Some banks switch off below a minimum
current. If a board goes dark after about 30 s with no payment involved, use
a bank that has a low-current or "always on" mode.

## Metered mode: sats buy seconds, and the chip is the meter

The phone offers 12, 36 or 72 sats, which is about 10, 30 or 60 s. The
chosen amount becomes the 402 price. Each verified payment turns into one
`channel_commitment` that raises `device_share`. B and C each meter
themselves at 1.2 sats/s, and each switches its own LED off once it has
consumed more than it was paid. Every phone polls `GET /meter` and shows
the seconds left, so the room can see that paying together keeps the
light on.

Measured on the bench, 2026-10-01, with B and C on USB so their logs could
be read:
- **12 sats:** `CHANNEL COMMIT seq=1 device_share=12` at t=591.8 s, then
  `METER EXHAUSTED consumed=14 > 12` at t=603.2 s. The light was on for
  11.4 s.
- **Back to back, 36 + 36:** `COMMIT seq=1 share=36` at t=628.4 s, then
  `COMMIT seq=2 share=72 consumed=23` at t=647.9 s (the light extended),
  then `METER EXHAUSTED` at t=689.8 s. That is 61.4 s, against the
  bridge's estimate of 60.8 s.
- **A board that reboots** (someone unplugs it) loses the channel. The
  bridge re-sends `channel_open` with the same id before a payment if the
  last open is more than 30 s old. Boards still in the channel answer
  `apply_open rc=-1` and carry on; the rebooted board rejoins. **Caveat:**
  the rejoined board starts a fresh meter against the whole share of the
  current lit stretch, so it can stay on longer than the others until
  that stretch ends.
- **When the light is out, the next payment starts a new channel:** the
  bridge re-sends the last commitment, sends `channel_close`, then a new
  `channel_open`. So the first payment after the light goes dark takes
  about 10 s to light, and later ones about 3 s.
- **Restarting the bridge** closes the channel it remembers in
  `~/.semantos-light-channel.json` and opens a new one. If the boards are
  in a channel the bridge does not know about, they ignore it until they
  are power-cycled.

## The bench (B and C reflashed 2026-10-01)

| board | port on the Mac | MAC | firmware | at the venue |
|---|---|---|---|---|
| A | `/dev/cu.usbmodem11201` | `58:e6:c5:1a:8b:28` | mesh_demo | injector, on the Mac's USB |
| B | `/dev/cu.usbmodem11301` | `58:e6:c5:1a:8c:54` | mesh_demo (was cold_chain `temp_logger` gateway) | actuator, power pack |
| C | `/dev/cu.usbmodem11401` | `58:e6:c5:1a:8c:f8` | mesh_demo (was cold_chain `temp_logger` sensor) | actuator, power pack |

B and C were flashed with esptool from the existing
`examples/mesh_demo/build`, built Aug 31. That build contains the
CHANNEL and METER handling.

## Manual commands (what the script runs)

```sh
# metered (default)
bun tools/x402-bridge/server.ts --port 4021 --real-payment --max-sats 500 --no-bridge-broadcast \
  --metered --inject-port /dev/cu.usbmodem11201

# blink fallback (./start-light.sh --blink): A pulses three times per payment
bun tools/x402-bridge/server.ts --port 4021 --real-payment --max-sats 500 --no-bridge-broadcast \
  --inject-port /dev/cu.usbmodem11201 --ack-port /dev/cu.usbmodem11201 --ack-match "CELL INJECTED"
```

`--real-payment` asks Metanet Desktop (`localhost:3321`) for the receive
key at startup. **Answer its permission dialog.** If you leave it
unanswered, Metanet Desktop hangs rather than failing.

## The https URL for phones

`start-light.sh` starts `cloudflared tunnel --url http://localhost:4021`
itself and publishes the URL behind `https://todriguez.com/cfb/light`.
Every new tunnel URL is a new origin, so each phone's wallet asks for
permission again.

## While it runs

- `curl localhost:4021/meter` shows the seconds left, the sats paid and
  the channel (metered mode).
- `curl localhost:4021/queue` shows the queue length and whether the board
  is lighting now.
- `curl localhost:4021/queue?ticket=<txid>` shows one payment's state.
- Ctrl-C stops the server and frees the serial port.

## How it behaves

- Payments are handled one at a time. In metered mode, each one waits for
  A's `*** CELL BROADCAST ***`. Boards on power packs cannot be heard, so
  "lit" means A broadcast the commitment. In blink mode, each payment waits
  for its own ack, then the queue holds 5.5 s.
- If the device stays silent past the timeout, that payment answers 504 and
  the queue moves on.
- A payment lights once. Sending the same txid again answers
  `409 payment already used`. The used-txid list is kept in memory and is
  lost on restart.
- The phone page uses `POST /actuator/activate?async=1`, which returns 202
  plus a ticket, and then polls `/queue`. No request stays open long, so the
  tunnel's 100 s limit is never hit.
