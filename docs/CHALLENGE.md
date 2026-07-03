# Meetup Challenge: What Can You Build?

The goal of this edge kit is not to convince you that Semantos is a
good idea. It is to let you play with a live, running cell-engine on
an ESP32 and see what falls out.

Here are some challenges, in rough order of ambition. Pick whichever
feels fun.

---

## Warm-up: prove it lives

- [ ] **Hello cell.** Flash `examples/hello_cell` and see it print
      `=== hello cell: success ===`. Free.
- [ ] **Custom script.** Replace `TRIVIAL_SCRIPT` in `main.c` with
      your own Bitcoin Script bytecode. Push two 4-byte values, ADD
      them, check the result.
- [ ] **Print all stack values.** After `kernel_execute`, loop
      `kernel_stack_peek(i)` from 0 to `kernel_stack_depth() - 1`
      and print each one. Understand what the 2-PDA actually does.

## Storage-adapter challenges

- [ ] **NVS-backed blob store.** Implement `storage_read` and
      `storage_write` against ESP-IDF's NVS. Key by `key` argument,
      values up to 4 KB. Reboot the board and verify values persist.
- [ ] **SPIFFS cell cache.** Same idea but with SPIFFS, so you can
      store bigger cells. Measure read/write latency and decide which
      wins for your workload.
- [ ] **PSRAM ring buffer.** On an ESP32-S3 with PSRAM, implement a
      large in-memory key/value store as a ring buffer. Measure how
      many cells you can keep alive simultaneously.

## Identity-adapter challenges

- [ ] **Provision an identity.** On first boot, generate a
      secp256k1 keypair, store the public key as a certificate JSON
      blob in NVS, and serve it via `identity_resolve`. Use the
      device MAC as `cert_id`.
- [ ] **Derived child certs.** Implement `identity_derive` using
      HKDF off the root key. Each derivation takes a `resource_id`
      and `domain_flag` and produces a unique child key. Test it by
      deriving two children from the same parent with different
      resource IDs and verifying they differ.
- [ ] **BLE provisioning.** Use `esp_ble_gatts` to let a phone app
      write the initial identity blob into flash at first boot.

## Anchor-adapter challenges

- [ ] **HTTP gateway anchor.** Implement `anchor_submit` to POST the
      state hash to a tiny gateway service you run on your laptop
      (a Python `http.server` is enough). Return a JSON proof.
- [ ] **ESP-NOW broadcast anchor.** Broadcast the state hash to all
      peers on the channel; collect proofs from any responder that
      acks. Fun for multi-device workshops.
- [ ] **SD card append-only log.** Every anchor submission gets
      written to a line in `/anchors.log` with a timestamp and
      sequence number. The proof is the byte offset of the entry.
- [ ] **LoRa anchor.** If you have a LoRa module (SX1276/SX1278),
      beam the state hash as an uplink and listen for an ack on a
      downlink. Sketch only — this one is ambitious.

## Network-adapter challenges

- [ ] **MQTT publish.** Implement `network_publish` to send the
      object JSON to an MQTT broker on `192.168.0.x` (or
      `test.mosquitto.org` if you trust the internet). Subscribe from
      a laptop and watch messages flow.
- [ ] **ESP-NOW mesh.** Multi-device workshop: every board
      broadcasts its objects over ESP-NOW and caches objects it
      receives in a local index. Query the index for
      `network_resolve`. Now you have a tiny mesh of Semantos
      cell-engines, each one holding a different view of the world.
- [ ] **mDNS resolve.** Implement only the `network_resolve` half:
      translate queries into mDNS lookups on the local network and
      return any matches. Good for device discovery.

## Hostcall-by-name challenges

These don't use adapters at all — they extend the kernel's vocabulary
instead by adding entries to `semantos_host_call_by_name`.

- [ ] **GPIO toggle.** Add `gpio.set <pin> <value>` so scripts can
      drive pins from inside the cell-engine.
- [ ] **ADC read.** Add `adc.read <channel>` returning the raw ADC
      value. Now scripts can react to sensor input.
- [ ] **WS2812 pixel.** Add `neopixel.set <index> <rgb>` using the
      RMT driver. Scripts become light programs.
- [ ] **I2C passthrough.** `i2c.write <addr> <reg> <val>`. Now the
      cell-engine can drive arbitrary peripherals.

## Full-stack challenges (pick two or more adapters)

- [ ] **Distributed counter.** Storage-backed monotonic counter that
      anchors to the network every 10 increments. Multiple devices
      converge on a common count via the network adapter.
- [ ] **Cert-gated LED.** A script runs on boot; if `identity_resolve`
      returns a valid cert, `hostcall gpio.set` lights a green LED;
      otherwise red. Physically visible identity enforcement.
- [ ] **Swarm oracle.** Each device publishes its current sensor
      reading via `network_publish`; the network_resolve returns the
      swarm median. Script decides whether to act.
- [ ] **Ephemeral payment meter.** Wire the metering package's 8-state
      FSM into storage + anchor, then make a script that "charges"
      based on elapsed blocktime. Requires digging into the main
      repo's `packages/metering`.

## Really ambitious

- [ ] **Pure-ESP32 Semantos node.** Implement all four adapters
      properly. Provision identity on first boot. Anchor to a real
      gateway. Publish and resolve over MQTT. Store cells in SPIFFS.
      Boot the device, hand it to someone else in the lab, and
      have it integrate into the rest of your setup automatically.
- [ ] **Zig ESP-IDF integration.** The pure `cell-mesh` modules now have Zig
      implementations behind the existing `cm_*` C ABI. Wire
      `components/cell-mesh-zig` into the ESP-IDF component build for C6 while
      keeping `cell_radio` and `cell_sig` C-facing.
- [ ] **Second radio.** The C6 has a RISC-V core and 802.15.4. Keep the
      WAMR runtime path, but build a Thread or Zigbee transport under the
      existing network adapter / frame API.

## Rules

There are no rules. Work on whatever sounds fun. Break things. Ignore
the "right" way when it's boring. Write up what you found so everyone
else can steal your ideas.

If something doesn't work the way the docs say, that's probably a bug
in the docs or the code. Open an issue with the board model, ESP-IDF version,
and the exact command you ran.
