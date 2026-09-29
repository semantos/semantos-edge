# temp_logger

A store-and-forward temperature logger on the XIAO ESP32-C6. A **node** rides in
a box with a DS18B20 probe, checks every reading against a heat policy in the
cell engine, keeps it in flash, and sends it over ESP-NOW whenever the
**gateway** answers. The gateway sits on a laptop's USB and hands batches to
`tools/templog-bridge`, which stores them and acknowledges them.

How it works, and the wire formats: [`docs/TEMP-LOGGER.md`](../../docs/TEMP-LOGGER.md).

## Parts, per node

- XIAO ESP32-C6
- DS18B20 waterproof probe, with a 4.7 kΩ pull-up between data and 3V3. The
  small adapter boards sold with the probes already have it.
- A USB power bank that stays on at low current. Leave a node running on its
  bank overnight before you trust it for a multi-day run.

The gateway is one more XIAO on the laptop's USB. It needs no probe.

## Wiring

| Probe | XIAO |
|---|---|
| red (VDD) | 3V3 |
| black (GND) | GND |
| yellow (data) | D0 (GPIO0) |

`examples/cold_chain` reads the probe on GPIO4, which on the XIAO is only a pad
on the back. Here the pin is `menuconfig → Temp logger → DS18B20 data GPIO`.

## Build

```bash
source ~/esp/esp-idf/export.sh
cd examples/temp_logger

# node
idf.py -B build-node -D SDKCONFIG=build-node/sdkconfig build

# gateway
idf.py -B build-gateway -D SDKCONFIG=build-gateway/sdkconfig \
  -D SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.gateway" build

# node with a simulated probe, reading every 10 s (bench runs, no DS18B20)
idf.py -B build-mock -D SDKCONFIG=build-mock/sdkconfig \
  -D SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.mock" build
```

Flash with `idf.py -B build-node -p /dev/cu.usbmodemXXXX flash monitor`. If
several boards are attached, tell them apart with
`esptool.py --chip esp32c6 --port /dev/cu.usbmodemXXXX chip_id`.

## Settings (`menuconfig → Temp logger`)

| Setting | Default |
|---|---|
| Role | node |
| Seconds between readings | 60 |
| DS18B20 data GPIO | 0 (XIAO D0) |
| Safe band | −2.00 to 28.00 °C, inclusive |
| Longest wait between unanswered sends | 60 s |
| Simulated probe | off |

## What the node's LED means

| Pattern | Meaning |
|---|---|
| a blip every 5 s | all well |
| slow blink | a reading has left the band since boot (latched, like a tripped dye strip) |
| fast blink | the latest reading is out of band |
| double blink | the probe is not answering |

The gateway flashes once per batch it passes on.

## What a node logs

```text
I (…) tlog_store: log 5e1c09a2 boot 7: 1440 records, seqs 1..1440, acked through 1380, 60 pending
I (…) temp_logger: heat policy: -2.00..28.00 C in the cell engine (7-byte lock script)
I (…) temp_logger: node up. mac=58:e6:c5:1a:8b:28 log=5e1c09a2 boot=7 every 60s
I (…) temp_logger: SAMPLE seq=1441 c=31.25 flags=0x01 pending=61  *** OUT OF BAND ***
I (…) temp_logger: TX batch seqs 1381..1441 (61) lost_through=0 unicast rc=0
I (…) temp_logger: RX ack through 1441 (was 1380), 0 pending
```

## Not yet

- Readings are not signed on the device: devices verify and wallets sign. The
  service behind the bridge signs what it keeps.
- The heat band is compiled in. Pushing it as a signed rule cell, so a policy
  can change without reflashing, is the next step.
- A fleet certificate (`tools/fleet`) is not yet installed or reported by the
  node.
