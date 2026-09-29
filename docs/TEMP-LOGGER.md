# Temperature logger

`examples/temp_logger` turns XIAO ESP32-C6 boards into store-and-forward
temperature loggers. A **node** rides in a box with a DS18B20 probe, keeps
every reading in flash, and sends them over ESP-NOW whenever a **gateway** is in
range. The gateway is a board on a laptop's USB. It hands readings to
`tools/templog-bridge`, and the bridge acknowledges them once they are stored.

The pure logic — decoding the probe, the flash log, the payload codecs, the send
schedule and the heat policy — lives in `components/cell-mesh-zig/src/cell_templog.zig`
behind the `cm_*` C ABI in `components/cell-mesh/include/cell_templog.h`. The
example is ESP-IDF glue around it.

```text
DS18B20 ──► node: decode → policy (cell engine) → flash log ──► ESP-NOW batch
                                                                    │
bridge ◄── serial "TL …" ◄── gateway ◄──────────────────────────────┘
  │  store (JSONL), then
  └──► serial "AK <mac> <seq>" ──► gateway ──► ESP-NOW ack ──► node advances
```

## What a node guarantees

- **A reading is never dropped for being unsent.** It stays in flash until the
  host acknowledges it or the ring wraps over it. A wrap over undelivered
  readings is reported to the host as `lost_through`, never hidden.
- **Sequence numbers never go backwards.** They come from flash, with a floor in
  NVS so that wiping the data partition cannot restart them. `log_id` is a
  random number drawn when NVS is first initialised, so a full chip erase starts
  a new log rather than colliding with the old one.
- **A heat verdict fails closed.** The policy runs in the cell engine as a
  script that accepts only a reading inside the safe band. If the engine cannot
  evaluate it, the sample is flagged as a reject.

It does **not** sign readings. The kit's rule is that devices verify and
wallets sign, so the bridge (or the service behind it) signs what it stores.
An unsigned batch proves only that something on the radio sent it.

## Identifiers

| Cell | `type_hash` | Domain flag |
|---|---|---|
| batch, node → gateway | SHA-256 of `templog.batch.v0` | `CM_DOMAIN_MESH_TELEMETRY` |
| ack, gateway → node | SHA-256 of `templog.ack.v0` | `CM_DOMAIN_MESH_TELEMETRY` |

Both are unsigned (all-zero signature), `CM_LINEARITY_AFFINE`, with the sender's
MAC in the first 6 bytes of `owner_id`, and `domain_payload_root` set to the
SHA-256 of the 768-byte payload, as `mesh_demo` does for telemetry.

## Batch payload (`templog.batch.v0`)

Little-endian. A batch never spans a boot, so one header's clock covers every
sample in it.

| Offset | Type | Field |
|---:|---|---|
| 0 | u8 | `version` = 0 |
| 1 | u8 | `flags` — reserved, 0 |
| 2 | u16 | `count` — samples that follow, at most 91 |
| 4 | u32 | `first_seq` — seq of sample 0; sample *i* is `first_seq + i` |
| 8 | u32 | `boot_id` — the boot the samples were taken in |
| 12 | u32 | `boot_now` — the node's current boot |
| 16 | u32 | `uptime_now_s` — node uptime when the batch was built |
| 20 | u32 | `boot_epoch_s` — Unix time of `boot_id`'s start if the node learned it, else 0 |
| 24 | u32 | `lost_through` — seqs up to here were overwritten before delivery; 0 = none |
| 28 | u32 | `sample_interval_s` |
| 32 | i16 | `policy_min_centi` — safe band, inclusive, centi-°C |
| 34 | i16 | `policy_max_centi` |
| 36 | u32 | `log_id` |
| 40 | 8 × `count` | samples |

Each sample:

| Offset | Type | Field |
|---:|---|---|
| 0 | u32 | `uptime_s` — node uptime when read, in `boot_id` |
| 4 | i16 | `centi_c` — centi-°C; −32768 when there is no valid reading |
| 6 | u8 | `flags` |
| 7 | u8 | reserved, 0 |

Sample flags:

| Bit | Name | Meaning |
|---:|---|---|
| 0 | `POLICY_REJECT` | outside the safe band, or the engine could not say |
| 1 | `VM_ERROR` | the engine failed to evaluate, or disagreed with the node's native check of the same band (always with `POLICY_REJECT`) |
| 2 | `SENSOR_ERROR` | no valid reading; `centi_c` is −32768 |
| 3 | `POR_SUSPECT` | the probe returned its 85.00 °C power-on value on every retry; recorded as no reading, with `SENSOR_ERROR` |
| 4 | `RECORD_LOST` | the flash record for this seq was unreadable |

### Placing samples in time

The node has no battery-backed clock, so each sample carries uptime within a
boot. The bridge anchors it:

- `boot_id == boot_now`: the boot started at `receipt_time − uptime_now_s`.
  This is accurate to the radio and serial latency, well under a second.
- an earlier boot with `boot_epoch_s ≠ 0`: the node learned that boot's start
  from an ack's `host_unix_s` before it rebooted.
- otherwise the samples are real but unplaced. The bridge keeps them and
  flags them; it must not guess a time.

## Ack payload (`templog.ack.v0`)

| Offset | Type | Field |
|---:|---|---|
| 0 | u8 | `version` = 0 |
| 1 | u8 | reserved |
| 2 | u8[6] | `target_mac` — the node this ack is for |
| 8 | u32 | `acked_through` — the host holds every seq up to here |
| 12 | u32 | `host_unix_s` — the host's clock, or 0 |

`acked_through` *sets* the node's pointer; it is not a maximum. A lower value is
how the host asks for a replay after losing data, and a stale ack only causes
duplicates, which the host drops by `(mac, log_id, seq)`. The node clamps it to
the newest record it has. Acks are unsigned: a forged one can suppress resends,
but it cannot delete a reading, and the host can always ask again.

## Flash log

A raw data partition (`templog`, 256 KB) holds a ring of 16-byte records, 256
per 4 KB sector:

| Offset | Type | Field |
|---:|---|---|
| 0 | u32 | `seq` — never 0 or 0xFFFFFFFF |
| 4 | u32 | `boot_id` |
| 8 | u32 | `uptime_s` |
| 12 | i16 | `centi_c` |
| 14 | u8 | `flags` |
| 15 | u8 | CRC-8/MAXIM over bytes 0–14 |

Seq *s* lives in slot `(s − 1) mod capacity`. Writing to the first slot of a
sector erases that sector first, which drops the oldest 256 records. That is
the only way a record leaves the ring.

On boot the node reads every slot. A record counts only if its CRC holds **and**
its seq maps to the slot it was found in, so a half-written record that happens
to pass its CRC is still rejected. The next seq is one past the newest record,
but never below the floor saved in NVS. If that slot is not erased — power
failed mid-write — the seq is burned rather than rewritten: NOR flash cannot be
reprogrammed without erasing the sector. A burned seq travels to the host as a
`RECORD_LOST` placeholder.

At one sample a minute, the 16,384-record ring holds about 11 days.

## Heat policy

The safe band is a pair of script numbers, and the check runs in the cell
engine:

```text
unlock: <reading>
lock:   <min> <max+1> OP_WITHIN
```

`OP_WITHIN` accepts `min ≤ x < max+1`, so the band is inclusive at both ends.
Temperatures are pushed as minimally encoded script numbers in centi-°C: 28.00
°C is `02 f0 0a`. Accept means in spec. Anything else — out of band or an engine
failure — flags the sample `POLICY_REJECT`, and the board's LED shows it.

The band is the policy's parameters, not the product's opinion: the default is
−2.00 to 28.00 °C, set in `menuconfig`.

The node also compares the reading with the band natively. If the engine and
the native check disagree, the sample is flagged `VM_ERROR` as well as
`POLICY_REJECT`. `tools/templog-policy/engine.test.ts` runs these exact script
bytes through the same `cell-engine-embedded.wasm` on the host, across both
edges of the band and negative temperatures, so a disagreement on a board
points at the board.

## Serial lines (gateway)

Gateway to host, one per received batch:

```text
TL <mac aa:bb:cc:dd:ee:ff> <2048 hex chars: the cell> <8 hex chars: CRC-32 of the cell bytes>
```

Host to gateway:

```text
AK <mac aabbccddeeff> <acked_through decimal> <host_unix_s decimal>
```

Other lines are ESP-IDF logs, and the bridge ignores them.

## Running it

Build, flash and wiring are in `examples/temp_logger/README.md`. The bridge is
`tools/templog-bridge`.

## Honest caveats

- Readings are unsigned on the device. See above.
- The DS18B20 is bit-banged. Radio interrupts can corrupt a read; the CRC
  catches that, and the node retries before it records a sensor error.
- The probe measures what it touches. Taped to a bottle's shoulder it reads the
  glass, which lags the air by tens of minutes.
- This is a research-preview kit. Nothing here is certified for cold-chain
  compliance.
