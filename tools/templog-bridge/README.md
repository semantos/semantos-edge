# templog-bridge

Host side of the store-and-forward temperature logger
([docs/TEMP-LOGGER.md](../../docs/TEMP-LOGGER.md)). A gateway board on USB
prints one `TL` line for each batch of readings a node sends it. The bridge
checks the line, stores the new readings in a JSONL file, and writes an `AK`
line back. The gateway radios that ack to the node, and the node can then let
those readings go.

```text
node ──ESP-NOW──► gateway ──"TL …"──► bridge: check → store (JSONL, fsync) ──► optional POST
node ◄──ESP-NOW── gateway ◄──"AK …"── bridge
```

An ack goes out only after its readings are on disk. If the bridge cannot
store a batch, it sends no ack, and the node keeps the readings and sends them
again.

## Run

```sh
# with a gateway plugged in (examples/temp_logger built as the gateway role)
bun run templog-bridge --port /dev/cu.usbmodemXXXX
bun tools/templog-bridge/bridge.ts --port /dev/cu.usbmodemXXXX --out readings.jsonl --post http://localhost:8080/readings

# no hardware: a synthetic node through the same code path
bun tools/templog-bridge/bridge.ts --sim

# the server was down: send what the JSONL holds to it again
bun tools/templog-bridge/bridge.ts --replay --out readings.jsonl --post http://localhost:5221/api/logger/samples
```

| Option | |
|---|---|
| `--port <tty>` | the gateway's serial port. The bridge sets it to raw with no echo (`stty -f`, or `-F` on Linux), reads it with `cat` and writes AK lines to it. Raw mode matters: a TL line is 2,078 characters, more than a canonical-mode line holds on macOS. If the port disappears, for example when the gateway resets, the bridge waits and reopens it. |
| `--out <file>` | the JSONL record, default `templog-readings.jsonl` in the current directory. Append-only; a restart carries on from it. |
| `--post <url>` | also POST each batch's new samples as JSON. See below. |
| `--replay` | send every sample the `--out` file holds to `--post` again, grouped by log, oldest first, at most 500 per POST. For after the server was down: the ack never waits for a POST, so the node has let those readings go and the JSONL is the only copy. The server drops what it already holds by (mac, logId, seq), so replaying twice is harmless. Exits non-zero if any POST failed. |
| `--sim` | no hardware. A synthetic node goes through first contact, a lost ack (so a duplicate), another gateway acking some readings (so a gap, then a replay), two reboots (all three time rules) and ten hours out of range (its ring wraps, so a loss). It writes to a fresh temp file unless you pass `--out`, then prints where it wrote. |

One line per batch:

```text
[templog] 58:e6:c5:1a:8b:28 log a1b2c3d4 · seqs 257..347 (91 new, 0 dup) · through 347 · lost 26..256 (231 missing) · unplaced 1 · 10 out of band → AK 347
```

## What it checks

A line becomes a stored batch only when all of these hold:
- It is a `TL` line whose CRC-32 matches the 1,024 cell bytes.
- The cell's magic is right and its type is `templog.batch.v0`.
- `owner_id` names the same MAC the radio heard.
- `domain_payload_root` is the SHA-256 of the payload.
- The batch decodes under the Zig decoder's rules: version 0, at most 91 samples, and `payload_total` long enough for them.

A TL line that fails any of these is logged and gets no ack. Every other line
(the gateway's ESP-IDF logs) is ignored. A whole TL frame that follows a log
fragment on the same line is still taken, because the gateway writes both from
two tasks to one console; the CRC decides.

## What the ack says

For each node log `(mac, log_id)` the bridge keeps `through`: it holds every
seq from where it first saw that log up to `through`. The ack sends `through`
(and the host clock, which is how the node learns when its boot began).

- Duplicates are normal (a lost ack causes them). They are dropped by `(mac, log_id, seq)` and acked again.
- A **gap** (a batch that starts past `through + 1`) is stored, but `through` stays where it is. The lower ack asks the node to replay from `through + 1`, and when the replay arrives `through` jumps past everything already held.
- A batch's `lost_through` above `through` means the node overwrote those readings before any host acked them. `through` moves to it, and a `loss` line records the range. A node that wrapped before this bridge first heard from it gets a `loss` line too, with `fromSeq: null`.

## The JSONL

One JSON object per line, of three kinds. The file is fsynced before the ack
goes out, and a restart rebuilds the dedupe sets and `through` from it. If a
crash leaves a torn last line, it is skipped and left in place.

**`start`** — the first batch this bridge saw from a log: `through` starts at `firstSeq - 1`.

```json
{"kind":"start","mac":"02:00:5e:c0:1d:01","logId":"b6964a08","firstSeq":1,"receivedUnixS":1790692912}
```

**`sample`** — one per newly stored reading.

```json
{"kind":"sample","mac":"02:00:5e:c0:1d:01","logId":"b6964a08","seq":21,"bootId":1,"uptimeS":1260,"centiC":517,"flags":0,"tUnix":1790693872,"anchor":"epoch","policyMinCenti":-200,"policyMaxCenti":2800,"receivedUnixS":1790694152}
```

| Field | |
|---|---|
| `mac`, `logId` | the node (lowercase, with colons) and its log (8 hex digits; a full chip erase starts a new one) |
| `seq`, `bootId`, `uptimeS` | as the node recorded them |
| `centiC` | hundredths of °C as sent. **−32768 means no reading**, so check `flags` before using the value |
| `flags` | bit 0 `POLICY_REJECT` (out of band, or the engine could not say), 1 `VM_ERROR`, 2 `SENSOR_ERROR`, 3 `POR_SUSPECT`, 4 `RECORD_LOST` (placeholder for an unreadable flash record) |
| `tUnix`, `anchor` | when the reading was taken, and which rule says so. `receipt`: the batch came from the node's current boot, which began at receipt time minus `uptime_now_s`. `epoch`: an earlier boot whose start the node learned from an ack. `unplaced`: nothing places it, so `tUnix` is `null`; the bridge does not guess. Lost-record placeholders are always unplaced |
| `policyMinCenti`, `policyMaxCenti` | the band the node judged the reading against, inclusive |
| `receivedUnixS` | the bridge's clock when the batch arrived |

**`loss`** — the node overwrote `fromSeq..throughSeq` before any host acked them. `missing` counts the ones this bridge does not hold. `fromSeq` and `missing` are `null` when the loss began before this bridge first saw the log.

```json
{"kind":"loss","mac":"02:00:5e:c0:1d:01","logId":"b6964a08","fromSeq":26,"throughSeq":256,"missing":231,"receivedUnixS":1790730152}
```

## `--post`

After a batch is stored and its AK line written, the batch's new samples are
POSTed as `application/json`:

```json
{ "mac": "58:e6:c5:1a:8b:28", "logId": "a1b2c3d4", "lostThrough": 0,
  "samples": [ { "seq": 101, "bootId": 3, "uptimeS": 120, "centiC": -200, "flags": 1, "tUnix": 1790000120, "anchor": "receipt" } ] }
```

`lostThrough` is the batch header's `lost_through` (0 when nothing was lost).
Only newly stored samples are sent, so a batch of duplicates sends nothing.
A network error or a non-2xx answer is logged and never holds up the ack.
The JSONL is the durable record. A failed POST is not retried on its own; `--replay` sends the JSONL again once the server is back.

## Honest caveats

- **Readings are unsigned from the device.** Devices verify and wallets sign,
  so a batch proves only that something on the radio sent it. The bridge checks
  integrity (the serial CRC, the payload root, owner against sender), not
  authenticity. A forged batch can put readings in the JSONL, or claim seqs
  were lost, which moves `through` and the ack past them. The service behind
  the bridge must sign what it keeps; the JSONL is a record, not an attestation.
- Times are as good as the host clock plus radio and serial latency, well
  under a second, and uptime counts whole seconds.
- One bridge per JSONL file. Two processes appending to one file would
  interleave their records.
- This is a research-preview kit. Nothing here is certified for cold-chain
  compliance.

## Files and tests

| File | |
|---|---|
| `codec.ts` | batch and ack payloads, cell parsing, TL/AK lines. Pure |
| `store.ts` | the delivery state machine and the JSONL. Pure logic with an injected clock, plus the file journal |
| `bridge.ts` | the CLI: line handling, `--post`, the serial loop, `--sim` |
| `sim.ts` | the synthetic node (a flash ring as `cell_templog.zig` keeps it) and gateway for `--sim` |

```sh
bun test tools/templog-bridge/
```

`codec.test.ts` decodes and re-encodes the hand-written golden bytes from
`components/cell-mesh-zig/src/cell_templog_test.zig`. It also reads that file
and fails if its bytes and these ever differ, so the TS and Zig codecs cannot
drift apart silently.
