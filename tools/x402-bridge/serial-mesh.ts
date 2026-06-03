/**
 * serial-mesh.ts — a real MeshPort over USB-Serial-JTAG to the XIAOs.
 *
 * Pairs with the firmware serial cell-injection task (main.c
 * serial_inject_task): the bridge frames a wallet-signed cell as a CRC'd
 * hex line and writes it to an injector C6's serial port; that C6
 * broadcasts it on the mesh; the rentable C6 verifies + actuates and logs
 * "*** ACTUATOR ACTIVATED ***", which the bridge reads off the actuator's
 * serial port.
 *
 * Frame: "IJ" <hex(cell||sig)> <hex(crc32le)> "\n". The CRC32 over
 * (cell||sig) makes the inject path integrity-checked: a dropped/garbled
 * byte (the console shares the USB-Serial-JTAG endpoint) fails the CRC and
 * the device rejects the frame rather than broadcasting a corrupt cell.
 * The line is sent in paced chunks so a burst can't outrun the RX ring.
 *
 * Inject via a device that does NOT itself broadcast deck activations
 * (e.g. device B): the actuator logs `from=[B-MAC]`, unambiguously the
 * bridge's injection rather than the deck's own device-A activations.
 *
 * No serialport dependency — configures the tty with `stty` and uses
 * fs write + a `cat` subprocess for read. macOS/Linux.
 */

import { spawn, spawnSync, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { openSync, writeSync, closeSync } from 'node:fs';
import type { MeshPort } from './bridge.js';

export interface SerialMeshConfig {
  /** Port of the C6 the bridge writes inject frames to (a non-actuator, e.g. device B). */
  injectPort: string;
  /** Port of the rentable C6 that actuates + logs the ack (device C). */
  ackPort: string;
  baud?: number;
  /** Log substring that signals activation. */
  ackMatch?: string;
}

// Standard CRC-32 (zlib/PNG), matching the firmware's inject_crc32.
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();
export function crc32(bytes: Uint8Array): number {
  let c = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/** Frame a cell+sig as the firmware's CRC'd hex line: "IJ"<hex(cell||sig)><hex(crc32le)>"\n". */
export function frameCell(cell: Uint8Array, sig: Uint8Array): Uint8Array {
  const body = new Uint8Array(cell.length + sig.length);
  body.set(cell, 0);
  body.set(sig, cell.length);
  const crc = crc32(body);
  const crcLE = Uint8Array.from([crc & 0xff, (crc >>> 8) & 0xff, (crc >>> 16) & 0xff, (crc >>> 24) & 0xff]);
  const hex = Buffer.concat([Buffer.from(body), Buffer.from(crcLE)]).toString('hex');
  return new TextEncoder().encode('IJ' + hex + '\n');
}

export class SerialMeshPort implements MeshPort {
  private lastAckAt = 0;
  private broadcastAt = 0;
  private reader?: ChildProcessWithoutNullStreams;
  private buf = '';
  private readonly match: string;

  constructor(private readonly cfg: SerialMeshConfig) {
    const baud = String(cfg.baud ?? 115200);
    this.match = cfg.ackMatch ?? '*** ACTUATOR ACTIVATED ***';
    for (const p of [cfg.injectPort, cfg.ackPort]) {
      spawnSync('stty', ['-f', p, baud, 'raw', '-echo'], { stdio: 'ignore' });
    }
    this.startAckReader();
  }

  private startAckReader(): void {
    this.reader = spawn('cat', [this.cfg.ackPort]) as ChildProcessWithoutNullStreams;
    this.reader.stdout.on('data', (d: Buffer) => {
      this.buf += d.toString('utf8');
      let i: number;
      while ((i = this.buf.indexOf('\n')) >= 0) {
        const line = this.buf.slice(0, i);
        this.buf = this.buf.slice(i + 1);
        if (line.includes(this.match)) {
          this.lastAckAt = Date.now();
          console.log(`[mesh:serial] device ack ← ${line.replace(/\x1b\[[0-9;]*m/g, '').trim()}`);
        }
      }
    });
  }

  async broadcast(cell: Uint8Array, sig: Uint8Array): Promise<void> {
    // Mark the broadcast start: the device may ack *during* the retry
    // sends (before awaitActivation runs), so the ack window opens here.
    this.broadcastAt = Date.now();
    const frame = Buffer.from(frameCell(cell, sig));
    // ESP-NOW broadcast is best-effort (no retransmit); the mesh may be
    // busy. Send the identical frame a few times — the device dedups on
    // cell content, so at most one actuation results.
    for (let attempt = 0; attempt < 3; attempt++) {
      const fd = openSync(this.cfg.injectPort, 'w');
      try {
        // Pace the send so a burst can't outrun the device RX ring (the
        // console shares the USB-Serial-JTAG endpoint; the ring is small).
        const CHUNK = 256;
        for (let off = 0; off < frame.length; off += CHUNK) {
          writeSync(fd, frame, off, Math.min(CHUNK, frame.length - off));
          await new Promise((r) => setTimeout(r, 2));
        }
      } finally {
        closeSync(fd);
      }
      await new Promise((r) => setTimeout(r, 400));
    }
  }

  async awaitActivation(_offerId: Uint8Array, timeoutMs: number): Promise<boolean> {
    const start = Date.now();
    // Count any activation logged since the broadcast began (the device may
    // ack mid-broadcast, before this method runs).
    const since = this.broadcastAt || start;
    while (Date.now() - start < timeoutMs) {
      if (this.lastAckAt >= since) return true;
      await new Promise((r) => setTimeout(r, 100));
    }
    return false;
  }

  dispose(): void {
    this.reader?.kill();
  }
}
