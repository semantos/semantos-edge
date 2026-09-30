#!/usr/bin/env bun
/**
 * bridge.ts — the temperature logger's host bridge (docs/TEMP-LOGGER.md).
 *
 *   bun tools/templog-bridge/bridge.ts --port /dev/cu.usbmodemXXXX [--out templog-readings.jsonl] [--post http://… [--token-file f]]
 *   bun tools/templog-bridge/bridge.ts --sim [--out file.jsonl] [--post http://… [--token-file f]]
 *   bun tools/templog-bridge/bridge.ts --replay --out templog-readings.jsonl --post http://… [--token-file f]
 *
 * The gateway prints one TL line per batch a node sends. For each, the bridge
 * checks the line's CRC and the cell, stores the new samples (store.ts:
 * dedupe, delivery pointer, time anchoring, JSONL), and writes
 * `AK <mac> <through> <now>` back to the port; the gateway radios that to the
 * node, which may then let those readings go. With --post the batch's new
 * samples are also POSTed as JSON — after the ack, never holding it up.
 *
 * This file is the I/O: stty + `cat` on the port as tools/mesh-observer does,
 * fs writes for AK lines. What one line does is TempLogBridge.handleLine,
 * which the tests drive directly and --sim drives from sim.ts.
 *
 * --replay sends what the JSONL already holds to the server again (replay.ts):
 * the way back after the server was down, since a failed POST never held up
 * the ack and the node has since let those readings go.
 *
 * --token-file names a file holding the server's operator token, sent with
 * each POST as `Authorization: Bearer <token>`. It is read from a file, never
 * taken on the command line, where any process on the machine could read it;
 * and it goes only over https, or plain http to this machine.
 */

import { closeSync, existsSync, mkdtempSync, openSync, readFileSync, writeSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { PAYLOAD_SIZE } from '../x402-bridge/cell-codec.js';
import { SF, classifyLine, decodeBatch, formatAkLine, parseCell, type DecodedBatch } from './codec.js';
import { TempLogStore, logIdHex, type Anchor, type IngestResult } from './store.js';
import { SimWorld, runScenario, type LineHandler } from './sim.js';
import { replayFile } from './replay.js';

const BAUD = 115200;
const SIM_MAC = '02:00:5e:c0:1d:01';
/** The longest partial line kept while waiting for its newline; a TL line is 2,080 chars. */
const MAX_LINE = 16 * 1024;

// ── --post ───────────────────────────────────────────────────────────

export interface PostSample {
  seq: number;
  bootId: number;
  uptimeS: number;
  /** as sent: -32768 means no reading */
  centiC: number;
  flags: number;
  /** null when anchor is 'unplaced' */
  tUnix: number | null;
  anchor: Anchor;
}

/** One POST per batch that stored something new. */
export interface PostBody {
  mac: string;
  /** 8 lowercase hex digits */
  logId: string;
  /** the batch header's lost_through; 0 when nothing was lost */
  lostThrough: number;
  samples: PostSample[];
}

export type Poster = (body: PostBody) => Promise<void>;

/** POST JSON to `url`; a network error or a non-2xx answer rejects. */
export interface PosterOptions {
  /** Sent as `Authorization: Bearer <token>`: the server's operator token. */
  token?: string;
  timeoutMs?: number;
}

/** POST JSON to `url`; a network error or a non-2xx answer rejects. */
export function httpPoster(url: string, { token, timeoutMs = 10_000 }: PosterOptions = {}): Poster {
  return async (body) => {
    const headers: Record<string, string> = { 'content-type': 'application/json' };
    if (token !== undefined) headers.authorization = `Bearer ${token}`;
    const res = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (res.status === 401) {
      throw new Error(token === undefined
        ? 'HTTP 401: the server wants its operator token; pass --token-file'
        : 'HTTP 401: the server refused the token from --token-file');
    }
    if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText}`.trim());
  };
}

/** A bearer token crosses a network only inside TLS: plain http is for this machine. */
export function tokenMayGoTo(url: URL): boolean {
  if (url.protocol === 'https:') return true;
  return url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
}

/** The one word a token file holds, or why it is not a token. */
function readTokenFile(path: string): string {
  const token = readFileSync(path, 'utf8').trim();
  if (token === '') throw new Error(`${path} is empty`);
  if (/\s/.test(token)) throw new Error(`${path} holds more than one word`);
  return token;
}

function postBody(batch: DecodedBatch, r: IngestResult): PostBody {
  return {
    mac: r.mac,
    logId: logIdHex(r.logId),
    lostThrough: batch.header.lostThrough,
    samples: r.newSamples.map((s) => ({
      seq: s.seq,
      bootId: s.bootId,
      uptimeS: s.uptimeS,
      centiC: s.centiC,
      flags: s.flags,
      tUnix: s.tUnix,
      anchor: s.anchor,
    })),
  };
}

// ── One line ─────────────────────────────────────────────────────────

export interface BridgeOptions {
  store: TempLogStore;
  /** Unix seconds: the only clock the bridge reads */
  now: () => number;
  log?: (message: string) => void;
  post?: Poster;
}

const errText = (e: unknown) => (e instanceof Error ? e.message : String(e));

function describeBatch(batch: DecodedBatch, r: IngestResult): string {
  const s = batch.samples;
  const lost = !r.loss
    ? 'none'
    : r.loss.fromSeq === null
      ? `..${r.loss.throughSeq} (before this bridge first saw the log)`
      : `${r.loss.fromSeq}..${r.loss.throughSeq} (${r.loss.missing} missing)`;
  const parts = [
    `${r.mac} log ${logIdHex(r.logId)}`,
    `seqs ${s.length ? `${s[0].seq}..${s[s.length - 1].seq}` : 'none'} (${r.newSamples.length} new, ${r.duplicates} dup)`,
    `through ${r.through}`,
    `lost ${lost}`,
    `unplaced ${r.newSamples.filter((x) => x.anchor === 'unplaced').length}`,
  ];
  const outOfBand = r.newSamples.filter((x) => x.flags & SF.POLICY_REJECT).length;
  if (outOfBand) parts.push(`${outOfBand} out of band`);
  if (r.heldAbove !== null) parts.push(`gap: holding up to ${r.heldAbove}, asking for a replay from ${r.through + 1}`);
  if (r.firstContact) parts.push('new log');
  return `${parts.join(' · ')} → AK ${r.ack.ackedThrough}`;
}

export class TempLogBridge implements LineHandler {
  private readonly inflight = new Set<Promise<void>>();
  private readonly log: (message: string) => void;

  constructor(private readonly opts: BridgeOptions) {
    this.log = opts.log ?? ((m) => console.log(`[templog] ${m}`));
  }

  /**
   * One serial line in; the AK line to write back, or null. Anything that is
   * not a TL line is ignored quietly; a TL line that fails a check is logged
   * and not acked, so the node keeps the readings and sends them again.
   */
  handleLine(line: string): string | null {
    const c = classifyLine(line);
    if (c.kind === 'other') return null;
    if (c.kind === 'bad') {
      this.log(`rejected a TL line: ${c.reason}`);
      return null;
    }
    const cell = parseCell(c.cell);
    if (!cell) {
      this.log(`${c.mac}: the TL line does not hold a cell; ignoring it`);
      return null;
    }
    if (cell.kind !== 'batch') {
      this.log(`${c.mac}: ignoring a ${cell.kind === 'ack' ? 'templog ack' : 'non-templog'} cell`);
      return null;
    }
    if (cell.ownerMac !== c.mac) {
      this.log(`${c.mac}: the batch's owner_id says ${cell.ownerMac}; not storing or acking it`);
      return null;
    }
    if (!cell.payloadRootOk) {
      this.log(`${c.mac}: the payload does not match domain_payload_root; not storing or acking it`);
      return null;
    }
    const batch = decodeBatch(cell.payload.subarray(0, Math.min(cell.payloadTotal, PAYLOAD_SIZE)));
    if (!batch) {
      this.log(`${c.mac}: the batch does not decode (version, count or payload_total ${cell.payloadTotal}); not acking it`);
      return null;
    }
    let r: IngestResult;
    try {
      r = this.opts.store.ingest(c.mac, batch, this.opts.now());
    } catch (e) {
      this.log(`${c.mac}: could not store the batch (${errText(e)}); not acking it`);
      return null;
    }
    this.log(describeBatch(batch, r));
    if (this.opts.post && r.newSamples.length > 0) this.postLater(postBody(batch, r));
    return formatAkLine(r.ack.mac, r.ack.ackedThrough, r.ack.hostUnixS);
  }

  /** Wait for the POSTs in flight: for tests, and before a clean exit. */
  async settle(): Promise<void> {
    while (this.inflight.size > 0) await Promise.allSettled([...this.inflight]);
  }

  // Starts on the microtask queue, so the caller has written the AK line before
  // the POST begins, and a POST that fails cannot take the ack with it.
  private postLater(body: PostBody): void {
    const post = this.opts.post!;
    const p: Promise<void> = Promise.resolve()
      .then(() => post(body))
      .then(
        () => undefined,
        (e) =>
          this.log(
            `${body.mac} log ${body.logId}: POST of ${body.samples.length} sample(s) failed (${errText(e)}); they are in the JSONL`,
          ),
      )
      .finally(() => this.inflight.delete(p));
    this.inflight.add(p);
  }
}

// ── The serial loop, minus the OS ────────────────────────────────────

/** Bytes to lines: UTF-8 decoded across chunk boundaries, CR stripped, a final unterminated line kept. */
export async function* splitLines(chunks: AsyncIterable<Uint8Array>): AsyncGenerator<string> {
  const dec = new TextDecoder();
  let buf = '';
  for await (const chunk of chunks) {
    buf += dec.decode(chunk, { stream: true });
    let nl: number;
    while ((nl = buf.indexOf('\n')) >= 0) {
      yield buf.slice(0, nl).replace(/\r$/, '');
      buf = buf.slice(nl + 1);
    }
    if (buf.length > MAX_LINE) buf = ''; // no newline in sight: not a line we could use
  }
  buf += dec.decode();
  if (buf.length > 0) yield buf.replace(/\r$/, '');
}

/** Feed lines to the bridge and write each AK line back. Returns how many acks went out. */
export async function pump(lines: AsyncIterable<string>, bridge: LineHandler, write: (ak: string) => void): Promise<number> {
  let acks = 0;
  for await (const line of lines) {
    const ak = bridge.handleLine(line);
    if (ak !== null) {
      write(ak);
      acks++;
    }
  }
  return acks;
}

// ── The OS ───────────────────────────────────────────────────────────

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function writeAll(fd: number, text: string): void {
  const buf = Buffer.from(text, 'utf8');
  let off = 0;
  while (off < buf.length) off += writeSync(fd, buf, off, buf.length - off);
}

/** Raw, no echo, 115200 — `stty -f` on macOS, `-F` on Linux. The C6's USB-CDC ignores the baud; raw is what matters. */
function configurePort(port: string, log: (m: string) => void): void {
  for (const flag of ['-f', '-F']) {
    const r = Bun.spawnSync(['stty', flag, port, String(BAUD), 'raw', '-echo'], { stdout: 'ignore', stderr: 'ignore' });
    if (r.exitCode === 0) return;
  }
  log(`warning: stty could not set ${port} to raw ${BAUD}; lines may be echoed or mangled`);
}

async function serveOnce(port: string, bridge: TempLogBridge, log: (m: string) => void): Promise<void> {
  configurePort(port, log);
  const cat = Bun.spawn(['cat', port], { stdout: 'pipe', stderr: 'inherit' });
  let fd: number | null = null;
  try {
    fd = openSync(port, 'w');
    log(`listening on ${port}`);
    const out = fd;
    await pump(splitLines(cat.stdout), bridge, (ak) => writeAll(out, ak));
  } catch (e) {
    log(`${port}: ${errText(e)}`);
  } finally {
    cat.kill();
    if (fd !== null) {
      try {
        closeSync(fd);
      } catch {
        // already gone with the device
      }
    }
  }
}

async function runSerial(port: string, outPath: string, post: Poster | undefined, postUrl: string | undefined): Promise<number> {
  const log = (m: string) => console.log(`${new Date().toISOString()} [templog] ${m}`);
  const store = TempLogStore.open(outPath);
  if (store.skippedLines > 0) log(`warning: skipped ${store.skippedLines} unreadable line(s) in ${outPath}`);
  for (const s of store.summary()) {
    const gap = s.heldAbove !== null ? `, holding up to ${s.heldAbove} above a gap` : '';
    log(`resuming ${s.mac} log ${logIdHex(s.logId)} through ${s.through}${gap}`);
  }
  log(`readings go to ${outPath}${postUrl ? `; new samples are POSTed to ${postUrl}` : ''}`);
  const bridge = new TempLogBridge({ store, now: () => Math.floor(Date.now() / 1000), log, post });
  // The gateway resets and re-enumerates; wait for the port and pick it up again.
  for (;;) {
    if (!existsSync(port)) {
      log(`waiting for ${port}`);
      while (!existsSync(port)) await sleep(1000);
    }
    await serveOnce(port, bridge, log);
    log(`${port} closed; reopening in 2 s`);
    await sleep(2000);
  }
}

async function runSim(outPath: string | undefined, post: Poster | undefined): Promise<number> {
  const log = (m: string) => console.log(`[templog] ${m}`);
  const path = outPath ?? join(mkdtempSync(join(tmpdir(), 'templog-sim-')), 'readings.jsonl');
  const store = TempLogStore.open(path);
  // A fresh log_id per run, as a newly erased chip would draw.
  const logId = crypto.getRandomValues(new Uint32Array(1))[0];
  const world = new SimWorld({ startUnixS: Math.floor(Date.now() / 1000), mac: SIM_MAC, logId });
  const bridge = new TempLogBridge({ store, now: () => world.nowUnixS, log, post });
  log(`sim: node ${SIM_MAC} log ${logIdHex(logId)}, a reading every ${world.node.intervalS} s, a ${world.node.capacity}-record ring`);
  const report = runScenario(world, bridge, (m) => console.log(`[sim] ${m}`));
  await bridge.settle();
  const through = store.through(SIM_MAC, logId);
  store.close();
  log(
    `sim done: ${report.sends} batches sent, ${report.acksLost} ack lost; the bridge holds through ${through} ` +
      `and the node's newest is ${report.lastSeq}. Readings: ${path}`,
  );
  return through === report.lastSeq ? 0 : 1;
}

const USAGE = `usage:
  bun tools/templog-bridge/bridge.ts --port /dev/cu.usbmodemXXXX [--out templog-readings.jsonl] [--post http://… [--token-file f]]
  bun tools/templog-bridge/bridge.ts --sim [--out file.jsonl] [--post http://… [--token-file f]]
  bun tools/templog-bridge/bridge.ts --replay --out templog-readings.jsonl --post http://… [--token-file f]`;

async function runReplay(path: string, post: Poster, postUrl: string): Promise<number> {
  const log = (m: string) => console.log(`[templog] ${m}`);
  if (!existsSync(path)) {
    log(`${path}: no such file`);
    return 1;
  }
  const r = await replayFile(path, post, (m) => log(`replay failed: ${m}`));
  log(`replayed ${r.samples} sample(s) from ${path} to ${postUrl} in ${r.bodies} POST(s): ${r.posted} ok, ${r.failed} failed` +
    (r.skipped ? `, ${r.skipped} unreadable line(s) skipped` : ''));
  return r.failed === 0 ? 0 : 1;
}

export async function main(argv: string[]): Promise<number> {
  let values: { port?: string; out?: string; post?: string; 'token-file'?: string; sim?: boolean; replay?: boolean; help?: boolean };
  try {
    ({ values } = parseArgs({
      args: argv,
      options: {
        port: { type: 'string' },
        out: { type: 'string' },
        post: { type: 'string' },
        'token-file': { type: 'string' },
        sim: { type: 'boolean' },
        replay: { type: 'boolean' },
        help: { type: 'boolean', short: 'h' },
      },
      strict: true,
      allowPositionals: false,
    }));
  } catch (e) {
    console.error(`${errText(e)}\n${USAGE}`);
    return 2;
  }
  if (values.help) {
    console.log(USAGE);
    return 0;
  }
  if ([values.sim, values.port !== undefined, values.replay].filter(Boolean).length > 1) {
    console.error(`--port, --sim and --replay do not mix\n${USAGE}`);
    return 2;
  }
  if (values.replay && (values.post === undefined || values.out === undefined)) {
    console.error(`--replay needs --out (the readings file) and --post (where to send it)\n${USAGE}`);
    return 2;
  }
  if (!values.sim && !values.port && !values.replay) {
    console.error(`--port is required (or --sim to run without hardware)\n${USAGE}`);
    return 2;
  }
  if (values['token-file'] !== undefined && values.post === undefined) {
    console.error(`--token-file goes with --post: it is the token the server there wants\n${USAGE}`);
    return 2;
  }
  let post: Poster | undefined;
  let postUrl: string | undefined;
  if (values.post !== undefined) {
    let url: URL;
    try {
      url = new URL(values.post);
    } catch {
      url = new URL('invalid:');
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      console.error(`--post needs an http(s) URL, got ${JSON.stringify(values.post)}`);
      return 2;
    }
    postUrl = url.href;
    let token: string | undefined;
    if (values['token-file'] !== undefined) {
      if (!tokenMayGoTo(url)) {
        console.error(`--token-file: a token goes over https, or plain http to this machine; not to ${url.host} in the clear`);
        return 2;
      }
      try {
        token = readTokenFile(values['token-file']);
      } catch (e) {
        console.error(`--token-file: ${errText(e)}`);
        return 2;
      }
    }
    post = httpPoster(postUrl, { token });
  }
  if (values.replay) return runReplay(values.out!, post!, postUrl!);
  if (values.sim) return runSim(values.out, post);
  return runSerial(values.port!, values.out ?? 'templog-readings.jsonl', post, postUrl);
}

if (import.meta.main) process.exit(await main(process.argv.slice(2)));
