#!/usr/bin/env bun
/**
 * BitPiggy bridge: local HTTP/SSE control plane for an iOS-installable
 * Flutter PWA. The phone talks to this server over LAN; this server tails and
 * writes the LilyGO USB-Serial-JTAG port.
 */

import { spawn, spawnSync, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { existsSync, readFileSync, statSync, openSync, writeSync, closeSync } from 'node:fs';
import { extname, join, normalize, relative, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { PrivateKey } from '@bsv/sdk';
import {
  CELL_SIZE,
  mintCell,
  signCell,
  typeHash,
  writeU16LE,
  writeU32LE,
  writeU64LE,
  sha256,
} from '../x402-bridge/cell-codec.js';
import { frameCell } from '../x402-bridge/serial-mesh.js';

const flag = (name: string, fallback?: string) => {
  const eq = process.argv.find((a) => a.startsWith(name + '='));
  if (eq) return eq.slice(name.length + 1);
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : fallback;
};

const httpPort = Number(flag('--http-port', process.env.PORT ?? '4050'));
const serialPort = flag('--port', process.env.BITPIGGY_SERIAL_PORT ?? '/dev/cu.usbmodem1101')!;
const baud = flag('--baud', '115200')!;
const noSerial = process.argv.includes('--no-serial');
const selfTest = process.argv.includes('--self-test');
const childName = flag('--child', process.env.BITPIGGY_CHILD ?? 'Theo')!;
const choreName = flag('--chore', process.env.BITPIGGY_CHORE ?? 'Bins out')!;
const deviceName = flag('--device-name', process.env.BITPIGGY_DEVICE_NAME ?? 'LilyGO-S3')!;
const parentName = flag('--parent', process.env.BITPIGGY_PARENT ?? 'Sam')!;
const payCentsDefault = Number(flag('--pay-cents', process.env.BITPIGGY_PAY_CENTS ?? '100'));
const repoRoot = normalize(join(dirname(fileURLToPath(import.meta.url)), '..', '..'));
const deckPath = flag('--deck', join(repoRoot, 'examples', 'bitpiggy_mesh', 'main', 'embed', 'cell_deck.bin'))!;
const appDir = flag('--app-dir', join(repoRoot, 'apps', 'bitpiggy_control', 'build', 'web'))!;

const WALLET = new PrivateKey('0000000000000000000000000000000000000000000000000000000000000042', 16);
const WALLET_PUB = new Uint8Array(Buffer.from(WALLET.toPublicKey().toString(), 'hex'));
const OWNER = WALLET_PUB.subarray(0, 16);
const APPROVAL_TYPE = typeHash('bitpiggy.approval.v0');
const REJECTION_TYPE = typeHash('bitpiggy.rejection.v0');
const KIND_BITPIGGY_CHORE_CLAIM = 32;
const DECK_MAGIC = 0xdecdcdcd;
const ENTRY_PREFIX = 8;
const SIG_SIZE = 64;
const ENTRY_SIZE = ENTRY_PREFIX + CELL_SIZE + SIG_SIZE;
const OFF_PAYLOAD = 256;

interface DeckClaim {
  index: number;
  claimId: string;
  claimPrefix: string;
  child: string;
  chore: string;
  device: string;
  payCents: number;
  counter: number;
  claimedAtMs: number;
}

interface HistoryItem {
  id: string;
  kind: 'claim' | 'approval' | 'rejection' | 'device' | 'bridge';
  text: string;
  atMs: number;
  claimId?: string;
}

const enc = new TextEncoder();
const clients = new Set<ReadableStreamDefaultController<Uint8Array>>();
const recentLines: string[] = [];
const history: HistoryItem[] = [];
const deckClaims = loadDeckClaims(deckPath);
let pendingClaim: DeckClaim | null = null;
let lastSeenMs = 0;
let decisionCounter = 1;
let serialReader: ChildProcessWithoutNullStreams | null = null;

function readU32LE(b: Uint8Array, off: number): number {
  return (b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24)) >>> 0;
}

function readU64LE(b: Uint8Array, off: number): bigint {
  let v = 0n;
  for (let i = 0; i < 8; i++) v |= BigInt(b[off + i]) << BigInt(i * 8);
  return v;
}

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}

function id16(label: string): Uint8Array {
  return sha256(new TextEncoder().encode(label)).subarray(0, 16);
}

function noteRef(note?: string): Uint8Array {
  if (!note?.trim()) return new Uint8Array(32);
  return new Uint8Array(createHash('sha256').update(note.trim()).digest());
}

function loadDeckClaims(path: string): DeckClaim[] {
  if (!existsSync(path)) return [];
  const raw = new Uint8Array(readFileSync(path));
  if (raw.length < 16 || readU32LE(raw, 0) !== DECK_MAGIC) {
    throw new Error(`bad BitPiggy deck: ${path}`);
  }
  const count = readU32LE(raw, 8);
  const out: DeckClaim[] = [];
  for (let i = 0; i < count; i++) {
    const off = 16 + i * ENTRY_SIZE;
    if (off + ENTRY_SIZE > raw.length) break;
    const kind = raw[off + 6];
    if (kind !== KIND_BITPIGGY_CHORE_CLAIM) continue;
    const cell = raw.subarray(off + ENTRY_PREFIX, off + ENTRY_PREFIX + CELL_SIZE);
    const p = cell.subarray(OFF_PAYLOAD, OFF_PAYLOAD + 128);
    const claimId = hex(p.subarray(0, 16));
    out.push({
      index: out.length + 1,
      claimId,
      claimPrefix: claimId.slice(0, 8),
      child: childName,
      chore: choreName,
      device: deviceName,
      payCents: payCentsDefault,
      counter: readU32LE(p, 120),
      claimedAtMs: Number(readU64LE(p, 80)),
    });
  }
  return out;
}

function pushHistory(item: HistoryItem): void {
  history.unshift(item);
  if (history.length > 80) history.pop();
}

function emit(event: string, data: unknown): void {
  const chunk = enc.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  for (const c of clients) {
    try { c.enqueue(chunk); } catch { clients.delete(c); }
  }
}

function broadcastLine(line: string): void {
  recentLines.push(line);
  if (recentLines.length > 200) recentLines.shift();
  emit('line', { line, atMs: Date.now() });
}

function emitState(): void {
  emit('state', currentState());
}

function setPendingFromClaimNumber(n: number, prefix?: string): void {
  const byNumber = deckClaims[n - 1];
  const byPrefix = prefix
    ? deckClaims.find((c) => c.claimPrefix.toLowerCase() === prefix.toLowerCase())
    : undefined;
  const claim = byPrefix ?? byNumber;
  if (!claim) {
    broadcastLine(`[bridge] saw claim #${n}, but deck has only ${deckClaims.length} claim(s)`);
    return;
  }
  if (byPrefix && byNumber && byPrefix.claimId !== byNumber.claimId) {
    broadcastLine(`[bridge] claim #${n} resolved by prefix ${prefix}; deck slot ${byNumber.index} is ${byNumber.claimPrefix}`);
  } else if (prefix && claim.claimPrefix.toLowerCase() !== prefix.toLowerCase()) {
    broadcastLine(`[bridge] claim #${n} prefix mismatch: log=${prefix} deck=${claim.claimPrefix}`);
  }
  pendingClaim = claim;
  pushHistory({
    id: `claim-${claim.claimId}-${Date.now()}`,
    kind: 'claim',
    text: `${claim.child} claimed ${claim.chore}`,
    atMs: Date.now(),
    claimId: claim.claimId,
  });
  emitState();
}

function parseSerialLine(line: string): void {
  const clean = line.replace(/\x1b\[[0-9;]*m/g, '').trim();
  if (!clean) return;
  lastSeenMs = Date.now();
  broadcastLine(clean);

  const claim = clean.match(/BITPIGGY CHORE CLAIM #(\d+).*claim=([0-9a-fA-F]{8})/);
  if (claim) {
    setPendingFromClaimNumber(Number(claim[1]), claim[2]);
    return;
  }
  const approved = clean.match(/BITPIGGY APPROVED.*claim=([0-9a-fA-F]{8})/);
  if (approved) {
    pushHistory({ id: `approved-${Date.now()}`, kind: 'approval', text: 'Device accepted approval', atMs: Date.now() });
    emitState();
    return;
  }
  const rejected = clean.match(/BITPIGGY NOT YET.*claim=([0-9a-fA-F]{8})/);
  if (rejected) {
    pushHistory({ id: `rejected-${Date.now()}`, kind: 'rejection', text: 'Device accepted not-yet decision', atMs: Date.now() });
    emitState();
  }
}

function startSerial(): void {
  if (noSerial) {
    broadcastLine('[bridge] --no-serial: running without LilyGO serial tail/write');
    return;
  }
  spawnSync('stty', ['-f', serialPort, baud, 'raw', '-echo'], { stdio: 'ignore' });
  serialReader = spawn('cat', [serialPort]) as ChildProcessWithoutNullStreams;
  let buf = '';
  serialReader.stdout.on('data', (d: Buffer) => {
    buf += d.toString('utf8');
    let i: number;
    while ((i = buf.indexOf('\n')) >= 0) {
      parseSerialLine(buf.slice(0, i));
      buf = buf.slice(i + 1);
    }
  });
  serialReader.on('exit', (code) => {
    broadcastLine(`[bridge] serial reader exited (${code ?? 'signal'})`);
  });
}

async function writeFrame(cell: Uint8Array, sig: Uint8Array): Promise<void> {
  const frame = Buffer.from(frameCell(cell, sig));
  if (noSerial) {
    broadcastLine(`[bridge] dry-run inject ${frame.length} bytes`);
    return;
  }
  for (let r = 0; r < 2; r++) {
    const fd = openSync(serialPort, 'w');
    try {
      for (let off = 0; off < frame.length; off += 256) {
        writeSync(fd, frame, off, Math.min(256, frame.length - off));
        await Bun.sleep(2);
      }
    } finally {
      closeSync(fd);
    }
    await Bun.sleep(250);
  }
}

function buildApprovalPayload(claim: DeckClaim, note: string | undefined, payCents: number): Uint8Array {
  const p = new Uint8Array(120);
  p.set(id16(`approval:${claim.claimId}:${decisionCounter}`), 0);
  p.set(Buffer.from(claim.claimId, 'hex'), 16);
  p.set(id16('household:whitfield'), 32);
  p.set(id16(`parent:${parentName}`), 48);
  writeU64LE(p, 64, BigInt(Date.now()));
  writeU32LE(p, 72, payCents);
  writeU64LE(p, 76, 0n);
  p.set(noteRef(note), 84);
  writeU32LE(p, 116, note?.trim() ? 1 : 0);
  return p;
}

function buildRejectionPayload(claim: DeckClaim, note: string | undefined, reasonCode: number): Uint8Array {
  const p = new Uint8Array(106);
  p.set(id16(`rejection:${claim.claimId}:${decisionCounter}`), 0);
  p.set(Buffer.from(claim.claimId, 'hex'), 16);
  p.set(id16('household:whitfield'), 32);
  p.set(id16(`parent:${parentName}`), 48);
  writeU64LE(p, 64, BigInt(Date.now()));
  writeU16LE(p, 72, reasonCode);
  p.set(noteRef(note), 74);
  return p;
}

async function decide(action: 'approve' | 'reject', note?: string, claimId?: string, payCents?: number): Promise<DeckClaim> {
  const claim = pendingClaim ?? deckClaims.find((c) => c.claimId === claimId);
  if (!claim) throw new Error('no pending claim');
  if (claimId && claim.claimId !== claimId) throw new Error('claimId does not match pending claim');

  const payload = action === 'approve'
    ? buildApprovalPayload(claim, note, payCents ?? claim.payCents)
    : buildRejectionPayload(claim, note, 1);
  const cell = mintCell(action === 'approve' ? APPROVAL_TYPE : REJECTION_TYPE, payload, OWNER, BigInt(Date.now()));
  const sig = signCell(cell, WALLET);
  decisionCounter++;
  await writeFrame(cell, sig);

  pushHistory({
    id: `${action}-${claim.claimId}-${Date.now()}`,
    kind: action === 'approve' ? 'approval' : 'rejection',
    text: action === 'approve'
      ? `${parentName} approved ${claim.chore}`
      : `${parentName} sent ${claim.chore} back`,
    atMs: Date.now(),
    claimId: claim.claimId,
  });
  pendingClaim = null;
  emitState();
  return claim;
}

function currentState() {
  return {
    ok: true,
    bridge: {
      httpPort,
      serialPort,
      noSerial,
      deckPath,
      appMounted: existsSync(appDir),
      walletPubkey: hex(WALLET_PUB),
    },
    device: {
      name: deviceName,
      child: childName,
      online: lastSeenMs > 0 && Date.now() - lastSeenMs < 15000,
      lastSeenMs: lastSeenMs ? Date.now() - lastSeenMs : null,
    },
    pendingClaim,
    deckClaims,
    history,
    recentLines: recentLines.slice(-80),
  };
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'content-type': 'application/json',
      'cache-control': 'no-store',
      'access-control-allow-origin': '*',
      'access-control-allow-methods': 'GET,POST,OPTIONS',
      'access-control-allow-headers': 'content-type',
    },
  });
}

const TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.wasm': 'application/wasm',
};

function staticResponse(url: URL): Response | null {
  if (!url.pathname.startsWith('/app')) return null;
  if (!existsSync(appDir)) return null;
  const rel = url.pathname === '/app' || url.pathname === '/app/'
    ? 'index.html'
    : decodeURIComponent(url.pathname.slice('/app/'.length));
  const resolved = normalize(join(appDir, rel));
  if (relative(appDir, resolved).startsWith('..')) return new Response('bad path', { status: 400 });
  const file = existsSync(resolved) && statSync(resolved).isFile() ? resolved : join(appDir, 'index.html');
  return new Response(readFileSync(file), {
    headers: { 'content-type': TYPES[extname(file)] ?? 'application/octet-stream' },
  });
}

if (selfTest) {
  const claim = deckClaims[0];
  if (!claim) throw new Error(`no BitPiggy claims in ${deckPath}`);
  const approval = buildApprovalPayload(claim, 'self-test', claim.payCents);
  const cell = mintCell(APPROVAL_TYPE, approval, OWNER, BigInt(Date.now()));
  const sig = signCell(cell, WALLET);
  console.log(JSON.stringify({
    ok: true,
    deckClaims: deckClaims.length,
    firstClaim: claim.claimId,
    approvalBytes: approval.length,
    cellBytes: cell.length,
    sigBytes: sig.length,
  }, null, 2));
  process.exit(0);
}

startSerial();

const server = Bun.serve({
  port: httpPort,
  idleTimeout: 60,
  async fetch(req) {
    const url = new URL(req.url);
    if (req.method === 'OPTIONS') return json({ ok: true });
    const staticFile = staticResponse(url);
    if (staticFile) return staticFile;

    if (req.method === 'GET' && url.pathname === '/') {
      if (existsSync(appDir)) return Response.redirect('/app/', 302);
      return json({ ok: true, app: 'build Flutter web, then open /app/', state: currentState() });
    }
    if (req.method === 'GET' && (url.pathname === '/api/config' || url.pathname === '/api/state')) {
      return json(currentState());
    }
    if (req.method === 'GET' && url.pathname === '/api/events') {
      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          clients.add(controller);
          controller.enqueue(enc.encode(`event: state\ndata: ${JSON.stringify(currentState())}\n\n`));
        },
        cancel() {},
      });
      return new Response(stream, {
        headers: {
          'content-type': 'text/event-stream',
          'cache-control': 'no-cache',
          connection: 'keep-alive',
          'access-control-allow-origin': '*',
        },
      });
    }
    if (req.method === 'POST' && url.pathname === '/api/simulate-claim') {
      const next = deckClaims.find((c) => !history.some((h) => h.claimId === c.claimId && (h.kind === 'approval' || h.kind === 'rejection')))
        ?? deckClaims[0];
      if (!next) return json({ ok: false, error: 'deck has no claims' }, 404);
      pendingClaim = next;
      pushHistory({ id: `sim-${Date.now()}`, kind: 'claim', text: `${next.child} claimed ${next.chore}`, atMs: Date.now(), claimId: next.claimId });
      emitState();
      return json(currentState());
    }
    if (req.method === 'POST' && url.pathname === '/api/decision') {
      try {
        const b = (await req.json().catch(() => ({}))) as {
          action?: 'approve' | 'reject';
          claimId?: string;
          note?: string;
          payCents?: number;
        };
        if (b.action !== 'approve' && b.action !== 'reject') {
          return json({ ok: false, error: 'action must be approve or reject' }, 400);
        }
        const claim = await decide(b.action, b.note, b.claimId, b.payCents);
        return json({ ok: true, claim, state: currentState() });
      } catch (e) {
        broadcastLine(`[bridge] decision error: ${(e as Error).message}`);
        return json({ ok: false, error: (e as Error).message }, 500);
      }
    }
    return new Response('not found', { status: 404 });
  },
});

console.log(`BitPiggy bridge -> http://localhost:${server.port}`);
console.log(`  serial ${noSerial ? '(disabled)' : serialPort} @ ${baud}`);
console.log(`  deck ${deckPath} (${deckClaims.length} claim cells)`);
console.log(`  Flutter app ${existsSync(appDir) ? `mounted at /app/ from ${appDir}` : 'not built yet'}`);

process.on('SIGINT', () => {
  serialReader?.kill();
  process.exit(0);
});
