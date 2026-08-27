#!/usr/bin/env bun
/**
 * Does a cert built by the BRIDGE install on a fleet-anchored board?
 *
 * The bridge's own cell shape and domain, signed by the fleet operator root so
 * the board's trust anchor is satisfied. That isolates the question to the one
 * thing this change is about: the domain flag.
 *
 * The bridge's demo key (…0042) is NOT this key. A fleet-anchored board rejects
 * that signature outright — which is a separate, pre-existing incompatibility
 * and not what we are testing here.
 *
 *   PLEXUS_SDK=/path/to/plexus-sdk-ts/dist/index.js \
 *     bun tools/x402-bridge/bridge-cert-hardware-check.ts [--port /dev/cu.usbmodemXXXX]
 */

import { openSync, writeSync, closeSync } from 'node:fs';
import { spawn, execFileSync } from 'node:child_process';
import { buildCapabilityCertPayload, certHash, CAP_ROUTE_FWD_V1, CAPABILITY_V0_TYPE } from './capability-cert.js';
import { mintCell } from './cell-codec.js';
import { domainForType } from './cell-domains.js';
import { DOMAIN, domainName } from '../domains.js';

const arg = (n: string, d: string) => {
  const i = process.argv.indexOf(n);
  return i > 0 ? process.argv[i + 1] : d;
};
const INJECT = arg('--port', '/dev/cu.usbmodem21201');
const WATCH = arg('--watch', '/dev/cu.usbmodem21301');
// The demo fleet the boards are flashed for (salt is in the repo — DEMO only).
const ROOT_EMAIL = 'operator@fleet.example';
const ROOT_SALT = 'demo-fleet-salt';

const SDK = process.env.PLEXUS_SDK ?? '/Users/toddprice/projects/repos/libs/plexus-sdk-ts/dist/index.js';
const sdk = await import(SDK);

const crc32 = (b: Uint8Array): number => {
  let c = ~0;
  for (const x of b) {
    c ^= x;
    for (let i = 0; i < 8; i++) c = (c >>> 1) ^ (0xedb88320 & -(c & 1));
  }
  return ~c >>> 0;
};
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');

// ── build the cert exactly as the bridge does ───────────────────────────────
const operator = sdk.derivePrivateKeyAtPath(ROOT_EMAIL, ROOT_SALT, 'root');
const operatorPk = new Uint8Array(Buffer.from(operator.toPublicKey().toString(), 'hex'));

// A relay key for a demo channel — public half only reaches the device.
const relay = sdk.derivePrivateKeyAtPath(ROOT_EMAIL, ROOT_SALT, 'root');
const relayPk = new Uint8Array(Buffer.from(relay.toPublicKey().toString(), 'hex'));
const channelId = new Uint8Array(16).fill(0xa5);
const validFrom = BigInt(Date.now());

const payload = buildCapabilityCertPayload(
  relayPk, channelId, 0xffffffffffffffffn, CAP_ROUTE_FWD_V1, validFrom,
);
const flag = domainForType(CAPABILITY_V0_TYPE);

const build = (domainFlag: number) => {
  const cell = mintCell(CAPABILITY_V0_TYPE, payload, operatorPk.subarray(0, 16), validFrom, domainFlag);
  const sig = operator.sign(Array.from(cell));
  return {
    cell,
    sig: new Uint8Array([...sig.r.toArray('be', 32), ...sig.s.toArray('be', 32)]),
  };
};

console.log('bridge-built capability cert');
console.log(`  operator anchor  ${hex(operatorPk)}`);
console.log(`  domain           0x${flag.toString(16).padStart(8, '0')}  (${domainName(flag)})`);
console.log(`  cert hash        ${hex(certHash(payload))}`);

// ── inject and watch ────────────────────────────────────────────────────────
// Both ports need raw mode with no hangup, or `cat` returns nothing and the
// injected line is line-disciplined into something the firmware will not parse.
for (const p of [INJECT, WATCH]) {
  execFileSync('stty', ['-f', p, 'raw', '-echo', '115200', 'clocal', 'cread']);
}

const injectOnce = async (cell: Uint8Array, sig: Uint8Array): Promise<string> => {
  const frame = new Uint8Array(cell.length + sig.length);
  frame.set(cell); frame.set(sig, cell.length);
  const line = `IJ${hex(frame)}${Buffer.from(new Uint32Array([crc32(frame)]).buffer).toString('hex')}\n`;

  const tail = spawn('cat', [WATCH]);
  let seen = '';
  tail.stdout.on('data', (d) => { seen += d.toString(); });
  await new Promise((r) => setTimeout(r, 500));

  // Chunked, with gaps, and sent twice — a single 2 KB write overruns the C6's
  // USB-CDC line buffer and the firmware never sees a terminated line. Same
  // pacing the Zig harness uses (tools/fleet-zig/src/hardware.zig inject).
  const bytes = Buffer.from(line, 'ascii');
  for (let attempt = 0; attempt < 2; attempt++) {
    const fd = openSync(INJECT, 'w');
    for (let off = 0; off < bytes.length; off += 256) {
      writeSync(fd, bytes.subarray(off, Math.min(off + 256, bytes.length)));
      await new Promise((r) => setTimeout(r, 2));
    }
    closeSync(fd);
    await new Promise((r) => setTimeout(r, 400));
  }
  await new Promise((r) => setTimeout(r, 6000));
  tail.kill();

  // Search the WHOLE buffer, not line-by-line: `cat` on a tty delivers in
  // chunks and a split('\n') can land mid-line, which reads as "the board said
  // nothing" when it in fact said the right thing.
  const clean = seen.replace(/\x1b\[[0-9;]*m/g, '');
  const m = clean.match(/mesh_demo: (CAP cert [^\n\r]*|.*signature INVALID[^\n\r]*)/);
  void m;
  return clean;
};

/**
 * Inject, and retry once if the tail caught nothing.
 *
 * Two `cat` processes on the same tty in quick succession can race: the second
 * opens before the first has fully released, and the reply lands in nobody's
 * buffer. That reads as "the board said nothing", which is indistinguishable
 * from a real refusal — so retry rather than report a false negative.
 */
const inject = async (label: string, cell: Uint8Array, sig: Uint8Array): Promise<string> => {
  console.log(`\n${label}`);
  let out = '';
  for (let attempt = 0; attempt < 2; attempt++) {
    out = await injectOnce(cell, sig);
    if (/CAP cert |signature INVALID/.test(out)) break;
    if (attempt === 0) {
      console.log('  (no reply captured — retrying, the serial tail can race)');
      await new Promise((r) => setTimeout(r, 1500));
    }
  }
  const m = out.match(/mesh_demo: (CAP cert [^\n\r]*|[^\n\r]*signature INVALID[^\n\r]*)/);
  console.log(`  board said: ${m?.[1]?.trim() ?? '(nothing — is the board flashed and idle?)'}`);
  return out;
};

let failures = 0;

const good = build(flag);
const gotGood = await inject(
  `1. the bridge's own rail (0x${flag.toString(16).padStart(8, '0')}) — must INSTALL`,
  good.cell, good.sig);
if (gotGood.includes('CAP cert installed')) {
  console.log('  ACCEPTED — the bridge and the board agree on the relay rail');
} else { console.log('  NOT ACCEPTED'); failures++; }

// Same operator, same payload, same signature scheme — only byte 24 differs.
// Without this, the run above proves only that SOMETHING installs.
const bad = build(DOMAIN.orgMember);
const gotBad = await inject(
  `2. the same cert on the org.member rail (0x${DOMAIN.orgMember.toString(16)}) — must be REFUSED`,
  bad.cell, bad.sig);
if (gotBad.includes('CAP cert REFUSED')) {
  console.log('  REFUSED — valid operator signature, byte-identical payload, wrong rail');
} else { console.log('  NOT REFUSED — the domain is not being enforced'); failures++; }

console.log(failures === 0
  ? '\nA cert built by the x402 bridge, carrying the rail the bridge declares,\n' +
    'installs on a fleet-anchored C6 — and the same cert on another rail does not.'
  : `\n${failures} check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
