#!/usr/bin/env bun
/**
 * Does a cert built by the BRIDGE install on a fleet-anchored board?
 *
 * Everything here is the bridge's own code and the bridge's own resolved
 * signer — no test-only key handling, so a pass means the shipped path works.
 * Three cases, isolating one variable each:
 *
 *   1. the bridge as shipped              -> must INSTALL
 *   2. the same cert on another domain    -> must be REFUSED for its domain
 *   3. the same cert signed by the legacy key -> must be REFUSED for its signature
 *
 * Case 3 matters because it distinguishes the two gates. Before the signer was
 * repointed, EVERY bridge cell failed on the signature and the domain was never
 * reached; case 1 passing while case 3 fails is the proof that changed.
 *
 *   bun tools/x402-bridge/bridge-cert-hardware-check.ts [--port /dev/cu.usbmodemXXXX]
 */

import { openSync, writeSync, closeSync } from 'node:fs';
import { spawn, execFileSync } from 'node:child_process';
import { buildCapabilityCertPayload, certHash, deriveChannelRelayKey, CAP_ROUTE_FWD_V1, CAPABILITY_V0_TYPE } from './capability-cert.js';
import { startSigner, checkAgainstFirmware, resolveSigner } from './signer.js';
import { mintCell } from './cell-codec.js';
import { domainForType } from './cell-domains.js';
import { DOMAIN, domainName } from '../domains.js';

const arg = (n: string, d: string) => {
  const i = process.argv.indexOf(n);
  return i > 0 ? process.argv[i + 1] : d;
};
const INJECT = arg('--port', '/dev/cu.usbmodem21201');
const WATCH = arg('--watch', '/dev/cu.usbmodem21301');

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
// The SHIPPED resolution path, not a test fixture: whatever a bridge tool would
// sign with is what gets injected here.
const signer = startSigner();
const check = checkAgainstFirmware(signer);
console.log(`\n${check.message}\n`);
const operator = signer.key;
const operatorPk = new Uint8Array(Buffer.from(signer.publicKeyHex, 'hex'));

// A relay key for a demo channel — public half only reaches the device.
const relay = deriveChannelRelayKey(operator, 'a5'.repeat(16));
const relayPk = relay.pk;
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
console.log(`  signer           ${signer.source}`);
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

// The legacy key: correct payload, correct domain, wrong SIGNER. This is what
// every bridge cell looked like before the signer was repointed, and it must
// now fail on the signature — a different gate from case 2.
const legacy = resolveSigner({ MESH_SIGNER: 'legacy' } as NodeJS.ProcessEnv);
const legacyCell = mintCell(CAPABILITY_V0_TYPE, payload, operatorPk.subarray(0, 16), validFrom, flag);
const legacySigObj = legacy.key.sign(Array.from(legacyCell));
const legacySig = new Uint8Array([
  ...legacySigObj.r.toArray('be', 32), ...legacySigObj.s.toArray('be', 32),
]);
const gotLegacy = await inject(
  '3. the same cert signed by the LEGACY key — must be refused on its SIGNATURE',
  legacyCell, legacySig);
if (gotLegacy.includes('signature INVALID')) {
  console.log('  REFUSED — right domain, wrong signer: a different gate from case 2');
} else { console.log('  NOT REFUSED as expected'); failures++; }

console.log(failures === 0
  ? '\nThe x402 bridge, as shipped, signs with the fleet operator root and its\n' +
    'certs install on a fleet-anchored C6. The same cert is refused for the\n' +
    'wrong domain, and refused again for the wrong signer — two gates, both live.'
  : `\n${failures} check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
