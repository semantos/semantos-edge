#!/usr/bin/env bun
/**
 * Do the two new forward gates actually refuse anything?
 *
 * A passing positive test only proves nothing broke. These are the cases that
 * prove the gates exist:
 *
 *   1. forward.v0 signed by the WRONG key   -> "forward: sig INVALID"
 *      Before this gate existed the cell was acted on regardless, and
 *      INSTALL_RULE writes the rule table — an unauthenticated remote policy
 *      write to anyone in radio range.
 *
 *   2. forward.v2 with Cell B TAMPERED      -> "does not match Cell A's routing_digest"
 *      Cell A is signed and Cell B is not, and Cell B carries the route and the
 *      payment commitments. Flipping one byte of a share used to be invisible.
 *
 *   bun tools/x402-bridge/forward-negative-check.ts
 */
import { openSync, writeSync, closeSync } from 'node:fs';
import { spawn, execFileSync } from 'node:child_process';
import { PrivateKey } from '@bsv/sdk';
import { mintCell, signCell, typeHash, writeU32LE, sha256 } from './cell-codec.js';
import { domainForType } from './cell-domains.js';
import { buildCapabilityCertCell, deriveChannelRelayKey } from './capability-cert.js';
import { startSigner, resolveSigner } from './signer.js';
import { DOMAIN } from '../domains.js';

const INJECT = '/dev/cu.usbmodem21201';
const WATCH = '/dev/cu.usbmodem21301';          // MAC_B — segments[0]
const MAC_B = new Uint8Array([0x58, 0xe6, 0xc5, 0x1a, 0x8c, 0x54]);
const MAC_C = new Uint8Array([0x58, 0xe6, 0xc5, 0x1a, 0x8c, 0xf8]);
const OWNER = new Uint8Array(16);

const T_FWD_V0 = typeHash('cellmesh.forward.v0');
const T_FWD_V2 = typeHash('cellmesh.forward.v2');
const T_ROUTING = typeHash('cellmesh.routing.cont.v0');

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const crc32 = (b: Uint8Array): number => {
  let c = ~0;
  for (const x of b) { c ^= x; for (let i = 0; i < 8; i++) c = (c >>> 1) ^ (0xedb88320 & -(c & 1)); }
  return ~c >>> 0;
};

/** forward.v0 payload: 48-byte base header, segments at 24. */
const buildV0Payload = (hopVerb: number): Uint8Array => {
  const buf = new Uint8Array(48);
  buf.set(sha256(new Uint8Array([1, 2, 3])).subarray(0, 16), 0);  // flow_id
  buf[16] = 0; buf[17] = 2; buf[18] = 2; buf[19] = hopVerb;
  writeU32LE(buf, 20, 0);
  buf.set(MAC_B, 24); buf.set(MAC_C, 30);
  return buf;
};

/** forward.v2 Cell B: routing + commitments. Mirrors buildForwardV2PayloadB. */
const buildCellB = (flowId: Uint8Array): Uint8Array => {
  const buf = new Uint8Array(320);
  buf.set(flowId, 0);
  buf[16] = 0; buf[17] = 2;
  buf.set(MAC_B, 24); buf.set(MAC_C, 30);
  for (let i = 0; i < 2; i++) {
    const off = 48 + i * 68;
    writeU32LE(buf, off + 16, 1);         // seq
    writeU32LE(buf, off + 20, 10);        // device_share
  }
  return buf;
};

/** forward.v2 Cell A: 24-byte header. The binding rides in flow_id. */
const buildCellA = (flowId: Uint8Array): Uint8Array => {
  const buf = new Uint8Array(24);
  buf.set(flowId, 0);
  buf[16] = 0; buf[17] = 2; buf[18] = 0; buf[19] = 0x01;
  writeU32LE(buf, 20, 0);
  return buf;
};

/** Mirrors cm_routing_cont_flow_id: sha256(payloadB[16..320])[0..16]. */
const routingFlowId = (payloadB: Uint8Array): Uint8Array =>
  sha256(payloadB.subarray(16, 320)).subarray(0, 16);

for (const p of [INJECT, WATCH]) {
  execFileSync('stty', ['-f', p, 'raw', '-echo', '115200', 'clocal', 'cread']);
}

const send = async (cell: Uint8Array, sig: Uint8Array) => {
  const frame = new Uint8Array(cell.length + sig.length);
  frame.set(cell); frame.set(sig, cell.length);
  const line = `IJ${hex(frame)}${Buffer.from(new Uint32Array([crc32(frame)]).buffer).toString('hex')}\n`;
  const bytes = Buffer.from(line, 'ascii');
  for (let a = 0; a < 2; a++) {
    const fd = openSync(INJECT, 'w');
    for (let o = 0; o < bytes.length; o += 256) {
      writeSync(fd, bytes.subarray(o, Math.min(o + 256, bytes.length)));
      await new Promise((r) => setTimeout(r, 2));
    }
    closeSync(fd);
    await new Promise((r) => setTimeout(r, 250));
  }
};

const watch = async (label: string, run: () => Promise<void>, waitMs: number): Promise<string> => {
  const tail = spawn('cat', [WATCH]);
  let seen = '';
  tail.stdout.on('data', (d) => { seen += d.toString(); });
  await new Promise((r) => setTimeout(r, 500));
  await run();
  await new Promise((r) => setTimeout(r, waitMs));
  tail.kill();
  const clean = seen.replace(/\x1b\[[0-9;]*m/g, '');
  console.log(`\n${label}`);
  for (const l of clean.split('\n')) {
    if (/forward|routing\.cont|RELAY|DELIVERED/.test(l)) console.log(`  ${l.trim()}`);
  }
  return clean;
};

const signer = startSigner();
let failures = 0;

// ── 1. forward.v0 signed by the wrong key ───────────────────────────────────
{
  const payload = buildV0Payload(2);  // INSTALL_RULE — the dangerous verb
  const cell = mintCell(T_FWD_V0, payload, OWNER, BigInt(Date.now()), domainForType(T_FWD_V0));
  const wrong = resolveSigner({ MESH_SIGNER: 'legacy' } as NodeJS.ProcessEnv).key;
  const s = wrong.sign(Array.from(cell));
  const sig = new Uint8Array([...s.r.toArray('be', 32), ...s.s.toArray('be', 32)]);
  const out = await watch('1. forward.v0 INSTALL_RULE signed by the LEGACY key — must be REFUSED',
    () => send(cell, sig), 6000);
  if (out.includes('forward: sig INVALID')) {
    console.log('  REFUSED — an unauthenticated rule write is no longer possible');
  } else if (/forward → relay|FORWARD DELIVERED|INSTALL_RULE: queued/.test(out)) {
    console.log('  ACTED ON IT — the signature gate is not working'); failures++;
  } else { console.log('  no verdict (nothing logged)'); failures++; }
}

// ── 2. forward.v2 with Cell B tampered after Cell A committed to it ─────────
{
  // Build Cell B, derive its flow_id from its OWN routing content, write it
  // back, and let Cell A carry that flow_id. Exactly what the bridge does.
  const payloadB = buildCellB(new Uint8Array(16));
  payloadB.set(routingFlowId(payloadB), 0);
  const cellB = mintCell(T_ROUTING, payloadB, OWNER, BigInt(Date.now()), domainForType(T_ROUTING));
  const payloadA = buildCellA(payloadB.subarray(0, 16));
  const cellA = mintCell(T_FWD_V2, payloadA, OWNER, BigInt(Date.now()), domainForType(T_FWD_V2));
  const sigA = (() => { const x = signer.key.sign(Array.from(cellA));
    return new Uint8Array([...x.r.toArray('be', 32), ...x.s.toArray('be', 32)]); })();

  // Raise hop 0's claimed device_share from 10 to 9999. The attacker cannot
  // repair flow_id to match: it is inside Cell A, which is signed.
  const tampered = new Uint8Array(cellB);
  writeU32LE(tampered, 256 + 48 + 20, 9999);

  const out = await watch('2. forward.v2 with Cell B\'s device_share raised 10 -> 9999 — must be REFUSED',
    async () => {
      await send(cellA, sigA);
      await new Promise((r) => setTimeout(r, 2500));   // clear the 1800ms staging window
      await send(tampered, new Uint8Array(64));
    }, 7000);
  if (out.includes("does not match Cell A's flow_id binding")) {
    console.log('  REFUSED — the route and the payment claims ride under Cell A\'s signature');
  } else if (/forward\.v2: CAP-verified|FORWARD\.V2 DELIVERED/.test(out)) {
    console.log('  ACCEPTED — the flow_id binding is not working'); failures++;
  } else { console.log('  no verdict (nothing logged)'); failures++; }
}

// ── 3. forward.v0 from the RIGHT key, to a device with no relay grant ───────
{
  // Reset board B so its capability table is empty — the state an
  // unprovisioned board is in. Then send a perfectly valid, correctly-signed
  // forward.v0. Authenticated is not authorised.
  console.log('\n3. forward.v0, correctly signed, to a board with NO relay grant — must be REFUSED');
  console.log('   (resetting the watch board to clear its capability table…)');
  execFileSync('python3', ['-c', `
import serial,time
p=serial.Serial('${WATCH}',115200,timeout=1)
p.setDTR(False); p.setRTS(True); time.sleep(0.1); p.setRTS(False); p.close()`]);
  await new Promise((r) => setTimeout(r, 20000));  // boot ECDSA bench
  execFileSync('stty', ['-f', WATCH, 'raw', '-echo', '115200', 'clocal', 'cread']);

  const payload = buildV0Payload(2);
  const cell = mintCell(T_FWD_V0, payload, OWNER, BigInt(Date.now()), domainForType(T_FWD_V0));
  const x = signer.key.sign(Array.from(cell));
  const sig = new Uint8Array([...x.r.toArray('be', 32), ...x.s.toArray('be', 32)]);

  const out = await watch('   injecting…', () => send(cell, sig), 6000);
  if (out.includes('no relay grant')) {
    console.log('  REFUSED — the operator signed it, but this board was never granted relay');
  } else if (/forward → relay|FORWARD DELIVERED|INSTALL_RULE: queued/.test(out)) {
    console.log('  ACTED ON IT — the capability gate is not working'); failures++;
  } else { console.log('  no verdict (nothing logged)'); failures++; }
}

// ── 4. Cell B's HEADER must not steer any decision ─────────────────────────
{
  // The flow_id binding covers Cell B's PAYLOAD (bytes 16..320), not its
  // header. So Cell B's header is attacker-controlled for good — it carries no
  // signature and never will. The device must therefore make no decision from
  // it. It used to: the capability lookup took its domain from Cell B, so an
  // attacker could re-mint Cell B with an identical payload and a chosen
  // domain, pass the binding, and pick which grant authorised the relay.
  //
  // Here Cell A is on the relay rail and Cell B's header says org.member. If
  // the device still read the domain from Cell B it would find no cert and drop
  // with "no cert for channel". Accepting it is the proof that the domain now
  // comes from the signed cell.
  // Case 3 reset the board, so its capability table is empty. Install a cert
  // first, or this fails with "no cert" for a reason that has nothing to do
  // with what is being tested.
  const relay = deriveChannelRelayKey(signer.key, '00'.repeat(16));
  {
    const { cell: certCell, sig: certSig } = buildCapabilityCertCell(
      new Uint8Array(16), relay, signer.key, 0xffffffffffffffffn, BigInt(Date.now()),
    );
    await send(certCell, certSig);
    await new Promise((r) => setTimeout(r, 3000));   // one cell per second, roughly
  }

  const payloadB = buildCellB(new Uint8Array(16));
  payloadB.set(routingFlowId(payloadB), 0);
  const cellB = mintCell(T_ROUTING, payloadB, OWNER, BigInt(Date.now()), DOMAIN.orgMember);
  const payloadA = buildCellA(payloadB.subarray(0, 16));
  const cellA = mintCell(T_FWD_V2, payloadA, OWNER, BigInt(Date.now()), domainForType(T_FWD_V2));
  // Cell A is signed by the RELAY key the cert grants, not by the operator
  // root — that is what the device verifies against, via the cert's edge_pubkey.
  const relayWallet = new PrivateKey(Buffer.from(relay.sk).toString('hex'), 16);
  const x = relayWallet.sign(Array.from(cellA));
  const sigA = new Uint8Array([...x.r.toArray('be', 32), ...x.s.toArray('be', 32)]);

  const out = await watch(
    "4. Cell B's header domain switched to org.member — the decision must ignore it",
    async () => {
      await send(cellA, sigA);
      await new Promise((r) => setTimeout(r, 2500));
      await send(cellB, new Uint8Array(64));
    }, 7000);
  if (/forward\.v2: CAP-verified/.test(out)) {
    console.log("  IGNORED — the capability domain came from the SIGNED Cell A");
  } else if (out.includes('no cert for channel')) {
    console.log("  STEERED BY IT — Cell B's unsigned header is still choosing the grant"); failures++;
  } else if (out.includes('sig INVALID')) {
    console.log('  inconclusive — Cell A was signed by the wrong key, not a domain result'); failures++;
  } else { console.log('  no verdict (nothing logged)'); failures++; }
}

console.log(failures === 0
  ? '\nAll four checks behave as intended.'
  : `\n${failures} check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
