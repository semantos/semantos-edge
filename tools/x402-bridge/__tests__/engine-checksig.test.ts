/**
 * The vendored engine, run the way a board runs a scripted cell (mesh_demo's
 * dispatch_scripted_cell): reset, the BIP-143 tx context, the lock, the
 * unlock, execute. The payload is built with the kit's own helpers, as
 * scripted-vm-demo.ts and sign-cell-deck.ts build theirs: a P2PK lock, and an
 * unlock pushing DER plus the hash-type byte.
 *
 * The host answers the way components/semantos/src/host_crypto_mbedtls.c
 * does, under the contract in docs/HOST_IMPORTS.md: verify over the 32 bytes
 * it is given, never hash them again, and expect strict DER with no hash-type
 * byte. These tests hold the kernel's half of that contract, which changed in
 * core in November 2026 (the kernel strips the byte once and checks BIP-66
 * before it asks the host), so a refreshed blob that broke it fails here
 * rather than on a board.
 */
import { describe, expect, test } from 'bun:test';
import { resolve } from 'node:path';
import { BigNumber, ECDSA, Hash, PrivateKey, PublicKey, Signature } from '@bsv/sdk';

import { bip143Sighash, ecdsaDer } from '../cell-codec.js';

const WASM = resolve(import.meta.dir, '../../../components/semantos/wasm/cell-engine-embedded.wasm');
const SIGHASH_ALL_FORKID = 0x41;

type CheckSigCall = { pk: Uint8Array; msg: Uint8Array; sig: Uint8Array };

async function openEngine() {
  const module = new WebAssembly.Module(await Bun.file(WASM).arrayBuffer());
  let memory!: WebAssembly.Memory;
  const bytes = (p: number, n: number) => new Uint8Array(memory.buffer, p, n).slice();
  const put = (p: number, b: number[] | Uint8Array) => new Uint8Array(memory.buffer, p, b.length).set(b);
  const calls: CheckSigCall[] = [];

  const host: Record<string, (...a: any[]) => number | void> = {};
  for (const imp of WebAssembly.Module.imports(module)) host[imp.name] = () => 0;
  host.host_sha256 = (p: number, n: number, out: number) => put(out, Hash.sha256(Array.from(bytes(p, n))));
  host.host_hash256 = (p: number, n: number, out: number) => put(out, Hash.hash256(Array.from(bytes(p, n))));
  host.host_hash160 = (p: number, n: number, out: number) => put(out, Hash.hash160(Array.from(bytes(p, n))));
  host.host_ripemd160 = (p: number, n: number, out: number) => put(out, Hash.ripemd160(Array.from(bytes(p, n))));
  host.host_sha1 = (p: number, n: number, out: number) => put(out, Hash.sha1(Array.from(bytes(p, n))));
  host.host_checksig = (pk: number, pkl: number, msg: number, msgl: number, sig: number, sigl: number) => {
    const call = { pk: bytes(pk, pkl), msg: bytes(msg, msgl), sig: bytes(sig, sigl) };
    calls.push(call);
    if (call.msg.length !== 32) return 0;
    try {
      const key = PublicKey.fromDER(Array.from(call.pk));
      const s = Signature.fromDER(Array.from(call.sig));
      // The digest as given: no hashing here, as the board's host does not hash.
      return ECDSA.verify(new BigNumber(Array.from(call.msg)), s, key) ? 1 : 0;
    } catch {
      return 0;
    }
  };
  host.host_consumed_set = () => 2; // no consumed set, as on the board

  const instance = new WebAssembly.Instance(module, { host });
  const x = instance.exports as Record<string, any>;
  memory = x.memory as WebAssembly.Memory;
  const scratch = memory.grow(1) * 65536;
  if (x.kernel_init() !== 0) throw new Error('kernel_init failed');

  return {
    calls,
    run(tx: Uint8Array, inputIdx: number, inputValue: bigint, lock: Uint8Array, unlock: Uint8Array): number {
      calls.length = 0;
      x.kernel_reset();
      put(scratch, tx);
      const t = x.kernel_load_tx_context(scratch, tx.length, inputIdx, inputValue);
      if (t !== 0) return t;
      put(scratch + 2048, lock);
      const l = x.kernel_load_script(scratch + 2048, lock.length);
      if (l !== 0) return l;
      put(scratch + 4096, unlock);
      const u = x.kernel_load_unlock(scratch + 4096, unlock.length);
      if (u !== 0) return u;
      return x.kernel_execute();
    },
  };
}

/** The scripted-vm-demo payload's parts: P2PK lock, a minimal spending tx, its BIP-143 digest. */
function p2pk(key: PrivateKey) {
  const pub = Uint8Array.from(key.toPublicKey().encode(true) as number[]);
  const lock = new Uint8Array([0x21, ...pub, 0xac]);
  const prevTxid = new Uint8Array(32);
  const tx = new Uint8Array([
    0x01, 0x00, 0x00, 0x00, 0x01, ...prevTxid, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0x01, 0x10, 0x27, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x51, 0x00, 0x00, 0x00, 0x00,
  ]);
  const inputValue = 50_000n;
  const digest = bip143Sighash(
    1,
    [{ prevTxid, prevVout: 0, sequence: 0xffffffff }],
    [{ value: 10_000n, script: new Uint8Array([0x51]) }],
    0, 0, lock, inputValue, SIGHASH_ALL_FORKID,
  );
  const der = ecdsaDer(ECDSA.sign(new BigNumber(Array.from(digest)), key, true));
  return { pub, lock, tx, inputValue, digest, der };
}

/** PUSH(sig ‖ hashtype), as the kit's unlock scripts are built. */
function unlockOf(sigWithType: Uint8Array): Uint8Array {
  return new Uint8Array([sigWithType.length, ...sigWithType]);
}

describe('the vendored engine runs a scripted P2PK cell the way a board does', () => {
  test('a valid signature is accepted, and the host sees the 32-byte digest and bare DER', async () => {
    const engine = await openEngine();
    const key = PrivateKey.fromRandom();
    const { pub, lock, tx, inputValue, digest, der } = p2pk(key);

    const rc = engine.run(tx, 0, inputValue, lock, unlockOf(new Uint8Array([...der, SIGHASH_ALL_FORKID])));

    expect(rc).toBe(0);
    expect(engine.calls).toHaveLength(1);
    expect(Buffer.from(engine.calls[0]!.pk).toString('hex')).toBe(Buffer.from(pub).toString('hex'));
    expect(Buffer.from(engine.calls[0]!.msg).toString('hex')).toBe(Buffer.from(digest).toString('hex'));
    expect(Buffer.from(engine.calls[0]!.sig).toString('hex')).toBe(Buffer.from(der).toString('hex'));
  });

  test('a signature with one byte of its s value changed is refused', async () => {
    const engine = await openEngine();
    const { lock, tx, inputValue, der } = p2pk(PrivateKey.fromRandom());
    const tampered = new Uint8Array([...der, SIGHASH_ALL_FORKID]);
    tampered[tampered.length - 2]! ^= 0x01;

    expect(engine.run(tx, 0, inputValue, lock, unlockOf(tampered))).not.toBe(0);
  });

  test('a signature by another key is refused', async () => {
    const engine = await openEngine();
    const { lock, tx, inputValue } = p2pk(PrivateKey.fromRandom());
    const { der: otherDer } = p2pk(PrivateKey.fromRandom());

    expect(engine.run(tx, 0, inputValue, lock, unlockOf(new Uint8Array([...otherDer, SIGHASH_ALL_FORKID])))).not.toBe(0);
  });

  test('DER with a trailing byte is refused before the host is asked', async () => {
    const engine = await openEngine();
    const { lock, tx, inputValue, der } = p2pk(PrivateKey.fromRandom());

    const rc = engine.run(tx, 0, inputValue, lock, unlockOf(new Uint8Array([...der, 0x00, SIGHASH_ALL_FORKID])));

    expect(rc).not.toBe(0);
    expect(engine.calls).toHaveLength(0);
  });
});
