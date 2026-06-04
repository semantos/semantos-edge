/**
 * Proves the cell-engine's BIP-143 sighash (cell-codec.bip143Sighash, mirroring
 * core/cell-engine sighash.zig) is byte-identical to the canonical sighash that
 * miners/ARC enforce (@bsv/sdk Transaction.preimage → hash256). This is what
 * makes "C6-gated real spend" sound: a spend the C6 accepts is valid on mainnet.
 */
import { describe, it, expect } from 'bun:test';
import { PrivateKey, Transaction, Script, P2PKH } from '@bsv/sdk';
import { bip143Sighash, sha256 } from '../cell-codec.js';

describe('cell-engine sighash == canonical BSV sighash', () => {
  it('matches @bsv/sdk for a P2PK input (SIGHASH_ALL|FORKID)', () => {
    const key = new PrivateKey('00000000000000000000000000000000000000000000000000000000000000a1', 16);
    const pk = new Uint8Array(Buffer.from(key.toPublicKey().toString(), 'hex'));
    const p2pkLock = new Uint8Array([0x21, ...pk, 0xac]);
    const V = 1000, fee = 200, SCOPE = 0x41;

    const funding = new Transaction();
    funding.addInput({ sourceTXID: '00'.repeat(32), sourceOutputIndex: 0, unlockingScript: new Script(), sequence: 0xffffffff });
    funding.addOutput({ satoshis: V, lockingScript: Script.fromBinary(Array.from(p2pkLock)) });

    const outScript = new P2PKH().lock(key.toAddress());
    const spend = new Transaction();
    spend.addInput({ sourceTransaction: funding, sourceOutputIndex: 0, unlockingScript: new Script(), sequence: 0xffffffff });
    spend.addOutput({ satoshis: V - fee, lockingScript: outScript });
    spend.version = 1; spend.lockTime = 0;

    const canonical = sha256(sha256(new Uint8Array(spend.preimage(0, SCOPE, Script.fromBinary(Array.from(p2pkLock))))));
    const cellEngine = bip143Sighash(
      1,
      [{ prevTxid: new Uint8Array(Buffer.from(funding.id('hex'), 'hex')).reverse(), prevVout: 0, sequence: 0xffffffff }],
      [{ value: BigInt(V - fee), script: new Uint8Array(outScript.toBinary()) }],
      0, 0, p2pkLock, BigInt(V), SCOPE,
    );

    expect(Buffer.from(cellEngine).toString('hex')).toBe(Buffer.from(canonical).toString('hex'));
  });
});
