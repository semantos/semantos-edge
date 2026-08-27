/**
 * The signing key is the trust anchor, or nothing works.
 *
 * The failure this guards against is the one that already happened: the
 * firmware's anchor was switched to the fleet root, the bridge kept signing
 * with the old demo key, and every cell was refused with "signature INVALID
 * (wallet pubkey)" — a message that reads as a framing or radio fault. Nothing
 * in the repo could have told you the two had diverged.
 */

import { describe, expect, test } from 'bun:test';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  resolveSigner, deriveFleetRoot, firmwareAnchorHex, checkAgainstFirmware,
  DEMO_ROOT_EMAIL, DEMO_ROOT_SALT,
} from '../signer.js';

const FLEET_ANCHOR = '0245ad80f7eb6d2222ad6741fe6aa6a9b51d5571c6945a43813cf4b71b5441e6d6';
const LEGACY_PUB = '03079264c4b4bfcd7fe3a7b7b92b6c439f3a5b3abcd29189bf7b54d781ff03d722';

describe('deriving the fleet root without the SDK', () => {
  test('reproduces the anchor the boards are flashed with', () => {
    // The whole reason the bridge needs no Plexus dependency: the root is plain
    // PBKDF2-HMAC-SHA512(email, salt, 100k, 32) and the output IS the key.
    // If this drifts from tools/fleet-zig/src/derive.zig, the two planes have
    // forked and the bridge will sign as somebody else.
    expect(deriveFleetRoot(DEMO_ROOT_EMAIL, DEMO_ROOT_SALT).toPublicKey().toString())
      .toBe(FLEET_ANCHOR);
  });

  test('a different salt is a different universe, not an error', () => {
    expect(deriveFleetRoot(DEMO_ROOT_EMAIL, 'other-salt').toPublicKey().toString())
      .not.toBe(FLEET_ANCHOR);
  });

  test('email and salt are not interchangeable', () => {
    // derive.zig warns that the slot order is easy to invert and silently
    // produces a different, valid universe. Pin it.
    expect(deriveFleetRoot(DEMO_ROOT_SALT, DEMO_ROOT_EMAIL).toPublicKey().toString())
      .not.toBe(FLEET_ANCHOR);
  });
});

describe('resolution order', () => {
  test('defaults to the fleet root — what the boards expect', () => {
    const s = resolveSigner({} as NodeJS.ProcessEnv);
    expect(s.source).toBe('fleet-root');
    expect(s.publicKeyHex).toBe(FLEET_ANCHOR);
  });

  test('the legacy key must be opted into explicitly', () => {
    const s = resolveSigner({ MESH_SIGNER: 'legacy' } as NodeJS.ProcessEnv);
    expect(s.source).toBe('legacy-demo');
    expect(s.publicKeyHex).toBe(LEGACY_PUB);
    expect(s.describe).toContain('USE_FLEET_ANCHOR=0');
  });

  test('an explicit key wins over everything', () => {
    const s = resolveSigner({
      MESH_SIGNER_KEY_HEX: '11'.repeat(32),
      MESH_SIGNER: 'legacy',
      MESH_ROOT_EMAIL: 'ignored@example.com',
    } as NodeJS.ProcessEnv);
    expect(s.source).toBe('explicit-key');
  });

  test('a malformed explicit key is refused, not silently coerced', () => {
    expect(() => resolveSigner({ MESH_SIGNER_KEY_HEX: 'deadbeef' } as NodeJS.ProcessEnv))
      .toThrow(/64 hex/);
  });

  test('a custom universe is honoured', () => {
    const s = resolveSigner({
      MESH_ROOT_EMAIL: 'ops@acme.test', MESH_ROOT_SALT: 'acme-salt',
    } as NodeJS.ProcessEnv);
    expect(s.source).toBe('fleet-root');
    expect(s.publicKeyHex).toBe(deriveFleetRoot('ops@acme.test', 'acme-salt').toPublicKey().toString());
    expect(s.describe).toContain('ops@acme.test');
  });

  test('no resolution path ever exposes the private key', () => {
    for (const env of [
      {}, { MESH_SIGNER: 'legacy' }, { MESH_SIGNER_KEY_HEX: '11'.repeat(32) },
    ] as NodeJS.ProcessEnv[]) {
      const s = resolveSigner(env);
      const secret = s.key.toString();
      expect(s.describe).not.toContain(secret);
      expect(s.publicKeyHex).not.toContain(secret);
      // and the describe line is safe to paste into a log
      expect(s.describe).toContain(s.publicKeyHex);
    }
  });
});

describe('the firmware mismatch guard', () => {
  test('reads the anchor from the real main.c', () => {
    expect(firmwareAnchorHex()).toBe(FLEET_ANCHOR);
  });

  test('follows USE_FLEET_ANCHOR rather than picking the first array', () => {
    // The parse must honour the #if. Taking whichever array appears first would
    // pass today and be wrong the moment someone flips the gate.
    const dir = mkdtempSync(join(tmpdir(), 'anchor-'));
    const body = (gate: number) => `
#define USE_FLEET_ANCHOR ${gate}
#if USE_FLEET_ANCHOR
static const uint8_t s_wallet_pubkey[33] = {
    0x02, 0x45, 0xad, 0x80, 0xf7, 0xeb, 0x6d, 0x22, 0x22, 0xad, 0x67, 0x41,
    0xfe, 0x6a, 0xa6, 0xa9, 0xb5, 0x1d, 0x55, 0x71, 0xc6, 0x94, 0x5a, 0x43,
    0x81, 0x3c, 0xf4, 0xb7, 0x1b, 0x54, 0x41, 0xe6, 0xd6,
};
#else
static const uint8_t s_wallet_pubkey[33] = {
    0x03, 0x07, 0x92, 0x64, 0xc4, 0xb4, 0xbf, 0xcd, 0x7f, 0xe3, 0xa7, 0xb7,
    0xb9, 0x2b, 0x6c, 0x43, 0x9f, 0x3a, 0x5b, 0x3a, 0xbc, 0xd2, 0x91, 0x89,
    0xbf, 0x7b, 0x54, 0xd7, 0x81, 0xff, 0x03, 0xd7, 0x22,
};
#endif
`;
    const on = join(dir, 'on.c'); writeFileSync(on, body(1));
    const off = join(dir, 'off.c'); writeFileSync(off, body(0));
    expect(firmwareAnchorHex(on)).toBe(FLEET_ANCHOR);
    expect(firmwareAnchorHex(off)).toBe(LEGACY_PUB);
  });

  test('an unreadable main.c is "unknown", not "mismatch"', () => {
    // A bridge pointed at somebody else's board has no main.c to consult.
    // Failing closed there would block a legitimate run for no evidence.
    const check = checkAgainstFirmware(resolveSigner({} as NodeJS.ProcessEnv), '/nope/main.c');
    expect(check.matches).toBe(true);
    expect(check.firmwareAnchorHex).toBeNull();
    expect(check.message).toContain('cannot check');
  });

  test('the fleet root matches; the legacy key does not, and says why', () => {
    expect(checkAgainstFirmware(resolveSigner({} as NodeJS.ProcessEnv)).matches).toBe(true);

    const bad = checkAgainstFirmware(resolveSigner({ MESH_SIGNER: 'legacy' } as NodeJS.ProcessEnv));
    expect(bad.matches).toBe(false);
    expect(bad.message).toContain('signature INVALID');
    expect(bad.message).toContain(FLEET_ANCHOR);
    expect(bad.message).not.toContain('0000000000000000');  // never the private key
  });
});
