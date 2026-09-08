/**
 * signer.ts — which key signs cells, and does it match the flashed firmware?
 *
 * ## Two keys, two jobs
 *
 * The bridge conflated these, and the conflation is why repointing the anchor
 * looks scarier than it is:
 *
 *   SIGNER  authority over CELLS. A device verifies every signed cell against
 *           the trust anchor compiled into its firmware, so this key must equal
 *           that anchor or nothing the bridge sends is accepted.
 *
 *   WALLET  funds ON-CHAIN. openChannel() locks sats to its pubkey and
 *           settleChannel() spends them, so changing it strands anything
 *           sitting at the old address.
 *
 * They are not the same concern and must not move together. This module owns
 * the first one only. The on-chain key stays where the money is.
 *
 * ## Where the signer comes from
 *
 * semantos-edge deliberately does NOT depend on the Plexus SDK — the fleet
 * tooling loads it dynamically from a path, and everything else in this repo
 * builds and runs without it. So this derives the fleet root ITSELF: the
 * derivation is plain PBKDF2-HMAC-SHA512, 100k iterations, password = email,
 * salt = salt, and the 32-byte output IS the private key. Verified to reproduce
 * the flashed anchor byte for byte (see the test), so no SDK is required to
 * sign as the operator.
 *
 * ⚠ The private key is never printed, logged, or returned as hex by anything
 * here. `describe()` reports the PUBLIC key and the source; that is all a log
 * line ever needs, and it is what makes a mismatch diagnosable.
 */

import { pbkdf2Sync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { PrivateKey } from '@bsv/sdk';

/** Matches tools/fleet-zig/src/derive.zig — change both or neither. */
const PBKDF2_ITERATIONS = 100_000;
const PBKDF2_KEY_BYTES = 32;
const PBKDF2_DIGEST = 'sha512';

/**
 * The demo fleet the C6 boards in this repo are flashed for.
 *
 * Demo only — the salt is checked into a public repo, so this universe is not
 * secret and is not meant to be. A real deployment overrides both.
 */
export const DEMO_ROOT_EMAIL = 'operator@fleet.example';
export const DEMO_ROOT_SALT = 'demo-fleet-salt';

/** The pre-fleet demo key. Only useful against USE_FLEET_ANCHOR=0 firmware. */
const LEGACY_KEY_HEX =
  '0000000000000000000000000000000000000000000000000000000000000042';

export type SignerSource = 'fleet-root' | 'explicit-key' | 'legacy-demo';

export interface Signer {
  /** The signing key. Never log this, never serialise it. */
  readonly key: PrivateKey;
  /** 33-byte compressed pubkey, hex. Safe to print — this is the anchor. */
  readonly publicKeyHex: string;
  readonly source: SignerSource;
  /** One line for a log, containing no secret. */
  readonly describe: string;
}

/** Derive the fleet operator root. Same algorithm as derive.zig deriveRootKey. */
export const deriveFleetRoot = (email: string, salt: string): PrivateKey => {
  const out = pbkdf2Sync(email, salt, PBKDF2_ITERATIONS, PBKDF2_KEY_BYTES, PBKDF2_DIGEST);
  return new PrivateKey(out.toString('hex'), 16);
};

/**
 * Resolve the cell-signing key.
 *
 * Order, most specific first:
 *   1. MESH_SIGNER_KEY_HEX  — a raw 64-hex key the operator supplies
 *   2. MESH_SIGNER=legacy   — the pre-fleet ...0042 demo key, opted into
 *   3. the fleet root       — DEFAULT, from MESH_ROOT_EMAIL / MESH_ROOT_SALT
 *
 * The fleet root is the default because that is what the boards are flashed
 * with. Defaulting to the legacy key would mean the shipped configuration
 * produces "signature INVALID (wallet pubkey)" on every cell — a failure that
 * reads as a radio or framing problem and costs an afternoon to trace.
 */
export const resolveSigner = (env: NodeJS.ProcessEnv = process.env): Signer => {
  const explicit = env.MESH_SIGNER_KEY_HEX?.trim();
  if (explicit) {
    if (!/^[0-9a-fA-F]{64}$/.test(explicit)) {
      throw new Error('MESH_SIGNER_KEY_HEX must be exactly 64 hex characters');
    }
    const key = new PrivateKey(explicit, 16);
    const publicKeyHex = key.toPublicKey().toString();
    return {
      key, publicKeyHex, source: 'explicit-key',
      describe: `explicit key (MESH_SIGNER_KEY_HEX) -> ${publicKeyHex}`,
    };
  }

  if (env.MESH_SIGNER?.trim() === 'legacy') {
    const key = new PrivateKey(LEGACY_KEY_HEX, 16);
    const publicKeyHex = key.toPublicKey().toString();
    return {
      key, publicKeyHex, source: 'legacy-demo',
      describe: `LEGACY demo key (...0042) -> ${publicKeyHex} ` +
        '— only accepted by firmware built with USE_FLEET_ANCHOR=0',
    };
  }

  const email = env.MESH_ROOT_EMAIL?.trim() || DEMO_ROOT_EMAIL;
  const salt = env.MESH_ROOT_SALT?.trim() || DEMO_ROOT_SALT;
  const key = deriveFleetRoot(email, salt);
  const publicKeyHex = key.toPublicKey().toString();
  const isDemo = email === DEMO_ROOT_EMAIL && salt === DEMO_ROOT_SALT;
  return {
    key, publicKeyHex, source: 'fleet-root',
    describe: `fleet root ${isDemo ? '(demo universe)' : `<${email}>`} -> ${publicKeyHex}`,
  };
};

// ── Does this key match the firmware? ───────────────────────────────────────

/** Where the firmware's compiled-in trust anchor lives. */
const MAIN_C = new URL('../../examples/mesh_demo/main/main.c', import.meta.url).pathname;

/**
 * Read the trust anchor the firmware is ACTUALLY compiled with.
 *
 * Parses the byte array, not the comment beside it: a comment that names a key
 * goes on asserting the old value after the array changes, which is the exact
 * failure mode that put `ZONE_KEY (0x0b)` in a comment above a 0x0e constant.
 *
 * Returns null if main.c cannot be read or parsed — the caller decides whether
 * that is fatal. It should not be: a bridge run against a board someone else
 * flashed has no main.c to consult.
 */
export const firmwareAnchorHex = (path: string = MAIN_C): string | null => {
  let src: string;
  try {
    src = readFileSync(path, 'utf-8');
  } catch {
    return null;
  }
  const gate = src.match(/^#define\s+USE_FLEET_ANCHOR\s+(\d+)/m);
  if (!gate) return null;
  const useFleet = gate[1] !== '0';

  // Both arrays, in source order: the #if branch then the #else branch.
  const arrays = [...src.matchAll(
    /static const uint8_t s_wallet_pubkey\[[^\]]*\]\s*=\s*\{([^}]*)\}/g,
  )].map((m) => m[1]);
  const chosen = useFleet ? arrays[0] : arrays[1];
  if (!chosen) return null;

  const bytes = [...chosen.matchAll(/0x([0-9a-fA-F]{2})/g)].map((m) => m[1].toLowerCase());
  return bytes.length === 33 ? bytes.join('') : null;
};

export interface AnchorCheck {
  readonly matches: boolean;
  readonly signerPublicKeyHex: string;
  readonly firmwareAnchorHex: string | null;
  readonly message: string;
}

/**
 * Compare the signer against the firmware's anchor and explain the result.
 *
 * This exists so a mismatch is caught in one line at startup rather than as
 * "signature INVALID (wallet pubkey)" after a cell has crossed a radio.
 */
export const checkAgainstFirmware = (signer: Signer, path?: string): AnchorCheck => {
  const anchor = firmwareAnchorHex(path);
  if (anchor === null) {
    return {
      matches: true, // unknown is not a failure — the board may not be ours to read
      signerPublicKeyHex: signer.publicKeyHex,
      firmwareAnchorHex: null,
      message: 'firmware anchor unreadable (no main.c here) — cannot check; ' +
        `signing as ${signer.publicKeyHex}`,
    };
  }
  const matches = anchor === signer.publicKeyHex.toLowerCase();
  return {
    matches,
    signerPublicKeyHex: signer.publicKeyHex,
    firmwareAnchorHex: anchor,
    message: matches
      ? `signer matches the firmware anchor (${anchor.slice(0, 16)}…)`
      : `SIGNER DOES NOT MATCH THE FIRMWARE ANCHOR.\n` +
        `  signing with : ${signer.publicKeyHex}\n` +
        `  firmware wants: ${anchor}\n` +
        `  Every signed cell will be refused with "signature INVALID (wallet pubkey)".\n` +
        `  Fix: leave MESH_SIGNER unset to use the fleet root, or reflash with a\n` +
        `  matching USE_FLEET_ANCHOR setting in examples/mesh_demo/main/main.c.`,
  };
};

/** Resolve, report, and warn on mismatch. What every executable should call. */
export const startSigner = (): Signer => {
  const signer = resolveSigner();
  const check = checkAgainstFirmware(signer);
  console.error(`signer: ${signer.describe}`);
  if (!check.matches) console.error(`\n${check.message}\n`);
  return signer;
};
