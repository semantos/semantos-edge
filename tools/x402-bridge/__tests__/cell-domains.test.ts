/**
 * Every cell this repo mints declares an authority rail, and the three
 * languages that name those rails agree.
 *
 * The failure this guards against is not subtle in effect but is invisible in
 * review: a cell minted into domain 0 looks fine, signs fine, and is refused by
 * a provisioned device with a message about a missing certificate. And a flag
 * table copied into C, Zig and TypeScript drifts silently — which is exactly
 * how ZONE_KEY ended up colliding with CHANGE.
 */

import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';

import { DOMAIN, SCRIPT_SAFE_MAX, domainName } from '../../domains.js';
import {
  domainForType,
  assertRelayRailConsistent,
  KNOWN_CELL_TYPES,
} from '../cell-domains.js';
import { mintCell, typeHash, DOMAIN_UNDECLARED } from '../cell-codec.js';
import { buildCapabilityCertCell } from '../capability-cert.js';

const OFF_FLAGS = 24;
const readFlag = (cell: Uint8Array): number =>
  (cell[OFF_FLAGS] | (cell[OFF_FLAGS + 1] << 8) | (cell[OFF_FLAGS + 2] << 16) |
    (cell[OFF_FLAGS + 3] << 24)) >>> 0;

describe('authority rails', () => {
  test('the capability cert and the forwards it authorises share one flag', () => {
    // If this fails, cm_cap_lookup misses for every forward cell and the relay
    // path goes dark in a way that looks like a radio fault.
    expect(() => assertRelayRailConsistent()).not.toThrow();
    expect(domainForType(typeHash('cellmesh.forward.v1')))
      .toBe(domainForType(typeHash('cellmesh.capability.v0')));
  });

  test('every known cell type resolves to a declared, non-zero rail', () => {
    for (const t of KNOWN_CELL_TYPES) {
      const flag = domainForType(typeHash(t));
      expect(flag).not.toBe(DOMAIN_UNDECLARED);
      expect(Object.values(DOMAIN)).toContain(flag);
    }
  });

  test('an unknown cell type throws rather than defaulting to undeclared', () => {
    // Silently minting into domain 0 is how every cell in this repo came to
    // carry flag 0. A new type must fail until someone picks its rail.
    expect(() => domainForType(typeHash('cellmesh.not.a.real.type.v0')))
      .toThrow(/no authority rail/);
  });

  test('rails are actually distinct — this is not one flag wearing four names', () => {
    const distinct = new Set([
      DOMAIN.meshRelay, DOMAIN.meshPayment, DOMAIN.meshControl,
      DOMAIN.meshTelemetry, DOMAIN.meshScript,
    ]);
    expect(distinct.size).toBe(5);
  });

  test('payment and control are separate — "may spend" is not "may actuate"', () => {
    expect(domainForType(typeHash('cellmesh.channel_commitment.v0')))
      .not.toBe(domainForType(typeHash('cellmesh.actuator_activate.v0')));
  });

  test('no allocated flag has bit 31 set', () => {
    // Bit 31 is a SIGN bit to the engine's script-number reader: a 4-byte push
    // of 0x80000000 compares equal to 0, so a cell declaring domain 0 would be
    // accepted. See components/cell-mesh/test/vectors/README.md.
    for (const [name, flag] of Object.entries(DOMAIN)) {
      expect(flag, `${name} must stay script-safe`).toBeLessThanOrEqual(SCRIPT_SAFE_MAX);
    }
  });
});

describe('minted cells carry their rail', () => {
  test('mintCell writes the flag at header offset 24', () => {
    for (const t of KNOWN_CELL_TYPES) {
      const want = domainForType(typeHash(t));
      const cell = mintCell(typeHash(t), new Uint8Array(8), new Uint8Array(16), 1n, want);
      expect(readFlag(cell), `${t} header flag`).toBe(want);
    }
  });

  test('a real capability cert cell declares the relay rail', () => {
    // The end-to-end shape: this is the exact function mesh-control.ts calls,
    // so a regression here is a regression on the wire.
    const { PrivateKey } = require('@bsv/sdk');
    const wallet = new PrivateKey('01'.repeat(32), 16);
    const relay = new PrivateKey('02'.repeat(32), 16);
    const relayPk = new Uint8Array(
      Buffer.from(relay.toPublicKey().toString(), 'hex'),
    );
    const { cell } = buildCapabilityCertCell(
      new Uint8Array(16),
      { sk: new Uint8Array(32), pk: relayPk },
      wallet, 0xffffffffffffffffn, 1n,
    );
    expect(readFlag(cell)).toBe(DOMAIN.meshRelay);
  });

  test('DOMAIN_UNDECLARED is still zero, and still means "no domain"', () => {
    expect(DOMAIN_UNDECLARED).toBe(0);
    const cell = mintCell(typeHash('cellmesh.tap.v0'), new Uint8Array(4), new Uint8Array(16), 1n);
    expect(readFlag(cell)).toBe(0); // the default is unchanged for old callers
  });
});

describe('the three languages agree', () => {
  const root = new URL('../../../', import.meta.url).pathname;

  test('domains.ts and cell_domains.h are not stale vs domains.zig', () => {
    // Regenerate into memory and compare with what is checked in. A generated
    // file that drifts from its source is worse than a hand-written one,
    // because everybody trusts the header comment that says not to edit it.
    const out = execFileSync('zig', ['build', 'gen-domains'], {
      cwd: `${root}tools/fleet-zig`,
      encoding: 'utf-8',
      env: { ...process.env },
    });
    const [header, ts] = out.split('\n// ---- domains.ts ----\n');
    expect(readFileSync(`${root}components/cell-mesh/include/cell_domains.h`, 'utf-8').trim())
      .toBe(header.trim());
    expect(readFileSync(`${root}tools/domains.ts`, 'utf-8').trim()).toBe(ts.trim());
  }, 120_000);

  test("cell-codec's inlined control flag matches the generated table", () => {
    // cell-codec.ts inlines the value to avoid an import cycle. That is only
    // safe if something checks it.
    const src = readFileSync(`${root}tools/x402-bridge/cell-codec.ts`, 'utf-8');
    const m = src.match(/const DOMAIN_MESH_CONTROL = (0x[0-9a-f]+);/);
    expect(m).not.toBeNull();
    expect(Number(m![1])).toBe(DOMAIN.meshControl);
  });

  test('domainName round-trips every allocated flag', () => {
    for (const [name, flag] of Object.entries(DOMAIN)) {
      // fleetDevice and meshRelay are the same value by design, so the lookup
      // returns whichever is declared first — assert the VALUE round-trips.
      expect(DOMAIN[domainName(flag) as keyof typeof DOMAIN]).toBe(flag);
      expect(typeof name).toBe('string');
    }
  });
});
