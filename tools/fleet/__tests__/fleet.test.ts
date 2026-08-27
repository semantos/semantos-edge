/**
 * Fleet identity tests.
 *
 * These run against the real Plexus SDK when it is present, because the whole
 * point is that the derivation is real. If it is missing the suite skips with a
 * message rather than silently passing on a stub — a green run has to mean the
 * derivation actually happened.
 */

import { describe, it, expect } from "bun:test";
import { PublicKey, Signature, BigNumber } from "@bsv/sdk";
import { Fleet, channelIdFor, NO_EXPIRY } from "../fleet.js";
import { openPlexusDeriver } from "../plexus-deriver.js";
import type { FleetDeriver, FleetRecipe } from "../deriver.js";

// Offsets are duplicated from components/cell-mesh/include/cell_capability.h.
// If the firmware layout moves, these tests are what notices.
const CM_CAP_PAYLOAD_BYTES = 66;
const CM_CAP_OFF_EDGE_PUBKEY = 0;
const CM_CAP_OFF_CHANNEL_ID = 33;
const CM_CAP_OFF_EXPIRY_MS = 49;
const CM_CAP_OFF_ROUTE_TYPE = 57;
const CM_CAP_OFF_VALID_FROM_MS = 58;
const CM_CAP_ROUTE_FWD_V1 = 0x01;

const ROOT_EMAIL = "operator@fleet.example";
const ROOT_SALT = "fleet-test-salt";

const readU64LE = (b: Uint8Array, o: number): bigint =>
  new DataView(b.buffer, b.byteOffset, b.byteLength).getBigUint64(o, true);

const openFleet = async (
  salt = ROOT_SALT,
): Promise<{ fleet: Fleet; deriver: FleetDeriver & { recipe(): FleetRecipe } }> => {
  const deriver = await openPlexusDeriver({
    rootEmail: ROOT_EMAIL,
    rootSalt: salt,
  });
  return { fleet: new Fleet({ deriver }), deriver };
};

// Probed at module load, not in beforeAll, so the SDK-dependent blocks can be
// registered as SKIPPED rather than running and passing on nothing. A suite
// that reports "pass" when it never exercised the derivation is worse than a
// red one — it reads as proof and is not.
const available = await (async (): Promise<boolean> => {
  try {
    const { fleet } = await openFleet();
    await fleet.close();
    return true;
  } catch {
    console.warn(
      "[fleet] Plexus SDK not found — set PLEXUS_SDK to its dist/index.js. " +
        "The derivation tests below are SKIPPED, not passing.",
    );
    return false;
  }
})();

const withSdk = describe.skipIf(!available);

withSdk("fleet identity — provisioning", () => {
  it("derives a device whose public key is a real compressed secp256k1 point", async () => {
    const { fleet } = await openFleet();
    const zone = await fleet.addZone("North Depot");
    const unit = await fleet.addDevice(zone, "sensor-01");

    expect(unit.node.publicKey.length).toBe(33);
    expect([0x02, 0x03]).toContain(unit.node.publicKey[0]);
    // Parses as a curve point, so the firmware's cm_sig_pubkey_load will too.
    const parsed = PublicKey.fromString(
      Buffer.from(unit.node.publicKey).toString("hex"),
    );
    expect(parsed.toString()).toBe(
      Buffer.from(unit.node.publicKey).toString("hex"),
    );
    // Position is the identity: zone 0, device 0.
    expect(zone.index).toBe(0);
    expect(unit.node.index).toBe(0);
    expect(unit.node.derivationPath).toBe("root/zone:6:0/device:6:0");
    await fleet.close();
  });

  it("builds a cert payload the firmware's cm_cap_install can read", async () => {
    const { fleet } = await openFleet();
    const zone = await fleet.addZone("North Depot");
    const unit = await fleet.addDevice(zone, "sensor-01");
    const p = unit.certPayload;

    expect(p.length).toBe(CM_CAP_PAYLOAD_BYTES);
    expect(
      p.subarray(CM_CAP_OFF_EDGE_PUBKEY, CM_CAP_OFF_EDGE_PUBKEY + 33),
    ).toEqual(unit.node.publicKey);
    expect(
      p.subarray(CM_CAP_OFF_CHANNEL_ID, CM_CAP_OFF_CHANNEL_ID + 16),
    ).toEqual(unit.channelId);
    expect(readU64LE(p, CM_CAP_OFF_EXPIRY_MS)).toBe(NO_EXPIRY);
    expect(p[CM_CAP_OFF_ROUTE_TYPE]).toBe(CM_CAP_ROUTE_FWD_V1);
    expect(readU64LE(p, CM_CAP_OFF_VALID_FROM_MS)).toBeGreaterThan(0n);
    await fleet.close();
  });

  it("signs the cert cell with the operator key, verifiable against the anchor", async () => {
    const { fleet } = await openFleet();
    const zone = await fleet.addZone("North Depot");
    const unit = await fleet.addDevice(zone, "sensor-01");

    const anchor = await fleet.operatorPublicKey();
    expect(anchor.length).toBe(33);
    // The device verifies exactly this: raw r||s over the cell, against the
    // operator pubkey it was flashed with.
    expect(unit.certSig.length).toBe(64);
    const pub = PublicKey.fromString(Buffer.from(anchor).toString("hex"));
    const sig = new Signature(
      new BigNumber(Buffer.from(unit.certSig.subarray(0, 32)).toString("hex"), 16),
      new BigNumber(Buffer.from(unit.certSig.subarray(32)).toString("hex"), 16),
    );
    expect(pub.verify(Array.from(unit.certCell), sig)).toBe(true);

    // A tampered cell must not verify — the device rejects it the same way.
    const tampered = new Uint8Array(unit.certCell);
    tampered[900] ^= 0x01;
    expect(pub.verify(Array.from(tampered), sig)).toBe(false);
    await fleet.close();
  });

  it("gives each unit a channel id derived from its own identity", async () => {
    const { fleet } = await openFleet();
    const zone = await fleet.addZone("North Depot");
    const a = await fleet.addDevice(zone, "sensor-01");
    const b = await fleet.addDevice(zone, "sensor-02");

    expect(a.channelId.length).toBe(16);
    expect(a.channelId).not.toEqual(b.channelId);
    expect(a.channelId).toEqual(channelIdFor(a.node.certId));
    await fleet.close();
  });
});

withSdk("fleet identity — no private key reaches a device", () => {
  it("exposes nothing private on a provisioning packet", async () => {
    const { fleet } = await openFleet();
    const zone = await fleet.addZone("North Depot");
    const unit = await fleet.addDevice(zone, "sensor-01");

    // Everything the device receives, serialized and scanned.
    const json = JSON.stringify(unit, (_k, v) =>
      v instanceof Uint8Array ? Buffer.from(v).toString("hex") : v,
    );
    expect(json).not.toMatch(/priv|secret|seed|salt/i);

    // And the strongest form: the operator's own private scalar must not appear
    // anywhere in the bytes that go out.
    const sdk = await import(
      process.env.PLEXUS_SDK ??
        "/Users/toddprice/projects/repos/libs/plexus-sdk-ts/dist/index.js"
    );
    const operatorPriv = sdk
      .derivePrivateKeyAtPath(ROOT_EMAIL, ROOT_SALT, "root")
      .toString();
    expect(operatorPriv.length).toBeGreaterThan(0);
    expect(json.toLowerCase()).not.toContain(operatorPriv.toLowerCase());
    await fleet.close();
  });
});

withSdk("fleet identity — decommission burns the slot", () => {
  it("gives the replacement unit a different key, and never reissues the burned index", async () => {
    const { fleet } = await openFleet();
    const zone = await fleet.addZone("North Depot");
    const returned = await fleet.addDevice(zone, "sensor-01");
    expect(returned.node.index).toBe(0);

    const mark = await fleet.decommission(zone);
    expect(mark).toBe(2); // index 1 burned

    const replacement = await fleet.addDevice(zone, "sensor-01-replacement");
    expect(replacement.node.index).toBe(2);
    expect(replacement.node.publicKey).not.toEqual(returned.node.publicKey);
    expect(replacement.certPayload).not.toEqual(returned.certPayload);
    await fleet.close();
  });

  it("keeps zones independent — retiring one does not disturb another", async () => {
    const { fleet } = await openFleet();
    const north = await fleet.addZone("North Depot");
    const south = await fleet.addZone("South Depot");
    await fleet.addDevice(north, "n-01");
    await fleet.decommission(north);

    const s = await fleet.addDevice(south, "s-01");
    expect(s.node.index).toBe(0);
    await fleet.close();
  });
});

withSdk("fleet identity — the fleet is recoverable", () => {
  it("re-derives identical device keys from the operator root alone", async () => {
    // Provision a fleet, record what the devices were flashed with, throw the
    // control plane away, and rebuild from the same root.
    const first = await openFleet("recover-salt");
    const zoneA = await first.fleet.addZone("North Depot");
    const unitsA = [
      await first.fleet.addDevice(zoneA, "sensor-01"),
      await first.fleet.addDevice(zoneA, "sensor-02"),
    ];
    const recipe = first.deriver.recipe();
    await first.fleet.close();

    const second = await openFleet("recover-salt");
    const zoneB = await second.fleet.addZone("North Depot");
    const unitsB = [
      await second.fleet.addDevice(zoneB, "sensor-01"),
      await second.fleet.addDevice(zoneB, "sensor-02"),
    ];

    expect(zoneB.publicKey).toEqual(zoneA.publicKey);
    expect(unitsB[0]!.node.publicKey).toEqual(unitsA[0]!.node.publicKey);
    expect(unitsB[1]!.node.publicKey).toEqual(unitsA[1]!.node.publicKey);
    // Which means the certs already installed on hardware still verify.
    expect(unitsB[0]!.channelId).toEqual(unitsA[0]!.channelId);

    // The recipe carries paths and ceilings, never key material.
    expect(recipe.schemaVersion).toBe("fleet-v1");
    expect(recipe.nodes.length).toBe(4); // root + zone + 2 devices
    expect(JSON.stringify(recipe)).not.toMatch(/priv|secret|seed/i);
    await second.fleet.close();
  });
});

describe("fleet identity — the cert layout tracks the firmware header", () => {
  // The offsets above are copied from C. Copies drift. This reads the header
  // itself, so if cell_capability.h moves a field the seam fails here rather
  // than on a board.
  it("matches components/cell-mesh/include/cell_capability.h", async () => {
    const header = await Bun.file(
      new URL("../../../components/cell-mesh/include/cell_capability.h", import.meta.url),
    ).text();
    const constant = (name: string): number => {
      const m = header.match(new RegExp(`#define\\s+${name}\\s+(0x[0-9a-fA-F]+|\\d+)u?`));
      if (!m) throw new Error(`${name} not found in cell_capability.h`);
      return Number(m[1]);
    };
    expect(constant("CM_CAP_PAYLOAD_BYTES")).toBe(CM_CAP_PAYLOAD_BYTES);
    expect(constant("CM_CAP_OFF_EDGE_PUBKEY")).toBe(CM_CAP_OFF_EDGE_PUBKEY);
    expect(constant("CM_CAP_OFF_CHANNEL_ID")).toBe(CM_CAP_OFF_CHANNEL_ID);
    expect(constant("CM_CAP_OFF_EXPIRY_MS")).toBe(CM_CAP_OFF_EXPIRY_MS);
    expect(constant("CM_CAP_OFF_ROUTE_TYPE")).toBe(CM_CAP_OFF_ROUTE_TYPE);
    expect(constant("CM_CAP_OFF_VALID_FROM_MS")).toBe(CM_CAP_OFF_VALID_FROM_MS);
    expect(constant("CM_CAP_ROUTE_FWD_V1")).toBe(CM_CAP_ROUTE_FWD_V1);
  });

  it("fits a zone's units inside the device-side cert table", async () => {
    // cm_cap_table_t is a static array. A fleet tool that hands one unit more
    // certs than it can hold is silently dropping authority, so surface the cap.
    const header = await Bun.file(
      new URL("../../../components/cell-mesh/include/cell_capability.h", import.meta.url),
    ).text();
    const max = Number(header.match(/#define\s+CM_CAP_TABLE_MAX\s+(\d+)u?/)![1]);
    expect(max).toBeGreaterThan(0);
    // One cert per unit per route type, so a unit is only ever near the cap if
    // it relays for several channels at once. Documented, not enforced here.
    expect(max).toBe(4);
  });
});
