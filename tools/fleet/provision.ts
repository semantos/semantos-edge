/**
 * provision.ts — walk a device fleet's whole identity lifecycle.
 *
 *   bun run fleet:demo
 *
 * Provisions two zones, issues certs, decommissions a unit and replaces it,
 * then throws the control plane away and rebuilds the fleet from the operator
 * root to show the surviving units' certs still match.
 *
 * Everything printed is real: real BRC-42 derivation, real secp256k1 public
 * keys, real signatures over real 1 KB cells. What is NOT here is a device —
 * flashing and radio delivery are the x402 bridge's job. This is the control
 * plane that decides who a device is.
 */

import { PublicKey, Signature, BigNumber } from "@bsv/sdk";
import { Fleet, type DeviceProvision } from "./fleet.js";
import { openPlexusDeriver } from "./plexus-deriver.js";

const hex = (b: Uint8Array, n = b.length): string =>
  Buffer.from(b.subarray(0, n)).toString("hex");

const rule = (title: string): void => {
  console.log(`\n\x1b[1m${title}\x1b[0m`);
  console.log("─".repeat(72));
};

const showUnit = (u: DeviceProvision): void => {
  console.log(`  ${u.node.label.padEnd(24)} slot ${u.node.index}`);
  console.log(`    path       ${u.node.derivationPath}`);
  console.log(`    pubkey     ${hex(u.node.publicKey)}`);
  console.log(`    channel    ${hex(u.channelId)}`);
  console.log(`    cert_hash  ${hex(u.certHash)}`);
};

const ROOT_EMAIL = process.env.FLEET_ROOT_EMAIL ?? "operator@fleet.example";
const ROOT_SALT = process.env.FLEET_ROOT_SALT ?? "demo-fleet-salt";

const openFleet = async (): Promise<Fleet> =>
  new Fleet({
    deriver: await openPlexusDeriver({
      rootEmail: ROOT_EMAIL,
      rootSalt: ROOT_SALT,
    }),
  });

const main = async (): Promise<void> => {
  console.log("\n\x1b[1mFleet identity — Plexus control plane, semantos-edge devices\x1b[0m");
  console.log(`operator universe: ${ROOT_EMAIL}`);

  const fleet = await openFleet();
  const anchor = await fleet.operatorPublicKey();

  rule("1. Trust anchor");
  console.log("  Flash this into every unit. It is the key the firmware checks");
  console.log("  each capability cert against — s_wallet_pubkey in main.c.");
  console.log(`\n    operator pubkey  ${hex(anchor)}`);

  rule("2. Provision two zones");
  const north = await fleet.addZone("North Depot");
  const south = await fleet.addZone("South Depot");
  for (const z of [north, south]) {
    console.log(`  ${z.label.padEnd(24)} slot ${z.index}   ${z.derivationPath}`);
  }

  rule("3. Provision units");
  const units: DeviceProvision[] = [];
  for (const [zone, labels] of [
    [north, ["cold-chain-01", "cold-chain-02"]],
    [south, ["gate-controller-01"]],
  ] as const) {
    console.log(`\n  ${zone.label}`);
    for (const label of labels) {
      const u = await fleet.addDevice(zone, label);
      units.push(u);
      showUnit(u);
    }
  }

  rule("4. What actually goes to a device");
  const sample = units[0]!;
  console.log("  A 66-byte cellmesh.capability.v0 payload inside a signed 1 KB cell.");
  console.log("  cm_cap_install reads the payload; cm_sig_verify checks the signature");
  console.log("  against the anchor above. No private key crosses this line.\n");
  console.log(`    payload (66B)  ${hex(sample.certPayload)}`);
  console.log(`    cell           ${sample.certCell.length} bytes`);
  console.log(`    signature      ${hex(sample.certSig, 16)}… (${sample.certSig.length}B raw r||s)`);

  const pub = PublicKey.fromString(hex(anchor));
  const sig = new Signature(
    new BigNumber(hex(sample.certSig.subarray(0, 32)), 16),
    new BigNumber(hex(sample.certSig.subarray(32)), 16),
  );
  const good = pub.verify(Array.from(sample.certCell), sig);
  const tampered = new Uint8Array(sample.certCell);
  tampered[900] ^= 0x01;
  const bad = pub.verify(Array.from(tampered), sig);
  console.log(`\n    verifies against anchor          ${good ? "\x1b[32mACCEPT\x1b[0m" : "\x1b[31mREJECT\x1b[0m"}`);
  console.log(`    same cell, one byte flipped      ${bad ? "\x1b[31mACCEPT\x1b[0m" : "\x1b[32mREJECT\x1b[0m"}`);

  rule("5. Decommission and replace");
  const returned = units[0]!;
  console.log(`  ${returned.node.label} is returned from the field. Burn its slot:`);
  const mark = await fleet.decommission(north);
  console.log(`    burned slot ${mark - 1}, next unit receives slot ${mark}`);
  const replacement = await fleet.addDevice(north, "cold-chain-01-rma");
  console.log();
  showUnit(replacement);
  console.log(
    `\n    replacement key differs from the returned unit's  ${
      hex(replacement.node.publicKey) !== hex(returned.node.publicKey)
        ? "\x1b[32myes\x1b[0m"
        : "\x1b[31mno\x1b[0m"
    }`,
  );
  console.log("    the returned unit's cert is NOT reachable from here — it stops");
  console.log("    working at expiry, or when the meter it drains runs out.");

  await fleet.close();

  rule("6. Lose the provisioning server, rebuild the fleet");
  console.log("  A brand new control plane that has never seen this fleet,");
  console.log("  holding nothing but the operator root.\n");
  const rebuilt = await openFleet();
  const northAgain = await rebuilt.addZone("North Depot");
  const first = await rebuilt.addDevice(northAgain, "cold-chain-01");
  const second = await rebuilt.addDevice(northAgain, "cold-chain-02");

  const match = (a: DeviceProvision, b: DeviceProvision): string =>
    hex(a.node.publicKey) === hex(b.node.publicKey)
      ? "\x1b[32mmatches\x1b[0m"
      : "\x1b[31mDIFFERS\x1b[0m";
  console.log(`    ${units[0]!.node.label.padEnd(22)} ${match(first, units[0]!)}`);
  console.log(`    ${units[1]!.node.label.padEnd(22)} ${match(second, units[1]!)}`);
  console.log("\n  The certs already installed on those boards still verify.");
  console.log("  Nothing had to be re-flashed.");
  await rebuilt.close();
  console.log();
};

main().catch((err) => {
  console.error(`\n\x1b[31mfleet demo failed:\x1b[0m ${(err as Error).message}\n`);
  process.exit(1);
});
