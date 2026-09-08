/**
 * Ask the SDK whether it accepts a recipe the Zig plane produced.
 *
 *   zig build export-recipe > /tmp/zig-recipe.json
 *   node check-recipe-interop.mjs /tmp/zig-recipe.json
 *
 * The conformance suite proves Zig can CONSUME what the SDK emits. This is the
 * other direction, and it cannot live in the Zig test suite because the oracle
 * is a TypeScript function. A recovery format only helps if both sides read and
 * write it — a plane that can only import is a plane that cannot back anything up.
 *
 * Exits non-zero on any mismatch, so it is usable as a gate.
 */

import { readFileSync } from "node:fs";

const SDK =
  process.env.PLEXUS_SDK ??
  "/Users/toddprice/projects/repos/libs/plexus-sdk-ts/dist/index.js";
const { MemoryKeyStore } = await import(SDK);
const { reconstituteFromRecoveryExport } = await import(
  SDK.replace(/index\.js$/, "modules/recovery/reconstituteFromRecoveryExport.js"),
);

// Must match src/export_recipe.zig.
const EMAIL = "interop@fleet.example";
const SALT = "interop-salt-v1";
const EXPECTED_DEVICES = 3;
const EXPECTED_BURNS = 1;

const file = process.argv[2] ?? "/tmp/zig-recipe.json";
const payload = JSON.parse(readFileSync(file, "utf8"));

const store = new MemoryKeyStore();
const out = await reconstituteFromRecoveryExport({
  store,
  rootEmail: EMAIL,
  rootSalt: SALT,
  payload,
});

const zonePath = payload.tenantPaths.find((p) => p.steps.length === 1);
if (!zonePath) throw new Error("no depth-1 path in the recipe");
const nextZone = await store.incrementChildIndex(payload.certId, "zone", 6);
const nextDevice = await store.incrementChildIndex(zonePath.certId, "device", 6);

let failures = 0;
const check = (label, got, want) => {
  const ok = got === want;
  if (!ok) failures++;
  console.log(`  ${ok ? "ok  " : "FAIL"} ${label.padEnd(34)} got ${got}${ok ? "" : `, want ${want}`}`);
};

console.log("SDK <- Zig recovery recipe");
check("root certId round-trips", out.certId, payload.certId);
check("next zone index", nextZone, 1);
// The burn is the interesting one: it is a fact only the store knew, carried
// through the recipe as a mark above the paths and honoured by the other plane.
check("next device index (issued + burned)", nextDevice, EXPECTED_DEVICES + EXPECTED_BURNS);

if (failures > 0) {
  console.error(`\n${failures} check(s) failed\n`);
  process.exit(1);
}
console.log("\nthe SDK accepts a recipe this plane wrote, burns and all\n");
