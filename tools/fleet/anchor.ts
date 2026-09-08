/**
 * anchor.ts — print the fleet's trust anchor as a C array for the firmware.
 *
 *   bun run fleet:anchor
 *
 * A device trusts exactly one key: the `s_wallet_pubkey` compiled into main.c.
 * For a Plexus-derived fleet that key is the operator root's public half, so
 * this prints it in the form main.c wants, plus the hex the host tools use.
 *
 * ⚠ The default root here is a DEMO root, and its salt is in this repo. Anyone
 * who reads it can derive the operator private key and sign certs your boards
 * will accept — exactly like the `…0042` demo key it replaces. That is fine for
 * boards on a desk and is not fine for anything else. Set FLEET_ROOT_EMAIL and
 * FLEET_ROOT_SALT from somewhere private before flashing hardware you care about.
 */

import { openPlexusDeriver } from "./plexus-deriver.js";

const ROOT_EMAIL = process.env.FLEET_ROOT_EMAIL ?? "operator@fleet.example";
const ROOT_SALT = process.env.FLEET_ROOT_SALT ?? "demo-fleet-salt";
const IS_DEMO_ROOT =
  process.env.FLEET_ROOT_EMAIL === undefined &&
  process.env.FLEET_ROOT_SALT === undefined;

const main = async (): Promise<void> => {
  const deriver = await openPlexusDeriver({
    rootEmail: ROOT_EMAIL,
    rootSalt: ROOT_SALT,
  });
  const pk = await deriver.operatorPublicKey();
  await deriver.close();

  const hex = Buffer.from(pk).toString("hex");
  const rows: string[] = [];
  for (let i = 0; i < pk.length; i += 8) {
    rows.push(
      "    " +
        [...pk.subarray(i, i + 8)]
          .map((b) => `0x${b.toString(16).padStart(2, "0")},`)
          .join(" "),
    );
  }

  console.log(`\n// Fleet operator trust anchor — derived, not invented.`);
  console.log(`// universe: ${ROOT_EMAIL}`);
  console.log(`// pubkey  : ${hex}`);
  console.log(
    `static const uint8_t s_wallet_pubkey[CM_SIG_PUBKEY_COMPRESSED] = {`,
  );
  console.log(rows.join("\n"));
  console.log(`};\n`);
  console.log(`hex (for host tools): ${hex}`);

  if (IS_DEMO_ROOT) {
    console.log(
      `\n\x1b[33m⚠ demo root — its salt is committed to this repo, so the matching\n` +
        `  private key is public. Fine for a board on a desk, nothing else.\n` +
        `  Set FLEET_ROOT_EMAIL / FLEET_ROOT_SALT for real hardware.\x1b[0m`,
    );
  }
  console.log();
};

main().catch((err) => {
  console.error(`\nfleet anchor failed: ${(err as Error).message}\n`);
  process.exit(1);
});
