/**
 * hardware.ts — provision a unit and prove it on a real ESP32-C6.
 *
 *   bun run fleet:hw                                    # auto-discovers both boards
 *   bun run fleet:hw -- --inject /dev/cu.X --watch /dev/cu.Y
 *
 * Everything up to now was true off-device. This closes the loop: a
 * Plexus-derived device key goes into a 66-byte `cellmesh.capability.v0` cert,
 * the operator signs it, the frame goes down the wire, and the C6 verifies it
 * against the anchor compiled into its firmware and installs it into
 * `cm_cap_table_t`.
 *
 * Then the same cert with one byte flipped, which the board must refuse.
 *
 * Both boards need mesh_demo built with USE_FLEET_ANCHOR 1 and the anchor from
 * `bun run fleet:anchor` for the same root used here — otherwise every frame is
 * correctly rejected as signed by a key they do not trust.
 */

import { readdirSync, openSync, writeSync, closeSync } from "node:fs";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { spawnSync } from "node:child_process";
import { frameCell } from "../x402-bridge/serial-mesh.js";
import { PrivateKey } from "@bsv/sdk";
import { signCell } from "../x402-bridge/cell-codec.js";
import { Fleet, type DeviceProvision } from "./fleet.js";
import { openPlexusDeriver } from "./plexus-deriver.js";

const ROOT_EMAIL = process.env.FLEET_ROOT_EMAIL ?? "operator@fleet.example";
const ROOT_SALT = process.env.FLEET_ROOT_SALT ?? "demo-fleet-salt";

const hex = (b: Uint8Array, n = b.length): string =>
  Buffer.from(b.subarray(0, n)).toString("hex");
const sleep = (ms: number): Promise<void> =>
  new Promise((r) => setTimeout(r, ms));
const strip = (s: string): string => s.replace(/\x1b\[[0-9;]*m/g, "").trim();

/**
 * The C6's native-USB CDC renames on every reset, so never hardcode a port.
 *
 * Two boards are required, and the reason is in the firmware: with
 * DEMO_SCRIPT_ONLY the board you inject into does not process the cell itself.
 * It ack-blinks, then broadcasts it over ESP-NOW after DEMO_BROADCAST_DELAY_MS,
 * and the OTHER board is the one that verifies the signature and installs the
 * cert. So the proof needs a sender and a receiver — which is also the honest
 * shape, since it puts a real radio hop between the operator and the device.
 */
const discoverPorts = (): { inject: string; watch: string } => {
  const found = readdirSync("/dev")
    .filter((f) => /^cu\.usbmodem\d+$/.test(f))
    .sort()
    .map((f) => `/dev/${f}`);
  if (found.length < 2) {
    throw new Error(
      `need two C6 boards, found ${found.length} (${found.join(", ") || "none"}). ` +
        `One injects and broadcasts; the other verifies and installs. ` +
        `Their CDC names change on every reset, so they are discovered, not hardcoded.`,
    );
  }
  return { inject: found[0]!, watch: found[1]! };
};

class Board {
  private reader?: ChildProcessWithoutNullStreams;
  private buf = "";
  readonly lines: string[] = [];

  constructor(readonly port: string, opts: { read?: boolean } = {}) {
    spawnSync("stty", ["-f", port, "115200", "raw", "-echo"], {
      stdio: "ignore",
    });
    if (opts.read === false) return;
    this.reader = spawn("cat", [port]) as ChildProcessWithoutNullStreams;
    this.reader.stdout.on("data", (d: Buffer) => {
      this.buf += d.toString("utf8");
      let i: number;
      while ((i = this.buf.indexOf("\n")) >= 0) {
        const line = strip(this.buf.slice(0, i));
        this.buf = this.buf.slice(i + 1);
        if (line) this.lines.push(line);
      }
    });
  }

  /** Inject a framed cell, paced so the burst cannot outrun the RX ring. */
  async inject(cell: Uint8Array, sig: Uint8Array): Promise<void> {
    const frame = Buffer.from(frameCell(cell, sig));
    for (let attempt = 0; attempt < 2; attempt++) {
      const fd = openSync(this.port, "w");
      try {
        const CHUNK = 256;
        for (let off = 0; off < frame.length; off += CHUNK) {
          writeSync(fd, frame, off, Math.min(CHUNK, frame.length - off));
          await sleep(2);
        }
      } finally {
        closeSync(fd);
      }
      await sleep(400);
    }
  }

  /** Wait for a log line matching any of `needles`, or time out. */
  async await(needles: string[], timeoutMs = 12000): Promise<string | null> {
    const from = this.lines.length;
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      for (let i = from; i < this.lines.length; i++) {
        const line = this.lines[i]!;
        if (needles.some((n) => line.includes(n))) return line;
      }
      await sleep(100);
    }
    return null;
  }

  dispose(): void {
    this.reader?.kill();
  }
}

const rule = (title: string): void => {
  console.log(`\n\x1b[1m${title}\x1b[0m`);
  console.log("─".repeat(72));
};

const main = async (): Promise<void> => {
  const argInject = process.argv.indexOf("--inject");
  const argWatch = process.argv.indexOf("--watch");
  const auto = argInject >= 0 && argWatch >= 0 ? null : discoverPorts();
  const injectPort = argInject >= 0 ? process.argv[argInject + 1]! : auto!.inject;
  const watchPort = argWatch >= 0 ? process.argv[argWatch + 1]! : auto!.watch;

  console.log("\n\x1b[1mFleet identity on real silicon — ESP32-C6\x1b[0m");
  console.log(`inject → ${injectPort}   (relays over ESP-NOW)`);
  console.log(`watch  ← ${watchPort}   (verifies + installs)`);

  const fleet = new Fleet({
    deriver: await openPlexusDeriver({
      rootEmail: ROOT_EMAIL,
      rootSalt: ROOT_SALT,
    }),
  });
  const anchor = await fleet.operatorPublicKey();

  rule("1. Provision a unit off-device");
  const zone = await fleet.addZone("North Depot");
  const unit: DeviceProvision = await fleet.addDevice(zone, "cold-chain-01");
  console.log(`  operator anchor  ${hex(anchor)}`);
  console.log(`  device path      ${unit.node.derivationPath}`);
  console.log(`  device pubkey    ${hex(unit.node.publicKey)}`);
  console.log(`  channel          ${hex(unit.channelId)}`);
  console.log(`  cert payload     ${unit.certPayload.length} bytes`);

  // Write-only to the sender; the reader holds the watcher. Reading and
  // writing the same CDC endpoint fights over it, which is why the repo's own
  // bridge keeps injectPort and ackPort separate.
  const sender = new Board(injectPort, { read: false });
  const board = new Board(watchPort);
  let failures = 0;
  try {
    await sleep(600);

    rule("2. Inject the cert — the board must accept and install it");
    await sender.inject(unit.certCell, unit.certSig);
    const ok = await board.await([
      "CAP cert installed",
      "CAP cert install FAILED",
      "signature INVALID",
    ]);
    console.log(`  board said: ${ok ?? "(nothing — timed out)"}`);
    if (ok?.includes("CAP cert installed")) {
      const edge = hex(unit.node.publicKey, 4);
      const ch = hex(unit.channelId, 4);
      const echoed = ok.includes(edge) && ok.includes(ch);
      console.log(
        `  \x1b[32mACCEPTED\x1b[0m — and it echoed back ch=${ch}… edge=${edge}… ${
          echoed ? "\x1b[32m(matches what we derived)\x1b[0m" : "\x1b[31m(MISMATCH)\x1b[0m"
        }`,
      );
      if (!echoed) failures++;
    } else {
      console.log(
        "  \x1b[31mNOT ACCEPTED\x1b[0m — is mesh_demo built with USE_FLEET_ANCHOR 1\n" +
          "  and the anchor from `bun run fleet:anchor` for this same root?",
      );
      failures++;
    }

    rule("3. Flip one byte — the board must refuse it");
    const tampered = new Uint8Array(unit.certCell);
    tampered[900] ^= 0x01;
    await sender.inject(tampered, unit.certSig);
    const bad = await board.await([
      "signature INVALID",
      "CAP cert installed",
      "CAP cert install FAILED",
    ]);
    console.log(`  board said: ${bad ?? "(nothing — timed out)"}`);
    if (bad?.includes("signature INVALID")) {
      console.log("  \x1b[32mREJECTED\x1b[0m — the tamper did not survive cm_sig_verify");
    } else {
      console.log("  \x1b[31mNOT REJECTED\x1b[0m — a tampered cert was accepted");
      failures++;
    }

    rule("4. Sign with the OLD demo key — the board must refuse that too");
    // The control that makes step 2 mean anything. If the board accepted a cert
    // signed by the key it used to trust, "we changed the anchor" would be
    // unproven — it might simply be accepting whatever arrives. This is the
    // same cert bytes, signed by sign-cell-deck's ...0042 key.
    const legacyKey = new PrivateKey(
      "0000000000000000000000000000000000000000000000000000000000000042",
      16,
    );
    const legacySig = signCell(unit.certCell, legacyKey);
    console.log(`  legacy signer pubkey  ${legacyKey.toPublicKey().toString()}`);
    await sender.inject(unit.certCell, legacySig);
    const legacy = await board.await([
      "signature INVALID",
      "CAP cert installed",
      "CAP cert install FAILED",
    ]);
    console.log(`  board said: ${legacy ?? "(nothing — timed out)"}`);
    if (legacy?.includes("signature INVALID")) {
      console.log(
        "  \x1b[32mREJECTED\x1b[0m — the board trusts the fleet root, not the key it shipped with",
      );
    } else {
      console.log(
        "  \x1b[31mNOT REJECTED\x1b[0m — the anchor did not actually change",
      );
      failures++;
    }

    rule("Result");
    if (failures === 0) {
      console.log(
        "  A Plexus-derived device identity was verified and installed by an\n" +
          "  ESP32-C6 over a real radio hop. A tampered copy was refused, and so\n" +
          "  was the same cert signed by the key the firmware used to trust — so\n" +
          "  the board is checking against the fleet root specifically, not\n" +
          "  accepting whatever arrives. It holds no private key throughout.\n",
      );
    } else {
      console.log(`  \x1b[31m${failures} step(s) did not behave as required.\x1b[0m\n`);
    }
  } finally {
    board.dispose();
    sender.dispose();
    await fleet.close();
  }
  process.exit(failures === 0 ? 0 : 1);
};

main().catch((err) => {
  console.error(`\n\x1b[31mfleet hardware run failed:\x1b[0m ${(err as Error).message}\n`);
  process.exit(1);
});
