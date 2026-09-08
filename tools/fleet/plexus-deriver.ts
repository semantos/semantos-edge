/**
 * plexus-deriver.ts — the Plexus implementation of the fleet deriver port.
 *
 * Replaces the ad-hoc key derivation the bridge used for relay keys
 * (`HMAC-SHA256(master_sk, "cell-routing-relay/" + channel_id)`, then
 * `child = (master + tweak) mod N`). That worked, but it derives into nowhere:
 * no recorded path, no index, no way to retire a position, and nothing to
 * rebuild from if the machine holding the master key is lost.
 *
 * Plexus gives the same shape a real BRC-42 derivation with three things the
 * HMAC tweak cannot have:
 *
 *   - a recorded derivation path, so any device's key is reproducible from the
 *     operator root alone;
 *   - a monotonic per-slot index, so a device's position IS its identity;
 *   - `rotateContext`, which burns a slot so a decommissioned unit's key is
 *     never handed to its replacement.
 *
 * The SDK is a private package, so it is imported dynamically from a path the
 * caller supplies. semantos-edge does not depend on it — a fleet operator who
 * has it points `PLEXUS_SDK` at it, and everything else in this repo builds and
 * runs without it.
 */

import type {
  CompressedPubKey,
  FleetDeriver,
  FleetNode,
  FleetRecipe,
} from "./deriver.js";

/** Structural children are derived under the child-creation domain (0x06). */
const CHILD_CREATION = 0x06;

/** Where the SDK lives, unless PLEXUS_SDK says otherwise. */
const DEFAULT_SDK =
  "/Users/toddprice/projects/repos/libs/plexus-sdk-ts/dist/index.js";

interface PlexusChild {
  certId: string;
  publicKey: string;
  childIndex: number;
  derivationPath: string;
}

interface PlexusSdk {
  PlexusClient: new (config: Record<string, unknown>) => PlexusClientLike;
  derivePrivateKeyAtPath: (
    rootEmail: string,
    rootSalt: string,
    path: string,
  ) => { sign: (msg: number[]) => { r: unknown; s: unknown } };
}

interface PlexusClientLike {
  registerIdentity(): Promise<{ certId: string; publicKey: string }>;
  deriveChild(
    parentCertId: string,
    resourceId: string,
    domainFlag: number,
  ): Promise<PlexusChild>;
  rotateContext(
    parentCertId: string,
    resourceId: string,
    domainFlag: number,
  ): Promise<number>;
  setNodeMetadata(certId: string, key: string, value: string): Promise<void>;
  close(): Promise<void>;
}

const hexToBytes = (hex: string): Uint8Array =>
  new Uint8Array(Buffer.from(hex, "hex"));

export interface PlexusDeriverConfig {
  /** The operator universe's PBKDF2 password slot. */
  rootEmail: string;
  /** The operator universe's PBKDF2 salt slot. Keep it off every device. */
  rootSalt: string;
  /** Absolute path to the built Plexus SDK. Defaults to PLEXUS_SDK. */
  sdkPath?: string;
  /** SQLite file for a persistent fleet, or omit for an in-memory one. */
  dbPath?: string;
}

/**
 * Stand up a fleet deriver over a Plexus universe.
 *
 * Registers the operator root if it does not exist yet, so calling this twice
 * against the same (rootEmail, rootSalt, dbPath) reopens the same fleet rather
 * than forking a second one.
 */
export const openPlexusDeriver = async (
  config: PlexusDeriverConfig,
): Promise<FleetDeriver & { recipe(): FleetRecipe }> => {
  const sdkPath = config.sdkPath ?? process.env.PLEXUS_SDK ?? DEFAULT_SDK;
  let sdk: PlexusSdk;
  try {
    sdk = (await import(sdkPath)) as unknown as PlexusSdk;
  } catch (err) {
    throw new Error(
      `could not load the Plexus SDK from ${sdkPath}. ` +
        `Build it (npx tsc -p tsconfig.build.json) and set PLEXUS_SDK to its dist/index.js. ` +
        `Cause: ${(err as Error).message}`,
    );
  }

  const client = new sdk.PlexusClient({
    ...(config.dbPath !== undefined
      ? { mode: "local", dbPath: config.dbPath }
      : { mode: "memory" }),
    rootEmail: config.rootEmail,
    rootSalt: config.rootSalt,
    broadcaster: "none",
  });

  const root = await client.registerIdentity();

  // Mirrors what the SDK records, so a recipe can be written without reaching
  // into the client's private store.
  const nodes: FleetRecipe["nodes"] = [
    {
      certId: root.certId,
      parentCertId: null,
      resourceId: "root",
      domainFlag: CHILD_CREATION,
      index: 0,
      label: "operator root",
    },
  ];
  const ceilings = new Map<string, FleetRecipe["ceilings"][number]>();
  const bumpCeiling = (
    parentCertId: string,
    resourceId: string,
    nextIndex: number,
    domainFlag: number = CHILD_CREATION,
  ): void => {
    const key = `${parentCertId}|${resourceId}|${domainFlag}`;
    const seen = ceilings.get(key);
    if (!seen || nextIndex > seen.nextIndex) {
      ceilings.set(key, {
        parentCertId,
        resourceId,
        domainFlag,
        nextIndex,
      });
    }
  };

  return {
    async rootCertId(): Promise<string> {
      return root.certId;
    },

    async operatorPublicKey(): Promise<CompressedPubKey> {
      return hexToBytes(root.publicKey);
    },

    async derive(
      parentCertId: string,
      resourceId: string,
      label: string,
      domainFlag: number = CHILD_CREATION,
    ): Promise<FleetNode> {
      const child = await client.deriveChild(
        parentCertId,
        resourceId,
        domainFlag,
      );
      await client.setNodeMetadata(child.certId, "label", label);
      nodes.push({
        certId: child.certId,
        parentCertId,
        resourceId,
        domainFlag,
        index: child.childIndex,
        label,
      });
      bumpCeiling(parentCertId, resourceId, child.childIndex + 1, domainFlag);
      return {
        certId: child.certId,
        publicKey: hexToBytes(child.publicKey),
        derivationPath: child.derivationPath,
        index: child.childIndex,
        label,
      };
    },

    async burnSlot(parentCertId: string, resourceId: string, domainFlag: number = CHILD_CREATION): Promise<number> {
      const mark = await client.rotateContext(
        parentCertId,
        resourceId,
        domainFlag,
      );
      bumpCeiling(parentCertId, resourceId, mark, domainFlag);
      return mark;
    },

    async signAsOperator(cell: Uint8Array): Promise<Uint8Array> {
      // The operator's key is materialised here, used, and dropped — it is
      // never returned, so no caller of this port can leak it toward a device.
      const key = sdk.derivePrivateKeyAtPath(
        config.rootEmail,
        config.rootSalt,
        "root",
      );
      const sig = key.sign(Array.from(cell)) as {
        r: { toArray: (e: string, n: number) => number[] };
        s: { toArray: (e: string, n: number) => number[] };
      };
      return new Uint8Array([
        ...sig.r.toArray("be", 32),
        ...sig.s.toArray("be", 32),
      ]);
    },

    recipe(): FleetRecipe {
      return {
        schemaVersion: "fleet-v1",
        rootCertId: root.certId,
        nodes: nodes.map((n) => ({ ...n })),
        ceilings: [...ceilings.values()].map((c) => ({ ...c })),
      };
    },

    async close(): Promise<void> {
      await client.close();
    },
  };
};
