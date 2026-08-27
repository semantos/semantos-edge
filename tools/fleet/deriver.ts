/**
 * deriver.ts — the port a fleet's identity hangs off.
 *
 * Devices verify and act; wallets sign. That rule decides the shape of this
 * interface: every method either returns PUBLIC material or performs a
 * signature on the operator's behalf. No method returns a private key, and the
 * only bytes any implementation is allowed to hand toward a device are a
 * 33-byte compressed public key and a signature over a cell.
 *
 * The port exists so the root's custody is swappable without the fleet logic
 * knowing. `PlexusDeriver` keeps the root in an operator-side Plexus universe;
 * a future implementation could keep it behind an HSM or a k-of-n split, and
 * `FleetIdentity` would not change. Tests inject a deterministic stub.
 */

/** A compressed secp256k1 point — 33 bytes. What the firmware calls a pubkey. */
export type CompressedPubKey = Uint8Array;

/** One node of the fleet hierarchy, as seen from the control plane. */
export interface FleetNode {
  /** BRC-52 certificate id — the node's identity in the operator's universe. */
  certId: string;
  /** 33-byte compressed public key. The only key material a device ever sees. */
  publicKey: CompressedPubKey;
  /** The derivation that reproduces this node from the operator root. */
  derivationPath: string;
  /** Monotonic position under its parent. Position IS the identity here. */
  index: number;
  /** Human label. Metadata hung off the side; never part of the derivation. */
  label: string;
}

/**
 * The recipe that rebuilds a fleet without the operator's database.
 *
 * Derivation paths and slot high-water marks only — never key material. This is
 * what makes a fleet recoverable: lose the provisioning server and the whole
 * device hierarchy re-derives from the operator root plus this.
 */
export interface FleetRecipe {
  schemaVersion: "fleet-v1";
  /** The operator universe's root certificate id. */
  rootCertId: string;
  /** Every node's path, so the tree can be replayed. */
  nodes: Array<{
    certId: string;
    parentCertId: string | null;
    resourceId: string;
    domainFlag: number;
    index: number;
    label: string;
  }>;
  /** Per-slot next-free index, so a rebuilt fleet never reissues a live key. */
  ceilings: Array<{
    parentCertId: string;
    resourceId: string;
    domainFlag: number;
    nextIndex: number;
  }>;
}

export interface FleetDeriver {
  /**
   * The operator's trust anchor: the public key devices are flashed with and
   * verify every cert against. Its private half stays in the control plane.
   */
  operatorPublicKey(): Promise<CompressedPubKey>;

  /** Derive the next child at a slot, returning public material only. */
  derive(
    parentCertId: string,
    resourceId: string,
    label: string,
  ): Promise<FleetNode>;

  /**
   * Burn a slot's next free index so the position is never reissued.
   *
   * @returns the new high-water mark — the index the next `derive` will receive
   */
  burnSlot(parentCertId: string, resourceId: string): Promise<number>;

  /**
   * Sign a cell as the operator. The signing key is never returned, so a fleet
   * tool can authorise a device without ever holding the key that does it.
   */
  signAsOperator(cell: Uint8Array): Promise<Uint8Array>;

  /** The root node of the operator's universe. */
  rootCertId(): Promise<string>;

  close(): Promise<void>;
}
