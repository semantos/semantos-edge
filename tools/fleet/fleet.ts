/**
 * fleet.ts — the identity control plane for a device fleet.
 *
 * The split this file exists to hold:
 *
 *   Plexus is the control plane. It runs off-device, holds the operator root,
 *   derives every zone and unit, and can rebuild the whole hierarchy from a
 *   recipe if the provisioning server is lost.
 *
 *   semantos-edge is the device runtime. It is unchanged. A device still
 *   installs a 66-byte `cellmesh.capability.v0` cert into `cm_cap_table_t` and
 *   still verifies it against the operator public key it was flashed with.
 *
 * The seam between them is one 33-byte compressed public key. No Plexus code
 * runs on the MCU, no BEEF crosses the boundary, and no device is ever handed a
 * private key — which is the same rule the mesh already follows, reached from
 * the other side.
 *
 * What this buys over the bridge's previous relay-key derivation:
 *
 *   - a unit's key is reproducible from the operator root alone, so losing the
 *     provisioning database costs an afternoon rather than a fleet;
 *   - a unit's position under its zone is monotonic and recorded, so "slot 3 in
 *     the north depot" is a cryptographic fact rather than a spreadsheet row;
 *   - decommissioning burns the slot, so the replacement unit cannot be issued
 *     the key the returned unit had.
 */

import {
  buildCapabilityCertPayload,
  certHash,
  CAP_ROUTE_FWD_V1,
  CAPABILITY_V0_TYPE,
} from "../x402-bridge/capability-cert.js";
import { mintCell } from "../x402-bridge/cell-codec.js";
import type {
  CompressedPubKey,
  FleetDeriver,
  FleetNode,
} from "./deriver.js";

/** Slot names. `resourceId` names the KIND of slot; the index names which one. */
export const SLOT = {
  zone: "zone",
  device: "device",
} as const;

/** `UINT64_MAX` — what the firmware reads as "no expiry", until it has an RTC. */
export const NO_EXPIRY = 0xffffffffffffffffn;

/** The provisioning packet for one unit: everything that goes to the device. */
export interface DeviceProvision {
  node: FleetNode;
  /** 16-byte channel the cert authorises this unit on. */
  channelId: Uint8Array;
  /** The 66-byte `cellmesh.capability.v0` payload, exactly as `cm_cap_install` reads it. */
  certPayload: Uint8Array;
  /** SHA-256 of the payload — the BRC-108 binding carried in every commitment. */
  certHash: Uint8Array;
  /** The full 1 KB cell the device receives over the radio. */
  certCell: Uint8Array;
  /** Operator signature over the cell, raw r||s. */
  certSig: Uint8Array;
}

export interface FleetConfig {
  deriver: FleetDeriver;
  /** Absolute expiry stamped into every cert. Defaults to no expiry. */
  defaultExpiryMs?: bigint;
}

/**
 * Derive a stable 16-byte channel id for a unit from its certificate id.
 *
 * The firmware keys its cert table on (channel_id, route_type), so the channel
 * has to be reproducible from the identity rather than allocated and remembered
 * — otherwise a rebuilt fleet would re-provision every unit onto a channel the
 * unit does not answer on.
 */
export const channelIdFor = (certId: string): Uint8Array =>
  new Uint8Array(Buffer.from(certId, "hex").subarray(0, 16));

export class Fleet {
  private readonly deriver: FleetDeriver;
  private readonly defaultExpiryMs: bigint;

  constructor(config: FleetConfig) {
    this.deriver = config.deriver;
    this.defaultExpiryMs = config.defaultExpiryMs ?? NO_EXPIRY;
  }

  /** The key every device in this fleet is flashed with as its trust anchor. */
  async operatorPublicKey(): Promise<CompressedPubKey> {
    return this.deriver.operatorPublicKey();
  }

  /** Create a site, depot, or any other grouping of units. */
  async addZone(label: string): Promise<FleetNode> {
    const rootCertId = await this.deriver.rootCertId();
    return this.deriver.derive(rootCertId, SLOT.zone, label);
  }

  /**
   * Provision one unit into a zone and build everything it needs to be trusted.
   *
   * Returns public material only. The unit's private key is never derived here
   * and could not be: the operator root that would produce it stays in the
   * deriver, and the device has no use for it — it verifies and acts.
   */
  async addDevice(
    zone: FleetNode,
    label: string,
    expiryMs?: bigint,
  ): Promise<DeviceProvision> {
    const node = await this.deriver.derive(zone.certId, SLOT.device, label);
    return this.issueCert(node, expiryMs ?? this.defaultExpiryMs);
  }

  /**
   * Retire a unit's slot so its position is never reissued.
   *
   * Burning is what makes the retirement bite: the next unit into this zone
   * derives past the burned index, so it cannot be handed the key the returned
   * unit held. What this does NOT do is reach the returned unit — its cert
   * stays installed in whatever hardware still has it until the cert expires.
   * Cutting off a unit that is still powered and in range is the expiry and
   * metering path's job, not this one's.
   *
   * @returns the index the next unit provisioned into this zone will occupy
   */
  async decommission(zone: FleetNode): Promise<number> {
    return this.deriver.burnSlot(zone.certId, SLOT.device);
  }

  /** Re-issue a cert for an existing unit — a renewal, not a new identity. */
  async issueCert(
    node: FleetNode,
    expiryMs: bigint = this.defaultExpiryMs,
    validFromMs: bigint = BigInt(Date.now()),
  ): Promise<DeviceProvision> {
    if (node.publicKey.length !== 33) {
      throw new Error(
        `device public key must be 33 compressed bytes, got ${node.publicKey.length}`,
      );
    }
    const channelId = channelIdFor(node.certId);
    const certPayload = buildCapabilityCertPayload(
      node.publicKey,
      channelId,
      expiryMs,
      CAP_ROUTE_FWD_V1,
      validFromMs,
    );
    const operatorPk = await this.deriver.operatorPublicKey();
    const certCell = mintCell(
      CAPABILITY_V0_TYPE,
      certPayload,
      operatorPk.subarray(0, 16),
      validFromMs,
    );
    const certSig = await this.deriver.signAsOperator(certCell);
    return {
      node,
      channelId,
      certPayload,
      certHash: certHash(certPayload),
      certCell,
      certSig,
    };
  }

  async close(): Promise<void> {
    await this.deriver.close();
  }
}
