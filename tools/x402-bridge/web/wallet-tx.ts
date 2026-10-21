import { Utils } from '@bsv/sdk';

/**
 * The transaction a wallet's createAction returned, as hex, ancestry included.
 *
 * BRC-100 wallets return Atomic BEEF. The bridge broadcasts through ARCADE,
 * which needs the transaction in extended format: every input carries its
 * source output. Converting to raw hex would drop that and ARCADE would refuse
 * the payment, so the bytes go to the bridge exactly as the wallet gave them.
 * The bridge's parser reads Atomic BEEF, BEEF, EF and raw hex.
 */
export function walletTxHex(tx: number[] | Uint8Array): string {
  return Utils.toHex(Array.from(tx));
}
