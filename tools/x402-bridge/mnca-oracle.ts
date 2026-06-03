/**
 * mnca-oracle.ts — MNCA transition validator + oracle signer.
 *
 * POST /validate-mnca-transition
 *   Body: { prev_state: string (hex), next_state: string (hex),
 *            rule_id: string (4-char ASCII), x: number, y: number, gen: number }
 *   Response: { valid: boolean, oracle_sig: string (hex) | null, message: string }
 *
 * The oracle re-runs the MNCA rule in TypeScript (identical integer
 * arithmetic to cell_mnca.c) and signs { x, y, gen, next_hash } with
 * the bridge wallet key if the transition is valid.
 *
 * This is the "brain oracle" from the MNCA incentives arc:
 *   device → tile.v0 cell → quorum → channel_settle.v0
 *                                   → POST /validate-mnca-transition
 *                                   → oracle_sig included in settle payload
 *
 * The oracle sig can be verified by any downstream node holding the
 * bridge's wallet pubkey — no on-device key needed.
 */

import { createHmac } from 'node:crypto';
import { PrivateKey } from '@bsv/sdk';

// ── Rule parameters (match CM_MNCA_DEFAULT_RULE in cell_mnca.c) ──────────────
interface MncaRule {
  aliveThreshold: number;   // cell >= this is "alive"
  innerRadius: number;      // Moore neighbourhood radius
  birthLo: number;
  birthHi: number;
  surviveLo: number;
  surviveHi: number;
  growStep: number;         // +growStep on birth/survive (saturate 255)
  decayStep: number;        // -decayStep on death (saturate 0)
  ruleId: string;           // 4-char ASCII
}

const DEFAULT_RULE: MncaRule = {
  aliveThreshold: 128,
  innerRadius:    1,
  birthLo:        3,
  birthHi:        3,
  surviveLo:      2,
  surviveHi:      3,
  growStep:       64,
  decayStep:      64,
  ruleId:         'MNCA',
};

// ── MNCA step (mirrors cm_mnca_step in cell_mnca.c) ──────────────────────────
const TILE_W = 8;
const TILE_H = 8;
const TILE_CELLS = TILE_W * TILE_H;

function clampU8(v: number): number {
  return Math.max(0, Math.min(255, v));
}

function stepTile(cur: Uint8Array, rule: MncaRule = DEFAULT_RULE): Uint8Array {
  const next = new Uint8Array(TILE_CELLS);
  for (let row = 0; row < TILE_H; row++) {
    for (let col = 0; col < TILE_W; col++) {
      let aliveCount = 0;
      for (let dr = -rule.innerRadius; dr <= rule.innerRadius; dr++) {
        for (let dc = -rule.innerRadius; dc <= rule.innerRadius; dc++) {
          if (dr === 0 && dc === 0) continue;
          const r = row + dr;
          const c = col + dc;
          if (r < 0 || r >= TILE_H || c < 0 || c >= TILE_W) continue;
          if (cur[r * TILE_W + c] >= rule.aliveThreshold) aliveCount++;
        }
      }
      const me = cur[row * TILE_W + col];
      const alive = me >= rule.aliveThreshold;
      let val: number;
      if (!alive) {
        // Dead cell — born if aliveCount in [birthLo, birthHi]
        if (aliveCount >= rule.birthLo && aliveCount <= rule.birthHi) {
          val = clampU8(me + rule.growStep);
        } else {
          val = clampU8(me > rule.decayStep ? me - rule.decayStep : 0);
        }
      } else {
        // Alive cell — survive if aliveCount in [surviveLo, surviveHi]
        if (aliveCount >= rule.surviveLo && aliveCount <= rule.surviveHi) {
          val = clampU8(me + rule.growStep);
        } else {
          val = clampU8(me > rule.decayStep ? me - rule.decayStep : 0);
        }
      }
      next[row * TILE_W + col] = val;
    }
  }
  return next;
}

// ── SHA-256 of state bytes (Node crypto) ─────────────────────────────────────
async function hashTile(state: Uint8Array): Promise<string> {
  const { createHash } = await import('node:crypto');
  return createHash('sha256').update(state).digest('hex');
}

// ── Oracle signer ─────────────────────────────────────────────────────────────
export interface ValidateRequest {
  prev_state: string;  // 128 hex chars (64 bytes = TILE_CELLS)
  next_state: string;
  rule_id:    string;  // '4D4E4341' (hex) or 'MNCA' (ASCII)
  x:          number;
  y:          number;
  gen:        number;
}

export interface ValidateResponse {
  valid:      boolean;
  oracle_sig: string | null;   // hex-encoded r||s (64 bytes) if valid
  message:    string;
}

export async function validateMncaTransition(
  req: ValidateRequest,
  walletWif: string,
): Promise<ValidateResponse> {
  // Decode rule_id
  let ruleId = req.rule_id;
  if (/^[0-9a-fA-F]{8}$/.test(ruleId)) {
    // hex-encoded 4 bytes
    ruleId = Buffer.from(ruleId, 'hex').toString('ascii');
  }
  if (ruleId !== 'MNCA') {
    return { valid: false, oracle_sig: null,
             message: `Unknown rule_id '${ruleId}' — only MNCA supported` };
  }

  if (req.prev_state.length !== TILE_CELLS * 2) {
    return { valid: false, oracle_sig: null,
             message: `prev_state must be ${TILE_CELLS * 2} hex chars` };
  }
  if (req.next_state.length !== TILE_CELLS * 2) {
    return { valid: false, oracle_sig: null,
             message: `next_state must be ${TILE_CELLS * 2} hex chars` };
  }

  const prevBytes = Uint8Array.from(Buffer.from(req.prev_state, 'hex'));
  const nextExpected = stepTile(prevBytes);
  const nextActual   = Uint8Array.from(Buffer.from(req.next_state, 'hex'));

  // Compare computed vs claimed next state.
  let match = true;
  for (let i = 0; i < TILE_CELLS; i++) {
    if (nextExpected[i] !== nextActual[i]) { match = false; break; }
  }

  if (!match) {
    const expHex = Buffer.from(nextExpected).toString('hex');
    return { valid: false, oracle_sig: null,
             message: `Transition invalid — expected state ${expHex.slice(0,16)}... got ${req.next_state.slice(0,16)}...` };
  }

  // Valid transition. Sign (x, y, gen, next_hash) with the oracle key.
  const nextHash = await hashTile(nextExpected);

  // Sighash: SHA-256 of "MNCA_ORACLE|x|y|gen|next_hash"
  const { createHash } = await import('node:crypto');
  const msg = `MNCA_ORACLE|${req.x}|${req.y}|${req.gen}|${nextHash}`;
  const sigHash = createHash('sha256').update(msg).digest('hex');

  let oracleSig: string | null = null;
  try {
    // Accept both WIF (51/52 char base58) and 64-char hex privkey.
    const wallet = walletWif.length === 64
      ? new PrivateKey(walletWif, 16)
      : new PrivateKey(walletWif, 'wif');
    const sig = wallet.sign(Buffer.from(sigHash, 'hex'));
    // Compact r||s encoding (64 bytes)
    const rHex = sig.r.toHex().padStart(64, '0');
    const sHex = sig.s.toHex().padStart(64, '0');
    oracleSig = rHex + sHex;
  } catch (e) {
    return { valid: true, oracle_sig: null,
             message: `Valid transition but signing failed: ${(e as Error).message}` };
  }

  return {
    valid:      true,
    oracle_sig: oracleSig,
    message:    `Valid transition at (${req.x},${req.y}) gen=${req.gen} next_hash=${nextHash.slice(0,16)}...`,
  };
}

// ── Express route handler (attach to mesh-control.ts server) ─────────────────
//
// Usage: import { attachMncaOracle } from './mnca-oracle';
//        attachMncaOracle(app, walletWif);
export function attachMncaOracle(app: { post: Function }, walletWif: string) {
  app.post('/validate-mnca-transition', async (req: any, res: any) => {
    try {
      const body = req.body as ValidateRequest;
      if (!body || typeof body !== 'object') {
        res.status(400).json({ error: 'body must be JSON' });
        return;
      }
      const result = await validateMncaTransition(body, walletWif);
      res.status(result.valid ? 200 : 422).json(result);
    } catch (e) {
      res.status(500).json({ error: String(e) });
    }
  });
  console.log('[mnca-oracle] POST /validate-mnca-transition registered');
}

// ── Standalone test (bun run mnca-oracle.ts) ─────────────────────────────────
if (import.meta.main) {
  // Initialise seed=12345 with the LCG from cell_mnca.c:
  //   s = s * 1664525u + 1013904223u  (repeated TILE_CELLS times)
  const state0 = new Uint8Array(TILE_CELLS);
  let seed = 12345;
  for (let i = 0; i < TILE_CELLS; i++) {
    seed = ((seed * 1664525 + 1013904223) >>> 0);
    state0[i] = seed & 0xff;
  }
  const state1 = stepTile(state0);
  const state2 = stepTile(state1);

  const prevHex = Buffer.from(state0).toString('hex');
  const nextHex = Buffer.from(state1).toString('hex');
  const wrongHex = Buffer.from(state2).toString('hex');

  console.log('state[0] =', prevHex.slice(0, 32) + '...');
  console.log('state[1] =', nextHex.slice(0, 32) + '...');

  // Demo hex privkey (same as mesh-control.ts WALLET for testing)
  const dummyWif = '0000000000000000000000000000000000000000000000000000000000000042';
  const r1 = await validateMncaTransition({
    prev_state: prevHex, next_state: nextHex,
    rule_id: 'MNCA', x: 0, y: 0, gen: 1,
  }, dummyWif);
  console.log('valid transition:', r1.valid, '|', r1.message);

  const r2 = await validateMncaTransition({
    prev_state: prevHex, next_state: wrongHex,
    rule_id: 'MNCA', x: 0, y: 0, gen: 1,
  }, dummyWif);
  console.log('invalid transition:', r2.valid, '|', r2.message);
}
