/**
 * codec.test.ts — the temperature logger's wire, host side.
 *
 * The golden bytes are copied by hand from the Zig reference tests in
 * components/cell-mesh-zig/src/cell_templog_test.zig, which were written from
 * docs/TEMP-LOGGER.md rather than captured from an encoder. The parity tests
 * at the bottom read that file and fail if the two copies ever disagree, so
 * the TS and Zig codecs cannot drift apart silently.
 *
 * Run: bun test tools/templog-bridge/codec.test.ts
 */
import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { mintCell, PAYLOAD_SIZE } from '../x402-bridge/cell-codec.js';
import { DOMAIN } from '../domains.js';
import {
  BATCH_MAX_SAMPLES,
  SF,
  TEMP_INVALID,
  TYPE_ACK,
  TYPE_BATCH,
  classifyLine,
  crc32,
  decodeAck,
  decodeBatch,
  encodeAck,
  encodeBatch,
  formatAkLine,
  formatTlLine,
  macToBytes,
  macToString,
  parseAkLine,
  parseCell,
  parseTlLine,
  type BatchHeaderFields,
} from './codec.js';

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const ascii = (s: string) => new TextEncoder().encode(s);

// ── Golden bytes, from cell_templog_test.zig ─────────────────────────

// test "a batch encodes to the byte layout in the spec"
const GOLDEN_BATCH = Uint8Array.from([
  0x00, // version
  0x00, // flags
  0x02, 0x00, // count = 2
  0x64, 0x00, 0x00, 0x00, // first_seq = 100
  0x03, 0x00, 0x00, 0x00, // boot_id = 3
  0x04, 0x00, 0x00, 0x00, // boot_now = 4
  0x20, 0x1c, 0x00, 0x00, // uptime_now_s = 7200
  0x80, 0x3b, 0xb1, 0x6a, // boot_epoch_s = 1790000000
  0x00, 0x00, 0x00, 0x00, // lost_through = 0
  0x3c, 0x00, 0x00, 0x00, // sample_interval_s = 60
  0x38, 0xff, // policy_min_centi = -200
  0xf0, 0x0a, // policy_max_centi = 2800
  0xd4, 0xc3, 0xb2, 0xa1, // log_id
  0x3c, 0x00, 0x00, 0x00, 0xca, 0x09, 0x00, 0x00, // sample 0
  0x78, 0x00, 0x00, 0x00, 0x38, 0xff, 0x01, 0x00, // sample 1
]);

const GOLDEN_HEADER: BatchHeaderFields = {
  firstSeq: 100,
  bootId: 3,
  bootNow: 4,
  uptimeNowS: 7200,
  bootEpochS: 1790000000,
  lostThrough: 0,
  sampleIntervalS: 60,
  policyMinCenti: -200,
  policyMaxCenti: 2800,
  logId: 0xa1b2c3d4,
};

// test "an ack encodes to the byte layout in the spec and round-trips"
const GOLDEN_ACK = Uint8Array.from([
  0x00, 0x00, // version, reserved
  0x58, 0xe6, 0xc5, 0x1a, 0x8b, 0x28, // target mac
  0xc2, 0x01, 0x00, 0x00, // acked_through = 450
  0x90, 0x49, 0xb1, 0x6a, // host_unix_s = 1790003600
]);
const GOLDEN_ACK_MAC = '58:e6:c5:1a:8b:28';

// ── Helpers ──────────────────────────────────────────────────────────

const MAC = '58:e6:c5:1a:8b:28';

function ownerId(mac: string): Uint8Array {
  const o = new Uint8Array(16);
  o.set(macToBytes(mac));
  return o;
}

function batchCell(payload: Uint8Array = GOLDEN_BATCH, mac = MAC): Uint8Array {
  return mintCell(TYPE_BATCH, payload, ownerId(mac), 123_456n, DOMAIN.meshTelemetry);
}

function crcHex(bytes: Uint8Array): string {
  return crc32(bytes).toString(16).padStart(8, '0');
}

// ── Type hashes ──────────────────────────────────────────────────────

describe('type hashes', () => {
  test('are SHA-256 of the ASCII type names (digests from shasum, not from this code)', () => {
    expect(hex(TYPE_BATCH)).toBe('27e0502a8a993c2f3ba4de92cdaa0d93e20491ea8fa6a6198d7ca568b62023df');
    expect(hex(TYPE_ACK)).toBe('bdeb6b0d1244a3aca6726d39923966a2f14b2ef8934a4e14a22a51f3f5014eb8');
  });
});

// ── Batch payload ────────────────────────────────────────────────────

describe('batch payload', () => {
  test('decodes the golden batch, every field', () => {
    const b = decodeBatch(GOLDEN_BATCH);
    expect(b).not.toBeNull();
    expect(b!.header).toEqual({ version: 0, flags: 0, count: 2, ...GOLDEN_HEADER });
    expect(b!.samples).toEqual([
      { seq: 100, uptimeS: 60, centiC: 2506, flags: 0 },
      { seq: 101, uptimeS: 120, centiC: -200, flags: SF.POLICY_REJECT },
    ]);
  });

  test('encodes the golden batch byte for byte', () => {
    const p = encodeBatch(GOLDEN_HEADER, [
      { uptimeS: 60, centiC: 2506, flags: 0 },
      { uptimeS: 120, centiC: -200, flags: SF.POLICY_REJECT },
    ]);
    expect(hex(p)).toBe(hex(GOLDEN_BATCH));
  });

  test('decodes from a whole zero-padded 768-byte payload as well', () => {
    const full = new Uint8Array(PAYLOAD_SIZE);
    full.set(GOLDEN_BATCH);
    expect(decodeBatch(full)?.samples.map((s) => s.seq)).toEqual([100, 101]);
  });

  test('a sample with no reading keeps centi -32768 and its flags', () => {
    const p = encodeBatch(GOLDEN_HEADER, [{ uptimeS: 60, centiC: TEMP_INVALID, flags: SF.SENSOR_ERROR | SF.POR_SUSPECT }]);
    expect(decodeBatch(p)!.samples[0]).toEqual({ seq: 100, uptimeS: 60, centiC: -32768, flags: 0x0c });
  });

  test('refuses an unknown version', () => {
    const bad = GOLDEN_BATCH.slice();
    bad[0] = 1;
    expect(decodeBatch(bad)).toBeNull();
  });

  test('refuses count 92 even when the buffer is long enough to hold it', () => {
    const big = new Uint8Array(40 + 92 * 8);
    big.set(GOLDEN_BATCH.subarray(0, 40));
    big[2] = 92;
    expect(decodeBatch(big)).toBeNull();
    big[2] = 91; // the same buffer at the limit is fine
    expect(decodeBatch(big)?.samples.length).toBe(91);
  });

  test('refuses a buffer shorter than the header plus count samples', () => {
    expect(decodeBatch(GOLDEN_BATCH.subarray(0, 55))).toBeNull();
    expect(decodeBatch(GOLDEN_BATCH.subarray(0, 56))).not.toBeNull();
    expect(decodeBatch(GOLDEN_BATCH.subarray(0, 39))).toBeNull();
    expect(decodeBatch(new Uint8Array(0))).toBeNull();
  });

  test('holds 91 samples, which fill the payload exactly, and refuses a 92nd', () => {
    expect(BATCH_MAX_SAMPLES).toBe(91);
    const s = (i: number) => ({ uptimeS: i, centiC: i, flags: 0 });
    const p = encodeBatch({ ...GOLDEN_HEADER, firstSeq: 1 }, Array.from({ length: 91 }, (_, i) => s(i)));
    expect(p.length).toBe(PAYLOAD_SIZE);
    expect(decodeBatch(p)!.samples.at(-1)!.seq).toBe(91);
    expect(() => encodeBatch(GOLDEN_HEADER, Array.from({ length: 92 }, (_, i) => s(i)))).toThrow();
  });
});

// ── Ack payload ──────────────────────────────────────────────────────

describe('ack payload', () => {
  test('encodes the golden ack byte for byte', () => {
    expect(hex(encodeAck(GOLDEN_ACK_MAC, 450, 1790003600))).toBe(hex(GOLDEN_ACK));
  });

  test('decodes the golden ack', () => {
    expect(decodeAck(GOLDEN_ACK)).toEqual({ targetMac: GOLDEN_ACK_MAC, ackedThrough: 450, hostUnixS: 1790003600 });
  });

  test('decodes from a zero-padded 768-byte payload', () => {
    const full = new Uint8Array(PAYLOAD_SIZE);
    full.set(GOLDEN_ACK);
    expect(decodeAck(full)?.ackedThrough).toBe(450);
  });

  test('refuses a short buffer or an unknown version', () => {
    expect(decodeAck(GOLDEN_ACK.subarray(0, 15))).toBeNull();
    const bad = GOLDEN_ACK.slice();
    bad[0] = 9;
    expect(decodeAck(bad)).toBeNull();
  });
});

// ── Cells ────────────────────────────────────────────────────────────

describe('cells', () => {
  test('a batch cell yields its type, owner MAC, payload_total and payload', () => {
    const c = parseCell(batchCell());
    expect(c).not.toBeNull();
    expect(c!.kind).toBe('batch');
    expect(hex(c!.typeHash)).toBe(hex(TYPE_BATCH));
    expect(c!.ownerMac).toBe(MAC);
    expect(c!.payloadTotal).toBe(56);
    expect(c!.payload.length).toBe(PAYLOAD_SIZE);
    expect(hex(c!.payload.subarray(0, 56))).toBe(hex(GOLDEN_BATCH));
    expect(c!.payloadRootOk).toBe(true);
    expect(c!.domainFlags).toBe(DOMAIN.meshTelemetry);
    expect(c!.version).toBe(2);
  });

  test('an ack cell is recognised as an ack, and anything else as other', () => {
    const ack = mintCell(TYPE_ACK, GOLDEN_ACK, ownerId(MAC), 1n, DOMAIN.meshTelemetry);
    expect(parseCell(ack)!.kind).toBe('ack');
    expect(parseCell(ack)!.payloadTotal).toBe(16);
    const other = mintCell(new Uint8Array(32).fill(7), GOLDEN_ACK, ownerId(MAC), 1n);
    expect(parseCell(other)!.kind).toBe('other');
  });

  test('is null for bytes that are not a cell', () => {
    const cell = batchCell();
    const badMagic = cell.slice();
    badMagic[5] ^= 0xff; // inside the second magic word
    expect(parseCell(badMagic)).toBeNull();
    expect(parseCell(cell.subarray(0, 1023))).toBeNull();
    const long = new Uint8Array(1025);
    long.set(cell);
    expect(parseCell(long)).toBeNull();
  });

  test('says when the payload no longer matches domain_payload_root', () => {
    const cell = batchCell();
    cell[256 + 4] ^= 0x01;
    expect(parseCell(cell)!.payloadRootOk).toBe(false);
  });
});

// ── MACs ─────────────────────────────────────────────────────────────

describe('MACs', () => {
  test('parse with or without colons, in either case, and print lowercase with colons', () => {
    const b = macToBytes('58:E6:c5:1A:8b:28');
    expect(Array.from(b)).toEqual([0x58, 0xe6, 0xc5, 0x1a, 0x8b, 0x28]);
    expect(macToString(b)).toBe(MAC);
    expect(macToString(macToBytes('58e6c51a8b28'))).toBe(MAC);
  });

  test('refuse anything that is not six octets', () => {
    expect(() => macToBytes(MAC)).not.toThrow(); // so a parser that refuses everything fails here
    for (const bad of ['58:e6:c5:1a:8b', '58:e6:c5:1a:8b:28:00', '58:e6:c5:1a:8b:2g', '58e6c51a8b2', '']) {
      expect(() => macToBytes(bad)).toThrow();
    }
  });
});

// ── Serial lines ─────────────────────────────────────────────────────

describe('serial lines', () => {
  // Built per test, not at collection time, so a broken codec fails each test
  // on its own instead of taking the whole block down before it runs.
  const fixture = () => {
    const cell = batchCell();
    return { cell, line: `TL ${MAC} ${hex(cell)} ${crcHex(cell)}` };
  };

  test('crc32 is zlib CRC-32 (the published check value)', () => {
    expect(crc32(ascii('123456789'))).toBe(0xcbf43926);
  });

  test('a TL line yields the MAC and the 1024 cell bytes', () => {
    const { cell, line } = fixture();
    const got = parseTlLine(line);
    expect(got).not.toBeNull();
    expect(got!.mac).toBe(MAC);
    expect(hex(got!.cell)).toBe(hex(cell));
    expect(classifyLine(line).kind).toBe('tl');
  });

  test('tolerates the CR of a CRLF line ending', () => {
    const { line } = fixture();
    expect(parseTlLine(line + '\r')?.mac).toBe(MAC);
  });

  test('formatTlLine writes what the gateway prints', () => {
    const { cell, line } = fixture();
    expect(formatTlLine(MAC, cell)).toBe(line + '\n');
  });

  test('rejects a CRC that does not match the cell', () => {
    const { cell } = fixture();
    const crc = (crc32(cell) ^ 1) >>> 0;
    const bad = `TL ${MAC} ${hex(cell)} ${crc.toString(16).padStart(8, '0')}`;
    expect(parseTlLine(bad)).toBeNull();
    const c = classifyLine(bad);
    expect(c.kind).toBe('bad');
    expect(c.kind === 'bad' && c.reason).toContain('CRC');
  });

  test('rejects a cell corrupted in transit, because its CRC no longer holds', () => {
    const { cell } = fixture();
    const corrupt = hex(cell).split('');
    corrupt[600] = corrupt[600] === '0' ? '1' : '0';
    const bad = `TL ${MAC} ${corrupt.join('')} ${crcHex(cell)}`;
    expect(parseTlLine(bad)).toBeNull();
    expect(classifyLine(bad).kind).toBe('bad');
  });

  test('rejects bad hex', () => {
    const { cell } = fixture();
    const cellHex = hex(cell);
    const badCell = `TL ${MAC} ${'g' + cellHex.slice(1)} ${crcHex(cell)}`;
    const badCrc = `TL ${MAC} ${cellHex} ${'x' + crcHex(cell).slice(1)}`;
    for (const bad of [badCell, badCrc]) {
      expect(parseTlLine(bad)).toBeNull();
      expect(classifyLine(bad).kind).toBe('bad');
    }
  });

  test('rejects wrong lengths', () => {
    const { cell } = fixture();
    const cellHex = hex(cell);
    const crc = crcHex(cell);
    const bads = [
      `TL ${MAC} ${cellHex.slice(2)} ${crc}`, // 1023 bytes
      `TL ${MAC} ${cellHex}00 ${crc}`, // 1025 bytes
      `TL ${MAC} ${cellHex} ${crc.slice(1)}`, // 7-digit CRC
      `TL ${MAC} ${cellHex} 0${crc}`, // 9-digit CRC
      `TL 58:e6:c5:1a:8b ${cellHex} ${crc}`, // 5-octet MAC
      `TL ${MAC} ${cellHex}`, // no CRC at all
      `TL ${MAC} ${cellHex} ${crc} extra`,
    ];
    for (const bad of bads) {
      expect(parseTlLine(bad)).toBeNull();
      expect(classifyLine(bad).kind).toBe('bad');
    }
  });

  test('ignores every other line, ESP-IDF logs included', () => {
    const others = [
      'I (1234) temp_logger: gateway up. mac=58:e6:c5:1a:8b:28 — TL lines out, AK lines in',
      '\x1b[0;32mI (5120) temp_logger: RX [58:e6:c5:1a:8b:28] batch log=a1b2c3d4 seqs 1..5\x1b[0m',
      'AK 58e6c51a8b28 450 1790003600',
      'ESP-ROM:esp32c6-20220919',
      '',
      '   ',
    ];
    for (const l of others) {
      expect(parseTlLine(l)).toBeNull();
      expect(classifyLine(l).kind).toBe('other');
    }
  });

  test('still finds a whole TL frame that lands after a log fragment on the same line', () => {
    // The gateway prints TL lines and ESP-IDF logs on one USB console from
    // two tasks, so a frame can follow a partial log line. The CRC decides.
    const { cell, line } = fixture();
    const got = parseTlLine(`I (5120) temp_logger: TX ack → 58:e6:c5${line}`);
    expect(got?.mac).toBe(MAC);
    expect(hex(got!.cell)).toBe(hex(cell));
  });

  test('formats an AK line with the bare lowercase MAC and two decimals', () => {
    expect(formatAkLine('58:E6:C5:1A:8B:28', 450, 1790003600)).toBe('AK 58e6c51a8b28 450 1790003600\n');
    expect(formatAkLine(MAC, 0, 0)).toBe('AK 58e6c51a8b28 0 0\n');
  });

  test('refuses to format an AK line whose numbers do not fit a u32', () => {
    expect(formatAkLine(MAC, 0xffffffff, 0xffffffff)).toBe('AK 58e6c51a8b28 4294967295 4294967295\n');
    for (const [a, h] of [[-1, 0], [2 ** 32, 0], [1.5, 0], [0, -1], [0, 2 ** 32], [Number.NaN, 0]]) {
      expect(() => formatAkLine(MAC, a, h)).toThrow();
    }
  });

  test('parses an AK line the way the gateway does', () => {
    expect(parseAkLine('AK 58e6c51a8b28 450 1790003600\n')).toEqual({ mac: MAC, ackedThrough: 450, hostUnixS: 1790003600 });
    expect(parseAkLine('AK 58e6c51a8b2 450 1790003600')).toBeNull();
    expect(parseAkLine('AK 58e6c51a8b28 x 1790003600')).toBeNull();
    expect(parseAkLine('I (1) temp_logger: AK 58e6c51a8b28 1 2')).toBeNull();
  });
});

// ── Parity with the Zig reference tests ──────────────────────────────

const ZIG_TESTS = join(import.meta.dir, '../../components/cell-mesh-zig/src/cell_templog_test.zig');
const BATCH_TEST = 'a batch encodes to the byte layout in the spec';
const ACK_TEST = 'an ack encodes to the byte layout in the spec and round-trips';

/**
 * The `const want = [_]u8{ ... };` array inside the named Zig test. Throws
 * rather than returning something partial: a renamed test or a new literal
 * syntax must turn this red, not quietly compare less.
 */
function zigWant(src: string, testName: string): Uint8Array {
  const start = src.indexOf(`test "${testName}" {`);
  if (start < 0) throw new Error(`zig test "${testName}" not found`);
  const next = src.indexOf('\ntest "', start + 1);
  const end = next < 0 ? src.length : next;
  const decl = src.indexOf('const want = [_]u8{', start);
  if (decl < 0 || decl > end) throw new Error(`no want array in zig test "${testName}"`);
  const open = decl + 'const want = [_]u8'.length;
  const close = src.indexOf('};', open);
  if (close < 0 || close > end) throw new Error(`unterminated want array in zig test "${testName}"`);
  const body = src.slice(open + 1, close).replace(/\/\/[^\n]*/g, '');
  const bytes = body
    .split(',')
    .map((t) => t.trim())
    .filter((t) => t.length > 0)
    .map((t) => {
      if (!/^(0x[0-9a-fA-F]{1,2}|\d{1,3})$/.test(t)) throw new Error(`unexpected token "${t}" in zig test "${testName}"`);
      const v = Number(t);
      if (v > 0xff) throw new Error(`byte out of range: ${t}`);
      return v;
    });
  return Uint8Array.from(bytes);
}

describe('parity with cell_templog_test.zig', () => {
  const src = readFileSync(ZIG_TESTS, 'utf8');

  test('the batch golden bytes here are the ones in the Zig test', () => {
    expect(hex(zigWant(src, BATCH_TEST))).toBe(hex(GOLDEN_BATCH));
  });

  test('the ack golden bytes here are the ones in the Zig test', () => {
    expect(hex(zigWant(src, ACK_TEST))).toBe(hex(GOLDEN_ACK));
  });

  test('the check can fail: one changed byte in the Zig source is noticed', () => {
    const tampered = src.replace('0xD4, 0xC3, 0xB2, 0xA1, // log_id', '0xD4, 0xC3, 0xB2, 0xA0, // log_id');
    expect(tampered).not.toBe(src);
    expect(hex(zigWant(tampered, BATCH_TEST))).not.toBe(hex(GOLDEN_BATCH));
    const tamperedAck = src.replace('0xC2, 0x01, 0x00, 0x00, // acked_through = 450', '0xC3, 0x01, 0x00, 0x00, // acked_through = 450');
    expect(tamperedAck).not.toBe(src);
    expect(hex(zigWant(tamperedAck, ACK_TEST))).not.toBe(hex(GOLDEN_ACK));
  });

  test('the check fails loudly when a test is renamed or its array changes shape', () => {
    expect(() => zigWant(src, 'a test that does not exist')).toThrow();
    const reshaped = src.replace('0x3C, 0x00, 0x00, 0x00, 0xCA, 0x09, 0x00, 0x00,', '[_]u8{0} ** 8,');
    expect(reshaped).not.toBe(src);
    expect(() => zigWant(reshaped, BATCH_TEST)).toThrow();
  });
});
