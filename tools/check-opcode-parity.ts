#!/usr/bin/env bun

import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const defaultCoreDir = resolve(repoRoot, '..', 'semantos-core', 'core', 'cell-engine');

function argValue(name: string): string | undefined {
  const prefix = `--${name}=`;
  const inline = process.argv.find((arg) => arg.startsWith(prefix));
  if (inline) return inline.slice(prefix.length);

  const index = process.argv.indexOf(`--${name}`);
  if (index >= 0) return process.argv[index + 1];

  return undefined;
}

const coreDir = resolve(argValue('core') ?? process.env.SEMANTOS_CORE ?? defaultCoreDir);
const edgeWasm = join(repoRoot, 'components/semantos/wasm/cell-engine-embedded.wasm');
const coreWasm = join(coreDir, 'zig-out/bin/cell-engine-embedded.wasm');

const failures: string[] = [];

function requireFile(path: string, hint?: string): boolean {
  if (existsSync(path)) return true;
  failures.push(hint ? `${path} is missing (${hint})` : `${path} is missing`);
  return false;
}

function sha256(path: string): string {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function includes(path: string, needle: string): boolean {
  return readFileSync(path, 'utf8').includes(needle);
}

function requireContains(path: string, needle: string) {
  if (!requireFile(path)) return;
  if (!includes(path, needle)) failures.push(`${path} does not contain ${needle}`);
}

requireFile(edgeWasm);
requireFile(coreWasm, 'run `zig build -Dembedded=true` in semantos-core/core/cell-engine first');

if (existsSync(edgeWasm) && existsSync(coreWasm)) {
  const edgeHash = sha256(edgeWasm);
  const coreHash = sha256(coreWasm);

  if (edgeHash !== coreHash) {
    failures.push([
      'edge WASM is not byte-identical to the current core embedded build',
      `  edge: ${edgeHash}  ${edgeWasm}`,
      `  core: ${coreHash}  ${coreWasm}`,
    ].join('\n'));
  }

  const edgeBytes = readFileSync(edgeWasm);
  for (const exportName of [
    'kernel_execute',
    'kernel_load_tx_context',
    'kernel_set_output_index',
  ]) {
    if (!edgeBytes.includes(Buffer.from(exportName))) {
      failures.push(`edge WASM does not expose ${exportName}`);
    }
  }

  for (const importName of [
    'host_call_by_name',
    'host_sha256',
    'host_hash160',
    'host_hash256',
    'host_ripemd160',
    'host_sha1',
    'host_fetch_cell',
    'host_sign',
    'host_checksig',
    'hostDbOpenCursor',
    'hostDbCursorPull',
    'hostDbCursorClose',
  ]) {
    if (!edgeBytes.includes(Buffer.from(importName))) {
      failures.push(`edge WASM does not import ${importName}`);
    }
    requireContains(join(repoRoot, 'components/semantos/src/runtime_wamr.c'), `"${importName}"`);
  }
}

requireContains(join(repoRoot, 'components/semantos/include/semantos.h'), 'semantos_kernel_set_output_index');
requireContains(join(repoRoot, 'components/semantos/src/semantos.c'), '"kernel_set_output_index"');

const coreChecks: Array<[string, string]> = [
  ['src/opcodes/macro.zig', '0xB8 => try hashcat'],
  ['src/opcodes/plexus.zig', 'constants.OP_CHECKDOMAINFLAG => try opCheckDomainFlag'],
  ['src/opcodes/plexus.zig', 'constants.OP_CHECKTYPEHASH => try opCheckTypeHash'],
  ['src/opcodes/plexus.zig', 'constants.OP_DEREF_POINTER => try opDerefPointer'],
  ['src/opcodes/plexus.zig', '0xD1 => try opWritePayload'],
  ['src/opcodes/hostcall.zig', 'OP_CALLHOST'],
  ['src/opcodes/routing.zig', 'constants.OP_BRANCHONOUTPUT'],
  ['src/executor.zig', 'opcode >= constants.OPCODE_ROUTING_MIN'],
];

for (const [file, needle] of coreChecks) {
  requireContains(join(coreDir, file), needle);
}

if (failures.length > 0) {
  console.error('Opcode parity check failed:\n');
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

const hash = sha256(edgeWasm);
console.log(`opcode parity ok: edge WASM matches core (${hash})`);
console.log(`core source: ${coreDir}`);
