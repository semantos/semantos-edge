// A host-side runner for the embedded cell-engine WASM — the same binary the
// C6 loads — for checking scripts before they reach a board.
//
// It mirrors components/semantos/src/semantos.c: reset, load the lock script,
// load the unlock script, execute; 0 means accept. Host imports are stubs
// that fail closed, so a script that needs hashing, signatures or the cell
// store is rejected here rather than silently passed. Scripts are copied
// into a page of linear memory this runner owns, as WAMR's module_malloc
// does on the device.

import { resolve } from 'node:path';

const WASM = resolve(import.meta.dir, '../../components/semantos/wasm/cell-engine-embedded.wasm');
const FAIL = 1;

export interface Engine {
  /** True when the engine accepts `unlock` followed by `lock`. */
  run(lock: Uint8Array, unlock: Uint8Array): boolean;
}

export async function openEngine(path = WASM): Promise<Engine> {
  const module = new WebAssembly.Module(await Bun.file(path).arrayBuffer());
  const host: Record<string, () => number> = {};
  for (const imp of WebAssembly.Module.imports(module)) host[imp.name] = () => FAIL;
  const instance = new WebAssembly.Instance(module, { host });
  const x = instance.exports as Record<string, any>;
  const memory = x.memory as WebAssembly.Memory;

  const scratch = memory.grow(1) * 65536;   // a page nothing else uses
  if (x.kernel_init() !== 0) throw new Error('kernel_init failed');

  const load = (fn: (p: number, n: number) => number, bytes: Uint8Array, at: number): number => {
    new Uint8Array(memory.buffer, scratch + at, bytes.length).set(bytes);
    return fn(scratch + at, bytes.length);
  };

  return {
    run(lock, unlock) {
      x.kernel_reset();
      if (load(x.kernel_load_script, lock, 0) !== 0) return false;
      if (unlock.length > 0 && load(x.kernel_load_unlock, unlock, 4096) !== 0) return false;
      return x.kernel_execute() === 0;
    },
  };
}
