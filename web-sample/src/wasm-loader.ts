// WASM loader — dynamically imports the kchat-drive-wasm pkg.
// The pkg files are copied to src/wasm/ so Vite processes the JS glue
// as a module and resolves the .wasm binary via import.meta.url.

let wasm: WasmExports | null = null;

export async function loadWasm(): Promise<WasmExports> {
  if (wasm) return wasm;

  const wasmModule = await import("./wasm/kchat_drive_wasm.js");
  await wasmModule.default();
  wasm = wasmModule as unknown as WasmExports;
  return wasm;
}
