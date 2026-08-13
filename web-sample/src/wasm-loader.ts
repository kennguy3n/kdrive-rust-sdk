// WASM loader — dynamically imports the kchat-drive-wasm pkg.
// The pkg files are copied to src/wasm/ so Vite processes the JS glue
// as a module and resolves the .wasm binary via import.meta.url.
//
// The WasmDriveRuntime is created once and persisted across the app's
// lifetime. The vault (including tenant pepper) lives in the runtime's
// memory. The master key is persisted in IndexedDB so the vault can be
// restored across page reloads.

// The WASM module exports both functions (WasmExports) and classes.
type WasmModule = WasmExports & {
  WasmDriveRuntime: typeof WasmDriveRuntime;
  DedupCallbacks: typeof DedupCallbacks;
};

let wasm: WasmModule | null = null;
let runtime: WasmDriveRuntime | null = null;

const MASTER_KEY_IDB_KEY = "kchat_drive_master_key";

export async function loadWasm(): Promise<WasmModule> {
  if (wasm) return wasm;

  const wasmModule = await import("./wasm/kchat_drive_wasm.js");
  await wasmModule.default();
  wasm = wasmModule as unknown as WasmModule;
  return wasm;
}

/// Returns the persistent WasmDriveRuntime, creating it if needed.
/// The master key is persisted in IndexedDB so the vault survives reloads.
export async function getRuntime(): Promise<WasmDriveRuntime> {
  if (runtime) return runtime;

  const wasmModule = await loadWasm();

  // Try to load persisted master key from IndexedDB
  const savedKey = await loadMasterKey();
  if (savedKey) {
    try {
      runtime = wasmModule.WasmDriveRuntime.withMasterKey(savedKey);
    } catch {
      // Saved key was corrupted/invalid — regenerate
      runtime = new wasmModule.WasmDriveRuntime();
      const masterKey = runtime.exportMasterKey();
      await storeMasterKey(masterKey);
    }
  } else {
    // First run — create new runtime and persist the master key
    runtime = new wasmModule.WasmDriveRuntime();
    const masterKey = runtime.exportMasterKey();
    await storeMasterKey(masterKey);
  }

  return runtime;
}

// --- IndexedDB helpers for master key persistence ---

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open("kchat-drive-demo", 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains("keys")) {
        db.createObjectStore("keys", { keyPath: "id" });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function storeMasterKey(keyHex: string): Promise<void> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction("keys", "readwrite");
    tx.objectStore("keys").put({ id: MASTER_KEY_IDB_KEY, value: keyHex });
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function loadMasterKey(): Promise<string | null> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction("keys", "readonly");
    const req = tx.objectStore("keys").get(MASTER_KEY_IDB_KEY);
    req.onsuccess = () => {
      const entry = req.result;
      resolve(entry?.value ?? null);
    };
    req.onerror = () => reject(req.error);
  });
}
