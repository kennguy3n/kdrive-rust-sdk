// Minimal IndexedDB key vault for the web sample.
// Stores domain keys, share grant keys, and device key pairs per user.

const DB_NAME = "kchat-drive-demo";
const DB_VERSION = 1;
const STORE_KEYS = "keys";

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_KEYS)) {
        db.createObjectStore(STORE_KEYS, { keyPath: "id" });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

interface KeyEntry {
  id: string;
  value: string;
}

export async function storeKey(id: string, value: string): Promise<void> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_KEYS, "readwrite");
    tx.objectStore(STORE_KEYS).put({ id, value } as KeyEntry);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function loadKey(id: string): Promise<string | null> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_KEYS, "readonly");
    const req = tx.objectStore(STORE_KEYS).get(id);
    req.onsuccess = () => {
      const entry = req.result as KeyEntry | undefined;
      resolve(entry?.value ?? null);
    };
    req.onerror = () => reject(req.error);
  });
}

export async function deleteKey(id: string): Promise<void> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_KEYS, "readwrite");
    tx.objectStore(STORE_KEYS).delete(id);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function listKeys(): Promise<string[]> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_KEYS, "readonly");
    const req = tx.objectStore(STORE_KEYS).getAllKeys();
    req.onsuccess = () => resolve(req.result as string[]);
    req.onerror = () => reject(req.error);
  });
}
