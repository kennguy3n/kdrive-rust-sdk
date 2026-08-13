// Electron main process — loads the KChat Drive NAPI addon and exposes
// it to the renderer via a simple IPC handler.
const { app, BrowserWindow, ipcMain } = require("electron");
const path = require("path");

// The NAPI addon is a native .node file. We load it via the generated
// index.js which resolves the platform-specific binary.
const kdrive = require("kchat-drive-napi");

let mainWindow;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 900,
    height: 700,
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  mainWindow.loadFile("index.html");
}

// --- IPC handlers: expose the NAPI crypto surface to the renderer ---

ipcMain.handle("kdrive:generateVersionDek", () => kdrive.generateVersionDek());

ipcMain.handle("kdrive:generateEd25519Keypair", () =>
  kdrive.generateEd25519Keypair(),
);

ipcMain.handle("kdrive:generateHpkeKeypair", () => kdrive.generateHpkeKeypair());

ipcMain.handle("kdrive:randomIdHex", () => kdrive.randomIdHex());

ipcMain.handle("kdrive:selectChunkSize", (_e, fileSize) =>
  kdrive.selectChunkSize(Number(fileSize)),
);

ipcMain.handle("kdrive:chunkCount", (_e, fileSize, chunkSize) =>
  kdrive.chunkCount(Number(fileSize), Number(chunkSize)),
);

ipcMain.handle(
  "kdrive:encryptFile",
  (
    _e,
    versionDekHex,
    nodeIdHex,
    versionIdHex,
    driveIdHex,
    domainIdHex,
    accessContextRevision,
    snapshotHashHex,
    plaintextHex,
  ) => {
    const plaintext = Buffer.from(plaintextHex, "hex");
    return kdrive.encryptFileNapi(
      versionDekHex,
      nodeIdHex,
      versionIdHex,
      driveIdHex,
      domainIdHex,
      Number(accessContextRevision),
      snapshotHashHex,
      plaintext,
    );
  },
);

ipcMain.handle(
  "kdrive:decryptFile",
  (
    _e,
    versionDekHex,
    nodeIdHex,
    versionIdHex,
    driveIdHex,
    domainIdHex,
    accessContextRevision,
    snapshotHashHex,
    manifestCiphertextHex,
    manifestNonceHex,
    ciphertextsHex,
  ) => {
    const plaintext = kdrive.decryptFileNapi(
      versionDekHex,
      nodeIdHex,
      versionIdHex,
      driveIdHex,
      domainIdHex,
      Number(accessContextRevision),
      snapshotHashHex,
      manifestCiphertextHex,
      manifestNonceHex,
      ciphertextsHex,
    );
    return Buffer.from(plaintext).toString("hex");
  },
);

ipcMain.handle("kdrive:getTestVectors", () => kdrive.getTestVectorsJson());

// --- KDRV1 content dedup with SDK-managed pepper ---

// Persistent DriveRuntime — vault (including tenant pepper) lives in the
// native addon's in-memory vault. The master key is persisted to disk
// (encrypted via safeStorage on supported platforms) so the same vault
// encryption key can be reused across app restarts.
//
// NOTE: Vault entries (pepper, domain keys, etc.) are in-memory only.
// On restart, the vault starts empty — pepper must be re-distributed
// via MLS (openPepperFromMls) or domain-key wrapping (unwrapPepperFromDomainKey).
let driveRuntime = null;
const { safeStorage } = require("electron");

function initDriveRuntime() {
  if (driveRuntime) return driveRuntime;

  const fs = require("fs");
  const keyPath = path.join(app.getPath("userData"), "drive-master-key.dat");
  let masterKeyHex = "";

  try {
    if (fs.existsSync(keyPath)) {
      const raw = fs.readFileSync(keyPath);
      // safeStorage encrypts at rest on supported platforms; falls back to plaintext
      const decrypted = safeStorage.isEncryptionAvailable()
        ? safeStorage.decryptString(raw)
        : raw.toString("utf8");
      masterKeyHex = decrypted.trim();
    }
  } catch (_) {}

  if (masterKeyHex) {
    try {
      driveRuntime = kdrive.DriveRuntime.withMasterKey(masterKeyHex);
    } catch (err) {
      // Saved key was corrupted/invalid — regenerate
      driveRuntime = new kdrive.DriveRuntime();
      masterKeyHex = driveRuntime.exportMasterKey();
      try {
        const data = safeStorage.isEncryptionAvailable()
          ? safeStorage.encryptString(masterKeyHex)
          : Buffer.from(masterKeyHex);
        fs.writeFileSync(keyPath, data);
      } catch (_) {}
    }
  } else {
    driveRuntime = new kdrive.DriveRuntime();
    masterKeyHex = driveRuntime.exportMasterKey();
    try {
      const data = safeStorage.isEncryptionAvailable()
        ? safeStorage.encryptString(masterKeyHex)
        : Buffer.from(masterKeyHex, "utf8");
      fs.writeFileSync(keyPath, data);
    } catch (_) {}
  }

  return driveRuntime;
}

ipcMain.handle("kdrive:initTenantPepper", (_e, tenantIdHex) => {
  const rt = initDriveRuntime();
  return rt.initTenantPepper(tenantIdHex);
});

ipcMain.handle("kdrive:ensureTenantPepper", (_e, tenantIdHex) => {
  const rt = initDriveRuntime();
  return rt.ensureTenantPepper(tenantIdHex);
});

ipcMain.handle("kdrive:loadTenantPepper", (_e, tenantIdHex) => {
  const rt = initDriveRuntime();
  return rt.loadTenantPepper(tenantIdHex);
});

ipcMain.handle("kdrive:hasTenantPepper", (_e, tenantIdHex) => {
  const rt = initDriveRuntime();
  return rt.hasTenantPepper(tenantIdHex);
});

ipcMain.handle("kdrive:storeTenantPepper", (_e, tenantIdHex, pepperHex) => {
  const rt = initDriveRuntime();
  return rt.storeTenantPepper(tenantIdHex, pepperHex);
});

ipcMain.handle("kdrive:sealPepperForMls", (_e, tenantIdHex, exporterHex, saltHex, domainIdHex, generation, mlsEpoch, treeHashHex, envelopeIdHex) => {
  const rt = initDriveRuntime();
  return rt.sealPepperForMls(tenantIdHex, exporterHex, saltHex, domainIdHex, Number(generation), Number(mlsEpoch), treeHashHex, envelopeIdHex);
});

ipcMain.handle("kdrive:openPepperFromMls", (_e, tenantIdHex, ctHex, nonceHex, exporterHex, saltHex, domainIdHex, generation, mlsEpoch, treeHashHex, envelopeIdHex) => {
  const rt = initDriveRuntime();
  return rt.openPepperFromMls(tenantIdHex, ctHex, nonceHex, exporterHex, saltHex, domainIdHex, Number(generation), Number(mlsEpoch), treeHashHex, envelopeIdHex);
});

ipcMain.handle("kdrive:wrapPepperUnderDomainKey", (_e, tenantIdHex, domainKeyHex) => {
  const rt = initDriveRuntime();
  return rt.wrapPepperUnderDomainKey(tenantIdHex, domainKeyHex);
});

ipcMain.handle("kdrive:unwrapPepperFromDomainKey", (_e, tenantIdHex, ctHex, nonceHex, domainKeyHex) => {
  const rt = initDriveRuntime();
  return rt.unwrapPepperFromDomainKey(tenantIdHex, ctHex, nonceHex, domainKeyHex);
});

// Low-level content encryption (still available for backward compat,
// but pepper should come from the vault via loadTenantPepper)
ipcMain.handle("kdrive:encryptContentFile", (_e, pepperHex, plaintextHex) => {
  const plaintext = Buffer.from(plaintextHex, "hex");
  return kdrive.encryptContentFile(pepperHex, plaintext);
});

ipcMain.handle(
  "kdrive:decryptContentFile",
  (_e, contentKeyHex, contentIdHex, ciphertextsHex, plaintextLens) => {
    const plaintext = kdrive.decryptContentFile(
      contentKeyHex,
      contentIdHex,
      ciphertextsHex,
      plaintextLens.map(Number),
    );
    return Buffer.from(plaintext).toString("hex");
  },
);

ipcMain.handle("kdrive:computeContentId", (_e, plaintextHex, pepperHex) =>
  kdrive.computeContentId(plaintextHex, pepperHex),
);

// --- High-level dedup upload (pepper stays in SDK vault, never exposed to JS) ---

// Gateway URL for dedup endpoints. In production, this comes from config.
const GATEWAY_URL = process.env.KDRIVE_GATEWAY_URL || "http://localhost:8080";

/**
 * Creates 4 synchronous callback functions for the NAPI dedup_upload method.
 * These use Node.js sync HTTP requests (via `sync-rpc` pattern) or, for the
 * sample, we use a simple sync XMLHttpRequest-like approach via `child_process`.
 *
 * For the sample, we use `XMLHttpRequest` via a sync subprocess call.
 * In production, replace with your gateway client.
 */
function createDedupCallbacks(tenantToken) {
  // For the sample, we use sync HTTP via a child process with execFileSync
  // to avoid shell injection. In production, use your async gateway client.
  const { execFileSync } = require("child_process");

  function syncHttpRequest(method, path, body) {
    // Safe: execFileSync does NOT spawn a shell, so no injection risk.
    // Args are passed directly to the curl binary.
    const url = `${GATEWAY_URL}${path}`;
    const args = ["-s", "-X", method, "-H", "Content-Type: application/json",
                  "-H", `Authorization: Bearer ${tenantToken}`];
    if (body) {
      args.push("-d", body);
    }
    args.push(url);
    try {
      return execFileSync("curl", args, { encoding: "utf8", timeout: 30000 });
    } catch (err) {
      throw new Error(`HTTP ${method} ${path} failed: ${err.message}`);
    }
  }

  return {
    checkContentFn: (contentIdHex) => {
      return syncHttpRequest("GET", `/api/v1/content/${contentIdHex}`);
    },
    checkChunksFn: (reqJson) => {
      return syncHttpRequest("POST", "/api/v1/content/chunks/check", reqJson);
    },
    uploadBlobFn: (reqJson) => {
      const req = JSON.parse(reqJson);
      return syncHttpRequest("PUT", `/api/v1/blobs/${req.blob_key}`, req.ciphertext_hex);
    },
    commitVersionFn: (reqJson) => {
      return syncHttpRequest("POST", "/api/v1/uploads/commitDedup", reqJson);
    },
  };
}

ipcMain.handle("kdrive:dedupUpload", (_e, params) => {
  const rt = initDriveRuntime();
  const callbacks = createDedupCallbacks(params.tenantToken || "");

  return rt.dedupUpload(
    params.tenantIdHex,
    params.driveIdHex,
    params.nodeIdHex,
    params.domainIdHex,
    params.privacyMode,
    params.plaintextHex,
    params.creatorDeviceKeyHex,
    params.signingKeyHex,
    params.accessContextRevision,
    params.accessContextSnapshotHashHex,
    params.wrappingKeyHex,
    callbacks.checkContentFn,
    callbacks.checkChunksFn,
    callbacks.uploadBlobFn,
    callbacks.commitVersionFn,
  );
});

app.whenReady().then(createWindow);

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});

app.on("activate", () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});
