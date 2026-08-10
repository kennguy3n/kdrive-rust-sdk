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

app.whenReady().then(createWindow);

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});

app.on("activate", () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});
