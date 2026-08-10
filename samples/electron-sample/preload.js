// Preload script — exposes a safe kdrive API to the renderer via contextBridge.
const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("kdrive", {
  generateVersionDek: () => ipcRenderer.invoke("kdrive:generateVersionDek"),
  generateEd25519Keypair: () =>
    ipcRenderer.invoke("kdrive:generateEd25519Keypair"),
  generateHpkeKeypair: () => ipcRenderer.invoke("kdrive:generateHpkeKeypair"),
  randomIdHex: () => ipcRenderer.invoke("kdrive:randomIdHex"),
  selectChunkSize: (fileSize) =>
    ipcRenderer.invoke("kdrive:selectChunkSize", fileSize),
  chunkCount: (fileSize, chunkSize) =>
    ipcRenderer.invoke("kdrive:chunkCount", fileSize, chunkSize),
  encryptFile: (
    versionDekHex,
    nodeIdHex,
    versionIdHex,
    driveIdHex,
    domainIdHex,
    accessContextRevision,
    snapshotHashHex,
    plaintextHex,
  ) =>
    ipcRenderer.invoke(
      "kdrive:encryptFile",
      versionDekHex,
      nodeIdHex,
      versionIdHex,
      driveIdHex,
      domainIdHex,
      accessContextRevision,
      snapshotHashHex,
      plaintextHex,
    ),
  decryptFile: (
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
  ) =>
    ipcRenderer.invoke(
      "kdrive:decryptFile",
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
    ),
  getTestVectors: () => ipcRenderer.invoke("kdrive:getTestVectors"),
});
