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
  // KDRV1 content dedup — SDK-managed pepper
  initTenantPepper: (tenantIdHex) =>
    ipcRenderer.invoke("kdrive:initTenantPepper", tenantIdHex),
  ensureTenantPepper: (tenantIdHex) =>
    ipcRenderer.invoke("kdrive:ensureTenantPepper", tenantIdHex),
  loadTenantPepper: (tenantIdHex) =>
    ipcRenderer.invoke("kdrive:loadTenantPepper", tenantIdHex),
  hasTenantPepper: (tenantIdHex) =>
    ipcRenderer.invoke("kdrive:hasTenantPepper", tenantIdHex),
  storeTenantPepper: (tenantIdHex, pepperHex) =>
    ipcRenderer.invoke("kdrive:storeTenantPepper", tenantIdHex, pepperHex),
  sealPepperForMls: (tenantIdHex, exporterHex, saltHex, domainIdHex, generation, mlsEpoch, treeHashHex, envelopeIdHex) =>
    ipcRenderer.invoke("kdrive:sealPepperForMls", tenantIdHex, exporterHex, saltHex, domainIdHex, generation, mlsEpoch, treeHashHex, envelopeIdHex),
  openPepperFromMls: (tenantIdHex, ctHex, nonceHex, exporterHex, saltHex, domainIdHex, generation, mlsEpoch, treeHashHex, envelopeIdHex) =>
    ipcRenderer.invoke("kdrive:openPepperFromMls", tenantIdHex, ctHex, nonceHex, exporterHex, saltHex, domainIdHex, generation, mlsEpoch, treeHashHex, envelopeIdHex),
  wrapPepperUnderDomainKey: (tenantIdHex, domainKeyHex) =>
    ipcRenderer.invoke("kdrive:wrapPepperUnderDomainKey", tenantIdHex, domainKeyHex),
  unwrapPepperFromDomainKey: (tenantIdHex, ctHex, nonceHex, domainKeyHex) =>
    ipcRenderer.invoke("kdrive:unwrapPepperFromDomainKey", tenantIdHex, ctHex, nonceHex, domainKeyHex),
  // Low-level content encryption (pepper from vault via loadTenantPepper)
  encryptContentFile: (pepperHex, plaintextHex) =>
    ipcRenderer.invoke("kdrive:encryptContentFile", pepperHex, plaintextHex),
  decryptContentFile: (contentKeyHex, contentIdHex, ciphertextsHex, plaintextLens) =>
    ipcRenderer.invoke(
      "kdrive:decryptContentFile",
      contentKeyHex,
      contentIdHex,
      ciphertextsHex,
      plaintextLens,
    ),
  computeContentId: (plaintextHex, pepperHex) =>
    ipcRenderer.invoke("kdrive:computeContentId", plaintextHex, pepperHex),
  // High-level dedup upload — pepper stays in SDK vault, never exposed to JS
  dedupUpload: (params) =>
    ipcRenderer.invoke("kdrive:dedupUpload", params),
});
