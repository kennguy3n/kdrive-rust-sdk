# KChat Drive — Electron Sample

A minimal Electron app that loads the KChat Drive NAPI-RS native addon and
demonstrates the KDRV1 crypto pipeline (key generation, encrypt/decrypt
round-trip, cross-language test vectors).

## Prerequisites

- Node.js 18+
- The NAPI addon must be built:
  ```bash
  cd crates/kchat-drive-napi
  napi build --platform --release --output-dir ./dist
  ```

## Run

```bash
cd samples/electron-sample
npm install
npm start
```

This launches an Electron window with three sections:

1. **Key Generation** — generate VersionDEK, Ed25519, and HPKE keypairs
   via the native addon.
2. **Encrypt / Decrypt Round-Trip** — type plaintext, click the button,
   and the app runs the full KDRV1 pipeline (encrypt → manifest → decrypt)
   through the NAPI addon and verifies the round-trip.
3. **Cross-Language Test Vectors** — fetches the KDRV1 test vectors from
   the Rust SDK for cross-language verification with the Go gateway.

## Architecture

```
┌──────────────────────────────────────────────┐
│  Electron Renderer (index.html + <script>)    │
│                                               │
│  window.kdrive.* (contextBridge)              │
└──────────────────┬───────────────────────────┘
                   │ IPC (ipcRenderer.invoke)
┌──────────────────▼───────────────────────────┐
│  Electron Main (main.js)                      │
│                                               │
│  ipcMain.handle("kdrive:…")                   │
│  → require("kchat-drive-napi")                │
└──────────────────┬───────────────────────────┘
                   │ N-API native call
┌──────────────────▼───────────────────────────┐
│  kchat-drive.darwin-arm64.node                │
│  (Rust crypto core, compiled via NAPI-RS)     │
└──────────────────────────────────────────────┘
```

The renderer never touches the native addon directly — all calls go
through the preload script's `contextBridge` and the main process's
`ipcMain` handlers. This keeps `nodeIntegration: false` and
`contextIsolation: true` for security.
