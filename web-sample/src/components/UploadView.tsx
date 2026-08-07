import { useState, useEffect } from "react";
import { Upload } from "lucide-react";
import type { PrivacyMode, EncryptResult, WrapResult, Folder } from "../types";
import { loadWasm } from "../wasm-loader";
import { storeKey, loadKey } from "../vault";
import * as api from "../api";

interface Props {
  userId: string;
  tenantId: string;
}

export function UploadView({ userId, tenantId }: Props) {
  const [text, setText] = useState("Hello KChat Drive! This is a test file.");
  const [mode, setMode] = useState<PrivacyMode>("secured");
  const [folderId, setFolderId] = useState("");
  const [log, setLog] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [modeError, setModeError] = useState<string | null>(null);
  const [folders, setFolders] = useState<Folder[]>([]);

  // Fetch folders for this tenant on mount / tenant change
  useEffect(() => {
    api.fetchFolders(tenantId).then(setFolders).catch(() => setFolders([]));
  }, [tenantId]);

  // Auto-select first folder when folders load
  useEffect(() => {
    if (folders.length > 0 && !folders.find(f => f.id === folderId)) {
      const first = folders[0];
      setFolderId(first.id);
      setMode(first.privacy_mode);
      setModeError(null);
    }
  }, [folders]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleModeChange = (newMode: PrivacyMode) => {
    setMode(newMode);
    const folder = folders.find(f => f.id === folderId);
    if (folder && folder.privacy_mode !== newMode) {
      setModeError(`Selected mode (${newMode}) does not match folder's privacy mode (${folder.privacy_mode})`);
    } else {
      setModeError(null);
    }
  };

  const handleFolderChange = (newFolderId: string) => {
    setFolderId(newFolderId);
    const folder = folders.find(f => f.id === newFolderId);
    if (folder) {
      setMode(folder.privacy_mode);
      setModeError(null);
    }
  };

  const addLog = (msg: string, level: "info" | "success" | "error" = "info") => {
    const prefix = level === "success" ? "✅ " : level === "error" ? "❌ " : "ℹ️ ";
    setLog((prev) => [...prev, prefix + msg]);
  };

  const handleUpload = async () => {
    if (modeError) {
      addLog(`Cannot upload: ${modeError}`, "error");
      return;
    }
    setBusy(true);
    setLog([]);
    try {
      const wasm = await loadWasm();
      const plaintext = new TextEncoder().encode(text);

      // 1. Generate VersionDEK
      const versionDekHex = wasm.generate_version_dek();
      addLog(`Generated VersionDEK: ${versionDekHex.slice(0, 16)}…`);

      // 2. Generate IDs
      const nodeIdHex = wasm.random_id_hex();
      const versionIdHex = wasm.random_id_hex();
      const driveIdHex = wasm.random_id_hex();
      const domainIdHex = wasm.random_id_hex();

      // 3. Encrypt the file
      const snapshotHashHex = wasm.sha256_hex(new Uint8Array(32));
      const encryptResult: EncryptResult = JSON.parse(
        wasm.encrypt_file_wasm(
          versionDekHex,
          nodeIdHex,
          versionIdHex,
          driveIdHex,
          domainIdHex,
          1n, // access_context_revision
          snapshotHashHex,
          plaintext,
        ),
      );
      addLog(`Encrypted ${plaintext.length} bytes → ${encryptResult.chunkCount} chunks, root=${encryptResult.chunkPlanRoot.slice(0, 16)}…`);

      // 4. Wrap DEK based on privacy mode
      let wrappedDekHex = "";
      let wrapNonceHex = "";
      let wrappingKeyHex = "";

      if (mode === "secured" || mode === "advanced") {
        // Generate or load domain key
        const domainKeyKey = `domain_key_${domainIdHex}`;
        let domainKeyHex = await loadKey(domainKeyKey);
        if (!domainKeyHex) {
          const dkResult = JSON.parse(wasm.generate_domain_key_wasm(domainIdHex));
          domainKeyHex = dkResult.domain_key_hex;
          await storeKey(domainKeyKey, domainKeyHex!);
        }
        wrappingKeyHex = domainKeyHex!;
        const wrapResult: WrapResult = JSON.parse(
          wasm.wrap_dek_under_domain_key(domainKeyHex!, versionDekHex),
        );
        wrappedDekHex = wrapResult.wrapped_dek_hex;
        wrapNonceHex = wrapResult.wrap_nonce_hex;
        addLog(`Wrapped DEK under domain key (${mode} mode)`);
      } else {
        // Max mode: wrap under share grant key
        const grantIdHex = wasm.random_id_hex();
        const userHexId = wasm.sha256_hex(new TextEncoder().encode(userId)).slice(0, 32);
        const recipients = JSON.stringify([userHexId]);
        const sgkResult = JSON.parse(
          wasm.generate_share_grant_key_wasm(
            grantIdHex,
            recipients,
            snapshotHashHex,
            1n, // mls_epoch
            snapshotHashHex, // mls_tree_hash (demo: reuse snapshot hash)
          ),
        );
        wrappingKeyHex = sgkResult.share_grant_key_hex;
        await storeKey(`share_grant_key_${grantIdHex}`, wrappingKeyHex);
        const wrapResult: WrapResult = JSON.parse(
          wasm.wrap_dek_under_share_grant_key(wrappingKeyHex, versionDekHex),
        );
        wrappedDekHex = wrapResult.wrapped_dek_hex;
        wrapNonceHex = wrapResult.wrap_nonce_hex;
        addLog(`Wrapped DEK under share grant key (Max mode)`);
      }

      // 5. Create node on gateway
      const fileName = text.slice(0, 20).replace(/[^a-zA-Z0-9]/g, "_") + ".txt";
      const nameEncryptedHex = "00".repeat(16) + Array.from(new TextEncoder().encode(fileName)).map(b => b.toString(16).padStart(2, "0")).join("");
      const nodeId = await api.createNode(tenantId, folderId, nameEncryptedHex, "text/plain");
      addLog(`Created node: ${nodeId}`);

      // 6. Initiate upload session
      const sessionId = await api.initiateUpload(tenantId, {
        node_id: nodeId,
        folder_id: folderId,
        chunk_plan: encryptResult,
        manifest: {},
        header: {},
        wrapped_dek_hex: wrappedDekHex,
        wrap_nonce_hex: wrapNonceHex,
      });
      addLog(`Upload session: ${sessionId}`);

      // 7. Register each chunk
      for (let i = 0; i < encryptResult.ciphertexts.length; i++) {
        const blobKey = await api.registerChunk(tenantId, sessionId, i, {
          ciphertext_hex: encryptResult.ciphertexts[i],
          ciphertext_sha256: encryptResult.chunks[i].ciphertext_sha256,
          plaintext_len: encryptResult.chunks[i].plaintext_len,
          ciphertext_len: encryptResult.chunks[i].ciphertext_len,
        });
        addLog(`Registered chunk ${i} → blob_key: ${blobKey}`);
      }

      // 8. Verify round-trip: decrypt locally
      const decrypted = wasm.decrypt_file_wasm(
        versionDekHex,
        nodeIdHex,
        versionIdHex,
        driveIdHex,
        domainIdHex,
        1n,
        snapshotHashHex,
        JSON.stringify(encryptResult),
        JSON.stringify(encryptResult.ciphertexts),
      );
      const decryptedText = new TextDecoder().decode(decrypted);
      const roundTripOk = decryptedText === text;
      addLog(
        `Round-trip decrypt: ${roundTripOk ? "MATCH" : "MISMATCH"}`,
        roundTripOk ? "success" : "error",
      );

      // 9. Verify DEK unwrap
      if (mode === "secured" || mode === "advanced") {
        const unwrappedDekHex = wasm.unwrap_dek_from_domain_key(
          wrappingKeyHex,
          wrappedDekHex,
          wrapNonceHex,
        );
        addLog(
          `DEK unwrap: ${unwrappedDekHex === versionDekHex ? "MATCH" : "MISMATCH"}`,
          unwrappedDekHex === versionDekHex ? "success" : "error",
        );
      } else {
        const unwrappedDekHex = wasm.unwrap_dek_from_share_grant_key(
          wrappingKeyHex,
          wrappedDekHex,
          wrapNonceHex,
        );
        addLog(
          `DEK unwrap: ${unwrappedDekHex === versionDekHex ? "MATCH" : "MISMATCH"}`,
          unwrappedDekHex === versionDekHex ? "success" : "error",
        );
      }

      addLog("Upload complete!", "success");
    } catch (err) {
      addLog(`Error: ${err}`, "error");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="upload-view">
      <h2 className="section-title">Upload File</h2>
      <p style={{ color: "var(--text-dim)", fontSize: 13, marginBottom: 12 }}>
        Files are encrypted client-side with WASM before upload. The privacy mode is determined by the folder you select — each folder has a fixed mode. After upload, check the Folders tab to see your uploaded file.
      </p>
      <div className="field-row">
        <label>Privacy Mode:</label>
        <select value={mode} onChange={(e) => handleModeChange(e.target.value as PrivacyMode)}>
          <option value="secured">Secured</option>
          <option value="advanced">Advanced</option>
          <option value="max">Max</option>
        </select>
      </div>
      <div className="field-row">
        <label>Folder:</label>
        <select value={folderId} onChange={(e) => handleFolderChange(e.target.value)}>
          {folders.length === 0 && <option value="" disabled>Loading folders…</option>}
          {folders.map((f) => (
            <option key={f.id} value={f.id}>
              {f.id} ({f.privacy_mode})
            </option>
          ))}
        </select>
      </div>
      {modeError && (
        <div className="field-row" style={{ color: "var(--error)" }}>
          ⚠️ {modeError}
        </div>
      )}
      <div className="field-row">
        <label>File content:</label>
      </div>
      <textarea value={text} onChange={(e) => setText(e.target.value)} />
      <div>
        <button className="btn" onClick={handleUpload} disabled={busy}>
          <Upload size={16} /> {busy ? "Uploading…" : "Encrypt & Upload"}
        </button>
      </div>
      {log.length > 0 && (
        <div className="log-output">
          {log.map((entry, i) => (
            <div key={i} className="log-entry">
              {entry}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
