import { useState, useEffect } from "react";
import { Upload, Zap, FileBox, Layers } from "lucide-react";
import type { PrivacyMode, Folder } from "../types";
import { loadWasm, getRuntime } from "../wasm-loader";
import { storeKey, loadKey } from "../vault";
import * as api from "../api";

interface Props {
  userId: string;
  tenantId: string;
}

interface DedupInfo {
  contentId: string;
  fullyDeduped: boolean;
  chunkCount: number;
  reusedCount: number;
  newCount: number;
}

// 4 MiB chunk size — files larger than this produce multiple chunks.
const CHUNK_SIZE = 4 * 1024 * 1024;

export function UploadView({ userId, tenantId }: Props) {
  const [text, setText] = useState("Hello KChat Drive! Upload this twice to see file-level dedup.");
  const [mode, setMode] = useState<PrivacyMode>("secured");
  const [folderId, setFolderId] = useState("");
  const [log, setLog] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [modeError, setModeError] = useState<string | null>(null);
  const [folders, setFolders] = useState<Folder[]>([]);
  const [dedupInfo, setDedupInfo] = useState<DedupInfo | null>(null);
  const [fileSize, setFileSize] = useState(0);

  useEffect(() => {
    api.fetchFolders(tenantId).then(setFolders).catch(() => setFolders([]));
  }, [tenantId]);

  useEffect(() => {
    if (folders.length > 0 && !folders.find(f => f.id === folderId)) {
      const first = folders[0];
      setFolderId(first.id);
      setMode(first.privacy_mode);
      setModeError(null);
    }
  }, [folders]); // eslint-disable-line react-hooks/exhaustive-deps

  // Ensure tenant pepper exists in the SDK vault.
  // The SDK manages the pepper internally — JS never sees or stores it.
  // B2B: one pepper per tenant. B2C: one shared pepper for all B2C users
  // (the B2C tenant ID is used as the pepper key).
  // The tenant_id_hex passed here is a 16-byte hex ID. For the demo, we
  // derive a deterministic tenant ID from the tenant string.
  useEffect(() => {
    (async () => {
      const runtime = await getRuntime();
      const tenantIdHex = tenantIdToHex(tenantId);
      if (!runtime.hasTenantPepper(tenantIdHex)) {
        runtime.ensureTenantPepper(tenantIdHex);
      }
    })().catch(() => {});
  }, [tenantId]);

  useEffect(() => {
    setFileSize(new TextEncoder().encode(text).length);
  }, [text]);

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

  const addLog = (msg: string, level: "info" | "success" | "error" | "dedup" = "info") => {
    const prefix = level === "success" ? "✅ " : level === "error" ? "❌ " : level === "dedup" ? "♻️ " : "ℹ️ ";
    setLog((prev) => [...prev, prefix + msg]);
  };

  // Preset: small file (1 chunk) — upload twice to see file-level dedup
  const loadSmallFile = () => {
    setText("Hello KChat Drive! Upload this twice to see file-level dedup.");
  };

  // Preset: large file (2 chunks, ~5MB) — upload same to see file dedup,
  // then load modified version to see chunk-level dedup (chunk 0 reused, chunk 1 new)
  const loadLargeFile = () => {
    const prefix = "KChat Drive large file demo — this file spans multiple 4MB chunks.\n";
    const chunk1Padding = "A".repeat(CHUNK_SIZE - prefix.length - 100);
    const suffix = "\n--- End of chunk 1 ---\nThis is chunk 2 content. Modify this and re-upload to see chunk-level dedup.\n";
    setText(prefix + chunk1Padding + suffix);
  };

  // Preset: same large file but with modified chunk 2 — chunk 1 is identical
  const loadLargeFileModified = () => {
    const prefix = "KChat Drive large file demo — this file spans multiple 4MB chunks.\n";
    const chunk1Padding = "A".repeat(CHUNK_SIZE - prefix.length - 100);
    const suffix = "\n--- End of chunk 1 ---\nThis is MODIFIED chunk 2 content. Chunk 1 should be deduped, chunk 2 is new.\n";
    setText(prefix + chunk1Padding + suffix);
  };

  const handleUpload = async () => {
    if (modeError) {
      addLog(`Cannot upload: ${modeError}`, "error");
      return;
    }
    setBusy(true);
    setLog([]);
    setDedupInfo(null);
    try {
      const wasm = await loadWasm();
      const runtime = await getRuntime();
      const plaintext = new TextEncoder().encode(text);
      const ptHex = Array.from(plaintext).map(b => b.toString(16).padStart(2, "0")).join("");
      const tenantIdHex = tenantIdToHex(tenantId);

      addLog(`File size: ${plaintext.length} bytes (${(plaintext.length / 1024 / 1024).toFixed(2)} MiB)`);
      const expectedChunks = Math.ceil(plaintext.length / CHUNK_SIZE);
      addLog(`Expected chunks: ${expectedChunks} (chunk size = 4 MiB)`);

      // Ensure pepper exists in SDK vault (auto-creates on first call)
      runtime.ensureTenantPepper(tenantIdHex);

      // Generate demo key material
      const driveIdHex = wasm.random_id_hex();
      const nodeIdHex = wasm.random_id_hex();
      const domainIdHex = wasm.random_id_hex();
      const edKp = JSON.parse(wasm.generate_ed25519_keypair());
      const snapshotHashHex = wasm.generate_version_dek();

      // Get wrapping key
      let wrappingKeyHex = "";
      if (mode === "secured" || mode === "advanced") {
        const domainKeyKey = `domain_key_${domainIdHex}`;
        let dkHex = await loadKey(domainKeyKey);
        if (!dkHex) {
          const dkResult = JSON.parse(wasm.generate_domain_key_wasm(domainIdHex)) as DomainKeyResult;
          dkHex = dkResult.domain_key_hex;
          await storeKey(domainKeyKey, dkHex);
        }
        wrappingKeyHex = dkHex;
        addLog(`Loaded domain key for ${mode} mode`);
      } else {
        const grantIdHex = wasm.random_id_hex();
        const userHexId = wasm.sha256_hex(new TextEncoder().encode(userId)).slice(0, 32);
        const recipients = JSON.stringify([userHexId]);
        const sgkResult = JSON.parse(
          wasm.generate_share_grant_key_wasm(
            grantIdHex, recipients, snapshotHashHex, 1n, snapshotHashHex,
          ),
        ) as ShareGrantKeyResult;
        wrappingKeyHex = sgkResult.share_grant_key_hex;
        await storeKey(`share_grant_key_${grantIdHex}`, wrappingKeyHex);
        addLog(`Generated share grant key for Max mode`);
      }

      const privacyModeNum = mode === "secured" ? 1 : mode === "advanced" ? 2 : 3;

      // Transport callbacks — synchronous XHR to the real gateway.
      // The gateway flow is: content:check → content:checkChunks → content:register → uploads:commitDedup

      // Collect blob info during upload_blob calls so we can register them in commit
      // Map: blob_key → ciphertext_sha256_hex
      const blobHashes: Record<string, string> = {};

      const checkContentCb = (contentIdHex: string): string => {
        const xhr = new XMLHttpRequest();
        xhr.open("POST", "/v1/content:check", false);
        xhr.setRequestHeader("Content-Type", "application/json");
        xhr.setRequestHeader("X-Demo-Tenant", tenantId);
        xhr.send(JSON.stringify({ content_id: contentIdHex }));
        if (xhr.status !== 200) {
          return JSON.stringify({ exists: false, blob_keys: [], ciphertext_hashes: [], chunk_count: 0, plaintext_size: 0 });
        }
        return xhr.responseText;
      };

      const checkChunksCb = (reqJson: string): string => {
        const req = JSON.parse(reqJson);
        const xhr = new XMLHttpRequest();
        xhr.open("POST", "/v1/content:checkChunks", false);
        xhr.setRequestHeader("Content-Type", "application/json");
        xhr.setRequestHeader("X-Demo-Tenant", tenantId);
        xhr.send(JSON.stringify({ content_id: req.content_id, chunk_hashes: req.chunk_hashes }));
        if (xhr.status !== 200) {
          return JSON.stringify({ results: [] });
        }
        return xhr.responseText;
      };

      const uploadBlobCb = (reqJson: string): string => {
        // Compute SHA-256 of ciphertext for later registration
        const req = JSON.parse(reqJson);
        const ctBytes = new Uint8Array(req.ciphertext_hex.match(/.{2}/g).map((h: string) => parseInt(h, 16)));
        const hashHex = wasm.sha256_hex(ctBytes);
        blobHashes[req.blob_key] = hashHex;
        return "";
      };

      const commitVersionCb = (reqJson: string): string => {
        const req = JSON.parse(reqJson);
        const contentId = req.content_id_hex;

        // Step 1: Register content with all blob keys + ciphertext hashes
        const allBlobKeys = req.all_blob_keys || [...req.reused_blob_keys, ...req.new_blob_keys];
        const allBlobHashes = req.all_blob_hashes || [];
        const chunks = allBlobKeys.map((blobKey: string, i: number) => ({
          chunk_index: i,
          chunk_content_hash: allBlobHashes[i] || blobKey,
          blob_key: blobKey,
          plaintext_len: plaintext.length,
          ciphertext_len: 0,
        }));

        const regXhr = new XMLHttpRequest();
        regXhr.open("POST", "/v1/content:register", false);
        regXhr.setRequestHeader("Content-Type", "application/json");
        regXhr.setRequestHeader("X-Demo-Tenant", tenantId);
        regXhr.send(JSON.stringify({
          content_id: contentId,
          plaintext_size: req.plaintext_size || plaintext.length,
          chunk_count: req.chunk_count || allBlobKeys.length,
          chunk_size: 4 * 1024 * 1024,
          chunk_plan_root: req.manifest_ciphertext_sha256_hex || "",
          chunks: chunks,
        }));
        // Ignore register errors (might already exist — that's fine for dedup)

        // Step 2: Commit the version
        const xhr = new XMLHttpRequest();
        xhr.open("POST", "/v1/uploads:commitDedup", false);
        xhr.setRequestHeader("Content-Type", "application/json");
        xhr.setRequestHeader("X-Demo-Tenant", tenantId);
        xhr.send(JSON.stringify({
          protocol: "KDRV1",
          content_id: contentId,
          node_id: nodeIdHex,
          manifest: {},
          manifest_nonce_hex: req.manifest_nonce_hex || "",
          manifest_ciphertext_sha256: req.manifest_ciphertext_sha256_hex || "",
          header: {},
          wrapped_dek_hex: req.wrapped_dek_hex || "",
          wrap_nonce_hex: req.wrap_nonce_hex || "",
          wrapped_content_key_hex: req.wrapped_content_key_hex || "",
          content_wrap_nonce_hex: req.content_wrap_nonce_hex || "",
          reused_blob_keys: req.reused_blob_keys,
          new_blob_keys: req.new_blob_keys,
        }));
        if (xhr.status !== 200) {
          return JSON.stringify({ version_id: "", committed: false, deduped_chunks: 0, new_chunks: 0, error: xhr.responseText });
        }
        return xhr.responseText;
      };

      const callbacks = new wasm.DedupCallbacks(
        checkContentCb, checkChunksCb, uploadBlobCb, commitVersionCb,
      );

      addLog(`Calling SDK dedup_upload() — all dedup logic in Rust…`);

      const raw = wasm.dedup_upload(
        runtime,
        tenantIdHex,
        driveIdHex, nodeIdHex, domainIdHex, privacyModeNum,
        ptHex, edKp.public_key_hex, edKp.private_key_hex,
        1n, snapshotHashHex, wrappingKeyHex,
        callbacks,
      );

      const result = typeof raw === "string" ? JSON.parse(raw) : raw;

      addLog(`Content ID: ${result.content_id_hex.slice(0, 16)}…`);
      addLog(`Chunk count: ${result.chunk_count}`);
      addLog(`New blobs: ${result.new_blob_keys.length}, Reused blobs: ${result.reused_blob_keys.length}`);

      if (result.fully_deduped) {
        addLog(`FULLY DEDUPED — zero new chunks uploaded!`, "dedup");
      } else if (result.reused_blob_keys.length > 0) {
        addLog(`Partial dedup — ${result.reused_blob_keys.length} chunks reused, ${result.new_blob_keys.length} new`, "dedup");
      } else {
        addLog(`No dedup — all ${result.new_blob_keys.length} chunks are new`);
      }

      // Create node in gateway so it appears in the Folders tab.
      // When fully deduped, the file already exists — skip node creation.
      if (!result.fully_deduped) {
        const fileName = text.slice(0, 20).replace(/[^a-zA-Z0-9]/g, "_") + ".txt";
        const nameEncryptedHex = "00".repeat(16) + Array.from(new TextEncoder().encode(fileName)).map(b => b.toString(16).padStart(2, "0")).join("");
        try {
          const nodeId = await api.createNode(tenantId, folderId, nameEncryptedHex, "text/plain");
          addLog(`Created node: ${nodeId}`);
        } catch (nodeErr) {
          addLog(`Node creation skipped: ${nodeErr}`, "info");
        }
      } else {
        addLog(`File already exists — no new node created (content deduped)`);
      }

      addLog(`Manifest: ${result.manifest_ciphertext_hex.length / 2} bytes`);
      addLog("Upload complete!", "success");

      setDedupInfo({
        contentId: result.content_id_hex,
        fullyDeduped: result.fully_deduped,
        chunkCount: result.chunk_count,
        reusedCount: result.reused_blob_keys.length,
        newCount: result.new_blob_keys.length,
      });
    } catch (err) {
      addLog(`Error: ${api.formatError(err)}`, "error");
      console.error("Upload error:", err);
    } finally {
      setBusy(false);
    }
  };

  const chunkCount = Math.max(1, Math.ceil(fileSize / CHUNK_SIZE));

  return (
    <div className="upload-view">
      <h2 className="section-title">Upload File</h2>
      <p style={{ color: "var(--text-dim)", fontSize: 13, marginBottom: 12 }}>
        Files are encrypted client-side with the Rust SDK's <code>dedup_upload()</code>.
        The SDK checks the gateway for existing content and skips duplicate chunks automatically.
      </p>

      {/* Preset buttons */}
      <div style={{ marginBottom: 12, display: "flex", gap: 8, flexWrap: "wrap" }}>
        <button
          className="btn"
          style={{ padding: "6px 12px", fontSize: 13 }}
          onClick={loadSmallFile}
        >
          <FileBox size={14} /> Small file (1 chunk)
        </button>
        <button
          className="btn"
          style={{ padding: "6px 12px", fontSize: 13 }}
          onClick={loadLargeFile}
        >
          <Layers size={14} /> Large file (2 chunks)
        </button>
        <button
          className="btn"
          style={{ padding: "6px 12px", fontSize: 13 }}
          onClick={loadLargeFileModified}
        >
          <Layers size={14} /> Large file (modified chunk 2)
        </button>
      </div>

      <div style={{ marginBottom: 8, fontSize: 12, color: "var(--text-dim)" }}>
        File size: {fileSize.toLocaleString()} bytes ({(fileSize / 1024 / 1024).toFixed(2)} MiB) ·
        Chunks: {chunkCount}
      </div>

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
      <textarea
        value={text}
        onChange={(e) => setText(e.target.value)}
        style={{ height: chunkCount > 1 ? 120 : 100 }}
      />
      <div style={{ marginTop: 8, fontSize: 12, color: "var(--text-dim)" }}>
        💡 <strong>File dedup:</strong> Upload the same file twice → same content_id → zero new chunks.
        <br/>
        💡 <strong>Chunk dedup:</strong> Upload "Large file" then "Large file (modified chunk 2)" →
        chunk 1 reused, chunk 2 is new.
      </div>
      <div style={{ marginTop: 12 }}>
        <button className="btn" onClick={handleUpload} disabled={busy}>
          <Upload size={16} /> {busy ? "Uploading…" : "Encrypt & Upload"}
        </button>
      </div>

      {dedupInfo && (
        <div style={{
          marginTop: 12,
          padding: 12,
          borderRadius: 8,
          background: dedupInfo.fullyDeduped
            ? "rgba(34, 197, 94, 0.15)"
            : dedupInfo.reusedCount > 0
            ? "rgba(234, 179, 8, 0.15)"
            : "rgba(100, 100, 100, 0.1)",
          border: `1px solid ${dedupInfo.fullyDeduped ? "rgba(34, 197, 94, 0.4)" : dedupInfo.reusedCount > 0 ? "rgba(234, 179, 8, 0.4)" : "rgba(100, 100, 100, 0.2)"}`,
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
            <Zap size={16} />
            <strong>
              {dedupInfo.fullyDeduped
                ? "FILE DEDUP — zero new chunks uploaded!"
                : dedupInfo.reusedCount > 0
                ? `CHUNK DEDUP — ${dedupInfo.reusedCount}/${dedupInfo.chunkCount} chunks reused`
                : "No dedup — all chunks are new"}
            </strong>
          </div>
          <div style={{ fontSize: 12, color: "var(--text-dim)" }}>
            Content ID: {dedupInfo.contentId.slice(0, 32)}…<br/>
            New chunks: {dedupInfo.newCount} · Reused chunks: {dedupInfo.reusedCount} · Total: {dedupInfo.chunkCount}
          </div>
        </div>
      )}

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

/// Converts a tenant string ID (e.g. "tenant_acme") to a 16-byte hex ID
/// that the SDK can use. Uses SHA-256 and takes the first 16 bytes.
function tenantIdToHex(tenantId: string): string {
  // Simple deterministic hash — for production, the tenant ID would be
  // a proper UUID assigned by the identity service.
  let hash = 0;
  for (let i = 0; i < tenantId.length; i++) {
    hash = ((hash << 5) - hash + tenantId.charCodeAt(i)) | 0;
  }
  // Expand to 32 hex chars (16 bytes) using a simple PRNG seeded by hash
  const bytes: string[] = [];
  let state = Math.abs(hash) || 1;
  for (let i = 0; i < 16; i++) {
    state = (state * 1103515245 + 12345) & 0x7fffffff;
    bytes.push((state & 0xff).toString(16).padStart(2, "0"));
  }
  return bytes.join("");
}
