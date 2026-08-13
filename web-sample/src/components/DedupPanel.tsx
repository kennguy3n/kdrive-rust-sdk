import { useState, useCallback } from "react";
import { Copy, Check, Database, Zap } from "lucide-react";
import { loadWasm, getRuntime } from "../wasm-loader";
import { formatError } from "../api";

interface DedupResult {
  contentId: string;
  fullyDeduped: boolean;
  chunkCount: number;
  reusedBlobKeys: string[];
  newBlobKeys: string[];
  newCiphertexts: string[];
}

// Demo tenant ID (deterministic 16-byte hex)
const TENANT_ID_HEX = "74656e616e745f64656d6f0000000000";

export function DedupPanel() {
  const [plaintext, setPlaintext] = useState(
    "Dedup test: same content = same ciphertext across modes",
  );
  const [upload1, setUpload1] = useState<DedupResult | null>(null);
  const [upload2, setUpload2] = useState<DedupResult | null>(null);
  const [status, setStatus] = useState<string>("idle");
  const [error, setError] = useState<string | null>(null);

  // In-memory mock gateway for the demo. In production, these would be fetch() calls
  // to the Go gateway's dedup endpoints.
  const mockGateway = useCallback(() => {
    const contentStore = new Map<
      string,
      { blobKeys: string[]; ciphertextHashes: string[]; chunkCount: number }
    >();
    const blobStore = new Map<string, string>(); // blob_key → ciphertext_hex

    return {
      checkContent: (contentIdHex: string) => {
        const entry = contentStore.get(contentIdHex);
        if (entry) {
          return JSON.stringify({
            exists: true,
            blob_keys: entry.blobKeys,
            ciphertext_hashes: entry.ciphertextHashes,
            chunk_count: entry.chunkCount,
            plaintext_size: 0,
          });
        }
        return JSON.stringify({
          exists: false,
          blob_keys: [],
          ciphertext_hashes: [],
          chunk_count: 0,
          plaintext_size: 0,
        });
      },
      checkChunks: (reqJson: string) => {
        const req = JSON.parse(reqJson);
        const entry = contentStore.get(req.content_id);
        const knownHashes = new Set(entry?.ciphertextHashes ?? []);
        const results = req.chunk_hashes.map((h: string) => ({
          hash: h,
          exists: knownHashes.has(h),
          blob_key: entry?.blobKeys[entry.ciphertextHashes.indexOf(h)] ?? null,
        }));
        return JSON.stringify({ results });
      },
      uploadBlob: (reqJson: string) => {
        const req = JSON.parse(reqJson);
        blobStore.set(req.blob_key, req.ciphertext_hex);
        return "";
      },
      commitVersion: (reqJson: string) => {
        const req = JSON.parse(reqJson);
        const reused = req.reused_blob_keys ?? [];
        const newBlobs = req.new_blob_keys ?? [];
        // Register content in the mock store
        const allHashes = [...reused, ...newBlobs];
        contentStore.set(req.content_id_hex, {
          blobKeys: allHashes,
          ciphertextHashes: allHashes,
          chunkCount: allHashes.length,
        });
        return JSON.stringify({
          version_id: "v_" + Math.random().toString(36).slice(2),
          committed: true,
          deduped_chunks: reused.length,
          new_chunks: newBlobs.length,
        });
      },
    };
  }, []);

  const doUpload = useCallback(
    async (which: 1 | 2) => {
      try {
        setError(null);

        const wasm = await loadWasm();
        const runtime = await getRuntime();
        const gateway = mockGateway();

        // Ensure tenant pepper exists in the SDK vault (auto-creates on first call)
        // Pepper is never exposed to JS — it stays in the Rust vault.
        runtime.ensureTenantPepper(TENANT_ID_HEX);

        // Generate demo key material
        const driveId = wasm.random_id_hex();
        const nodeId = wasm.random_id_hex();
        const domainId = wasm.random_id_hex();
        const edKp = JSON.parse(wasm.generate_ed25519_keypair());
        const snapshotHash = wasm.generate_version_dek(); // reuse as 32-byte hash
        const wrappingKey = wasm.generate_version_dek(); // DomainKey or ShareGrantKey

        const ptHex = Array.from(new TextEncoder().encode(plaintext))
          .map((b) => b.toString(16).padStart(2, "0"))
          .join("");

        // Call the SDK's dedup_upload — all dedup logic runs in Rust
        // Pepper is loaded from the vault internally; JS never sees it.
        const callbacks = new wasm.DedupCallbacks(
          gateway.checkContent,
          gateway.checkChunks,
          gateway.uploadBlob,
          gateway.commitVersion,
        );

        const raw = wasm.dedup_upload(
          runtime,
          TENANT_ID_HEX,
          driveId,
          nodeId,
          domainId,
          1, // PrivacyMode::Secured
          ptHex,
          edKp.public_key_hex,
          edKp.private_key_hex,
          BigInt(1), // access_context_revision
          snapshotHash,
          wrappingKey,
          callbacks,
        );

        const r = typeof raw === "string" ? JSON.parse(raw) : raw;
        const result: DedupResult = {
          contentId: r.content_id_hex,
          fullyDeduped: r.fully_deduped,
          chunkCount: Number(r.chunk_count),
          reusedBlobKeys: r.reused_blob_keys,
          newBlobKeys: r.new_blob_keys,
          newCiphertexts: r.new_ciphertexts_hex,
        };

        if (which === 1) {
          setUpload1(result);
          setUpload2(null);
          setStatus("upload #1 complete");
        } else {
          setUpload2(result);
          const isDup = upload1 && upload1.contentId === result.contentId;
          setStatus(
            isDup
              ? result.fullyDeduped
                ? "DEDUPED — zero new chunks uploaded!"
                : "partial dedup — some chunks reused"
              : "no dedup match",
          );
        }
      } catch (err) {
        setError(formatError(err));
        setStatus("error");
      }
    },
    [plaintext, upload1, mockGateway],
  );

  const isDeduped =
    upload1 && upload2 && upload1.contentId === upload2.contentId;

  return (
    <div className="dedup-panel">
      <div className="dedup-header">
        <Database size={20} />
        <h3>Content Deduplication (KDRV1)</h3>
      </div>
      <p className="dedup-desc">
        Upload the same content twice. The SDK's <code>dedup_upload()</code>{" "}
        handles the full flow: content check, chunk check, encryption, and
        manifest construction — all in Rust. The tenant pepper is managed by
        the SDK vault and never exposed to JS.
      </p>

      <div className="dedup-row">
        <label>Plaintext:</label>
        <input
          type="text"
          value={plaintext}
          onChange={(e) => setPlaintext(e.target.value)}
        />
      </div>

      <div className="dedup-row">
        <label>Pepper:</label>
        <span className="dedup-pepper-info">
          SDK-managed vault (auto-initialized, never exposed to JS)
        </span>
      </div>

      <div className="dedup-buttons">
        <button onClick={() => doUpload(1)}>Upload #1</button>
        <button onClick={() => doUpload(2)} disabled={!upload1}>
          Upload #2 (same content)
        </button>
      </div>

      {status && (
        <div className={`dedup-status ${isDeduped ? "deduped" : ""}`}>
          <Zap size={14} />
          {isDeduped && upload2?.fullyDeduped ? (
            <strong>DEDUPED — zero new chunks uploaded!</strong>
          ) : (
            status
          )}
        </div>
      )}

      {error && <div className="dedup-error">{error}</div>}

      {upload1 && (
        <div className="dedup-result">
          <h4>Upload #1</h4>
          <pre>
            Content ID: {upload1.contentId.slice(0, 32)}…{"\n"}
            Chunk count: {upload1.chunkCount}{"\n"}
            New blobs: {upload1.newBlobKeys.length}{"\n"}
            Reused blobs: {upload1.reusedBlobKeys.length}{"\n"}
            Fully deduped: {upload1.fullyDeduped ? "yes" : "no"}
          </pre>
        </div>
      )}

      {upload2 && (
        <div className="dedup-result">
          <h4>Upload #2 (same content)</h4>
          <pre>
            Content ID: {upload2.contentId.slice(0, 32)}…{"\n"}
            Chunk count: {upload2.chunkCount}{"\n"}
            New blobs: {upload2.newBlobKeys.length}{"\n"}
            Reused blobs: {upload2.reusedBlobKeys.length}{"\n"}
            Fully deduped: {upload2.fullyDeduped ? "yes" : "no"}
          </pre>
        </div>
      )}
    </div>
  );
}
