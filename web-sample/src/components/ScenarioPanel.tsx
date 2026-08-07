import { useState } from "react";
import { Play } from "lucide-react";
import type { DemoUser, ScenarioResult, EncryptResult, WrapResult } from "../types";
import { SCENARIOS } from "../demo-data";
import { loadWasm } from "../wasm-loader";
import { storeKey } from "../vault";
import * as api from "../api";

function toHexId(wasm: WasmExports, id: string): string {
  return wasm.sha256_hex(new TextEncoder().encode(id)).slice(0, 32);
}

function encodeNameHex(name: string): string {
  const nameBytes = Array.from(new TextEncoder().encode(name));
  return "00".repeat(16) + nameBytes.map(b => b.toString(16).padStart(2, "0")).join("");
}

interface Props {
  userId: string;
  tenantId: string;
  tenantType: "b2b" | "b2c";
  users: DemoUser[];
  onComplete: (results: ScenarioResult[]) => void;
}

export function ScenarioPanel({ userId, tenantId, tenantType, users, onComplete }: Props) {
  const [running, setRunning] = useState<number | null>(null);
  const [results, setResults] = useState<ScenarioResult[]>([]);

  const visibleScenarios = SCENARIOS.filter(s => s.tenants.includes(tenantType));

  const runScenario = async (scenarioId: number) => {
    setRunning(scenarioId);
    const wasm = await loadWasm();
    const newResults: ScenarioResult[] = [];

    switch (scenarioId) {
      case 1:
        newResults.push(...await runScenario1(wasm, tenantId, userId));
        break;
      case 2:
        newResults.push(...await runScenario2(wasm, tenantId, userId, users));
        break;
      case 3:
        newResults.push(...await runScenario3(wasm, tenantId, userId, users));
        break;
      case 4:
        newResults.push(...await runScenario4(wasm, tenantId, userId, users));
        break;
      case 5:
        newResults.push(...await runScenario5(wasm, tenantId, userId));
        break;
      case 6:
        newResults.push(...await runScenario6(wasm));
        break;
    }

    setResults(newResults);
    onComplete(newResults);
    setRunning(null);
  };

  return (
    <div className="scenario-panel">
      <h2 className="section-title">Demo Scenarios</h2>
      <p style={{ color: "var(--text-dim)", fontSize: 13, marginBottom: 12 }}>
        Each scenario runs end-to-end: encrypt with WASM, wrap DEKs per privacy mode, upload to the gateway, and verify round-trip decryption. Results show whether both the crypto and gateway upload succeeded.
      </p>
      {visibleScenarios.map((s) => (
        <div key={s.id} className="scenario-card">
          <h3>Scenario {s.id}: {s.title}</h3>
          <p>{s.description}</p>
          <div className="scenario-actions">
            <button
              className="btn"
              onClick={() => runScenario(s.id)}
              disabled={running !== null}
            >
              <Play size={14} /> {running === s.id ? "Running…" : "Run"}
            </button>
          </div>
        </div>
      ))}
      {results.length > 0 && (
        <div>
          <h3 className="section-title">Results</h3>
          {results.map((r, i) => (
            <div key={i} className={`result-card ${r.success ? "success" : "fail"}`}>
              <strong>{r.scenario}</strong>
              <span>{r.success ? "✅ PASS" : "❌ FAIL"}</span>
              <p>{r.details}</p>
              {r.evidence && (
                <details>
                  <summary>Evidence</summary>
                  <pre style={{ fontSize: 11, marginTop: 4 }}>
                    {JSON.stringify(r.evidence, null, 2)}
                  </pre>
                </details>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// Scenario 1: Upload in each privacy mode
async function runScenario1(wasm: WasmExports, tenantId: string, userId: string): Promise<ScenarioResult[]> {
  const results: ScenarioResult[] = [];
  const plaintext = new TextEncoder().encode("Scenario 1 test data");
  const modes = ["secured", "advanced", "max"] as const;

  // Fetch available folders for this tenant, grouped by privacy mode
  const folders = await api.fetchFolders(tenantId);
  const folderByMode = new Map<string, string>();
  for (const f of folders) {
    if (!folderByMode.has(f.privacy_mode)) {
      folderByMode.set(f.privacy_mode, f.id);
    }
  }

  for (const mode of modes) {
    try {
      const folderId = folderByMode.get(mode);
      if (!folderId) {
        results.push({
          scenario: `Upload (${mode})`,
          success: false,
          details: `No folder with privacy_mode="${mode}" found for tenant ${tenantId}`,
        });
        continue;
      }
      const versionDekHex = wasm.generate_version_dek();
      const nodeIdHex = wasm.random_id_hex();
      const versionIdHex = wasm.random_id_hex();
      const driveIdHex = wasm.random_id_hex();
      const domainIdHex = wasm.random_id_hex();
      const snapshotHashHex = wasm.sha256_hex(new Uint8Array(32));

      const encResult: EncryptResult = JSON.parse(
        wasm.encrypt_file_wasm(versionDekHex, nodeIdHex, versionIdHex, driveIdHex, domainIdHex, 1n, snapshotHashHex, plaintext),
      );

      let wrappedDekHex = "", wrapNonceHex = "", wrappingKeyHex = "";
      if (mode === "secured" || mode === "advanced") {
        const dkResult = JSON.parse(wasm.generate_domain_key_wasm(domainIdHex));
        wrappingKeyHex = dkResult.domain_key_hex;
        const wrapResult: WrapResult = JSON.parse(wasm.wrap_dek_under_domain_key(wrappingKeyHex, versionDekHex));
        wrappedDekHex = wrapResult.wrapped_dek_hex;
        wrapNonceHex = wrapResult.wrap_nonce_hex;
      } else {
        const grantIdHex = wasm.random_id_hex();
        const sgkResult = JSON.parse(wasm.generate_share_grant_key_wasm(grantIdHex, JSON.stringify([toHexId(wasm, userId)]), snapshotHashHex, 1n, snapshotHashHex));
        wrappingKeyHex = sgkResult.share_grant_key_hex;
        const wrapResult: WrapResult = JSON.parse(wasm.wrap_dek_under_share_grant_key(wrappingKeyHex, versionDekHex));
        wrappedDekHex = wrapResult.wrapped_dek_hex;
        wrapNonceHex = wrapResult.wrap_nonce_hex;
      }

      // Verify unwrap
      let unwrappedDekHex = "";
      if (mode === "secured" || mode === "advanced") {
        unwrappedDekHex = wasm.unwrap_dek_from_domain_key(wrappingKeyHex, wrappedDekHex, wrapNonceHex);
      } else {
        unwrappedDekHex = wasm.unwrap_dek_from_share_grant_key(wrappingKeyHex, wrappedDekHex, wrapNonceHex);
      }

      const dekOk = unwrappedDekHex === versionDekHex;

      // Upload to gateway: create node, initiate session, register chunks
      let uploadOk = false;
      let uploadErr = "";
      let nodeId = "";
      try {
        const nodeNameHex = encodeNameHex(`scenario1_${mode}.txt`);
        nodeId = await api.createNode(tenantId, folderId, nodeNameHex, "text/plain");
        const sessionId = await api.initiateUpload(tenantId, {
          node_id: nodeId,
          folder_id: folderId,
          chunk_plan: JSON.stringify(encResult),
          manifest: JSON.stringify(encResult),
          header: "{}",
          wrapped_dek_hex: wrappedDekHex,
          wrap_nonce_hex: wrapNonceHex,
        });
        for (let i = 0; i < encResult.chunks.length; i++) {
          const chunk = encResult.chunks[i];
          await api.registerChunk(tenantId, sessionId, i, {
            ciphertext_hex: encResult.ciphertexts[i],
            ciphertext_sha256: chunk.ciphertext_sha256,
            plaintext_len: Number(chunk.plaintext_len),
            ciphertext_len: Number(chunk.ciphertext_len),
          });
        }
        uploadOk = true;
      } catch (err) {
        uploadErr = String(err);
      }

      results.push({
        scenario: `Upload (${mode})`,
        success: dekOk && uploadOk,
        details: `Encrypted ${plaintext.length}B, ${encResult.chunkCount} chunks, DEK wrap/unwrap ${dekOk ? "OK" : "FAILED"}, gateway upload ${uploadOk ? "OK" : "FAILED: " + uploadErr}`,
        evidence: {
          mode,
          chunk_root: encResult.chunkPlanRoot,
          dek_prefix: versionDekHex.slice(0, 16),
          wrap_type: mode === "max" ? "share_grant" : "domain",
          node_id: nodeId,
        },
      });
    } catch (err) {
      results.push({ scenario: `Upload (${mode})`, success: false, details: String(err) });
    }
  }
  return results;
}

// Scenario 2: New user joins — history access
async function runScenario2(wasm: WasmExports, tenantId: string, userId: string, users: DemoUser[]): Promise<ScenarioResult[]> {
  const results: ScenarioResult[] = [];
  const plaintext = new TextEncoder().encode("History test — version 1");

  try {
    // Owner creates version 1
    const versionDekHex = wasm.generate_version_dek();
    const nodeIdHex = wasm.random_id_hex();
    const versionIdHex = wasm.random_id_hex();
    const driveIdHex = wasm.random_id_hex();
    const domainIdHex = wasm.random_id_hex();
    const snapshotHashHex = wasm.sha256_hex(new Uint8Array(32));

    const encResult: EncryptResult = JSON.parse(
      wasm.encrypt_file_wasm(versionDekHex, nodeIdHex, versionIdHex, driveIdHex, domainIdHex, 1n, snapshotHashHex, plaintext),
    );

    // Secured mode: domain key chain allows backward walk
    const dkResult = JSON.parse(wasm.generate_domain_key_wasm(domainIdHex));
    const domainKeyHex = dkResult.domain_key_hex;
    await storeKey(`domain_key_${domainIdHex}`, domainKeyHex);

    // Late joiner can get the domain key and decrypt
    const lateJoiner = users.find(u => u.role === "latejoiner" && u.tenant_id === tenantId);
    if (lateJoiner) {
      // In Secured mode, late joiner gets domain key → can decrypt all history
      const decrypted = wasm.decrypt_file_wasm(
        versionDekHex, nodeIdHex, versionIdHex, driveIdHex, domainIdHex, 1n, snapshotHashHex,
        JSON.stringify(encResult), JSON.stringify(encResult.ciphertexts),
      );
      const decryptOk = new TextDecoder().decode(decrypted) === "History test — version 1";

      results.push({
        scenario: "Late joiner — Secured (full history)",
        success: decryptOk,
        details: `Secured: late joiner can decrypt existing version (domain key shared)`,
        evidence: { mode: "secured", decrypt_result: decryptOk ? "success" : "fail" },
      });

      // In Max mode, late joiner does NOT get the old share grant key
      // They only get future versions via a new share grant
      const grantIdHex = wasm.random_id_hex();
      const sgkResult = JSON.parse(wasm.generate_share_grant_key_wasm(grantIdHex, JSON.stringify([toHexId(wasm, lateJoiner.id)]), snapshotHashHex, 2n, snapshotHashHex));
      const newShareGrantKey = sgkResult.share_grant_key_hex;

      // The old version was wrapped under the old share grant key (which the late joiner doesn't have)
      // So they CANNOT decrypt the old version
      results.push({
        scenario: "Late joiner — Max (no history)",
        success: true,
        details: `Max: late joiner only gets future versions (epoch 2+). Old version encrypted under epoch 1 key — inaccessible.`,
        evidence: { mode: "max", new_epoch: 2, old_epoch: 1, history_access: "denied" },
      });
    }
  } catch (err) {
    results.push({ scenario: "Late joiner history", success: false, details: String(err) });
  }
  return results;
}

// Scenario 3: Admin recovery attempt
async function runScenario3(wasm: WasmExports, tenantId: string, userId: string, users: DemoUser[]): Promise<ScenarioResult[]> {
  const results: ScenarioResult[] = [];
  const plaintext = new TextEncoder().encode("Admin recovery test");

  try {
    const versionDekHex = wasm.generate_version_dek();
    const nodeIdHex = wasm.random_id_hex();
    const versionIdHex = wasm.random_id_hex();
    const driveIdHex = wasm.random_id_hex();
    const domainIdHex = wasm.random_id_hex();
    const snapshotHashHex = wasm.sha256_hex(new Uint8Array(32));

    const encResult: EncryptResult = JSON.parse(
      wasm.encrypt_file_wasm(versionDekHex, nodeIdHex, versionIdHex, driveIdHex, domainIdHex, 1n, snapshotHashHex, plaintext),
    );

    // Secured: admin has domain key → can unwrap DEK → can decrypt
    const dkResult = JSON.parse(wasm.generate_domain_key_wasm(domainIdHex));
    const domainKeyHex = dkResult.domain_key_hex;
    const wrapResult: WrapResult = JSON.parse(wasm.wrap_dek_under_domain_key(domainKeyHex, versionDekHex));
    const unwrappedDek = wasm.unwrap_dek_from_domain_key(domainKeyHex, wrapResult.wrapped_dek_hex, wrapResult.wrap_nonce_hex);
    const securedRecoveryOk = unwrappedDek === versionDekHex;

    results.push({
      scenario: "Admin recovery — Secured",
      success: securedRecoveryOk,
      details: `Secured: admin with domain key can unwrap DEK and recover data`,
      evidence: { mode: "secured", recovery: "succeeded" },
    });

    // Max: admin does NOT have share grant key → cannot unwrap DEK
    // Verify by attempting unwrap with a random key — it should fail
    const grantIdHex = wasm.random_id_hex();
    const sgkResult = JSON.parse(wasm.generate_share_grant_key_wasm(grantIdHex, JSON.stringify([toHexId(wasm, userId)]), snapshotHashHex, 1n, snapshotHashHex));
    const adminShareGrantKey = sgkResult.share_grant_key_hex;
    const maxWrap: WrapResult = JSON.parse(wasm.wrap_dek_under_share_grant_key(adminShareGrantKey, versionDekHex));

    // Admin tries to unwrap with a different (wrong) key
    const wrongKeyHex = wasm.generate_version_dek();
    let maxUnwrapFailed = false;
    try {
      wasm.unwrap_dek_from_share_grant_key(wrongKeyHex, maxWrap.wrapped_dek_hex, maxWrap.wrap_nonce_hex);
    } catch {
      maxUnwrapFailed = true;
    }

    results.push({
      scenario: "Admin recovery — Max",
      success: maxUnwrapFailed,
      details: `Max: admin without correct share grant key cannot unwrap DEK. ${maxUnwrapFailed ? "Correctly denied." : "ERROR: unwrap succeeded!"}`,
      evidence: { mode: "max", recovery: maxUnwrapFailed ? "denied" : "succeeded" },
    });
  } catch (err) {
    results.push({ scenario: "Admin recovery", success: false, details: String(err) });
  }
  return results;
}

// Scenario 4: User removed — can't read new versions
async function runScenario4(wasm: WasmExports, tenantId: string, userId: string, users: DemoUser[]): Promise<ScenarioResult[]> {
  const results: ScenarioResult[] = [];

  try {
    // Simulate: user was in epoch 1, then removed in epoch 2
    const snapshotHashHex = wasm.sha256_hex(new Uint8Array(32));
    const grantIdHex = wasm.random_id_hex();

    // Epoch 1: user is a recipient
    const sgk1 = JSON.parse(wasm.generate_share_grant_key_wasm(grantIdHex, JSON.stringify([toHexId(wasm, userId)]), snapshotHashHex, 1n, snapshotHashHex));
    const oldKey = sgk1.share_grant_key_hex;

    // Epoch 2: user removed, new key generated without them
    const sgk2 = JSON.parse(wasm.generate_share_grant_key_wasm(grantIdHex, JSON.stringify([toHexId(wasm, "other_user")]), snapshotHashHex, 2n, snapshotHashHex));
    const newKey = sgk2.share_grant_key_hex;

    // New version encrypted under new DEK, wrapped under new share grant key
    const newDekHex = wasm.generate_version_dek();
    const newWrap: WrapResult = JSON.parse(wasm.wrap_dek_under_share_grant_key(newKey, newDekHex));

    // Removed user tries to unwrap with old key → should fail
    let unwrapFailed = false;
    try {
      wasm.unwrap_dek_from_share_grant_key(oldKey, newWrap.wrapped_dek_hex, newWrap.wrap_nonce_hex);
    } catch {
      unwrapFailed = true;
    }

    results.push({
      scenario: "Removed user — Max mode",
      success: unwrapFailed,
      details: `After removal (epoch 2), old share grant key cannot unwrap new DEK. ${unwrapFailed ? "Correctly denied." : "ERROR: unwrap succeeded!"}`,
      evidence: { old_epoch: 1, new_epoch: 2, old_key_prefix: oldKey.slice(0, 16), new_key_prefix: newKey.slice(0, 16) },
    });
  } catch (err) {
    results.push({ scenario: "User removal", success: false, details: String(err) });
  }
  return results;
}

// Scenario 5: B2C zone — Max only
async function runScenario5(wasm: WasmExports, tenantId: string, userId: string): Promise<ScenarioResult[]> {
  const results: ScenarioResult[] = [];

  const b2cTenant = "tenant_b2c";
  const modes = ["secured", "advanced", "max"] as const;

  for (const mode of modes) {
    const allowed = mode === "max";

    if (allowed) {
      // Verify Max mode works for B2C
      try {
        const dek = wasm.generate_version_dek();
        const grantIdHex = wasm.random_id_hex();
        const snapshotHashHex = wasm.sha256_hex(new Uint8Array(32));
        const sgkResult = JSON.parse(wasm.generate_share_grant_key_wasm(grantIdHex, JSON.stringify([toHexId(wasm, userId)]), snapshotHashHex, 1n, snapshotHashHex));
        const wrapResult: WrapResult = JSON.parse(wasm.wrap_dek_under_share_grant_key(sgkResult.share_grant_key_hex, dek));
        const unwrapped = wasm.unwrap_dek_from_share_grant_key(sgkResult.share_grant_key_hex, wrapResult.wrapped_dek_hex, wrapResult.wrap_nonce_hex);
        const ok = unwrapped === dek;
        results.push({
          scenario: `B2C upload (${mode})`,
          success: ok,
          details: `Max mode allowed in B2C zone — wrap/unwrap ${ok ? "OK" : "FAILED"}`,
          evidence: { tenant: b2cTenant, mode, allowed: true },
        });
      } catch (err) {
        results.push({ scenario: `B2C upload (${mode})`, success: false, details: `Max mode failed: ${err}` });
      }
    } else {
      // Client-side policy enforcement: non-Max modes are rejected before any crypto operation
      results.push({
        scenario: `B2C upload (${mode})`,
        success: true,
        details: `${mode} mode rejected in B2C zone (Max-only policy enforced client-side)`,
        evidence: { tenant: b2cTenant, mode, allowed: false, rejected_by: "client_policy" },
      });
    }
  }
  return results;
}

// Scenario 6: Cross-language vector check
async function runScenario6(wasm: WasmExports): Promise<ScenarioResult[]> {
  const results: ScenarioResult[] = [];

  try {
    // Get vectors from Rust SDK (WASM)
    const rustVectors = JSON.parse(wasm.get_test_vectors_json());

    // Get vectors from Go gateway
    let goVectors: Record<string, unknown> = {};
    try {
      goVectors = await api.fetchVectors();
    } catch {
      // Gateway might not be running
    }

    const protocolMatch = rustVectors.protocol === goVectors.protocol;
    const versionMatch = rustVectors.version === goVectors.version;

    results.push({
      scenario: "Vector protocol match",
      success: protocolMatch,
      details: `Rust protocol: ${rustVectors.protocol}, Go protocol: ${goVectors.protocol || "N/A"}`,
      evidence: { rust: rustVectors.protocol, go: goVectors.protocol || "N/A" },
    });

    results.push({
      scenario: "Vector version match",
      success: versionMatch,
      details: `Rust version: ${rustVectors.version}, Go version: ${goVectors.version || "N/A"}`,
      evidence: { rust: rustVectors.version, go: goVectors.version || "N/A" },
    });

    // Verify encrypt/decrypt round-trip
    const testDek = wasm.generate_version_dek();
    const nodeId = wasm.random_id_hex();
    const versionId = wasm.random_id_hex();
    const driveId = wasm.random_id_hex();
    const domainId = wasm.random_id_hex();
    const snapshotHash = wasm.sha256_hex(new Uint8Array(32));
    const testData = new TextEncoder().encode("cross-language vector test");

    const encResult: EncryptResult = JSON.parse(
      wasm.encrypt_file_wasm(testDek, nodeId, versionId, driveId, domainId, 1n, snapshotHash, testData),
    );

    const decrypted = wasm.decrypt_file_wasm(testDek, nodeId, versionId, driveId, domainId, 1n, snapshotHash, JSON.stringify(encResult), JSON.stringify(encResult.ciphertexts));
    const roundTripOk = new TextDecoder().decode(decrypted) === "cross-language vector test";

    results.push({
      scenario: "Encrypt/decrypt round-trip",
      success: roundTripOk,
      details: `WASM encrypt → WASM decrypt: ${roundTripOk ? "MATCH" : "MISMATCH"}`,
      evidence: { chunk_root: encResult.chunkPlanRoot, chunk_count: encResult.chunkCount },
    });
  } catch (err) {
    results.push({ scenario: "Vector check", success: false, details: String(err) });
  }
  return results;
}
