import { useState, useEffect } from "react";
import { Key, CheckCircle, XCircle } from "lucide-react";
import { loadWasm } from "../wasm-loader";
import * as api from "../api";

export function VectorCheck() {
  const [rustVectors, setRustVectors] = useState<string>("");
  const [goVectors, setGoVectors] = useState<string>("");
  const [matchResult, setMatchResult] = useState<string>("");
  const [busy, setBusy] = useState(false);

  const runCheck = async () => {
    setBusy(true);
    try {
      const wasm = await loadWasm();
      const rustJson = wasm.get_test_vectors_json();
      const rustParsed = JSON.parse(rustJson);
      setRustVectors(JSON.stringify(rustParsed, null, 2));

      try {
        const goJson = await api.fetchVectors();
        setGoVectors(JSON.stringify(goJson, null, 2));

        const protocolMatch = rustParsed.protocol === goJson.protocol;
        const versionMatch = rustParsed.version === goJson.version;
        setMatchResult(
          `Protocol: ${protocolMatch ? "MATCH" : "MISMATCH"} (${rustParsed.protocol} vs ${goJson.protocol})\n` +
          `Version: ${versionMatch ? "MATCH" : "MISMATCH"} (${rustParsed.version} vs ${goJson.version})`,
        );
      } catch {
        setGoVectors("(Gateway not reachable)");
        setMatchResult("Gateway not reachable — showing Rust vectors only.");
      }
    } catch (err) {
      setMatchResult(`Error: ${err}`);
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    runCheck();
  }, []);

  return (
    <div className="vector-check">
      <h2 className="section-title">Cross-Language Test Vectors</h2>
      <p style={{ color: "var(--text-dim)", marginBottom: 12 }}>
        Verifies byte-equality of KDRV1 protocol vectors between the Rust SDK (WASM) and the Go gateway.
      </p>
      <button className="btn" onClick={runCheck} disabled={busy}>
        <Key size={16} /> {busy ? "Checking…" : "Re-run Vector Check"}
      </button>

      {matchResult && (
        <div className="result-card" style={{ marginTop: 12 }}>
          <pre style={{ whiteSpace: "pre-wrap" }}>{matchResult}</pre>
        </div>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
        <div>
          <h3 style={{ fontSize: 14, marginBottom: 8 }}>Rust SDK (WASM)</h3>
          <div className="vector-output">{rustVectors || "Loading…"}</div>
        </div>
        <div>
          <h3 style={{ fontSize: 14, marginBottom: 8 }}>Go Gateway</h3>
          <div className="vector-output">{goVectors || "Loading…"}</div>
        </div>
      </div>
    </div>
  );
}
