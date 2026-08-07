import { useState, useEffect, useCallback } from "react";
import {
  Shield,
  FolderTree,
  Upload,
  XCircle,
  CheckCircle,
  Key,
  FlaskConical,
  FileLock2,
} from "lucide-react";
import type { DemoUser, Tenant, ScenarioResult } from "./types";
import { DEMO_USERS, DEMO_TENANTS } from "./demo-data";
import { loadWasm } from "./wasm-loader";
import { storeKey, loadKey } from "./vault";
import * as api from "./api";
import { UserSwitcher } from "./components/UserSwitcher";
import { FolderTreeView } from "./components/FolderTree";
import { UploadView } from "./components/UploadView";
import { ScenarioPanel } from "./components/ScenarioPanel";
import { VectorCheck } from "./components/VectorCheck";

export default function App() {
  const [wasmReady, setWasmReady] = useState(false);
  const [wasmError, setWasmError] = useState<string | null>(null);
  const [users, setUsers] = useState<DemoUser[]>([]);
  const [currentUser, setCurrentUser] = useState<DemoUser | null>(null);
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [activeTab, setActiveTab] = useState<
    "folders" | "upload" | "scenarios" | "vectors"
  >("folders");
  const [scenarioResults, setScenarioResults] = useState<ScenarioResult[]>([]);

  // Initialize WASM + generate user key pairs
  useEffect(() => {
    (async () => {
      try {
        const wasm = await loadWasm();
        // Generate Ed25519 key pairs for each demo user (or load from vault)
        const fullUsers: DemoUser[] = [];
        for (const u of DEMO_USERS) {
          let priv = await loadKey(`ed25519_priv_${u.id}`);
          let pubKey = await loadKey(`ed25519_pub_${u.id}`);
          if (!priv || !pubKey) {
            const kp = JSON.parse(wasm.generate_ed25519_keypair());
            priv = kp.private_key_hex;
            pubKey = kp.public_key_hex;
            await storeKey(`ed25519_priv_${u.id}`, priv!);
            await storeKey(`ed25519_pub_${u.id}`, pubKey!);
          }
          fullUsers.push({ ...u, ed25519_priv_hex: priv!, ed25519_pub_hex: pubKey! });
        }
        setUsers(fullUsers);
        if (fullUsers.length > 0) setCurrentUser(fullUsers[0]);
        setWasmReady(true);
      } catch (err) {
        setWasmError(String(err));
      }
    })();
  }, []);

  // Fetch tenants from gateway
  useEffect(() => {
    if (!wasmReady) return;
    api.fetchTenants().then(setTenants).catch(() => {});
  }, [wasmReady]);

  const handleScenarioComplete = useCallback((results: ScenarioResult[]) => {
    setScenarioResults(results);
  }, []);

  if (wasmError) {
    return (
      <div className="error-screen">
        <XCircle size={48} />
        <h2>WASM Load Error</h2>
        <pre>{wasmError}</pre>
        <p>Make sure the WASM pkg is built: <code>wasm-pack build crates/kchat-drive-wasm --target web --out-dir pkg -- --features mls-js</code></p>
      </div>
    );
  }

  if (!wasmReady) {
    return (
      <div className="loading-screen">
        <FileLock2 size={48} className="spin" />
        <h2>Loading KChat Drive WASM…</h2>
      </div>
    );
  }

  return (
    <div className="app">
      <header className="app-header">
        <div className="header-left">
          <Shield size={28} />
          <h1>KChat Drive — Privacy-Mode Web Sample</h1>
        </div>
        <div className="header-right">
          <span className={`status ${wasmReady ? "ok" : "pending"}`}>
            WASM: {wasmReady ? "Ready" : "Loading"}
          </span>
          <span className={`status ${tenants.length > 0 ? "ok" : "pending"}`}>
            Gateway: {tenants.length > 0 ? "Connected" : "Disconnected"}
          </span>
        </div>
      </header>

      <UserSwitcher
        users={users}
        currentUser={currentUser}
        onSelect={setCurrentUser}
        tenants={DEMO_TENANTS}
      />

      <nav className="tabs">
        <button
          className={activeTab === "folders" ? "active" : ""}
          onClick={() => setActiveTab("folders")}
        >
          <FolderTree size={18} /> Folders
        </button>
        <button
          className={activeTab === "upload" ? "active" : ""}
          onClick={() => setActiveTab("upload")}
        >
          <Upload size={18} /> Upload
        </button>
        <button
          className={activeTab === "scenarios" ? "active" : ""}
          onClick={() => setActiveTab("scenarios")}
        >
          <FlaskConical size={18} /> Scenarios
        </button>
        <button
          className={activeTab === "vectors" ? "active" : ""}
          onClick={() => setActiveTab("vectors")}
        >
          <Key size={18} /> Vectors
        </button>
      </nav>

      {currentUser && (
        <div className="tab-context">
          {activeTab === "folders" && `Browsing folders for ${currentUser.label} (${currentUser.tenant_id})`}
          {activeTab === "upload" && `Encrypt and upload files as ${currentUser.label} to a folder in ${currentUser.tenant_id}`}
          {activeTab === "scenarios" && `Running crypto demos as ${currentUser.label} — ${DEMO_TENANTS.find(t => t.id === currentUser.tenant_id)?.type === "b2c" ? "B2C Max-only scenarios" : "B2B all privacy mode scenarios"} for ${currentUser.tenant_id}`}
          {activeTab === "vectors" && "Cross-language test vectors — verifies WASM crypto matches Rust native"}
        </div>
      )}

      <main className="app-main">
        {activeTab === "folders" && currentUser && (
          <FolderTreeView
            tenantId={currentUser.tenant_id}
          />
        )}
        {activeTab === "upload" && currentUser && (
          <UploadView
            userId={currentUser.id}
            tenantId={currentUser.tenant_id}
          />
        )}
        {activeTab === "scenarios" && currentUser && (
          <ScenarioPanel
            userId={currentUser.id}
            tenantId={currentUser.tenant_id}
            tenantType={DEMO_TENANTS.find(t => t.id === currentUser.tenant_id)?.type ?? "b2b"}
            users={users}
            onComplete={handleScenarioComplete}
          />
        )}
        {activeTab === "vectors" && <VectorCheck />}
      </main>

      {scenarioResults.length > 0 && (
        <footer className="scenario-results">
          <h3><CheckCircle size={16} /> Last Scenario Results</h3>
          <div className="results-grid">
            {scenarioResults.map((r, i) => (
              <div key={i} className={`result-card ${r.success ? "success" : "fail"}`}>
                <strong>{r.scenario}</strong>
                <span>{r.success ? "✅ PASS" : "❌ FAIL"}</span>
                <p>{r.details}</p>
              </div>
            ))}
          </div>
        </footer>
      )}
    </div>
  );
}
