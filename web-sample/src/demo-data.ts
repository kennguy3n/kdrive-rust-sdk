import type { DemoUser } from "./types";

// Demo users — 1 B2C zone + 3 B2B tenants, each with owner/member/latejoiner/admin.
// Ed25519 key pairs are generated at startup and stored in IndexedDB.
export const DEMO_TENANTS = [
  { id: "tenant_b2c", label: "B2C Zone", type: "b2c" as const },
  { id: "tenant_acme", label: "Acme Corp", type: "b2b" as const },
  { id: "tenant_globex", label: "Globex", type: "b2b" as const },
  { id: "tenant_initech", label: "Initech", type: "b2b" as const },
];

export const DEMO_USERS: Omit<DemoUser, "ed25519_priv_hex" | "ed25519_pub_hex">[] = [
  // B2C zone — Max only
  { id: "user_b2c_alice", label: "Alice (B2C Owner)", tenant_id: "tenant_b2c", role: "owner" },
  { id: "user_b2c_bob", label: "Bob (B2C Member)", tenant_id: "tenant_b2c", role: "member" },

  // Acme Corp
  { id: "user_acme_owner", label: "Alice (Acme Owner)", tenant_id: "tenant_acme", role: "owner" },
  { id: "user_acme_member", label: "Bob (Acme Member)", tenant_id: "tenant_acme", role: "member" },
  { id: "user_acme_latejoiner", label: "Charlie (Acme Late Joiner)", tenant_id: "tenant_acme", role: "latejoiner" },
  { id: "user_acme_admin", label: "Dana (Acme Admin)", tenant_id: "tenant_acme", role: "admin" },

  // Globex
  { id: "user_globex_owner", label: "Eve (Globex Owner)", tenant_id: "tenant_globex", role: "owner" },
  { id: "user_globex_member", label: "Frank (Globex Member)", tenant_id: "tenant_globex", role: "member" },
  { id: "user_globex_admin", label: "Grace (Globex Admin)", tenant_id: "tenant_globex", role: "admin" },

  // Initech
  { id: "user_initech_owner", label: "Heidi (Initech Owner)", tenant_id: "tenant_initech", role: "owner" },
  { id: "user_initech_member", label: "Ivan (Initech Member)", tenant_id: "tenant_initech", role: "member" },
  { id: "user_initech_admin", label: "Judy (Initech Admin)", tenant_id: "tenant_initech", role: "admin" },
];

export interface Scenario {
  id: number;
  title: string;
  description: string;
  tenants: ("b2b" | "b2c")[];
}

export const SCENARIOS: Scenario[] = [
  {
    id: 1,
    title: "Upload in each privacy mode",
    description:
      "Upload the same file to Secured, Advanced, and Max folders. Observe how the DEK wrapping differs: domain-wrap (Secured/Advanced) vs share-grant-wrap (Max).",
    tenants: ["b2b"],
  },
  {
    id: 2,
    title: "New user joins — history access",
    description:
      "A late joiner attempts to read an existing version. In Secured mode, the domain key chain allows backward walking. In Max mode, the new user only gets future versions.",
    tenants: ["b2b"],
  },
  {
    id: 3,
    title: "Admin recovery attempt",
    description:
      "An admin attempts to recover a deleted version. Secured: domain key available → can decrypt. Advanced/Max: no domain key → cannot decrypt.",
    tenants: ["b2b"],
  },
  {
    id: 4,
    title: "User removed — can't read new versions",
    description:
      "After a user is removed from the MLS group, they attempt to read a new version. In all modes, the removed user lacks the current epoch key and cannot decrypt.",
    tenants: ["b2b", "b2c"],
  },
  {
    id: 5,
    title: "B2C zone — Max only",
    description:
      "The B2C zone enforces Max mode. Attempting to upload in Secured or Advanced mode should be rejected by the client.",
    tenants: ["b2c"],
  },
  {
    id: 6,
    title: "Cross-language vector check",
    description:
      "Fetch test vectors from the Rust SDK (WASM) and the Go gateway. Verify byte-equality of ciphertexts, hashes, and signatures.",
    tenants: ["b2b", "b2c"],
  },
];
