export type PrivacyMode = "secured" | "advanced" | "max";

export interface Tenant {
  id: string;
  pool_id: string;
  privacy_mode: string;
  tenant_type: "b2b" | "b2c";
  bucket_name: string;
}

export interface Folder {
  id: string;
  tenant_id: string;
  parent_folder_id: string;
  name_encrypted: string;
  privacy_mode: PrivacyMode;
  created_at: string;
}

export interface Node {
  id: string;
  tenant_id: string;
  folder_id: string;
  name_encrypted: string;
  mime_type: string;
  created_at: string;
  updated_at: string;
}

export interface DemoUser {
  id: string;
  label: string;
  tenant_id: string;
  role: "owner" | "member" | "latejoiner" | "admin";
  ed25519_priv_hex: string;
  ed25519_pub_hex: string;
}

export interface ChunkDescriptor {
  index: number;
  plaintext_len: number;
  ciphertext_len: number;
  ciphertext_sha256: string;
  blob_key: string;
}

export interface EncryptResult {
  chunkPlanRoot: string;
  chunkCount: number;
  ciphertexts: string[];
  chunks: ChunkDescriptor[];
}

export interface WrapResult {
  wrapped_dek_hex: string;
  wrap_nonce_hex: string;
}

export interface SignResult {
  signed_header_cbor_hex: string;
  signature_hex: string;
  verifying_key_hex: string;
}

export interface ScenarioResult {
  scenario: string;
  success: boolean;
  details: string;
  evidence?: Record<string, unknown>;
}
