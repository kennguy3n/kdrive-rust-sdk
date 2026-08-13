/// <reference types="vite/client" />

declare module "*.wasm" {
  const wasmExport: WasmExports;
  export default wasmExport;
}

/// Structured error thrown by WASM SDK functions.
/// Contains a `code` field (e.g. "Crypto", "NotFound") and a `message` field.
interface DriveSdkError {
  code: string;
  message: string;
}

// --- Result interfaces for JSON returned by WASM functions ---
// These functions return JSON strings (via JsValue::from_str).
// Callers must JSON.parse() the result and can then cast to these interfaces.

interface DomainKeyResult {
  domain_id_hex: string;
  generation: bigint;
  domain_key_hex: string;
  prev_envelope_hex: string | null;
}

interface EncryptFileResult {
  version_id_hex: string;
  chunk_plan_root_hex: string;
  chunk_count: bigint;
  manifest_ciphertext_hex: string;
  manifest_nonce_hex: string;
  header_cbor_hex: string;
  ciphertexts_hex: string[];
}

interface EncryptManifestResult {
  manifest_ciphertext_hex: string;
  manifest_nonce_hex: string;
}

interface DecryptManifestResult {
  version_id_hex: string;
  node_id_hex: string;
  chunk_plan_json: string;
  plaintext_size: bigint;
}

interface SignHeaderResult {
  signature_hex: string;
}

interface RotateDomainKeyResult {
  domain_id_hex: string;
  generation: bigint;
  new_key_hex: string;
  prev_envelope_hex: string;
}

interface ShareGrantKeyResult {
  grant_id_hex: string;
  generation: bigint;
  share_grant_key_hex: string;
  prev_envelope_hex: string | null;
}

interface EncryptContentFileResult {
  chunk_plan: { chunks: ChunkDescriptor[] };
  ciphertexts_hex: string[];
  content_id_hex: string;
  content_key_hex: string;
  chunk_count: bigint;
  blob_keys: string[];
}

interface ChunkDescriptor {
  index: bigint;
  plaintext_len: bigint;
  ciphertext_len: bigint;
  ciphertext_sha256_hex: string;
  blob_key: string;
}

interface DedupUploadResult {
  version_id_hex: string;
  content_id_hex: string;
  chunk_plan_root_hex: string;
  chunk_count: bigint;
  manifest_ciphertext_hex: string;
  manifest_nonce_hex: string;
  header_cbor_hex: string;
  new_ciphertexts_hex: string[];
  all_blob_keys: string[];
  reused_blob_keys: string[];
  new_blob_keys: string[];
  wrapped_dek_hex: string;
  wrap_nonce_hex: string;
  wrapped_content_key_hex: string;
  content_wrap_nonce_hex: string;
  fully_deduped: boolean;
}

interface WasmExports {
  init_panic_hook(): void;
  generate_version_dek(): string;
  generate_domain_key_wasm(domain_id_hex: string): string;
  select_chunk_size(file_size: bigint): bigint;
  chunk_count(file_size: bigint, chunk_size: bigint): bigint;
  encrypt_file_wasm(
    version_dek_hex: string,
    node_id_hex: string,
    version_id_hex: string,
    drive_id_hex: string,
    domain_id_hex: string,
    access_context_revision: bigint,
    access_context_snapshot_hash_hex: string,
    plaintext: Uint8Array,
  ): string;
  decrypt_file_wasm(
    version_dek_hex: string,
    node_id_hex: string,
    version_id_hex: string,
    drive_id_hex: string,
    domain_id_hex: string,
    access_context_revision: bigint,
    access_context_snapshot_hash_hex: string,
    chunk_plan_json: string,
    ciphertexts_hex_json: string,
  ): Uint8Array;
  get_test_vectors_json(): string;
  wrap_dek_under_domain_key(domain_key_hex: string, version_dek_hex: string): string;
  unwrap_dek_from_domain_key(domain_key_hex: string, wrapped_dek_hex: string, wrap_nonce_hex: string): string;
  wrap_dek_under_share_grant_key(share_grant_key_hex: string, version_dek_hex: string): string;
  unwrap_dek_from_share_grant_key(share_grant_key_hex: string, wrapped_dek_hex: string, wrap_nonce_hex: string): string;
  encrypt_manifest_wasm(version_dek_hex: string, node_id_hex: string, version_id_hex: string, manifest_cbor_hex: string): string;
  decrypt_manifest_wasm(version_dek_hex: string, node_id_hex: string, version_id_hex: string, manifest_ct_hex: string, manifest_nonce_hex: string): string;
  sign_header_wasm(header_cbor_hex: string, signing_key_hex: string): string;
  verify_header_wasm(header_cbor_hex: string, verifying_key_hex: string): boolean;
  rotate_domain_key_wasm(current_key_hex: string, domain_id_hex: string, current_generation: bigint): string;
  generate_share_grant_key_wasm(grant_id_hex: string, recipients_json: string, user_snapshot_hash_hex: string, mls_epoch: bigint, mls_tree_hash_hex: string): string;
  generate_hpke_keypair(): string;
  generate_ed25519_keypair(): string;
  random_id_hex(): string;
  sha256_hex(data: Uint8Array): string;
  encrypt_content_file(tenant_pepper_hex: string, plaintext_hex: string): string;
  decrypt_content_file(
    content_key_hex: string,
    content_id_hex: string,
    ciphertexts_hex_json: string,
    plaintext_lens_json: string,
  ): Uint8Array;
  compute_content_id(plaintext_hex: string, tenant_pepper_hex: string): string;
  dedup_upload(
    runtime: WasmDriveRuntime,
    tenant_id_hex: string,
    drive_id_hex: string,
    node_id_hex: string,
    domain_id_hex: string,
    privacy_mode: number,
    plaintext_hex: string,
    creator_device_key_hex: string,
    signing_key_hex: string,
    access_context_revision: bigint,
    access_context_snapshot_hash_hex: string,
    wrapping_key_hex: string,
    callbacks: DedupCallbacks,
  ): string;
}

/// Persistent WASM Drive runtime with SDK-managed vault + pepper.
declare class WasmDriveRuntime {
  constructor();
  static withMasterKey(master_key_hex: string): WasmDriveRuntime;
  initTenantPepper(tenant_id_hex: string): string;
  loadTenantPepper(tenant_id_hex: string): string;
  ensureTenantPepper(tenant_id_hex: string): string;
  storeTenantPepper(tenant_id_hex: string, pepper_hex: string): void;
  hasTenantPepper(tenant_id_hex: string): boolean;
  exportMasterKey(): string;
  sealPepperForMls(
    tenant_id_hex: string,
    mls_exporter_output_hex: string,
    transport_salt_hex: string,
    domain_id_hex: string,
    generation: bigint,
    mls_epoch: bigint,
    mls_tree_hash_hex: string,
    envelope_id_hex: string,
  ): string;
  openPepperFromMls(
    tenant_id_hex: string,
    ciphertext_hex: string,
    nonce_hex: string,
    mls_exporter_output_hex: string,
    transport_salt_hex: string,
    domain_id_hex: string,
    generation: bigint,
    mls_epoch: bigint,
    mls_tree_hash_hex: string,
    envelope_id_hex: string,
  ): string;
  wrapPepperUnderDomainKey(tenant_id_hex: string, domain_key_hex: string): string;
  unwrapPepperFromDomainKey(
    tenant_id_hex: string,
    ciphertext_hex: string,
    nonce_hex: string,
    domain_key_hex: string,
  ): void;
  createDomain(domain_id_hex: string): string;
}

/// Callbacks for dedup transport operations.
/// Each callback receives a string argument and returns a string (or void for upload_blob).
declare class DedupCallbacks {
  constructor(
    check_content_fn: (contentIdHex: string) => string,
    check_chunks_fn: (requestJson: string) => string,
    upload_blob_fn: (requestJson: string) => void,
    commit_version_fn: (requestJson: string) => string,
  );
}
