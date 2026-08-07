/// <reference types="vite/client" />

declare module "*.wasm" {
  const wasmExport: WasmExports;
  export default wasmExport;
}

interface WasmExports {
  generate_version_dek(): string;
  generate_domain_key_wasm(domain_id_hex: string): any;
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
  ): any;
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
  encrypt_manifest_wasm(version_dek_hex: string, node_id_hex: string, version_id_hex: string, manifest_cbor_hex: string): any;
  decrypt_manifest_wasm(version_dek_hex: string, node_id_hex: string, version_id_hex: string, manifest_ct_hex: string, manifest_nonce_hex: string): any;
  sign_header_wasm(header_cbor_hex: string, signing_key_hex: string): any;
  verify_header_wasm(header_cbor_hex: string, verifying_key_hex: string): boolean;
  rotate_domain_key_wasm(current_key_hex: string, domain_id_hex: string, current_generation: bigint): any;
  generate_share_grant_key_wasm(grant_id_hex: string, recipients_json: string, user_snapshot_hash_hex: string, mls_epoch: bigint, mls_tree_hash_hex: string): any;
  generate_hpke_keypair(): string;
  generate_ed25519_keypair(): string;
  random_id_hex(): string;
  sha256_hex(data: Uint8Array): string;
}
