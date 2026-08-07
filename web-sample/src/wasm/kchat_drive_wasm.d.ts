/* tslint:disable */
/* eslint-disable */

/**
 * WASM-exposed high-level Drive API.
 * These functions wrap the crypto operations and return JSON for JS consumption.
 */
export class WasmDriveRuntime {
    free(): void;
    [Symbol.dispose](): void;
    create_domain(domain_id_hex: string): string;
    constructor();
}

export function chunk_count(file_size: bigint, chunk_size: bigint): bigint;

export function decrypt_file_wasm(version_dek_hex: string, node_id_hex: string, version_id_hex: string, drive_id_hex: string, domain_id_hex: string, access_context_revision: bigint, access_context_snapshot_hash_hex: string, chunk_plan_json: string, ciphertexts_hex_json: string): Uint8Array;

export function decrypt_manifest_wasm(version_dek_hex: string, node_id_hex: string, version_id_hex: string, manifest_ct_hex: string, manifest_nonce_hex: string): string;

export function encrypt_file_wasm(version_dek_hex: string, node_id_hex: string, version_id_hex: string, drive_id_hex: string, domain_id_hex: string, access_context_revision: bigint, access_context_snapshot_hash_hex: string, plaintext: Uint8Array): any;

export function encrypt_manifest_wasm(version_dek_hex: string, node_id_hex: string, version_id_hex: string, manifest_cbor_hex: string): any;

export function generate_domain_key_wasm(domain_id_hex: string): any;

export function generate_ed25519_keypair(): any;

export function generate_hpke_keypair(): any;

export function generate_share_grant_key_wasm(grant_id_hex: string, recipients_json: string, user_snapshot_hash_hex: string, mls_epoch: bigint, mls_tree_hash_hex: string): any;

/**
 * WASM-exposed crypto operations for KChat Drive.
 * These are the browser-callable functions for KDRV1 encryption/decryption.
 */
export function generate_version_dek(): string;

export function get_test_vectors_json(): string;

export function random_id_hex(): string;

export function rotate_domain_key_wasm(current_key_hex: string, domain_id_hex: string, current_generation: bigint): any;

export function select_chunk_size(file_size: bigint): bigint;

export function sha256_hex(data: Uint8Array): string;

export function sign_header_wasm(header_cbor_hex: string, signing_key_hex: string): any;

export function unwrap_dek_from_domain_key(domain_key_hex: string, wrapped_dek_hex: string, wrap_nonce_hex: string): string;

export function unwrap_dek_from_share_grant_key(share_grant_key_hex: string, wrapped_dek_hex: string, wrap_nonce_hex: string): string;

export function verify_header_wasm(header_cbor_hex: string, verifying_key_hex: string): boolean;

export function wrap_dek_under_domain_key(domain_key_hex: string, version_dek_hex: string): any;

export function wrap_dek_under_share_grant_key(share_grant_key_hex: string, version_dek_hex: string): any;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly chunk_count: (a: bigint, b: bigint) => bigint;
    readonly decrypt_file_wasm: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: bigint, l: number, m: number, n: number, o: number, p: number, q: number) => [number, number, number, number];
    readonly decrypt_manifest_wasm: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => [number, number, number, number];
    readonly encrypt_file_wasm: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: bigint, l: number, m: number, n: number, o: number) => [number, number, number];
    readonly encrypt_manifest_wasm: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number];
    readonly generate_domain_key_wasm: (a: number, b: number) => [number, number, number];
    readonly generate_share_grant_key_wasm: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint, h: number, i: number) => [number, number, number];
    readonly generate_version_dek: () => [number, number];
    readonly get_test_vectors_json: () => [number, number];
    readonly rotate_domain_key_wasm: (a: number, b: number, c: number, d: number, e: bigint) => [number, number, number];
    readonly select_chunk_size: (a: bigint) => bigint;
    readonly sign_header_wasm: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly unwrap_dek_from_domain_key: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly unwrap_dek_from_share_grant_key: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly verify_header_wasm: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly wrap_dek_under_domain_key: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly wrap_dek_under_share_grant_key: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly __wbg_wasmdriveruntime_free: (a: number, b: number) => void;
    readonly generate_ed25519_keypair: () => [number, number, number];
    readonly generate_hpke_keypair: () => [number, number, number];
    readonly random_id_hex: () => [number, number];
    readonly sha256_hex: (a: number, b: number) => [number, number];
    readonly wasmdriveruntime_create_domain: (a: number, b: number, c: number) => [number, number, number, number];
    readonly wasmdriveruntime_new: () => number;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
