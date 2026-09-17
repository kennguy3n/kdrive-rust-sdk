/* tslint:disable */
/* eslint-disable */

/**
 * JS callbacks for dedup transport operations.
 * Each callback is a JS function that receives a JSON string and returns a JSON string.
 * Callbacks must be synchronous — if you need async I/O, pre-fetch the data before
 * calling dedup_upload.
 */
export class DedupCallbacks {
    free(): void;
    [Symbol.dispose](): void;
    constructor(check_content_fn: Function, check_chunks_fn: Function, upload_blob_fn: Function, commit_version_fn: Function);
}

/**
 * Persistent WASM Drive runtime.
 *
 * Wraps `ClientRuntime` + `DriveFacade` so that the encrypted vault
 * (including the tenant pepper) persists across calls within a single
 * page session. The master key can be provided from JS (e.g. derived
 * from WebCrypto PBKDF2 over a user passphrase) or auto-generated.
 *
 * Production flow:
 * 1. JS creates `new WasmDriveRuntime(masterKeyHex)` once at app startup.
 * 2. JS calls `init_tenant_pepper(tenantIdHex)` on first use per tenant.
 *    The pepper is generated inside the SDK and stored in the encrypted vault.
 * 3. JS calls `dedup_upload(runtime, tenantIdHex, ...)` — the SDK loads
 *    the pepper from the vault internally; JS never sees the pepper.
 * 4. For multi-device sync, JS calls `seal_pepper_for_mls(...)` to get
 *    an MLS-encrypted pepper blob to send via MLS group messages.
 * 5. New devices call `open_pepper_from_mls(...)` to unwrap and store.
 */
export class WasmDriveRuntime {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Creates a domain key and stores it in the vault.
     */
    createDomain(domain_id_hex: string): string;
    /**
     * Loads the tenant pepper from the vault, auto-initializing if missing.
     * This is the convenience method for the common case: first upload
     * auto-generates the pepper, subsequent uploads reuse it.
     */
    ensureTenantPepper(tenant_id_hex: string): string;
    /**
     * Returns the master key hex (for JS to persist across sessions).
     * In production, JS should store this securely (e.g. WebCrypto + IndexedDB).
     */
    exportMasterKey(): string;
    /**
     * Checks whether a tenant pepper exists in the vault.
     */
    hasTenantPepper(tenant_id_hex: string): boolean;
    /**
     * Generates and stores a new tenant pepper in the vault.
     * Returns the pepper hex (for debugging/MLS sealing — JS should NOT
     * store this; the SDK vault is the source of truth).
     *
     * B2B: call once per tenant (each tenant gets its own pepper).
     * B2C: call once with the shared B2C tenant ID (all B2C users share it).
     */
    initTenantPepper(tenant_id_hex: string): string;
    /**
     * Loads the tenant pepper from the vault (without creating if missing).
     * Returns the pepper hex, or throws if not found.
     */
    loadTenantPepper(tenant_id_hex: string): string;
    /**
     * Creates a runtime with a fresh auto-generated master key.
     * The vault is in-memory only — pepper is lost on page reload.
     * For persistence, use `with_master_key` with a WebCrypto-derived key.
     */
    constructor();
    /**
     * Opens a tenant pepper sealed via MLS and stores it in the vault.
     *
     * Called by a new device that received the sealed pepper via MLS.
     * The device must be a member of the same MLS group at the same epoch
     * to derive the same transport key.
     *
     * Parameters match `seal_pepper_for_mls`, plus:
     * - `ciphertext_hex`: The sealed pepper ciphertext
     * - `nonce_hex`: The nonce from the seal operation
     *
     * Returns the pepper hex (for verification), or throws on error.
     */
    openPepperFromMls(tenant_id_hex: string, ciphertext_hex: string, nonce_hex: string, mls_exporter_output_hex: string, transport_salt_hex: string, domain_id_hex: string, generation: bigint, mls_epoch: bigint, mls_tree_hash_hex: string, envelope_id_hex: string): string;
    /**
     * Seals the tenant pepper using an MLS exporter-derived transport key.
     *
     * This produces an encrypted blob that can be sent via MLS group messages
     * to other group members. Recipients call `open_pepper_from_mls` to unwrap.
     *
     * Parameters:
     * - `mls_exporter_output_hex`: MLS exporter output (from `export_secret`)
     * - `transport_salt_hex`: Random salt for HKDF key derivation
     * - `domain_id_hex`: Domain ID (binds to MLS context)
     * - `generation`: Key generation number
     * - `mls_epoch`: MLS epoch number
     * - `mls_tree_hash_hex`: MLS tree hash (binds to group state)
     * - `envelope_id_hex`: Unique envelope ID for this seal
     *
     * Returns JSON: `{ "ciphertext_hex": "...", "nonce_hex": "..." }`
     */
    sealPepperForMls(tenant_id_hex: string, mls_exporter_output_hex: string, transport_salt_hex: string, domain_id_hex: string, generation: bigint, mls_epoch: bigint, mls_tree_hash_hex: string, envelope_id_hex: string): string;
    /**
     * Stores an existing pepper into the vault (e.g. unwrapped from MLS).
     * Used when a new device receives the pepper via MLS distribution.
     */
    storeTenantPepper(tenant_id_hex: string, pepper_hex: string): void;
    /**
     * Unwraps a pepper from a DomainKey-wrapped blob and stores it in the vault.
     *
     * Used when a new device has the domain key but no MLS access.
     */
    unwrapPepperFromDomainKey(tenant_id_hex: string, ciphertext_hex: string, nonce_hex: string, domain_key_hex: string): void;
    /**
     * Creates a runtime with a specific 32-byte master key (hex-encoded).
     * If `master_key_hex` is empty, a random key is generated.
     * In production, JS should derive this from a user passphrase via
     * WebCrypto PBKDF2 and persist it (e.g. in IndexedDB or via
     * the WebAuthn platform authenticator).
     */
    static withMasterKey(master_key_hex: string): WasmDriveRuntime;
    /**
     * Wraps the tenant pepper under a DomainKey (Secured/Advanced mode).
     *
     * This produces a backup copy of the pepper encrypted under the domain key,
     * which can be stored in gateway metadata. New devices that have the domain
     * key can unwrap the pepper without MLS.
     *
     * Returns JSON: `{ "ciphertext_hex": "...", "nonce_hex": "..." }`
     */
    wrapPepperUnderDomainKey(tenant_id_hex: string, domain_key_hex: string): string;
}

export function chunk_count(file_size: bigint, chunk_size: bigint): bigint;

export function compute_content_id(plaintext_hex: string, tenant_pepper_hex: string): string;

export function decrypt_content_file(content_key_hex: string, content_id_hex: string, ciphertexts_hex_json: string, plaintext_lens_json: string): Uint8Array;

export function decrypt_file_wasm(version_dek_hex: string, node_id_hex: string, version_id_hex: string, drive_id_hex: string, domain_id_hex: string, access_context_revision: bigint, access_context_snapshot_hash_hex: string, chunk_plan_json: string, ciphertexts_hex_json: string): Uint8Array;

export function decrypt_manifest_wasm(version_dek_hex: string, node_id_hex: string, version_id_hex: string, manifest_ct_hex: string, manifest_nonce_hex: string): string;

/**
 * WASM-exposed dedup upload with SDK-managed pepper.
 *
 * The tenant pepper is loaded from the SDK vault (not passed from JS).
 * The SDK handles pepper generation, storage, and retrieval internally.
 * JS only provides the tenant ID and 4 callback functions for gateway I/O.
 *
 * # Pepper distribution model
 *
 * - **B2B**: One pepper per tenant. Each tenant's pepper is isolated.
 * - **B2C**: One shared pepper for all B2C users (use the shared B2C tenant ID).
 *
 * # Multi-device sync
 *
 * When a user adds a new device, the pepper must be distributed to that device.
 * Use `WasmDriveRuntime.sealPepperForMls()` on an existing device and
 * `WasmDriveRuntime.openPepperFromMls()` on the new device.
 *
 * # JS usage
 *
 * ```js
 * const runtime = new WasmDriveRuntime();
 * // or: const runtime = WasmDriveRuntime.withMasterKey(masterKeyHex);
 *
 * // Ensure pepper exists (auto-creates on first call)
 * runtime.ensureTenantPepper(tenantIdHex);
 *
 * const callbacks = new DedupCallbacks(
 *   (contentIdHex) => { ... return JSON },
 *   (reqJson) => { ... return JSON },
 *   (blobReqJson) => { ... return "" },
 *   (commitReqJson) => { ... return JSON },
 * );
 * const result = dedup_upload(
 *   runtime, tenantIdHex, driveIdHex, nodeIdHex, ...,
 *   callbacks,
 * );
 * const parsed = JSON.parse(result);
 * if (parsed.fully_deduped) { showBadge("DEDUPED"); }
 * ```
 */
export function dedup_upload(runtime: WasmDriveRuntime, tenant_id_hex: string, drive_id_hex: string, node_id_hex: string, domain_id_hex: string, privacy_mode: number, plaintext_hex: string, creator_device_key_hex: string, signing_key_hex: string, access_context_revision: bigint, access_context_snapshot_hash_hex: string, wrapping_key_hex: string, callbacks: DedupCallbacks): string;

export function encrypt_content_file(tenant_pepper_hex: string, plaintext_hex: string): any;

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

/**
 * Initialize the panic hook for better error messages in the browser console.
 * Call this once before any other WASM function.
 */
export function init_panic_hook(): void;

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
    readonly compute_content_id: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly decrypt_content_file: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number, number];
    readonly decrypt_file_wasm: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: bigint, l: number, m: number, n: number, o: number, p: number, q: number) => [number, number, number, number];
    readonly decrypt_manifest_wasm: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => [number, number, number, number];
    readonly encrypt_content_file: (a: number, b: number, c: number, d: number) => [number, number, number];
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
    readonly __wbg_dedupcallbacks_free: (a: number, b: number) => void;
    readonly dedup_upload: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number, p: number, q: bigint, r: number, s: number, t: number, u: number, v: number) => [number, number, number, number];
    readonly dedupcallbacks_new: (a: any, b: any, c: any, d: any) => number;
    readonly __wbg_wasmdriveruntime_free: (a: number, b: number) => void;
    readonly wasmdriveruntime_createDomain: (a: number, b: number, c: number) => [number, number, number, number];
    readonly wasmdriveruntime_ensureTenantPepper: (a: number, b: number, c: number) => [number, number, number, number];
    readonly wasmdriveruntime_exportMasterKey: (a: number) => [number, number, number, number];
    readonly wasmdriveruntime_hasTenantPepper: (a: number, b: number, c: number) => number;
    readonly wasmdriveruntime_initTenantPepper: (a: number, b: number, c: number) => [number, number, number, number];
    readonly wasmdriveruntime_loadTenantPepper: (a: number, b: number, c: number) => [number, number, number, number];
    readonly wasmdriveruntime_new: () => number;
    readonly wasmdriveruntime_openPepperFromMls: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: bigint, o: bigint, p: number, q: number, r: number, s: number) => [number, number, number, number];
    readonly wasmdriveruntime_sealPepperForMls: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: bigint, k: bigint, l: number, m: number, n: number, o: number) => [number, number, number, number];
    readonly wasmdriveruntime_storeTenantPepper: (a: number, b: number, c: number, d: number, e: number) => [number, number];
    readonly wasmdriveruntime_unwrapPepperFromDomainKey: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => [number, number];
    readonly wasmdriveruntime_withMasterKey: (a: number, b: number) => [number, number, number];
    readonly wasmdriveruntime_wrapPepperUnderDomainKey: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly init_panic_hook: () => void;
    readonly generate_ed25519_keypair: () => [number, number, number];
    readonly generate_hpke_keypair: () => [number, number, number];
    readonly random_id_hex: () => [number, number];
    readonly sha256_hex: (a: number, b: number) => [number, number];
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __externref_table_dealloc: (a: number) => void;
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
