/* @ts-self-types="./kchat_drive_wasm.d.ts" */

/**
 * JS callbacks for dedup transport operations.
 * Each callback is a JS function that receives a JSON string and returns a JSON string.
 * Callbacks must be synchronous — if you need async I/O, pre-fetch the data before
 * calling dedup_upload.
 */
export class DedupCallbacks {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        DedupCallbacksFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_dedupcallbacks_free(ptr, 0);
    }
    /**
     * @param {Function} check_content_fn
     * @param {Function} check_chunks_fn
     * @param {Function} upload_blob_fn
     * @param {Function} commit_version_fn
     */
    constructor(check_content_fn, check_chunks_fn, upload_blob_fn, commit_version_fn) {
        const ret = wasm.dedupcallbacks_new(check_content_fn, check_chunks_fn, upload_blob_fn, commit_version_fn);
        this.__wbg_ptr = ret;
        DedupCallbacksFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
}
if (Symbol.dispose) DedupCallbacks.prototype[Symbol.dispose] = DedupCallbacks.prototype.free;

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
    static __wrap(ptr) {
        const obj = Object.create(WasmDriveRuntime.prototype);
        obj.__wbg_ptr = ptr;
        WasmDriveRuntimeFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmDriveRuntimeFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmdriveruntime_free(ptr, 0);
    }
    /**
     * Creates a domain key and stores it in the vault.
     * @param {string} domain_id_hex
     * @returns {string}
     */
    createDomain(domain_id_hex) {
        let deferred3_0;
        let deferred3_1;
        try {
            const ptr0 = passStringToWasm0(domain_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.wasmdriveruntime_createDomain(this.__wbg_ptr, ptr0, len0);
            var ptr2 = ret[0];
            var len2 = ret[1];
            if (ret[3]) {
                ptr2 = 0; len2 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred3_0 = ptr2;
            deferred3_1 = len2;
            return getStringFromWasm0(ptr2, len2);
        } finally {
            wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
        }
    }
    /**
     * Loads the tenant pepper from the vault, auto-initializing if missing.
     * This is the convenience method for the common case: first upload
     * auto-generates the pepper, subsequent uploads reuse it.
     * @param {string} tenant_id_hex
     * @returns {string}
     */
    ensureTenantPepper(tenant_id_hex) {
        let deferred3_0;
        let deferred3_1;
        try {
            const ptr0 = passStringToWasm0(tenant_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.wasmdriveruntime_ensureTenantPepper(this.__wbg_ptr, ptr0, len0);
            var ptr2 = ret[0];
            var len2 = ret[1];
            if (ret[3]) {
                ptr2 = 0; len2 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred3_0 = ptr2;
            deferred3_1 = len2;
            return getStringFromWasm0(ptr2, len2);
        } finally {
            wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
        }
    }
    /**
     * Returns the master key hex (for JS to persist across sessions).
     * In production, JS should store this securely (e.g. WebCrypto + IndexedDB).
     * @returns {string}
     */
    exportMasterKey() {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.wasmdriveruntime_exportMasterKey(this.__wbg_ptr);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * Checks whether a tenant pepper exists in the vault.
     * @param {string} tenant_id_hex
     * @returns {boolean}
     */
    hasTenantPepper(tenant_id_hex) {
        const ptr0 = passStringToWasm0(tenant_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmdriveruntime_hasTenantPepper(this.__wbg_ptr, ptr0, len0);
        return ret !== 0;
    }
    /**
     * Generates and stores a new tenant pepper in the vault.
     * Returns the pepper hex (for debugging/MLS sealing — JS should NOT
     * store this; the SDK vault is the source of truth).
     *
     * B2B: call once per tenant (each tenant gets its own pepper).
     * B2C: call once with the shared B2C tenant ID (all B2C users share it).
     * @param {string} tenant_id_hex
     * @returns {string}
     */
    initTenantPepper(tenant_id_hex) {
        let deferred3_0;
        let deferred3_1;
        try {
            const ptr0 = passStringToWasm0(tenant_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.wasmdriveruntime_initTenantPepper(this.__wbg_ptr, ptr0, len0);
            var ptr2 = ret[0];
            var len2 = ret[1];
            if (ret[3]) {
                ptr2 = 0; len2 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred3_0 = ptr2;
            deferred3_1 = len2;
            return getStringFromWasm0(ptr2, len2);
        } finally {
            wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
        }
    }
    /**
     * Loads the tenant pepper from the vault (without creating if missing).
     * Returns the pepper hex, or throws if not found.
     * @param {string} tenant_id_hex
     * @returns {string}
     */
    loadTenantPepper(tenant_id_hex) {
        let deferred3_0;
        let deferred3_1;
        try {
            const ptr0 = passStringToWasm0(tenant_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.wasmdriveruntime_loadTenantPepper(this.__wbg_ptr, ptr0, len0);
            var ptr2 = ret[0];
            var len2 = ret[1];
            if (ret[3]) {
                ptr2 = 0; len2 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred3_0 = ptr2;
            deferred3_1 = len2;
            return getStringFromWasm0(ptr2, len2);
        } finally {
            wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
        }
    }
    /**
     * Creates a runtime with a fresh auto-generated master key.
     * The vault is in-memory only — pepper is lost on page reload.
     * For persistence, use `with_master_key` with a WebCrypto-derived key.
     */
    constructor() {
        const ret = wasm.wasmdriveruntime_new();
        this.__wbg_ptr = ret;
        WasmDriveRuntimeFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
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
     * @param {string} tenant_id_hex
     * @param {string} ciphertext_hex
     * @param {string} nonce_hex
     * @param {string} mls_exporter_output_hex
     * @param {string} transport_salt_hex
     * @param {string} domain_id_hex
     * @param {bigint} generation
     * @param {bigint} mls_epoch
     * @param {string} mls_tree_hash_hex
     * @param {string} envelope_id_hex
     * @returns {string}
     */
    openPepperFromMls(tenant_id_hex, ciphertext_hex, nonce_hex, mls_exporter_output_hex, transport_salt_hex, domain_id_hex, generation, mls_epoch, mls_tree_hash_hex, envelope_id_hex) {
        let deferred10_0;
        let deferred10_1;
        try {
            const ptr0 = passStringToWasm0(tenant_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(ciphertext_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            const ptr2 = passStringToWasm0(nonce_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len2 = WASM_VECTOR_LEN;
            const ptr3 = passStringToWasm0(mls_exporter_output_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len3 = WASM_VECTOR_LEN;
            const ptr4 = passStringToWasm0(transport_salt_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len4 = WASM_VECTOR_LEN;
            const ptr5 = passStringToWasm0(domain_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len5 = WASM_VECTOR_LEN;
            const ptr6 = passStringToWasm0(mls_tree_hash_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len6 = WASM_VECTOR_LEN;
            const ptr7 = passStringToWasm0(envelope_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len7 = WASM_VECTOR_LEN;
            const ret = wasm.wasmdriveruntime_openPepperFromMls(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5, generation, mls_epoch, ptr6, len6, ptr7, len7);
            var ptr9 = ret[0];
            var len9 = ret[1];
            if (ret[3]) {
                ptr9 = 0; len9 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred10_0 = ptr9;
            deferred10_1 = len9;
            return getStringFromWasm0(ptr9, len9);
        } finally {
            wasm.__wbindgen_free(deferred10_0, deferred10_1, 1);
        }
    }
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
     * @param {string} tenant_id_hex
     * @param {string} mls_exporter_output_hex
     * @param {string} transport_salt_hex
     * @param {string} domain_id_hex
     * @param {bigint} generation
     * @param {bigint} mls_epoch
     * @param {string} mls_tree_hash_hex
     * @param {string} envelope_id_hex
     * @returns {string}
     */
    sealPepperForMls(tenant_id_hex, mls_exporter_output_hex, transport_salt_hex, domain_id_hex, generation, mls_epoch, mls_tree_hash_hex, envelope_id_hex) {
        let deferred8_0;
        let deferred8_1;
        try {
            const ptr0 = passStringToWasm0(tenant_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(mls_exporter_output_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            const ptr2 = passStringToWasm0(transport_salt_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len2 = WASM_VECTOR_LEN;
            const ptr3 = passStringToWasm0(domain_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len3 = WASM_VECTOR_LEN;
            const ptr4 = passStringToWasm0(mls_tree_hash_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len4 = WASM_VECTOR_LEN;
            const ptr5 = passStringToWasm0(envelope_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len5 = WASM_VECTOR_LEN;
            const ret = wasm.wasmdriveruntime_sealPepperForMls(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, generation, mls_epoch, ptr4, len4, ptr5, len5);
            var ptr7 = ret[0];
            var len7 = ret[1];
            if (ret[3]) {
                ptr7 = 0; len7 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred8_0 = ptr7;
            deferred8_1 = len7;
            return getStringFromWasm0(ptr7, len7);
        } finally {
            wasm.__wbindgen_free(deferred8_0, deferred8_1, 1);
        }
    }
    /**
     * Stores an existing pepper into the vault (e.g. unwrapped from MLS).
     * Used when a new device receives the pepper via MLS distribution.
     * @param {string} tenant_id_hex
     * @param {string} pepper_hex
     */
    storeTenantPepper(tenant_id_hex, pepper_hex) {
        const ptr0 = passStringToWasm0(tenant_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(pepper_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmdriveruntime_storeTenantPepper(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Unwraps a pepper from a DomainKey-wrapped blob and stores it in the vault.
     *
     * Used when a new device has the domain key but no MLS access.
     * @param {string} tenant_id_hex
     * @param {string} ciphertext_hex
     * @param {string} nonce_hex
     * @param {string} domain_key_hex
     */
    unwrapPepperFromDomainKey(tenant_id_hex, ciphertext_hex, nonce_hex, domain_key_hex) {
        const ptr0 = passStringToWasm0(tenant_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(ciphertext_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(nonce_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(domain_key_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ret = wasm.wasmdriveruntime_unwrapPepperFromDomainKey(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Creates a runtime with a specific 32-byte master key (hex-encoded).
     * If `master_key_hex` is empty, a random key is generated.
     * In production, JS should derive this from a user passphrase via
     * WebCrypto PBKDF2 and persist it (e.g. in IndexedDB or via
     * the WebAuthn platform authenticator).
     * @param {string} master_key_hex
     * @returns {WasmDriveRuntime}
     */
    static withMasterKey(master_key_hex) {
        const ptr0 = passStringToWasm0(master_key_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmdriveruntime_withMasterKey(ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return WasmDriveRuntime.__wrap(ret[0]);
    }
    /**
     * Wraps the tenant pepper under a DomainKey (Secured/Advanced mode).
     *
     * This produces a backup copy of the pepper encrypted under the domain key,
     * which can be stored in gateway metadata. New devices that have the domain
     * key can unwrap the pepper without MLS.
     *
     * Returns JSON: `{ "ciphertext_hex": "...", "nonce_hex": "..." }`
     * @param {string} tenant_id_hex
     * @param {string} domain_key_hex
     * @returns {string}
     */
    wrapPepperUnderDomainKey(tenant_id_hex, domain_key_hex) {
        let deferred4_0;
        let deferred4_1;
        try {
            const ptr0 = passStringToWasm0(tenant_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(domain_key_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            const ret = wasm.wasmdriveruntime_wrapPepperUnderDomainKey(this.__wbg_ptr, ptr0, len0, ptr1, len1);
            var ptr3 = ret[0];
            var len3 = ret[1];
            if (ret[3]) {
                ptr3 = 0; len3 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred4_0 = ptr3;
            deferred4_1 = len3;
            return getStringFromWasm0(ptr3, len3);
        } finally {
            wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
        }
    }
}
if (Symbol.dispose) WasmDriveRuntime.prototype[Symbol.dispose] = WasmDriveRuntime.prototype.free;

/**
 * @param {bigint} file_size
 * @param {bigint} chunk_size
 * @returns {bigint}
 */
export function chunk_count(file_size, chunk_size) {
    const ret = wasm.chunk_count(file_size, chunk_size);
    return BigInt.asUintN(64, ret);
}

/**
 * @param {string} plaintext_hex
 * @param {string} tenant_pepper_hex
 * @returns {string}
 */
export function compute_content_id(plaintext_hex, tenant_pepper_hex) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(plaintext_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(tenant_pepper_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.compute_content_id(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * @param {string} content_key_hex
 * @param {string} content_id_hex
 * @param {string} ciphertexts_hex_json
 * @param {string} plaintext_lens_json
 * @returns {Uint8Array}
 */
export function decrypt_content_file(content_key_hex, content_id_hex, ciphertexts_hex_json, plaintext_lens_json) {
    const ptr0 = passStringToWasm0(content_key_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(content_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(ciphertexts_hex_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(plaintext_lens_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.decrypt_content_file(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v5 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v5;
}

/**
 * @param {string} version_dek_hex
 * @param {string} node_id_hex
 * @param {string} version_id_hex
 * @param {string} drive_id_hex
 * @param {string} domain_id_hex
 * @param {bigint} access_context_revision
 * @param {string} access_context_snapshot_hash_hex
 * @param {string} chunk_plan_json
 * @param {string} ciphertexts_hex_json
 * @returns {Uint8Array}
 */
export function decrypt_file_wasm(version_dek_hex, node_id_hex, version_id_hex, drive_id_hex, domain_id_hex, access_context_revision, access_context_snapshot_hash_hex, chunk_plan_json, ciphertexts_hex_json) {
    const ptr0 = passStringToWasm0(version_dek_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(node_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(version_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(drive_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(domain_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ptr5 = passStringToWasm0(access_context_snapshot_hash_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len5 = WASM_VECTOR_LEN;
    const ptr6 = passStringToWasm0(chunk_plan_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len6 = WASM_VECTOR_LEN;
    const ptr7 = passStringToWasm0(ciphertexts_hex_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len7 = WASM_VECTOR_LEN;
    const ret = wasm.decrypt_file_wasm(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, access_context_revision, ptr5, len5, ptr6, len6, ptr7, len7);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v9 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v9;
}

/**
 * @param {string} version_dek_hex
 * @param {string} node_id_hex
 * @param {string} version_id_hex
 * @param {string} manifest_ct_hex
 * @param {string} manifest_nonce_hex
 * @returns {string}
 */
export function decrypt_manifest_wasm(version_dek_hex, node_id_hex, version_id_hex, manifest_ct_hex, manifest_nonce_hex) {
    let deferred7_0;
    let deferred7_1;
    try {
        const ptr0 = passStringToWasm0(version_dek_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(node_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(version_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(manifest_ct_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(manifest_nonce_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        const ret = wasm.decrypt_manifest_wasm(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4);
        var ptr6 = ret[0];
        var len6 = ret[1];
        if (ret[3]) {
            ptr6 = 0; len6 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred7_0 = ptr6;
        deferred7_1 = len6;
        return getStringFromWasm0(ptr6, len6);
    } finally {
        wasm.__wbindgen_free(deferred7_0, deferred7_1, 1);
    }
}

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
 * @param {WasmDriveRuntime} runtime
 * @param {string} tenant_id_hex
 * @param {string} drive_id_hex
 * @param {string} node_id_hex
 * @param {string} domain_id_hex
 * @param {number} privacy_mode
 * @param {string} plaintext_hex
 * @param {string} creator_device_key_hex
 * @param {string} signing_key_hex
 * @param {bigint} access_context_revision
 * @param {string} access_context_snapshot_hash_hex
 * @param {string} wrapping_key_hex
 * @param {DedupCallbacks} callbacks
 * @returns {string}
 */
export function dedup_upload(runtime, tenant_id_hex, drive_id_hex, node_id_hex, domain_id_hex, privacy_mode, plaintext_hex, creator_device_key_hex, signing_key_hex, access_context_revision, access_context_snapshot_hash_hex, wrapping_key_hex, callbacks) {
    let deferred11_0;
    let deferred11_1;
    try {
        _assertClass(runtime, WasmDriveRuntime);
        const ptr0 = passStringToWasm0(tenant_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(drive_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(node_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(domain_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(plaintext_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        const ptr5 = passStringToWasm0(creator_device_key_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len5 = WASM_VECTOR_LEN;
        const ptr6 = passStringToWasm0(signing_key_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len6 = WASM_VECTOR_LEN;
        const ptr7 = passStringToWasm0(access_context_snapshot_hash_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len7 = WASM_VECTOR_LEN;
        const ptr8 = passStringToWasm0(wrapping_key_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len8 = WASM_VECTOR_LEN;
        _assertClass(callbacks, DedupCallbacks);
        const ret = wasm.dedup_upload(runtime.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, privacy_mode, ptr4, len4, ptr5, len5, ptr6, len6, access_context_revision, ptr7, len7, ptr8, len8, callbacks.__wbg_ptr);
        var ptr10 = ret[0];
        var len10 = ret[1];
        if (ret[3]) {
            ptr10 = 0; len10 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred11_0 = ptr10;
        deferred11_1 = len10;
        return getStringFromWasm0(ptr10, len10);
    } finally {
        wasm.__wbindgen_free(deferred11_0, deferred11_1, 1);
    }
}

/**
 * @param {string} tenant_pepper_hex
 * @param {string} plaintext_hex
 * @returns {any}
 */
export function encrypt_content_file(tenant_pepper_hex, plaintext_hex) {
    const ptr0 = passStringToWasm0(tenant_pepper_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(plaintext_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.encrypt_content_file(ptr0, len0, ptr1, len1);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * @param {string} version_dek_hex
 * @param {string} node_id_hex
 * @param {string} version_id_hex
 * @param {string} drive_id_hex
 * @param {string} domain_id_hex
 * @param {bigint} access_context_revision
 * @param {string} access_context_snapshot_hash_hex
 * @param {Uint8Array} plaintext
 * @returns {any}
 */
export function encrypt_file_wasm(version_dek_hex, node_id_hex, version_id_hex, drive_id_hex, domain_id_hex, access_context_revision, access_context_snapshot_hash_hex, plaintext) {
    const ptr0 = passStringToWasm0(version_dek_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(node_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(version_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(drive_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(domain_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ptr5 = passStringToWasm0(access_context_snapshot_hash_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len5 = WASM_VECTOR_LEN;
    const ptr6 = passArray8ToWasm0(plaintext, wasm.__wbindgen_malloc);
    const len6 = WASM_VECTOR_LEN;
    const ret = wasm.encrypt_file_wasm(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, access_context_revision, ptr5, len5, ptr6, len6);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * @param {string} version_dek_hex
 * @param {string} node_id_hex
 * @param {string} version_id_hex
 * @param {string} manifest_cbor_hex
 * @returns {any}
 */
export function encrypt_manifest_wasm(version_dek_hex, node_id_hex, version_id_hex, manifest_cbor_hex) {
    const ptr0 = passStringToWasm0(version_dek_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(node_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(version_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(manifest_cbor_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.encrypt_manifest_wasm(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * @param {string} domain_id_hex
 * @returns {any}
 */
export function generate_domain_key_wasm(domain_id_hex) {
    const ptr0 = passStringToWasm0(domain_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.generate_domain_key_wasm(ptr0, len0);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * @returns {any}
 */
export function generate_ed25519_keypair() {
    const ret = wasm.generate_ed25519_keypair();
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * @returns {any}
 */
export function generate_hpke_keypair() {
    const ret = wasm.generate_hpke_keypair();
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * @param {string} grant_id_hex
 * @param {string} recipients_json
 * @param {string} user_snapshot_hash_hex
 * @param {bigint} mls_epoch
 * @param {string} mls_tree_hash_hex
 * @returns {any}
 */
export function generate_share_grant_key_wasm(grant_id_hex, recipients_json, user_snapshot_hash_hex, mls_epoch, mls_tree_hash_hex) {
    const ptr0 = passStringToWasm0(grant_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(recipients_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(user_snapshot_hash_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(mls_tree_hash_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.generate_share_grant_key_wasm(ptr0, len0, ptr1, len1, ptr2, len2, mls_epoch, ptr3, len3);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * WASM-exposed crypto operations for KChat Drive.
 * These are the browser-callable functions for KDRV1 encryption/decryption.
 * @returns {string}
 */
export function generate_version_dek() {
    let deferred1_0;
    let deferred1_1;
    try {
        const ret = wasm.generate_version_dek();
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}

/**
 * @returns {string}
 */
export function get_test_vectors_json() {
    let deferred1_0;
    let deferred1_1;
    try {
        const ret = wasm.get_test_vectors_json();
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}

/**
 * Initialize the panic hook for better error messages in the browser console.
 * Call this once before any other WASM function.
 */
export function init_panic_hook() {
    wasm.init_panic_hook();
}

/**
 * @returns {string}
 */
export function random_id_hex() {
    let deferred1_0;
    let deferred1_1;
    try {
        const ret = wasm.random_id_hex();
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}

/**
 * @param {string} current_key_hex
 * @param {string} domain_id_hex
 * @param {bigint} current_generation
 * @returns {any}
 */
export function rotate_domain_key_wasm(current_key_hex, domain_id_hex, current_generation) {
    const ptr0 = passStringToWasm0(current_key_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(domain_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.rotate_domain_key_wasm(ptr0, len0, ptr1, len1, current_generation);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * @param {bigint} file_size
 * @returns {bigint}
 */
export function select_chunk_size(file_size) {
    const ret = wasm.select_chunk_size(file_size);
    return BigInt.asUintN(64, ret);
}

/**
 * @param {Uint8Array} data
 * @returns {string}
 */
export function sha256_hex(data) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.sha256_hex(ptr0, len0);
        deferred2_0 = ret[0];
        deferred2_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * @param {string} header_cbor_hex
 * @param {string} signing_key_hex
 * @returns {any}
 */
export function sign_header_wasm(header_cbor_hex, signing_key_hex) {
    const ptr0 = passStringToWasm0(header_cbor_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(signing_key_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.sign_header_wasm(ptr0, len0, ptr1, len1);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * @param {string} domain_key_hex
 * @param {string} wrapped_dek_hex
 * @param {string} wrap_nonce_hex
 * @returns {string}
 */
export function unwrap_dek_from_domain_key(domain_key_hex, wrapped_dek_hex, wrap_nonce_hex) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(domain_key_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(wrapped_dek_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(wrap_nonce_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.unwrap_dek_from_domain_key(ptr0, len0, ptr1, len1, ptr2, len2);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}

/**
 * @param {string} share_grant_key_hex
 * @param {string} wrapped_dek_hex
 * @param {string} wrap_nonce_hex
 * @returns {string}
 */
export function unwrap_dek_from_share_grant_key(share_grant_key_hex, wrapped_dek_hex, wrap_nonce_hex) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(share_grant_key_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(wrapped_dek_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(wrap_nonce_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.unwrap_dek_from_share_grant_key(ptr0, len0, ptr1, len1, ptr2, len2);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}

/**
 * @param {string} header_cbor_hex
 * @param {string} verifying_key_hex
 * @returns {boolean}
 */
export function verify_header_wasm(header_cbor_hex, verifying_key_hex) {
    const ptr0 = passStringToWasm0(header_cbor_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(verifying_key_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.verify_header_wasm(ptr0, len0, ptr1, len1);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return ret[0] !== 0;
}

/**
 * @param {string} domain_key_hex
 * @param {string} version_dek_hex
 * @returns {any}
 */
export function wrap_dek_under_domain_key(domain_key_hex, version_dek_hex) {
    const ptr0 = passStringToWasm0(domain_key_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(version_dek_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.wrap_dek_under_domain_key(ptr0, len0, ptr1, len1);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * @param {string} share_grant_key_hex
 * @param {string} version_dek_hex
 * @returns {any}
 */
export function wrap_dek_under_share_grant_key(share_grant_key_hex, version_dek_hex) {
    const ptr0 = passStringToWasm0(share_grant_key_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(version_dek_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.wrap_dek_under_share_grant_key(ptr0, len0, ptr1, len1);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}
function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg___wbindgen_debug_string_c25d447a39f5578f: function(arg0, arg1) {
            const ret = debugString(arg1);
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_is_function_1ff95bcc5517c252: function(arg0) {
            const ret = typeof(arg0) === 'function';
            return ret;
        },
        __wbg___wbindgen_is_object_a27215656b807791: function(arg0) {
            const val = arg0;
            const ret = typeof(val) === 'object' && val !== null;
            return ret;
        },
        __wbg___wbindgen_is_string_ea5e6cc2e4141dfe: function(arg0) {
            const ret = typeof(arg0) === 'string';
            return ret;
        },
        __wbg___wbindgen_is_undefined_c05833b95a3cf397: function(arg0) {
            const ret = arg0 === undefined;
            return ret;
        },
        __wbg___wbindgen_string_get_b0ca35b86a603356: function(arg0, arg1) {
            const obj = arg1;
            const ret = typeof(obj) === 'string' ? obj : undefined;
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_throw_344f42d3211c4765: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg_call_a6e5c5dce5018821: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.call(arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_crypto_38df2bab126b63dc: function(arg0) {
            const ret = arg0.crypto;
            return ret;
        },
        __wbg_error_a6fa202b58aa1cd3: function(arg0, arg1) {
            let deferred0_0;
            let deferred0_1;
            try {
                deferred0_0 = arg0;
                deferred0_1 = arg1;
                console.error(getStringFromWasm0(arg0, arg1));
            } finally {
                wasm.__wbindgen_free(deferred0_0, deferred0_1, 1);
            }
        },
        __wbg_getRandomValues_c44a50d8cfdaebeb: function() { return handleError(function (arg0, arg1) {
            arg0.getRandomValues(arg1);
        }, arguments); },
        __wbg_length_1f0964f4a5e2c6d8: function(arg0) {
            const ret = arg0.length;
            return ret;
        },
        __wbg_msCrypto_bd5a034af96bcba6: function(arg0) {
            const ret = arg0.msCrypto;
            return ret;
        },
        __wbg_new_227d7c05414eb861: function() {
            const ret = new Error();
            return ret;
        },
        __wbg_new_da52cf8fe3429cb2: function() {
            const ret = new Object();
            return ret;
        },
        __wbg_new_with_length_e6785c33c8e4cce8: function(arg0) {
            const ret = new Uint8Array(arg0 >>> 0);
            return ret;
        },
        __wbg_node_84ea875411254db1: function(arg0) {
            const ret = arg0.node;
            return ret;
        },
        __wbg_now_86c0d4ba3fa605b8: function() {
            const ret = Date.now();
            return ret;
        },
        __wbg_now_e7c6795a7f81e10f: function(arg0) {
            const ret = arg0.now();
            return ret;
        },
        __wbg_performance_3fcf6e32a7e1ed0a: function(arg0) {
            const ret = arg0.performance;
            return ret;
        },
        __wbg_process_44c7a14e11e9f69e: function(arg0) {
            const ret = arg0.process;
            return ret;
        },
        __wbg_prototypesetcall_4770620bbe4688a0: function(arg0, arg1, arg2) {
            Uint8Array.prototype.set.call(getArrayU8FromWasm0(arg0, arg1), arg2);
        },
        __wbg_randomFillSync_6c25eac9869eb53c: function() { return handleError(function (arg0, arg1) {
            arg0.randomFillSync(arg1);
        }, arguments); },
        __wbg_require_b4edbdcf3e2a1ef0: function() { return handleError(function () {
            const ret = module.require;
            return ret;
        }, arguments); },
        __wbg_set_8535240470bf2500: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = Reflect.set(arg0, arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_stack_3b0d974bbf31e44f: function(arg0, arg1) {
            const ret = arg1.stack;
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg_static_accessor_GLOBAL_4ef717fb391d88b7: function() {
            const ret = typeof global === 'undefined' ? null : global;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_GLOBAL_THIS_8d1badc68b5a74f4: function() {
            const ret = typeof globalThis === 'undefined' ? null : globalThis;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_SELF_146583524fe1469b: function() {
            const ret = typeof self === 'undefined' ? null : self;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_WINDOW_f2829a2234d7819e: function() {
            const ret = typeof window === 'undefined' ? null : window;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_subarray_3ed232c8a6baee09: function(arg0, arg1, arg2) {
            const ret = arg0.subarray(arg1 >>> 0, arg2 >>> 0);
            return ret;
        },
        __wbg_versions_276b2795b1c6a219: function(arg0) {
            const ret = arg0.versions;
            return ret;
        },
        __wbindgen_cast_0000000000000001: function(arg0, arg1) {
            // Cast intrinsic for `Ref(Slice(U8)) -> NamedExternref("Uint8Array")`.
            const ret = getArrayU8FromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_cast_0000000000000002: function(arg0, arg1) {
            // Cast intrinsic for `Ref(String) -> Externref`.
            const ret = getStringFromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_init_externref_table: function() {
            const table = wasm.__wbindgen_externrefs;
            const offset = table.grow(4);
            table.set(0, undefined);
            table.set(offset + 0, undefined);
            table.set(offset + 1, null);
            table.set(offset + 2, true);
            table.set(offset + 3, false);
        },
    };
    return {
        __proto__: null,
        "./kchat_drive_wasm_bg.js": import0,
    };
}

const DedupCallbacksFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_dedupcallbacks_free(ptr, 1));
const WasmDriveRuntimeFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmdriveruntime_free(ptr, 1));

function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_externrefs.set(idx, obj);
    return idx;
}

function _assertClass(instance, klass) {
    if (!(instance instanceof klass)) {
        throw new Error(`expected instance of ${klass.name}`);
    }
}

function debugString(val) {
    // primitive types
    const type = typeof val;
    if (type == 'number' || type == 'boolean' || val == null) {
        return  `${val}`;
    }
    if (type == 'string') {
        return `"${val}"`;
    }
    if (type == 'symbol') {
        const description = val.description;
        if (description == null) {
            return 'Symbol';
        } else {
            return `Symbol(${description})`;
        }
    }
    if (type == 'function') {
        const name = val.name;
        if (typeof name == 'string' && name.length > 0) {
            return `Function(${name})`;
        } else {
            return 'Function';
        }
    }
    // objects
    if (Array.isArray(val)) {
        const length = val.length;
        let debug = '[';
        if (length > 0) {
            debug += debugString(val[0]);
        }
        for(let i = 1; i < length; i++) {
            debug += ', ' + debugString(val[i]);
        }
        debug += ']';
        return debug;
    }
    // Test for built-in
    const builtInMatches = /\[object ([^\]]+)\]/.exec(toString.call(val));
    let className;
    if (builtInMatches && builtInMatches.length > 1) {
        className = builtInMatches[1];
    } else {
        // Failed to match the standard '[object ClassName]'
        return toString.call(val);
    }
    if (className == 'Object') {
        // we're a user defined class or Object
        // JSON.stringify avoids problems with cycles, and is generally much
        // easier than looping through ownProperties of `val`.
        try {
            return 'Object(' + JSON.stringify(val) + ')';
        } catch (_) {
            return 'Object';
        }
    }
    // errors
    if (val instanceof Error) {
        return `${val.name}: ${val.message}\n${val.stack}`;
    }
    // TODO we could test for more things here, like `Set`s and `Map`s.
    return className;
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

let cachedDataViewMemory0 = null;
function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

function getStringFromWasm0(ptr, len) {
    return decodeText(ptr >>> 0, len);
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        const idx = addToExternrefTable0(e);
        wasm.__wbindgen_exn_store(idx);
    }
}

function isLikeNone(x) {
    return x === undefined || x === null;
}

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1, 1) >>> 0;
    getUint8ArrayMemory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function passStringToWasm0(arg, malloc, realloc) {
    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }
    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = cachedTextEncoder.encodeInto(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

function takeFromExternrefTable0(idx) {
    const value = wasm.__wbindgen_externrefs.get(idx);
    wasm.__externref_table_dealloc(idx);
    return value;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
const MAX_SAFARI_DECODE_BYTES = 2146435072;
let numBytesDecoded = 0;
function decodeText(ptr, len) {
    numBytesDecoded += len;
    if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
        cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
        cachedTextDecoder.decode();
        numBytesDecoded = len;
    }
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

const cachedTextEncoder = new TextEncoder();

if (!('encodeInto' in cachedTextEncoder)) {
    cachedTextEncoder.encodeInto = function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    };
}

let WASM_VECTOR_LEN = 0;

let wasmModule, wasmInstance, wasm;
function __wbg_finalize_init(instance, module) {
    wasmInstance = instance;
    wasm = instance.exports;
    wasmModule = module;
    cachedDataViewMemory0 = null;
    cachedUint8ArrayMemory0 = null;
    wasm.__wbindgen_start();
    return wasm;
}

async function __wbg_load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);
            } catch (e) {
                const validResponse = module.ok && expectedResponseType(module.type);

                if (validResponse && module.headers.get('Content-Type') !== 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else { throw e; }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);
    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };
        } else {
            return instance;
        }
    }

    function expectedResponseType(type) {
        switch (type) {
            case 'basic': case 'cors': case 'default': return true;
        }
        return false;
    }
}

function initSync(module) {
    if (wasm !== undefined) return wasm;


    if (module !== undefined) {
        if (Object.getPrototypeOf(module) === Object.prototype) {
            ({module} = module)
        } else {
            console.warn('using deprecated parameters for `initSync()`; pass a single object instead')
        }
    }

    const imports = __wbg_get_imports();
    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }
    const instance = new WebAssembly.Instance(module, imports);
    return __wbg_finalize_init(instance, module);
}

async function __wbg_init(module_or_path) {
    if (wasm !== undefined) return wasm;


    if (module_or_path !== undefined) {
        if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
            ({module_or_path} = module_or_path)
        } else {
            console.warn('using deprecated parameters for the initialization function; pass a single object instead')
        }
    }

    if (module_or_path === undefined) {
        module_or_path = new URL('kchat_drive_wasm_bg.wasm', import.meta.url);
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync, __wbg_init as default };
