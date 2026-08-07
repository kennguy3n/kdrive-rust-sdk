/* @ts-self-types="./kchat_drive_wasm.d.ts" */

/**
 * WASM-exposed high-level Drive API.
 * These functions wrap the crypto operations and return JSON for JS consumption.
 */
export class WasmDriveRuntime {
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
     * @param {string} domain_id_hex
     * @returns {string}
     */
    create_domain(domain_id_hex) {
        let deferred3_0;
        let deferred3_1;
        try {
            const ptr0 = passStringToWasm0(domain_id_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.wasmdriveruntime_create_domain(this.__wbg_ptr, ptr0, len0);
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
    constructor() {
        const ret = wasm.wasmdriveruntime_new();
        this.__wbg_ptr = ret;
        WasmDriveRuntimeFinalization.register(this, this.__wbg_ptr, this);
        return this;
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
        __wbg_new_with_length_e6785c33c8e4cce8: function(arg0) {
            const ret = new Uint8Array(arg0 >>> 0);
            return ret;
        },
        __wbg_node_84ea875411254db1: function(arg0) {
            const ret = arg0.node;
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

const WasmDriveRuntimeFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmdriveruntime_free(ptr, 1));

function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_externrefs.set(idx, obj);
    return idx;
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
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
