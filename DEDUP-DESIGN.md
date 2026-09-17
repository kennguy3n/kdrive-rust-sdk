# KChat Drive — Convergent Dedup Design

How KChat Drive deduplicates end-to-end-encrypted content without the server
ever seeing plaintext or keys. This document is self-contained: it specifies
the primitives, key hierarchy, flows, storage layout, and gateway contract
needed to implement (or evaluate) the system without reading the source.

Companion docs: `ARCHITECTURE.md` (crate layout), `web-sample/DEMO.md`
(demo walkthrough), kdrive `ARCHITECTURE.md` (server/storage plan).

---

## 1. Core idea

The system splits every file into two independent layers:

| Layer | Property | Scope |
| --- | --- | --- |
| **Content layer** (ciphertext) | Encrypted **once**, content-addressed, shared by everyone in the dedup scope | Per dedup scope (see §4) |
| **Access layer** (key wrapping) | The file's VersionDEK is **wrapped per grant**, distributed via MLS | Per share / per group |

A file shared with a group of 10 and forwarded to a group of 5 is:

- **1 ciphertext** stored once — all 15 users fetch the same blobs.
- **2 key grants** — each group gets its own wrapped copy of the file key.

The server stores only opaque ciphertext + opaque metadata. It can dedup
(identical ciphertexts map to identical keys) but can never decrypt.

---

## 2. Primitives

All symmetric primitives are SHA-256 / HMAC-SHA256 / HKDF-SHA256 /
AES-256-GCM. Key sizes: 32-byte keys, 12-byte nonces.

### 2.1 The tenant pepper

A random 32-byte secret generated client-side per **dedup scope**:

- **B2B**: one pepper per tenant (per organization).
- **B2C**: one pepper shared by the entire B2C zone.

The pepper is the dedup boundary. It lives only in the client-side encrypted
vault and is distributed between devices/members via MLS or domain-key
wrapping (§6). The server never sees it. Without the pepper, content_ids and
content keys are uncomputable — this is what makes dedup scope cryptographic
rather than merely ACL-enforced.

### 2.2 Content addressing (convergent)

For plaintext `P`:

```
pt_hash       = SHA-256(P)
content_id    = HMAC-SHA256(pepper, pt_hash)              # 32 bytes
content_key   = HKDF-Extract("kchat-drive/content-key/v1",
                             pt_hash || pepper)            # 32 bytes
```

`content_id` is the value sent to the server for dedup checks. Because it is
an HMAC keyed by the pepper, it reveals nothing about `P` to anyone who does
not hold the pepper.

### 2.3 Chunking and per-chunk convergent encryption

Files are split into fixed-size chunks: 4 MiB (< 64 MiB files), 8 MiB
(< 512 MiB), 16 MiB (≥ 512 MiB).

For chunk `i` with plaintext `Cᵢ`:

```
chunk_pt_hash   = SHA-256(Cᵢ)
chunk_key       = HKDF-Extract("kchat-drive/content-key/v1",
                               chunk_pt_hash || pepper)
chunk_nonce     = HKDF-Expand(chunk_key,
                              "kchat-drive/chunk-content-nonce/v1" || u64be(0), 12)
chunk_ct_id     = HMAC-SHA256(pepper, chunk_pt_hash)     # per-chunk AAD id
chunk_ctᵢ       = AES-256-GCM(chunk_key, chunk_nonce, Cᵢ,
                              AAD = protocol || suite || chunk_ct_id || u64be(0) || len)
chunk_ct_hashᵢ  = SHA-256(chunk_ctᵢ)
blob_keyᵢ       = "blob_{content_id}_{chunk_ct_hashᵢ}"   # storage key
```

Every element is deterministic given (chunk plaintext, pepper). Identical
chunks produce identical ciphertext **regardless of which file they came
from** — this is what enables cross-file chunk dedup.

### 2.4 Key hierarchy (per uploaded version)

```
TenantPepper (per dedup scope, long-lived, vault-resident)
   │
   ├─► ContentKey        ← convergent, derives all chunk ciphertexts
   │
VersionDEK (random, generated per version)
   │  PRK = HKDF-Extract(version_salt, VersionDEK)
   ├─► manifest key/nonce  → encrypts the manifest (chunk plan, names)
   ├─► content-wrap key    → wraps ContentKey → wrapped_content_key
   │
   └─► VersionDEK itself is wrapped under the mode key:
         • Secured/Advanced: AES-256-GCM(DomainKey, VersionDEK)
         • Max:              AES-256-GCM(ShareGrantKey, VersionDEK)
```

Decryption order reverses this: unwrap VersionDEK → unwrap ContentKey →
decrypt manifest → re-derive chunk keys from chunk plaintext hashes (or from
ContentKey for non-convergent chunks) → decrypt chunks.

### 2.5 ShareGrantKey (Max mode)

A fresh random 32-byte key per share grant, bound to its context:

```
ShareGrantKeyRecord = {
    grant_id,                      # random ID
    generation,                    # 0 on create, +1 on rotate
    key,                           # 32 random bytes
    recipient_user_set_root,       # Merkle root over recipients + user snapshot hash
    user_snapshot_hash,            # access-context snapshot
    mls_epoch,                     # MLS epoch the grant is bound to
    mls_tree_hash,                 # MLS tree hash (binds to group state)
}
```

The key is delivered to recipients inside the MLS group channel (§6.2).
Rotation on membership change creates a new generation — the old key cannot
unwrap DEKs of versions committed after rotation.

---

## 3. Privacy modes

| Mode | Wrapping key | Key distribution | History access for late joiner | Admin recovery |
| --- | --- | --- | --- | --- |
| **Secured** (1) | DomainKey per tenant-governed domain | Domain key shared within tenant; tenant recovery envelope | ✅ yes (domain key chain walks backward) | ✅ yes |
| **Advanced** (2) | DomainKey per MLS group/folder domain | Sealed via MLS exporter (`seal_advanced_domain_key`) | ❌ no (needs MLS epoch key) | ❌ no |
| **Max** (3) | ShareGrantKey per share grant | Sealed via MLS exporter (`seal_max_share_grant_key`) | ❌ no (grant bound to epoch+recipient set) | ❌ no |

In all three modes the server holds only wrapped keys and ciphertext.

**B2C enforces Max-only.** The client SDK refuses to wrap DEKs under domain
keys for B2C tenants (client-side policy check), so consumer shares always
get per-grant isolation.

---

## 4. Dedup scopes

| Scope | Pepper | Who dedups together | Why |
| --- | --- | --- | --- |
| **B2C zone** | One shared pepper for the whole zone | All B2C users | Zone-wide dedup: same file shared to any group converges to the same content_id and ciphertext |
| **B2B tenant** | One pepper per tenant | Members of that tenant only | Cross-tenant dedup is cryptographically impossible — different peppers yield unrelated content_ids and ciphertexts |

Two independent enforcement layers:

1. **Crypto** — without tenant A's pepper, tenant B cannot produce tenant A's
   content_ids, chunk keys, or ciphertexts.
2. **Gateway** — every dedup endpoint is additionally scoped by `tenant_id`
   (§7). Cross-tenant `content_id` collision → `403` (fail-closed).

---

## 5. Upload flow with dedup

Client-side pipeline (`dedup_upload` in the SDK facade):

```
1. pt_hash = SHA-256(plaintext)
2. Load pepper from vault (auto-create on first use)
3. content_id = HMAC(pepper, pt_hash)
4. POST /v1/content:check { content_id }
   ├─ exists && blob_keys/chunk_hashes complete → FULL FILE DEDUP
   │   reuse all blob keys; skip encryption and upload entirely
   └─ miss/partial → continue
5. Encrypt each chunk convergently (§2.3) → chunk_ct, chunk_ct_hash, blob_key
6. POST /v1/content:checkChunks { content_id, chunk_hashes[] }
   → per-chunk exists + existing blob_key (reused) vs. upload-needed
7. POST /v1/blobs:upload { blob_key, ciphertext_hex, sha256 } for NEW chunks only
8. Generate VersionDEK; wrap ContentKey under it (content-wrap key)
9. Wrap VersionDEK under mode key (DomainKey or ShareGrantKey)
10. Build + encrypt manifest (chunk plan); build + sign public header
11. POST /v1/content:register { content_id, chunk list w/ real hashes }
12. POST /v1/uploads:commitDedup { header, wrapped keys, reused/new blob keys }
    → gateway verifies entry ownership, reused keys registered,
      and new keys actually present in the blob store (HEAD)
```

Result: `{ version_id, content_id, chunk_count, reused_blob_keys,
new_blob_keys, fully_deduped }`.

### Forwarding a file (the 10→5 scenario)

1. Forwarder already holds a grant for group A — unwraps the VersionDEK.
2. Creates share grant #2 for group B: new ShareGrantKey bound to group B's
   MLS epoch + recipient set; re-wraps the same VersionDEK.
3. `content:check` hits → **zero ciphertext uploaded**; commits a new version
   header + wrapped DEK referencing the existing blob keys.

Cost of forwarding ≈ one small metadata write. No re-encryption, no re-upload.

### Download

1. Fetch version metadata (wrapped DEK, manifest ciphertext, blob keys).
2. Unwrap VersionDEK with the recipient's grant key → unwrap ContentKey.
3. Fetch blobs by `blob_key`; decrypt manifest → chunk plan; decrypt chunks
   convergently (pepper re-derives chunk keys for deduped chunks).

---

## 6. Pepper distribution

The pepper must reach every member of the dedup scope while remaining
invisible to the server. Two transports, both client-side:

### 6.1 MLS (primary)

```
transport_key   = HKDF-Extract(transport_salt, MLS_exporter_output)
                  → Expand("kchat-drive/{purpose}/transport-key/v1"
                           || context_hash || envelope_id, 32)
transport_nonce = same derivation with "transport-nonce/v1"
context_hash    = binds (domain_id, generation, mls_epoch, mls_tree_hash)
sealed          = AES-256-GCM(transport_key, transport_nonce, pepper)
```

Only current MLS group members at that epoch can derive the transport key —
the pepper rides inside the already-E2EE group channel.

### 6.2 Domain-key wrap (Secured fallback)

`wrap_pepper_under_domain_key` / `unwrap_pepper_from_domain_key` — for members
who hold the domain key but lack MLS access. Also used for pepper backup in
gateway metadata.

### 6.3 Client vault

The pepper and all wrapping keys live in a per-device vault: AES-256-GCM-
encrypted entries under a device master key, in-memory at runtime, export/
import for persistence (encrypted entries only; master key re-derived per
session). Web demo persists the master key + pepper entries in IndexedDB.

---

## 7. Gateway (server-side) contract

The gateway is an **untrusted store**. It sees content_ids, chunk hashes,
blob keys, sizes, and wrapped keys — never plaintext, peppers, or DEKs.

### Stored data

| Store | Contents |
| --- | --- |
| `content_entries` | `(content_id, tenant_id)` → plaintext_size, chunk_count, chunk_size, chunk_plan_root, pepper_generation |
| `content_chunks` | `(content_id, chunk_index)` → chunk_content_hash, blob_key, lengths |
| Blob store (S3/local) | `blob_key → ciphertext bytes` (checksum-verified on write) |
| Version metadata | Encrypted manifest, signed header, wrapped DEK/content keys, nonces |

### Endpoints

| Endpoint | Semantics |
| --- | --- |
| `POST /v1/content:check` | `(content_id, tenant)` → exists, blob_keys, ciphertext_hashes, sizes |
| `POST /v1/content:checkChunks` | per-hash exists + blob_key, scoped to chunks owned by the caller's tenant (tenant-wide, cross-content_id) |
| `POST /v1/blobs:upload` | store ciphertext under blob_key with SHA-256 verification |
| `POST /v1/content:register` | idempotent insert; 403 if content_id owned by another tenant |
| `POST /v1/uploads:commitDedup` | verify entry belongs to tenant; every reused blob key is registered; every **new** blob key exists in the blob store (HEAD); then commit version |

### Tenant isolation rules

- All lookups are `(content_id, tenant_id)` or tenant-filtered — a tenant can
  never observe another tenant's dedup metadata.
- `commitDedup` fails closed: unknown reused key or missing new blob → 400.
- Demo uses `X-Demo-Tenant` headers; production must replace this with the
  real identity layer (session tokens / device certificates).

---

## 8. Security properties & honest limitations

**Guarantees**

- Server learns: dedup *relationships* within a tenant (which uploads share a
  content_id), sizes, chunk counts, timing. Never plaintext or keys.
- Cross-tenant/zone correlation is impossible without the pepper (HMAC).
- Membership removal → new ShareGrantKey generation / MLS epoch → removed
  members lose access to all future versions (forward secrecy in Max and
  Advanced; Secured allows backward walk by design).
- A deduped file has no weaker confidentiality: the ciphertext is identical
  to what a non-deduped upload would produce.

**Inherent trade-off (convergent encryption)**

- *Known-plaintext confirmation*: anyone holding the pepper who already
  suspects a file's contents can confirm the match (compute the content_id).
  The pepper raises this to scope-members only, but the leak is intrinsic to
  dedup — it is the price of the feature, not a bug.
- Do not dedup-scope across trust boundaries you wouldn't want confirmation
  leaks across. (B2B per-tenant pepper exists precisely for this reason.)

**Demo-scope limitations** (not architectural)

- Auth headers are trusted, not authenticated.
- The demo's tenant→pepper mapping is `SHA-256(tenant_id)[:16]`; production
  uses real tenant UUIDs from the identity service.
- The browser sample keeps peppers per browser profile (single shared vault).

---

## 9. Implementation checklist

**Client SDK**

- [ ] Random pepper per dedup scope; vault-resident; never exposed raw to app
      code paths that log/persist it
- [ ] Convergent chunk encryptor implementing §2.3 formulas exactly
- [ ] `dedup_upload` pipeline per §5 with transport callbacks
      (check → checkChunks → blob upload → register → commit)
- [ ] Mode-key wrap: DomainKey (Secured/Advanced) or ShareGrantKey (Max)
- [ ] MLS pepper/grant-key sealing + domain-key fallback
- [ ] B2C Max-mode enforcement (reject domain-key wraps for B2C)

**Gateway**

- [ ] `content_entries` / `content_chunks` tables keyed `(content_id, tenant)`
- [ ] Blob store keyed by `blob_key` with SHA-256 verification on write
- [ ] Five endpoints per §7 with tenant scoping + commit verification
      (reused keys registered; new keys present via HEAD)
- [ ] Fail-closed cross-tenant content_id collision (403)
- [ ] Real identity layer replacing demo headers

**Product notes**

- Dedup ratios to expect: file-level dedup is exact-match only (whole-file
  content_id); chunk-level catches partial edits and forwards.
- Forwarding is ~free (metadata write only) — a headline feature for "share
  this file to another group" UX.
- Retention/GC policy must be reference-counted: a blob_key is live while any
  tenant-registered chunk references it (not covered by this document).
