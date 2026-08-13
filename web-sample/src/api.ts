import type { Tenant, Folder, Node } from "./types";

const API_BASE = "";

/**
 * Format an error from the WASM SDK or fetch API into a human-readable string.
 * WASM SDK errors are now structured objects with `code` and `message` fields.
 * Legacy string errors and Error instances are also handled.
 */
export function formatError(err: unknown): string {
  if (err === null || err === undefined) return "unknown error";
  if (typeof err === "string") return err;
  if (err instanceof Error) return err.message;
  if (typeof err === "object" && err !== null) {
    const e = err as { code?: string; message?: string };
    if (e.code && e.message) return `[${e.code}] ${e.message}`;
    if (e.message) return e.message;
    if (e.code) return e.code;
  }
  return String(err);
}

/** Get the error code from a structured WASM SDK error. */
export function errorCode(err: unknown): string {
  if (typeof err === "object" && err !== null) {
    const e = err as { code?: string };
    if (e.code) return e.code;
  }
  return "Unknown";
}

function headers(tenantId?: string, userId?: string): Record<string, string> {
  const h: Record<string, string> = { "Content-Type": "application/json" };
  if (tenantId) h["X-Demo-Tenant"] = tenantId;
  if (userId) h["X-Demo-User"] = userId;
  return h;
}

export async function fetchTenants(): Promise<Tenant[]> {
  const res = await fetch(`${API_BASE}/v1/tenants`);
  if (!res.ok) throw new Error(`fetchTenants: ${res.status}`);
  const data = await res.json();
  return data.tenants || [];
}

export async function fetchFolders(
  tenantId: string,
  parentFolderId?: string,
): Promise<Folder[]> {
  const url = new URL(`${API_BASE}/v1/folders`, window.location.origin);
  url.searchParams.set("parent", parentFolderId || "");
  const res = await fetch(url.toString(), { headers: headers(tenantId) });
  if (!res.ok) throw new Error(`fetchFolders: ${res.status}`);
  const data = await res.json();
  return data.folders || [];
}

export async function createFolder(
  tenantId: string,
  nameEncryptedHex: string,
  parentFolderId: string,
  privacyMode: string,
): Promise<string> {
  const res = await fetch(`${API_BASE}/v1/folders`, {
    method: "POST",
    headers: headers(tenantId),
    body: JSON.stringify({
      name_encrypted_hex: nameEncryptedHex,
      parent_folder_id: parentFolderId,
      privacy_mode: privacyMode,
    }),
  });
  if (!res.ok) throw new Error(`createFolder: ${res.status}`);
  const data = await res.json();
  return data.folder_id;
}

export async function fetchFolderChildren(
  tenantId: string,
  folderId: string,
): Promise<{ folder: Folder; children: Folder[]; nodes: Node[] }> {
  const res = await fetch(
    `${API_BASE}/v1/folders/${folderId}/children`,
    { headers: headers(tenantId) },
  );
  if (!res.ok) throw new Error(`fetchFolderChildren: ${res.status}`);
  return res.json();
}

export async function createNode(
  tenantId: string,
  folderId: string,
  nameEncryptedHex: string,
  mimeType: string,
): Promise<string> {
  const res = await fetch(`${API_BASE}/v1/folders/${folderId}/children`, {
    method: "POST",
    headers: headers(tenantId),
    body: JSON.stringify({
      name_encrypted_hex: nameEncryptedHex,
      mime_type: mimeType,
    }),
  });
  if (!res.ok) throw new Error(`createNode: ${res.status}`);
  const data = await res.json();
  return data.node_id;
}

export async function initiateUpload(
  tenantId: string,
  body: {
    node_id: string;
    folder_id: string;
    chunk_plan: unknown;
    manifest: unknown;
    header: unknown;
    wrapped_dek_hex: string;
    wrap_nonce_hex: string;
  },
): Promise<string> {
  const res = await fetch(`${API_BASE}/v1/uploads:initiate`, {
    method: "POST",
    headers: headers(tenantId),
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`initiateUpload: ${res.status}`);
  const data = await res.json();
  return data.session_id;
}

export async function registerChunk(
  tenantId: string,
  sessionId: string,
  ordinal: number,
  body: {
    ciphertext_hex: string;
    ciphertext_sha256: string;
    plaintext_len: number;
    ciphertext_len: number;
  },
): Promise<string> {
  const res = await fetch(
    `${API_BASE}/v1/uploads/${sessionId}/chunks/${ordinal}:register`,
    {
      method: "POST",
      headers: headers(tenantId),
      body: JSON.stringify(body),
    },
  );
  if (!res.ok) throw new Error(`registerChunk: ${res.status}`);
  const data = await res.json();
  return data.blob_key;
}

export async function authorizeDownload(
  tenantId: string,
  versionId: string,
): Promise<{ version_id: string; capability: string; expires_at: string }> {
  const res = await fetch(
    `${API_BASE}/v1/versions/${versionId}:authorizeDownload`,
    { method: "POST", headers: headers(tenantId) },
  );
  if (!res.ok) throw new Error(`authorizeDownload: ${res.status}`);
  return res.json();
}

export async function fetchVectors(): Promise<Record<string, unknown>> {
  const res = await fetch(`${API_BASE}/v1/vectors`);
  if (!res.ok) throw new Error(`fetchVectors: ${res.status}`);
  return res.json();
}

export async function createShareGrant(
  tenantId: string,
  userId: string,
  nodeId: string,
  granteeUserId: string,
  keyEnvelopeId: string,
): Promise<string> {
  const res = await fetch(`${API_BASE}/v1/nodes/${nodeId}/shares`, {
    method: "POST",
    headers: headers(tenantId, userId),
    body: JSON.stringify({
      grantee_user_id: granteeUserId,
      key_envelope_id: keyEnvelopeId,
    }),
  });
  if (!res.ok) throw new Error(`createShareGrant: ${res.status}`);
  const data = await res.json();
  return data.grant_id;
}

export async function revokeShareGrant(
  tenantId: string,
  grantId: string,
): Promise<void> {
  const res = await fetch(`${API_BASE}/v1/shares/${grantId}`, {
    method: "DELETE",
    headers: headers(tenantId),
  });
  if (!res.ok) throw new Error(`revokeShareGrant: ${res.status}`);
}

export async function listShares(
  tenantId: string,
  userId: string,
): Promise<unknown[]> {
  const res = await fetch(`${API_BASE}/v1/shares`, {
    headers: headers(tenantId, userId),
  });
  if (!res.ok) throw new Error(`listShares: ${res.status}`);
  const data = await res.json();
  return data.grants || [];
}

// ---- Dedup gateway endpoints (KDRV1) ----

export async function checkContent(
  tenantId: string,
  contentIdHex: string,
): Promise<{
  exists: boolean;
  blob_keys: string[];
  ciphertext_hashes: string[];
  chunk_count: number;
  plaintext_size: number;
}> {
  const res = await fetch(`${API_BASE}/v1/content:check`, {
    method: "POST",
    headers: headers(tenantId),
    body: JSON.stringify({ content_id: contentIdHex }),
  });
  if (!res.ok) throw new Error(`checkContent: ${res.status}`);
  return res.json();
}

export async function checkChunks(
  tenantId: string,
  contentIdHex: string,
  chunkHashes: string[],
): Promise<{ results: { hash: string; exists: boolean; blob_key: string | null }[] }> {
  const res = await fetch(`${API_BASE}/v1/content:checkChunks`, {
    method: "POST",
    headers: headers(tenantId),
    body: JSON.stringify({ content_id: contentIdHex, chunk_hashes: chunkHashes }),
  });
  if (!res.ok) throw new Error(`checkChunks: ${res.status}`);
  return res.json();
}

export async function registerContent(
  tenantId: string,
  body: {
    content_id: string;
    plaintext_size: number;
    chunk_count: number;
    chunk_size: number;
    chunk_plan_root: string;
    chunks: {
      chunk_index: number;
      chunk_content_hash: string;
      blob_key: string;
      plaintext_len: number;
      ciphertext_len: number;
    }[];
  },
): Promise<{ already_existed: boolean }> {
  const res = await fetch(`${API_BASE}/v1/content:register`, {
    method: "POST",
    headers: headers(tenantId),
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`registerContent: ${res.status}`);
  return res.json();
}

export async function commitDedup(
  tenantId: string,
  body: {
    content_id: string;
    reused_blob_keys: string[];
    new_blob_keys: string[];
  },
): Promise<{ version_id: string; committed: boolean; deduped_chunks: number; new_chunks: number }> {
  const res = await fetch(`${API_BASE}/v1/uploads:commitDedup`, {
    method: "POST",
    headers: headers(tenantId),
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`commitDedup: ${res.status}`);
  return res.json();
}
