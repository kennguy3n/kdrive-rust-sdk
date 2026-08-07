import type { Tenant, Folder, Node } from "./types";

const API_BASE = "";

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
