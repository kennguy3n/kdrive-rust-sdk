import { useState, useEffect } from "react";
import { Folder, FileText, ChevronRight, ChevronDown } from "lucide-react";
import type { Folder as FolderType, Node } from "../types";
import * as api from "../api";

interface Props {
  tenantId: string;
}

export function FolderTreeView({ tenantId }: Props) {
  const [folders, setFolders] = useState<FolderType[]>([]);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [children, setChildren] = useState<
    Record<string, { children: FolderType[]; nodes: Node[] }>
  >({});
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setLoading(true);
    api
      .fetchFolders(tenantId)
      .then(setFolders)
      .catch(() => setFolders([]))
      .finally(() => setLoading(false));
  }, [tenantId]);

  const toggleFolder = async (folder: FolderType) => {
    const newExpanded = new Set(expanded);
    if (newExpanded.has(folder.id)) {
      newExpanded.delete(folder.id);
    } else {
      newExpanded.add(folder.id);
      try {
        const data = await api.fetchFolderChildren(tenantId, folder.id);
        setChildren((prev) => ({
          ...prev,
          [folder.id]: { children: data.children, nodes: data.nodes },
        }));
      } catch (err) {
        console.error("Failed to fetch folder children:", err);
      }
      }
    setExpanded(newExpanded);
  };

  const renderFolder = (folder: FolderType, depth: number = 0) => {
    const isExpanded = expanded.has(folder.id);
    const childData = children[folder.id];
    const name = bytesToName(folder.name_encrypted);

    return (
      <div key={folder.id}>
        <div
          className="folder-item"
          style={{ paddingLeft: `${12 + depth * 20}px` }}
          onClick={() => toggleFolder(folder)}
        >
          {isExpanded ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
          <Folder size={16} />
          <span>{name}</span>
          <span className={`mode-badge ${folder.privacy_mode}`}>
            {folder.privacy_mode}
          </span>
        </div>
        {isExpanded && childData && (
          <div>
            {(childData.children || []).map((c) => renderFolder(c, depth + 1))}
            {(childData.nodes || []).map((n) => (
              <div
                key={n.id}
                className="node-item"
                style={{ paddingLeft: `${32 + depth * 20}px` }}
              >
                <FileText size={14} />
                <span>{bytesToName(n.name_encrypted)}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="folder-tree">
      <h2 className="section-title">Folders — {tenantId}</h2>
      {loading && <p style={{ color: "var(--text-dim)" }}>Loading…</p>}
      {!loading && folders.length === 0 && (
        <p style={{ color: "var(--text-dim)" }}>
          No folders found. Make sure the gateway is running and migrated.
        </p>
      )}
      {folders.map((f) => renderFolder(f))}
    </div>
  );
}

function bytesToName(b64: string): string {
  // Demo: the encrypted name has a 16-byte zero prefix, then ASCII name.
  // Go serializes []byte as base64 in JSON.
  try {
    const bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    if (bytes.length > 16) {
      return new TextDecoder().decode(bytes.slice(16));
    }
  } catch {
    // ignore decode errors
  }
  return "(encrypted)";
}
