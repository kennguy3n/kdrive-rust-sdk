import { Users } from "lucide-react";
import type { DemoUser } from "../types";

interface Props {
  users: DemoUser[];
  currentUser: DemoUser | null;
  onSelect: (user: DemoUser) => void;
  tenants: { id: string; label: string; type: "b2b" | "b2c" }[];
}

export function UserSwitcher({ users, currentUser, onSelect, tenants }: Props) {
  const tenantLabel = (tenantId: string) =>
    tenants.find((t) => t.id === tenantId)?.label ?? tenantId;

  return (
    <div className="user-switcher">
      <Users size={20} style={{ alignSelf: "center", color: "var(--text-dim)" }} />
      {users.map((u) => (
        <div
          key={u.id}
          className={`user-card ${currentUser?.id === u.id ? "active" : ""}`}
          onClick={() => onSelect(u)}
        >
          <span className="user-label">{u.label}</span>
          <span className="user-role">
            {u.role} · {tenantLabel(u.tenant_id)}
          </span>
        </div>
      ))}
    </div>
  );
}
