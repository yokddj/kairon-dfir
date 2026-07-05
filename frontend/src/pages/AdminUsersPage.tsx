import { useState, useEffect, FormEvent } from "react";
import { useAuth } from "../context/AuthContext";

interface UserRow {
  id: string;
  username: string;
  email: string | null;
  display_name: string | null;
  is_admin: boolean;
  is_active: boolean;
  created_at: string;
  last_login_at: string | null;
  password_changed_at: string | null;
}

const ROLE_INFO = {
  admin: { label: "Administrator", desc: "Can use Kairon and manage other users, passwords, sessions and account status.", color: "text-amber-400" },
  user: { label: "Standard user", desc: "Can use Kairon and change their own password. Cannot view or manage other users.", color: "text-zinc-400" },
};

const PERMISSION_MATRIX = [
  ["Use Kairon", "Yes", "Yes"],
  ["Change own password", "Yes", "Yes"],
  ["View users", "Yes", "No"],
  ["Create users", "Yes", "No"],
  ["Edit users", "Yes", "No"],
  ["Disable users", "Yes", "No"],
  ["Reset passwords", "Yes", "No"],
  ["Revoke sessions", "Yes", "No"],
  ["Promote users", "Yes", "No"],
];

export default function AdminUsersPage() {
  const { user } = useAuth();
  const [users, setUsers] = useState<UserRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [showCreate, setShowCreate] = useState(false);
  const [editingUser, setEditingUser] = useState<UserRow | null>(null);
  const [actionMsg, setActionMsg] = useState("");
  const [showMatrix, setShowMatrix] = useState(false);

  const fetchUsers = async () => {
    setLoading(true);
    try {
      const r = await fetch("/api/admin/users");
      if (r.ok) setUsers(await r.json());
      else setError("Failed to load users");
    } catch { setError("Connection error"); }
    setLoading(false);
  };

  useEffect(() => { fetchUsers(); }, []);

  async function doAction(url: string, method = "POST", body?: object) {
    setActionMsg("");
    try {
      const r = await fetch(url, {
        method,
        headers: body ? { "Content-Type": "application/json" } : undefined,
        body: body ? JSON.stringify(body) : undefined,
      });
      const data = await r.json();
      if (r.ok) { setActionMsg(data.detail || data.status || "OK"); fetchUsers(); }
      else { setActionMsg(data.detail || "Error"); }
    } catch { setActionMsg("Connection error"); }
  }

  if (!user?.is_admin) return <div className="p-8 text-red-400">Access denied — admin only</div>;

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white">Users</h1>
          <p className="text-sm text-zinc-400 mt-1">Manage platform users, roles, and case access.</p>
          <button onClick={() => setShowMatrix(!showMatrix)} className="text-xs text-blue-400 hover:text-blue-300 mt-1 underline">
            {showMatrix ? "Hide permission matrix" : "Compare roles"}
          </button>
        </div>
        <button onClick={() => setShowCreate(true)} className="rounded-md bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-700">
          + Create user
        </button>
      </div>

      {showMatrix && (
        <div className="mb-6 rounded-lg border border-zinc-700 bg-zinc-900 p-4 overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-zinc-700 text-left text-zinc-400">
                <th className="p-2">Capability</th>
                <th className="p-2">Admin</th>
                <th className="p-2">Administrator</th>
                <th className="p-2">Standard user</th>
              </tr>
            </thead>
            <tbody>{PERMISSION_MATRIX.map((row, i) => (
              <tr key={i} className="border-b border-zinc-800">
                <td className="p-2 text-white">{row[0]}</td>
                <td className="p-2 text-amber-400">{row[1]}</td>
                <td className="p-2 text-blue-400">{row[2]}</td>
                <td className="p-2 text-zinc-400">{row[3]}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      )}

      {actionMsg && <div className="mb-4 rounded border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-300">{actionMsg}</div>}

      {error && <div className="mb-4 rounded bg-red-900/40 px-3 py-2 text-sm text-red-300">{error}</div>}

      {showCreate && (
        <CreateUserForm
          onClose={() => setShowCreate(false)}
          onCreated={() => { setShowCreate(false); fetchUsers(); }}
        />
      )}

      {editingUser && (
        <EditUserForm
          user={editingUser}
          onClose={() => setEditingUser(null)}
          onUpdated={() => { setEditingUser(null); fetchUsers(); }}
        />
      )}

      {loading ? <div className="text-zinc-400 text-sm">Loading users...</div> : users.length === 0 ? (
        <EmptyState onCreate={() => setShowCreate(true)} />
      ) : (
        <div className="overflow-x-auto rounded-lg border border-zinc-800">
          <table className="w-full text-sm text-zinc-300">
            <thead className="bg-zinc-900 text-left text-zinc-400">
              <tr>
                <th className="p-3">Username</th>
                <th className="p-3">Display Name</th>
                <th className="p-3">Email</th>
                <th className="p-3">Global Role</th>
                <th className="p-3">Status</th>
                <th className="p-3">Last Login</th>
                <th className="p-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id} className="border-t border-zinc-800 hover:bg-zinc-900/50">
                  <td className="p-3 text-white font-medium">{u.username}</td>
                  <td className="p-3">{u.display_name || "-"}</td>
                  <td className="p-3 text-zinc-400">{u.email || "-"}</td>
                  <td className={`p-3 font-medium ${u.is_admin ? ROLE_INFO.admin.color : ROLE_INFO.user.color}`}>
                    {u.is_admin ? ROLE_INFO.admin.label : ROLE_INFO.user.label}
                  </td>
                  <td className="p-3">
                    <span className={`inline-block rounded-full px-2 py-0.5 text-xs font-medium ${u.is_active ? "bg-emerald-900/40 text-emerald-400" : "bg-red-900/40 text-red-400"}`}>
                      {u.is_active ? "Active" : "Disabled"}
                    </span>
                  </td>
                  <td className="p-3 text-zinc-500 text-xs">{u.last_login_at ? new Date(u.last_login_at).toLocaleString() : "Never"}</td>
                  <td className="p-3">
                    <div className="flex gap-1 flex-wrap">
                      <ActionBtn label="Edit" onClick={() => setEditingUser(u)} />
                      <ActionBtn label={u.is_active ? "Disable" : "Enable"}
                        onClick={() => doAction(`/api/admin/users/${u.id}/${u.is_active ? "disable" : "enable"}`)} />
                      <ActionBtn label="Reset Pwd" onClick={() => {
                        const p = prompt("New password (min 12 chars):");
                        if (p) doAction(`/api/admin/users/${u.id}/reset-password`, "POST", { new_password: p });
                      }} />
                      <ActionBtn label="Revoke" onClick={() => doAction(`/api/admin/users/${u.id}/revoke-sessions`)} />
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function ActionBtn({ label, onClick }: { label: string; onClick: () => void }) {
  return <button onClick={onClick}
    className="rounded border border-zinc-700 bg-zinc-800 px-2 py-0.5 text-xs text-zinc-300 hover:border-zinc-500 hover:text-white transition-colors">
    {label}
  </button>;
}

function EmptyState({ onCreate }: { onCreate: () => void }) {
  return (
    <div className="rounded-lg border border-dashed border-zinc-700 p-12 text-center">
      <p className="text-zinc-400 mb-4">No additional users yet.</p>
      <p className="text-zinc-500 text-sm mb-6">Create a standard user account to begin collaborating.</p>
      <button onClick={onCreate}
        className="rounded-md bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-700">
        Create user
      </button>
    </div>
  );
}

function CreateUserForm({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [isAdmin, setIsAdmin] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError("");
    if (password !== confirmPassword) { setError("Passwords do not match"); return; }
    if (password.length < 12) { setError("Password must be at least 12 characters"); return; }
    if (!username.trim()) { setError("Username is required"); return; }
    setLoading(true);
    try {
      const r = await fetch("/api/admin/users", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: username.trim(), email: email.trim() || null, display_name: displayName.trim() || null, password, is_admin: isAdmin }),
      });
      if (r.ok) { onCreated(); return; }
      const data = await r.json();
      setError(data.detail || "Failed to create user");
    } catch { setError("Connection error"); }
    setLoading(false);
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={onClose}>
      <form onSubmit={handleSubmit} className="w-full max-w-md rounded-xl border border-zinc-700 bg-zinc-900 p-6" onClick={e => e.stopPropagation()}>
        <h2 className="text-lg font-bold text-white mb-4">Create user</h2>
        {error && <div className="mb-3 rounded bg-red-900/40 px-3 py-2 text-sm text-red-300">{error}</div>}
        <div className="space-y-3">
          <Input label="Username *" value={username} onChange={setUsername} autoFocus />
          <Input label="Display name" value={displayName} onChange={setDisplayName} />
          <Input label="Email" value={email} onChange={setEmail} type="email" />
          <Input label="Password *" value={password} onChange={setPassword} type="password" />
          <Input label="Confirm password *" value={confirmPassword} onChange={setConfirmPassword} type="password" />
          <div>
            <label className="text-xs text-zinc-400 mb-1 block">Global role</label>
            <select value={isAdmin ? "admin" : "user"} onChange={e => setIsAdmin(e.target.value === "admin")}
              className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-white text-sm">
              <option value="user">Standard user — Use Kairon investigation features</option>
              <option value="admin">Administrator — Full platform administration</option>
            </select>
            <p className="text-xs text-zinc-500 mt-1">{isAdmin ? ROLE_INFO.admin.desc : ROLE_INFO.user.desc}</p>
          </div>
        </div>
        <div className="flex gap-2 mt-6">
          <button type="submit" disabled={loading}
            className="flex-1 rounded-md bg-emerald-600 px-3 py-2 text-sm font-medium text-white hover:bg-emerald-700 disabled:opacity-50">
            {loading ? "Creating..." : "Create user"}
          </button>
          <button type="button" onClick={onClose}
            className="rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-300 hover:border-zinc-500">
            Cancel
          </button>
        </div>
      </form>
    </div>
  );
}

function EditUserForm({ user: u, onClose, onUpdated }: { user: UserRow; onClose: () => void; onUpdated: () => void }) {
  const [email, setEmail] = useState(u.email || "");
  const [displayName, setDisplayName] = useState(u.display_name || "");
  const [isAdmin, setIsAdmin] = useState(u.is_admin);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const r = await fetch(`/api/admin/users/${u.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.trim() || null, display_name: displayName.trim() || null, is_admin: isAdmin }),
      });
      if (r.ok) { onUpdated(); return; }
      const data = await r.json();
      setError(data.detail || "Failed to update user");
    } catch { setError("Connection error"); }
    setLoading(false);
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={onClose}>
      <form onSubmit={handleSubmit} className="w-full max-w-md rounded-xl border border-zinc-700 bg-zinc-900 p-6" onClick={e => e.stopPropagation()}>
        <h2 className="text-lg font-bold text-white mb-4">Edit user: {u.username}</h2>
        {error && <div className="mb-3 rounded bg-red-900/40 px-3 py-2 text-sm text-red-300">{error}</div>}
        <div className="space-y-3">
          <Input label="Display name" value={displayName} onChange={setDisplayName} />
          <Input label="Email" value={email} onChange={setEmail} type="email" />
          <div>
            <label className="text-xs text-zinc-400 mb-1 block">Global role</label>
            <select value={isAdmin ? "admin" : "user"} onChange={e => setIsAdmin(e.target.value === "admin")}
              className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-white text-sm">
              <option value="user">Standard user — Use Kairon investigation features</option>
              <option value="admin">Administrator — Full platform administration</option>
            </select>
            <p className="text-xs text-zinc-500 mt-1">{isAdmin ? ROLE_INFO.admin.desc : ROLE_INFO.user.desc}</p>
          </div>
        </div>
        <div className="flex gap-2 mt-6">
          <button type="submit" disabled={loading}
            className="flex-1 rounded-md bg-blue-600 px-3 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50">
            {loading ? "Saving..." : "Save changes"}
          </button>
          <button type="button" onClick={onClose}
            className="rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-300 hover:border-zinc-500">
            Cancel
          </button>
        </div>
      </form>
    </div>
  );
}

function Input({ label, value, onChange, type = "text", autoFocus }: { label: string; value: string; onChange: (v: string) => void; type?: string; autoFocus?: boolean }) {
  return (
    <div>
      <label className="text-xs text-zinc-400 mb-1 block">{label}</label>
      <input type={type} value={value} onChange={e => onChange(e.target.value)} autoFocus={autoFocus}
        className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-white text-sm" />
    </div>
  );
}
