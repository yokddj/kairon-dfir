import { useState, useEffect } from "react";
import { useAuth } from "../context/AuthContext";

export default function AdminUsersPage() {
  const { user } = useAuth();
  const [users, setUsers] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch("/api/admin/users").then(r => r.json()).then(setUsers).finally(() => setLoading(false));
  }, []);

  if (!user?.is_admin) return <div className="p-8 text-red-400">Access denied</div>;
  if (loading) return <div className="p-8 text-zinc-400">Loading...</div>;

  return (
    <div className="p-6">
      <h1 className="text-xl font-bold text-white mb-4">Users</h1>
      <div className="overflow-x-auto">
        <table className="w-full text-sm text-zinc-300">
          <thead className="border-b border-zinc-700 text-left">
            <tr><th className="p-2">Username</th><th className="p-2">Role</th><th className="p-2">Active</th><th className="p-2">Last Login</th></tr>
          </thead>
          <tbody>{users.map(u => (
            <tr key={u.id} className="border-b border-zinc-800">
              <td className="p-2 text-white">{u.username}</td>
              <td className="p-2">{u.is_admin ? "Admin" : "User"}</td>
              <td className="p-2">{u.is_active ? "Yes" : "No"}</td>
              <td className="p-2 text-zinc-500">{u.last_login_at || "-"}</td>
            </tr>
          ))}</tbody>
        </table>
      </div>
    </div>
  );
}
