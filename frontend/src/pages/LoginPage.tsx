import { useState, FormEvent } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

export default function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const from = (location.state as any)?.from?.pathname || "/";

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);
    const result = await login(username, password);
    setLoading(false);
    if (result.ok) {
      navigate(from, { replace: true });
    } else {
      setError(result.error || "Login failed");
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-zinc-950">
      <form onSubmit={handleSubmit} className="w-full max-w-sm rounded-xl border border-zinc-800 bg-zinc-900 p-8">
        <h1 className="mb-6 text-center text-2xl font-bold text-white">Kairon DFIR</h1>
        {error && <div className="mb-4 rounded bg-red-900/40 px-3 py-2 text-sm text-red-300">{error}</div>}
        <div className="mb-4">
          <label className="mb-1 block text-xs text-zinc-400">Username</label>
          <input type="text" value={username} onChange={(e) => setUsername(e.target.value)}
            className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-white text-sm"
            placeholder="admin" autoComplete="username" autoFocus />
        </div>
        <div className="mb-6">
          <label className="mb-1 block text-xs text-zinc-400">Password</label>
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
            className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-white text-sm"
            placeholder="••••••••" autoComplete="current-password" />
        </div>
        <button type="submit" disabled={loading}
          className="w-full rounded-md bg-blue-600 px-3 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50">
          {loading ? "Signing in..." : "Sign in"}
        </button>
      </form>
    </div>
  );
}
