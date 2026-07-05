import { useState, FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

export default function SetupWizardPage() {
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError("");
    if (password !== confirmPassword) {
      setError("Passwords do not match");
      return;
    }
    if (password.length < 12) {
      setError("Password must be at least 12 characters");
      return;
    }
    if (!username.trim()) {
      setError("Username is required");
      return;
    }
    setLoading(true);
    try {
      const resp = await fetch("/api/auth/setup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: username.trim(), email: email.trim() || null, password }),
      });
      if (!resp.ok) {
        const data = await resp.json();
        setError(data.detail || "Setup failed");
        setLoading(false);
        return;
      }
      window.location.href = "/";
    } catch {
      setError("Connection error. Is the backend running?");
      setLoading(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-zinc-950">
      <form onSubmit={handleSubmit} className="w-full max-w-md rounded-xl border border-zinc-800 bg-zinc-900 p-8">
        <h1 className="mb-2 text-center text-2xl font-bold text-white">Welcome to Kairon DFIR</h1>
        <p className="mb-6 text-center text-sm text-zinc-400">Create your administrator account to get started.</p>
        {error && <div className="mb-4 rounded bg-red-900/40 px-3 py-2 text-sm text-red-300">{error}</div>}
        <div className="mb-4">
          <label className="mb-1 block text-xs text-zinc-400">Username</label>
          <input type="text" value={username} onChange={(e) => setUsername(e.target.value)}
            className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-white text-sm" autoFocus />
        </div>
        <div className="mb-4">
          <label className="mb-1 block text-xs text-zinc-400">Email (optional)</label>
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)}
            className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-white text-sm" />
        </div>
        <div className="mb-4">
          <label className="mb-1 block text-xs text-zinc-400">Password (min 12 characters)</label>
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
            className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-white text-sm" />
        </div>
        <div className="mb-6">
          <label className="mb-1 block text-xs text-zinc-400">Confirm password</label>
          <input type="password" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)}
            className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-white text-sm" />
        </div>
        <button type="submit" disabled={loading}
          className="w-full rounded-md bg-emerald-600 px-3 py-2 text-sm font-medium text-white hover:bg-emerald-700 disabled:opacity-50">
          {loading ? "Creating account..." : "Create administrator account"}
        </button>
      </form>
    </div>
  );
}
