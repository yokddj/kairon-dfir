import { useState, useEffect } from "react";
import { Navigate, useLocation } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

export function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  const location = useLocation();
  const [needsSetup, setNeedsSetup] = useState(false);
  const [checking, setChecking] = useState(true);

  useEffect(() => {
    fetch("/api/auth/needs-setup")
      .then(r => r.json())
      .then(d => setNeedsSetup(!!d.needs_setup))
      .catch(() => setNeedsSetup(false))
      .finally(() => setChecking(false));
  }, []);

  if (loading || checking) {
    return <div className="flex min-h-screen items-center justify-center bg-zinc-950"><div className="text-zinc-400">Loading...</div></div>;
  }

  if (needsSetup && location.pathname !== "/setup") {
    return <Navigate to="/setup" replace />;
  }

  if (!needsSetup && !user) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return <>{children}</>;
}
