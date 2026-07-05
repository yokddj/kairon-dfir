import { Navigate, useLocation } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

export function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  const location = useLocation();

  if (loading) {
    return <div className="flex min-h-screen items-center justify-center bg-zinc-950"><div className="text-zinc-400">Loading...</div></div>;
  }

  if (!user) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return <>{children}</>;
}
