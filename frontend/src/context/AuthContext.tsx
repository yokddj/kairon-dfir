import React, { createContext, useContext, useState, useEffect, useCallback, ReactNode } from "react";

interface AuthUser {
  user_id: string;
  username: string;
  display_name: string | null;
  email: string | null;
  is_admin: boolean;
  is_active: boolean;
  created_at: string;
  last_login_at: string | null;
}

interface AuthContextType {
  user: AuthUser | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<{ ok: boolean; error?: string }>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType>({
  user: null,
  loading: true,
  login: async () => ({ ok: false }),
  logout: async () => {},
});

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchMe = useCallback(async () => {
    try {
      const resp = await fetch("/api/auth/me");
      if (resp.ok) {
        const data = await resp.json();
        setUser(data);
      } else {
        setUser(null);
      }
    } catch {
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchMe();
  }, [fetchMe]);

  const login = async (username: string, password: string) => {
    try {
      const resp = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      if (!resp.ok) {
        return { ok: false, error: "Invalid credentials" };
      }
      await fetchMe();
      return { ok: true };
    } catch {
      return { ok: false, error: "Connection error" };
    }
  };

  const logout = async () => {
    await fetch("/api/auth/logout", { method: "POST" });
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
