import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from "react";

export type NotificationTone = "info" | "success" | "warning" | "error";

export type NotificationItem = {
  id: string;
  title: string;
  description?: string;
  tone: NotificationTone;
};

type NotificationsContextValue = {
  notifications: NotificationItem[];
  notify: (input: { title: string; description?: string; tone?: NotificationTone; durationMs?: number }) => void;
  dismiss: (id: string) => void;
};

const NotificationsContext = createContext<NotificationsContextValue | null>(null);

export function NotificationsProvider({ children }: { children: ReactNode }) {
  const [notifications, setNotifications] = useState<NotificationItem[]>([]);
  const timeouts = useRef(new Map<string, number>());

  const dismiss = useCallback((id: string) => {
    const timeout = timeouts.current.get(id);
    if (timeout) {
      window.clearTimeout(timeout);
      timeouts.current.delete(id);
    }
    setNotifications((current) => current.filter((item) => item.id !== id));
  }, []);

  const notify = useCallback(
    ({ title, description, tone = "info", durationMs = 3600 }: { title: string; description?: string; tone?: NotificationTone; durationMs?: number }) => {
      const id = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
      setNotifications((current) => [...current, { id, title, description, tone }]);
      const timeout = window.setTimeout(() => dismiss(id), durationMs);
      timeouts.current.set(id, timeout);
    },
    [dismiss],
  );

  const value = useMemo(() => ({ notifications, notify, dismiss }), [notifications, notify, dismiss]);

  return <NotificationsContext.Provider value={value}>{children}</NotificationsContext.Provider>;
}

export function useNotifications() {
  const context = useContext(NotificationsContext);
  if (!context) {
    throw new Error("useNotifications must be used within NotificationsProvider");
  }
  return context;
}
