import { X } from "lucide-react";
import { useNotifications } from "../context/NotificationsContext";

const toneClasses: Record<string, string> = {
  info: "border-accent/30 bg-accent/10 text-accent",
  success: "border-mint/30 bg-mint/10 text-mint",
  warning: "border-amber/30 bg-amber/10 text-amber",
  error: "border-danger/30 bg-danger/10 text-danger",
};

export default function ToastViewport() {
  const { notifications, dismiss } = useNotifications();

  if (!notifications.length) return null;

  return (
    <div className="pointer-events-none fixed right-4 top-4 z-50 flex w-[min(420px,calc(100vw-2rem))] flex-col gap-3">
      {notifications.map((item) => (
        <div key={item.id} className={`pointer-events-auto rounded-3xl border px-4 py-3 shadow-panel backdrop-blur ${toneClasses[item.tone] ?? toneClasses.info}`}>
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <p className="text-sm font-semibold">{item.title}</p>
              {item.description ? <p className="mt-1 text-xs opacity-90">{item.description}</p> : null}
            </div>
            <button onClick={() => dismiss(item.id)} className="rounded-full border border-current/20 p-1 opacity-80 transition hover:opacity-100" aria-label="Dismiss notification">
              <X size={14} />
            </button>
          </div>
        </div>
      ))}
    </div>
  );
}
