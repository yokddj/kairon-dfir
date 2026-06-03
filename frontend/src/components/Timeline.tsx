import { useState } from "react";
import EventSummary from "./EventSummary";
import TagPill from "./TagPill";
import { formatTimestamp } from "../lib/time";

export default function Timeline({
  items,
  mode = "storyline",
  timezone = "UTC",
  selectedIds = [],
  onToggleSelect,
}: {
  items: Record<string, unknown>[];
  mode?: "storyline" | "raw";
  timezone?: string;
  selectedIds?: string[];
  onToggleSelect?: (eventId: string) => void;
}) {
  const [openId, setOpenId] = useState<string | null>(null);
  const grouped = items.reduce<Record<string, Record<string, unknown>[]>>((acc, item) => {
    const timestamp = String(item["@timestamp"] ?? "Undated");
    const key = timestamp === "Undated" ? "Undated" : formatTimestamp(timestamp, timezone).slice(0, 10);
    acc[key] = [...(acc[key] ?? []), item];
    return acc;
  }, {});
  return (
    <div className="space-y-3">
      {Object.entries(grouped).map(([day, dayItems]) => (
        <section key={day} className="space-y-3">
          <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">{day}</p>
          {mode === "storyline" ? (
            <div className="rounded-3xl border border-line bg-panel/50 p-4 text-sm text-muted">
              {dayItems.length} events in this time slice. Expand entries below to inspect exact timestamps, fields and raw data.
            </div>
          ) : null}
          {dayItems.map((item) => {
            const id = String(item.id ?? item.event_id);
            const event = (item.event as Record<string, unknown>) ?? {};
            const host = (item.host as Record<string, unknown>) ?? {};
            const user = (item.user as Record<string, unknown>) ?? {};
            const artifact = (item.artifact as Record<string, unknown>) ?? {};
            const tags = (item.tags as string[]) ?? [];
            return (
              <div key={id} className="rounded-3xl border border-line bg-panel/70 p-4 shadow-panel">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">{item["@timestamp"] ? formatTimestamp(item["@timestamp"], timezone) : "Undated event"}</p>
                    <p className="mt-2 text-sm text-ink">{String(event.message ?? "No message")}</p>
                    <p className="mt-2 text-xs text-muted">
                      {String(host.name ?? "-")} · {String(user.name ?? "-")} · {String(event.category ?? "unknown")} · {String(event.type ?? "unknown")} · {String(artifact.name ?? artifact.type ?? "-")}
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    {onToggleSelect ? (
                      <label className="flex items-center gap-2 rounded-full border border-line bg-abyss/60 px-3 py-1 font-mono text-[11px] uppercase tracking-[0.16em] text-muted">
                        <input type="checkbox" checked={selectedIds.includes(id)} onChange={() => onToggleSelect(id)} />
                        Select
                      </label>
                    ) : null}
                    <span className="rounded-full border border-line bg-white/5 px-3 py-1 font-mono text-[11px] uppercase tracking-[0.16em] text-muted">
                      {String(event.category ?? "unknown")}
                    </span>
                    <button onClick={() => setOpenId(openId === id ? null : id)} className="rounded-full border border-line bg-abyss/60 px-3 py-1 font-mono text-[11px] uppercase tracking-[0.16em] text-muted">
                      Raw
                    </button>
                  </div>
                </div>
                <div className="mt-3 flex flex-wrap gap-2">{tags.map((tag) => <TagPill key={tag} tag={tag} />)}</div>
                {openId === id ? (
                  <div className="mt-3 space-y-3 rounded-2xl border border-line bg-abyss/70 p-4">
                    <EventSummary event={item} />
                    <pre className="max-h-[24rem] overflow-auto whitespace-pre-wrap break-all rounded-2xl border border-line bg-panel/40 p-4 text-xs leading-6 text-muted">
                      {JSON.stringify(item, null, 2)}
                    </pre>
                  </div>
                ) : null}
              </div>
            );
          })}
        </section>
      ))}
    </div>
  );
}
