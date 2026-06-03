import { useEffect } from "react";
import EventSummary from "./EventSummary";
import { copyToClipboard } from "../lib/time";

type Props = {
  open: boolean;
  loading?: boolean;
  error?: string | null;
  event: Record<string, unknown> | null;
  onClose: () => void;
  onSearchAround?: (eventId: string) => void;
  onSearchSameFile?: (value: string) => void;
  onSearchSameProcess?: (value: string) => void;
  onSearchSameHost?: (value: string) => void;
};

export default function EventDetailDrawer({ open, loading = false, error, event, onClose, onSearchAround, onSearchSameFile, onSearchSameProcess, onSearchSameHost }: Props) {
  useEffect(() => {
    if (!open) return;
    function onKeyDown(ev: KeyboardEvent) {
      if (ev.key === "Escape") onClose();
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [onClose, open]);

  useEffect(() => {
    if (!open) return;
    const body = document.body;
    const previousOverflow = body.style.overflow;
    const previousOverscroll = body.style.overscrollBehavior;
    body.style.overflow = "hidden";
    body.style.overscrollBehavior = "contain";
    return () => {
      body.style.overflow = previousOverflow;
      body.style.overscrollBehavior = previousOverscroll;
    };
  }, [open]);

  if (!open) return null;

  const eventMeta = ((event?.event as Record<string, unknown>) ?? {});
  const host = ((event?.host as Record<string, unknown>) ?? {});
  const user = ((event?.user as Record<string, unknown>) ?? {});
  const artifact = ((event?.artifact as Record<string, unknown>) ?? {});
  const file = ((event?.file as Record<string, unknown>) ?? {});
  const process = ((event?.process as Record<string, unknown>) ?? {});
  const eventId = String(event?.id ?? event?.event_id ?? "");
  const filePath = String(file.path ?? "");
  const processName = String(process.name ?? "");
  const hostName = String(host.name ?? "");

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4 backdrop-blur-sm">
      <button type="button" aria-label="Close event details" className="absolute inset-0 cursor-default" onClick={onClose} />
      <aside className="relative flex max-h-[90vh] min-h-0 w-full max-w-6xl flex-col overflow-hidden rounded-[28px] border border-line bg-panel shadow-panel">
        <div className="sticky top-0 z-10 flex items-start justify-between gap-4 border-b border-line bg-panel/95 px-6 py-4 backdrop-blur">
          <div>
            <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Event detail</p>
            <h3 className="mt-2 text-xl font-semibold">{String(eventMeta.message ?? "Event")}</h3>
            <p className="mt-2 text-sm text-muted">
              {String(event?.["@timestamp"] ?? "-")} · {String(host.name ?? "-")} · {String(user.name ?? "-")} · {String(eventMeta.category ?? "-")} / {String(eventMeta.type ?? "-")}
            </p>
          </div>
          <button type="button" onClick={onClose} className="rounded-2xl border border-line px-4 py-2 text-sm text-muted">
            Close
          </button>
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto px-6 py-4">
        {loading ? <div className="rounded-2xl border border-line bg-abyss/60 p-4 text-sm text-muted">Loading event…</div> : null}
        {error ? <div className="rounded-2xl border border-danger/30 bg-danger/10 p-4 text-sm text-danger">{error}</div> : null}
        {event ? (
          <div className="space-y-4">
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
              <div className="rounded-2xl border border-line bg-abyss/70 p-3 text-sm text-muted">Case: {String(event.case_id ?? "-")}</div>
              <div className="rounded-2xl border border-line bg-abyss/70 p-3 text-sm text-muted">Evidence: {String(event.evidence_id ?? "-")}</div>
              <div className="rounded-2xl border border-line bg-abyss/70 p-3 text-sm text-muted">Artifact: {String(artifact.name ?? artifact.type ?? "-")}</div>
            </div>
            <div className="flex flex-wrap gap-2">
              {eventId && onSearchAround ? (
                <button type="button" onClick={() => onSearchAround(eventId)} className="rounded-xl border border-line px-3 py-2 text-xs text-muted">
                  Show around this event
                </button>
              ) : null}
              {filePath && onSearchSameFile ? (
                <button type="button" onClick={() => onSearchSameFile(filePath)} className="rounded-xl border border-line px-3 py-2 text-xs text-muted">
                  Search same file
                </button>
              ) : null}
              {processName && onSearchSameProcess ? (
                <button type="button" onClick={() => onSearchSameProcess(processName)} className="rounded-xl border border-line px-3 py-2 text-xs text-muted">
                  Search same process
                </button>
              ) : null}
              {hostName && onSearchSameHost ? (
                <button type="button" onClick={() => onSearchSameHost(hostName)} className="rounded-xl border border-line px-3 py-2 text-xs text-muted">
                  Search same host
                </button>
              ) : null}
            </div>
            <EventSummary event={event} />
            <details className="rounded-2xl border border-line bg-abyss/70 p-4">
              <summary className="cursor-pointer font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Normalized fields</summary>
              <div className="mt-3">
                <button type="button" onClick={() => void copyToClipboard(JSON.stringify(event, null, 2))} className="rounded-xl border border-line px-3 py-2 text-xs text-muted">
                  Copy normalized JSON
                </button>
              </div>
              <pre className="mt-3 overflow-auto whitespace-pre-wrap break-words text-xs text-muted">{JSON.stringify(event, null, 2)}</pre>
            </details>
            <details className="rounded-2xl border border-line bg-abyss/70 p-4">
              <summary className="cursor-pointer font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Raw JSON</summary>
              <div className="mt-3">
                <button type="button" onClick={() => void copyToClipboard(JSON.stringify((event.raw as Record<string, unknown>) ?? {}, null, 2))} className="rounded-xl border border-line px-3 py-2 text-xs text-muted">
                  Copy raw JSON
                </button>
              </div>
              <pre className="mt-3 overflow-auto whitespace-pre-wrap break-words text-xs text-muted">{JSON.stringify((event.raw as Record<string, unknown>) ?? {}, null, 2)}</pre>
            </details>
          </div>
        ) : null}
        </div>
      </aside>
    </div>
  );
}
