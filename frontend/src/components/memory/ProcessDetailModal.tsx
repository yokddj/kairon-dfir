import { useEffect, useId, useMemo, useRef, useState } from "react";
import {
  type MemoryProcessEntity,
  type MemoryProcessEntityDetail,
} from "../../api/client";
import {
  AlertCircle,
  ChevronRight,
  Copy,
  Eye,
  GitBranch,
  Network,
  ShieldAlert,
  Sparkles,
  XCircle,
} from "lucide-react";

type Props = {
  open: boolean;
  detail: MemoryProcessEntityDetail | null;
  isLoading: boolean;
  error: Error | null;
  onClose: () => void;
  onSelectEntityId?: (entityId: string) => void;
  onOpenInGraph?: (entityId: string) => void;
  onShowInTree?: (entityId: string) => void;
};

type TabKey = "overview" | "relationships" | "observations" | "raw";

const TABS: { key: TabKey; label: string }[] = [
  { key: "overview", label: "Overview" },
  { key: "relationships", label: "Relationships" },
  { key: "observations", label: "Observations" },
  { key: "raw", label: "Raw references" },
];

function reported(value: unknown): string {
  if (value === null || value === undefined || value === "") return "—";
  return String(value);
}

function sourceBadge(plugin: string): string {
  return plugin.replace("windows.", "");
}

function describeVisibility(entity: MemoryProcessEntity | null | undefined): string {
  if (!entity) return "—";
  if (entity.visibility?.terminated) return "Terminated";
  if (entity.visibility?.hidden_candidate) return "Hidden candidate";
  if (entity.visibility?.scan_only) return "Scan only";
  if (entity.visibility?.unknown) return "Unknown";
  return "Listed";
}

function visibilityToneClass(entity: MemoryProcessEntity | null | undefined): string {
  if (!entity) return "border-line bg-abyss/70 text-muted";
  if (entity.visibility?.scan_only || entity.visibility?.hidden_candidate)
    return "border-rose-400/30 bg-rose-500/10 text-rose-100";
  if (entity.visibility?.terminated) return "border-line bg-abyss/70 text-muted";
  if (entity.visibility?.unknown) return "border-amber-400/30 bg-amber-500/10 text-amber-100";
  return "border-sky-400/30 bg-sky-500/10 text-sky-100";
}

function nodeIcon(entity: MemoryProcessEntity | null | undefined) {
  if (!entity) return <Network className="h-3.5 w-3.5 text-muted" />;
  const name = (entity.process?.name || "").toLowerCase();
  if (entity.visibility?.scan_only || entity.visibility?.hidden_candidate)
    return <ShieldAlert className="h-3.5 w-3.5 text-rose-300" />;
  if (entity.visibility?.terminated) return <XCircle className="h-3.5 w-3.5 text-muted" />;
  if (name.includes("svchost")) return <Sparkles className="h-3.5 w-3.5 text-cyan-200" />;
  if (name.includes("powershell") || name.includes("cmd")) return <Network className="h-3.5 w-3.5 text-orange-200" />;
  if (name.includes("system") || entity.process?.pid === 4) return <GitBranch className="h-3.5 w-3.5 text-emerald-200" />;
  return <Network className="h-3.5 w-3.5 text-muted" />;
}

function useFocusTrap(active: boolean, onEscape: () => void, containerRef: React.RefObject<HTMLDivElement>) {
  useEffect(() => {
    if (!active) return;
    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") {
        event.stopPropagation();
        onEscape();
        return;
      }
      if (event.key !== "Tab") return;
      const root = containerRef.current;
      if (!root) return;
      const focusable = root.querySelectorAll<HTMLElement>(
        'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])',
      );
      if (focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      const active = document.activeElement as HTMLElement | null;
      if (event.shiftKey && active === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && active === last) {
        event.preventDefault();
        first.focus();
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [active, onEscape, containerRef]);
}

function copyText(value: string) {
  if (typeof navigator !== "undefined" && navigator.clipboard) {
    navigator.clipboard.writeText(value).catch(() => undefined);
  }
}

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="rounded-xl border border-line bg-abyss/40 p-3" data-testid={`modal-field-${label.toLowerCase().replace(/\s+/g, "-")}`}>
      <p className="text-[10px] uppercase tracking-[0.16em] text-muted">{label}</p>
      <p className={`mt-1 break-words text-ink ${mono ? "font-mono text-xs" : "text-sm"}`}>{value}</p>
    </div>
  );
}

function BreadcrumbPath({ treePath }: { treePath: string[] }) {
  if (!treePath.length) {
    return <span className="text-xs text-muted">Root (no ancestors in canonical set)</span>;
  }
  return (
    <ol className="flex flex-wrap items-center gap-1 text-xs" data-testid="modal-tree-path">
      {treePath.map((segment, index) => (
        <li key={`${segment}-${index}`} className="flex items-center gap-1">
          {index > 0 ? <ChevronRight className="h-3 w-3 text-muted" /> : null}
          <span className="rounded-md border border-line bg-abyss/70 px-2 py-0.5 text-ink">{segment}</span>
        </li>
      ))}
    </ol>
  );
}

function buildTreePathWithNames(
  detail: MemoryProcessEntityDetail | null,
  _byId: Map<string, MemoryProcessEntity>,
): string[] {
  if (!detail) return [];
  // Build a parent_id chain from the entity's parent; the API already
  // returns a tree_path of names+pids, but fall back to a manual chain
  // if the API ever omits it.
  if (detail.tree_path && detail.tree_path.length) {
    return detail.tree_path;
  }
  const out: string[] = [];
  const seen = new Set<string>();
  let cur: MemoryProcessEntity | null = detail.parent;
  while (cur) {
    if (seen.has(cur.process_entity_id)) break;
    seen.add(cur.process_entity_id);
    out.unshift(`${cur.process.name ?? "—"} (${cur.process.pid})`);
    // MemoryProcessEntity does not carry a back-reference to its
    // own parent; we just walk the linked-list the API gave us.
    cur = null;
  }
  return out;
}

export function ProcessDetailModal({
  open,
  detail,
  isLoading,
  error,
  onClose,
  onSelectEntityId,
  onOpenInGraph,
  onShowInTree,
}: Props) {
  const [tab, setTab] = useState<TabKey>("overview");
  const [copyMessage, setCopyMessage] = useState<string | null>(null);
  const triggerRef = useRef<HTMLElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const headingId = useId();

  useEffect(() => {
    if (open) {
      // Capture the element that opened the modal so we can restore focus
      // on close.  document.activeElement is the most reliable source
      // because callers do not need to pass a ref.
      triggerRef.current = (document.activeElement as HTMLElement | null) ?? null;
      setTab("overview");
    }
  }, [open]);

  useFocusTrap(open, onClose, containerRef);

  useEffect(() => {
    if (!open) {
      // Restore focus to the trigger element once the modal is closed.
      const trigger = triggerRef.current;
      if (trigger && typeof trigger.focus === "function") {
        // Microtask to ensure the trigger is still in the DOM.
        setTimeout(() => trigger.focus(), 0);
      }
      triggerRef.current = null;
    }
  }, [open]);

  const byId = useMemo(() => {
    const m = new Map<string, MemoryProcessEntity>();
    const ent = detail?.entity;
    if (ent) m.set(ent.process_entity_id, ent);
    detail?.parent && m.set(detail.parent.process_entity_id, detail.parent);
    detail?.children?.forEach((c) => m.set(c.process_entity_id, c));
    return m;
  }, [detail]);

  const treePathNames = useMemo(() => buildTreePathWithNames(detail, byId), [detail, byId]);
  const entity = detail?.entity;

  function handleCopyCommandLine() {
    if (!entity?.process.command_line) return;
    copyText(entity.process.command_line);
    setCopyMessage("Command line copied to clipboard");
    window.setTimeout(() => setCopyMessage(null), 2000);
  }

  function handleCopyPid() {
    if (!entity) return;
    copyText(String(entity.process.pid));
    setCopyMessage(`PID ${entity.process.pid} copied to clipboard`);
    window.setTimeout(() => setCopyMessage(null), 2000);
  }

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-abyss/80 p-4 backdrop-blur-sm"
      role="presentation"
      onMouseDown={(event) => {
        // Close when clicking the overlay background (but not the dialog itself).
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div
        ref={containerRef}
        className="relative flex max-h-[88vh] w-full max-w-[min(1100px,92vw)] flex-col overflow-hidden rounded-[28px] border border-line bg-panel/95 shadow-panel"
        role="dialog"
        aria-modal="true"
        aria-labelledby={headingId}
        data-testid="process-detail-modal"
      >
        <header className="flex flex-wrap items-start justify-between gap-3 border-b border-line bg-abyss/50 p-5">
          <div className="min-w-0 flex-1">
            <p className="text-[10px] uppercase tracking-[0.18em] text-muted">Process inspector</p>
            <h2
              id={headingId}
              className="mt-1 flex items-center gap-2 text-lg font-semibold text-ink"
              data-testid="process-detail-modal-title"
            >
              {nodeIcon(entity)}
              {entity ? (
                <>
                  {reported(entity.process?.name)} <span className="font-mono text-sm text-muted">PID {entity.process?.pid}</span>
                </>
              ) : (
                "Process detail"
              )}
            </h2>
            {entity ? (
              <div className="mt-2 flex flex-wrap items-center gap-2 text-[11px]">
                <span
                  className={`rounded-md border px-2 py-0.5 ${visibilityToneClass(entity)}`}
                  data-testid="modal-visibility"
                >
                  {describeVisibility(entity)}
                </span>
                <span className="rounded-md border border-line bg-abyss/70 px-2 py-0.5 text-muted" data-testid="modal-confidence">
                  Confidence: {reported(entity.confidence)}
                </span>
                <span className="rounded-md border border-line bg-abyss/70 px-2 py-0.5 text-muted" data-testid="modal-sources">
                  Sources: {entity.sources.map(sourceBadge).join(", ") || "—"}
                </span>
                {entity.findings?.length ? (
                  <span className="rounded-md border border-amber-400/30 bg-amber-500/10 px-2 py-0.5 text-amber-100" data-testid="modal-findings">
                    Findings: {entity.findings.join(", ")}
                  </span>
                ) : null}
              </div>
            ) : null}
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={handleCopyPid}
              disabled={!entity}
              className="rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-xs text-muted disabled:opacity-50"
              data-testid="modal-copy-pid"
            >
              <Copy className="mr-1 inline h-3.5 w-3.5" />
              Copy PID
            </button>
            <button
              type="button"
              onClick={onClose}
              aria-label="Close process detail"
              data-testid="process-detail-modal-close"
              className="rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-xs"
            >
              <XCircle className="mr-1 inline h-3.5 w-3.5" />
              Close
            </button>
          </div>
        </header>

        <div
          role="tablist"
          aria-label="Process detail sections"
          className="flex flex-wrap gap-1 border-b border-line bg-abyss/30 px-5 py-2 text-xs"
          data-testid="process-detail-modal-tabs"
        >
          {TABS.map((t) => (
            <button
              key={t.key}
              role="tab"
              type="button"
              aria-selected={tab === t.key}
              aria-controls={`process-detail-modal-tabpanel-${t.key}`}
              id={`process-detail-modal-tab-${t.key}`}
              onClick={() => setTab(t.key)}
              data-testid={`process-detail-modal-tab-${t.key}`}
              className={`rounded-lg px-3 py-1.5 ${
                tab === t.key ? "bg-accent text-abyss" : "text-muted hover:bg-abyss/40"
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>

        <div className="flex-1 overflow-y-auto p-5" data-testid="process-detail-modal-body">
          {isLoading ? (
            <div className="space-y-3" role="status" aria-live="polite">
              <p className="text-sm text-muted">Loading process detail…</p>
              <div className="space-y-2">
                {Array.from({ length: 4 }).map((_, i) => (
                  <div key={i} className="h-12 animate-pulse rounded-xl border border-line bg-abyss/40" />
                ))}
              </div>
            </div>
          ) : error ? (
            <p className="rounded-2xl border border-rose-400/30 bg-rose-500/10 p-3 text-sm text-rose-100" role="alert">
              <AlertCircle className="mr-1 inline h-4 w-4" />
              {error.message}
            </p>
          ) : !entity ? (
            <p className="text-sm text-muted">No process selected.</p>
          ) : (
            <TabsContent
              tab={tab}
              detail={detail!}
              treePathNames={treePathNames}
              onSelectEntityId={onSelectEntityId}
              onOpenInGraph={onOpenInGraph}
              onShowInTree={onShowInTree}
              handleCopyCommandLine={handleCopyCommandLine}
            />
          )}
          {copyMessage ? (
            <p className="mt-3 rounded-md border border-sky-400/30 bg-sky-500/10 px-3 py-1.5 text-xs text-sky-100" role="status">
              {copyMessage}
            </p>
          ) : null}
        </div>
      </div>
    </div>
  );
}

function TabsContent({
  tab,
  detail,
  treePathNames,
  onSelectEntityId,
  onOpenInGraph,
  onShowInTree,
  handleCopyCommandLine,
}: {
  tab: TabKey;
  detail: MemoryProcessEntityDetail;
  treePathNames: string[];
  onSelectEntityId?: (entityId: string) => void;
  onOpenInGraph?: (entityId: string) => void;
  onShowInTree?: (entityId: string) => void;
  handleCopyCommandLine: () => void;
}) {
  const entity = detail.entity;
  if (tab === "overview") {
    return (
      <section
        role="tabpanel"
        id="process-detail-modal-tabpanel-overview"
        aria-labelledby="process-detail-modal-tab-overview"
        className="space-y-4"
        data-testid="process-detail-modal-tabpanel-overview"
      >
        <div className="grid gap-3 md:grid-cols-3">
          <Field label="PID" value={reported(entity.process?.pid)} mono />
          <Field label="PPID" value={reported(entity.process?.ppid)} mono />
          <Field label="Process name" value={reported(entity.process?.name)} />
          <Field label="Create time" value={reported(entity.process?.create_time)} mono />
          <Field label="Exit time" value={reported(entity.process?.exit_time)} mono />
          <Field label="Source count" value={String(entity.sources?.length ?? 0)} />
          <Field label="Visibility" value={describeVisibility(entity)} />
          <Field label="Confidence" value={reported(entity.confidence)} />
          <Field label="Findings" value={(detail.findings || []).join(", ") || "None"} />
        </div>
        <section
          className="rounded-2xl border border-line bg-abyss/40 p-3"
          data-testid="process-detail-modal-command-line"
        >
          <div className="flex flex-wrap items-center justify-between gap-2">
            <p className="text-[10px] uppercase tracking-[0.18em] text-muted">Command line</p>
            <button
              type="button"
              onClick={handleCopyCommandLine}
              disabled={!entity.process?.command_line}
              className="rounded-md border border-line bg-abyss/70 px-2 py-0.5 text-[10px] text-muted disabled:opacity-50"
              data-testid="process-detail-modal-copy-cmdline"
            >
              <Copy className="mr-1 inline h-3 w-3" />
              Copy
            </button>
          </div>
          <p
            className="mt-2 whitespace-pre-wrap break-words font-mono text-xs text-ink"
            data-testid="process-detail-modal-command-line-text"
          >
            {reported(entity.process?.command_line)}
          </p>
        </section>
      </section>
    );
  }
  if (tab === "relationships") {
    return (
      <section
        role="tabpanel"
        id="process-detail-modal-tabpanel-relationships"
        aria-labelledby="process-detail-modal-tab-relationships"
        className="space-y-4"
        data-testid="process-detail-modal-tabpanel-relationships"
      >
        <div className="grid gap-3 md:grid-cols-2">
          <Field label="Parent" value={detail.parent ? `${detail.parent.process?.name ?? "—"} (${detail.parent.process?.pid})` : "None"} />
          <Field label="Child count" value={String(detail.children.length)} />
          <Field label="Tree state" value={entity.tree?.is_root ? "Root" : entity.tree?.is_orphan ? "Orphan" : "Child"} />
          <Field label="Missing parent state" value={entity.tree?.is_unknown_parent ? "Yes" : "No"} />
        </div>
        <section className="rounded-2xl border border-line bg-abyss/40 p-3">
          <p className="text-[10px] uppercase tracking-[0.18em] text-muted">Tree path</p>
          <div className="mt-2">
            <BreadcrumbPath treePath={treePathNames} />
          </div>
        </section>
        <div className="flex flex-wrap gap-2" data-testid="process-detail-modal-actions">
          {detail.parent ? (
            <button
              type="button"
              onClick={() => onSelectEntityId?.(detail.parent!.process_entity_id)}
              className="rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-xs"
              data-testid="modal-open-parent"
            >
              <GitBranch className="mr-1 inline h-3.5 w-3.5" />
              Open parent ({detail.parent.process?.name} {detail.parent.process?.pid})
            </button>
          ) : null}
          <button
            type="button"
            onClick={() => onOpenInGraph?.(entity.process_entity_id)}
            disabled={!onOpenInGraph}
            className="rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-xs disabled:opacity-50"
            data-testid="modal-focus-in-graph"
          >
            <Eye className="mr-1 inline h-3.5 w-3.5" />
            Focus in visual graph
          </button>
          <button
            type="button"
            onClick={() => onShowInTree?.(entity.process_entity_id)}
            disabled={!onShowInTree}
            className="rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-xs disabled:opacity-50"
            data-testid="modal-show-in-tree"
          >
            <GitBranch className="mr-1 inline h-3.5 w-3.5" />
            Show in indented tree
          </button>
        </div>
        {detail.children.length > 0 ? (
          <section className="rounded-2xl border border-line bg-abyss/40 p-3">
            <p className="text-[10px] uppercase tracking-[0.18em] text-muted">Children</p>
            <ul className="mt-2 grid gap-1 text-xs">
              {detail.children.map((child) => (
                <li key={child.process_entity_id} className="flex flex-wrap items-center gap-2 rounded-md border border-line bg-abyss/60 p-2">
                  <span className="font-mono text-ink">{reported(child.process?.name)} (PID {child.process?.pid})</span>
                  <button
                    type="button"
                    onClick={() => onSelectEntityId?.(child.process_entity_id)}
                    className="rounded-md border border-line bg-abyss/70 px-2 py-0.5 text-[10px] text-accent"
                    data-testid="modal-open-child"
                  >
                    Open child
                  </button>
                </li>
              ))}
            </ul>
          </section>
        ) : null}
      </section>
    );
  }
  if (tab === "observations") {
    return (
      <section
        role="tabpanel"
        id="process-detail-modal-tabpanel-observations"
        aria-labelledby="process-detail-modal-tab-observations"
        className="space-y-3"
        data-testid="process-detail-modal-tabpanel-observations"
      >
        <div className="max-w-full overflow-x-auto rounded-2xl border border-line bg-abyss/40">
          <table className="min-w-[860px] w-full divide-y divide-line text-xs" data-testid="modal-observations-table">
            <thead className="bg-abyss/70 text-left text-[10px] uppercase tracking-[0.14em] text-muted">
              <tr>
                <th className="px-2 py-2">Plugin</th>
                <th className="px-2 py-2">PID</th>
                <th className="px-2 py-2">PPID</th>
                <th className="px-2 py-2">Name</th>
                <th className="px-2 py-2">Command line</th>
                <th className="px-2 py-2">Create</th>
                <th className="px-2 py-2">Exit</th>
                <th className="px-2 py-2">Plugin run</th>
                <th className="px-2 py-2">Source reference</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {detail.observations.map((obs) => {
                const obsPid = (obs.observed as { pid?: number | null } | undefined)?.pid;
                const obsPpid = (obs.observed as { ppid?: number | null } | undefined)?.ppid;
                const obsName = (obs.observed as { name?: string | null } | undefined)?.name;
                const obsCmd = (obs.observed as { command_line?: string | null } | undefined)?.command_line;
                const obsCreate = (obs.observed as { create_time?: string | null } | undefined)?.create_time;
                const obsExit = (obs.observed as { exit_time?: string | null } | undefined)?.exit_time;
                return (
                  <tr key={obs.document_id || `${entity.process_entity_id}-${obs.plugin_name}`}>
                    <td className="px-2 py-2 text-ink">{sourceBadge(obs.plugin_name)}</td>
                    <td className="px-2 py-2 text-muted">{reported(obsPid)}</td>
                    <td className="px-2 py-2 text-muted">{reported(obsPpid)}</td>
                    <td className="px-2 py-2 text-ink">{reported(obsName)}</td>
                    <td className="px-2 py-2 text-muted" title={reported(obsCmd)}>{reported(obsCmd)}</td>
                    <td className="px-2 py-2 text-muted">{reported(obsCreate)}</td>
                    <td className="px-2 py-2 text-muted">{reported(obsExit)}</td>
                    <td className="px-2 py-2 text-muted">{reported(obs.plugin_run_id)}</td>
                    <td className="px-2 py-2 text-muted">{reported(obs.source_record_id)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>
    );
  }
  return (
    <section
      role="tabpanel"
      id="process-detail-modal-tabpanel-raw"
      aria-labelledby="process-detail-modal-tab-raw"
      className="space-y-3"
      data-testid="process-detail-modal-tabpanel-raw"
    >
      <p className="text-xs text-muted">
        Only safe provenance references are listed. Paths, raw RAM and symbol cache locations
        are never displayed.
      </p>
      <ul className="space-y-2" data-testid="modal-raw-references">
        {(detail.source_record_refs || []).map((ref) => (
          <li key={ref} className="rounded-md border border-line bg-abyss/60 p-2 text-xs">
            <span className="font-mono text-ink">{ref}</span>
          </li>
        ))}
        {!detail.source_record_refs?.length ? (
          <li className="rounded-md border border-line bg-abyss/40 p-2 text-xs text-muted">
            No raw references recorded for this entity.
          </li>
        ) : null}
      </ul>
    </section>
  );
}
