import { useEffect, useId, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  api,
  type MemoryArtifactList,
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
  Loader2,
  ExternalLink,
  Cpu,
  Database,
  HardDrive,
  KeyRound,
  Shield,
  Globe,
  Box,
  MousePointer,
  Zap,
  FileCode,
} from "lucide-react";

type Props = {
  open: boolean;
  detail: MemoryProcessEntityDetail | null;
  isLoading: boolean;
  error: Error | null;
  caseId: string;
  evidenceId: string;
  runId: string | null;
  onClose: () => void;
  onSelectEntityId?: (entityId: string) => void;
  onOpenInGraph?: (entityId: string) => void;
  onShowInTree?: (entityId: string) => void;
};

type TabKey = "overview" | "relationships" | "observations" | "raw" | "command_line" | "environment" | "sids" | "privileges" | "network" | "modules" | "handles" | "suspicious" | "vads";

const TABS: { key: TabKey; label: string; icon?: React.ReactNode }[] = [
  { key: "overview", label: "Overview" },
  { key: "command_line", label: "Command line" },
  { key: "environment", label: "Environment" },
  { key: "sids", label: "SIDs" },
  { key: "privileges", label: "Privileges" },
  { key: "network", label: "Network" },
  { key: "modules", label: "Modules" },
  { key: "handles", label: "Handles" },
  { key: "suspicious", label: "Suspicious" },
  { key: "vads", label: "VADs" },
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

function tabPanelId(key: TabKey) { return `process-detail-modal-tabpanel-${key}`; }
function tabButtonId(key: TabKey) { return `process-detail-modal-tab-${key}`; }

function SectionPanel({ tab, title, children, testId }: { tab: TabKey; title: string; children: React.ReactNode; testId: string }) {
  return (
    <section role="tabpanel" id={tabPanelId(tab)} aria-labelledby={tabButtonId(tab)} className="space-y-3" data-testid={testId}>
      <p className="text-[10px] uppercase tracking-[0.18em] text-muted">{title}</p>
      {children}
    </section>
  );
}

const PAGE_SIZE = 30;

function SectionInfo({ total, source }: { total: number; source?: string }) {
  return (
    <div className="flex items-center gap-2 text-[10px] text-muted">
      <span>{total} result{total !== 1 ? "s" : ""}</span>
      {source ? <span className="rounded border border-line px-1.5 py-0.5">Source: {source}</span> : null}
    </div>
  );
}

function CommandLineSection({ entity }: { entity: MemoryProcessEntity | null | undefined }) {
  if (!entity) return <SectionPanel tab="command_line" title="Command line" testId="process-detail-modal-tabpanel-command-line"><p className="text-xs text-muted">No process selected.</p></SectionPanel>;
  const cmd = entity.process?.command_line;
  const alts = entity.findings || [];
  return (
    <SectionPanel tab="command_line" title="Command line" testId="process-detail-modal-tabpanel-command-line">
      <div className="rounded-2xl border border-line bg-abyss/40 p-4">
        <p className="text-[10px] uppercase tracking-[0.18em] text-muted mb-2">Canonical command line</p>
        {cmd ? (
          <pre className="whitespace-pre-wrap break-all font-mono text-xs text-ink max-h-48 overflow-y-auto">{cmd}</pre>
        ) : (
          <p className="text-xs text-muted">No command-line observation recorded for this process. windows.cmdline may not have been run or produced zero rows.</p>
        )}
      </div>
      {alts.length > 0 && (
        <div className="mt-2 text-[10px] text-muted">
          {alts.length} additional observation{alts.length !== 1 ? "s" : ""} available in the Observations tab.
        </div>
      )}
    </SectionPanel>
  );
}

function EnvironmentSection({ caseId, evidenceId, runId, pid }: { caseId: string; evidenceId: string; runId: string | null; pid: number | null }) {
  const [page, setPage] = useState(1);
  const qt = useQuery<MemoryArtifactList>({
    queryKey: ["memory-env-vars-detail", caseId, evidenceId, runId, pid, page],
    queryFn: () => api.getMemoryEnvVariables(caseId, { evidence_id: evidenceId, run_id: runId ?? undefined, pid: pid ?? undefined, page, page_size: PAGE_SIZE } as never),
    enabled: pid != null,
    refetchOnWindowFocus: false,
  });
  const data = qt.data;
  const items = data?.items ?? [];
  const total = data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  return <SectionPanel tab="environment" title="Environment variables" testId="process-detail-modal-tabpanel-environment">
    {qt.isLoading ? <p className="text-xs text-muted"><Loader2 className="mr-1 inline h-3 w-3 animate-spin" /> Loading…</p> : qt.isError ? <p className="text-xs text-rose-300">Failed to load environment variables.</p> : items.length === 0 ? <p className="text-xs text-muted">{pid != null ? "windows.envars completed but returned no rows for this process." : "No process selected."}</p> : (
      <>
        <SectionInfo total={total} source={typeof items[0] === "object" && items[0] ? (items[0] as Record<string, unknown>).source_plugin as string : undefined} />
        <div className="max-w-full overflow-x-auto rounded-2xl border border-line bg-abyss/40">
          <table className="min-w-[500px] w-full divide-y divide-line text-xs">
            <thead className="bg-abyss/70 text-left text-[10px] uppercase tracking-[0.14em] text-muted"><tr><th className="px-3 py-2">Variable</th><th className="px-3 py-2">Value</th></tr></thead>
            <tbody className="divide-y divide-line/60">
              {items.map((it) => { const r = it as Record<string, unknown>; return <tr key={r.document_id as string} className="hover:bg-abyss/30"><td className="px-3 py-1.5 font-mono whitespace-nowrap text-ink">{String(r.variable ?? "—")}</td><td className="px-3 py-1.5 text-muted max-w-md truncate" title={String(r.value ?? "")}>{String(r.value ?? "—")}</td></tr>; })}
            </tbody>
          </table>
        </div>
        {totalPages > 1 && (
          <div className="flex items-center justify-between text-xs"><button disabled={page <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))} className="rounded-xl border border-line bg-abyss/70 px-3 py-1.5 disabled:opacity-40">Previous</button><span className="text-muted">Page {page} of {totalPages}</span><button disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)} className="rounded-xl border border-line bg-abyss/70 px-3 py-1.5 disabled:opacity-40">Next</button></div>
        )}
      </>
    )}
  </SectionPanel>;
}

function SidsSection({ caseId, evidenceId, runId, pid }: { caseId: string; evidenceId: string; runId: string | null; pid: number | null }) {
  const [page, setPage] = useState(1);
  const qt = useQuery<MemoryArtifactList>({
    queryKey: ["memory-sids-detail", caseId, evidenceId, runId, pid, page],
    queryFn: () => api.getMemorySids(caseId, { evidence_id: evidenceId, run_id: runId ?? undefined, pid: pid ?? undefined, page, page_size: PAGE_SIZE } as never),
    enabled: pid != null,
    refetchOnWindowFocus: false,
  });
  const data = qt.data;
  const items = data?.items ?? [];
  const total = data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  return <SectionPanel tab="sids" title="Security Identifiers (SIDs)" testId="process-detail-modal-tabpanel-sids">
    {qt.isLoading ? <p className="text-xs text-muted"><Loader2 className="mr-1 inline h-3 w-3 animate-spin" /> Loading…</p> : qt.isError ? <p className="text-xs text-rose-300">Failed to load SIDs.</p> : items.length === 0 ? <p className="text-xs text-muted">{pid != null ? "windows.getsids completed but returned no rows for this process." : "No process selected."}</p> : (
      <>
        <SectionInfo total={total} />
        <div className="max-w-full overflow-x-auto rounded-2xl border border-line bg-abyss/40">
          <table className="min-w-[400px] w-full divide-y divide-line text-xs">
            <thead className="bg-abyss/70 text-left text-[10px] uppercase tracking-[0.14em] text-muted"><tr><th className="px-3 py-2">SID</th><th className="px-3 py-2">Resolved name</th></tr></thead>
            <tbody className="divide-y divide-line/60">
              {items.map((it) => { const r = it as Record<string, unknown>; return <tr key={r.document_id as string} className="hover:bg-abyss/30"><td className="px-3 py-1.5 font-mono text-ink">{String(r.sid ?? "—")}</td><td className="px-3 py-1.5 text-muted">{String(r.resolved_name ?? "—")}</td></tr>; })}
            </tbody>
          </table>
        </div>
        {totalPages > 1 && <div className="flex items-center justify-between text-xs"><button disabled={page <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))} className="rounded-xl border border-line bg-abyss/70 px-3 py-1.5 disabled:opacity-40">Previous</button><span className="text-muted">Page {page} of {totalPages}</span><button disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)} className="rounded-xl border border-line bg-abyss/70 px-3 py-1.5 disabled:opacity-40">Next</button></div>}
      </>
    )}
  </SectionPanel>;
}

function PrivilegesSection({ caseId, evidenceId, runId, pid }: { caseId: string; evidenceId: string; runId: string | null; pid: number | null }) {
  const [page, setPage] = useState(1);
  const [enabledOnly, setEnabledOnly] = useState(false);
  const qt = useQuery<MemoryArtifactList>({
    queryKey: ["memory-privs-detail", caseId, evidenceId, runId, pid, page, enabledOnly],
    queryFn: () => api.getMemoryPrivileges(caseId, { evidence_id: evidenceId, run_id: runId ?? undefined, pid: pid ?? undefined, enabled: enabledOnly || undefined, page, page_size: PAGE_SIZE } as never),
    enabled: pid != null,
    refetchOnWindowFocus: false,
  });
  const data = qt.data;
  const items = data?.items ?? [];
  const total = data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  return <SectionPanel tab="privileges" title="Process privileges" testId="process-detail-modal-tabpanel-privileges">
    {qt.isLoading ? <p className="text-xs text-muted"><Loader2 className="mr-1 inline h-3 w-3 animate-spin" /> Loading…</p> : qt.isError ? <p className="text-xs text-rose-300">Failed to load privileges.</p> : items.length === 0 ? <p className="text-xs text-muted">{pid != null ? "windows.privileges completed but returned no rows for this process." : "No process selected."}</p> : (
      <>
        <div className="flex items-center justify-between gap-2">
          <SectionInfo total={total} />
          <label className="flex items-center gap-1.5 text-[11px] text-muted"><input type="checkbox" checked={enabledOnly} onChange={(e) => { setEnabledOnly(e.target.checked); setPage(1); }} className="rounded" /> Enabled only</label>
        </div>
        <div className="max-w-full overflow-x-auto rounded-2xl border border-line bg-abyss/40">
          <table className="min-w-[500px] w-full divide-y divide-line text-xs">
            <thead className="bg-abyss/70 text-left text-[10px] uppercase tracking-[0.14em] text-muted"><tr><th className="px-3 py-2">Privilege</th><th className="px-3 py-2">State</th><th className="px-3 py-2">Description</th></tr></thead>
            <tbody className="divide-y divide-line/60">
              {items.map((it) => { const r = it as Record<string, unknown>; const en = r.enabled; return <tr key={r.document_id as string} className="hover:bg-abyss/30"><td className="px-3 py-1.5 font-mono text-ink">{String(r.privilege ?? "—")}</td><td className="px-3 py-1.5"><span className={`rounded px-1.5 py-0.5 text-[10px] ${en ? "bg-emerald-500/20 text-emerald-200" : "bg-abyss/70 text-muted"}`}>{en ? "Enabled" : "Disabled"}</span></td><td className="px-3 py-1.5 text-muted max-w-xs truncate">{String(r.description ?? "—")}</td></tr>; })}
            </tbody>
          </table>
        </div>
        {totalPages > 1 && <div className="flex items-center justify-between text-xs"><button disabled={page <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))} className="rounded-xl border border-line bg-abyss/70 px-3 py-1.5 disabled:opacity-40">Previous</button><span className="text-muted">Page {page} of {totalPages}</span><button disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)} className="rounded-xl border border-line bg-abyss/70 px-3 py-1.5 disabled:opacity-40">Next</button></div>}
      </>
    )}
  </SectionPanel>;
}

function ArtifactLazySection({ tab, title, testId, caseId, evidenceId, runId, pid, queryKey, fetcher, columns, emptyMsg }: {
  tab: TabKey; title: string; testId: string; caseId: string; evidenceId: string; runId: string | null; pid: number | null;
  queryKey: string; fetcher: (caseId: string, params: Record<string, unknown>) => Promise<MemoryArtifactList>;
  columns: { label: string; key: string; render?: (r: Record<string, unknown>) => React.ReactNode }[]; emptyMsg: string;
}) {
  const [page, setPage] = useState(1);
  const qt = useQuery<MemoryArtifactList>({
    queryKey: [queryKey, caseId, evidenceId, runId, pid, page],
    queryFn: () => fetcher(caseId, { evidence_id: evidenceId, run_id: runId ?? undefined, pid: pid ?? undefined, page, page_size: PAGE_SIZE }),
    enabled: pid != null,
    refetchOnWindowFocus: false,
  });
  const data = qt.data;
  const items = data?.items ?? [];
  const total = data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  return <SectionPanel tab={tab} title={title} testId={testId}>
    {qt.isLoading ? <p className="text-xs text-muted"><Loader2 className="mr-1 inline h-3 w-3 animate-spin" /> Loading…</p> :
     qt.isError ? <p className="text-xs text-rose-300">Failed to load {title.toLowerCase()}.</p> :
     items.length === 0 ? <p className="text-xs text-muted">{pid != null ? emptyMsg : "No process selected."}</p> : (
      <>
        <SectionInfo total={total} />
        <div className="max-w-full overflow-x-auto rounded-2xl border border-line bg-abyss/40">
          <table className="min-w-[500px] w-full divide-y divide-line text-xs">
            <thead className="bg-abyss/70 text-left text-[10px] uppercase tracking-[0.14em] text-muted"><tr>{columns.map((c) => <th key={c.key} className="px-3 py-2">{c.label}</th>)}</tr></thead>
            <tbody className="divide-y divide-line/60">
              {items.map((it) => { const r = it as Record<string, unknown>; return <tr key={r.document_id as string} className="hover:bg-abyss/30">{columns.map((c) => <td key={c.key} className="px-3 py-1.5 text-muted whitespace-nowrap">{c.render ? c.render(r) : String(r[c.key] ?? "—")}</td>)}</tr>; })}
            </tbody>
          </table>
        </div>
        {totalPages > 1 && <div className="flex items-center justify-between text-xs"><button disabled={page <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))} className="rounded-xl border border-line bg-abyss/70 px-3 py-1.5 disabled:opacity-40">Previous</button><span className="text-muted">Page {page} of {totalPages}</span><button disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)} className="rounded-xl border border-line bg-abyss/70 px-3 py-1.5 disabled:opacity-40">Next</button></div>}
      </>
    )}
  </SectionPanel>;
}

function NetworkSection({ caseId, evidenceId, runId, pid }: { caseId: string; evidenceId: string; runId: string | null; pid: number | null }) {
  return <ArtifactLazySection tab="network" title="Network connections" testId="process-detail-modal-tabpanel-network" caseId={caseId} evidenceId={evidenceId} runId={runId} pid={pid} queryKey="modal-network" fetcher={api.getMemoryNetworkConnections as (cid: string, p: Record<string, unknown>) => Promise<MemoryArtifactList>}
    columns={[{ label: "Protocol", key: "protocol" }, { label: "Local", key: "local_address", render: (r: Record<string, unknown>) => <span>{String(r.local_address ?? "—")}:{String(r.local_port ?? "")}</span> }, { label: "Remote", key: "remote_address", render: (r: Record<string, unknown>) => <span>{String(r.remote_address ?? "—")}:{String(r.remote_port ?? "")}</span> }, { label: "State", key: "state" }, { label: "Source", key: "source_plugin", render: (r: Record<string, unknown>) => String(r.source_plugin ?? "").replace("windows.", "") }]}
    emptyMsg="No network connections found for this process." />;
}

function ModulesSection({ caseId, evidenceId, runId, pid }: { caseId: string; evidenceId: string; runId: string | null; pid: number | null }) {
  return <ArtifactLazySection tab="modules" title="Modules and DLLs" testId="process-detail-modal-tabpanel-modules" caseId={caseId} evidenceId={evidenceId} runId={runId} pid={pid} queryKey="modal-modules" fetcher={api.getMemoryProcessModules as (cid: string, p: Record<string, unknown>) => Promise<MemoryArtifactList>}
    columns={[{ label: "Module", key: "module_name" }, { label: "Path", key: "path", render: (r: Record<string, unknown>) => <span className="max-w-[200px] truncate inline-block" title={String(r.path ?? "")}>{String(r.path ?? "—")}</span> }, { label: "Base", key: "base_address" }, { label: "Size", key: "size" }, { label: "Load", key: "load_state" }, { label: "Source", key: "source_plugin", render: (r: Record<string, unknown>) => String(r.source_plugin ?? "").replace("windows.", "") }]}
    emptyMsg="No modules found for this process." />;
}

function HandlesSection({ caseId, evidenceId, runId, pid }: { caseId: string; evidenceId: string; runId: string | null; pid: number | null }) {
  return <ArtifactLazySection tab="handles" title="Handles" testId="process-detail-modal-tabpanel-handles" caseId={caseId} evidenceId={evidenceId} runId={runId} pid={pid} queryKey="modal-handles" fetcher={api.getMemoryHandles as (cid: string, p: Record<string, unknown>) => Promise<MemoryArtifactList>}
    columns={[{ label: "Handle", key: "handle_value" }, { label: "Type", key: "object_type" }, { label: "Name", key: "object_name", render: (r: Record<string, unknown>) => <span className="max-w-[250px] truncate inline-block" title={String(r.object_name ?? "")}>{String(r.object_name ?? "—")}</span> }, { label: "Access", key: "granted_access" }]}
    emptyMsg="No handles found for this process." />;
}

function SuspiciousSection({ caseId, evidenceId, runId, pid }: { caseId: string; evidenceId: string; runId: string | null; pid: number | null }) {
  return <ArtifactLazySection tab="suspicious" title="Suspicious memory regions" testId="process-detail-modal-tabpanel-suspicious" caseId={caseId} evidenceId={evidenceId} runId={runId} pid={pid} queryKey="modal-suspicious" fetcher={api.getMemorySuspiciousRegions as (cid: string, p: Record<string, unknown>) => Promise<MemoryArtifactList>}
    columns={[{ label: "Start", key: "start_address" }, { label: "End", key: "end_address" }, { label: "Protection", key: "protection" }, { label: "Tag", key: "tag" }, { label: "Source", key: "source_plugin", render: (r: Record<string, unknown>) => String(r.source_plugin ?? "").replace("windows.", "") }]}
    emptyMsg="No suspicious memory regions found for this process." />;
}

function VadsSection({ caseId, evidenceId, runId, pid }: { caseId: string; evidenceId: string; runId: string | null; pid: number | null }) {
  const [page, setPage] = useState(1);
  const qt = useQuery<MemoryArtifactList>({
    queryKey: ["modal-vads", caseId, evidenceId, runId, pid, page],
    queryFn: () => api.getMemoryVads(caseId, { evidence_id: evidenceId, run_id: runId ?? undefined, pid: pid ?? undefined, page, page_size: PAGE_SIZE } as never),
    enabled: pid != null,
    refetchOnWindowFocus: false,
  });
  const data = qt.data;
  const items = data?.items ?? [];
  const total = data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  return <SectionPanel tab="vads" title="Virtual Address Descriptors (VADs)" testId="process-detail-modal-tabpanel-vads">
    {qt.isLoading ? <p className="text-xs text-muted"><Loader2 className="mr-1 inline h-3 w-3 animate-spin" /> Loading…</p> : qt.isError ? <p className="text-xs text-rose-300">Failed to load VADs.</p> : items.length === 0 ? <p className="text-xs text-muted">{pid != null ? "No VAD regions found for this process." : "No process selected."}</p> : (
      <>
        <SectionInfo total={total} />
        <div className="max-w-full overflow-x-auto rounded-2xl border border-line bg-abyss/40">
          <table className="min-w-[700px] w-full divide-y divide-line text-xs">
            <thead className="bg-abyss/70 text-left text-[10px] uppercase tracking-[0.14em] text-muted"><tr><th className="px-3 py-2">Start</th><th className="px-3 py-2">End</th><th className="px-3 py-2">Protection</th><th className="px-3 py-2">Tag</th><th className="px-3 py-2">Commit</th><th className="px-3 py-2">Private</th><th className="px-3 py-2">File</th></tr></thead>
            <tbody className="divide-y divide-line/60">
              {items.map((it) => { const r = it as Record<string, unknown>; return <tr key={r.document_id as string} className="hover:bg-abyss/30"><td className="px-3 py-1.5 font-mono text-ink">{String(r.start_address ?? "—")}</td><td className="px-3 py-1.5 font-mono text-ink">{String(r.end_address ?? "—")}</td><td className="px-3 py-1.5 text-muted">{String(r.protection ?? "—")}</td><td className="px-3 py-1.5 text-muted">{String(r.tag ?? "—")}</td><td className="px-3 py-1.5 text-muted">                {String(r.commit_charge ?? "—")}</td><td className="px-3 py-1.5"><span className={`rounded px-1.5 py-0.5 text-[10px] ${r.private_memory ? "bg-emerald-500/20 text-emerald-200" : "bg-abyss/70 text-muted"}`}>{r.private_memory ? "Private" : "Shared"}</span></td><td className="px-3 py-1.5 text-muted max-w-[200px] truncate" title={String(r.file_object ?? "")}>{String(r.file_object ?? "—")}</td></tr>; })}
            </tbody>
          </table>
        </div>
        {totalPages > 1 && <div className="flex items-center justify-between text-xs"><button disabled={page <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))} className="rounded-xl border border-line bg-abyss/70 px-3 py-1.5 disabled:opacity-40">Previous</button><span className="text-muted">Page {page} of {totalPages}</span><button disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)} className="rounded-xl border border-line bg-abyss/70 px-3 py-1.5 disabled:opacity-40">Next</button></div>}
      </>
    )}
  </SectionPanel>;
}

export function ProcessDetailModal({
  open,
  detail,
  isLoading,
  error,
  caseId,
  evidenceId,
  runId,
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
              caseId={caseId}
              evidenceId={evidenceId}
              runId={runId}
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
  caseId,
  evidenceId,
  runId,
}: {
  tab: TabKey;
  detail: MemoryProcessEntityDetail;
  treePathNames: string[];
  onSelectEntityId?: (entityId: string) => void;
  onOpenInGraph?: (entityId: string) => void;
  onShowInTree?: (entityId: string) => void;
  handleCopyCommandLine: () => void;
  caseId: string;
  evidenceId: string;
  runId: string | null;
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
  if (tab === "command_line") {
    return <CommandLineSection entity={entity} />;
  }
  if (tab === "environment") {
    return <EnvironmentSection caseId={caseId} evidenceId={evidenceId} runId={runId} pid={entity?.process?.pid ?? null} />;
  }
  if (tab === "sids") {
    return <SidsSection caseId={caseId} evidenceId={evidenceId} runId={runId} pid={entity?.process?.pid ?? null} />;
  }
  if (tab === "privileges") {
    return <PrivilegesSection caseId={caseId} evidenceId={evidenceId} runId={runId} pid={entity?.process?.pid ?? null} />;
  }
  if (tab === "network") {
    return <NetworkSection caseId={caseId} evidenceId={evidenceId} runId={runId} pid={entity?.process?.pid ?? null} />;
  }
  if (tab === "modules") {
    return <ModulesSection caseId={caseId} evidenceId={evidenceId} runId={runId} pid={entity?.process?.pid ?? null} />;
  }
  if (tab === "handles") {
    return <HandlesSection caseId={caseId} evidenceId={evidenceId} runId={runId} pid={entity?.process?.pid ?? null} />;
  }
  if (tab === "suspicious") {
    return <SuspiciousSection caseId={caseId} evidenceId={evidenceId} runId={runId} pid={entity?.process?.pid ?? null} />;
  }
  if (tab === "vads") {
    return <VadsSection caseId={caseId} evidenceId={evidenceId} runId={runId} pid={entity?.process?.pid ?? null} />;
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
