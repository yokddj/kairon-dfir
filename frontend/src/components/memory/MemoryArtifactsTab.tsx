import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  type MemoryArtifactDetail,
  type MemoryArtifactList,
  type MemoryArtifactOverview,
  type MemoryProcessEntity,
  type MemoryRunSelector,
  api,
} from "../../api/client";
import { ProcessDetailModal } from "./ProcessDetailModal";
import {
  AlertCircle,
  ChevronRight,
  Copy,
  ExternalLink,
  Eye,
  Filter,
  Network,
  RefreshCw,
  Search,
} from "lucide-react";

type Props = {
  caseId: string;
  runOptions: MemoryRunSelector | null;
  selectedRunId: string | null;
  onSelectRunId: (next: string | null) => void;
  onSelectEntity: (entityId: string) => void;
  onJumpToProcesses: (entityId: string) => void;
  onJumpToGraph: (entityId: string) => void;
  onJumpToTree: (entityId: string) => void;
  evidenceId?: string;
};

type SubView =
  | "network"
  | "modules"
  | "handles"
  | "drivers"
  | "kernel"
  | "suspicious";

const SUBVIEWS: ReadonlyArray<{ key: SubView; label: string; testId: string; description: string; family: string }> = [
  { key: "network", label: "Network", testId: "memory-artifacts-subview-network", description: "TCP/UDP endpoints observed in memory.", family: "network" },
  { key: "modules", label: "Modules", testId: "memory-artifacts-subview-modules", description: "DLLs and per-process modules (dlllist + ldrmodules).", family: "modules" },
  { key: "handles", label: "Handles", testId: "memory-artifacts-subview-handles", description: "Kernel handles per process.", family: "handles" },
  { key: "drivers", label: "Drivers", testId: "memory-artifacts-subview-drivers", description: "Loaded drivers (driverscan, scan-only).", family: "drivers" },
  { key: "kernel", label: "Kernel modules", testId: "memory-artifacts-subview-kernel", description: "Kernel modules (windows.modules).", family: "kernel_modules" },
  { key: "suspicious", label: "Suspicious regions", testId: "memory-artifacts-subview-suspicious", description: "Indicators (windows.malfind), needs review.", family: "suspicious_regions" },
];

function reported(value: unknown): string {
  if (value === null || value === undefined || value === "") return "—";
  return String(value);
}

function safeNum(value: unknown): number | null {
  if (value === null || value === undefined || value === "") return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function RunPicker({
  runOptions,
  selectedRunId,
  onSelectRunId,
  testId,
}: {
  runOptions: MemoryRunSelector | null;
  selectedRunId: string | null;
  onSelectRunId: (next: string | null) => void;
  testId: string;
}) {
  const runs = (runOptions?.runs || []).filter(
    (r) =>
      r.profile === "processes_basic" ||
      r.profile === "processes_extended" ||
      r.profile === "network_basic" ||
      r.profile === "modules_basic" ||
      r.profile === "handles_basic" ||
      r.profile === "kernel_basic" ||
      r.profile === "suspicious_memory" ||
      r.profile === "metadata_only",
  );
  return (
    <div className="flex flex-wrap items-center gap-2 text-xs">
      <label className="text-muted" htmlFor={testId}>Run</label>
      <select
        id={testId}
        value={selectedRunId || ""}
        onChange={(event) => onSelectRunId(event.target.value || null)}
        className="rounded-xl border border-line bg-abyss/70 px-2 py-1 text-sm"
        data-testid={testId}
      >
        <option value="">Latest</option>
        {runs.map((run) => (
          <option key={run.run_id} value={run.run_id}>
            {run.profile} · {run.status} · {(run.completed_at || run.created_at).slice(0, 16).replace("T", " ")} UTC
          </option>
        ))}
      </select>
    </div>
  );
}

function NotAnalyzedCard({ label, testId }: { label: string; testId: string }) {
  return (
    <div
      className="rounded-xl border border-line bg-abyss/40 px-3 py-2"
      data-testid={`memory-artifacts-${testId}`}
    >
      <p className="text-[10px] uppercase tracking-[0.18em] text-muted">{label}</p>
      <p className="mt-1 text-base text-muted" data-testid={`memory-artifacts-${testId}-value`}>
        Not analyzed
      </p>
    </div>
  );
}

function CountCard({ label, value, testId }: { label: string; value: number | null; testId: string }) {
  return (
    <div
      className="rounded-xl border border-line bg-abyss/40 px-3 py-2"
      data-testid={`memory-artifacts-${testId}`}
    >
      <p className="text-[10px] uppercase tracking-[0.18em] text-muted">{label}</p>
      <p className="mt-1 text-base font-semibold text-ink" data-testid={`memory-artifacts-${testId}-value`}>
        {value === null ? "Not analyzed" : value}
      </p>
    </div>
  );
}

function FamilyCountCard({
  label,
  testId,
  familyValue,
}: {
  label: string;
  testId: string;
  familyValue?: { count?: number | null; analysis_state?: string | null; active_run?: { id?: string; profile?: string } | null };
}) {
  // The per-family card distinguishes the truthful states:
  // * not_analyzed:    no compatible run yet (show "Not analyzed")
  // * failed:          latest attempt failed (show "Not analyzed")
  // * unavailable:     the family is unavailable in this runtime
  // * analyzed_empty:  successful run with zero rows (show "0")
  // * analyzed_with_results: successful run with rows (show the count)
  // * partial:         run finished with plugin failures (show the count)
  const state = familyValue?.analysis_state ?? "not_analyzed";
  const count = familyValue?.count ?? 0;
  const showZero = state === "analyzed_empty" || state === "analyzed_with_results" || state === "partial";
  const display = showZero ? count : null;
  return (
    <div
      className="rounded-xl border border-line bg-abyss/40 px-3 py-2"
      data-testid={`memory-artifacts-${testId}`}
      data-state={state}
    >
      <p className="text-[10px] uppercase tracking-[0.18em] text-muted">{label}</p>
      <p className="mt-1 text-base font-semibold text-ink" data-testid={`memory-artifacts-${testId}-value`}>
        {display === null ? "Not analyzed" : display}
      </p>
    </div>
  );
}

function Pagination({
  page,
  totalPages,
  onPage,
  testId,
}: {
  page: number;
  totalPages: number;
  onPage: (next: number) => void;
  testId: string;
}) {
  return (
    <div className="flex items-center justify-between text-xs" data-testid={testId}>
      <span className="text-muted">Page {page} of {totalPages}</span>
      <div className="flex gap-2">
        <button
          type="button"
          onClick={() => onPage(Math.max(1, page - 1))}
          disabled={page <= 1}
          className="rounded-md border border-line bg-abyss/70 px-2 py-1 disabled:opacity-50"
          data-testid={`${testId}-prev`}
        >
          Previous
        </button>
        <button
          type="button"
          onClick={() => onPage(Math.min(totalPages, page + 1))}
          disabled={page >= totalPages}
          className="rounded-md border border-line bg-abyss/70 px-2 py-1 disabled:opacity-50"
          data-testid={`${testId}-next`}
        >
          Next
        </button>
      </div>
    </div>
  );
}

function ProcessLink({ entity, onOpen, onGraph, onTree, testId }: {
  entity: { pid?: number | null; name?: string | null; process_entity_id?: string | null } | null;
  onOpen: (entityId: string) => void;
  onGraph: (entityId: string) => void;
  onTree: (entityId: string) => void;
  testId: string;
}) {
  if (!entity || entity.process_entity_id) {
    if (!entity) return <span className="text-muted">—</span>;
    return (
      <span className="font-mono text-xs text-ink" data-testid={testId}>
        {reported(entity.name)} ({reported(entity.pid)})
      </span>
    );
  }
  return (
    <span className="flex flex-wrap items-center gap-1 text-xs" data-testid={testId}>
      <span className="font-mono text-ink">{reported(entity.name)} ({reported(entity.pid)})</span>
      <span className="rounded-md border border-amber-400/30 bg-amber-500/10 px-1.5 py-0.5 text-[10px] text-amber-100" data-testid={`${testId}-unresolved`}>
        unresolved
      </span>
    </span>
  );
}

function ProcessActions({ entity, onOpen, onGraph, onTree, onModal, testId }: {
  entity: { process_entity_id?: string | null; pid?: number | null; name?: string | null };
  onOpen: (entityId: string) => void;
  onGraph: (entityId: string) => void;
  onTree: (entityId: string) => void;
  onModal: (entityId: string) => void;
  testId: string;
}) {
  const entId = entity?.process_entity_id;
  if (!entId) {
    return (
      <button
        type="button"
        onClick={() => entity?.pid !== undefined && onModal(`pid:${entity?.pid}`)}
        className="rounded-md border border-line bg-abyss/70 px-2 py-0.5 text-[10px] text-muted"
        data-testid={`${testId}-no-entity`}
      >
        Open details
      </button>
    );
  }
  return (
    <div className="flex flex-wrap gap-1" data-testid={testId}>
      <button
        type="button"
        onClick={() => onOpen(entId)}
        className="rounded-md border border-accent/40 bg-accent/10 px-2 py-0.5 text-[10px] text-accent"
        data-testid={`${testId}-open`}
      >
        Open process
      </button>
      <button
        type="button"
        onClick={() => onGraph(entId)}
        className="rounded-md border border-line bg-abyss/70 px-2 py-0.5 text-[10px] text-muted"
        data-testid={`${testId}-graph`}
      >
        Focus graph
      </button>
      <button
        type="button"
        onClick={() => onTree(entId)}
        className="rounded-md border border-line bg-abyss/70 px-2 py-0.5 text-[10px] text-muted"
        data-testid={`${testId}-tree`}
      >
        Show in tree
      </button>
    </div>
  );
}

function NetworkTable({ items, onModal, onOpen, onGraph, onTree }: {
  items: Array<Record<string, unknown> & { document_id: string }>;
  onModal: (id: string) => void;
  onOpen: (id: string) => void;
  onGraph: (id: string) => void;
  onTree: (id: string) => void;
}) {
  if (!items.length) {
    return <p className="rounded-2xl border border-line bg-abyss/40 p-3 text-xs text-muted" data-testid="memory-artifacts-network-empty">No network connections indexed for this run.</p>;
  }
  return (
    <div className="max-w-full overflow-x-auto rounded-2xl border border-line bg-abyss/40">
      <table className="min-w-[1100px] w-full divide-y divide-line text-xs" data-testid="memory-artifacts-network-table">
        <thead className="bg-abyss/70 text-left text-[10px] uppercase tracking-[0.14em] text-muted">
          <tr>
            <th className="px-2 py-1">Protocol</th>
            <th className="px-2 py-1">Local</th>
            <th className="px-2 py-1">Remote</th>
            <th className="px-2 py-1">State</th>
            <th className="px-2 py-1">PID</th>
            <th className="px-2 py-1">Process</th>
            <th className="px-2 py-1">Created</th>
            <th className="px-2 py-1">Source</th>
            <th className="px-2 py-1">Actions</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-line">
          {items.map((row) => (
            <tr key={row.document_id} data-testid="memory-artifacts-network-row">
              <td className="px-2 py-1 text-ink">{reported((row as any).protocol)}</td>
              <td className="px-2 py-1 text-muted">{reported((row as any).local_address)}:{reported((row as any).local_port)}</td>
              <td className="px-2 py-1 text-muted">{reported((row as any).remote_address)}:{reported((row as any).remote_port)}</td>
              <td className="px-2 py-1 text-muted">{reported((row as any).state)}</td>
              <td className="px-2 py-1 text-muted">{reported((row as any).pid)}</td>
              <td className="px-2 py-1">
                <ProcessLink
                  entity={{ pid: (row as any).pid, name: (row as any).process_name, process_entity_id: (row as any).process_entity_id }}
                  onOpen={onOpen}
                  onGraph={onGraph}
                  onTree={onTree}
                  testId="memory-artifacts-network-process"
                />
              </td>
              <td className="px-2 py-1 text-muted">{reported((row as any).create_time)}</td>
              <td className="px-2 py-1 text-muted">{reported((row as any).source_plugin)}</td>
              <td className="px-2 py-1">
                <ProcessActions
                  entity={{ pid: (row as any).pid, name: (row as any).process_name, process_entity_id: (row as any).process_entity_id }}
                  onOpen={onOpen}
                  onGraph={onGraph}
                  onTree={onTree}
                  onModal={onModal}
                  testId="memory-artifacts-network-actions"
                />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ModuleRow({ row, onModal, onOpen, onGraph, onTree }: {
  row: any;
  onModal: (id: string) => void;
  onOpen: (id: string) => void;
  onGraph: (id: string) => void;
  onTree: (id: string) => void;
}) {
  return (
    <tr key={row.document_id} data-testid="memory-artifacts-modules-row">
      <td className="px-2 py-1 text-ink">{reported(row.pid)}</td>
      <td className="px-2 py-1">
        <ProcessLink
          entity={{ pid: row.pid, name: row.process_name, process_entity_id: row.process_entity_id }}
          onOpen={onOpen}
          onGraph={onGraph}
          onTree={onTree}
          testId="memory-artifacts-modules-process"
        />
      </td>
      <td className="px-2 py-1 text-ink">{reported(row.module_name)}</td>
      <td className="max-w-[280px] truncate px-2 py-1 text-muted" title={reported(row.path)}>{reported(row.path)}</td>
      <td className="px-2 py-1 text-muted">{reported(row.base_address)}</td>
      <td className="px-2 py-1 text-muted">{reported(row.size)}</td>
      <td className="px-2 py-1 text-muted">{reported(row.load_state)}</td>
      <td className="px-2 py-1 text-muted">{(row.source_plugins || []).join(", ")}</td>
      <td className="px-2 py-1 text-muted">{(row.findings || []).join(", ") || "—"}</td>
      <td className="px-2 py-1">
        <ProcessActions
          entity={{ pid: row.pid, name: row.process_name, process_entity_id: row.process_entity_id }}
          onOpen={onOpen}
          onGraph={onGraph}
          onTree={onTree}
          onModal={onModal}
          testId="memory-artifacts-modules-actions"
        />
      </td>
    </tr>
  );
}

function ModulesTable({ items, onModal, onOpen, onGraph, onTree }: {
  items: Array<Record<string, unknown> & { document_id: string }>;
  onModal: (id: string) => void;
  onOpen: (id: string) => void;
  onGraph: (id: string) => void;
  onTree: (id: string) => void;
}) {
  if (!items.length) {
    return <p className="rounded-2xl border border-line bg-abyss/40 p-3 text-xs text-muted" data-testid="memory-artifacts-modules-empty">No process modules indexed for this run.</p>;
  }
  return (
    <div className="max-w-full overflow-x-auto rounded-2xl border border-line bg-abyss/40">
      <table className="min-w-[1100px] w-full divide-y divide-line text-xs" data-testid="memory-artifacts-modules-table">
        <thead className="bg-abyss/70 text-left text-[10px] uppercase tracking-[0.14em] text-muted">
          <tr>
            <th className="px-2 py-1">PID</th>
            <th className="px-2 py-1">Process</th>
            <th className="px-2 py-1">Module</th>
            <th className="px-2 py-1">Path</th>
            <th className="px-2 py-1">Base</th>
            <th className="px-2 py-1">Size</th>
            <th className="px-2 py-1">Load</th>
            <th className="px-2 py-1">Sources</th>
            <th className="px-2 py-1">Findings</th>
            <th className="px-2 py-1">Actions</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-line">
          {items.map((row) => <ModuleRow key={row.document_id} row={row} onModal={onModal} onOpen={onOpen} onGraph={onGraph} onTree={onTree} />)}
        </tbody>
      </table>
    </div>
  );
}

function HandlesTable({ items, onModal, onOpen, onGraph, onTree }: {
  items: Array<Record<string, unknown> & { document_id: string }>;
  onModal: (id: string) => void;
  onOpen: (id: string) => void;
  onGraph: (id: string) => void;
  onTree: (id: string) => void;
}) {
  if (!items.length) {
    return <p className="rounded-2xl border border-line bg-abyss/40 p-3 text-xs text-muted" data-testid="memory-artifacts-handles-empty">No handles indexed for this run.</p>;
  }
  return (
    <div className="max-w-full overflow-x-auto rounded-2xl border border-line bg-abyss/40">
      <table className="min-w-[900px] w-full divide-y divide-line text-xs" data-testid="memory-artifacts-handles-table">
        <thead className="bg-abyss/70 text-left text-[10px] uppercase tracking-[0.14em] text-muted">
          <tr>
            <th className="px-2 py-1">PID</th>
            <th className="px-2 py-1">Process</th>
            <th className="px-2 py-1">Type</th>
            <th className="px-2 py-1">Object</th>
            <th className="px-2 py-1">Handle</th>
            <th className="px-2 py-1">Access</th>
            <th className="px-2 py-1">Actions</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-line">
          {items.map((row: any) => (
            <tr key={row.document_id} data-testid="memory-artifacts-handles-row">
              <td className="px-2 py-1 text-ink">{reported(row.pid)}</td>
              <td className="px-2 py-1">
                <ProcessLink
                  entity={{ pid: row.pid, name: row.process_name, process_entity_id: row.process_entity_id }}
                  onOpen={onOpen}
                  onGraph={onGraph}
                  onTree={onTree}
                  testId="memory-artifacts-handles-process"
                />
              </td>
              <td className="px-2 py-1 text-ink">{reported(row.object_type)}</td>
              <td className="max-w-[420px] truncate px-2 py-1 text-muted" title={reported(row.object_name)}>{reported(row.object_name)}</td>
              <td className="px-2 py-1 text-muted">{reported(row.handle_value)}</td>
              <td className="px-2 py-1 text-muted">{reported(row.granted_access)}</td>
              <td className="px-2 py-1">
                <ProcessActions
                  entity={{ pid: row.pid, name: row.process_name, process_entity_id: row.process_entity_id }}
                  onOpen={onOpen}
                  onGraph={onGraph}
                  onTree={onTree}
                  onModal={onModal}
                  testId="memory-artifacts-handles-actions"
                />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function DriversTable({ items, onModal, testId, type }: {
  items: Array<Record<string, unknown> & { document_id: string }>;
  onModal: (id: string) => void;
  testId: string;
  type: "drivers" | "kernel";
}) {
  if (!items.length) {
    return <p className="rounded-2xl border border-line bg-abyss/40 p-3 text-xs text-muted" data-testid={`memory-artifacts-${type}-empty`}>{type === "drivers" ? "No drivers indexed for this run." : "No kernel modules indexed for this run."}</p>;
  }
  return (
    <div className="max-w-full overflow-x-auto rounded-2xl border border-line bg-abyss/40">
      <table className="min-w-[900px] w-full divide-y divide-line text-xs" data-testid={testId}>
        <thead className="bg-abyss/70 text-left text-[10px] uppercase tracking-[0.14em] text-muted">
          <tr>
            <th className="px-2 py-1">Name</th>
            <th className="px-2 py-1">Path</th>
            <th className="px-2 py-1">{type === "drivers" ? "Start" : "Base"}</th>
            <th className="px-2 py-1">Size</th>
            <th className="px-2 py-1">Source</th>
            <th className="px-2 py-1">Visibility</th>
            <th className="px-2 py-1">Findings</th>
            <th className="px-2 py-1">Actions</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-line">
          {items.map((row: any) => {
            const name = type === "drivers" ? row.driver_name : row.module_name;
            return (
              <tr key={row.document_id} data-testid={`memory-artifacts-${type}-row`}>
                <td className="px-2 py-1 text-ink">{reported(name)}</td>
                <td className="max-w-[420px] truncate px-2 py-1 text-muted" title={reported(row.path)}>{reported(row.path)}</td>
                <td className="px-2 py-1 text-muted">{reported(type === "drivers" ? row.start_address : row.base_address)}</td>
                <td className="px-2 py-1 text-muted">{reported(row.size)}</td>
                <td className="px-2 py-1 text-muted">{reported(row.source_plugin)}</td>
                <td className="px-2 py-1 text-muted">{row.visibility?.scan_only ? "scan_only" : row.visibility?.listed ? "listed" : "—"}</td>
                <td className="px-2 py-1 text-muted">{(row.findings || []).join(", ") || "—"}</td>
                <td className="px-2 py-1">
                  <button
                    type="button"
                    onClick={() => onModal(row.document_id)}
                    className="rounded-md border border-line bg-abyss/70 px-2 py-0.5 text-[10px] text-muted"
                    data-testid={`memory-artifacts-${type}-inspect`}
                  >
                    <Eye className="mr-0.5 inline h-3 w-3" />
                    Detail
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function SuspiciousTable({ items, onModal, onOpen, onGraph, onTree }: {
  items: Array<Record<string, unknown> & { document_id: string }>;
  onModal: (id: string) => void;
  onOpen: (id: string) => void;
  onGraph: (id: string) => void;
  onTree: (id: string) => void;
}) {
  if (!items.length) {
    return <p className="rounded-2xl border border-line bg-abyss/40 p-3 text-xs text-muted" data-testid="memory-artifacts-suspicious-empty">No suspicious regions indexed for this run.</p>;
  }
  return (
    <div className="max-w-full overflow-x-auto rounded-2xl border border-line bg-abyss/40">
      <table className="min-w-[1100px] w-full divide-y divide-line text-xs" data-testid="memory-artifacts-suspicious-table">
        <thead className="bg-abyss/70 text-left text-[10px] uppercase tracking-[0.14em] text-muted">
          <tr>
            <th className="px-2 py-1">PID</th>
            <th className="px-2 py-1">Process</th>
            <th className="px-2 py-1">Address range</th>
            <th className="px-2 py-1">Protection</th>
            <th className="px-2 py-1">Private</th>
            <th className="px-2 py-1">Tag</th>
            <th className="px-2 py-1">Confidence</th>
            <th className="px-2 py-1">Review</th>
            <th className="px-2 py-1">Actions</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-line">
          {items.map((row: any) => (
            <tr key={row.document_id} data-testid="memory-artifacts-suspicious-row">
              <td className="px-2 py-1 text-ink">{reported(row.pid)}</td>
              <td className="px-2 py-1">
                <ProcessLink
                  entity={{ pid: row.pid, name: row.process_name, process_entity_id: row.process_entity_id }}
                  onOpen={onOpen}
                  onGraph={onGraph}
                  onTree={onTree}
                  testId="memory-artifacts-suspicious-process"
                />
              </td>
              <td className="px-2 py-1 text-muted">{reported(row.start_address)} → {reported(row.end_address)}</td>
              <td className="px-2 py-1 text-muted">{reported(row.protection)}</td>
              <td className="px-2 py-1 text-muted">{row.private_memory ? "Yes" : "—"}</td>
              <td className="px-2 py-1 text-muted">{reported(row.tag)}</td>
              <td className="px-2 py-1 text-muted">{reported(row.confidence)}</td>
              <td className="px-2 py-1">
                <span className="rounded-md border border-amber-400/30 bg-amber-500/10 px-1.5 py-0.5 text-[10px] text-amber-100" data-testid="memory-artifacts-suspicious-review">
                  {reported(row.review_status)}
                </span>
              </td>
              <td className="px-2 py-1">
                <ProcessActions
                  entity={{ pid: row.pid, name: row.process_name, process_entity_id: row.process_entity_id }}
                  onOpen={onOpen}
                  onGraph={onGraph}
                  onTree={onTree}
                  onModal={onModal}
                  testId="memory-artifacts-suspicious-actions"
                />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function MemoryArtifactsTab({
  caseId,
  runOptions,
  selectedRunId,
  onSelectRunId,
  onSelectEntity,
  evidenceId,
  onJumpToProcesses,
  onJumpToGraph,
  onJumpToTree,
}: Props) {
  const [subView, setSubView] = useState<SubView>("network");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [filter, setFilter] = useState("");
  const [pidFilter, setPidFilter] = useState("");
  const [objectTypeFilter, setObjectTypeFilter] = useState("");
  const [reviewFilter, setReviewFilter] = useState("");
  const [inspect, setInspect] = useState<{ type: string; id: string } | null>(null);

  const effectiveRunId = selectedRunId || runOptions?.default_run_id || null;

  const overviewQuery = useQuery<MemoryArtifactOverview>({
    // The overview now resolves per-family active runs on the
    // server side, so we do not pass the global default run ID.
    // Passing it would force a single-run scope and zero out
    // every family except the one matching the default profile.
    queryKey: ["memory-artifact-overview", caseId, evidenceId],
    queryFn: () => api.getMemoryArtifactOverview(caseId, {}),
    refetchOnWindowFocus: false,
  });
  const overview = overviewQuery.data;

  // Per-family active-result queries.  Each one resolves the
  // correct scan run for its family (handles_basic for handles,
  // kernel_basic for drivers and kernel modules, etc.) and
  // returns the real per-family total and items.  The list
  // queries below use the run id returned by the matching
  // active-result, so a query for ``handles`` no longer hits
  // the processes run.
  const networkActiveQuery = useQuery({
    queryKey: ["memory-active", caseId, evidenceId, "network", page ,pageSize, filter, pidFilter],
    queryFn: () => api.getMemoryActiveResult(caseId, evidenceId || "", "network", undefined).then((r) => r),
    enabled: Boolean(evidenceId) && subView === "network",
    refetchOnWindowFocus: false,
  });
  const modulesActiveQuery = useQuery({
    queryKey: ["memory-active", caseId, evidenceId, "modules", page ,pageSize, filter, pidFilter],
    queryFn: () => api.getMemoryActiveResult(caseId, evidenceId || "", "modules", undefined),
    enabled: Boolean(evidenceId) && subView === "modules",
    refetchOnWindowFocus: false,
  });
  const handlesActiveQuery = useQuery({
    queryKey: ["memory-active", caseId, evidenceId, "handles", page ,pageSize, objectTypeFilter],
    queryFn: () => api.getMemoryActiveResult(caseId, evidenceId || "", "handles", undefined, {
      object_type: objectTypeFilter || undefined,
    }),
    enabled: Boolean(evidenceId) && subView === "handles",
    refetchOnWindowFocus: false,
  });
  const driversActiveQuery = useQuery({
    queryKey: ["memory-active", caseId, evidenceId, "drivers", page],
    queryFn: () => api.getMemoryActiveResult(caseId, evidenceId || "", "drivers", undefined),
    enabled: Boolean(evidenceId) && subView === "drivers",
    refetchOnWindowFocus: false,
  });
  const kernelActiveQuery = useQuery({
    queryKey: ["memory-active", caseId, evidenceId, "kernel_modules", page],
    queryFn: () => api.getMemoryActiveResult(caseId, evidenceId || "", "kernel_modules", undefined),
    enabled: Boolean(evidenceId) && subView === "kernel",
    refetchOnWindowFocus: false,
  });
  const suspiciousActiveQuery = useQuery({
    queryKey: ["memory-active", caseId, evidenceId, "suspicious_regions", page],
    queryFn: () => api.getMemoryActiveResult(caseId, evidenceId || "", "suspicious_regions", undefined),
    enabled: Boolean(evidenceId) && subView === "suspicious",
    refetchOnWindowFocus: false,
  });

  // Build the per-family list params using the per-family active
  // run id.  The list endpoints still accept a ``run_id`` query
  // param; we forward the canonical per-family run id so the
  // OpenSearch query is correctly scoped.
  const listParams: Record<string, unknown> = useMemo(() => {
    let activeRunId: string | undefined = effectiveRunId || undefined;
    if (subView === "network") activeRunId = networkActiveQuery.data?.active_run?.id;
    else if (subView === "modules") activeRunId = modulesActiveQuery.data?.active_run?.id;
    else if (subView === "handles") activeRunId = handlesActiveQuery.data?.active_run?.id;
    else if (subView === "drivers") activeRunId = driversActiveQuery.data?.active_run?.id;
    else if (subView === "kernel") activeRunId = kernelActiveQuery.data?.active_run?.id;
    else if (subView === "suspicious") activeRunId = suspiciousActiveQuery.data?.active_run?.id;
    const params: Record<string, unknown> = {
      run_id: activeRunId,
      page,
      page_size: pageSize,
    };
    if (evidenceId) params.evidence_id = evidenceId;
    if (filter) params.process_name = filter;
    if (pidFilter) params.pid = Number(pidFilter);
    if (objectTypeFilter) params.object_type = objectTypeFilter;
    if (reviewFilter) params.review_status = reviewFilter;
    return params;
  }, [effectiveRunId, subView, evidenceId, page, filter, pidFilter, objectTypeFilter, reviewFilter,
      networkActiveQuery.data, modulesActiveQuery.data, handlesActiveQuery.data,
      driversActiveQuery.data, kernelActiveQuery.data, suspiciousActiveQuery.data]);

  const networkQuery = useQuery<MemoryArtifactList>({
    queryKey: ["memory-artifact-network", caseId, listParams],
    queryFn: () => api.getMemoryNetworkConnections(caseId, listParams as never),
    enabled: subView === "network",
    refetchOnWindowFocus: false,
  });
  const modulesQuery = useQuery<MemoryArtifactList>({
    queryKey: ["memory-artifact-modules", caseId, listParams],
    queryFn: () => api.getMemoryProcessModules(caseId, listParams as never),
    enabled: subView === "modules",
    refetchOnWindowFocus: false,
  });
  const handlesQuery = useQuery<MemoryArtifactList>({
    queryKey: ["memory-artifact-handles", caseId, listParams],
    queryFn: () => api.getMemoryHandles(caseId, listParams as never),
    enabled: subView === "handles",
    refetchOnWindowFocus: false,
  });
  const driversQuery = useQuery<MemoryArtifactList>({
    queryKey: ["memory-artifact-drivers", caseId, listParams],
    queryFn: () => api.getMemoryDrivers(caseId, listParams as never),
    enabled: subView === "drivers",
    refetchOnWindowFocus: false,
  });
  const kernelQuery = useQuery<MemoryArtifactList>({
    queryKey: ["memory-artifact-kernel", caseId, listParams],
    queryFn: () => api.getMemoryKernelModules(caseId, listParams as never),
    enabled: subView === "kernel",
    refetchOnWindowFocus: false,
  });
  const suspiciousQuery = useQuery<MemoryArtifactList>({
    queryKey: ["memory-artifact-suspicious", caseId, listParams],
    queryFn: () => api.getMemorySuspiciousRegions(caseId, listParams as never),
    enabled: subView === "suspicious",
    refetchOnWindowFocus: false,
  });

  const inspectQuery = useQuery<MemoryArtifactDetail>({
    queryKey: ["memory-artifact-detail", caseId, inspect?.type, inspect?.id],
    queryFn: () => api.getMemoryArtifactDetail(caseId, inspect!.type, inspect!.id),
    enabled: Boolean(inspect),
    refetchOnWindowFocus: false,
  });

  const totalPages = (list: MemoryArtifactList | undefined) =>
    list ? Math.max(1, Math.ceil(list.total / list.page_size)) : 1;

  function jumpToEntity(entityId: string) {
    if (!entityId.startsWith("pid:")) {
      onSelectEntity(entityId);
      onJumpToProcesses(entityId);
    }
  }

  return (
    <div className="space-y-4" data-testid="memory-artifacts-tab">
      <section className="rounded-[28px] border border-line bg-panel/60 p-5 shadow-panel">
        <header className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-muted">Artifacts</h3>
            <p className="mt-1 text-xs text-muted">
              Forensic artifacts from the authorized memory run.  All values are
              bounded server-side; raw bytes and full paths are never displayed.
            </p>
          </div>
          {evidenceId ? (
            <span
              className="rounded-md border border-emerald-400/30 bg-emerald-500/10 px-2 py-0.5 text-[10px] text-emerald-100"
              data-testid="memory-artifacts-latest-successful"
            >
              Latest successful
            </span>
          ) : (
            <RunPicker
              runOptions={runOptions}
              selectedRunId={effectiveRunId}
              onSelectRunId={(next) => { onSelectRunId(next); setPage(1); }}
              testId="memory-artifacts-run-picker"
            />
          )}
        </header>
        <div className="mt-3 flex flex-wrap gap-2" role="tablist" aria-label="Memory artifact subviews">
          {SUBVIEWS.map((sv) => (
            <button
              key={sv.key}
              type="button"
              role="tab"
              aria-selected={subView === sv.key}
              onClick={() => { setSubView(sv.key); setPage(1); }}
              data-testid={sv.testId}
              className={`rounded-xl border px-3 py-1.5 text-xs ${
                subView === sv.key ? "border-accent bg-accent/10 text-accent" : "border-line bg-abyss/70 text-muted"
              }`}
            >
              {sv.label}
            </button>
          ))}
        </div>
        <p className="mt-2 text-[11px] text-muted" data-testid="memory-artifacts-subview-description">
          {SUBVIEWS.find((sv) => sv.key === subView)?.description}
        </p>

        <div className="mt-3 grid gap-2 md:grid-cols-3 lg:grid-cols-6" data-testid="memory-artifacts-overview-cards">
          {/* The overview endpoint now resolves per-family active
              runs on the server, so each card shows the count from
              the correct scan run.  When a family has no
              successful run yet, the card shows "Not analyzed";
              when the run completed with zero rows the card shows
              "0" (analyzed_empty); when the run completed with
              rows the card shows the count.  No single global
              run scope is applied. */}
          {overview ? (
            <>
              <FamilyCountCard
                label="Network connections"
                testId="overview-network"
                familyValue={overview.network_connections}
              />
              <FamilyCountCard
                label="Process modules"
                testId="overview-modules"
                familyValue={overview.process_modules}
              />
              <CountCard
                label="Module discrepancies"
                value={overview.module_discrepancies ?? 0}
                testId="overview-discrepancies"
              />
              <FamilyCountCard
                label="Handles"
                testId="overview-handles"
                familyValue={overview.handles}
              />
              <FamilyCountCard
                label="Drivers"
                testId="overview-drivers"
                familyValue={overview.drivers}
              />
              <FamilyCountCard
                label="Suspicious regions"
                testId="overview-suspicious"
                familyValue={overview.suspicious_regions}
              />
            </>
          ) : (
            <>
              <NotAnalyzedCard label="Network connections" testId="overview-network" />
              <NotAnalyzedCard label="Process modules" testId="overview-modules" />
              <NotAnalyzedCard label="Module discrepancies" testId="overview-discrepancies" />
              <NotAnalyzedCard label="Handles" testId="overview-handles" />
              <NotAnalyzedCard label="Drivers" testId="overview-drivers" />
              <NotAnalyzedCard label="Suspicious regions" testId="overview-suspicious" />
            </>
          )}
        </div>
      </section>

      <section className="rounded-[28px] border border-line bg-panel/60 p-5 shadow-panel">
        <div className="flex flex-wrap items-center gap-2" data-testid="memory-artifacts-filters">
          <Filter className="h-3.5 w-3.5 text-muted" />
          {subView === "handles" ? (
            <input
              value={objectTypeFilter}
              onChange={(event) => { setObjectTypeFilter(event.target.value); setPage(1); }}
              placeholder="Object type (File, Key, Mutant)"
              className="rounded-xl border border-line bg-abyss/70 px-3 py-1 text-xs"
              data-testid="memory-artifacts-filter-object-type"
            />
          ) : null}
          {subView === "suspicious" ? (
            <input
              value={reviewFilter}
              onChange={(event) => { setReviewFilter(event.target.value); setPage(1); }}
              placeholder="Review status (needs_review)"
              className="rounded-xl border border-line bg-abyss/70 px-3 py-1 text-xs"
              data-testid="memory-artifacts-filter-review"
            />
          ) : null}
          <input
            value={filter}
            onChange={(event) => { setFilter(event.target.value); setPage(1); }}
            placeholder="Process name"
            className="rounded-xl border border-line bg-abyss/70 px-3 py-1 text-xs"
            data-testid="memory-artifacts-filter-name"
          />
          <input
            value={pidFilter}
            onChange={(event) => { setPidFilter(event.target.value); setPage(1); }}
            placeholder="PID"
            className="w-20 rounded-xl border border-line bg-abyss/70 px-3 py-1 text-xs"
            data-testid="memory-artifacts-filter-pid"
          />
          <button
            type="button"
            onClick={() => { setFilter(""); setPidFilter(""); setObjectTypeFilter(""); setReviewFilter(""); setPage(1); }}
            className="rounded-xl border border-line bg-abyss/70 px-2 py-1 text-xs"
            data-testid="memory-artifacts-filter-reset"
          >
            Reset
          </button>
        </div>
        <div className="mt-3 space-y-3" data-testid="memory-artifacts-table-pane">
          {subView === "network" ? (
            <NetworkTable
              items={networkQuery.data?.items || []}
              onModal={() => undefined}
              onOpen={jumpToEntity}
              onGraph={onJumpToGraph}
              onTree={onJumpToTree}
            />
          ) : null}
          {subView === "modules" ? (
            <ModulesTable
              items={modulesQuery.data?.items || []}
              onModal={() => undefined}
              onOpen={jumpToEntity}
              onGraph={onJumpToGraph}
              onTree={onJumpToTree}
            />
          ) : null}
          {subView === "handles" ? (
            <HandlesTable
              items={handlesQuery.data?.items || []}
              onModal={() => undefined}
              onOpen={jumpToEntity}
              onGraph={onJumpToGraph}
              onTree={onJumpToTree}
            />
          ) : null}
          {subView === "drivers" ? (
            <DriversTable
              items={driversQuery.data?.items || []}
              onModal={(id) => setInspect({ type: "memory_driver", id })}
              testId="memory-artifacts-drivers-table"
              type="drivers"
            />
          ) : null}
          {subView === "kernel" ? (
            <DriversTable
              items={kernelQuery.data?.items || []}
              onModal={(id) => setInspect({ type: "memory_kernel_module", id })}
              testId="memory-artifacts-kernel-table"
              type="kernel"
            />
          ) : null}
          {subView === "suspicious" ? (
            <SuspiciousTable
              items={suspiciousQuery.data?.items || []}
              onModal={(id) => setInspect({ type: "memory_suspicious_region", id })}
              onOpen={jumpToEntity}
              onGraph={onJumpToGraph}
              onTree={onJumpToTree}
            />
          ) : null}
        </div>
        <div className="mt-3">
          <Pagination
            page={page}
            totalPages={totalPages(
              subView === "network" ? networkQuery.data
                : subView === "modules" ? modulesQuery.data
                : subView === "handles" ? handlesQuery.data
                : subView === "drivers" ? driversQuery.data
                : subView === "kernel" ? kernelQuery.data
                : suspiciousQuery.data,
            )}
            onPage={setPage}
            testId="memory-artifacts-pagination"
          />
        </div>
      </section>

      {inspect ? (
        <ArtifactDetailPanel
          detail={inspectQuery.data}
          isLoading={inspectQuery.isLoading}
          error={inspectQuery.error instanceof Error ? inspectQuery.error : null}
          onClose={() => setInspect(null)}
        />
      ) : null}
    </div>
  );
}

function ArtifactDetailPanel({
  detail,
  isLoading,
  error,
  onClose,
}: {
  detail: MemoryArtifactDetail | undefined;
  isLoading: boolean;
  error: Error | null;
  onClose: () => void;
}) {
  if (isLoading) {
    return <p className="rounded-2xl border border-line bg-panel/60 p-3 text-sm text-muted" role="status">Loading detail…</p>;
  }
  if (error) {
    return <p className="rounded-2xl border border-rose-400/30 bg-rose-500/10 p-3 text-sm text-rose-200" role="alert"><AlertCircle className="mr-1 inline h-4 w-4" />{error.message}</p>;
  }
  if (!detail) return null;
  const fields = (detail.fields || {}) as Record<string, unknown>;
  const hexdump = fields.hexdump_preview_bounded as string | undefined;
  const disasm = fields.disassembly_preview_bounded as string | undefined;
  return (
    <aside
      className="space-y-3 rounded-2xl border border-line bg-panel/60 p-5 shadow-panel"
      data-testid="memory-artifacts-detail"
    >
      <header className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-ink">Artifact detail</h3>
        <button
          type="button"
          onClick={onClose}
          className="rounded-md border border-line bg-abyss/70 px-2 py-1 text-xs"
          data-testid="memory-artifacts-detail-close"
        >
          Close
        </button>
      </header>
      <div className="grid gap-2 md:grid-cols-2 text-xs">
        {Object.entries(fields)
          .filter(([key]) => !["hexdump_preview_bounded", "disassembly_preview_bounded"].includes(key))
          .slice(0, 16)
          .map(([key, value]) => (
            <div key={key} className="rounded-md border border-line bg-abyss/40 p-2" data-testid={`memory-artifacts-detail-field-${key}`}>
              <p className="text-[10px] uppercase tracking-[0.18em] text-muted">{key}</p>
              <p className="mt-1 break-words text-ink">{reported(value)}</p>
            </div>
          ))}
      </div>
      {hexdump ? (
        <section data-testid="memory-artifacts-detail-hexdump">
          <p className="text-[10px] uppercase tracking-[0.18em] text-muted">Hexdump preview (bounded)</p>
          <pre className="mt-1 max-h-32 overflow-auto rounded-md border border-line bg-abyss/40 p-2 font-mono text-[10px] text-ink">{hexdump}</pre>
        </section>
      ) : null}
      {disasm ? (
        <section data-testid="memory-artifacts-detail-disasm">
          <p className="text-[10px] uppercase tracking-[0.18em] text-muted">Disassembly preview (bounded)</p>
          <pre className="mt-1 max-h-32 overflow-auto rounded-md border border-line bg-abyss/40 p-2 font-mono text-[10px] text-ink">{disasm}</pre>
        </section>
      ) : null}
    </aside>
  );
}
