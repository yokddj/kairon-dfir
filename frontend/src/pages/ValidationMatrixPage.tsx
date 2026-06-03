import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Download, ExternalLink, Search, X } from "lucide-react";
import { Link, useParams, useSearchParams } from "react-router-dom";

import { api, type ValidationMatrixItem, type ValidationMatrixResult } from "../api/client";
import { useActiveCase } from "../context/ActiveCaseContext";

const RESULT_LABELS: Record<ValidationMatrixResult, string> = {
  found: "Found",
  partial: "Partial",
  not_found: "Not found",
  memory_only: "Memory only",
  not_present_in_evidence: "Not present",
  parser_gap: "Parser gap",
  ux_gap: "UX gap",
};

const RESULT_STYLES: Record<ValidationMatrixResult, string> = {
  found: "border-emerald-400/40 bg-emerald-500/10 text-emerald-100",
  partial: "border-amber-400/40 bg-amber-500/10 text-amber-100",
  not_found: "border-rose-400/40 bg-rose-500/10 text-rose-100",
  memory_only: "border-sky-400/40 bg-sky-500/10 text-sky-100",
  not_present_in_evidence: "border-zinc-400/40 bg-zinc-500/10 text-zinc-100",
  parser_gap: "border-rose-400/40 bg-rose-500/10 text-rose-100",
  ux_gap: "border-purple-400/40 bg-purple-500/10 text-purple-100",
};

function numberValue(value: unknown): number {
  return typeof value === "number" ? value : 0;
}

function phaseLabel(value: string) {
  return value
    .split(/[_/\s]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function downloadBlob(filename: string, blob: Blob) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function ResultBadge({ result }: { result: ValidationMatrixResult }) {
  return (
    <span className={`rounded-full border px-3 py-1 font-mono text-[10px] uppercase tracking-[0.14em] ${RESULT_STYLES[result] ?? RESULT_STYLES.partial}`}>
      {RESULT_LABELS[result] ?? result}
    </span>
  );
}

function StatCard({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-2xl border border-line bg-abyss/70 p-4">
      <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">{label}</p>
      <p className="mt-2 text-2xl font-semibold text-ink">{value}</p>
    </div>
  );
}

export default function ValidationMatrixPage() {
  const { caseId = "" } = useParams();
  const [searchParams, setSearchParams] = useSearchParams();
  const { setActiveCaseId } = useActiveCase();
  const [selectedItem, setSelectedItem] = useState<ValidationMatrixItem | null>(null);
  const [reviewedIds, setReviewedIds] = useState<Set<string>>(new Set());
  const [notes, setNotes] = useState<Record<string, string>>({});
  const [exportStatus, setExportStatus] = useState("");

  const filters = {
    host: searchParams.get("host") || "",
    phase: searchParams.get("phase") || "",
    result: searchParams.get("result") || "",
    source_part: searchParams.get("source_part") || "",
    memory_required:
      searchParams.get("memory_required") === "true"
        ? true
        : searchParams.get("memory_required") === "false"
          ? false
          : null,
  };

  useEffect(() => {
    if (caseId) setActiveCaseId(caseId);
  }, [caseId, setActiveCaseId]);

  const matrixQuery = useQuery({
    queryKey: ["validation-matrix", caseId, filters],
    queryFn: () => api.getValidationMatrix(caseId, filters),
    enabled: Boolean(caseId),
    staleTime: 30_000,
  });

  const matrix = matrixQuery.data;
  const summary = matrix?.summary ?? {};
  const items = matrix?.items ?? [];
  const visibility = matrix?.visibility;

  const selectedWithLocalState = useMemo(() => {
    if (!selectedItem) return null;
    return {
      ...selectedItem,
      local_note: notes[selectedItem.finding_id] ?? "",
      reviewed: reviewedIds.has(selectedItem.finding_id),
    };
  }, [notes, reviewedIds, selectedItem]);

  function updateFilter(key: string, value: string) {
    const next = new URLSearchParams(searchParams);
    if (value) next.set(key, value);
    else next.delete(key);
    setSearchParams(next);
  }

  function clearFilters() {
    setSearchParams(new URLSearchParams());
  }

  async function exportMatrix() {
    if (!caseId) return;
    setExportStatus("Exporting matrix...");
    try {
      const { blob, filename } = await api.exportValidationMatrixMarkdown(caseId);
      downloadBlob(filename, blob);
      setExportStatus("Matrix exported.");
    } catch (error) {
      setExportStatus(error instanceof Error ? error.message : "Export failed.");
    }
  }

  if (!caseId) {
    return <div className="rounded-[28px] border border-line bg-panel/70 p-8 text-sm text-muted shadow-panel">Select a case to open the validation matrix.</div>;
  }

  if (matrixQuery.isPending) {
    return <div className="rounded-[28px] border border-line bg-panel/70 p-8 text-sm text-muted shadow-panel">Loading validation matrix...</div>;
  }

  if (matrixQuery.error instanceof Error) {
    return <div className="rounded-[28px] border border-danger/40 bg-danger/10 p-8 text-sm text-danger shadow-panel">{matrixQuery.error.message}</div>;
  }

  if (visibility && !visibility.show_validation_matrix && !items.length) {
    return (
      <div className="space-y-6" data-testid="validation-matrix-empty">
        <section className="rounded-[28px] border border-line bg-panel/70 p-8 shadow-panel">
          <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">Validation Matrix</p>
          <h2 className="mt-2 text-3xl font-semibold">No ground truth matrix for this case</h2>
          <p className="mt-3 max-w-3xl text-sm text-muted">
            Validation Matrix is used for training cases, QA datasets, or imported ground-truth scenarios. Real investigations usually start with Findings and Incident Timeline.
          </p>
          <div className="mt-5 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            <button type="button" disabled className="rounded-2xl border border-line bg-abyss/60 px-4 py-3 text-left text-sm text-muted/60">Import validation matrix · planned</button>
            <button type="button" disabled className="rounded-2xl border border-line bg-abyss/60 px-4 py-3 text-left text-sm text-muted/60">Create validation checklist · planned</button>
            <button type="button" disabled className="rounded-2xl border border-line bg-abyss/60 px-4 py-3 text-left text-sm text-muted/60">Convert findings to checklist · planned</button>
            <button type="button" disabled className="rounded-2xl border border-line bg-abyss/60 px-4 py-3 text-left text-sm text-muted/60">Enable validation mode · planned</button>
          </div>
        </section>
        <section className="grid gap-3 md:grid-cols-3">
          <Link to={`/cases/${caseId}/search`} className="rounded-2xl border border-line bg-panel/70 px-4 py-3 text-sm text-muted">Open Search</Link>
          <Link to={`/cases/${caseId}/incident-timeline`} className="rounded-2xl border border-line bg-panel/70 px-4 py-3 text-sm text-muted">Open Incident Timeline</Link>
          <Link to={`/cases/${caseId}/findings`} className="rounded-2xl border border-line bg-panel/70 px-4 py-3 text-sm text-muted">Open Findings</Link>
        </section>
      </div>
    );
  }

  return (
    <div className="space-y-6" data-testid="validation-matrix-page">
      <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">Ground Truth Coverage</p>
            <h2 className="mt-2 text-3xl font-semibold">Validation Matrix</h2>
            <p className="mt-2 max-w-3xl text-sm text-muted">
              Compare imported expected findings against indexed evidence. Memory-only and not-present items are tracked separately from parser gaps.
            </p>
            <div className="mt-3 flex flex-wrap gap-2 text-xs text-muted">
              {visibility?.mode ? <span className="rounded-full border border-accent/40 bg-accent/10 px-3 py-1 text-accent">{visibility.label}</span> : null}
              {(matrix?.source_parts ?? []).map((part) => (
                <span key={part} className="rounded-full border border-line bg-abyss/70 px-3 py-1">Part {part}</span>
              ))}
              {matrix?.validation_id ? <span className="rounded-full border border-line bg-abyss/70 px-3 py-1">{matrix.validation_id}</span> : null}
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            <Link to="/docs/validation-readme" className="rounded-2xl border border-line bg-abyss/70 px-4 py-2 text-sm text-muted">
              Open docs
            </Link>
            <button type="button" onClick={exportMatrix} className="inline-flex items-center gap-2 rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss">
              <Download size={16} /> Export matrix
            </button>
          </div>
        </div>
        {exportStatus ? <p className="mt-3 text-sm text-muted">{exportStatus}</p> : null}
        {matrix?.warnings?.length ? (
          <div className="mt-4 rounded-2xl border border-amber/40 bg-amber/10 p-4 text-sm text-amber">
            {matrix.warnings.join(" ")}
          </div>
        ) : null}
      </section>

      <section className="grid gap-4 md:grid-cols-3 xl:grid-cols-7">
        <StatCard label="Expected" value={numberValue(summary.total_expected)} />
        <StatCard label="Found" value={numberValue(summary.found)} />
        <StatCard label="Partial" value={numberValue(summary.partial)} />
        <StatCard label="Memory only" value={numberValue(summary.memory_only)} />
        <StatCard label="Not present" value={numberValue(summary.not_present_in_evidence)} />
        <StatCard label="Parser gaps" value={numberValue(summary.parser_gap)} />
        <StatCard label="UX gaps" value={numberValue(summary.ux_gap)} />
      </section>

      <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
        <div className="grid gap-4 md:grid-cols-3 xl:grid-cols-6">
          <label className="rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm">
            <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Host</span>
            <select value={filters.host} onChange={(event) => updateFilter("host", event.target.value)} className="w-full bg-transparent outline-none">
              <option value="">All hosts</option>
              {(matrix?.filters.hosts ?? []).map((host) => <option key={host} value={host}>{host}</option>)}
            </select>
          </label>
          <label className="rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm">
            <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Phase</span>
            <select value={filters.phase} onChange={(event) => updateFilter("phase", event.target.value)} className="w-full bg-transparent outline-none">
              <option value="">All phases</option>
              {(matrix?.filters.phases ?? []).map((phase) => <option key={phase} value={phase}>{phaseLabel(phase)}</option>)}
            </select>
          </label>
          <label className="rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm">
            <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Result</span>
            <select value={filters.result} onChange={(event) => updateFilter("result", event.target.value)} className="w-full bg-transparent outline-none">
              <option value="">All results</option>
              {(matrix?.filters.results ?? []).map((result) => <option key={result} value={result}>{RESULT_LABELS[result]}</option>)}
            </select>
          </label>
          <label className="rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm">
            <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Source part</span>
            <select value={filters.source_part} onChange={(event) => updateFilter("source_part", event.target.value)} className="w-full bg-transparent outline-none">
              <option value="">All parts</option>
              {(matrix?.filters.source_parts ?? []).map((part) => <option key={part} value={part}>Part {part}</option>)}
            </select>
          </label>
          <label className="rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm">
            <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Memory required</span>
            <select value={filters.memory_required === null ? "" : String(filters.memory_required)} onChange={(event) => updateFilter("memory_required", event.target.value)} className="w-full bg-transparent outline-none">
              <option value="">Either</option>
              <option value="true">Required</option>
              <option value="false">Not required</option>
            </select>
          </label>
          <button type="button" onClick={clearFilters} className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm text-muted">
            Clear filters
          </button>
        </div>
      </section>

      <section className="grid gap-6 xl:grid-cols-[minmax(0,1.5fr)_minmax(360px,0.8fr)]">
        <div className="overflow-hidden rounded-[28px] border border-line bg-panel/70 shadow-panel">
          <table className="w-full text-sm">
            <thead className="bg-abyss/80 font-mono text-[11px] uppercase tracking-[0.16em] text-muted">
              <tr>
                <th className="px-4 py-3 text-left">ID</th>
                <th className="px-4 py-3 text-left">Phase</th>
                <th className="px-4 py-3 text-left">Host</th>
                <th className="px-4 py-3 text-left">Title</th>
                <th className="px-4 py-3 text-left">Result</th>
                <th className="px-4 py-3 text-left">Evidence</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line/60">
              {items.map((item) => (
                <tr key={item.finding_id} className={`cursor-pointer hover:bg-white/5 ${selectedItem?.finding_id === item.finding_id ? "bg-accent/5" : ""}`} onClick={() => setSelectedItem(item)}>
                  <td className="px-4 py-3 font-mono text-xs text-accent">{item.finding_id}</td>
                  <td className="px-4 py-3">{phaseLabel(item.phase)}</td>
                  <td className="px-4 py-3">{item.host}</td>
                  <td className="px-4 py-3">
                    <div className="font-medium text-ink">{item.title}</div>
                    <div className="mt-1 line-clamp-2 text-xs text-muted">{item.description}</div>
                  </td>
                  <td className="px-4 py-3"><ResultBadge result={item.result} /></td>
                  <td className="px-4 py-3 text-xs text-muted">{item.evidence_source_used.join(", ") || "-"}</td>
                </tr>
              ))}
              {!items.length ? (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-muted">No validation items match the current filters.</td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>

        <aside className="rounded-[28px] border border-line bg-panel/70 p-5 shadow-panel">
          {selectedWithLocalState ? (
            <div className="space-y-4" data-testid="validation-detail">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">{selectedWithLocalState.finding_id}</p>
                  <h3 className="mt-2 text-xl font-semibold">{selectedWithLocalState.title}</h3>
                </div>
                <button type="button" onClick={() => setSelectedItem(null)} className="rounded-xl border border-line bg-abyss/70 p-2 text-muted">
                  <X size={16} />
                </button>
              </div>
              <ResultBadge result={selectedWithLocalState.result} />
              <p className="text-sm text-muted">{selectedWithLocalState.description}</p>
              {selectedWithLocalState.result === "memory_only" ? (
                <div className="rounded-2xl border border-sky-400/30 bg-sky-500/10 p-3 text-sm text-sky-100">
                  This finding requires memory or mail evidence and is not expected to be recovered from disk/logs alone.
                </div>
              ) : null}
              {selectedWithLocalState.result === "not_present_in_evidence" ? (
                <div className="rounded-2xl border border-zinc-400/30 bg-zinc-500/10 p-3 text-sm text-zinc-100">
                  The writeup mentions this item, but targeted searches did not locate it in the loaded evidence. This is not classified as a parser gap.
                </div>
              ) : null}
              <div className="grid gap-3">
                <div>
                  <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Indicators</p>
                  <p className="mt-1 text-sm text-ink">{selectedWithLocalState.expected_indicators.join(", ") || "-"}</p>
                </div>
                <div>
                  <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Artifacts</p>
                  <p className="mt-1 text-sm text-ink">{selectedWithLocalState.expected_artifacts.join(", ") || "-"}</p>
                </div>
                <div>
                  <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Source parts</p>
                  <p className="mt-1 text-sm text-ink">{selectedWithLocalState.source_part.map((part) => `Part ${part}`).join(", ")}</p>
                </div>
                <div>
                  <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Notes</p>
                  <p className="mt-1 text-sm text-muted">{selectedWithLocalState.notes || "No additional notes."}</p>
                </div>
              </div>
              <div className="grid gap-2">
                {selectedWithLocalState.search_url ? (
                  <Link to={selectedWithLocalState.search_url} className="inline-flex items-center gap-2 rounded-2xl border border-line bg-abyss/70 px-4 py-2 text-sm text-muted">
                    <Search size={16} /> Open related Search
                  </Link>
                ) : null}
                {selectedWithLocalState.timeline_url ? (
                  <Link to={selectedWithLocalState.timeline_url} className="inline-flex items-center gap-2 rounded-2xl border border-line bg-abyss/70 px-4 py-2 text-sm text-muted">
                    <ExternalLink size={16} /> Open Incident Timeline
                  </Link>
                ) : null}
                <Link to="/docs/validation-matrix-format" className="inline-flex items-center gap-2 rounded-2xl border border-line bg-abyss/70 px-4 py-2 text-sm text-muted">
                  <ExternalLink size={16} /> Source coverage docs
                </Link>
              </div>
              <label className="block rounded-2xl border border-line bg-abyss/60 p-3 text-sm text-muted">
                <span className="font-mono text-[11px] uppercase tracking-[0.16em]">Analyst note</span>
                <textarea
                  value={selectedWithLocalState.local_note}
                  onChange={(event) => setNotes((current) => ({ ...current, [selectedWithLocalState.finding_id]: event.target.value }))}
                  className="mt-2 h-24 w-full resize-none rounded-xl border border-line bg-panel/60 p-2 text-ink outline-none"
                  placeholder="Local review note"
                />
              </label>
              <button
                type="button"
                onClick={() =>
                  setReviewedIds((current) => {
                    const next = new Set(current);
                    if (next.has(selectedWithLocalState.finding_id)) next.delete(selectedWithLocalState.finding_id);
                    else next.add(selectedWithLocalState.finding_id);
                    return next;
                  })
                }
                className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted"
              >
                {selectedWithLocalState.reviewed ? "Mark unreviewed" : "Mark reviewed"}
              </button>
            </div>
          ) : (
            <div className="rounded-2xl border border-line bg-abyss/60 p-4 text-sm text-muted">
              Select a validation row to see indicators, source parts, evidence links and gap explanation.
            </div>
          )}
        </aside>
      </section>
    </div>
  );
}
