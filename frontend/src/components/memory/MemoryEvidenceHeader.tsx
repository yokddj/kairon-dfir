import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { type MemoryActiveResult, type MemoryAnalysisCatalogue, type MemoryEvidenceLandingItem, type MemorySymbolReadiness } from "../../api/client";

type DetectionDisplay = {
  label: string;
  tone: "neutral" | "good" | "warn" | "bad";
};

function detectionDisplay(
  status: string | null | undefined,
  format: string | null | undefined,
  confidence: string | null | undefined,
  operatorOverride: boolean | undefined,
): DetectionDisplay | null {
  const s = (status || "").toLowerCase();
  if (!s) return null;
  if (s === "ambiguous_raw_confirmed" || s === "probable_disk_confirmed_as_memory" || operatorOverride) {
    return { label: "Confirmed memory evidence", tone: "good" };
  }
  if (s === "ambiguous_raw") {
    return { label: "Confirmation required", tone: "warn" };
  }
  if (s === "probable_disk") {
    return { label: "Probable disk image", tone: "bad" };
  }
  if (s === "probable_memory" || s === "confirmed_memory") {
    return { label: `${format || "Memory image"} (${confidence || "confirmed"})`, tone: "good" };
  }
  if (s === "unsupported" || s === "invalid" || s === "probe_failed") {
    return { label: `Cannot analyze (${s})`, tone: "bad" };
  }
  return { label: s, tone: "neutral" };
}

type Props = {
  caseId: string;
  evidence: MemoryEvidenceLandingItem;
  activeResult: MemoryActiveResult | null;
  family: string;
  historicalRunId: string | null;
  onViewHistory: () => void;
  onReturnToLatest: () => void;
  onOpenCatalogue: () => void;
  symbolReadiness?: MemorySymbolReadiness | null;
  symbolPreparation?: { ui_state?: string; sanitized_message?: string } | null;
  catalogue?: MemoryAnalysisCatalogue | null;
};

function shortId(id: string): string {
  if (!id) return "";
  return id.length > 12 ? id.slice(0, 12) : id;
}

function sizeLabel(bytes: number): string {
  if (!bytes) return "0 B";
  if (bytes >= 1024 ** 3) return `${(bytes / 1024 ** 3).toFixed(2)} GiB`;
  if (bytes >= 1024 ** 2) return `${(bytes / 1024 ** 2).toFixed(2)} MiB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(2)} KiB`;
  return `${bytes} B`;
}

function formatDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  return iso.slice(0, 19).replace("T", " ");
}

export function MemoryEvidenceHeader({
  caseId,
  evidence,
  activeResult,
  family,
  historicalRunId,
  onViewHistory,
  onReturnToLatest,
  onOpenCatalogue,
  symbolReadiness,
  symbolPreparation,
  catalogue,
}: Props) {
  const [copied, setCopied] = useState(false);

  // Determine the header action label based on the catalogue
  // state.  The button is always "Analyze memory" / "Complete
  // analysis" / "Re-run analysis" depending on how many
  // supported profiles are already completed.
  const headerLabel = useMemo(() => {
    if (!catalogue) return "Run analysis";
    const supported = catalogue.items.filter((it) => it.available);
    if (supported.length === 0) return "Run analysis";
    const completed = supported.filter(
      (it) => it.last_status === "completed" || it.last_status === "completed_with_errors",
    );
    if (completed.length === 0) return "Analyze memory";
    if (completed.length >= supported.length) return "Re-run analysis";
    return "Complete analysis";
  }, [catalogue]);

  function copyId() {
    if (typeof navigator === "undefined" || !navigator.clipboard) return;
    void navigator.clipboard.writeText(evidence.evidence_id).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }

  const activeRun = activeResult?.active_run ?? null;
  const latestAttempt = activeResult?.latest_attempt ?? null;
  const usingFallback = activeResult?.using_fallback === true;
  const isHistorical = historicalRunId !== null;
  const detection = detectionDisplay(
    evidence.detection_status,
    evidence.detected_format,
    evidence.detection_confidence,
    evidence.operator_override,
  );
  // Canonical analysis capability: when the preparation endpoint
  // is available, trust its authoritative can_analyze_metadata field
  // (which already accounts for native compatibility, metadata
  // readiness, and symbol state).  Fall back to the legacy
  // evidence.can_analyze field only when preparation data is absent.
  const prepCanAnalyze = symbolPreparation?.can_analyze_metadata;
  const canLaunchAnalysis = prepCanAnalyze ?? (evidence.can_analyze !== false);
  const legacySymbolState = symbolReadiness?.state ?? "unknown";
  const prepState = symbolPreparation?.effective_state || symbolPreparation?.ui_state;
  const prepReady = prepState === "ready";
  const prepNativeReady = prepReady && symbolPreparation?.native_compatible === true;
  const symbolBlocksAnalysis =
    !prepReady &&
    !prepNativeReady &&
    (
      (legacySymbolState !== "unknown" && legacySymbolState !== "cached") ||
      prepState === "preparing" ||
      prepState === "blocked" ||
      prepState === "blocked_symbols" ||
      prepState === "failed"
    );
  const runDisabled = !canLaunchAnalysis || (symbolBlocksAnalysis && !prepCanAnalyze);
  const runTitle = !canLaunchAnalysis
    ? "Confirm the evidence type before starting analysis."
    : symbolBlocksAnalysis && !prepCanAnalyze
      ? symbolPreparation?.sanitized_message ||
        symbolReadiness?.sanitized_message ||
        "Resolve the Windows symbol requirement before running analysis."
      : "Run analysis";

  return (
    <section
      className="rounded-[28px] border border-line bg-panel/70 p-5 shadow-panel"
      data-testid="memory-evidence-header"
      data-evidence-id={evidence.evidence_id}
    >
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <Link
              to={`/cases/${caseId}/memory`}
              className="rounded-md border border-line bg-abyss/70 px-2 py-0.5 text-[10px] text-muted"
              data-testid="memory-evidence-back"
            >
              ← All evidence
            </Link>
            <span className="rounded-md border border-line bg-abyss/70 px-2 py-0.5 text-[10px] text-muted">
              {evidence.ingest_status || "ingest_unknown"}
            </span>
            <span className="rounded-md border border-line bg-abyss/70 px-2 py-0.5 text-[10px] text-muted">
              {evidence.run_count} {evidence.run_count === 1 ? "run" : "runs"}
            </span>
            {detection ? (
              <span
                className={
                  "rounded-md border px-2 py-0.5 text-[10px] " +
                  (detection.tone === "good"
                    ? "border-emerald-400/30 bg-emerald-500/10 text-emerald-100"
                    : detection.tone === "warn"
                      ? "border-amber-400/30 bg-amber-500/10 text-amber-100"
                      : detection.tone === "bad"
                        ? "border-rose-400/30 bg-rose-500/10 text-rose-100"
                        : "border-line bg-abyss/70 text-muted")
                }
                data-testid="memory-detection-badge"
              >
                {detection.label}
              </span>
            ) : null}
          </div>
          <h2 className="mt-2 text-2xl font-semibold text-ink" data-testid="memory-evidence-filename">{evidence.filename}</h2>
          <div className="mt-2 grid gap-1 text-[11px] text-muted sm:grid-cols-2">
            <div>
              <span className="uppercase tracking-wider">Host:</span>{" "}
              <span className="text-ink" data-testid="memory-evidence-host">{evidence.detected_host || "Unknown"}</span>
            </div>
            <div>
              <span className="uppercase tracking-wider">Size:</span>{" "}
              <span className="text-ink" data-testid="memory-evidence-size">{sizeLabel(evidence.size_bytes)}</span>
            </div>
            <div>
              <span className="uppercase tracking-wider">Created:</span>{" "}
              <span className="font-mono text-ink">{formatDate(evidence.created_at)}</span>
            </div>
            <div>
              <span className="uppercase tracking-wider">Processed:</span>{" "}
              <span className="font-mono text-ink">{formatDate(evidence.processed_at)}</span>
            </div>
            <div className="sm:col-span-2">
              <span className="uppercase tracking-wider">Evidence ID:</span>{" "}
              <button
                type="button"
                onClick={copyId}
                className="rounded-md border border-line bg-abyss/70 px-2 py-0.5 font-mono text-[10px] text-ink"
                data-testid="memory-evidence-id"
                title="Copy evidence ID"
              >
                {copied ? "Copied" : shortId(evidence.evidence_id)}…
              </button>
            </div>
          </div>
        </div>
        <div className="flex flex-col items-end gap-2">
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={onOpenCatalogue}
              disabled={runDisabled}
              title={runTitle}
              className="rounded-xl bg-accent px-3 py-2 text-xs font-semibold text-abyss disabled:opacity-60"
              data-testid="memory-open-catalogue"
            >
              {headerLabel}
            </button>
            <button
              type="button"
              onClick={onViewHistory}
              className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted"
              data-testid="memory-view-history"
            >
              View analysis history
            </button>
            <Link
              to={`/cases/${caseId}/memory/upload`}
              className="rounded-xl border border-line bg-abyss/70 px-3 py-2 text-xs text-muted"
            >
              Add memory image
            </Link>
          </div>
        </div>
      </div>

      {isHistorical ? (
        <div
          className="mt-3 flex flex-wrap items-center justify-between gap-2 rounded-xl border border-amber-400/30 bg-amber-500/10 p-3 text-xs text-amber-100"
          data-testid="memory-historical-banner"
        >
          <span>
            Historical result — viewing run <span className="font-mono">{shortId(historicalRunId || "")}…</span> for {family}.
          </span>
          <button
            type="button"
            onClick={onReturnToLatest}
            className="rounded-md border border-amber-300/40 bg-amber-500/10 px-2 py-0.5 text-[10px]"
            data-testid="memory-historical-return"
          >
            Return to Latest successful
          </button>
        </div>
      ) : null}

      {!isHistorical && usingFallback && latestAttempt && latestAttempt.id !== activeRun?.id ? (
        <div
          className="mt-3 rounded-xl border border-rose-400/30 bg-rose-500/10 p-3 text-xs text-rose-100"
          data-testid="memory-latest-failed-banner"
        >
          Latest analysis attempt failed. Showing the last successful result from {formatDate(activeRun?.completed_at)}.
        </div>
      ) : null}

      {detection?.tone === "warn" ? (
        <div
          className="mt-3 rounded-xl border border-amber-400/30 bg-amber-500/10 p-3 text-xs text-amber-100"
          data-testid="memory-type-confirmation-required"
        >
          <p className="font-semibold text-ink">Memory type confirmation required</p>
          <p className="mt-1 text-amber-100/80">
            The file was accepted as a RAW candidate, but Kairon could not confirm that it is a memory image.
          </p>
          <div className="mt-2 flex flex-wrap gap-2">
            <button
              type="button"
              onClick={onOpenCatalogue}
              data-testid="memory-header-confirm-button"
              className="rounded-md border border-amber-300/40 bg-amber-500/20 px-2 py-0.5 text-[10px] font-semibold text-ink"
            >
              Confirm as memory evidence
            </button>
          </div>
        </div>
      ) : null}

      {symbolBlocksAnalysis ? (
        <div
          className="mt-3 rounded-xl border border-amber-400/30 bg-amber-500/10 p-3 text-xs text-amber-100"
          data-testid="memory-symbol-blocker-banner"
          data-state={prepState ?? legacySymbolState}
        >
          <p className="font-semibold text-ink">Analysis readiness</p>
          <p className="mt-1" data-testid="memory-symbol-blocker-message">
            {symbolReadiness?.sanitized_message ||
              "Windows symbol requirement for this evidence is not satisfied."}
          </p>
          {symbolReadiness?.error_code ? (
            <p
              className="mt-1 font-mono text-[10px] uppercase tracking-wider"
              data-testid="memory-symbol-blocker-code"
            >
              {symbolReadiness.error_code}
            </p>
          ) : null}
        </div>
      ) : null}

      {detection?.tone === "bad" ? (
        <div
          className="mt-3 rounded-xl border border-rose-400/30 bg-rose-500/10 p-3 text-xs text-rose-100"
          data-testid="memory-type-probable-disk"
        >
          <p className="font-semibold text-ink">Probable disk image</p>
          <p className="mt-1 text-rose-100/80">
            This evidence was classified as a probable disk image by the content probe. Import it as disk evidence
            or confirm it as memory before analyzing.
          </p>
          <div className="mt-2 flex flex-wrap gap-2">
            <button
              type="button"
              onClick={onOpenCatalogue}
              data-testid="memory-probable-disk-confirm-button"
              className="rounded-md border border-rose-300/40 bg-rose-500/20 px-2 py-0.5 text-[10px] font-semibold text-ink"
            >
              Confirm as memory evidence
            </button>
          </div>
        </div>
      ) : null}

      {activeRun ? (
        <div className="mt-3 flex flex-wrap items-center gap-2 text-[10px] text-muted" data-testid="memory-active-result-label">
          <span className="rounded-md border border-emerald-400/30 bg-emerald-500/10 px-2 py-0.5 text-emerald-100" data-testid="memory-active-result-badge">
            Latest successful
          </span>
          <span className="font-mono text-ink">{shortId(activeRun.id)}…</span>
          <span>· {activeRun.profile}</span>
          <span>· {formatDate(activeRun.completed_at || activeRun.started_at)}</span>
          {activeRun.duration_seconds ? <span>· {activeRun.duration_seconds.toFixed(1)}s</span> : null}
        </div>
      ) : null}
    </section>
  );
}
