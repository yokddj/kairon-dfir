import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api, type MemorySymbolReadiness } from "../../api/client";

type Tone = "neutral" | "good" | "warn" | "bad";

function toneForState(state: string): Tone {
  switch (state) {
    case "cached":
    case "acquired":
      return "good";
    case "missing":
    case "acquisition_required":
    case "acquisition_pending":
    case "failed":
    case "incompatible":
    case "unsupported":
      return "bad";
    case "acquiring":
    case "probing":
      return "warn";
    default:
      return "neutral";
  }
}

function stateLabel(state: string): string {
  switch (state) {
    case "cached":
      return "Cached · Ready for analysis";
    case "missing":
      return "Missing for this evidence";
    case "acquisition_required":
      return "Acquisition required";
    case "acquisition_pending":
      return "Acquisition pending operator approval";
    case "acquiring":
      return "Acquiring symbols";
    case "acquired":
      return "Acquired";
    case "failed":
      return "Acquisition failed";
    case "incompatible":
      return "Image is not a supported Windows memory image";
    case "unsupported":
      return "Symbol source does not provide the required PDB";
    case "probing":
      return "Probing requirements";
    case "unknown":
    default:
      return "Symbol requirement not identified";
  }
}

type Props = {
  caseId: string;
  evidenceId: string;
  readiness: MemorySymbolReadiness | null;
  onProbeCompleted?: () => void;
  onAcquireCompleted?: () => void;
};

export function MemorySymbolResolutionPanel({
  caseId,
  evidenceId,
  readiness,
  onProbeCompleted,
  onAcquireCompleted,
}: Props) {
  const queryClient = useQueryClient();
  const [probeError, setProbeError] = useState<string | null>(null);
  const [acquireError, setAcquireError] = useState<string | null>(null);
  const [ackChecked, setAckChecked] = useState(false);
  const [acquisitionModalOpen, setAcquisitionModalOpen] = useState(false);

  const probeMutation = useMutation({
    mutationFn: () => api.probeMemorySymbolRequirement(caseId, evidenceId),
    onSuccess: () => {
      setProbeError(null);
      void queryClient.invalidateQueries({ queryKey: ["memory-symbol-readiness", caseId, evidenceId] });
      void queryClient.invalidateQueries({ queryKey: ["memory-landing", caseId] });
      void queryClient.invalidateQueries({ queryKey: ["memory-catalogue", caseId, evidenceId] });
      onProbeCompleted?.();
    },
    onError: (err: Error) => {
      setProbeError(err.message || "The symbol probe failed.");
    },
  });

  const acquireMutation = useMutation({
    mutationFn: () => api.requestMemorySymbolAcquisition(caseId, evidenceId, true),
    onSuccess: () => {
      setAcquireError(null);
      void queryClient.invalidateQueries({ queryKey: ["memory-symbol-readiness", caseId, evidenceId] });
      void queryClient.invalidateQueries({ queryKey: ["memory-landing", caseId] });
      onAcquireCompleted?.();
    },
    onError: (err: Error) => {
      setAcquireError(err.message || "The acquisition request failed.");
    },
  });

  if (!readiness) {
    return null;
  }

  const tone = toneForState(readiness.state);
  const req = readiness.requirement;
  const cache = readiness.cache;
  const canProbe = !probeMutation.isPending;
  const canAcquire = readiness.acquisition_supported && !acquireMutation.isPending;
  const showAcquireButton = readiness.state === "missing" && readiness.acquisition_supported;

  return (
    <section
      className={
        "rounded-[28px] border bg-panel/70 p-5 shadow-panel " +
        (tone === "good"
          ? "border-emerald-400/30"
          : tone === "warn"
            ? "border-amber-400/30"
            : tone === "bad"
              ? "border-rose-400/30"
              : "border-line")
      }
      data-testid="memory-symbol-resolution-panel"
      data-state={readiness.state}
    >
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <p className="font-mono text-[10px] uppercase tracking-[0.24em] text-accent">
            Symbols for this evidence
          </p>
          <p
            className="mt-1 text-sm font-semibold"
            data-testid="memory-symbol-state-label"
          >
            {stateLabel(readiness.state)}
          </p>
          {readiness.sanitized_message ? (
            <p
              className="mt-1 text-xs text-muted"
              data-testid="memory-symbol-message"
            >
              {readiness.sanitized_message}
            </p>
          ) : null}
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() => probeMutation.mutate()}
            disabled={!canProbe}
            className="rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-xs text-muted disabled:opacity-50"
            data-testid="memory-symbol-probe-button"
          >
            {probeMutation.isPending ? "Probing…" : "Probe symbol requirements"}
          </button>
          {showAcquireButton ? (
            <button
              type="button"
              onClick={() => {
                setAckChecked(false);
                setAcquisitionModalOpen(true);
              }}
              disabled={!canAcquire}
              className="rounded-xl bg-accent px-3 py-1.5 text-xs font-semibold text-abyss disabled:opacity-50"
              data-testid="memory-symbol-acquire-button"
            >
              Acquire symbols
            </button>
          ) : null}
        </div>
      </div>

      {probeError ? (
        <p
          className="mt-3 text-xs text-rose-200"
          data-testid="memory-symbol-probe-error"
          role="alert"
        >
          {probeError}
        </p>
      ) : null}

      {req ? (
        <dl
          className="mt-3 grid grid-cols-1 gap-2 text-xs sm:grid-cols-2"
          data-testid="memory-symbol-requirement-grid"
        >
          <div>
            <dt className="uppercase tracking-wider text-muted">Kernel PDB</dt>
            <dd className="font-mono text-ink" data-testid="memory-symbol-pdb-name">{req.pdb_name}</dd>
          </div>
          <div>
            <dt className="uppercase tracking-wider text-muted">Architecture</dt>
            <dd className="font-mono text-ink" data-testid="memory-symbol-architecture">{req.architecture}</dd>
          </div>
          <div>
            <dt className="uppercase tracking-wider text-muted">GUID</dt>
            <dd className="font-mono text-ink" data-testid="memory-symbol-pdb-guid">{req.pdb_guid}</dd>
          </div>
          <div>
            <dt className="uppercase tracking-wider text-muted">Age</dt>
            <dd className="font-mono text-ink" data-testid="memory-symbol-pdb-age">{req.pdb_age}</dd>
          </div>
        </dl>
      ) : null}

      {cache ? (
        <div
          className="mt-3 rounded-xl border border-line bg-abyss/40 p-3 text-xs"
          data-testid="memory-symbol-cache-info"
        >
          <p data-testid="memory-symbol-cache-status">
            Cache status:{" "}
            <span
              className={
                cache.cache_status === "hit"
                  ? "text-emerald-100"
                  : "text-rose-200"
              }
            >
              {cache.cache_status}
            </span>{" "}
            · exact_match:{" "}
            <span
              className={
                cache.exact_match
                  ? "text-emerald-100"
                  : "text-rose-200"
              }
              data-testid="memory-symbol-cache-exact-match"
            >
              {String(cache.exact_match)}
            </span>
          </p>
          {cache.required_identifier ? (
            <p className="mt-1 font-mono text-[10px] text-muted" data-testid="memory-symbol-required-identifier">
              required: {cache.required_identifier}
            </p>
          ) : null}
          {cache.cached_identifiers.length > 0 ? (
            <ul
              className="mt-1 space-y-0.5 font-mono text-[10px] text-muted"
              data-testid="memory-symbol-cached-identifiers"
            >
              {cache.cached_identifiers.map((id) => (
                <li key={id}>{id}</li>
              ))}
            </ul>
          ) : null}
        </div>
      ) : null}

      {readiness.error_code ? (
        <p
          className="mt-3 text-[10px] uppercase tracking-wider text-muted"
          data-testid="memory-symbol-error-code"
        >
          code: {readiness.error_code}
        </p>
      ) : null}

      {acquisitionModalOpen ? (
        <div
          className="fixed inset-0 z-40 flex items-center justify-center bg-abyss/80 p-4"
          data-testid="memory-symbol-acquire-modal"
          role="dialog"
          aria-modal="true"
          aria-labelledby="memory-symbol-acquire-title"
        >
          <div className="max-h-[90vh] w-full max-w-xl overflow-y-auto rounded-[28px] border border-line bg-panel p-6 shadow-panel">
            <p className="font-mono text-[10px] uppercase tracking-[0.24em] text-accent">
              Acquire Windows symbols
            </p>
            <h2
              id="memory-symbol-acquire-title"
              className="mt-1 text-2xl font-semibold"
            >
              Confirm symbol acquisition
            </h2>
            <p className="mt-2 text-sm" data-testid="memory-symbol-acquire-summary">
              Kairon will request acquisition of the exact Windows symbols
              recorded for this evidence. The backend derives the
              identifier from the recorded requirement; the client does
              not provide a URL or PDB name.
            </p>
            {req ? (
              <dl className="mt-3 space-y-1 text-xs">
                <div>
                  <dt className="inline font-semibold">PDB: </dt>
                  <dd className="inline font-mono" data-testid="memory-symbol-acquire-pdb">{req.pdb_name}</dd>
                </div>
                <div>
                  <dt className="inline font-semibold">GUID: </dt>
                  <dd className="inline font-mono" data-testid="memory-symbol-acquire-guid">{req.pdb_guid}</dd>
                </div>
                <div>
                  <dt className="inline font-semibold">Age: </dt>
                  <dd className="inline font-mono" data-testid="memory-symbol-acquire-age">{req.pdb_age}</dd>
                </div>
                <div>
                  <dt className="inline font-semibold">Architecture: </dt>
                  <dd className="inline font-mono" data-testid="memory-symbol-acquire-arch">{req.architecture}</dd>
                </div>
              </dl>
            ) : null}
            <label
              className="mt-3 flex items-start gap-2 text-xs"
              data-testid="memory-symbol-acquire-ack"
            >
              <input
                type="checkbox"
                checked={ackChecked}
                onChange={(event) => setAckChecked(event.target.checked)}
                data-testid="memory-symbol-acquire-ack-checkbox"
                className="mt-1"
              />
              <span>
                I am authorized to request acquisition of the exact Windows
                symbols for this evidence.
              </span>
            </label>
            {acquireError ? (
              <p
                className="mt-3 text-xs text-rose-200"
                data-testid="memory-symbol-acquire-error"
                role="alert"
              >
                {acquireError}
              </p>
            ) : null}
            <div className="mt-4 flex flex-wrap justify-end gap-2">
              <button
                type="button"
                onClick={() => {
                  setAcquisitionModalOpen(false);
                  setAckChecked(false);
                }}
                className="rounded-xl border border-line bg-abyss/70 px-3 py-1.5 text-xs text-muted"
                data-testid="memory-symbol-acquire-cancel"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => {
                  if (!ackChecked) return;
                  acquireMutation.mutate();
                  setAcquisitionModalOpen(false);
                  setAckChecked(false);
                }}
                disabled={!ackChecked || acquireMutation.isPending}
                className="rounded-xl bg-accent px-3 py-1.5 text-xs font-semibold text-abyss disabled:opacity-50"
                data-testid="memory-symbol-acquire-confirm"
              >
                {acquireMutation.isPending ? "Requesting…" : "Request acquisition"}
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </section>
  );
}
