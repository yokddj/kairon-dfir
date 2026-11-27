import { useQuery } from "@tanstack/react-query";

import { api, type Evidence, type EvidenceRun } from "../../api/client";
import { Disclosure } from "../common/Disclosure";
import { evidenceTypeLabel, formatBytes, formatDateTime, formatDuration, formatPlatform } from "../../lib/evidenceDetailFormatting";

const INTEGRITY_TEXT: Record<string, string> = {
  verified: "SHA-256 verified",
  mismatch: "Hash mismatch",
  missing_file: "Stored file missing",
  error: "Check failed",
  unknown: "Not checked yet",
};

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[150px_minmax(0,1fr)] gap-3 py-1.5 text-sm">
      <dt className="text-muted">{label}</dt>
      <dd className="min-w-0 break-words text-ink">{children}</dd>
    </div>
  );
}

function Body({ evidence, runs }: { evidence: Evidence; runs: EvidenceRun[] }) {
  const integrity = useQuery({
    queryKey: ["evidence-integrity", evidence.case_id, evidence.id],
    queryFn: () => api.getEvidenceIntegrity(evidence.case_id, evidence.id),
  });
  const custody = useQuery({
    queryKey: ["evidence-custody-events", evidence.case_id, evidence.id],
    queryFn: () => api.getEvidenceCustodyEvents(evidence.case_id, evidence.id),
  });
  const status = String(integrity.data?.integrity_status ?? evidence.integrity_status ?? "unknown");
  const checkedAt = integrity.data?.integrity_checked_at ?? evidence.integrity_checked_at;
  const platformMismatch =
    evidence.provided_platform && evidence.provided_platform !== "auto" && evidence.detected_platform && evidence.detected_platform !== "unknown" && evidence.provided_platform !== evidence.detected_platform;
  const events = custody.data ?? [];

  return (
    <div className="space-y-5">
      <dl className="divide-y divide-line/60">
        <Row label="Type">{evidenceTypeLabel(evidence.evidence_type)}</Row>
        <Row label="Platform">
          {formatPlatform(evidence.effective_platform)}
          {platformMismatch ? <span className="text-amber"> · declared {formatPlatform(evidence.provided_platform)}, detected {formatPlatform(evidence.detected_platform)}</span> : null}
        </Row>
        <Row label="SHA-256">
          <span className="break-all font-mono text-xs">{integrity.data?.sha256 ?? evidence.sha256 ?? "not recorded"}</span>
        </Row>
        <Row label="Size">{formatBytes(integrity.data?.size_bytes ?? evidence.size_bytes)}</Row>
        <Row label="Integrity">
          <span className={status === "verified" ? "text-mint" : status === "unknown" ? "text-muted" : "text-danger"}>{INTEGRITY_TEXT[status] ?? status}</span>
          {checkedAt ? <span className="text-muted"> · {formatDateTime(checkedAt)}</span> : null}
        </Row>
        <Row label="Uploaded">{formatDateTime(evidence.uploaded_at ?? evidence.created_at)}</Row>
        <Row label="Stored at">
          <span className="break-all font-mono text-xs">{evidence.original_path || evidence.stored_path}</span>
        </Row>
      </dl>

      {runs.length ? (
        <div>
          <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Runs</p>
          <ul className="mt-2 divide-y divide-line/60 text-sm">
            {runs.slice(0, 6).map((run) => (
              <li key={run.run_id} className="flex flex-wrap justify-between gap-2 py-1.5">
                <span className="text-ink">
                  {run.run_type.replaceAll("_", " ")} · <span className="text-muted">{run.status.replaceAll("_", " ")}</span>
                </span>
                <span className="text-xs text-muted">
                  {formatDateTime(run.started_at)}
                  {run.elapsed_seconds ? ` · ${formatDuration(run.elapsed_seconds)}` : ""}
                  {run.artifacts_total ? ` · ${run.artifacts_done ?? 0}/${run.artifacts_total} artifacts` : ""}
                </span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      <div>
        <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Chain of custody</p>
        {events.length ? (
          <ul className="mt-2 divide-y divide-line/60 text-sm">
            {events
              .slice(-8)
              .reverse()
              .map((event) => (
                <li key={event.id} className="flex flex-wrap justify-between gap-2 py-1.5">
                  <span className="text-ink">{event.summary}</span>
                  <span className="text-xs text-muted">{formatDateTime(event.timestamp)}</span>
                </li>
              ))}
          </ul>
        ) : (
          <p className="mt-2 text-sm text-muted">{custody.isLoading ? "Loading…" : "No events recorded yet."}</p>
        )}
      </div>
    </div>
  );
}

export default function TechnicalDetails({ evidence, runs }: { evidence: Evidence; runs: EvidenceRun[] }) {
  return (
    <Disclosure label="Technical details" testId="evidence-technical-details">
      <Body evidence={evidence} runs={runs} />
    </Disclosure>
  );
}
