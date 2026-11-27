import type { ReactNode } from "react";
import { Link } from "react-router-dom";

import type { ProblematicArtifact } from "../../api/client";
import { artifactLabel, canonicalArtifactView } from "../../lib/artifactRegistry";
import { formatProblematicStatusLabel } from "../../lib/evidenceDetailFormatting";
import type { ProblemBuckets } from "../../lib/evidenceStatus";

function problemReason(artifact: ProblematicArtifact) {
  return artifact.error_message || artifact.health_summary || formatProblematicStatusLabel(artifact.effective_status ?? artifact.status);
}

function ProblemRow({ artifact, action }: { artifact: ProblematicArtifact; action?: ReactNode }) {
  return (
    <li className="flex flex-wrap items-start justify-between gap-3 px-4 py-3">
      <div className="min-w-0">
        <p className="text-sm font-medium text-ink">
          {artifact.name} <span className="text-xs font-normal text-muted">· {artifactLabel(artifact.artifact_type || artifact.parser)}</span>
        </p>
        <p className="mt-0.5 break-words text-xs text-muted">{problemReason(artifact)}</p>
        <p className="mt-0.5 break-all font-mono text-[11px] text-muted/80">{artifact.source_path}</p>
      </div>
      {action}
    </li>
  );
}

/**
 * After processing: what was found (per family, each linking to its view),
 * then failures only when there are any, and empty files as a one-line note.
 */
export default function EvidenceResults({
  caseId,
  evidenceId,
  totalDocs,
  artifactTypeCounts,
  problems,
  onRetry,
  retryBusy,
  extra,
}: {
  caseId: string;
  evidenceId: string;
  totalDocs: number;
  artifactTypeCounts: Record<string, number>;
  problems: ProblemBuckets;
  onRetry: (artifactIds: string[]) => void;
  retryBusy: boolean;
  extra?: ReactNode;
}) {
  const scope = `evidence_id=${encodeURIComponent(evidenceId)}`;
  const families = Object.entries(artifactTypeCounts)
    .filter(([, count]) => count > 0)
    .sort((left, right) => right[1] - left[1]);
  const retryableIds = problems.failures.filter((artifact) => artifact.retryable && artifact.artifact_id).map((artifact) => artifact.artifact_id as string);

  return (
    <>
      <section className="rounded-3xl border border-line bg-panel/70 p-5" data-testid="evidence-results">
        <div className="flex flex-wrap items-baseline justify-between gap-2">
          <h3 className="text-lg font-semibold text-ink">What was found</h3>
          <p className="text-sm text-muted">
            <span className="font-semibold text-ink">{totalDocs.toLocaleString()}</span> searchable records
          </p>
        </div>
        {families.length ? (
          <ul className="mt-4 grid gap-x-6 sm:grid-cols-2 xl:grid-cols-3">
            {families.map(([type, count]) => (
              <li key={type} className="border-b border-line/60">
                <Link
                  to={`/cases/${caseId}/artifacts?${scope}&artifact_type=${encodeURIComponent(canonicalArtifactView(type))}`}
                  className="flex items-center justify-between gap-3 py-2 text-sm text-ink hover:text-accent"
                >
                  <span className="truncate">{artifactLabel(type)}</span>
                  <span className="shrink-0 tabular-nums text-muted">{count.toLocaleString()}</span>
                </Link>
              </li>
            ))}
          </ul>
        ) : (
          <p className="mt-3 text-sm text-muted">Nothing searchable was indexed from this evidence.</p>
        )}
        {problems.emptyCount ? (
          <p className="mt-3 text-xs text-muted" data-testid="evidence-empty-note">
            {problems.emptyCount.toLocaleString()} file{problems.emptyCount === 1 ? "" : "s"} held no records and {problems.emptyCount === 1 ? "was" : "were"} skipped.
          </p>
        ) : null}
        {extra}
      </section>

      {problems.failures.length ? (
        <section className="rounded-3xl border border-danger/30 bg-panel/70" data-testid="evidence-failures">
          <div className="flex flex-wrap items-center justify-between gap-3 px-5 pt-5">
            <h3 className="text-lg font-semibold text-ink">
              {problems.failures.length} artifact{problems.failures.length === 1 ? "" : "s"} failed
            </h3>
            {retryableIds.length ? (
              <button type="button" onClick={() => onRetry(retryableIds)} disabled={retryBusy} className="rounded-xl bg-accent px-4 py-2 text-sm font-semibold text-abyss disabled:opacity-50">
                Retry {retryableIds.length === 1 ? "it" : `all ${retryableIds.length}`}
              </button>
            ) : null}
          </div>
          <ul className="mt-3 divide-y divide-line">
            {problems.failures.map((artifact, index) => (
              <ProblemRow
                key={`${artifact.artifact_id ?? artifact.source_path}:${index}`}
                artifact={artifact}
                action={
                  artifact.retryable && artifact.artifact_id && retryableIds.length > 1 ? (
                    <button type="button" onClick={() => onRetry([artifact.artifact_id as string])} disabled={retryBusy} className="rounded-full border border-accent/40 px-3 py-1 text-xs text-accent disabled:opacity-50">
                      Retry
                    </button>
                  ) : null
                }
              />
            ))}
          </ul>
        </section>
      ) : null}

      {problems.warnings.length ? (
        <details className="rounded-2xl border border-line bg-panel/50" data-testid="evidence-warnings">
          <summary className="cursor-pointer px-5 py-3 text-sm text-amber">
            {problems.warnings.length} artifact{problems.warnings.length === 1 ? "" : "s"} indexed with warnings
          </summary>
          <ul className="divide-y divide-line border-t border-line">
            {problems.warnings.map((artifact, index) => (
              <ProblemRow key={`${artifact.artifact_id ?? artifact.source_path}:${index}`} artifact={artifact} />
            ))}
          </ul>
        </details>
      ) : null}
    </>
  );
}
