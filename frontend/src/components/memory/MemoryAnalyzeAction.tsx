import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import {
  type MemoryBackendStatus,
  type MemoryEvidenceReadiness,
  type MemoryOverview,
  api,
} from "../../api/client";
import { backendBadge } from "../MemoryWorkspace";

type Profile = "metadata_only" | "processes_basic" | "processes_extended";

const PROFILE_COPY: Record<Profile, { title: string; description: string }> = {
  metadata_only: {
    title: "System metadata",
    description: "Capture the windows.info block (OS family, kernel base, architecture) without running plugin logic.",
  },
  processes_basic: {
    title: "Standard process analysis",
    description: "Active processes, parent-child relationships and command lines.",
  },
  processes_extended: {
    title: "Extended process analysis",
    description: "Adds memory scanning for terminated or unlinked processes. Builds on the standard analysis.",
  },
};

type Props = {
  caseId: string;
  overview: MemoryOverview;
  evidenceId?: string;
  readinessByEvidence: Map<string, MemoryEvidenceReadiness | undefined>;
  canRunMetadata: boolean;
  canRunProcessProfiles: boolean;
  volatilityBackend: MemoryBackendStatus | null;
};

function AuthorizationCopy(): string {
  return "I confirm that I own this memory image or am explicitly authorized to analyze it, and I understand that RAM may contain sensitive personal or authentication data.";
}

function ProfileCopy({ profile }: { profile: Profile }): string {
  if (profile === "processes_basic") {
    return "This will analyze the selected authorized memory image using the externally configured Volatility 3 backend and the windows.info, windows.pslist, windows.pstree, and windows.cmdline plugins.";
  }
  if (profile === "processes_extended") {
    return "This also runs windows.psscan, which may return additional process structures requiring analyst interpretation.";
  }
  return "This will analyze the selected authorized memory image using the externally configured Volatility 3 backend and the windows.info metadata plugin.";
}

export function MemoryAnalyzeAction({
  caseId,
  overview,
  evidenceId: evidenceIdProp,
  readinessByEvidence,
  canRunMetadata,
  canRunProcessProfiles,
  volatilityBackend,
}: Props) {
  const queryClient = useQueryClient();
  const [profile, setProfile] = useState<Profile>("processes_basic");
  const [feedback, setFeedback] = useState<string | null>(null);

  const startMutation = useMutation({
    mutationFn: (vars: { evidenceId: string; profile: Profile }) =>
      api.startMemoryScan(caseId, vars.evidenceId, vars.profile, true),
    onSuccess: (result) => {
      setFeedback(result.message);
      queryClient.invalidateQueries({ queryKey: ["memory-overview", caseId] });
      queryClient.invalidateQueries({ queryKey: ["memory-runs", caseId] });
      queryClient.invalidateQueries({ queryKey: ["memory-run-options", caseId] });
    },
  });

  const evidence = evidenceIdProp
    ? overview.evidences.find((e) => e.id === evidenceIdProp) ?? null
    : null;
  const readiness = evidence ? readinessByEvidence.get(evidence.id) : undefined;
  const canRunSelected =
    profile === "metadata_only"
      ? canRunMetadata
      : canRunProcessProfiles && readiness?.can_analyze;

  function handleRun() {
    if (!evidence) return;
    if (!window.confirm(AuthorizationCopy())) return;
    if (!window.confirm(ProfileCopy({ profile }))) return;
    startMutation.mutate({ evidenceId: evidence.id, profile });
  }

  return (
    <section
      className="sticky bottom-4 z-10 rounded-[28px] border border-line bg-panel/85 p-5 shadow-panel backdrop-blur"
      data-testid="memory-analyze-action"
    >
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-muted">Analyze memory</h3>
          <p className="mt-1 text-xs text-muted">
            Pick an analysis profile and confirm authorization. The selected profile runs against the active memory evidence.
          </p>
        </div>
        <div className="flex flex-wrap gap-2 text-[10px]">
          {volatilityBackend ? (
            <span className="rounded-md border border-line bg-abyss/70 px-2 py-0.5 text-muted">
              Volatility 3: {backendBadge(volatilityBackend)}
            </span>
          ) : null}
          <Link
            to={`/cases/${caseId}/memory/upload`}
            className="rounded-md border border-line bg-abyss/70 px-2 py-0.5 text-muted"
          >
            Add memory image
          </Link>
        </div>
      </header>

      <div className="mt-3 flex flex-wrap items-center gap-2">
        <label className="text-xs text-muted" htmlFor="analyze-profile">
          Profile
        </label>
        <select
          id="analyze-profile"
          value={profile}
          onChange={(event) => setProfile(event.target.value as Profile)}
          className="rounded-xl border border-line bg-abyss/70 px-2 py-1 text-sm"
          data-testid="analyze-profile-select"
        >
          {(Object.keys(PROFILE_COPY) as Profile[]).map((key) => (
            <option key={key} value={key}>
              {PROFILE_COPY[key].title}
            </option>
          ))}
        </select>
        <p className="ml-2 text-xs text-muted">{PROFILE_COPY[profile].description}</p>
      </div>

      <div className="mt-3 flex flex-wrap gap-2">
        {!evidence ? (
          <p className="text-xs text-amber-200">Select a memory evidence above to begin analysis.</p>
        ) : (
          <>
            <button
              type="button"
              disabled={!canRunSelected || startMutation.isPending}
              onClick={handleRun}
              data-testid="analyze-run-button"
              className="rounded-xl bg-accent px-3 py-2 text-xs font-semibold text-abyss disabled:opacity-50"
            >
              {startMutation.isPending ? "Starting analysis..." : "Run selected analysis"}
            </button>
            {!canRunMetadata ? (
              <p className="text-xs text-rose-200">
                {volatilityBackend?.message || "Volatility 3 is not ready for memory analysis."}
              </p>
            ) : null}
            {readiness && !readiness.can_analyze && readiness.sanitized_message ? (
              <p className="text-xs text-rose-200">{readiness.sanitized_message}</p>
            ) : null}
          </>
        )}
      </div>

      {feedback ? <p className="mt-2 text-xs text-emerald-200" data-testid="analyze-feedback">{feedback}</p> : null}
      {startMutation.error instanceof Error ? (
        <p className="mt-2 text-xs text-rose-200">{startMutation.error.message}</p>
      ) : null}
    </section>
  );
}

export type { Profile };
