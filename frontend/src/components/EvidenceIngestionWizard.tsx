import { useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";

import { api, type Evidence, type EvidencePlatform, type EvidenceUploadSessionRead, type PreflightReport } from "../api/client";
import { useNotifications } from "../context/NotificationsContext";
import { platformUploadOptions } from "../lib/platformRegistry";
import { hashFileWithProgress } from "../lib/sha256";

type IntakeType = "disk_image" | "memory_dump" | "artifact_collection" | "folder" | "server_path";
type WizardStep = 0 | 1 | 2 | 3 | 4 | 5 | 6;

const TOTAL_STEPS = 7;

type Props = {
  open: boolean;
  caseId: string;
  onClose: () => void;
};

const INTAKE_CARDS: { id: IntakeType; icon: string; title: string; examples: string }[] = [
  { id: "disk_image", icon: "\u{1F5B4}", title: "Disk Image", examples: "RAW, DD, IMG, E01, Ex01, QCOW2, VMDK..." },
  { id: "memory_dump", icon: "\u{1F4BE}", title: "Memory Dump", examples: "WinPmem, Lime, RAW memory..." },
  { id: "artifact_collection", icon: "\u{1F4E6}", title: "Artifact Collection", examples: "KAPE, Velociraptor, manual ZIP" },
  { id: "folder", icon: "\u{1F4C1}", title: "Folder", examples: "Directory containing artifacts" },
  { id: "server_path", icon: "\u{2601}", title: "Existing Server Path", examples: "Already stored locally" },
];

function bytes(value: number | null | undefined): string {
  if (value === null || value === undefined) return "unknown";
  let num = value;
  for (const unit of ["B", "KB", "MB", "GB", "TB"]) {
    if (num < 1024 || unit === "TB") return unit === "B" ? `${Math.round(num)} B` : `${num.toFixed(1)} ${unit}`;
    num /= 1024;
  }
  return `${num.toFixed(1)} TB`;
}

function durationBucketLabel(bucket: string | null): string | null {
  switch (bucket) {
    case "fast":
      return "Fast (under 2 minutes)";
    case "medium":
      return "Medium (10–20 minutes)";
    case "long":
      return "Long (1–2 hours)";
    case "very_long":
      return "Very long (several hours)";
    default:
      return null;
  }
}

export default function EvidenceIngestionWizard({ open, caseId, onClose }: Props) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { notify } = useNotifications();

  const [step, setStep] = useState<WizardStep>(0);
  const [intakeType, setIntakeType] = useState<IntakeType | null>(null);
  const [platform, setPlatform] = useState<EvidencePlatform>("auto");
  const [hostChoice, setHostChoice] = useState<"auto" | string>("auto");
  const [newHostName, setNewHostName] = useState("");
  const [files, setFiles] = useState<File[]>([]);
  const [serverPath, setServerPath] = useState("");
  const [session, setSession] = useState<EvidenceUploadSessionRead | null>(null);
  const [preflight, setPreflight] = useState<PreflightReport | null>(null);
  const [manualOverrideAccepted, setManualOverrideAccepted] = useState(false);
  const [memoryAuthorizationAcknowledged, setMemoryAuthorizationAcknowledged] = useState(false);
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [labels, setLabels] = useState("");
  const [notes, setNotes] = useState("");
  const [hashProgress, setHashProgress] = useState<number | null>(null);
  const [clientSha256, setClientSha256] = useState<string | null>(null);
  const promotedRef = useRef(false);

  const requiresPathInput = intakeType === "server_path";
  const requiresFolderInput = intakeType === "folder";

  const caseHostsQuery = useQuery({ queryKey: ["case-hosts", caseId], queryFn: () => api.getCaseHosts(caseId), enabled: open && Boolean(caseId), staleTime: 15_000 });
  const caseHosts = caseHostsQuery.data?.hosts ?? [];

  const healthQuery = useQuery({
    queryKey: ["ingestion-readiness", caseId],
    queryFn: () => api.getIngestionReadiness(caseId),
    enabled: open && Boolean(caseId),
    staleTime: 10_000,
  });

  useEffect(() => {
    if (requiresPathInput || files.length !== 1) {
      setClientSha256(null);
      setHashProgress(null);
      return;
    }
    let cancelled = false;
    setClientSha256(null);
    setHashProgress(0);
    hashFileWithProgress(files[0], (fraction) => {
      if (!cancelled) setHashProgress(fraction);
    })
      .then((hash) => {
        if (!cancelled) {
          setClientSha256(hash);
          setHashProgress(1);
        }
      })
      .catch(() => {
        if (!cancelled) setHashProgress(null);
      });
    return () => {
      cancelled = true;
    };
  }, [files, requiresPathInput]);

  function reset() {
    setStep(0);
    setIntakeType(null);
    setPlatform("auto");
    setHostChoice("auto");
    setNewHostName("");
    setFiles([]);
    setServerPath("");
    setSession(null);
    setPreflight(null);
    setManualOverrideAccepted(false);
    setMemoryAuthorizationAcknowledged(false);
    setAdvancedOpen(false);
    setLabels("");
    setNotes("");
    setHashProgress(null);
    setClientSha256(null);
    promotedRef.current = false;
  }

  function handleClose() {
    if (session && !promotedRef.current) {
      void api.cancelEvidenceUploadSession(caseId, session.id).catch(() => {});
    }
    reset();
    onClose();
  }

  const createSessionMutation = useMutation({
    mutationFn: async () => {
      if (intakeType === "server_path") {
        return api.createEvidenceUploadSession(caseId, { serverPath: serverPath.trim() }, { declaredPlatform: platform });
      }
      if (requiresFolderInput || files.length > 1) {
        return api.createEvidenceUploadSession(caseId, { files, folderUpload: requiresFolderInput }, { declaredPlatform: platform });
      }
      return api.createEvidenceUploadSession(caseId, { file: files[0] }, { declaredPlatform: platform, clientSha256: clientSha256 ?? undefined });
    },
    onSuccess: (response) => {
      setSession(response.session);
      setPreflight(response.preflight);
      setStep(5);
    },
    onError: (error) => {
      notify({ title: "Preflight inspection failed", description: error instanceof Error ? error.message : "Kairon could not inspect this evidence.", tone: "error" });
    },
  });

  async function resolveHostId(): Promise<string | undefined> {
    if (hostChoice === "auto") return undefined;
    if (hostChoice === "__create__") {
      const name = newHostName.trim();
      if (!name) return undefined;
      const result = await api.createCaseHost(caseId, { host_name: name, reason: "Created during evidence ingestion wizard" });
      await queryClient.invalidateQueries({ queryKey: ["case-hosts", caseId] });
      return result.host.id;
    }
    return hostChoice;
  }

  const startMutation = useMutation({
    mutationFn: async (): Promise<Evidence> => {
      if (!session) throw new Error("No upload session is active");
      const hostId = await resolveHostId();
      const declaredPlatform = platform === "auto" ? undefined : platform;
      return api.promoteEvidenceUploadSession(caseId, session.id, {
        provided_platform: declaredPlatform,
        host_id: hostId,
        memory_authorization_acknowledged: intakeType === "memory_dump" ? memoryAuthorizationAcknowledged : undefined,
        labels: labels.split(",").map((label) => label.trim()).filter(Boolean),
        notes: notes.trim() || undefined,
      });
    },
    onSuccess: (evidence) => {
      promotedRef.current = true;
      notify({ title: "Processing started", description: `${evidence.original_filename} was queued for processing.`, tone: "success" });
      void queryClient.invalidateQueries({ queryKey: ["case-processing", caseId] });
      void queryClient.invalidateQueries({ queryKey: ["evidences", caseId] });
      handleClose();
      navigate(`/cases/${caseId}?tab=processing&evidence_id=${evidence.id}`);
    },
    onError: (error) => {
      notify({ title: "Could not start processing", description: error instanceof Error ? error.message : "The evidence could not be queued for processing.", tone: "error" });
    },
  });

  const blocked = preflight?.status === "blocked" && !manualOverrideAccepted;

  const canAdvanceStep4 = useMemo(() => {
    if (requiresPathInput) return serverPath.trim().length > 0;
    return files.length > 0;
  }, [requiresPathInput, serverPath, files]);

  const hashPending = files.length === 1 && !requiresPathInput && hashProgress !== null && hashProgress < 1;

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4" role="dialog" aria-modal="true" aria-label="Add Evidence">
      <div className="w-full max-w-3xl max-h-[90vh] overflow-y-auto rounded-[28px] border border-line bg-panel p-6 shadow-panel">
        <div className="flex items-center justify-between">
          <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">Add Evidence &middot; Step {step + 1} of {TOTAL_STEPS}</p>
          <button type="button" onClick={handleClose} className="rounded-xl border border-line px-3 py-2 text-xs text-muted">Cancel</button>
        </div>

        {step === 0 ? (
          <section className="mt-5" data-testid="health-check">
            <h2 className="text-xl font-semibold text-ink">Server Health Check</h2>
            <p className="mt-1 text-sm text-muted">Kairon checks its core dependencies before you start adding evidence.</p>
            {healthQuery.isLoading ? (
              <p className="mt-4 text-sm text-muted">Checking system health...</p>
            ) : healthQuery.data ? (
              <>
                <div className="mt-4 space-y-2">
                  {healthQuery.data.checks.map((check) => (
                    <p key={check.label} className={`text-sm ${check.ok ? "text-mint" : "text-danger"}`}>
                      {check.ok ? "✔" : "⚠"} {check.label}: {check.detail}
                    </p>
                  ))}
                </div>
                <div className="mt-4 grid gap-2 text-sm text-muted sm:grid-cols-2">
                  <p>Available disk space: <span className="text-ink">{bytes(healthQuery.data.available_disk_space_bytes)}</span></p>
                  <p>Configured upload limit: <span className="text-ink">{bytes(healthQuery.data.configured_upload_limit_bytes)}</span></p>
                  <p>Configured extraction limit: <span className="text-ink">{bytes(healthQuery.data.configured_extraction_limit_bytes)}</span></p>
                </div>
                {!healthQuery.data.critical_ready ? (
                  <p className="mt-4 text-sm font-semibold text-danger">Processing cannot begin: Storage and Database must both be reachable.</p>
                ) : !healthQuery.data.ready ? (
                  <p className="mt-4 text-sm text-amber">Some non-critical dependencies (search or workers) are unavailable. You can continue, but processing may be delayed until they recover.</p>
                ) : (
                  <p className="mt-4 text-sm font-semibold text-mint">All systems ready</p>
                )}
              </>
            ) : (
              <p className="mt-4 text-sm text-danger">Kairon could not reach its own health check endpoint.</p>
            )}
            <div className="mt-5 flex justify-between">
              <button type="button" onClick={() => healthQuery.refetch()} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">Recheck</button>
              <button
                type="button"
                disabled={!healthQuery.data?.critical_ready}
                onClick={() => setStep(1)}
                className="rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss disabled:opacity-50"
              >
                Continue
              </button>
            </div>
          </section>
        ) : null}

        {step === 1 ? (
          <section className="mt-5">
            <h2 className="text-xl font-semibold text-ink">What are you adding?</h2>
            <div className="mt-4 grid gap-3 sm:grid-cols-2">
              {INTAKE_CARDS.map((card) => (
                <button
                  key={card.id}
                  type="button"
                  onClick={() => { setIntakeType(card.id); setStep(2); }}
                  className="rounded-2xl border border-line bg-abyss/60 p-4 text-left transition hover:border-accent/50"
                >
                  <p className="text-2xl">{card.icon}</p>
                  <p className="mt-2 font-semibold text-ink">{card.title}</p>
                  <p className="mt-1 text-xs text-muted">{card.examples}</p>
                </button>
              ))}
            </div>
          </section>
        ) : null}

        {step === 2 ? (
          <section className="mt-5">
            <h2 className="text-xl font-semibold text-ink">Platform</h2>
            <p className="mt-1 text-sm text-muted">Auto Detect is recommended &mdash; Kairon classifies the platform from the evidence itself during the next step.</p>
            <div className="mt-4 grid gap-3">
              {platformUploadOptions().map((option) => (
                <button
                  key={option.id}
                  type="button"
                  disabled={option.disabled}
                  onClick={() => setPlatform(option.id as EvidencePlatform)}
                  className={`rounded-2xl border p-4 text-left transition disabled:cursor-not-allowed disabled:opacity-50 ${platform === option.id ? "border-accent bg-accent/10" : "border-line bg-abyss/60 hover:border-accent/40"}`}
                >
                  <p className="font-semibold text-ink">{option.label}{option.id === "auto" ? " (Recommended)" : ""}</p>
                  <p className="mt-1 text-xs text-muted">{option.description}</p>
                </button>
              ))}
            </div>
            <div className="mt-5 flex justify-between">
              <button type="button" onClick={() => setStep(1)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">Back</button>
              <button type="button" onClick={() => setStep(3)} className="rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss">Continue</button>
            </div>
          </section>
        ) : null}

        {step === 3 ? (
          <section className="mt-5">
            <h2 className="text-xl font-semibold text-ink">Host</h2>
            <p className="mt-1 text-sm text-muted">Auto Assign lets Kairon match or create a host once the evidence is inspected.</p>
            <div className="mt-4 grid gap-3">
              <label className={`rounded-2xl border p-4 ${hostChoice === "auto" ? "border-accent bg-accent/10" : "border-line bg-abyss/60"}`}>
                <input type="radio" name="host-choice" className="mr-2" checked={hostChoice === "auto"} onChange={() => setHostChoice("auto")} />
                Auto Assign
              </label>
              <label className={`rounded-2xl border p-4 ${hostChoice !== "auto" && hostChoice !== "__create__" ? "border-accent bg-accent/10" : "border-line bg-abyss/60"}`}>
                <input type="radio" name="host-choice" className="mr-2" checked={hostChoice !== "auto" && hostChoice !== "__create__"} onChange={() => setHostChoice(caseHosts[0]?.id ?? "auto")} disabled={!caseHosts.length} />
                Assign existing host
                {hostChoice !== "auto" && hostChoice !== "__create__" ? (
                  <select value={hostChoice} onChange={(event) => setHostChoice(event.target.value)} className="mt-3 w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm text-ink">
                    {caseHosts.map((host) => <option key={host.id} value={host.id}>{host.display_name}</option>)}
                  </select>
                ) : null}
              </label>
              <label className={`rounded-2xl border p-4 ${hostChoice === "__create__" ? "border-accent bg-accent/10" : "border-line bg-abyss/60"}`}>
                <input type="radio" name="host-choice" className="mr-2" checked={hostChoice === "__create__"} onChange={() => setHostChoice("__create__")} />
                Create new host
                {hostChoice === "__create__" ? (
                  <input value={newHostName} onChange={(event) => setNewHostName(event.target.value)} placeholder="WS-01" className="mt-3 w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm text-ink" />
                ) : null}
              </label>
            </div>
            <div className="mt-5 flex justify-between">
              <button type="button" onClick={() => setStep(2)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">Back</button>
              <button type="button" onClick={() => setStep(4)} className="rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss">Continue</button>
            </div>
          </section>
        ) : null}

        {step === 4 ? (
          <section className="mt-5">
            <h2 className="text-xl font-semibold text-ink">Choose evidence</h2>
            {requiresPathInput ? (
              <label className="mt-4 block text-sm text-muted">
                Server path
                <input value={serverPath} onChange={(event) => setServerPath(event.target.value)} placeholder="/mnt/evidence/case-001/disk.E01" className="mt-2 w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm text-ink" />
              </label>
            ) : (
              <label className="mt-4 flex flex-col gap-2 rounded-2xl border border-dashed border-line bg-abyss/60 p-6 text-sm text-muted">
                <span>{requiresFolderInput ? "Select a folder" : "Select a file"}</span>
                <input
                  type="file"
                  multiple={requiresFolderInput || intakeType === "disk_image"}
                  {...(requiresFolderInput ? { webkitdirectory: "true", directory: "true" } : {})}
                  onChange={(event) => setFiles(Array.from(event.target.files ?? []))}
                />
                {files.length ? <span className="text-xs text-ink">{files.length === 1 ? files[0].name : `${files.length} files selected`}</span> : null}
                {files.length === 1 && !requiresPathInput ? (
                  hashProgress === null ? null : hashProgress < 1 ? (
                    <span className="text-xs text-muted" data-testid="sha256-progress">Calculating SHA-256... {Math.round(hashProgress * 100)}%</span>
                  ) : (
                    <span className="text-xs text-mint" data-testid="sha256-ready">SHA-256: {clientSha256}</span>
                  )
                ) : null}
              </label>
            )}
            <div className="mt-5 flex justify-between">
              <button type="button" onClick={() => setStep(3)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">Back</button>
              <button
                type="button"
                disabled={!canAdvanceStep4 || createSessionMutation.isPending || hashPending}
                onClick={() => createSessionMutation.mutate()}
                className="rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss disabled:opacity-50"
              >
                {createSessionMutation.isPending ? "Inspecting..." : hashPending ? "Calculating SHA-256..." : "Inspect evidence"}
              </button>
            </div>
          </section>
        ) : null}

        {step === 5 && preflight ? (
          <section className="mt-5" data-testid="preflight-report">
            <h2 className="text-xl font-semibold text-ink">Preflight Inspection</h2>

            {session?.client_sha256_mismatch ? (
              <p className="mt-3 rounded-2xl border border-amber/40 bg-amber/10 p-3 text-xs text-amber" data-testid="hash-mismatch-warning">
                The SHA-256 computed in your browser does not match what Kairon staged on the server. The file may have changed during upload &mdash; consider re-selecting it before continuing.
              </p>
            ) : null}

            <div className="mt-4 rounded-2xl border border-line bg-abyss/60 p-4">
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Evidence Classification</p>
              <p className="mt-2 text-sm text-ink">{[...preflight.classification.chain, preflight.classification.platform !== "unknown" ? preflight.classification.platform : null].filter(Boolean).join(" → ")}</p>
              <div className="mt-3 grid gap-2 text-sm text-muted sm:grid-cols-2">
                <p>Evidence type: <span className="text-ink">{preflight.classification.category}</span></p>
                {preflight.classification.container ? <p>Container: <span className="text-ink">{preflight.classification.container}</span></p> : null}
                {preflight.classification.contained_object ? <p>Contained object: <span className="text-ink">{preflight.classification.contained_object}</span></p> : null}
                {preflight.classification.hostname ? <p>Hostname: <span className="text-ink">{preflight.classification.hostname}</span></p> : null}
                {preflight.classification.distro ? <p>Distribution: <span className="text-ink">{preflight.classification.distro}{preflight.classification.version ? ` (${preflight.classification.version})` : ""}</span></p> : null}
                {preflight.classification.volumes !== null ? <p>Volumes: <span className="text-ink">{preflight.classification.volumes}</span></p> : null}
                {preflight.classification.partitions !== null ? <p>Partitions: <span className="text-ink">{preflight.classification.partitions}</span></p> : null}
                {preflight.classification.filesystems.length ? <p>Filesystems: <span className="text-ink">{preflight.classification.filesystems.join(", ")}</span></p> : null}
                {preflight.classification.installations !== null ? <p>Installations: <span className="text-ink">{preflight.classification.installations}</span></p> : null}
                <p>Confidence: <span className="text-ink">{preflight.classification.confidence}</span></p>
              </div>
              {preflight.classification.expected_parsers.length ? (
                <div className="mt-3">
                  <p className="text-xs text-muted">Expected artifact families</p>
                  <div className="mt-1 flex flex-wrap gap-1.5">
                    {preflight.classification.expected_parsers.map((parser) => (
                      <span key={parser} className="rounded-full border border-mint/30 bg-mint/10 px-2 py-0.5 text-xs text-mint">&#10003; {parser}</span>
                    ))}
                  </div>
                </div>
              ) : null}
              {preflight.classification.warnings.length ? (
                <div className="mt-3 space-y-1">
                  {preflight.classification.warnings.map((warning) => (
                    <p key={warning.message} className={`text-xs ${warning.severity === "recommendation" ? "text-amber" : "text-muted"}`}>
                      {warning.severity === "recommendation" ? "Recommendation" : "Information"}: {warning.message}
                    </p>
                  ))}
                </div>
              ) : null}
            </div>

            <div className="mt-4 rounded-2xl border border-line bg-abyss/60 p-4">
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Processing Pipeline Preview</p>
              <p className="mt-2 text-sm text-ink">{preflight.pipeline_preview.join(" → ")}</p>
            </div>

            <div className="mt-4 rounded-2xl border border-line bg-abyss/60 p-4">
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Preflight Resource Check</p>
              <div className="mt-3 grid gap-2 text-sm text-muted sm:grid-cols-2">
                <p>File size: <span className="text-ink">{bytes(preflight.resource_check.file_size_bytes)}</span></p>
                {preflight.resource_check.estimated_extracted_bytes !== null ? <p>Estimated disk usage: <span className="text-ink">{bytes(preflight.resource_check.estimated_final_size_bytes)}</span></p> : null}
                {preflight.resource_check.estimated_temp_storage_bytes !== null ? <p>Estimated temporary storage: <span className="text-ink">{bytes(preflight.resource_check.estimated_temp_storage_bytes)}</span></p> : null}
                <p>Available storage: <span className="text-ink">{bytes(preflight.resource_check.available_disk_space_bytes)}</span></p>
                <p>Estimated duration: <span className="text-ink">{durationBucketLabel(preflight.resource_check.estimated_duration_bucket) ?? "unknown"}</span></p>
                {preflight.resource_check.estimated_artifact_count !== null ? <p>Estimated artifact count: <span className="text-ink">{preflight.resource_check.estimated_artifact_count}</span></p> : null}
                <p>Upload limit: <span className="text-ink">{bytes(preflight.resource_check.configured_upload_limit_bytes)}</span></p>
              </div>
            </div>

            <div className="mt-4 space-y-2">
              {preflight.status_checks.map((check) => (
                <p key={check.label} className={`text-sm ${check.ok ? "text-mint" : "text-danger"}`}>
                  {check.ok ? "✔" : "⚠"} {check.label}: {check.detail}
                </p>
              ))}
            </div>

            {preflight.diagnostics.length ? (
              <div className="mt-4 space-y-3">
                {preflight.diagnostics.map((diag) => (
                  <div key={diag.problem} className={`rounded-2xl border p-4 text-sm ${diag.severity === "recommendation" ? "border-amber/30 bg-amber/10" : "border-danger/30 bg-danger/10"}`}>
                    <p className={`font-semibold ${diag.severity === "recommendation" ? "text-amber" : "text-danger"}`}>
                      {diag.severity === "recommendation" ? "Recommendation" : "Blocking"}: {diag.problem}
                    </p>
                    <p className="mt-1 text-muted">{diag.reason}</p>
                    {diag.configuration_key ? (
                      <div className="mt-2 rounded-xl border border-line bg-abyss/60 p-3 text-xs text-muted">
                        <p>Current value: <span className="text-ink">{diag.current_configuration?.limit ?? diag.current_configuration?.available ?? diag.current_configuration?.depth ?? "unknown"}</span></p>
                        <p>Required value: <span className="text-ink">{diag.required_configuration?.limit ?? diag.required_configuration?.available ?? diag.required_configuration?.depth ?? "unknown"}</span></p>
                        <p>Configuration key: <span className="text-ink">{diag.configuration_key}</span></p>
                        {diag.configuration_file ? <p>Configuration file: <span className="text-ink">{diag.configuration_file}</span></p> : null}
                      </div>
                    ) : null}
                    {diag.how_to_fix.length ? (
                      <ol className="mt-2 list-decimal space-y-1 pl-5 text-xs text-muted">
                        {diag.how_to_fix.map((step) => <li key={step}>{step}</li>)}
                      </ol>
                    ) : null}
                    {diag.problem === "Low confidence classification" ? (
                      <label className="mt-3 flex items-center gap-2 text-xs text-ink">
                        <input type="checkbox" checked={manualOverrideAccepted} onChange={(event) => setManualOverrideAccepted(event.target.checked)} />
                        Continue with a manual override
                      </label>
                    ) : null}
                  </div>
                ))}
              </div>
            ) : (
              <p className="mt-4 text-sm font-semibold text-mint">Ready to process</p>
            )}

            <details className="mt-4 rounded-2xl border border-line bg-abyss/50 p-4" open={advancedOpen} onToggle={(event) => setAdvancedOpen((event.target as HTMLDetailsElement).open)}>
              <summary className="cursor-pointer text-xs uppercase tracking-[0.16em] text-muted">Advanced options</summary>
              <div className="mt-3 grid gap-3">
                <label className="text-xs text-muted">Labels<input value={labels} onChange={(event) => setLabels(event.target.value)} placeholder="comma, separated, labels" className="mt-1 w-full rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-ink" /></label>
                <label className="text-xs text-muted">Evidence notes<textarea value={notes} onChange={(event) => setNotes(event.target.value)} className="mt-1 h-20 w-full rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-ink" /></label>
              </div>
            </details>

            <div className="mt-5 flex justify-between">
              <button type="button" onClick={() => setStep(4)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">Back</button>
              <button
                type="button"
                disabled={blocked}
                onClick={() => setStep(6)}
                className="rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss disabled:opacity-50"
              >
                Continue
              </button>
            </div>
          </section>
        ) : null}

        {step === 6 && preflight ? (
          <section className="mt-5">
            <h2 className="text-xl font-semibold text-ink">Confirmation</h2>
            <div className="mt-4 rounded-2xl border border-line bg-abyss/60 p-4 text-sm text-muted">
              <p>Evidence: <span className="text-ink">{preflight.original_filename}</span></p>
              <p className="mt-1">Platform: <span className="text-ink">{platform === "auto" ? `Auto Detect (${preflight.classification.platform})` : platform}</span></p>
              <p className="mt-1">Host: <span className="text-ink">{hostChoice === "auto" ? "Auto Assign" : hostChoice === "__create__" ? newHostName || "New host" : caseHosts.find((h) => h.id === hostChoice)?.display_name || "Selected host"}</span></p>
              <p className="mt-1">Pipeline: <span className="text-ink">{preflight.pipeline_preview.join(" → ")}</span></p>
              <p className="mt-1">Estimated duration: <span className="text-ink">{durationBucketLabel(preflight.resource_check.estimated_duration_bucket) ?? "unknown"}</span></p>
            </div>
            {intakeType === "memory_dump" ? (
              <label className="mt-4 flex items-start gap-2 rounded-2xl border border-amber/40 bg-amber/10 p-4 text-sm text-ink">
                <input type="checkbox" className="mt-1" checked={memoryAuthorizationAcknowledged} onChange={(event) => setMemoryAuthorizationAcknowledged(event.target.checked)} />
                I am authorized to handle this RAM evidence and understand it may contain highly sensitive data.
              </label>
            ) : null}
            {startMutation.error instanceof Error ? <p className="mt-3 text-sm text-danger">{startMutation.error.message}</p> : null}
            <div className="mt-5 flex justify-between">
              <button type="button" onClick={() => setStep(5)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">Back</button>
              <button
                type="button"
                disabled={startMutation.isPending || (intakeType === "memory_dump" && !memoryAuthorizationAcknowledged)}
                onClick={() => startMutation.mutate()}
                className="rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss disabled:opacity-50"
              >
                {startMutation.isPending ? "Starting..." : "Start Processing"}
              </button>
            </div>
          </section>
        ) : null}
      </div>
    </div>
  );
}
