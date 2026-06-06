import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { API_BASE_URL, api, type PerformanceSettingEntry, type PerformanceState, type StorageCapabilities, type SystemVersionInfo } from "../api/client";

type ProfileName = "safe" | "balanced" | "performance" | "max" | "custom";
type SectionKey = "overview" | "performance" | "evidence" | "branding" | "opensearch" | "deployment" | "advanced";
type PerformanceGroupKey = "ingest" | "opensearch_bulk" | "search_timeline" | "graph_correlation" | "debug_export" | "other";
type DeploymentDiagnostic = NonNullable<NonNullable<PerformanceState["deployment"]>["pending_changes"][number]["diagnostic"]>;

const SECTION_LABELS: Array<{ key: SectionKey; label: string }> = [
  { key: "overview", label: "Overview" },
  { key: "performance", label: "Performance" },
  { key: "evidence", label: "Evidence storage" },
  { key: "branding", label: "Report branding" },
  { key: "opensearch", label: "OpenSearch" },
  { key: "deployment", label: "Deployment" },
  { key: "advanced", label: "Advanced" },
];

const SECTION_TO_PARAM: Record<SectionKey, string> = {
  overview: "overview",
  performance: "performance",
  evidence: "evidence-storage",
  branding: "report-branding",
  opensearch: "opensearch",
  deployment: "deployment",
  advanced: "advanced",
};

const PARAM_TO_SECTION: Record<string, SectionKey> = {
  overview: "overview",
  performance: "performance",
  "evidence-storage": "evidence",
  "report-branding": "branding",
  opensearch: "opensearch",
  deployment: "deployment",
  advanced: "advanced",
};

const PERFORMANCE_GROUP_LABELS: Record<PerformanceGroupKey, string> = {
  ingest: "Ingest",
  opensearch_bulk: "OpenSearch bulk / indexing",
  search_timeline: "Search & Timeline",
  graph_correlation: "Graph / Correlation",
  debug_export: "Debug export",
  other: "Other runtime settings",
};

function formatBytes(value: number) {
  if (!Number.isFinite(value) || value <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = value;
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }
  return `${size >= 100 || unitIndex === 0 ? size.toFixed(0) : size.toFixed(1)} ${units[unitIndex]}`;
}

function normalizeDraftValue(entry: PerformanceSettingEntry, raw: string) {
  if (entry.value_type === "bool") return raw === "true";
  if (entry.value_type === "int") return Number(raw);
  return raw;
}

function validateDraftEntries(entries: PerformanceSettingEntry[], draft: Record<string, unknown>) {
  const errors: Record<string, string> = {};
  for (const entry of entries) {
    if (!(entry.name in draft)) continue;
    const value = draft[entry.name];
    if (entry.value_type === "int") {
      const numeric = Number(value);
      if (!Number.isFinite(numeric)) {
        errors[entry.name] = "Must be a number";
        continue;
      }
      if (typeof entry.min === "number" && numeric < entry.min) {
        errors[entry.name] = `Must be >= ${entry.min}`;
      }
      if (typeof entry.max === "number" && numeric > entry.max) {
        errors[entry.name] = `Must be <= ${entry.max}`;
      }
    }
  }
  return errors;
}

function matchesAny(value: string, patterns: string[]) {
  return patterns.some((pattern) => value.includes(pattern));
}

function parseSectionParam(value: string | null): SectionKey {
  return value && PARAM_TO_SECTION[value] ? PARAM_TO_SECTION[value] : "overview";
}

function settingSection(entry: PerformanceSettingEntry): SectionKey {
  const name = entry.name.toLowerCase();
  const key = entry.key.toLowerCase();
  const group = (entry.group ?? entry.category).toLowerCase();
  if (matchesAny(name, ["report_brand", "report_subtitle", "report_logo", "report_primary"])) return "branding";
  if (matchesAny(name, ["opensearch_dashboards_public_url", "opensearch_"]) || key.includes("opensearch")) return entry.category === "deployment" ? "deployment" : "opensearch";
  if (matchesAny(name, ["backend_workers", "worker_concurrency", "docker_", "java_heap"]) || group.includes("deployment")) return "deployment";
  if (matchesAny(name, ["evidence_root", "host_path_import"])) return "evidence";
  return entry.category === "deployment" ? "deployment" : "performance";
}

function performanceGroup(entry: PerformanceSettingEntry): PerformanceGroupKey {
  const name = entry.name.toLowerCase();
  if (matchesAny(name, ["ingest_batch_size", "ingest_parallelism"])) return "ingest";
  if (matchesAny(name, ["opensearch_bulk_", "opensearch_refresh_timeout"])) return "opensearch_bulk";
  if (matchesAny(name, ["search_default_page_size", "search_max_page_size"])) return "search_timeline";
  if (matchesAny(name, ["process_graph_max_nodes", "correlation_max_events"])) return "graph_correlation";
  if (matchesAny(name, ["debug_export_max_events"])) return "debug_export";
  return "other";
}

function displayDraftValue(entry: PerformanceSettingEntry, draftSettings: Record<string, unknown>, fallback: unknown) {
  return String(draftSettings[entry.name] ?? fallback ?? "");
}

function statusTone(status: string | null | undefined) {
  if (status === "critical" || status === "high") return "border-danger/30 bg-danger/10 text-danger";
  if (status === "degraded" || status === "medium" || status === "warning") return "border-amber/30 bg-amber/10 text-amber";
  return "border-mint/25 bg-mint/10 text-mint";
}

function buildDraftPayload(_profile: ProfileName, draftSettings: Record<string, unknown>) {
  return draftSettings;
}

function clearDraftState(
  setDraftProfile: (profile: ProfileName) => void,
  setDraftSettings: (settings: Record<string, unknown>) => void,
  setValidationErrors: (errors: Record<string, string>) => void,
  profile: string,
) {
  setDraftProfile((profile as ProfileName) || "balanced");
  setDraftSettings({});
  setValidationErrors({});
}

function servicesForRestartScopes(scopes: string[]) {
  const ordered: string[] = [];
  for (const scope of scopes) {
    const values =
      scope === "worker"
        ? ["worker"]
        : scope === "backend"
          ? ["backend"]
          : scope === "opensearch"
            ? ["opensearch"]
            : scope === "full_stack"
              ? ["backend", "worker", "frontend"]
              : [];
    for (const value of values) {
      if (!ordered.includes(value)) ordered.push(value);
    }
  }
  return ordered;
}

function EvidenceRootCard({ root }: { root: NonNullable<StorageCapabilities["allowed_root_details"]>[number] }) {
  return (
    <div className="rounded-2xl border border-line bg-abyss/70 p-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">{root.path}</p>
          <p className="mt-2 text-sm text-muted">{root.label}</p>
          <p className="mt-2 text-xs text-muted">
            Example path: <span className="font-mono text-slate-200">{root.example_path}</span>
          </p>
        </div>
        <button type="button" onClick={() => void navigator.clipboard?.writeText(root.path)} className="rounded-xl border border-line px-3 py-2 text-xs text-muted">
          Copy
        </button>
      </div>
    </div>
  );
}

function RestartBadges({ services }: { services: string[] }) {
  if (!services.length) return null;
  return (
    <div className="mt-2 flex flex-wrap gap-2">
      {services.map((service) => (
        <span key={service} className="rounded-full border border-amber/40 bg-amber/10 px-2 py-1 text-[11px] text-amber">
          Requires {service}
        </span>
      ))}
    </div>
  );
}

function SettingInput({
  entry,
  value,
  error,
  onChange,
  title,
  technicalKey,
}: {
  entry: PerformanceSettingEntry;
  value: string;
  error?: string;
  onChange: (entry: PerformanceSettingEntry, raw: string) => void;
  title?: string;
  technicalKey?: string;
}) {
  return (
    <label className="block rounded-2xl border border-line bg-abyss/80 p-4">
      <span className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">{title ?? entry.name}</span>
      {technicalKey ? <p className="mt-2 text-[11px] uppercase tracking-[0.16em] text-slate-400">{technicalKey}</p> : null}
      <p className="mt-2 text-xs text-muted">{entry.description}</p>
      <div className="mt-2 flex flex-wrap gap-2 text-[11px] text-muted">
        <span className="rounded-full border border-line px-2 py-1">{entry.scope === "deployment" ? "Deployment" : "Runtime"}</span>
      </div>
      <RestartBadges services={entry.requires_restart_services ?? (entry.requires_restart !== "none" ? [entry.requires_restart] : [])} />
      {entry.value_type === "bool" ? (
        <select value={value} onChange={(event) => onChange(entry, event.target.value)} className="mt-3 w-full rounded-xl border border-line bg-panel/50 px-3 py-2 text-sm">
          <option value="true">true</option>
          <option value="false">false</option>
        </select>
      ) : (
        <input value={value} onChange={(event) => onChange(entry, event.target.value)} className="mt-3 w-full rounded-xl border border-line bg-panel/50 px-3 py-2 text-sm" />
      )}
      {error ? <p className="mt-2 text-xs text-danger">{error}</p> : null}
    </label>
  );
}

export default function SystemPage() {
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();
  const performanceQuery = useQuery({ queryKey: ["admin-performance"], queryFn: api.getAdminPerformance, refetchInterval: 15000 });
  const recommendationQuery = useQuery({ queryKey: ["admin-performance-recommendation"], queryFn: api.getAdminPerformanceRecommendation, refetchInterval: 30000 });
  const versionQuery = useQuery<SystemVersionInfo>({ queryKey: ["system-version"], queryFn: api.getSystemVersion, refetchInterval: 60000 });

  const [draftProfile, setDraftProfile] = useState<ProfileName>("balanced");
  const [draftSettings, setDraftSettings] = useState<Record<string, unknown>>({});
  const [validationErrors, setValidationErrors] = useState<Record<string, string>>({});
  const [lastMessage, setLastMessage] = useState("");
  const [copyStatus, setCopyStatus] = useState("");
  const [restartStatusMessage, setRestartStatusMessage] = useState("");
  const [checkingRestart, setCheckingRestart] = useState(false);
  const [activeSection, setActiveSection] = useState<SectionKey>(() => parseSectionParam(searchParams.get("tab")));
  const [advancedFilter, setAdvancedFilter] = useState("");

  useEffect(() => {
    setActiveSection(parseSectionParam(searchParams.get("tab")));
  }, [searchParams]);

  useEffect(() => {
    if (!performanceQuery.data) return;
    setDraftProfile(performanceQuery.data.profile);
    setDraftSettings({});
    setValidationErrors({});
  }, [performanceQuery.data?.profile]);

  const saveMutation = useMutation({
    mutationFn: () => api.updateAdminPerformance({ profile: draftProfile, settings: buildDraftPayload(draftProfile, draftSettings) }),
    onSuccess: (result) => {
      setLastMessage(`Saved profile ${result.profile}. Runtime applied: ${result.runtime_applied.length}. Restart required: ${result.requires_restart.join(", ") || "none"}.`);
      clearDraftState(setDraftProfile, setDraftSettings, setValidationErrors, result.profile);
      queryClient.setQueryData(["admin-performance"], result.effective_after_restart);
      void queryClient.invalidateQueries({ queryKey: ["admin-performance"] });
      void queryClient.invalidateQueries({ queryKey: ["admin-performance-recommendation"] });
    },
  });

  const applyMutation = useMutation({
    mutationFn: (confirmMax: boolean) => api.applyAdminPerformanceProfile({ profile: draftProfile, settings: buildDraftPayload(draftProfile, draftSettings), confirm_max: confirmMax }),
    onSuccess: (result) => {
      setLastMessage(`Applied profile ${result.profile}. Runtime applied: ${result.runtime_applied.length}. Restart required: ${result.requires_restart.join(", ") || "none"}.`);
      clearDraftState(setDraftProfile, setDraftSettings, setValidationErrors, result.profile);
      queryClient.setQueryData(["admin-performance"], result.effective_after_restart);
      void queryClient.invalidateQueries({ queryKey: ["admin-performance"] });
      void queryClient.invalidateQueries({ queryKey: ["admin-performance-recommendation"] });
    },
  });

  const applyRecommendedMutation = useMutation({
    mutationFn: (confirmMax: boolean) => api.applyAdminPerformanceRecommended({ confirm_max: confirmMax }),
    onSuccess: (result) => {
      setLastMessage(`Applied recommended profile ${result.profile}. Runtime applied: ${result.runtime_applied.length}. Restart required: ${result.requires_restart.join(", ") || "none"}.`);
      clearDraftState(setDraftProfile, setDraftSettings, setValidationErrors, result.profile);
      queryClient.setQueryData(["admin-performance"], result.effective_after_restart);
      void queryClient.invalidateQueries({ queryKey: ["admin-performance"] });
      void queryClient.invalidateQueries({ queryKey: ["admin-performance-recommendation"] });
    },
  });

  const data = performanceQuery.data;
  const settings = data?.settings ?? [];
  const resources = data?.resources;
  const recommendation = recommendationQuery.data ?? data?.recommendation;
  const evidenceStorage = data?.evidence_storage;
  const diskStatus = String(data?.system.disk_status ?? resources?.disk_status ?? "healthy");
  const diskUsedPercent = Number(data?.system.disk_used_percent ?? resources?.disk_used_percent ?? 0);
  const diskWarningThreshold = Number(data?.system.disk_warning_threshold_percent ?? 80);
  const diskCriticalThreshold = Number(data?.system.disk_critical_threshold_percent ?? 90);
  const openSearchWriteBlocked = Boolean(data?.services.opensearch.write_blocked ?? resources?.opensearch_write_blocked);
  const openSearchIngestWritable = data?.services.opensearch.ingest_writable ?? resources?.opensearch_ingest_writable;
  const openSearchWatermarkRisk = String(data?.services.opensearch.watermark_risk ?? resources?.opensearch_watermark_risk ?? "unknown");
  const openSearchBlockingReasons = Array.isArray(data?.services.opensearch.blocking_reasons) ? data?.services.opensearch.blocking_reasons as string[] : [];

  const performanceSettings = settings.filter((entry) => settingSection(entry) === "performance");
  const brandingSettings = settings.filter((entry) => settingSection(entry) === "branding");
  const openSearchSettings = settings.filter((entry) => settingSection(entry) === "opensearch");
  const deploymentSettings = settings.filter((entry) => settingSection(entry) === "deployment");
  const advancedSettings = settings.filter((entry) => {
    if (!advancedFilter.trim()) return true;
    const haystack = `${entry.name} ${entry.key} ${entry.description} ${entry.category} ${entry.group ?? ""}`.toLowerCase();
    return haystack.includes(advancedFilter.toLowerCase());
  });

  const groupedPerformanceSettings = useMemo(
    () =>
      performanceSettings.reduce<Record<PerformanceGroupKey, PerformanceSettingEntry[]>>(
        (acc, entry) => {
          acc[performanceGroup(entry)].push(entry);
          return acc;
        },
        {
          ingest: [],
          opensearch_bulk: [],
          search_timeline: [],
          graph_correlation: [],
          debug_export: [],
          other: [],
        },
      ),
    [performanceSettings],
  );

  const groupedAdvancedSettings = useMemo(
    () =>
      advancedSettings.reduce<Record<string, PerformanceSettingEntry[]>>((acc, entry) => {
        const group = entry.group ?? entry.category;
        if (!acc[group]) acc[group] = [];
        acc[group].push(entry);
        return acc;
      }, {}),
    [advancedSettings],
  );

  const pendingPreview = useMemo(() => {
    if (!data) return [];
    return settings
      .filter((entry) => entry.name in draftSettings && draftSettings[entry.name] !== data.effective_settings[entry.name])
      .map((entry) => ({
        key: entry.key,
        name: entry.name,
        oldValue: data.effective_settings[entry.name],
        newValue: draftSettings[entry.name],
        scope: entry.scope ?? (entry.requires_restart !== "none" ? "deployment" : "runtime"),
        status: entry.requires_restart !== "none" ? "requires restart" : "pending apply",
        services: entry.requires_restart_services ?? (entry.requires_restart !== "none" ? [entry.requires_restart] : []),
      }));
  }, [data, draftSettings, settings]);

  const stagedDeploymentChanges = (data?.deployment?.pending_changes ?? []).map((change) => ({
    key: change.key,
    name: change.name,
    oldValue: change.old_value,
    newValue: change.new_value,
    scope: change.scope,
    status: change.status,
    services: change.requires_restart_services,
  }));

  const pendingChanges = [...pendingPreview, ...stagedDeploymentChanges];
  const deploymentDiagnostics = (data?.deployment?.pending_changes ?? [])
    .map((change) => change.diagnostic)
    .filter((item): item is DeploymentDiagnostic => Boolean(item));
  const pendingChangeSummary = deploymentDiagnostics.map((item) => {
    const location = item.change_location?.path ?? "deployment config";
    const variable = item.change_location?.variable ?? item.setting_key;
    const currentValue = String(item.current_value);
    const expectedValue = String(item.expected_value);
    if (item.change_location?.type === "compose_scale") {
      return `Scale ${item.affected_services?.join(", ") || "the affected service"} from ${currentValue} to ${expectedValue} using ${item.commands?.[0] ?? "docker compose up --scale ..."}.`;
    }
    return `Update ${location}: set ${variable} from ${currentValue} to ${expectedValue}.`;
  });
  const pendingRestartScopes = useMemo(() => {
    const scopes = new Set<string>(data?.requires_restart ?? []);
    for (const entry of settings) {
      if (entry.requires_restart !== "none" && entry.name in draftSettings) scopes.add(entry.requires_restart);
    }
    for (const change of stagedDeploymentChanges) {
      for (const service of change.services ?? []) {
        if (service) scopes.add(service);
      }
    }
    return Array.from(scopes).filter(Boolean);
  }, [data?.requires_restart, draftSettings, settings, stagedDeploymentChanges]);
  const manualRestartInfo = data?.deployment?.restart_instructions ?? data?.restart_instructions;
  const manualRestartServices = (data?.deployment?.services_to_restart ?? data?.services_to_restart ?? []).length
    ? (data?.deployment?.services_to_restart ?? data?.services_to_restart ?? [])
    : servicesForRestartScopes(pendingRestartScopes);

  async function copyCommand(command: string) {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(command);
      setCopyStatus("Command copied.");
      return;
    }
    setCopyStatus("Clipboard is unavailable. Copy the command manually from the block.");
  }

  async function checkRestartStatus() {
    setCheckingRestart(true);
    setRestartStatusMessage("");
    try {
      const refreshed = await performanceQuery.refetch();
      const next = refreshed.data;
      const stillPending = Boolean((next?.deployment?.pending_changes ?? []).length || (next?.services_to_restart ?? []).length);
      const message = stillPending
        ? "Changes are still pending. Services may not have restarted or environment values may not have changed."
        : "Restart detected. Settings are active.";
      setRestartStatusMessage(message);
      setLastMessage(message);
    } catch {
      const message = "The current service status could not be checked.";
      setRestartStatusMessage(message);
      setLastMessage(message);
    } finally {
      setCheckingRestart(false);
    }
  }

  function selectSection(section: SectionKey) {
    setActiveSection(section);
    const next = new URLSearchParams(searchParams);
    next.set("tab", SECTION_TO_PARAM[section]);
    setSearchParams(next, { replace: true });
  }

  function updateDraft(entry: PerformanceSettingEntry, raw: string) {
    const nextValue = normalizeDraftValue(entry, raw);
    setDraftSettings((current) => ({ ...current, [entry.name]: nextValue }));
    setValidationErrors((current) => {
      const next = { ...current };
      delete next[entry.name];
      return next;
    });
  }

  function handleProfileSelect(profile: ProfileName) {
    setDraftProfile(profile);
    if (!data) return;
    if (profile === "custom") {
      setDraftSettings({});
      return;
    }
    const preset = data.profiles[profile] ?? {};
    const changes: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(preset)) {
      if (data.effective_settings[key] !== value) changes[key] = value;
    }
    setDraftSettings(changes);
  }

  function resetDraft() {
    if (!data) return;
    setDraftProfile(data.profile);
    setDraftSettings({});
    setValidationErrors({});
    setLastMessage("");
  }

  function validateAndRun(action: "save" | "apply") {
    const errors = validateDraftEntries(settings, draftSettings);
    setValidationErrors(errors);
    if (Object.keys(errors).length > 0) return;
    if (action === "save") saveMutation.mutate();
    else {
      const confirmMax = draftProfile !== "max" ? true : window.confirm("This may use most available resources.");
      if (!confirmMax) return;
      applyMutation.mutate(confirmMax);
    }
  }

  function applyRecommendedProfile() {
    if (!recommendation) return;
    const recommendedProfile = recommendation.recommended_profile as ProfileName;
    const confirmMax = recommendedProfile !== "max" ? true : window.confirm("This may use most available resources.");
    if (!confirmMax) return;
    applyRecommendedMutation.mutate(confirmMax);
  }

  if (performanceQuery.isPending || !data || !recommendation) {
    return (
      <div className="space-y-6">
        <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
          <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">System</p>
          <h2 className="mt-2 text-2xl font-semibold">Loading performance and deployment state…</h2>
        </section>
      </div>
    );
  }

  const allowedRootDetails =
    evidenceStorage?.allowed_root_details ??
    (evidenceStorage?.allowed_roots ?? []).map((path) => ({
      path,
      label: "Configured allowed evidence root",
      example_path: `${path.replace(/\/$/, "")}/case001`,
    }));

  const dashboardsUrlEntry = openSearchSettings.find((entry) => entry.name === "opensearch_dashboards_public_url");
  const dashboardsUrl = String(draftSettings.opensearch_dashboards_public_url ?? dashboardsUrlEntry?.effective_value ?? "");
  const derivedDashboardsUrl = API_BASE_URL.replace(/:8000\/api$/, ":5601");

  return (
    <div className="space-y-6">
      <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
        <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">System</p>
        <h2 className="mt-2 text-2xl font-semibold">System settings and deployment guidance</h2>
        <p className="mt-2 max-w-4xl text-sm text-muted">
          Runtime settings apply immediately to new requests and ingest work. Deployment settings require restart or redeploy. Mounted evidence import is shown here as deployment state, not as a misleading runtime toggle.
        </p>
        <div className="mt-5 flex flex-wrap gap-2" role="tablist" aria-label="System sections">
          {SECTION_LABELS.map((section) => (
            <button
              key={section.key}
              type="button"
              role="tab"
              aria-selected={activeSection === section.key}
              onClick={() => selectSection(section.key)}
              className={`rounded-full px-4 py-2 text-sm ${activeSection === section.key ? "bg-accent text-abyss" : "border border-line bg-panel/60 text-muted"}`}
            >
              {section.label}
            </button>
          ))}
        </div>
      </section>

      {pendingRestartScopes.length > 0 && manualRestartInfo ? (
        <section className="rounded-3xl border border-amber/40 bg-amber/10 p-5 shadow-panel">
          <p className="font-mono text-xs uppercase tracking-[0.18em] text-amber">Pending restart</p>
          <h3 className="mt-2 text-lg font-semibold">{manualRestartInfo.title}</h3>
          <p className="mt-2 text-sm text-muted">These settings were saved, but they will only become active after restarting the affected services.</p>
          <p className="mt-2 text-sm text-muted">{manualRestartInfo.description}</p>
          <p className="mt-3 text-sm text-muted">Affected services: <span className="text-ink">{manualRestartServices.join(", ") || "backend, worker"}</span></p>
          <p className="mt-3 text-sm text-muted">Run this on the server, from the Kairon DFIR deployment directory:</p>
          {pendingChangeSummary.length ? (
            <div className="mt-4 rounded-2xl border border-amber/30 bg-abyss/70 p-4">
              <p className="font-mono text-xs uppercase tracking-[0.16em] text-amber">What you still need to change now</p>
              <p className="mt-2 text-sm text-muted">A plain <span className="font-mono text-slate-200">docker compose restart</span> is not enough for these settings because the services are still running with the old deployment values.</p>
              <div className="mt-3 space-y-2 text-sm text-slate-200">
                {pendingChangeSummary.map((summary) => (
                  <p key={summary}>• {summary}</p>
                ))}
              </div>
            </div>
          ) : null}
          {deploymentDiagnostics.length ? (
            <div className="mt-4 space-y-4">
              <p className="font-mono text-xs uppercase tracking-[0.16em] text-accent">Why changes are still pending</p>
              {deploymentDiagnostics.map((item) => (
                <div key={item.setting_key} className="rounded-2xl border border-line bg-panel/70 p-4">
                  <p className="font-mono text-xs uppercase tracking-[0.16em] text-accent">{item.setting_name}</p>
                  <p className="mt-2 text-sm text-muted">{item.reason}</p>
                  <div className="mt-3 grid gap-2 text-sm text-muted md:grid-cols-2">
                    <p>Current: <span className="text-ink">{String(item.current_value)}</span></p>
                    <p>Expected: <span className="text-ink">{String(item.expected_value)}</span></p>
                    <p>Change in: <span className="text-ink">{item.change_location?.path ?? "deployment config"}</span></p>
                    <p>Variable: <span className="text-ink">{item.change_location?.variable ?? item.setting_key}</span></p>
                  </div>
                  {item.change_location?.compose_reference ? (
                    <p className="mt-2 text-xs text-slate-400">{item.change_location.compose_reference}</p>
                  ) : null}
                  <p className="mt-2 text-xs text-slate-400">What to change: {item.change_location?.type === "compose_scale" ? item.commands?.[0] ?? "docker compose up --scale ..." : `${item.change_location?.path ?? "deployment config"} → ${item.change_location?.variable ?? item.setting_key}`}</p>
                  <div className="mt-3 space-y-1 text-sm text-muted">
                    {item.steps?.map((step: string) => (
                      <p key={step}>• {step}</p>
                    ))}
                  </div>
                  {item.commands?.length ? (
                    <div className="mt-3 space-y-2">
                      {item.commands.map((command: string) => (
                        <pre key={command} className="overflow-x-auto rounded-xl bg-abyss/90 p-3 text-sm text-slate-200">{command}</pre>
                      ))}
                    </div>
                  ) : null}
                </div>
              ))}
            </div>
          ) : null}
          <div className="mt-4 space-y-4">
            {manualRestartInfo.commands.map((item) => (
              <div key={item.label} className="rounded-2xl border border-line bg-panel/70 p-4">
                <p className="font-mono text-xs uppercase tracking-[0.16em] text-accent">{item.label}</p>
                <pre className="mt-3 overflow-x-auto rounded-xl bg-abyss/90 p-3 text-sm text-slate-200">{item.command}</pre>
                <div className="mt-3 flex flex-wrap gap-3">
                  <button type="button" onClick={() => void copyCommand(item.command)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">
                    {item.label.toLowerCase().includes("rebuild") ? "Copy rebuild command" : "Copy restart command"}
                  </button>
                </div>
              </div>
            ))}
          </div>
          <div className="mt-4 space-y-2 text-sm text-muted">
            {manualRestartInfo.notes.map((note) => (
              <p key={note}>• {note}</p>
            ))}
          </div>
          <div className="mt-4 flex flex-wrap gap-3">
            <button type="button" onClick={() => void checkRestartStatus()} disabled={checkingRestart} className="rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss disabled:cursor-not-allowed disabled:opacity-60">
              {checkingRestart ? "Checking service status..." : "I restarted services, check status"}
            </button>
          </div>
          {restartStatusMessage ? <p className="mt-3 text-sm text-accent">{restartStatusMessage}</p> : null}
          {copyStatus ? <p className="mt-3 text-sm text-accent">{copyStatus}</p> : null}
        </section>
      ) : null}

      {activeSection === "overview" ? (
        <section className="space-y-6">
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
            <div className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
              <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Active profile</p>
              <p className="mt-3 text-2xl font-semibold">{data.profile}</p>
              <p className="mt-1 text-sm text-muted">draft profile {draftProfile}</p>
            </div>
            <div className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
              <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">CPU</p>
              <p className="mt-3 text-2xl font-semibold">{data.system.cpu_count} cores</p>
              <p className="mt-1 text-sm text-muted">{Math.round(data.system.cpu_percent)}% in use · container sees {resources?.effective_cpu_count ?? data.system.cpu_count_container ?? data.system.cpu_count} cores</p>
            </div>
            <div className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
              <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Memory</p>
              <p className="mt-3 text-2xl font-semibold">{formatBytes(data.system.memory_available_bytes)}</p>
              <p className="mt-1 text-sm text-muted">available of {formatBytes(data.system.memory_total_bytes)}</p>
              <p className="mt-1 text-xs text-muted">Host RAM {formatBytes(resources?.memory_host_total ?? data.system.memory_total_bytes)} · container visible RAM {formatBytes(resources?.memory_visible_total ?? data.system.memory_total_bytes)} · source {String(resources?.memory_limit_source ?? "unknown")}</p>
            </div>
            <div className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
              <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Disk</p>
              <p className="mt-3 text-2xl font-semibold">{formatBytes(data.system.disk_free_bytes)}</p>
              <p className="mt-1 text-sm text-muted">free of {formatBytes(data.system.disk_total_bytes)} · {diskUsedPercent.toFixed(0)}% used</p>
              <span className={`mt-3 inline-flex rounded-full border px-2 py-1 text-[11px] uppercase tracking-[0.14em] ${statusTone(diskStatus)}`}>{diskStatus}</span>
              {diskStatus !== "healthy" ? (
                <p className="mt-2 text-xs text-amber">Disk usage is high. Indexing may be blocked by OpenSearch watermarks.</p>
              ) : null}
            </div>
            <div className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
              <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">OpenSearch</p>
              <p className="mt-3 text-2xl font-semibold">{String(data.services.opensearch.cluster_status ?? data.services.opensearch.status ?? "unknown")}</p>
              <p className="mt-1 text-sm text-muted">heap {String(data.services.opensearch.heap_used_percent ?? "n/a")}% · watermark risk {openSearchWatermarkRisk}</p>
              <span className={`mt-3 inline-flex rounded-full border px-2 py-1 text-[11px] uppercase tracking-[0.14em] ${statusTone(openSearchWriteBlocked ? "critical" : openSearchWatermarkRisk)}`}>
                {openSearchWriteBlocked ? "write blocked" : openSearchIngestWritable === false ? "not writable" : "writable"}
              </span>
            </div>
          </div>

          <div className="grid gap-6 xl:grid-cols-2">
            <div className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
              <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Services</p>
              <div className="mt-4 space-y-3 text-sm text-muted">
                <p>Backend: {String(data.services.backend.status ?? "unknown")}</p>
                <p>Worker: {String(data.services.worker.status ?? "unknown")} · active {String(data.services.worker.active ?? 0)}</p>
                <p>Frontend: {String(data.services.frontend.status ?? "unknown")}</p>
                <p>OpenSearch: {String(data.services.opensearch.status ?? "unknown")}</p>
                <p>Disk guard: {diskStatus} · warning {diskWarningThreshold}% · critical {diskCriticalThreshold}%</p>
                <p>OpenSearch ingest writable: {openSearchIngestWritable === false ? "no" : "yes"} · watermark risk {openSearchWatermarkRisk}</p>
                <p>Ingest concurrency: desired {String(resources?.current_concurrency.desired_ingest_parallelism ?? resources?.current_concurrency.ingest_parallelism ?? 1)} · effective {String(resources?.current_concurrency.effective_ingest_parallelism ?? resources?.current_concurrency.ingest_parallelism ?? 1)}</p>
                {resources?.current_concurrency.ingest_parallelism_reason ? <p>Parallelism limit: {String(resources.current_concurrency.ingest_parallelism_reason)}</p> : null}
              </div>
              <p className="mt-4 text-xs text-muted">{resources?.memory_explanation}</p>
              <div className="mt-4 space-y-2 text-sm text-muted">
                {Object.entries(data.services.queues).map(([name, queue]) => (
                  <p key={name}>{name}: queued {queue.queued} · started {queue.started} · failed {queue.failed} · finished {queue.finished}</p>
                ))}
              </div>
            </div>

            <div className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
              <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Recommendation</p>
              <p className="mt-3 text-lg font-semibold">{recommendation.recommended_profile}</p>
              <p className="mt-2 text-xs uppercase tracking-[0.16em] text-muted">Why is this recommended?</p>
              <ul className="mt-3 space-y-2 text-sm text-muted">
                {recommendation.reasons.map((reason) => (
                  <li key={reason}>• {reason}</li>
                ))}
              </ul>
              {recommendation.warnings.length ? (
                <div className="mt-4 space-y-2 text-xs text-warning">
                  {recommendation.warnings.map((warning) => (
                    <p key={warning}>• {warning}</p>
                  ))}
                </div>
              ) : null}
              <div className="mt-4 flex flex-wrap gap-3">
                <button
                  type="button"
                  onClick={applyRecommendedProfile}
                  className="rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss"
                >
                  Apply recommended
                </button>
              </div>
            </div>
          </div>

          <div className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Pending changes</p>
                <p className="mt-2 text-sm text-muted">
                  Draft profile: <span className="text-ink">{draftProfile}</span> · Changed settings: <span className="text-ink">{pendingPreview.length}</span>
                </p>
              </div>
              <div className="flex flex-wrap gap-3">
                <button type="button" onClick={() => validateAndRun("save")} className="rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss">
                  Save settings
                </button>
                <button type="button" onClick={() => validateAndRun("apply")} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">
                  Apply now
                </button>
                <button type="button" onClick={resetDraft} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">
                  Revert pending changes
                </button>
              </div>
            </div>
            {pendingChanges.length ? (
              <div className="mt-4 grid gap-3 md:grid-cols-2">
                {pendingChanges.map((change) => (
                  <div key={`${change.key}-${String(change.newValue)}`} className="rounded-2xl border border-line bg-abyss/80 p-4 text-sm text-muted">
                    <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">{change.name}</p>
                    <p className="mt-2">Old value: <span className="text-white">{String(change.oldValue)}</span></p>
                    <p>New value: <span className="text-white">{String(change.newValue)}</span></p>
                    <p>Scope: <span className="text-white">{change.scope}</span></p>
                    <p>Status: <span className="text-white">{change.status}</span></p>
                    <RestartBadges services={change.services} />
                  </div>
                ))}
              </div>
            ) : (
              <p className="mt-4 text-sm text-muted">No local or staged pending changes.</p>
            )}
            {lastMessage ? <p className="mt-4 text-sm text-accent">{lastMessage}</p> : null}
          </div>

          <div className="flex flex-wrap gap-3">
            <button type="button" onClick={() => selectSection("advanced")} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">
              Open advanced settings
            </button>
            <button type="button" onClick={() => selectSection("evidence")} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">
              Review evidence storage
            </button>
          </div>
        </section>
      ) : null}

      {activeSection === "performance" ? (
        <section className="space-y-6">
          <div className="grid gap-4 xl:grid-cols-4">
            {([
              ["safe", "Safe", "Safe: slower but stable"],
              ["balanced", "Balanced", "Balanced: recommended"],
              ["performance", "Performance", "Performance: uses more CPU/RAM with safer limits than max"],
              ["max", "Max", "Max: uses more CPU/RAM and may affect responsiveness"],
              ["custom", "Custom", "Custom: tweak individual settings manually"],
            ] as Array<[ProfileName, string, string]>).map(([value, label, summary]) => (
              <button
                key={value}
                type="button"
                onClick={() => handleProfileSelect(value)}
                className={`rounded-3xl border p-5 text-left shadow-panel transition ${draftProfile === value ? "border-accent bg-accent/10" : "border-line bg-panel/70 hover:border-accent/50"}`}
              >
                <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">{label}</p>
                <p className="mt-3 text-lg font-semibold">{value === data.profile ? `${label} (active)` : label}</p>
                <p className="mt-2 text-sm text-muted">{summary}</p>
              </button>
            ))}
          </div>

          <div className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
            <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Runtime performance settings</p>
            <p className="mt-2 text-sm text-muted">These settings apply to future ingest jobs and search requests without restarting services.</p>
            <div className="mt-4 space-y-6">
              {(Object.entries(groupedPerformanceSettings) as Array<[PerformanceGroupKey, PerformanceSettingEntry[]]>)
                .filter(([, entries]) => entries.length > 0)
                .map(([groupKey, entries]) => (
                  <div key={groupKey}>
                    <p className="text-sm font-semibold text-ink">{PERFORMANCE_GROUP_LABELS[groupKey]}</p>
                    <div className="mt-3 grid gap-4 md:grid-cols-2 xl:grid-cols-3">
                      {entries.map((entry) => (
                        <SettingInput
                          key={entry.name}
                          entry={entry}
                          value={displayDraftValue(entry, draftSettings, data.effective_settings[entry.name])}
                          error={validationErrors[entry.name]}
                          onChange={updateDraft}
                        />
                      ))}
                    </div>
                  </div>
                ))}
            </div>
            <div className="mt-4 flex flex-wrap gap-3">
              <button type="button" onClick={() => validateAndRun("save")} className="rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss">
                Save
              </button>
              <button type="button" onClick={() => validateAndRun("apply")} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">
                Apply
              </button>
            </div>
          </div>
        </section>
      ) : null}

      {activeSection === "evidence" ? (
        <section className="space-y-6">
          <div className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Server-mounted evidence import</p>
                <p className="mt-3 text-xl font-semibold">{evidenceStorage?.allow_host_path_import ? "Enabled" : "Disabled"}</p>
                <p className="mt-2 max-w-3xl text-sm text-muted">
                  When enabled, Kairon DFIR can register evidence already mounted on the server without copying it. This does not allow reading arbitrary paths from the analyst browser machine.
                </p>
              </div>
              <div className={`rounded-2xl border px-4 py-3 text-sm ${evidenceStorage?.allow_host_path_import ? "border-mint/30 bg-mint/10 text-mint" : "border-warning/30 bg-warning/10 text-warning"}`}>
                Host path import enabled: {evidenceStorage?.allow_host_path_import ? "true" : "false"}
              </div>
            </div>

            {!evidenceStorage?.allow_host_path_import ? (
              <div className="mt-5 rounded-2xl border border-warning/30 bg-warning/10 p-4 text-sm text-warning">
                <p className="font-medium">Server-mounted path import is disabled.</p>
                <p className="mt-2">Upload from browser still works. To enable mounted paths, set DFIR_ALLOW_HOST_PATH_IMPORT=true and restart backend/worker.</p>
              </div>
            ) : null}

            <div className="mt-5 grid gap-4 md:grid-cols-2 xl:grid-cols-3">
              {allowedRootDetails.map((root) => (
                <EvidenceRootCard key={root.path} root={root} />
              ))}
            </div>

            <div className="mt-5 rounded-2xl border border-line bg-abyss/70 p-4 text-sm text-muted">
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Enable instructions</p>
              <div className="mt-3 grid gap-4 xl:grid-cols-2">
                <div>
                  <p className="text-xs uppercase tracking-[0.16em] text-muted">Environment</p>
                  <div className="mt-2 space-y-2 rounded-2xl border border-line bg-panel/40 p-3 font-mono text-xs text-slate-200">
                    {Object.entries(evidenceStorage?.enable_instructions?.env ?? {}).map(([key, value]) => (
                      <p key={key}>{key}={value}</p>
                    ))}
                  </div>
                </div>
                <div>
                  <p className="text-xs uppercase tracking-[0.16em] text-muted">Restart / redeploy</p>
                  <div className="mt-2 space-y-2 rounded-2xl border border-line bg-panel/40 p-3 font-mono text-xs text-slate-200">
                    {(evidenceStorage?.restart_commands ?? []).map((command) => (
                      <p key={command}>{command}</p>
                    ))}
                  </div>
                </div>
              </div>
            </div>

            <div className="mt-5 flex flex-wrap gap-3">
              <Link to="/cases" className="rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss">
                Open Evidence &amp; Ingest
              </Link>
              <button
                type="button"
                onClick={() =>
                  void navigator.clipboard?.writeText(
                    `DFIR_ALLOW_HOST_PATH_IMPORT=true\nDFIR_ALLOWED_EVIDENCE_ROOTS=${(evidenceStorage?.allowed_roots ?? []).join(",")}\ndocker compose up -d --build backend worker`,
                  )
                }
                className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted"
              >
                Copy enable instructions
              </button>
              <Link to="/cases" className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">
                Validate mounted path
              </Link>
            </div>
          </div>
        </section>
      ) : null}

      {activeSection === "branding" ? (
        <section className="space-y-6">
          <div className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
            <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Report branding</p>
            <div className="mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-3">
              {brandingSettings.length ? (
                brandingSettings.map((entry) => (
                  <SettingInput
                    key={entry.name}
                    entry={entry}
                    value={displayDraftValue(entry, draftSettings, data.effective_settings[entry.name])}
                    error={validationErrors[entry.name]}
                    onChange={updateDraft}
                  />
                ))
              ) : (
                <div className="rounded-2xl border border-line bg-abyss/80 p-4 text-sm text-muted">No report branding settings are exposed in this deployment.</div>
              )}
            </div>
            <div className="rounded-2xl border border-line bg-abyss/80 p-4">
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Preview</p>
              <div className="mt-3 rounded-2xl border border-line bg-panel/40 p-4">
                <p className="text-lg font-semibold">{String(draftSettings.report_brand_name ?? data.effective_settings.report_brand_name ?? "Kairon DFIR")}</p>
                <p className="mt-1 text-sm text-muted">{String(draftSettings.report_brand_subtitle ?? data.effective_settings.report_brand_subtitle ?? "Investigation report")}</p>
              </div>
            </div>
          </div>
        </section>
      ) : null}

      {activeSection === "opensearch" ? (
        <section className="space-y-6">
          <div className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
            <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">OpenSearch / Dashboards</p>
            <div className="mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
              <div className="rounded-2xl border border-line bg-abyss/80 p-4">
                <p className="text-xs uppercase tracking-[0.16em] text-muted">Health</p>
                <p className="mt-2 text-lg font-semibold">{String(data.services.opensearch.status ?? "unknown")}</p>
              </div>
              <div className="rounded-2xl border border-line bg-abyss/80 p-4">
                <p className="text-xs uppercase tracking-[0.16em] text-muted">Cluster</p>
                <p className="mt-2 text-lg font-semibold">{String(data.services.opensearch.cluster_status ?? "unknown")}</p>
              </div>
              <div className="rounded-2xl border border-line bg-abyss/80 p-4">
                <p className="text-xs uppercase tracking-[0.16em] text-muted">Heap</p>
                <p className="mt-2 text-lg font-semibold">{String(data.services.opensearch.heap_used_percent ?? "n/a")}%</p>
              </div>
              <div className="rounded-2xl border border-line bg-abyss/80 p-4">
                <p className="text-xs uppercase tracking-[0.16em] text-muted">Data view status</p>
                <p className="mt-2 text-lg font-semibold">Bootstrap ready</p>
              </div>
              <div className="rounded-2xl border border-line bg-abyss/80 p-4">
                <p className="text-xs uppercase tracking-[0.16em] text-muted">Write block</p>
                <p className="mt-2 text-lg font-semibold">{openSearchWriteBlocked ? "blocked" : "clear"}</p>
              </div>
              <div className="rounded-2xl border border-line bg-abyss/80 p-4">
                <p className="text-xs uppercase tracking-[0.16em] text-muted">Watermark risk</p>
                <p className="mt-2 text-lg font-semibold">{openSearchWatermarkRisk}</p>
              </div>
            </div>
            {openSearchWriteBlocked || openSearchWatermarkRisk === "medium" || openSearchWatermarkRisk === "high" ? (
              <div className="mt-4 rounded-2xl border border-amber/30 bg-amber/10 p-4 text-sm text-amber">
                Disk usage is high. Indexing may be blocked by OpenSearch watermarks.
                {openSearchBlockingReasons.length ? <span className="block text-xs text-muted">Reasons: {openSearchBlockingReasons.join(", ")}</span> : null}
              </div>
            ) : null}
            <div className="mt-4 grid gap-4 md:grid-cols-2">
              {openSearchSettings.map((entry) => (
                <SettingInput
                  key={entry.name}
                  entry={entry}
                  value={displayDraftValue(entry, draftSettings, data.effective_settings[entry.name])}
                  error={validationErrors[entry.name]}
                  onChange={updateDraft}
                />
              ))}
            </div>
            <div className="mt-4 flex flex-wrap gap-3">
              <a href={dashboardsUrl || derivedDashboardsUrl} target="_blank" rel="noreferrer" className="rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss">
                Open OpenSearch Console
              </a>
              <button type="button" className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">
                Bootstrap / Repair Data View
              </button>
            </div>
          </div>
        </section>
      ) : null}

      {activeSection === "deployment" ? (
        <section className="space-y-6">
          <div className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
            <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Deployment settings</p>
            <p className="mt-2 text-sm text-muted">These settings require restart or redeploy. They are not hot-applied.</p>
            <div className="mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-3">
              {deploymentSettings.map((entry) => (
                <SettingInput
                  key={entry.name}
                  entry={entry}
                  value={displayDraftValue(entry, draftSettings, entry.pending_value ?? entry.current_value)}
                  error={validationErrors[entry.name]}
                  onChange={updateDraft}
                />
              ))}
            </div>
          </div>
        </section>
      ) : null}

      {activeSection === "advanced" ? (
        <section className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Advanced settings</p>
              <p className="mt-2 text-sm text-muted">Advanced settings can affect ingest stability.</p>
            </div>
            <input
              value={advancedFilter}
              onChange={(event) => setAdvancedFilter(event.target.value)}
              placeholder="Filter advanced settings"
              className="w-full max-w-sm rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm"
            />
          </div>
          <div className="mt-4 space-y-6">
            {Object.entries(groupedAdvancedSettings).map(([group, entries]) => (
              <div key={group}>
                <p className="text-sm font-semibold capitalize text-ink">{group.replaceAll("_", " ")}</p>
                <div className="mt-3 grid gap-4 md:grid-cols-2 xl:grid-cols-3">
                  {entries.map((entry) => (
                    <SettingInput
                      key={entry.name}
                      entry={entry}
                      value={displayDraftValue(entry, draftSettings, entry.effective_value)}
                      error={validationErrors[entry.name]}
                      onChange={updateDraft}
                      title={entry.key}
                      technicalKey={entry.name}
                    />
                  ))}
                </div>
              </div>
            ))}
          </div>
        </section>
      ) : null}

      {data.system.warnings.length ? (
        <section className="rounded-3xl border border-amber/40 bg-amber/10 p-5 shadow-panel">
          <p className="font-mono text-xs uppercase tracking-[0.18em] text-amber">Resource warnings</p>
          <div className="mt-3 space-y-2 text-sm text-muted">
            {data.system.warnings.map((warning) => (
              <p key={warning}>• {warning}</p>
            ))}
          </div>
        </section>
      ) : null}

      <section className="rounded-3xl border border-line bg-panel/70 p-5 shadow-panel">
        <div className="grid gap-4 md:grid-cols-2">
          <div>
            <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">API base</p>
            <p className="mt-2 text-sm text-muted">{API_BASE_URL}</p>
          </div>
          <div>
            <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Build identity</p>
            {versionQuery.data ? (
              <div className="mt-2 space-y-1 text-sm text-muted">
                <p>
                  <span className="text-slate-300">Channel:</span> {versionQuery.data.build_channel}
                </p>
                <p>
                  <span className="text-slate-300">Vendor:</span> {versionQuery.data.vendor_id}
                </p>
                <p className="break-all">
                  <span className="text-slate-300">Fingerprint:</span> {versionQuery.data.build_fingerprint}
                </p>
                <p className="text-xs">{versionQuery.data.notice}</p>
              </div>
            ) : (
              <p className="mt-2 text-sm text-muted">Build metadata unavailable.</p>
            )}
          </div>
        </div>
      </section>
    </div>
  );
}
