import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { useParams, useSearchParams } from "react-router-dom";
import { api, type DfirCase, type EmailArtifactItem, type MotwItem, type StartupPersistenceItem } from "../api/client";
import CreateFindingDialog from "../components/CreateFindingDialog";
import DebugExportDialog from "../components/DebugExportDialog";
import EventTable, { type EventView } from "../components/EventTable";
import IndicatorResolutionPanel from "../components/IndicatorResolutionPanel";
import PaginationControls from "../components/PaginationControls";
import { useActiveCase } from "../context/ActiveCaseContext";
import { useTimezonePreference } from "../context/TimezoneContext";

const USER_ACTIVITY_TABS = [
  { value: "shellbag", label: "Shellbags" },
  { value: "userassist", label: "UserAssist" },
  { value: "recentdocs", label: "RecentDocs" },
  { value: "runmru", label: "RunMRU" },
  { value: "opensavemru", label: "OpenSaveMRU" },
];
const USER_ACTIVITY_TYPES = new Set(USER_ACTIVITY_TABS.map((item) => item.value));
const INTERNAL_ARTIFACT_TYPES_HIDDEN_FROM_MAIN = new Set(["registry_persistence"]);
const ARTIFACT_VIEW_LABELS: Record<string, string> = {
  amcache: "Amcache",
  appcompat: "Shimcache",
  autorun: "Autoruns",
  autoruns: "Autoruns",
  browser: "Browser History",
  cloud_sync: "Cloud Sync",
  defender: "Defender",
  email: "Email Artifacts",
  evtx: "Windows Events",
  jumplist: "Jump Lists",
  lnk: "LNK / Shortcuts",
  mft: "MFT / Filesystem",
  motw: "MOTW / Downloaded Files",
  network: "Network",
  powershell: "PowerShell",
  prefetch: "Prefetch",
  process: "Process / Execution",
  recentdocs: "RecentDocs",
  recycle_bin: "Recycle Bin",
  registry: "Registry",
  registry_command: "Registry Commands",
  registry_event: "Registry Events",
  scheduled_task: "Scheduled Tasks",
  scheduled_tasks: "Scheduled Tasks",
  service: "Services",
  services: "Services",
  shellbag: "Shellbags",
  shimcache: "Shimcache",
  srum: "SRUM",
  startup_persistence: "Startup & Persistence",
  usb: "USB",
  user_activity: "User Activity",
  userassist: "UserAssist",
  windows_event: "Windows Events",
  wmi: "WMI",
  zone_identifier: "MOTW / Downloaded Files",
};
const EZ_BACKENDS: Record<string, { tool: string; backend: string; note: string }> = {
  lnk: { tool: "LECmd", backend: "lecmd_csv", note: "Lower coverage on HOSTA benchmark, richer target and argument fields." },
  jumplist: { tool: "JLECmd", backend: "jlecmd_csv", note: "Lower coverage on HOSTA benchmark, richer AppId, MRU and target fields." },
  amcache: { tool: "AmcacheParser", backend: "amcacheparser_csv", note: "Richer path, hash, publisher and version fields." },
  shimcache: { tool: "AppCompatCacheParser", backend: "appcompatcacheparser_csv", note: "Richer path, order and timestamp fields." },
  appcompat: { tool: "AppCompatCacheParser", backend: "appcompatcacheparser_csv", note: "Richer path, order and timestamp fields." },
};

function riskLabel(score: number): string {
  if (score >= 70) return "High";
  if (score >= 40) return "Suspicious";
  return "Low";
}

function canonicalArtifactView(value: string | null | undefined): string {
  return value === "registry_persistence" ? "startup_persistence" : (value ?? "");
}

function artifactViewLabel(value: string): string {
  return ARTIFACT_VIEW_LABELS[value] ?? value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function StartupPersistenceView({
  data,
  loading,
  page,
  pageSize,
  onPageChange,
  onPageSizeChange,
  selectedItem,
  onSelectItem,
  indicatorData,
  onCreateFinding,
  onAddTimeline,
  timelinePending,
  timelineError,
  timelineSuccess,
}: {
  data?: Awaited<ReturnType<typeof api.getStartupPersistence>>;
  loading: boolean;
  page: number;
  pageSize: number;
  onPageChange: (page: number) => void;
  onPageSizeChange: (pageSize: number) => void;
  selectedItem: StartupPersistenceItem | null;
  onSelectItem: (item: StartupPersistenceItem | null) => void;
  indicatorData: Awaited<ReturnType<typeof api.resolveIndicators>> | null;
  onCreateFinding: (item: StartupPersistenceItem) => void;
  onAddTimeline: (item: StartupPersistenceItem) => void;
  timelinePending: boolean;
  timelineError: string;
  timelineSuccess: boolean;
}) {
  const items = data?.items ?? [];
  return (
    <div className="space-y-4">
      <section className="grid gap-3 md:grid-cols-4">
        <div className="rounded-2xl border border-line bg-panel/60 p-4">
          <p className="text-xs uppercase tracking-[0.16em] text-muted">Items</p>
          <p className="mt-1 text-2xl font-semibold">{data?.summary.total ?? 0}</p>
        </div>
        <div className="rounded-2xl border border-line bg-panel/60 p-4">
          <p className="text-xs uppercase tracking-[0.16em] text-muted">Suspicious</p>
          <p className="mt-1 text-2xl font-semibold text-amber-200">{data?.summary.suspicious ?? 0}</p>
        </div>
        <div className="rounded-2xl border border-line bg-panel/60 p-4">
          <p className="text-xs uppercase tracking-[0.16em] text-muted">High risk</p>
          <p className="mt-1 text-2xl font-semibold text-red-200">{data?.summary.high_risk ?? 0}</p>
        </div>
        <div className="rounded-2xl border border-line bg-panel/60 p-4">
          <p className="text-xs uppercase tracking-[0.16em] text-muted">WMI</p>
          <p className="mt-1 text-lg font-semibold">{data?.wmi_status ?? "not_present"}</p>
        </div>
      </section>
      {data?.warnings?.length ? (
        <section className="rounded-2xl border border-amber-400/30 bg-amber-500/10 p-4 text-sm text-amber-100">
          {data.warnings.slice(0, 3).map((warning) => <p key={warning}>{warning}</p>)}
        </section>
      ) : null}
      <PaginationControls page={page} totalPages={data?.total_pages ?? 0} total={data?.total ?? 0} pageSize={pageSize} onPageChange={onPageChange} onPageSizeChange={onPageSizeChange} />
      <section className="overflow-hidden rounded-[28px] border border-line bg-panel/60">
        <div className="border-b border-line px-5 py-4">
          <h3 className="text-lg font-semibold">Startup &amp; Persistence Items</h3>
          <p className="mt-1 text-sm text-muted">Risk reasons explain why an item is interesting. Benign OS locations are kept low risk unless suspicious behavior is present.</p>
        </div>
        {loading ? <p className="p-5 text-sm text-muted">Loading persistence sources...</p> : null}
        {!loading && !items.length ? <p className="p-5 text-sm text-muted">No startup or persistence items matched the current filters.</p> : null}
        {items.length ? (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-line text-sm">
              <thead className="bg-abyss/70 text-left text-xs uppercase tracking-[0.14em] text-muted">
                <tr>
                  <th className="px-4 py-3">Host</th>
                  <th className="px-4 py-3">Type</th>
                  <th className="px-4 py-3">Name</th>
                  <th className="px-4 py-3">Command / Target</th>
                  <th className="px-4 py-3">Risk</th>
                  <th className="px-4 py-3">Source</th>
                  <th className="px-4 py-3">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {items.map((item) => (
                  <tr key={item.id} className={selectedItem?.id === item.id ? "bg-accent/10" : "bg-panel/20"}>
                    <td className="px-4 py-3">{item.host || "-"}</td>
                    <td className="px-4 py-3">{item.type}</td>
                    <td className="px-4 py-3 font-medium text-ink">{item.name || "-"}</td>
                    <td className="max-w-[28rem] truncate px-4 py-3 text-muted" title={item.command_or_target || item.path || ""}>{item.command_or_target || item.path || "-"}</td>
                    <td className="px-4 py-3">
                      <span className={`rounded-full border px-2 py-1 text-xs ${item.risk_score >= 70 ? "border-red-300/40 bg-red-500/10 text-red-200" : item.risk_score >= 40 ? "border-amber-300/40 bg-amber-500/10 text-amber-100" : "border-line bg-abyss/80 text-muted"}`}>
                        {riskLabel(item.risk_score)} {item.risk_score}
                      </span>
                    </td>
                    <td className="px-4 py-3">{item.source_artifact || "-"}</td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-2">
                        <button type="button" onClick={() => onSelectItem(item)} className="rounded-lg border border-line px-2 py-1 text-xs text-muted hover:text-ink">Details</button>
                        {item.search_url ? <Link to={item.search_url} className="rounded-lg border border-line px-2 py-1 text-xs text-muted hover:text-ink">Open source evidence</Link> : null}
                        <button type="button" disabled={!item.source_event_id} onClick={() => onCreateFinding(item)} className="rounded-lg border border-line px-2 py-1 text-xs text-muted hover:text-ink disabled:opacity-40">Add to Finding</button>
                        <button type="button" disabled={!item.source_event_id || timelinePending} onClick={() => onAddTimeline(item)} className="rounded-lg border border-line px-2 py-1 text-xs text-muted hover:text-ink disabled:opacity-40">Add to Incident Timeline</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </section>
      {selectedItem ? (
        <section className="rounded-[28px] border border-line bg-panel/70 p-5">
          <div className="flex items-start justify-between gap-4">
            <div>
              <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Persistence detail</p>
              <h3 className="mt-1 text-xl font-semibold">{selectedItem.name}</h3>
              <p className="mt-2 text-sm text-muted">{selectedItem.command_or_target || selectedItem.path || "No command or target path captured."}</p>
            </div>
            <button type="button" onClick={() => onSelectItem(null)} className="rounded-lg border border-line px-3 py-2 text-sm text-muted">Close</button>
          </div>
          <div className="mt-4 grid gap-3 md:grid-cols-3">
            <div className="rounded-2xl border border-line bg-abyss/60 p-3 text-sm"><span className="text-muted">Enabled/start:</span> {String(selectedItem.enabled ?? selectedItem.start_type ?? "-")}</div>
            <div className="rounded-2xl border border-line bg-abyss/60 p-3 text-sm"><span className="text-muted">User:</span> {selectedItem.user || "-"}</div>
            <div className="rounded-2xl border border-line bg-abyss/60 p-3 text-sm"><span className="text-muted">First seen:</span> {selectedItem.first_seen || "-"}</div>
          </div>
          <div className="mt-4">
            <p className="text-sm font-medium">Risk reasons</p>
            <div className="mt-2 flex flex-wrap gap-2">
              {selectedItem.risk_reasons.map((reason) => <span key={reason} className="rounded-full border border-line bg-abyss/70 px-3 py-1 text-xs text-muted">{reason}</span>)}
            </div>
          </div>
          <div className="mt-4 flex flex-wrap gap-2">
            {selectedItem.search_url ? <Link to={selectedItem.search_url} className="rounded-xl border border-line bg-abyss/80 px-3 py-2 text-sm text-muted">Open source evidence</Link> : null}
            {selectedItem.timeline_url ? <Link to={selectedItem.timeline_url} className="rounded-xl border border-line bg-abyss/80 px-3 py-2 text-sm text-muted">Open Search around</Link> : null}
            <button type="button" disabled={!selectedItem.source_event_id} onClick={() => onCreateFinding(selectedItem)} className="rounded-xl border border-line bg-abyss/80 px-3 py-2 text-sm text-muted disabled:opacity-40">Add to Finding</button>
            <button type="button" disabled={!selectedItem.source_event_id || timelinePending} onClick={() => onAddTimeline(selectedItem)} className="rounded-xl border border-line bg-abyss/80 px-3 py-2 text-sm text-muted disabled:opacity-40">Add to Incident Timeline</button>
          </div>
          {timelineSuccess ? <p className="mt-3 text-sm text-emerald-300">Added as a key persistence event for timeline/report review.</p> : null}
          {timelineError ? <p className="mt-3 text-sm text-red-300">{timelineError}</p> : null}
          <div className="mt-5">
            <IndicatorResolutionPanel data={indicatorData} />
          </div>
        </section>
      ) : null}
    </div>
  );
}

function MotwArtifactView({
  data,
  loading,
  page,
  pageSize,
  onPageChange,
  onPageSizeChange,
  selectedItem,
  onSelectItem,
  indicatorData,
  onCreateFinding,
  onAddTimeline,
  timelinePending,
  timelineError,
  timelineSuccess,
}: {
  data?: Awaited<ReturnType<typeof api.getMotw>>;
  loading: boolean;
  page: number;
  pageSize: number;
  onPageChange: (page: number) => void;
  onPageSizeChange: (pageSize: number) => void;
  selectedItem: MotwItem | null;
  onSelectItem: (item: MotwItem | null) => void;
  indicatorData: Awaited<ReturnType<typeof api.resolveIndicators>> | null;
  onCreateFinding: (item: MotwItem) => void;
  onAddTimeline: (item: MotwItem) => void;
  timelinePending: boolean;
  timelineError: string;
  timelineSuccess: boolean;
}) {
  const items = data?.items ?? [];
  return (
    <div className="space-y-4">
      <section className="grid gap-3 md:grid-cols-4">
        <div className="rounded-2xl border border-line bg-panel/60 p-4">
          <p className="text-xs uppercase tracking-[0.16em] text-muted">MOTW items</p>
          <p className="mt-1 text-2xl font-semibold">{data?.summary.total ?? 0}</p>
        </div>
        <div className="rounded-2xl border border-line bg-panel/60 p-4">
          <p className="text-xs uppercase tracking-[0.16em] text-muted">Suspicious</p>
          <p className="mt-1 text-2xl font-semibold text-amber-200">{data?.summary.suspicious ?? 0}</p>
        </div>
        <div className="rounded-2xl border border-line bg-panel/60 p-4">
          <p className="text-xs uppercase tracking-[0.16em] text-muted">High risk</p>
          <p className="mt-1 text-2xl font-semibold text-red-200">{data?.summary.high_risk ?? 0}</p>
        </div>
        <div className="rounded-2xl border border-line bg-panel/60 p-4">
          <p className="text-xs uppercase tracking-[0.16em] text-muted">Internet zone</p>
          <p className="mt-1 text-2xl font-semibold">{data?.summary.by_zone?.["3"] ?? 0}</p>
        </div>
      </section>
      {data?.warnings?.length ? (
        <section className="rounded-2xl border border-amber-400/30 bg-amber-500/10 p-4 text-sm text-amber-100">
          {data.warnings.slice(0, 3).map((warning) => <p key={warning}>{warning}</p>)}
        </section>
      ) : null}
      <PaginationControls page={page} totalPages={data?.total_pages ?? 0} total={data?.total ?? 0} pageSize={pageSize} onPageChange={onPageChange} onPageSizeChange={onPageSizeChange} />
      <section className="overflow-hidden rounded-[28px] border border-line bg-panel/60">
        <div className="border-b border-line px-5 py-4">
          <h3 className="text-lg font-semibold">MOTW / Downloaded Files</h3>
          <p className="mt-1 text-sm text-muted">Normalizes Zone.Identifier ADS and Sysmon FileCreateStreamHash evidence without inventing HostUrl or ReferrerUrl when unavailable.</p>
        </div>
        {loading ? <p className="p-5 text-sm text-muted">Loading MOTW evidence...</p> : null}
        {!loading && !items.length ? <p className="p-5 text-sm text-muted">No MOTW / Zone.Identifier items matched the current filters.</p> : null}
        {items.length ? (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-line text-sm">
              <thead className="bg-abyss/70 text-left text-xs uppercase tracking-[0.14em] text-muted">
                <tr>
                  <th className="px-4 py-3">Host</th>
                  <th className="px-4 py-3">File</th>
                  <th className="px-4 py-3">Zone</th>
                  <th className="px-4 py-3">HostUrl</th>
                  <th className="px-4 py-3">ReferrerUrl</th>
                  <th className="px-4 py-3">Risk</th>
                  <th className="px-4 py-3">Source</th>
                  <th className="px-4 py-3">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {items.map((item) => (
                  <tr key={item.id} className={selectedItem?.id === item.id ? "bg-accent/10" : "bg-panel/20"}>
                    <td className="px-4 py-3">{item.host || "-"}</td>
                    <td className="max-w-[24rem] truncate px-4 py-3 font-medium text-ink" title={item.file_path}>{item.file_name || item.file_path || "-"}</td>
                    <td className="px-4 py-3">{item.zone_id ?? "-"} {item.zone_name}</td>
                    <td className="max-w-[18rem] truncate px-4 py-3 text-muted" title={item.host_url || ""}>{item.host_url || "-"}</td>
                    <td className="max-w-[18rem] truncate px-4 py-3 text-muted" title={item.referrer_url || ""}>{item.referrer_url || "-"}</td>
                    <td className="px-4 py-3">
                      <span className={`rounded-full border px-2 py-1 text-xs ${item.risk_score >= 70 ? "border-red-300/40 bg-red-500/10 text-red-200" : item.risk_score >= 40 ? "border-amber-300/40 bg-amber-500/10 text-amber-100" : "border-line bg-abyss/80 text-muted"}`}>
                        {riskLabel(item.risk_score)} {item.risk_score}
                      </span>
                    </td>
                    <td className="px-4 py-3">{item.source_artifact}</td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-2">
                        <button type="button" onClick={() => onSelectItem(item)} className="rounded-lg border border-line px-2 py-1 text-xs text-muted hover:text-ink">Details</button>
                        {item.linked?.base_file_search ? <Link to={item.linked.base_file_search} className="rounded-lg border border-line px-2 py-1 text-xs text-muted hover:text-ink">Find this file</Link> : null}
                        <button type="button" disabled={!item.source_event_id} onClick={() => onCreateFinding(item)} className="rounded-lg border border-line px-2 py-1 text-xs text-muted hover:text-ink disabled:opacity-40">Add to Finding</button>
                        <button type="button" disabled={!item.source_event_id || timelinePending} onClick={() => onAddTimeline(item)} className="rounded-lg border border-line px-2 py-1 text-xs text-muted hover:text-ink disabled:opacity-40">Add to Incident Timeline</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </section>
      {selectedItem ? (
        <section className="rounded-[28px] border border-line bg-panel/70 p-5">
          <div className="flex items-start justify-between gap-4">
            <div>
              <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">MOTW detail</p>
              <h3 className="mt-1 text-xl font-semibold">{selectedItem.file_name || selectedItem.file_path}</h3>
              <p className="mt-2 text-sm text-muted">{selectedItem.file_path || "Base file path unavailable."}</p>
              <p className="mt-1 text-xs text-muted">{selectedItem.zone_identifier_path}</p>
            </div>
            <button type="button" onClick={() => onSelectItem(null)} className="rounded-lg border border-line px-3 py-2 text-sm text-muted">Close</button>
          </div>
          <div className="mt-4 grid gap-3 md:grid-cols-3">
            <div className="rounded-2xl border border-line bg-abyss/60 p-3 text-sm"><span className="text-muted">Zone:</span> {selectedItem.zone_id ?? "-"} {selectedItem.zone_name}</div>
            <div className="rounded-2xl border border-line bg-abyss/60 p-3 text-sm"><span className="text-muted">Timestamp:</span> {selectedItem.timestamp || "-"}</div>
            <div className="rounded-2xl border border-line bg-abyss/60 p-3 text-sm"><span className="text-muted">Source:</span> {selectedItem.source_artifact}</div>
          </div>
          <div className="mt-4 grid gap-3 md:grid-cols-2">
            <div className="rounded-2xl border border-line bg-abyss/60 p-3 text-sm"><span className="text-muted">HostUrl:</span> {selectedItem.host_url || "Not available in indexed evidence"}</div>
            <div className="rounded-2xl border border-line bg-abyss/60 p-3 text-sm"><span className="text-muted">ReferrerUrl:</span> {selectedItem.referrer_url || "Not available in indexed evidence"}</div>
          </div>
          <div className="mt-4">
            <p className="text-sm font-medium">Risk reasons</p>
            <div className="mt-2 flex flex-wrap gap-2">
              {selectedItem.risk_reasons.map((reason) => <span key={reason} className="rounded-full border border-line bg-abyss/70 px-3 py-1 text-xs text-muted">{reason}</span>)}
            </div>
          </div>
          <div className="mt-4 flex flex-wrap gap-2">
            {selectedItem.linked?.base_file_search ? <Link to={selectedItem.linked.base_file_search} className="rounded-xl border border-line bg-abyss/80 px-3 py-2 text-sm text-muted">Find this file</Link> : null}
            {selectedItem.linked?.timeline_around ? <Link to={selectedItem.linked.timeline_around} className="rounded-xl border border-line bg-abyss/80 px-3 py-2 text-sm text-muted">View activity around this time</Link> : null}
            {selectedItem.linked?.browser_search ? <Link to={selectedItem.linked.browser_search} className="rounded-xl border border-line bg-abyss/80 px-3 py-2 text-sm text-muted">Open browser/download evidence</Link> : null}
            {selectedItem.linked?.user_activity_search ? <Link to={selectedItem.linked.user_activity_search} className="rounded-xl border border-line bg-abyss/80 px-3 py-2 text-sm text-muted">Open user activity</Link> : null}
            <button type="button" disabled={!selectedItem.source_event_id} onClick={() => onCreateFinding(selectedItem)} className="rounded-xl border border-line bg-abyss/80 px-3 py-2 text-sm text-muted disabled:opacity-40">Add to Finding</button>
            <button type="button" disabled={!selectedItem.source_event_id || timelinePending} onClick={() => onAddTimeline(selectedItem)} className="rounded-xl border border-line bg-abyss/80 px-3 py-2 text-sm text-muted disabled:opacity-40">Add to Incident Timeline</button>
          </div>
          {timelineSuccess ? <p className="mt-3 text-sm text-emerald-300">Added as a downloaded-file evidence event for timeline/report review.</p> : null}
          {timelineError ? <p className="mt-3 text-sm text-red-300">{timelineError}</p> : null}
          <div className="mt-5">
            <IndicatorResolutionPanel data={indicatorData} />
          </div>
        </section>
      ) : null}
    </div>
  );
}

function EmailArtifactsView({
  data,
  loading,
  page,
  pageSize,
  onPageChange,
  onPageSizeChange,
  selectedItem,
  onSelectItem,
  indicatorData,
  onCreateFinding,
  onAddTimeline,
  timelinePending,
  timelineError,
  timelineSuccess,
}: {
  data?: Awaited<ReturnType<typeof api.getEmailArtifacts>>;
  loading: boolean;
  page: number;
  pageSize: number;
  onPageChange: (page: number) => void;
  onPageSizeChange: (pageSize: number) => void;
  selectedItem: EmailArtifactItem | null;
  onSelectItem: (item: EmailArtifactItem | null) => void;
  indicatorData: Awaited<ReturnType<typeof api.resolveIndicators>> | null;
  onCreateFinding: (item: EmailArtifactItem) => void;
  onAddTimeline: (item: EmailArtifactItem) => void;
  timelinePending: boolean;
  timelineError: string;
  timelineSuccess: boolean;
}) {
  const items = data?.items ?? [];
  const directEmailItems = items.filter((item) => ["store", "message_file", "profile", "attachment_cache"].includes(String(item.email_artifact_type)));
  const webmailItems = items.filter((item) => item.email_artifact_type === "webmail_activity");
  const relatedDownloadItems = items.filter((item) => item.email_artifact_type === "related_email_download");
  const appPresenceItems = items.filter((item) => item.email_artifact_type === "app_presence");
  const relatedCount = (item: EmailArtifactItem) =>
    (item.related_downloads?.length ?? 0) + (item.related_motw?.length ?? 0) + (item.related_user_activity?.length ?? 0);
  const relatedMotw = selectedItem?.related_motw ?? [];
  return (
    <div className="space-y-4">
      <section className="grid gap-3 md:grid-cols-6">
        <div className="rounded-2xl border border-line bg-panel/60 p-4">
          <p className="text-xs uppercase tracking-[0.16em] text-muted">Email artifacts</p>
          <p className="mt-1 text-2xl font-semibold">{data?.summary.total ?? 0}</p>
        </div>
        <div className="rounded-2xl border border-line bg-panel/60 p-4">
          <p className="text-xs uppercase tracking-[0.16em] text-muted">Direct email</p>
          <p className="mt-1 text-2xl font-semibold">{directEmailItems.length}</p>
        </div>
        <div className="rounded-2xl border border-line bg-panel/60 p-4">
          <p className="text-xs uppercase tracking-[0.16em] text-muted">Webmail activity</p>
          <p className="mt-1 text-2xl font-semibold">{data?.summary.webmail_activity ?? 0}</p>
        </div>
        <div className="rounded-2xl border border-line bg-panel/60 p-4">
          <p className="text-xs uppercase tracking-[0.16em] text-muted">Related MOTW</p>
          <p className="mt-1 text-2xl font-semibold">{data?.summary.related_email_downloads ?? relatedDownloadItems.length}</p>
        </div>
        <div className="rounded-2xl border border-line bg-panel/60 p-4">
          <p className="text-xs uppercase tracking-[0.16em] text-muted">App presence</p>
          <p className="mt-1 text-2xl font-semibold">{data?.summary.app_presence ?? appPresenceItems.length}</p>
        </div>
        <div className="rounded-2xl border border-line bg-panel/60 p-4">
          <p className="text-xs uppercase tracking-[0.16em] text-muted">Advanced traces</p>
          <p className="mt-1 text-2xl font-semibold">{data?.summary.advanced_technical_traces ?? data?.summary.technical_traces ?? 0}</p>
        </div>
      </section>
      <section className="rounded-2xl border border-line bg-abyss/60 p-4 text-sm text-muted">
        <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Triage caveat</p>
        <p className="mt-2">Mail store presence does not prove malicious email content. OST/PST message content is not parsed in this version, and account hints are inferred from filenames or paths.</p>
        {data?.limitations?.slice(0, 3).map((limitation) => <p key={limitation} className="mt-1">{limitation}</p>)}
      </section>
      {data?.warnings?.length ? (
        <section className="rounded-2xl border border-amber-400/30 bg-amber-500/10 p-4 text-sm text-amber-100">
          {data.warnings.slice(0, 3).map((warning) => <p key={warning}>{warning}</p>)}
        </section>
      ) : null}
      <PaginationControls page={page} totalPages={data?.total_pages ?? 0} total={data?.total ?? 0} pageSize={pageSize} onPageChange={onPageChange} onPageSizeChange={onPageSizeChange} />
      <section className="overflow-hidden rounded-[28px] border border-line bg-panel/60">
        <div className="border-b border-line px-5 py-4">
          <h3 className="text-lg font-semibold">Email Artifacts</h3>
          <p className="mt-1 text-sm text-muted">Separates direct email artifacts, explicit webmail activity, and related MOTW/download evidence with a stated relationship.</p>
          <div className="mt-3 flex flex-wrap gap-2 text-xs text-muted">
            <span className="rounded-full border border-line px-2 py-1">Direct email artifacts: {directEmailItems.length}</span>
            <span className="rounded-full border border-line px-2 py-1">Webmail activity: {webmailItems.length}</span>
            <span className="rounded-full border border-line px-2 py-1">Related downloads/MOTW: {relatedDownloadItems.length}</span>
            <span className="rounded-full border border-line px-2 py-1">Windows Mail app presence: {appPresenceItems.length}</span>
            <span className="rounded-full border border-line px-2 py-1">Advanced technical traces hidden: {data?.summary.advanced_technical_traces ?? 0}</span>
          </div>
        </div>
        {loading ? <p className="p-5 text-sm text-muted">Loading email artifacts...</p> : null}
        {!loading && !items.length ? <p className="p-5 text-sm text-muted">No email artifacts matched the current filters. Attachment cache paths are treated as no data, not a parser failure.</p> : null}
        {items.length ? (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-line text-sm">
              <thead className="bg-abyss/70 text-left text-xs uppercase tracking-[0.14em] text-muted">
                <tr>
                  <th className="px-4 py-3">Host</th>
                  <th className="px-4 py-3">Type</th>
                  <th className="px-4 py-3">Client</th>
                  <th className="px-4 py-3">Account hint</th>
                  <th className="px-4 py-3">Path / URL</th>
                  <th className="px-4 py-3">Parsed</th>
                  <th className="px-4 py-3">Interest</th>
                  <th className="px-4 py-3">Related</th>
                  <th className="px-4 py-3">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {items.map((item) => (
                  <tr key={item.id} className={selectedItem?.id === item.id ? "bg-accent/10" : "bg-panel/20"}>
                    <td className="px-4 py-3">{item.host || "-"}</td>
                    <td className="px-4 py-3">{item.email_artifact_type}</td>
                    <td className="px-4 py-3">{item.client || "-"}</td>
                    <td className="px-4 py-3">{item.account_hint || "-"}</td>
                    <td className="max-w-[28rem] truncate px-4 py-3 text-muted" title={item.file_path || item.url || ""}>{item.file_path || item.url || item.file_name || "-"}</td>
                    <td className="px-4 py-3">{item.content_parsed ? "Parsed" : "Not parsed"}</td>
                    <td className="px-4 py-3">
                      <span className={`rounded-full border px-2 py-1 text-xs ${item.risk_score >= 70 ? "border-red-300/40 bg-red-500/10 text-red-200" : item.risk_score >= 40 ? "border-amber-300/40 bg-amber-500/10 text-amber-100" : "border-line bg-abyss/80 text-muted"}`}>
                        {riskLabel(item.risk_score)} {item.risk_score}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        {(item.related_downloads?.length ?? 0) ? <span className="rounded-full border border-line px-2 py-0.5 text-xs text-muted">downloads</span> : null}
                        {(item.related_motw?.length ?? 0) ? <span className="rounded-full border border-line px-2 py-0.5 text-xs text-muted">MOTW</span> : null}
                        {(item.related_user_activity?.length ?? 0) ? <span className="rounded-full border border-line px-2 py-0.5 text-xs text-muted">user activity</span> : null}
                        {!relatedCount(item) ? <span className="text-muted">-</span> : null}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-2">
                        <button type="button" onClick={() => onSelectItem(item)} className="rounded-lg border border-line px-2 py-1 text-xs text-muted hover:text-ink">Details</button>
                        {item.search_url ? <Link to={item.search_url} className="rounded-lg border border-line px-2 py-1 text-xs text-muted hover:text-ink">Resolve indicators</Link> : null}
                        {item.timeline_url ? <Link to={item.timeline_url} className="rounded-lg border border-line px-2 py-1 text-xs text-muted hover:text-ink">View activity around</Link> : null}
                        <button type="button" disabled={!item.source_event_id} onClick={() => onCreateFinding(item)} className="rounded-lg border border-line px-2 py-1 text-xs text-muted hover:text-ink disabled:opacity-40">Add to Finding</button>
                        <button type="button" disabled={!item.source_event_id || timelinePending} onClick={() => onAddTimeline(item)} className="rounded-lg border border-line px-2 py-1 text-xs text-muted hover:text-ink disabled:opacity-40">Add to Incident Timeline</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </section>
      {selectedItem ? (
        <section className="rounded-[28px] border border-line bg-panel/70 p-5">
          <div className="flex items-start justify-between gap-4">
            <div>
              <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Email artifact detail</p>
              <h3 className="mt-1 text-xl font-semibold">{selectedItem.account_hint || selectedItem.file_name || selectedItem.url || selectedItem.email_artifact_type}</h3>
              <p className="mt-2 text-sm text-muted">{selectedItem.file_path || selectedItem.url || "No file path or URL captured."}</p>
            </div>
            <button type="button" onClick={() => onSelectItem(null)} className="rounded-lg border border-line px-3 py-2 text-sm text-muted">Close</button>
          </div>
          <div className="mt-4 grid gap-3 md:grid-cols-3">
            <div className="rounded-2xl border border-line bg-abyss/60 p-3 text-sm"><span className="text-muted">Type:</span> {selectedItem.email_artifact_type}</div>
            <div className="rounded-2xl border border-line bg-abyss/60 p-3 text-sm"><span className="text-muted">Client:</span> {selectedItem.client || "-"}</div>
            <div className="rounded-2xl border border-line bg-abyss/60 p-3 text-sm"><span className="text-muted">Content parsed:</span> {selectedItem.content_parsed ? "yes" : "no"}</div>
          </div>
          {selectedItem.email_artifact_type === "store" ? (
            <div className="mt-4 rounded-2xl border border-amber-400/30 bg-amber-500/10 p-4 text-sm text-amber-100">
              Mail store detected. Message content is not parsed in this version. Use related downloads, MOTW, browser activity and user activity to build the demonstrable chain.
            </div>
          ) : null}
          <div className="mt-4">
            <p className="text-sm font-medium">Interest reasons</p>
            <div className="mt-2 flex flex-wrap gap-2">
              {selectedItem.risk_reasons.map((reason) => <span key={reason} className="rounded-full border border-line bg-abyss/70 px-3 py-1 text-xs text-muted">{reason}</span>)}
            </div>
          </div>
          <div className="mt-4 grid gap-3 md:grid-cols-3">
            <div className="rounded-2xl border border-line bg-abyss/60 p-3 text-sm">
              <span className="text-muted">Related downloads:</span> {selectedItem.related_downloads?.length ?? 0}
            </div>
            <div className="rounded-2xl border border-line bg-abyss/60 p-3 text-sm">
              <span className="text-muted">Related MOTW:</span> {selectedItem.related_motw?.length ?? 0}
            </div>
            <div className="rounded-2xl border border-line bg-abyss/60 p-3 text-sm">
              <span className="text-muted">Related user activity:</span> {selectedItem.related_user_activity?.length ?? 0}
            </div>
          </div>
          {selectedItem.email_artifact_type === "related_email_download" && selectedItem.relation_reason ? (
            <div className="mt-4 rounded-2xl border border-line bg-abyss/60 p-4 text-sm">
              <p className="font-medium">Relation reason</p>
              <p className="mt-1 text-muted">{selectedItem.relation_reason}</p>
              <p className="mt-2 text-xs text-muted">Confidence: {selectedItem.confidence || "unknown"}</p>
            </div>
          ) : null}
          {relatedMotw.length ? (
            <div className="mt-4 rounded-2xl border border-line bg-abyss/60 p-4 text-sm">
              <p className="font-medium">Related downloads/MOTW</p>
              <div className="mt-3 space-y-2">
                {relatedMotw.map((entry) => (
                  <div key={String(entry.id ?? entry.label)} className="rounded-xl border border-line bg-panel/30 p-3">
                    <p>{String(entry.label ?? entry.id ?? "MOTW")}</p>
                    <p className="mt-1 text-muted">{String(entry.relation_reason ?? "No relation reason captured.")}</p>
                    <p className="mt-1 text-xs text-muted">Confidence: {String(entry.confidence ?? "unknown")}</p>
                  </div>
                ))}
              </div>
            </div>
          ) : null}
          <div className="mt-4 flex flex-wrap gap-2">
            {selectedItem.search_url ? <Link to={selectedItem.search_url} className="rounded-xl border border-line bg-abyss/80 px-3 py-2 text-sm text-muted">Resolve indicators</Link> : null}
            {selectedItem.timeline_url ? <Link to={selectedItem.timeline_url} className="rounded-xl border border-line bg-abyss/80 px-3 py-2 text-sm text-muted">View activity around this time</Link> : null}
            <button type="button" disabled={!selectedItem.source_event_id} onClick={() => onCreateFinding(selectedItem)} className="rounded-xl border border-line bg-abyss/80 px-3 py-2 text-sm text-muted disabled:opacity-40">Add to Finding</button>
            <button type="button" disabled={!selectedItem.source_event_id || timelinePending} onClick={() => onAddTimeline(selectedItem)} className="rounded-xl border border-line bg-abyss/80 px-3 py-2 text-sm text-muted disabled:opacity-40">Add to Incident Timeline</button>
          </div>
          {timelineSuccess ? <p className="mt-3 text-sm text-emerald-300">Added as email/download triage evidence for timeline/report review.</p> : null}
          {timelineError ? <p className="mt-3 text-sm text-red-300">{timelineError}</p> : null}
          <div className="mt-5">
            <IndicatorResolutionPanel data={indicatorData} />
          </div>
        </section>
      ) : null}
    </div>
  );
}

export default function ArtifactExplorer() {
  const { caseId: routeCaseId } = useParams();
  const [searchParams] = useSearchParams();
  const { activeCaseId, selectedEvidenceId, selectedHost, setActiveCaseId } = useActiveCase();
  const { effectiveTimezone } = useTimezonePreference();
  const queryClient = useQueryClient();
  const [caseId, setCaseId] = useState(routeCaseId || activeCaseId);
  const [artifactType, setArtifactType] = useState(canonicalArtifactView(searchParams.get("artifact_type")));
  const [artifactName, setArtifactName] = useState("");
  const [query, setQuery] = useState(searchParams.get("q") ?? "");
  const [searchMode, setSearchMode] = useState<"smart" | "contains" | "ioc">("smart");
  const [mftDeletedOnly, setMftDeletedOnly] = useState(false);
  const [mftSuspiciousPathsOnly, setMftSuspiciousPathsOnly] = useState(false);
  const [mftExtension, setMftExtension] = useState("");
  const [backendVariant, setBackendVariant] = useState<"default" | "advanced" | "all">((searchParams.get("backend_variant") as "default" | "advanced" | "all") || "default");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [selectedEventIds, setSelectedEventIds] = useState<string[]>([]);
  const [findingDialogOpen, setFindingDialogOpen] = useState(false);
  const [persistenceFindingEventIds, setPersistenceFindingEventIds] = useState<string[]>([]);
  const [selectedPersistenceItem, setSelectedPersistenceItem] = useState<StartupPersistenceItem | null>(null);
  const [selectedMotwItem, setSelectedMotwItem] = useState<MotwItem | null>(null);
  const [selectedEmailItem, setSelectedEmailItem] = useState<EmailArtifactItem | null>(null);
  const [persistenceSuspiciousOnly, setPersistenceSuspiciousOnly] = useState(searchParams.get("suspicious_only") === "true");
  const [persistenceType, setPersistenceType] = useState("");
  const [persistenceSource, setPersistenceSource] = useState("");
  const [persistenceRiskMin, setPersistenceRiskMin] = useState("");
  const [motwZoneId, setMotwZoneId] = useState("");
  const [motwExtension, setMotwExtension] = useState("");
  const [motwRiskMin, setMotwRiskMin] = useState("");
  const [emailType, setEmailType] = useState("");
  const [emailClient, setEmailClient] = useState("");
  const [emailInterestingOnly, setEmailInterestingOnly] = useState(searchParams.get("interesting_only") === "true");
  const [emailRiskMin, setEmailRiskMin] = useState("");
  const [debugExportOpen, setDebugExportOpen] = useState(false);
  const [debugExportScope, setDebugExportScope] = useState<"artifact_type" | "selected_events">("artifact_type");
  const evidenceIdFilter = searchParams.get("evidence_id") || selectedEvidenceId;
  const hostFilter = searchParams.get("host") || selectedHost;
  const casesQuery = useQuery({ queryKey: ["cases"], queryFn: api.listCases });
  const facetsQuery = useQuery({ queryKey: ["artifact-explorer-facets", caseId], queryFn: () => api.searchFacets({ caseId: caseId || undefined }) });
  const artifactTypeOptions = Object.keys(facetsQuery.data?.["artifact.type"] ?? {});
  const artifactTypeSelectOptions = useMemo(() => {
    const options = new Set(artifactTypeOptions.filter((option) => !INTERNAL_ARTIFACT_TYPES_HIDDEN_FROM_MAIN.has(option)));
    options.add("startup_persistence");
    options.add("motw");
    options.add("email");
    return Array.from(options).sort((left, right) => artifactViewLabel(left).localeCompare(artifactViewLabel(right)));
  }, [artifactTypeOptions]);
  const artifactNameOptions = Object.keys(facetsQuery.data?.["artifact.name"] ?? {});
  const view: EventView =
    artifactType === "mft" || artifactType === "usn"
      ? "filesystem"
      : artifactType === "evtx"
        ? "evtx"
        : artifactType === "amcache" || artifactType === "shimcache" || artifactType === "appcompat"
          ? "execution_artifacts"
        : artifactType === "srum"
          ? "srum"
        : artifactType === "defender"
          ? "defender"
        : artifactType === "powershell"
          ? "powershell"
        : artifactType === "recycle_bin"
          ? "recycle_bin"
        : artifactType === "shellbags" || artifactType === "shellbag"
          ? "shellbags"
        : artifactType === "jumplist"
          ? "jumplist"
        : artifactType === "usb"
          ? "usb"
        : artifactType === "bits"
          ? "bits"
        : artifactType === "wmi"
          ? "wmi"
        : artifactType === "autoruns" || artifactType === "autorun"
          ? "autoruns"
        : artifactType === "cloud_sync"
          ? "cloud_sync"
        : artifactType === "registry" || artifactType === "registry_event" || artifactType === "registry_command"
          ? "registry"
          : artifactType === "browser"
            ? "browser"
            : artifactType === "network"
              ? "network"
              : artifactType === "process" || artifactType === "prefetch"
                ? "execution"
                : artifactType === "services" || artifactType === "scheduled_tasks" || artifactType === "scheduled_task"
                  ? "persistence"
                  : "auto";
  const payload = useMemo(
    () => ({
      case_id: caseId || undefined,
      query: query || "*",
      search_mode: searchMode,
        filters: {
          artifact_type: artifactType ? [artifactType] : [],
          artifact_name: artifactName ? [artifactName] : [],
          deleted_only: mftDeletedOnly || undefined,
          suspicious_paths_only: mftSuspiciousPathsOnly || undefined,
          extension: mftExtension ? [mftExtension.startsWith(".") ? mftExtension.toLowerCase() : `.${mftExtension.toLowerCase()}`] : [],
          backend_variant: backendVariant === "advanced" ? ["advanced"] : backendVariant === "all" ? ["all"] : [],
        evidence_id: evidenceIdFilter ? [evidenceIdFilter] : [],
        host: hostFilter ? [hostFilter] : [],
      },
      timezone: effectiveTimezone,
      page,
      page_size: pageSize,
    }),
    [artifactName, artifactType, backendVariant, caseId, effectiveTimezone, page, pageSize, query, searchMode, evidenceIdFilter, hostFilter, mftDeletedOnly, mftExtension, mftSuspiciousPathsOnly],
  );
  const isStartupPersistenceView = artifactType === "startup_persistence";
  const isMotwView = artifactType === "motw" || artifactType === "zone_identifier";
  const isEmailView = artifactType === "email" || artifactType === "email_store" || artifactType === "webmail_activity";
  const result = useQuery({ queryKey: ["artifact-explorer", payload], queryFn: () => api.search(payload), enabled: !isStartupPersistenceView && !isMotwView && !isEmailView });
  const persistenceQuery = useQuery({
    queryKey: ["startup-persistence", caseId, hostFilter, query, persistenceType, persistenceSource, persistenceSuspiciousOnly, persistenceRiskMin, page, pageSize],
    queryFn: () =>
      api.getStartupPersistence(caseId!, {
        host: hostFilter ? [hostFilter] : undefined,
        q: query || undefined,
        type: persistenceType ? [persistenceType] : undefined,
        source: persistenceSource ? [persistenceSource] : undefined,
        suspicious_only: persistenceSuspiciousOnly,
        risk_min: persistenceRiskMin ? Number(persistenceRiskMin) : undefined,
        page,
        page_size: pageSize,
      }),
    enabled: Boolean(caseId && isStartupPersistenceView),
  });
  const persistenceIndicatorQuery = useQuery({
    queryKey: ["startup-persistence-indicators", caseId, selectedPersistenceItem?.id],
    queryFn: () =>
      api.resolveIndicators(caseId!, {
        indicators: selectedPersistenceItem?.indicator_resolution ?? [],
        context: {
          host: selectedPersistenceItem?.host,
          evidence_id: selectedPersistenceItem?.evidence_id,
          timestamp: selectedPersistenceItem?.first_seen,
        },
      }),
    enabled: Boolean(caseId && selectedPersistenceItem && (selectedPersistenceItem.indicator_resolution?.length ?? 0) > 0),
  });
  const motwQuery = useQuery({
    queryKey: ["motw", caseId, hostFilter, query, motwZoneId, motwExtension, motwRiskMin, page, pageSize],
    queryFn: () =>
      api.getMotw(caseId!, {
        host: hostFilter ? [hostFilter] : undefined,
        q: query || undefined,
        zone_id: motwZoneId ? [Number(motwZoneId)] : undefined,
        extension: motwExtension ? [motwExtension] : undefined,
        risk_min: motwRiskMin ? Number(motwRiskMin) : undefined,
        page,
        page_size: pageSize,
      }),
    enabled: Boolean(caseId && isMotwView),
  });
  const motwIndicatorQuery = useQuery({
    queryKey: ["motw-indicators", caseId, selectedMotwItem?.id],
    queryFn: () =>
      api.resolveIndicators(caseId!, {
        indicators: selectedMotwItem?.indicator_resolution ?? [],
        context: {
          host: selectedMotwItem?.host,
          evidence_id: selectedMotwItem?.evidence_id,
          timestamp: selectedMotwItem?.timestamp,
        },
      }),
    enabled: Boolean(caseId && selectedMotwItem && (selectedMotwItem.indicator_resolution?.length ?? 0) > 0),
  });
  const emailQuery = useQuery({
    queryKey: ["email-artifacts", caseId, hostFilter, query, emailType, emailClient, emailInterestingOnly, emailRiskMin, page, pageSize],
    queryFn: () =>
      api.getEmailArtifacts(caseId!, {
        host: hostFilter ? [hostFilter] : undefined,
        q: query || undefined,
        artifact_type: emailType ? [emailType] : undefined,
        client: emailClient ? [emailClient] : undefined,
        interesting_only: emailInterestingOnly,
        risk_min: emailRiskMin ? Number(emailRiskMin) : undefined,
        page,
        page_size: pageSize,
      }),
    enabled: Boolean(caseId && isEmailView),
  });
  const emailIndicatorQuery = useQuery({
    queryKey: ["email-artifact-indicators", caseId, selectedEmailItem?.id],
    queryFn: () =>
      api.resolveIndicators(caseId!, {
        indicators: selectedEmailItem?.related_indicators ?? [],
        context: {
          host: selectedEmailItem?.host,
          evidence_id: selectedEmailItem?.evidence_id,
          timestamp: selectedEmailItem?.timestamp,
        },
      }),
    enabled: Boolean(caseId && selectedEmailItem && (selectedEmailItem.related_indicators?.length ?? 0) > 0),
  });
  const addPersistenceTimeline = useMutation({
    mutationFn: async (item: StartupPersistenceItem) => {
      if (!caseId || !item.source_event_id) throw new Error("This item does not have a source event to add.");
      return api.createTimelineKeyEvent(caseId, {
        event_id: item.source_event_id,
        note: `Startup & Persistence: ${item.type} ${item.name}`,
        category: "persistence",
        importance: item.risk_score >= 70 ? "critical" : item.risk_score >= 40 ? "high" : "medium",
        include_in_report: true,
      });
    },
  });
  const addMotwTimeline = useMutation({
    mutationFn: async (item: MotwItem) => {
      if (!caseId || !item.source_event_id) throw new Error("This item does not have a source event to add.");
      return api.createTimelineKeyEvent(caseId, {
        event_id: item.source_event_id,
        note: `MOTW / Downloaded file: ${item.file_name || item.file_path}`,
        category: "download",
        importance: item.risk_score >= 70 ? "critical" : item.risk_score >= 40 ? "high" : "medium",
        include_in_report: true,
      });
    },
  });
  const addEmailTimeline = useMutation({
    mutationFn: async (item: EmailArtifactItem) => {
      if (!caseId || !item.source_event_id) throw new Error("This item does not have a source event to add.");
      return api.createTimelineKeyEvent(caseId, {
        event_id: item.source_event_id,
        note: `Email artifact triage: ${item.email_artifact_type} ${item.account_hint || item.file_name || item.url || ""}`.trim(),
        category: item.email_artifact_type === "webmail_activity" ? "download" : "other",
        importance: item.risk_score >= 70 ? "critical" : item.risk_score >= 40 ? "high" : "medium",
        include_in_report: true,
      });
    },
  });
  const ezConfig = EZ_BACKENDS[artifactType];
  const ezRebuild = useMutation({
    mutationFn: async () => {
      if (!evidenceIdFilter || !artifactType || !ezConfig) {
        throw new Error("Select an evidence and supported artifact type first.");
      }
      return api.rebuildEvidenceCoreEzArtifact(evidenceIdFilter, artifactType === "appcompat" ? "shimcache" : artifactType, { force: true });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["artifact-explorer"] });
    },
  });
  const siemLinksQuery = useQuery({
    queryKey: ["artifact-explorer-siem-links", caseId, artifactType, query],
    queryFn: () =>
      api.siemExternalLinks({
        case_id: caseId || undefined,
        artifact_type: artifactType || undefined,
        query: query || undefined,
      }),
    staleTime: 15_000,
    refetchOnWindowFocus: false,
  });

  useEffect(() => {
    setPage(1);
  }, [artifactName, artifactType, backendVariant, caseId, pageSize, query, searchMode, persistenceType, persistenceSource, persistenceSuspiciousOnly, persistenceRiskMin, motwZoneId, motwExtension, motwRiskMin, emailType, emailClient, emailInterestingOnly, emailRiskMin]);

  const contextualPlaceholder =
    artifactType === "mft" || artifactType === "usn"
      ? "Search file name, path, extension..."
      : isMotwView
        ? "Search downloaded file, Zone.Identifier, HostUrl or domain..."
      : isEmailView
        ? "Search mail store, account hint, webmail URL, attachment cache..."
      : artifactType === "evtx"
        ? "Search EventID, provider, user, process..."
        : artifactType === "amcache" || artifactType === "shimcache" || artifactType === "appcompat"
          ? "Search path, hash, publisher, product..."
          : artifactType === "registry"
            ? "Search key, value, data..."
            : artifactType === "browser"
              ? "Search URL, domain, title..."
              : artifactType === "srum"
                ? "Search app, path, SID, interface..."
                : artifactType === "defender"
                  ? "Search threat, path, hash, action..."
                  : artifactType === "powershell"
                    ? "Search command, decoded preview, URL, path..."
                    : artifactType === "recycle_bin"
                      ? "Search original path, filename, SID, pair id..."
                      : artifactType === "shellbags"
                        ? "Search path, UNC host, user, shell type..."
                          : artifactType === "jumplist"
                            ? "Search app id, app name, path, filename, arguments..."
                          : artifactType === "usb"
                            ? "Search serial, vendor, product, device instance id, drive letter..."
                          : artifactType === "bits"
                            ? "Search job id, URL, local path, owner, notify command..."
                          : artifactType === "wmi"
                            ? "Search filter name, consumer name, namespace, WQL query, command, script..."
                          : artifactType === "autoruns" || artifactType === "autorun"
                            ? "Search entry, mechanism, image path, publisher, signer, hash..."
                          : artifactType === "cloud_sync"
                            ? "Search provider, account, sync root, local path, cloud path, status..."
                    : USER_ACTIVITY_TYPES.has(artifactType)
                      ? "Search path, filename, command, program or user..."
                      : "Search within selected artifact";

  useEffect(() => {
    setCaseId((current) => current || activeCaseId);
  }, [activeCaseId]);

  useEffect(() => {
    if (routeCaseId) {
      setActiveCaseId(routeCaseId);
      setCaseId(routeCaseId);
    }
  }, [routeCaseId, setActiveCaseId]);

  return (
    <div className="space-y-6">
      <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
        <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">Case Workspace</p>
        <h2 className="mt-2 text-2xl font-semibold">Artifact Views</h2>
        <p className="mt-2 text-sm text-muted">Open focused views for parsed artifact families. Use Search for global investigation across all data.</p>
        <div className="mt-4 rounded-2xl border border-line bg-abyss/50 p-4 text-sm text-muted">
          <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">When to use this view</p>
          <p className="mt-2">Use Artifact Views when you want a focused investigation inside one artifact family such as EVTX, Prefetch, LNK, Registry or MFT/Filesystem, with columns adapted to that source.</p>
          {caseId ? (
            <p className="mt-2">
              For cross-artifact queries, use{" "}
              <Link to={`/cases/${caseId}/search`} className="text-accent underline underline-offset-4">
                Search
              </Link>
              .
            </p>
          ) : null}
          <p className="mt-2">
            Looking to upload evidence?{" "}
            {caseId ? (
              <Link to={`/cases/${caseId}/evidence`} className="text-accent underline underline-offset-4">
                Go to Evidence &amp; Ingest
              </Link>
            ) : (
              <span className="text-accent">Go to Evidence &amp; Ingest</span>
            )}
            .
          </p>
        </div>
        {!caseId ? <p className="mt-2 text-sm text-amber-300">Artifact Views are available after selecting a case.</p> : null}
        {hostFilter || evidenceIdFilter ? (
          <div className="mt-3 flex flex-wrap gap-2 text-xs text-muted">
            <span className="rounded-full border border-line bg-abyss/70 px-3 py-1.5">{hostFilter ? `Host filter: ${hostFilter}` : "Host filter: all hosts"}</span>
            <span className="rounded-full border border-line bg-abyss/70 px-3 py-1.5">{evidenceIdFilter ? `Evidence filter: ${evidenceIdFilter.slice(0, 8)}` : "Evidence filter: all evidence"}</span>
          </div>
        ) : null}
        <div className="mt-5 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <select value={caseId} onChange={(event) => setCaseId(event.target.value)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm">
            <option value="">All cases</option>
            {(casesQuery.data ?? []).map((item: DfirCase) => <option key={item.id} value={item.id}>{item.name}</option>)}
          </select>
          <select aria-label="Artifact view" value={artifactType} onChange={(event) => setArtifactType(canonicalArtifactView(event.target.value))} className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm">
            <option value="">All artifact types</option>
            {artifactTypeSelectOptions.map((option) => <option key={option} value={option}>{artifactViewLabel(option)}</option>)}
          </select>
          <select value={artifactName} onChange={(event) => setArtifactName(event.target.value)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm">
            <option value="">All artifact names</option>
            {artifactNameOptions.map((option) => <option key={option} value={option}>{option}</option>)}
          </select>
          <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder={contextualPlaceholder} className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm" />
          <select value={searchMode} onChange={(event) => setSearchMode(event.target.value as "smart" | "contains" | "ioc")} className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm">
            <option value="smart">smart</option>
            <option value="contains">contains</option>
            <option value="ioc">ioc</option>
          </select>
          <select value={backendVariant} onChange={(event) => setBackendVariant(event.target.value as "default" | "advanced" | "all")} className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm">
            <option value="default">Default backend</option>
            <option value="advanced">EZ advanced only</option>
            <option value="all">Compare all backends</option>
          </select>
          <a href={siemLinksQuery.data?.discover_url || "#"} target="_blank" rel="noreferrer" className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-center text-sm text-muted">
            Open selected artifact in OpenSearch
          </a>
          <button disabled={!caseId || !selectedEventIds.length} onClick={() => setFindingDialogOpen(true)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm text-muted disabled:opacity-50">
            Create Finding from selected events
          </button>
          <button disabled={!caseId} onClick={() => { setDebugExportScope("artifact_type"); setDebugExportOpen(true); }} className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm text-muted disabled:opacity-50">
            Export artifact debug pack
          </button>
          <button disabled={!caseId || !selectedEventIds.length} onClick={() => { setDebugExportScope("selected_events"); setDebugExportOpen(true); }} className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm text-muted disabled:opacity-50">
            Export selected events debug pack
          </button>
        </div>
        {artifactType === "mft" ? (
          <div className="mt-4 rounded-2xl border border-line bg-abyss/50 p-4">
            <div className="flex flex-wrap items-center gap-3">
              <span className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">MFT filters</span>
              <label className="flex items-center gap-2 text-sm text-muted">
                <input type="checkbox" checked={mftDeletedOnly} onChange={(event) => setMftDeletedOnly(event.target.checked)} />
                Deleted files
              </label>
              <label className="flex items-center gap-2 text-sm text-muted">
                <input type="checkbox" checked={mftSuspiciousPathsOnly} onChange={(event) => setMftSuspiciousPathsOnly(event.target.checked)} />
                Temp/Public/AppData/Startup
              </label>
              <input value={mftExtension} onChange={(event) => setMftExtension(event.target.value)} placeholder=".ps1, .exe, .dll" className="rounded-xl border border-line bg-abyss/80 px-3 py-2 text-sm" />
              {caseId ? (
                <Link
                  to={`/cases/${caseId}/search?artifact_type=mft${evidenceIdFilter ? `&evidence_id=${encodeURIComponent(evidenceIdFilter)}` : ""}${hostFilter ? `&host=${encodeURIComponent(hostFilter)}` : ""}${query ? `&q=${encodeURIComponent(query)}` : ""}`}
                  className="rounded-xl border border-line bg-panel px-3 py-2 text-sm text-ink"
                >
                  Open matching documents in Search
                </Link>
              ) : null}
            </div>
          </div>
        ) : null}
        {artifactType === "prefetch" ? (
          <div className="mt-4 rounded-2xl border border-amber-400/30 bg-amber-500/10 p-4 text-sm text-amber-100">
            <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-amber-200">Prefetch backend</p>
            <p className="mt-2">Internal prefetch_raw is active. PECmd is installed, but raw .pf parsing on this Linux runtime requires Windows decompression support, so the advanced PECmd rebuild action is disabled.</p>
          </div>
        ) : null}
        {ezConfig ? (
          <div className="mt-4 rounded-2xl border border-line bg-abyss/50 p-4">
            <div className="flex flex-wrap items-center gap-3">
              <span className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Backend</span>
              <span className="rounded-full border border-line bg-panel px-3 py-1.5 text-xs text-muted">Internal default</span>
              <span className="rounded-full border border-accent/40 bg-accent/10 px-3 py-1.5 text-xs text-accent">EZ advanced: {ezConfig.tool}</span>
              <button
                type="button"
                disabled={!evidenceIdFilter || ezRebuild.isPending}
                onClick={() => {
                  if (!window.confirm(`Run ${ezConfig.tool} advanced rebuild for this evidence? Default/internal documents will be preserved.`)) return;
                  ezRebuild.mutate();
                }}
                className="rounded-xl border border-line bg-panel px-3 py-2 text-sm text-ink disabled:opacity-50"
              >
                {ezRebuild.isPending ? "Queueing rebuild..." : `Run ${ezConfig.tool} rebuild`}
              </button>
              <button type="button" onClick={() => setBackendVariant("advanced")} className="rounded-xl border border-line bg-abyss/80 px-3 py-2 text-sm text-muted">
                View EZ results
              </button>
              <button type="button" onClick={() => setBackendVariant("all")} className="rounded-xl border border-line bg-abyss/80 px-3 py-2 text-sm text-muted">
                Compare
              </button>
            </div>
            <p className="mt-3 text-sm text-muted">{ezConfig.note} Advanced rebuilds are scoped to the selected evidence and Search default results stay on the internal backend.</p>
            {!evidenceIdFilter ? <p className="mt-2 text-sm text-amber-300">Select an evidence to run an EZ rebuild.</p> : null}
            {ezRebuild.isSuccess ? <p className="mt-2 text-sm text-emerald-300">Rebuild queued. Switch to EZ advanced only after the worker finishes.</p> : null}
            {ezRebuild.isError ? <p className="mt-2 text-sm text-red-300">{ezRebuild.error instanceof Error ? ezRebuild.error.message : "Could not queue EZ rebuild."}</p> : null}
          </div>
        ) : null}
        {(USER_ACTIVITY_TYPES.has(artifactType) || artifactType === "user_activity") ? (
          <div className="mt-4 rounded-2xl border border-line bg-abyss/50 p-4">
            <div className="flex flex-wrap items-center gap-2">
              <span className="mr-1 font-mono text-[11px] uppercase tracking-[0.16em] text-accent">User Activity</span>
              {USER_ACTIVITY_TABS.map((tab) => (
                <button
                  key={tab.value}
                  type="button"
                  onClick={() => setArtifactType(tab.value)}
                  className={`rounded-xl border px-3 py-2 text-sm ${artifactType === tab.value ? "border-accent/50 bg-accent/15 text-accent" : "border-line bg-abyss/80 text-muted"}`}
                >
                  {tab.label}
                </button>
              ))}
              {caseId ? (
                <Link
                  to={`/cases/${caseId}/search?artifact_type=${encodeURIComponent(artifactType === "user_activity" ? "shellbag" : artifactType)}${evidenceIdFilter ? `&evidence_id=${encodeURIComponent(evidenceIdFilter)}` : ""}${hostFilter ? `&host=${encodeURIComponent(hostFilter)}` : ""}${query ? `&q=${encodeURIComponent(query)}` : ""}`}
                  className="rounded-xl border border-line bg-panel px-3 py-2 text-sm text-ink"
                >
                  Open matching documents in Search
                </Link>
              ) : null}
            </div>
            <p className="mt-3 text-sm text-muted">Focused RECmd views for Shellbags, UserAssist, RecentDocs, RunMRU and OpenSaveMRU. Use Search for cross-artifact investigation.</p>
          </div>
        ) : null}
        {isStartupPersistenceView ? (
          <div className="mt-4 rounded-2xl border border-line bg-abyss/50 p-4">
            <div className="flex flex-wrap items-center gap-3">
              <span className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Startup &amp; Persistence</span>
              <select aria-label="Persistence category" value={persistenceType} onChange={(event) => setPersistenceType(event.target.value)} className="rounded-xl border border-line bg-abyss/80 px-3 py-2 text-sm">
                <option value="">All categories</option>
                <option value="run_key">Run keys</option>
                <option value="runonce">RunOnce</option>
                <option value="scheduled_task">Scheduled Tasks</option>
                <option value="service">Services</option>
                <option value="startup_folder">Startup folders</option>
                <option value="winlogon">Winlogon</option>
                <option value="ifeo">IFEO</option>
                <option value="appinit">AppInit</option>
                <option value="defender_config">Defender config</option>
                <option value="task_cache">Task cache</option>
                <option value="rdp">RDP</option>
                <option value="active_setup">Active Setup</option>
                <option value="wmi">WMI</option>
              </select>
              <select aria-label="Persistence source" value={persistenceSource} onChange={(event) => setPersistenceSource(event.target.value)} className="rounded-xl border border-line bg-abyss/80 px-3 py-2 text-sm">
                <option value="">All sources</option>
                <option value="registry_autoruns">Registry hive</option>
                <option value="scheduled_tasks">Scheduled Tasks</option>
                <option value="services">Services</option>
                <option value="startup_folders">Startup folders</option>
                <option value="defender_config">Defender config</option>
                <option value="wmi">WMI</option>
                <option value="command_history">Command evidence</option>
              </select>
              <select value={persistenceRiskMin} onChange={(event) => setPersistenceRiskMin(event.target.value)} className="rounded-xl border border-line bg-abyss/80 px-3 py-2 text-sm">
                <option value="">Any risk</option>
                <option value="40">Suspicious+</option>
                <option value="70">High risk</option>
              </select>
              <label className="flex items-center gap-2 text-sm text-muted">
                <input type="checkbox" checked={persistenceSuspiciousOnly} onChange={(event) => setPersistenceSuspiciousOnly(event.target.checked)} />
                Suspicious only
              </label>
              {caseId ? (
                <Link to={`/cases/${caseId}/reports`} className="rounded-xl border border-line bg-panel px-3 py-2 text-sm text-ink">
                  Include in report
                </Link>
              ) : null}
            </div>
            <p className="mt-3 text-sm text-muted">
              Aggregates Scheduled Tasks, Services, registry hive persistence, Startup folders, WMI indicators, Defender configuration changes and command evidence. Registry hive rows preserve LastWrite semantics and are not shown as observed registry modification events.
            </p>
          </div>
        ) : null}
        {isMotwView ? (
          <div className="mt-4 rounded-2xl border border-line bg-abyss/50 p-4">
            <div className="flex flex-wrap items-center gap-3">
              <span className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">MOTW / Downloaded Files</span>
              <select value={motwZoneId} onChange={(event) => setMotwZoneId(event.target.value)} className="rounded-xl border border-line bg-abyss/80 px-3 py-2 text-sm">
                <option value="">All zones</option>
                <option value="0">0 Local Machine</option>
                <option value="1">1 Local Intranet</option>
                <option value="2">2 Trusted Sites</option>
                <option value="3">3 Internet</option>
                <option value="4">4 Restricted Sites</option>
              </select>
              <input value={motwExtension} onChange={(event) => setMotwExtension(event.target.value)} placeholder=".iso, .exe, .zip" className="rounded-xl border border-line bg-abyss/80 px-3 py-2 text-sm" />
              <select value={motwRiskMin} onChange={(event) => setMotwRiskMin(event.target.value)} className="rounded-xl border border-line bg-abyss/80 px-3 py-2 text-sm">
                <option value="">Any risk</option>
                <option value="40">Suspicious+</option>
                <option value="70">High risk</option>
              </select>
              {caseId ? (
                <Link to={`/cases/${caseId}/reports`} className="rounded-xl border border-line bg-panel px-3 py-2 text-sm text-ink">
                  Include in report
                </Link>
              ) : null}
            </div>
            <p className="mt-3 text-sm text-muted">
              Shows Zone.Identifier ADS, Sysmon FileCreateStreamHash MOTW evidence and related download pivots. HostUrl and ReferrerUrl only appear when present in indexed evidence.
            </p>
          </div>
        ) : null}
        {isEmailView ? (
          <div className="mt-4 rounded-2xl border border-line bg-abyss/50 p-4">
            <div className="flex flex-wrap items-center gap-3">
              <span className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Email Artifacts</span>
              <select value={emailType} onChange={(event) => setEmailType(event.target.value)} className="rounded-xl border border-line bg-abyss/80 px-3 py-2 text-sm">
                <option value="">All email artifact types</option>
                <option value="store">Mail stores</option>
                <option value="message_file">MSG/EML files</option>
                <option value="profile">Client profiles</option>
                <option value="app_presence">App presence</option>
                <option value="attachment_cache">Attachment/cache paths</option>
                <option value="webmail_activity">Webmail / related download activity</option>
                <option value="technical_trace">Advanced technical traces</option>
              </select>
              <select value={emailClient} onChange={(event) => setEmailClient(event.target.value)} className="rounded-xl border border-line bg-abyss/80 px-3 py-2 text-sm">
                <option value="">All clients</option>
                <option value="outlook">Outlook</option>
                <option value="thunderbird">Thunderbird</option>
                <option value="windows_mail">Windows Mail</option>
                <option value="browser_webmail">Browser webmail</option>
                <option value="unknown">Unknown</option>
              </select>
              <select value={emailRiskMin} onChange={(event) => setEmailRiskMin(event.target.value)} className="rounded-xl border border-line bg-abyss/80 px-3 py-2 text-sm">
                <option value="">Any interest</option>
                <option value="30">Interesting+</option>
                <option value="60">High interest</option>
              </select>
              <label className="flex items-center gap-2 text-sm text-muted">
                <input type="checkbox" checked={emailInterestingOnly} onChange={(event) => setEmailInterestingOnly(event.target.checked)} />
                Interesting only
              </label>
              {caseId ? (
                <Link to={`/cases/${caseId}/reports`} className="rounded-xl border border-line bg-panel px-3 py-2 text-sm text-ink">
                  Include in report
                </Link>
              ) : null}
            </div>
            <p className="mt-3 text-sm text-muted">
              Lists mail stores and mail-adjacent activity without claiming mailbox content. Use related downloads, MOTW and User Activity to corroborate initial-access chains.
            </p>
          </div>
        ) : null}
      </section>
      {!caseId ? (
        <section className="rounded-[28px] border border-line bg-panel/50 p-6 text-sm text-muted">
          Select a case and search processed artifacts.
        </section>
      ) : null}
      {caseId && !isStartupPersistenceView && !isMotwView && !isEmailView && !(result.data?.total ?? 0) && !result.isPending ? (
        <section className="rounded-[28px] border border-line bg-panel/50 p-6 text-sm text-muted">
          No processed artifacts are available yet. Upload or process evidence first.
        </section>
      ) : null}
      {isStartupPersistenceView ? (
        <StartupPersistenceView
          data={persistenceQuery.data}
          loading={persistenceQuery.isPending}
          page={page}
          pageSize={pageSize}
          onPageChange={setPage}
          onPageSizeChange={setPageSize}
          selectedItem={selectedPersistenceItem}
          onSelectItem={setSelectedPersistenceItem}
          indicatorData={persistenceIndicatorQuery.data ?? null}
          onCreateFinding={(item) => {
            if (!item.source_event_id) return;
            setPersistenceFindingEventIds([item.source_event_id]);
            setFindingDialogOpen(true);
          }}
          onAddTimeline={(item) => addPersistenceTimeline.mutate(item)}
          timelinePending={addPersistenceTimeline.isPending}
          timelineError={addPersistenceTimeline.error instanceof Error ? addPersistenceTimeline.error.message : ""}
          timelineSuccess={addPersistenceTimeline.isSuccess}
        />
      ) : isMotwView ? (
        <MotwArtifactView
          data={motwQuery.data}
          loading={motwQuery.isPending}
          page={page}
          pageSize={pageSize}
          onPageChange={setPage}
          onPageSizeChange={setPageSize}
          selectedItem={selectedMotwItem}
          onSelectItem={setSelectedMotwItem}
          indicatorData={motwIndicatorQuery.data ?? null}
          onCreateFinding={(item) => {
            if (!item.source_event_id) return;
            setPersistenceFindingEventIds([item.source_event_id]);
            setFindingDialogOpen(true);
          }}
          onAddTimeline={(item) => addMotwTimeline.mutate(item)}
          timelinePending={addMotwTimeline.isPending}
          timelineError={addMotwTimeline.error instanceof Error ? addMotwTimeline.error.message : ""}
          timelineSuccess={addMotwTimeline.isSuccess}
        />
      ) : isEmailView ? (
        <EmailArtifactsView
          data={emailQuery.data}
          loading={emailQuery.isPending}
          page={page}
          pageSize={pageSize}
          onPageChange={setPage}
          onPageSizeChange={setPageSize}
          selectedItem={selectedEmailItem}
          onSelectItem={setSelectedEmailItem}
          indicatorData={emailIndicatorQuery.data ?? null}
          onCreateFinding={(item) => {
            if (!item.source_event_id) return;
            setPersistenceFindingEventIds([item.source_event_id]);
            setFindingDialogOpen(true);
          }}
          onAddTimeline={(item) => addEmailTimeline.mutate(item)}
          timelinePending={addEmailTimeline.isPending}
          timelineError={addEmailTimeline.error instanceof Error ? addEmailTimeline.error.message : ""}
          timelineSuccess={addEmailTimeline.isSuccess}
        />
      ) : (
        <>
          <PaginationControls page={page} totalPages={result.data?.total_pages ?? 0} total={result.data?.total ?? 0} totalRelation={result.data?.total_relation ?? "eq"} pageSize={pageSize} onPageChange={setPage} onPageSizeChange={setPageSize} />
          <EventTable items={result.data?.items ?? []} view={view} selectedIds={selectedEventIds} onToggleSelect={(eventId) => setSelectedEventIds((current) => (current.includes(eventId) ? current.filter((item) => item !== eventId) : [...current, eventId]))} />
        </>
      )}
      <CreateFindingDialog
        open={findingDialogOpen}
        onClose={() => {
          setFindingDialogOpen(false);
          setPersistenceFindingEventIds([]);
        }}
        caseId={caseId}
        eventIds={persistenceFindingEventIds.length ? persistenceFindingEventIds : selectedEventIds}
        defaultTitle={persistenceFindingEventIds.length ? "Artifact evidence investigative lead" : "Artifact Explorer investigative lead"}
        defaultDescription={persistenceFindingEventIds.length ? "Created from a focused Artifact View source event." : `Created from ${selectedEventIds.length} selected Artifact Views event(s).`}
        defaultSeverity="medium"
        query={query || null}
        onCreated={() => {
          setSelectedEventIds([]);
          setPersistenceFindingEventIds([]);
        }}
      />
      {caseId ? (
        <DebugExportDialog
          open={debugExportOpen}
          onClose={() => setDebugExportOpen(false)}
          caseId={caseId}
          title={debugExportScope === "selected_events" ? "Export selected events debug pack" : "Export artifact debug pack"}
          defaultRequest={{
            scope: debugExportScope,
            event_ids: debugExportScope === "selected_events" ? selectedEventIds : [],
            artifact_types: artifactType ? [artifactType] : [],
            include_raw_samples: false,
            include_raw_xml: false,
            include_source_paths: true,
            include_full_raw: false,
            max_events_per_type: 25,
            max_field_length: 2000,
            redact_secrets: true,
            search_request: payload,
            ui_context: {
              page: "ArtifactSearch",
              selected_case: caseId,
              selected_artifact_type: artifactType,
              artifact_name: artifactName,
              query,
              current_view: view,
              selected_event_ids: selectedEventIds,
            },
          }}
        />
      ) : null}
    </div>
  );
}
