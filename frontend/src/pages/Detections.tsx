import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useParams, useSearchParams } from "react-router-dom";
import { api } from "../api/client";
import CreateFindingDialog from "../components/CreateFindingDialog";
import EventDetailDrawer from "../components/EventDetailDrawer";
import PaginationControls from "../components/PaginationControls";
import ResponsiveDetailPanel from "../components/ResponsiveDetailPanel";
import SearchableFacetSelect from "../components/SearchableFacetSelect";
import { useActiveCase } from "../context/ActiveCaseContext";

type SortField = "created_at" | "severity" | "engine" | "rule_name" | "status";
type SortDirection = "asc" | "desc";
type DetectionView = "grouped" | "raw";
type GroupingMode = "rule" | "severity" | "host" | "user" | "artifact_type" | "source_file" | "evidence" | "rule_run";
type GroupDetailTab = "overview" | "detections" | "events" | "rule" | "notes";
type DetectionGroupSelection = {
  mode: GroupingMode;
  key: string;
  label: string;
  count: number;
  rule_id?: string | null;
  severity?: string | null;
  meta?: string;
  first_seen?: string | null;
  last_seen?: string | null;
  samples?: string[];
  new_count?: number;
  reviewed_count?: number;
  dismissed_count?: number;
  confirmed_count?: number;
  unique_hosts?: number;
  unique_users?: number;
  unique_artifact_types?: number;
  unique_source_files?: number;
  sample_source_files?: string[];
  sample_event_ids?: string[];
} | null;

function extractEventMessage(error: Error) {
  try {
    const parsed = JSON.parse(error.message) as { error?: string };
    return parsed.error || error.message;
  } catch {
    return error.message;
  }
}

export default function Detections() {
  const queryClient = useQueryClient();
  const { caseId: routeCaseId } = useParams();
  const [searchParams, setSearchParams] = useSearchParams();
  const { activeCaseId, selectedEvidenceId, selectedHost, setActiveCaseId } = useActiveCase();
  const { data: cases } = useQuery({ queryKey: ["cases"], queryFn: api.listCases });
  const [caseId, setCaseId] = useState(routeCaseId || activeCaseId);
  const [source, setSource] = useState(searchParams.get("source") ?? "");
  const [engine, setEngine] = useState(searchParams.get("engine") ?? "");
  const [ruleIdQuery, setRuleIdQuery] = useState(searchParams.get("rule_id") ?? "");
  const [ruleRunIdFilter, setRuleRunIdFilter] = useState(searchParams.get("rule_run_id") ?? "");
  const [importRunIdFilter, setImportRunIdFilter] = useState(searchParams.get("import_run_id") ?? "");
  const [sourcePackFilter, setSourcePackFilter] = useState(searchParams.get("source_pack") ?? "");
  const [runTypeFilter, setRunTypeFilter] = useState(searchParams.get("run_type") ?? "");
  const [severity, setSeverity] = useState(searchParams.get("severity") ?? "");
  const [statusFilter, setStatusFilter] = useState(searchParams.get("status") ?? "");
  const [ruleName, setRuleName] = useState(searchParams.get("rule_name") ?? "");
  const [evidenceFilter, setEvidenceFilter] = useState(searchParams.get("evidence_id") ?? selectedEvidenceId);
  const [hostFilter, setHostFilter] = useState(searchParams.get("host") ?? selectedHost);
  const [artifactTypeFilter, setArtifactTypeFilter] = useState(searchParams.get("artifact_type") ?? "");
  const [matchedObjectType, setMatchedObjectType] = useState(searchParams.get("matched_object_type") ?? "");
  const [queryText, setQueryText] = useState(searchParams.get("q") ?? "");
  const [linkedEventFilter, setLinkedEventFilter] = useState("");
  const [fileTargetFilter, setFileTargetFilter] = useState("");
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [allMatchingSelected, setAllMatchingSelected] = useState(false);
  const [sortField, setSortField] = useState<SortField>("created_at");
  const [sortDirection, setSortDirection] = useState<SortDirection>("desc");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [viewMode, setViewMode] = useState<DetectionView>("grouped");
  const [groupingMode, setGroupingMode] = useState<GroupingMode>("rule");
  const [selectedGroup, setSelectedGroup] = useState<DetectionGroupSelection>(() => {
    const mode = searchParams.get("group_mode") as GroupingMode | null;
    const key = searchParams.get("group_key") ?? "";
    if (!mode || !key) return null;
    return {
      mode,
      key,
      label: searchParams.get("group_label") ?? key,
      count: Number(searchParams.get("group_count") ?? "0") || 0,
      rule_id: searchParams.get("group_rule_id"),
      severity: searchParams.get("group_severity"),
      first_seen: searchParams.get("group_first_seen"),
      last_seen: searchParams.get("group_last_seen"),
    };
  });
  const [groupPage, setGroupPage] = useState(1);
  const [groupTab, setGroupTab] = useState<GroupDetailTab>("overview");
  const [orphanedOnly, setOrphanedOnly] = useState(searchParams.get("orphaned_only") === "true");
  const [previewOpen, setPreviewOpen] = useState(false);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [previewEvent, setPreviewEvent] = useState<Record<string, unknown> | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [selectedDetectionId, setSelectedDetectionId] = useState<string | null>(null);
  const [findingDialogOpen, setFindingDialogOpen] = useState(false);
  const [findingDetectionIds, setFindingDetectionIds] = useState<string[]>([]);
  const [findingDialogCaseId, setFindingDialogCaseId] = useState("");
  const [findingDefaultTitle, setFindingDefaultTitle] = useState("");
  const [findingDefaultDescription, setFindingDefaultDescription] = useState("");
  const [bulkPreviewOpen, setBulkPreviewOpen] = useState(false);
  const [bulkPreviewLoading, setBulkPreviewLoading] = useState(false);
  const [bulkPreviewError, setBulkPreviewError] = useState<string | null>(null);
  const [bulkPreview, setBulkPreview] = useState<Awaited<ReturnType<typeof api.previewBulkDetections>> | null>(null);
  const [pendingDeleteMode, setPendingDeleteMode] = useState<"selected" | "matching" | "rule_run" | "orphaned_rules">("selected");
  const [deleteConfirmText, setDeleteConfirmText] = useState("");
  const selectedCaseId = caseId || "";

  useEffect(() => {
    setCaseId((current) => current || activeCaseId);
  }, [activeCaseId]);

  useEffect(() => {
    if (routeCaseId) {
      setActiveCaseId(routeCaseId);
      setCaseId(routeCaseId);
    }
  }, [routeCaseId, setActiveCaseId]);

  useEffect(() => {
    setEvidenceFilter((current) => current || selectedEvidenceId);
  }, [selectedEvidenceId]);

  useEffect(() => {
    setHostFilter((current) => current || selectedHost);
  }, [selectedHost]);

  useEffect(() => {
    setPage(1);
    setAllMatchingSelected(false);
    setSelectedIds([]);
  }, [caseId, source, engine, ruleIdQuery, ruleRunIdFilter, importRunIdFilter, sourcePackFilter, runTypeFilter, severity, statusFilter, ruleName, evidenceFilter, hostFilter, artifactTypeFilter, matchedObjectType, queryText, linkedEventFilter, fileTargetFilter, orphanedOnly, sortField, sortDirection, pageSize]);

  const queryOptions = {
    include_event_preview: true,
    source: source || undefined,
    engine: engine || undefined,
    rule_id: ruleIdQuery || undefined,
    rule_run_id: ruleRunIdFilter || undefined,
    import_run_id: importRunIdFilter || undefined,
    source_pack: sourcePackFilter || undefined,
    run_type: runTypeFilter || undefined,
    severity: severity || undefined,
    status: statusFilter || undefined,
    rule_name: ruleName || undefined,
    evidence_id: evidenceFilter || undefined,
    host: hostFilter || undefined,
    artifact_type: artifactTypeFilter || undefined,
    matched_object_type: matchedObjectType || undefined,
    q: queryText || undefined,
    has_linked_event: linkedEventFilter ? linkedEventFilter === "true" : undefined,
    has_file_target: fileTargetFilter ? fileTargetFilter === "true" : undefined,
    orphaned_only: orphanedOnly || undefined,
    page,
    page_size: pageSize,
    sort_field: sortField,
    sort_direction: sortDirection,
  };
  const summaryOptions = {
    source: source || undefined,
    engine: engine || undefined,
    rule_id: ruleIdQuery || undefined,
    rule_run_id: ruleRunIdFilter || undefined,
    import_run_id: importRunIdFilter || undefined,
    source_pack: sourcePackFilter || undefined,
    run_type: runTypeFilter || undefined,
    severity: severity || undefined,
    status: statusFilter || undefined,
    rule_name: ruleName || undefined,
    evidence_id: evidenceFilter || undefined,
    host: hostFilter || undefined,
    artifact_type: artifactTypeFilter || undefined,
    q: queryText || undefined,
    limit: 100,
  };

  const detectionsQuery = useQuery({
    queryKey: ["detections", selectedCaseId, queryOptions],
    queryFn: () => (selectedCaseId ? api.listDetections(selectedCaseId, queryOptions) : api.listAllDetections(queryOptions)),
  });
  const facetsQuery = useQuery({
    queryKey: ["detection-facets", selectedCaseId],
    queryFn: () => api.getDetectionFacets(selectedCaseId || undefined),
  });
  const summaryQuery = useQuery({
    queryKey: ["detection-summary", selectedCaseId, summaryOptions],
    queryFn: () => api.getDetectionSummary({ case_id: selectedCaseId || undefined, ...summaryOptions }),
  });

  function groupFilters(group: DetectionGroupSelection) {
    const filters = buildBulkFilters();
    if (!group) return filters;
    if (group.mode === "rule") return { ...filters, rule_name: group.key };
    if (group.mode === "severity") return { ...filters, severity: group.key };
    if (group.mode === "host") return { ...filters, host: group.key };
    if (group.mode === "user") return { ...filters, user: group.key };
    if (group.mode === "artifact_type") return { ...filters, artifact_type: group.key };
    if (group.mode === "source_file") return { ...filters, source_file: group.key };
    if (group.mode === "evidence") return { ...filters, evidence_id: group.key };
    if (group.mode === "rule_run") return { ...filters, rule_run_id: group.key };
    return filters;
  }

  const groupQueryOptions = {
    ...queryOptions,
    ...groupFilters(selectedGroup),
    page: groupPage,
    page_size: 25,
  };
  const groupDetectionsQuery = useQuery({
    queryKey: ["detections-group-detail", selectedCaseId, selectedGroup, groupPage, groupQueryOptions],
    queryFn: () => (selectedCaseId ? api.listDetections(selectedCaseId, groupQueryOptions) : api.listAllDetections(groupQueryOptions)),
    enabled: Boolean(selectedGroup),
  });

  const refreshDetections = async () => {
    await queryClient.invalidateQueries({ queryKey: ["detections"] });
    await queryClient.invalidateQueries({ queryKey: ["detection-summary"] });
    await queryClient.invalidateQueries({ queryKey: ["detections-group-detail"] });
    await queryClient.invalidateQueries({ queryKey: ["detection-facets"] });
    await queryClient.invalidateQueries({ queryKey: ["cases"] });
    if (selectedCaseId) await queryClient.invalidateQueries({ queryKey: ["dashboard-summary", selectedCaseId] });
  };

  const updateMutation = useMutation({
    mutationFn: ({ detectionId, status }: { detectionId: string; status: string }) => api.updateDetection(detectionId, { status }),
    onSuccess: () => void refreshDetections(),
  });
  const deleteMutation = useMutation({
    mutationFn: (detectionId: string) => api.deleteDetection(detectionId),
    onSuccess: () => {
      setSelectedIds([]);
      void refreshDetections();
    },
  });
  const bulkMutation = useMutation({
    mutationFn: (payload: {
      detection_ids: string[];
      action: "delete" | "archive" | "mark_reviewed" | "mark_false_positive";
      case_id?: string;
      engine?: string;
      severity?: string;
      status?: string;
      rule_name?: string;
      evidence_id?: string;
      has_linked_event?: boolean;
      has_file_target?: boolean;
    }) => api.bulkDetections(payload),
    onSuccess: () => {
      setSelectedIds([]);
      void refreshDetections();
    },
  });
  const bulkStatusMutation = useMutation({
    mutationFn: (payload: Parameters<typeof api.updateBulkDetections>[0]) => api.updateBulkDetections(payload),
    onSuccess: () => {
      setSelectedIds([]);
      setAllMatchingSelected(false);
      void refreshDetections();
    },
  });
  const bulkDeleteMutation = useMutation({
    mutationFn: (payload: Parameters<typeof api.deleteBulkDetections>[0]) => api.deleteBulkDetections(payload),
    onSuccess: () => {
      setSelectedIds([]);
      setAllMatchingSelected(false);
      setBulkPreviewOpen(false);
      setDeleteConfirmText("");
      void refreshDetections();
    },
  });
  const promoteMutation = useMutation({
    mutationFn: (detectionId: string) => api.promoteDetectionToFinding(detectionId),
    onSuccess: () => {
      void refreshDetections();
      void queryClient.invalidateQueries({ queryKey: ["findings-page"] });
      void queryClient.invalidateQueries({ queryKey: ["findings"] });
      if (selectedCaseId) void queryClient.invalidateQueries({ queryKey: ["case", selectedCaseId] });
    },
  });

  const detections = detectionsQuery.data?.items ?? [];
  const groupDetections = groupDetectionsQuery.data?.items ?? [];
  const selectedDetection = [...detections, ...groupDetections].find((item) => item.id === selectedDetectionId) ?? null;
  const allSelectedOnPage = useMemo(() => detections.length > 0 && detections.every((item) => selectedIds.includes(item.id)), [detections, selectedIds]);

  useEffect(() => {
    if (!selectedDetectionId) return;
    if (![...detections, ...groupDetections].some((item) => item.id === selectedDetectionId)) {
      setSelectedDetectionId(null);
    }
  }, [detections, groupDetections, selectedDetectionId]);

  function toggleSelected(detectionId: string) {
    setAllMatchingSelected(false);
    setSelectedIds((current) => (current.includes(detectionId) ? current.filter((item) => item !== detectionId) : [...current, detectionId]));
  }

  function toggleSelectPage() {
    const pageIds = detections.map((item) => item.id);
    setAllMatchingSelected(false);
    setSelectedIds((current) => (allSelectedOnPage ? current.filter((item) => !pageIds.includes(item)) : [...new Set([...current, ...pageIds])]));
  }

  function buildBulkFilters() {
    return {
      case_id: selectedCaseId || undefined,
      source: source || undefined,
      engine: engine || undefined,
      rule_id: ruleIdQuery || undefined,
      rule_run_id: ruleRunIdFilter || undefined,
      import_run_id: importRunIdFilter || undefined,
      source_pack: sourcePackFilter || undefined,
      severity: severity || undefined,
      status: statusFilter || undefined,
      rule_name: ruleName || undefined,
      evidence_id: evidenceFilter || undefined,
      host: hostFilter || undefined,
      artifact_type: artifactTypeFilter || undefined,
      matched_object_type: matchedObjectType || undefined,
      q: queryText || undefined,
      has_linked_event: linkedEventFilter ? linkedEventFilter === "true" : undefined,
      has_file_target: fileTargetFilter ? fileTargetFilter === "true" : undefined,
      orphaned_only: orphanedOnly || undefined,
    };
  }

  function buildSelectionPayload(mode: "selected" | "matching" | "rule_run" | "orphaned_rules" = allMatchingSelected ? "matching" : "selected") {
    return {
      mode,
      detection_ids: mode === "selected" ? selectedIds : [],
      filters: buildBulkFilters(),
      case_id: selectedCaseId || undefined,
      rule_run_id: mode === "rule_run" ? ruleRunIdFilter || undefined : undefined,
    } as const;
  }

  function bulkAction(action: "delete" | "archive" | "mark_reviewed" | "mark_false_positive") {
    if (!selectedIds.length) return;
    bulkMutation.mutate({ detection_ids: selectedIds, action });
  }

  async function openDeletePreview(mode: "selected" | "matching" | "rule_run" | "orphaned_rules") {
    setBulkPreviewOpen(true);
    setBulkPreviewLoading(true);
    setBulkPreviewError(null);
    setBulkPreview(null);
    setPendingDeleteMode(mode);
    setDeleteConfirmText("");
    try {
      const preview = await api.previewBulkDetections(buildSelectionPayload(mode));
      setBulkPreview(preview);
    } catch (error) {
      setBulkPreviewError(error instanceof Error ? error.message : String(error));
    } finally {
      setBulkPreviewLoading(false);
    }
  }

  async function confirmBulkDelete() {
    if (!bulkPreview) return;
    const requiresText = bulkPreview.matched > 25 || pendingDeleteMode !== "selected";
    const expectedConfirm = `DELETE ${bulkPreview.matched} DETECTIONS`;
    if (requiresText && deleteConfirmText !== expectedConfirm) return;
    bulkDeleteMutation.mutate({
      ...buildSelectionPayload(pendingDeleteMode),
      confirm: requiresText ? deleteConfirmText : null,
    });
  }

  function bulkStatusAction(action: "mark_reviewed" | "mark_dismissed" | "mark_new") {
    if (!selectedIds.length && !allMatchingSelected) return;
    bulkStatusMutation.mutate({
      ...buildSelectionPayload(),
      action,
    });
  }

  function bulkStatusGroup(action: "mark_reviewed" | "mark_dismissed" | "mark_new", group: NonNullable<DetectionGroupSelection>) {
    if (["mark_dismissed", "mark_new"].includes(action) && !window.confirm(`${action === "mark_dismissed" ? "Dismiss" : "Reopen"} ${group.count} detections in ${group.label}?`)) return;
    bulkStatusMutation.mutate({
      action,
      mode: "matching",
      filters: groupFilters(group),
      case_id: selectedCaseId || undefined,
    });
  }

  function openGroup(group: NonNullable<DetectionGroupSelection>) {
    setSelectedGroup(group);
    setGroupPage(1);
    setGroupTab("overview");
    const params = new URLSearchParams(searchParams);
    params.set("view", "group");
    params.set("group_mode", group.mode);
    params.set("group_key", group.key);
    params.set("group_label", group.label);
    params.set("group_count", String(group.count));
    if (group.rule_id) params.set("group_rule_id", group.rule_id);
    else params.delete("group_rule_id");
    if (group.severity) params.set("group_severity", group.severity);
    else params.delete("group_severity");
    if (group.first_seen) params.set("group_first_seen", group.first_seen);
    else params.delete("group_first_seen");
    if (group.last_seen) params.set("group_last_seen", group.last_seen);
    else params.delete("group_last_seen");
    setSearchParams(params, { replace: false });
  }

  function closeGroup() {
    setSelectedGroup(null);
    setGroupPage(1);
    setGroupTab("overview");
    const params = new URLSearchParams(searchParams);
    ["view", "group_mode", "group_key", "group_label", "group_count", "group_rule_id", "group_severity", "group_first_seen", "group_last_seen"].forEach((key) => params.delete(key));
    setSearchParams(params, { replace: false });
  }

  function searchRelatedGroup(group: NonNullable<DetectionGroupSelection>) {
    if (!selectedCaseId) return;
    const params = new URLSearchParams();
    params.set("scope", "all");
    params.set("tab", "results");
    params.set("page_size", "100");
    if (evidenceFilter) params.set("evidence_id", evidenceFilter);
    if (group.mode === "host") params.set("filters", JSON.stringify([{ field: "host.name", operator: "is", value: group.key }]));
    else if (group.mode === "artifact_type") params.set("filters", JSON.stringify([{ field: "artifact.type", operator: "is", value: group.key }]));
    else if (group.mode === "source_file") params.set("filters", JSON.stringify([{ field: "source_file", operator: "contains", value: group.key }]));
    else if (group.mode === "user") params.set("filters", JSON.stringify([{ field: "user.name", operator: "is", value: group.key }]));
    else params.set("q", group.key);
    window.location.href = `/cases/${selectedCaseId}/search?${params.toString()}`;
  }

  function promoteVisibleGroupToFinding() {
    const ids = (groupDetectionsQuery.data?.items ?? []).map((item) => item.id);
    if (!ids.length) {
      window.alert("Open a group with detections before creating a finding draft.");
      return;
    }
    openFindingDialogFromDetectionIds(ids);
  }

  function openFindingDialogFromDetectionIds(ids: string[]) {
    if (!ids.length) return;
    const selectedDetections = [...detections, ...groupDetections].filter((item) => ids.includes(item.id));
    const caseIds = selectedCaseId ? [selectedCaseId] : [...new Set(selectedDetections.map((item) => item.case_id).filter(Boolean))];
    if (caseIds.length !== 1) {
      window.alert("Select detections from a single case to create a finding.");
      return;
    }
    setFindingDetectionIds(ids);
    setFindingDialogCaseId(caseIds[0]);
    setFindingDefaultTitle(ids.length === 1 ? `Detection lead: ${selectedDetections[0]?.rule_name || "selected detection"}` : `Detection lead from ${ids.length} detections`);
    setFindingDefaultDescription(
      ids.length === 1
        ? `Created from detection ${selectedDetections[0]?.rule_name || ids[0]}. Review the linked event or file target and confirm the analyst narrative.`
        : `Created from ${ids.length} selected detections. Review the linked events/files and consolidate the storyline.`,
    );
    setFindingDialogOpen(true);
  }

  async function openEvent(detectionId: string) {
    setPreviewOpen(true);
    setPreviewLoading(true);
    setPreviewError(null);
    setPreviewEvent(null);
    try {
      const event = await api.getDetectionEvent(detectionId);
      setPreviewEvent(event);
    } catch (error) {
      setPreviewError(extractEventMessage(error as Error));
    } finally {
      setPreviewLoading(false);
    }
  }

  async function openDetectionInSiem(detection: (typeof detections)[number]) {
    if (detection.target_type !== "event" || (!detection.event_id && !detection.opensearch_id)) return;
    const links = await api.siemExternalLinks({
      case_id: detection.case_id,
      event_id: detection.event_id || undefined,
      detection_id: detection.id,
    });
    window.open(links.discover_url, "_blank", "noopener,noreferrer");
  }

  function renderDetectionActions(detection: (typeof detections)[number]) {
    return (
      <>
        <button onClick={() => updateMutation.mutate({ detectionId: detection.id, status: "reviewed" })} className="rounded-2xl border border-line bg-panel/40 px-4 py-2 text-sm text-muted">
          Mark reviewed
        </button>
        <button onClick={() => updateMutation.mutate({ detectionId: detection.id, status: "confirmed" })} className="rounded-2xl border border-line bg-panel/40 px-4 py-2 text-sm text-muted">
          Confirm
        </button>
        <button onClick={() => updateMutation.mutate({ detectionId: detection.id, status: "dismissed" })} className="rounded-2xl border border-line bg-panel/40 px-4 py-2 text-sm text-muted">
          Dismiss
        </button>
        <button onClick={() => openFindingDialogFromDetectionIds([detection.id])} className="rounded-2xl border border-line bg-panel/40 px-4 py-2 text-sm text-muted">
          Open finding draft
        </button>
        <button onClick={() => promoteMutation.mutate(detection.id)} className="rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss">
          Promote to finding
        </button>
        {detection.target_type === "event" && (detection.event_id || detection.opensearch_id) ? (
          <>
            <button onClick={() => void openEvent(detection.id)} className="rounded-2xl border border-line bg-panel/40 px-4 py-2 text-sm text-muted">
              Open event
            </button>
            <button onClick={() => void openDetectionInSiem(detection)} className="rounded-2xl border border-line bg-panel/40 px-4 py-2 text-sm text-muted">
              Open in OpenSearch
            </button>
          </>
        ) : (
          <span className="rounded-2xl border border-line bg-panel/40 px-4 py-2 text-sm text-muted">No linked event</span>
        )}
        {detection.target_type === "file" && detection.target_path ? (
          <button onClick={() => navigator.clipboard.writeText(detection.target_path as string)} className="rounded-2xl border border-line bg-panel/40 px-4 py-2 text-sm text-muted">
            Copy path
          </button>
        ) : null}
        <button onClick={() => { window.location.href = `/search?q=${encodeURIComponent(detection.target_path || detection.rule_name)}`; }} className="rounded-2xl border border-line bg-panel/40 px-4 py-2 text-sm text-muted">
          Search related IOC
        </button>
        {selectedCaseId && detection.event_id ? (
          <button onClick={() => { window.location.href = `/cases/${selectedCaseId}/timeline?around_event=${encodeURIComponent(detection.event_id || "")}`; }} className="rounded-2xl border border-line bg-panel/40 px-4 py-2 text-sm text-muted">
            Open in Timeline
          </button>
        ) : null}
        <button onClick={() => deleteMutation.mutate(detection.id)} className="rounded-2xl border border-danger/40 bg-danger/10 px-4 py-2 text-sm text-danger">
          Delete
        </button>
      </>
    );
  }

  const summary = summaryQuery.data;
  const groupingItems = useMemo(() => {
    if (!summary) return [];
    if (groupingMode === "rule") return summary.by_rule.map((item) => ({
      mode: "rule" as const,
      key: item.rule_name,
      label: item.rule_name,
      count: item.count,
      rule_id: item.rule_id,
      severity: item.severity,
      meta: `${item.unique_hosts} hosts · ${item.unique_users} users · ${item.new_count} new`,
      first_seen: item.first_seen,
      last_seen: item.last_seen,
      samples: item.sample_entities,
      new_count: item.new_count,
      reviewed_count: item.reviewed_count,
      dismissed_count: item.dismissed_count,
      confirmed_count: item.confirmed_count,
      unique_hosts: item.unique_hosts,
      unique_users: item.unique_users,
      unique_artifact_types: item.unique_artifact_types,
      unique_source_files: item.unique_source_files,
      sample_source_files: item.sample_source_files,
      sample_event_ids: item.sample_event_ids,
    }));
    const map = {
      severity: summary.by_severity ? Object.entries(summary.by_severity).map(([key, count]) => ({ key, count })) : [],
      host: summary.by_host,
      user: summary.by_user,
      artifact_type: summary.by_artifact_type,
      source_file: summary.by_source_file,
      evidence: summary.by_evidence,
      rule_run: summary.by_rule_run,
    }[groupingMode] ?? [];
    return map.map((item) => ({ mode: groupingMode, key: item.key, label: item.key, count: item.count, rule_id: null, severity: groupingMode === "severity" ? item.key : null, meta: "", first_seen: null, last_seen: null, samples: [] }));
  }, [groupingMode, summary]);

  const groupStatusBreakdown = useMemo(() => {
    const fromSelected = selectedGroup
      ? {
          new: selectedGroup.new_count,
          reviewed: selectedGroup.reviewed_count,
          dismissed: selectedGroup.dismissed_count,
          confirmed: selectedGroup.confirmed_count,
        }
      : {};
    const fromPage = groupDetections.reduce<Record<string, number>>((acc, detection) => {
      acc[detection.status] = (acc[detection.status] ?? 0) + 1;
      return acc;
    }, {});
    return {
      new: Number(fromSelected.new ?? fromPage.new ?? 0),
      reviewed: Number(fromSelected.reviewed ?? fromPage.reviewed ?? 0),
      dismissed: Number(fromSelected.dismissed ?? fromPage.dismissed ?? 0),
      confirmed: Number(fromSelected.confirmed ?? fromPage.confirmed ?? 0),
    };
  }, [groupDetections, selectedGroup]);

  const groupEntitySummary = useMemo(() => {
    const hosts = new Set<string>();
    const evidences = new Set<string>();
    const sources = new Set<string>();
    const users = new Set<string>();
    for (const detection of groupDetections) {
      if (detection.host_name) hosts.add(detection.host_name);
      if (detection.evidence_id) evidences.add(detection.evidence_id);
      const preview = (detection.raw?.event_preview as Record<string, unknown> | undefined) ?? {};
      const sourceFile = detection.raw?.source_file ?? preview.source_file;
      if (sourceFile) sources.add(String(sourceFile));
      if (preview.user) users.add(String(preview.user));
    }
    return {
      hosts: Array.from(hosts),
      users: Array.from(users),
      evidences: Array.from(evidences),
      sourceFiles: Array.from(sources),
    };
  }, [groupDetections]);

  return (
    <div className="space-y-6">
      <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
        <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">Detections</p>
        <h2 className="mt-2 text-2xl font-semibold">Automatic matches from rules and engines. Review them before turning them into findings.</h2>
        <p className="mt-2 text-sm text-muted">Detections are automatic matches generated by built-in heuristics, Sigma/heuristic rules over indexed events, or YARA rules over preserved files.</p>
        {!selectedCaseId ? <p className="mt-2 text-sm text-amber-300">All cases selected. Results include detections across the workspace.</p> : null}
        {selectedHost || selectedEvidenceId ? (
          <div className="mt-3 flex flex-wrap gap-2 text-xs text-muted">
            <span className="rounded-full border border-line bg-abyss/70 px-3 py-1.5">{selectedHost ? `Host filter not supported in this view yet: ${selectedHost}` : "Host filter: all hosts"}</span>
            <span className="rounded-full border border-line bg-abyss/70 px-3 py-1.5">{evidenceFilter ? `Evidence filter: ${evidenceFilter.slice(0, 8)}` : "Evidence filter: all evidence"}</span>
          </div>
        ) : null}
        {ruleRunIdFilter ? (
          <div className="mt-3 flex flex-wrap gap-2 text-xs text-muted">
            <span className="rounded-full border border-line bg-abyss/70 px-3 py-1.5">Rule run filter: {ruleRunIdFilter}</span>
            <button type="button" onClick={() => void openDeletePreview("rule_run")} className="rounded-full border border-danger/40 bg-danger/10 px-3 py-1.5 text-danger">
              Clean detections from this run
            </button>
          </div>
        ) : null}
        {orphanedOnly ? (
          <div className="mt-3 flex flex-wrap gap-2 text-xs text-muted">
            <span className="rounded-full border border-line bg-abyss/70 px-3 py-1.5">Orphaned detections only</span>
            <button type="button" onClick={() => void openDeletePreview("orphaned_rules")} className="rounded-full border border-danger/40 bg-danger/10 px-3 py-1.5 text-danger">
              Delete orphaned detections
            </button>
          </div>
        ) : null}
        <div className="mt-5 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <div className="rounded-2xl border border-line bg-abyss/80 p-3">
            <label className="block">
              <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Case</span>
              <select value={selectedCaseId} onChange={(event) => setCaseId(event.target.value)} className="w-full rounded-xl border border-line bg-panel/70 px-3 py-2 text-sm">
                <option value="">All cases</option>
                {(cases ?? []).map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.name}
                  </option>
                ))}
              </select>
            </label>
          </div>
          <SearchableFacetSelect label="Source" value={source} onChange={setSource} options={(facetsQuery.data?.sources ?? []).map((item) => ({ value: item.value, count: item.count }))} />
          <SearchableFacetSelect label="Engine" value={engine} onChange={setEngine} options={(facetsQuery.data?.engines ?? []).map((item) => ({ value: item.value, count: item.count }))} />
          <SearchableFacetSelect label="Severity" value={severity} onChange={setSeverity} options={(facetsQuery.data?.severities ?? []).map((item) => ({ value: item.value, count: item.count }))} />
          <SearchableFacetSelect label="Status" value={statusFilter} onChange={setStatusFilter} options={(facetsQuery.data?.statuses ?? []).map((item) => ({ value: item.value, count: item.count }))} />
          <SearchableFacetSelect label="Rule name" value={ruleName} onChange={setRuleName} options={(facetsQuery.data?.rule_names ?? []).map((item) => ({ value: item.value, count: item.count }))} />
          <SearchableFacetSelect label="Evidence" value={evidenceFilter} onChange={setEvidenceFilter} options={(facetsQuery.data?.evidences ?? []).map((item) => ({ value: item.id, label: item.name, count: item.count }))} />
          <SearchableFacetSelect label="Host" value={hostFilter} onChange={setHostFilter} options={(facetsQuery.data?.hosts ?? []).map((item) => ({ value: item.value, count: item.count }))} />
          <SearchableFacetSelect label="Matched object" value={matchedObjectType} onChange={setMatchedObjectType} options={(facetsQuery.data?.matched_object_types ?? []).map((item) => ({ value: item.value, count: item.count }))} />
          <SearchableFacetSelect label="Has linked event" value={linkedEventFilter} onChange={setLinkedEventFilter} options={(facetsQuery.data?.has_linked_event ?? []).map((item) => ({ value: String(item.value), label: item.value ? "Yes" : "No", count: item.count }))} />
          <SearchableFacetSelect label="Has file target" value={fileTargetFilter} onChange={setFileTargetFilter} options={(facetsQuery.data?.has_file_target ?? []).map((item) => ({ value: String(item.value), label: item.value ? "Yes" : "No", count: item.count }))} />
          <div className="rounded-2xl border border-line bg-abyss/80 p-3">
            <label className="block">
              <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Rule ID</span>
              <input value={ruleIdQuery} onChange={(event) => setRuleIdQuery(event.target.value)} className="w-full rounded-xl border border-line bg-panel/70 px-3 py-2 text-sm" />
            </label>
          </div>
          <div className="rounded-2xl border border-line bg-abyss/80 p-3">
            <label className="block">
              <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Rule run ID</span>
              <input value={ruleRunIdFilter} onChange={(event) => setRuleRunIdFilter(event.target.value)} className="w-full rounded-xl border border-line bg-panel/70 px-3 py-2 text-sm" />
            </label>
          </div>
          <div className="rounded-2xl border border-line bg-abyss/80 p-3">
            <label className="block">
              <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Import run ID</span>
              <input value={importRunIdFilter} onChange={(event) => setImportRunIdFilter(event.target.value)} className="w-full rounded-xl border border-line bg-panel/70 px-3 py-2 text-sm" />
            </label>
          </div>
          <div className="rounded-2xl border border-line bg-abyss/80 p-3">
            <label className="block">
              <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Source pack</span>
              <input value={sourcePackFilter} onChange={(event) => setSourcePackFilter(event.target.value)} className="w-full rounded-xl border border-line bg-panel/70 px-3 py-2 text-sm" />
            </label>
          </div>
          <div className="rounded-2xl border border-line bg-abyss/80 p-3">
            <label className="block">
              <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Run type</span>
              <select value={runTypeFilter} onChange={(event) => setRunTypeFilter(event.target.value)} className="w-full rounded-xl border border-line bg-panel/70 px-3 py-2 text-sm">
                <option value="">Any</option>
                <option value="smoke">Smoke</option>
              </select>
            </label>
          </div>
          <div className="rounded-2xl border border-line bg-abyss/80 p-3">
            <label className="block">
              <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Artifact type</span>
              <input value={artifactTypeFilter} onChange={(event) => setArtifactTypeFilter(event.target.value)} className="w-full rounded-xl border border-line bg-panel/70 px-3 py-2 text-sm" />
            </label>
          </div>
          <div className="rounded-2xl border border-line bg-abyss/80 p-3">
            <label className="block">
              <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Search</span>
              <input value={queryText} onChange={(event) => setQueryText(event.target.value)} placeholder="rule, path, hash, domain, ip" className="w-full rounded-xl border border-line bg-panel/70 px-3 py-2 text-sm" />
            </label>
          </div>
        </div>
        <div className="mt-4 flex flex-wrap items-center gap-3">
          <label className="text-sm text-muted">
            Sort
            <select value={sortField} onChange={(event) => setSortField(event.target.value as SortField)} className="ml-2 rounded-xl border border-line bg-abyss/80 px-3 py-2">
              <option value="created_at">Created</option>
              <option value="severity">Severity</option>
              <option value="engine">Engine</option>
              <option value="rule_name">Rule name</option>
              <option value="status">Status</option>
            </select>
          </label>
          <label className="text-sm text-muted">
            Direction
            <select value={sortDirection} onChange={(event) => setSortDirection(event.target.value as SortDirection)} className="ml-2 rounded-xl border border-line bg-abyss/80 px-3 py-2">
              <option value="desc">Desc</option>
              <option value="asc">Asc</option>
            </select>
          </label>
          <button type="button" onClick={toggleSelectPage} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">
            {allSelectedOnPage ? "Clear page selection" : "Select page"}
          </button>
          <button
            type="button"
            onClick={() => {
              setSelectedIds([]);
              setAllMatchingSelected(false);
            }}
            className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted"
          >
            Clear selection
          </button>
          <button type="button" onClick={() => setAllMatchingSelected(true)} disabled={!(detectionsQuery.data?.total)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted disabled:opacity-40">
            Select all matching ({detectionsQuery.data?.total ?? 0})
          </button>
          <label className="inline-flex items-center gap-2 text-sm text-muted">
            <input type="checkbox" checked={orphanedOnly} onChange={(event) => setOrphanedOnly(event.target.checked)} />
            Orphaned detections only
          </label>
        </div>
        <div className="mt-3 text-sm text-muted">
          {allMatchingSelected ? `All ${detectionsQuery.data?.total ?? 0} matching detections selected.` : `${selectedIds.length} selected`}
        </div>
        <div className="mt-4 flex flex-wrap gap-3">
          <button type="button" onClick={() => bulkStatusAction("mark_reviewed")} disabled={!selectedIds.length && !allMatchingSelected} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted disabled:opacity-40">
            Mark reviewed
          </button>
          <button type="button" onClick={() => bulkStatusAction("mark_dismissed")} disabled={!selectedIds.length && !allMatchingSelected} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted disabled:opacity-40">
            Mark dismissed
          </button>
          <button type="button" onClick={() => bulkStatusAction("mark_new")} disabled={!selectedIds.length && !allMatchingSelected} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted disabled:opacity-40">
            Reopen as new
          </button>
          <button type="button" onClick={() => void openDeletePreview(allMatchingSelected ? "matching" : "selected")} disabled={!selectedIds.length && !allMatchingSelected} className="rounded-2xl border border-danger/40 bg-danger/10 px-4 py-2 text-sm text-danger disabled:opacity-40">
            Delete selected detections
          </button>
          <button type="button" onClick={() => openFindingDialogFromDetectionIds(selectedIds)} disabled={!selectedIds.length} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted disabled:opacity-40">
            Create finding from selected detections
          </button>
          <button
            type="button"
            onClick={() => {
              setAllMatchingSelected(true);
              void openDeletePreview("matching");
            }}
            disabled={bulkDeleteMutation.isPending || !(detectionsQuery.data?.total)}
            className="rounded-2xl border border-danger/40 bg-danger/10 px-4 py-2 text-sm text-danger disabled:opacity-40"
          >
            Delete all filtered ({detectionsQuery.data?.total ?? 0})
          </button>
        </div>
        <p className="mt-3 text-xs text-muted">Findings and reports are not automatically deleted. Existing detections will remain unless you explicitly clean them.</p>
      </section>

      <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Triage overview</p>
            <h3 className="mt-2 text-xl font-semibold">Grouped detections</h3>
            <p className="mt-1 text-sm text-muted">Start from grouped evidence instead of a flat alert stream. Raw detections remain available for precise review.</p>
          </div>
          <div className="flex rounded-2xl border border-line bg-abyss/80 p-1">
            <button
              type="button"
              onClick={() => setViewMode("grouped")}
              className={`rounded-xl px-4 py-2 text-sm ${viewMode === "grouped" ? "bg-accent text-abyss" : "text-muted"}`}
            >
              Grouped
            </button>
            <button
              type="button"
              onClick={() => setViewMode("raw")}
              className={`rounded-xl px-4 py-2 text-sm ${viewMode === "raw" ? "bg-accent text-abyss" : "text-muted"}`}
            >
              Raw detections
            </button>
          </div>
        </div>

        <div className="mt-5 grid gap-3 md:grid-cols-4 xl:grid-cols-8">
          <div className="rounded-2xl border border-line bg-abyss/70 p-4">
            <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Total</p>
            <p className="mt-2 text-2xl font-semibold">{summary?.total ?? 0}</p>
          </div>
          <div className="rounded-2xl border border-line bg-abyss/70 p-4">
            <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">New</p>
            <p className="mt-2 text-2xl font-semibold">{summary?.new_vs_reviewed?.new ?? 0}</p>
          </div>
          <div className="rounded-2xl border border-line bg-abyss/70 p-4">
            <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Reviewed</p>
            <p className="mt-2 text-2xl font-semibold">{summary?.new_vs_reviewed?.reviewed ?? 0}</p>
          </div>
          <div className="rounded-2xl border border-line bg-abyss/70 p-4">
            <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Dismissed</p>
            <p className="mt-2 text-2xl font-semibold">{summary?.new_vs_reviewed?.dismissed ?? 0}</p>
          </div>
          <div className="rounded-2xl border border-line bg-abyss/70 p-4">
            <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Confirmed</p>
            <p className="mt-2 text-2xl font-semibold">{summary?.new_vs_reviewed?.confirmed ?? 0}</p>
          </div>
          <div className="rounded-2xl border border-line bg-abyss/70 p-4">
            <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">High/Critical</p>
            <p className="mt-2 text-2xl font-semibold">{(summary?.by_severity?.high ?? 0) + (summary?.by_severity?.critical ?? 0)}</p>
          </div>
          <div className="rounded-2xl border border-line bg-abyss/70 p-4">
            <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Hosts</p>
            <p className="mt-2 text-2xl font-semibold">{summary?.by_host?.length ?? 0}</p>
          </div>
          <div className="rounded-2xl border border-line bg-abyss/70 p-4">
            <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Evidence</p>
            <p className="mt-2 text-2xl font-semibold">{summary?.by_evidence?.length ?? 0}</p>
          </div>
        </div>
        {summary?.total === 0 && (summary.state?.soft_deleted ?? 0) > 0 ? (
          <div className="mt-4 rounded-2xl border border-danger/40 bg-danger/10 p-4 text-sm text-danger">
            No active detections match these filters, but {summary.state?.soft_deleted ?? 0} soft-deleted detections exist in this scope. Deleted detections stay hidden from triage unless explicitly recovered.
          </div>
        ) : null}

        <div className="mt-4 flex flex-wrap gap-3">
          <button type="button" onClick={() => setStatusFilter("new")} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">
            Show only new
          </button>
          <button type="button" onClick={() => setStatusFilter(statusFilter === "dismissed" ? "" : statusFilter)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">
            Hide dismissed
          </button>
          <button type="button" onClick={() => setSeverity("high")} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">
            High/Critical only
          </button>
          <button type="button" onClick={() => setEvidenceFilter(selectedEvidenceId || evidenceFilter)} disabled={!selectedEvidenceId && !evidenceFilter} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted disabled:opacity-40">
            Current evidence only
          </button>
        </div>

        {viewMode === "grouped" ? (
          <div className="mt-6 space-y-6">
            {!selectedGroup ? (
            <div className="space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <label className="text-sm text-muted">
                  Group by
                  <select
                    value={groupingMode}
                    onChange={(event) => {
                      setGroupingMode(event.target.value as GroupingMode);
                      closeGroup();
                    }}
                    className="ml-2 rounded-xl border border-line bg-abyss/80 px-3 py-2"
                  >
                    <option value="rule">Rule</option>
                    <option value="severity">Severity</option>
                    <option value="host">Host</option>
                    <option value="user">User</option>
                    <option value="artifact_type">Artifact type</option>
                    <option value="source_file">Source file</option>
                    <option value="evidence">Evidence</option>
                    <option value="rule_run">Rule run</option>
                  </select>
                </label>
                <span className="text-sm text-muted">{groupingItems.length} groups</span>
              </div>

              <div className="space-y-3">
                {groupingItems.length ? (
                  groupingItems.map((group) => (
                    <article key={`${group.mode}-${group.key}`} className="rounded-3xl border border-line bg-abyss/40 p-5">
                      <div className="flex flex-wrap items-start justify-between gap-4">
                        <div className="min-w-0">
                          <div className="flex flex-wrap gap-2">
                            {group.severity ? <span className="rounded-full border border-line px-2.5 py-1 font-mono text-[10px] uppercase tracking-[0.14em] text-accent">{group.severity}</span> : null}
                            <span className="rounded-full border border-line px-2.5 py-1 font-mono text-[10px] uppercase tracking-[0.14em] text-muted">{group.mode.replace("_", " ")}</span>
                          </div>
                          <h4 className="mt-3 break-words text-base font-semibold">{group.label}</h4>
                          <p className="mt-2 text-sm text-muted">{group.count} detections{group.meta ? ` · ${group.meta}` : ""}</p>
                          {group.first_seen || group.last_seen ? <p className="mt-1 text-xs text-muted">Seen {group.first_seen || "-"} to {group.last_seen || "-"}</p> : null}
                          {group.samples?.length ? <p className="mt-2 break-words text-xs text-muted">Samples: {group.samples.join(" · ")}</p> : null}
                        </div>
                        <p className="text-3xl font-semibold">{group.count}</p>
                      </div>
                      <div className="mt-4 flex flex-wrap gap-2">
                        <button type="button" onClick={() => openGroup(group)} className="rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss">
                          Open group
                        </button>
                        <button type="button" onClick={() => searchRelatedGroup(group)} className="rounded-2xl border border-line bg-panel/40 px-4 py-2 text-sm text-muted">
                          Search related events
                        </button>
                        <button type="button" onClick={() => bulkStatusGroup("mark_reviewed", group)} className="rounded-2xl border border-line bg-panel/40 px-4 py-2 text-sm text-muted">
                          Mark group reviewed
                        </button>
                        <button type="button" onClick={() => bulkStatusGroup("mark_dismissed", group)} className="rounded-2xl border border-line bg-panel/40 px-4 py-2 text-sm text-muted">
                          Dismiss group
                        </button>
                      </div>
                    </article>
                  ))
                ) : (
                  <div className="rounded-3xl border border-line bg-panel/40 p-6 text-sm text-muted">No grouped detections for the current filters.</div>
                )}
              </div>
            </div>
            ) : null}

            {!selectedGroup ? (
            <div className="space-y-4">
              <div className="rounded-3xl border border-line bg-abyss/50 p-5">
                <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Top noisy rules</p>
                <div className="mt-4 grid gap-3 lg:grid-cols-2">
                  {summary?.top_noisy_rules?.length ? (
                    summary.top_noisy_rules.map((rule) => (
                      <div key={`${rule.rule_id ?? "unknown"}-${rule.rule_name}`} className="rounded-2xl border border-line bg-panel/40 p-3">
                        <p className="break-words text-sm font-semibold">{rule.rule_name}</p>
                        <p className="mt-1 text-xs text-muted">{rule.severity || "unknown"} · {rule.count} detections · {rule.percentage ?? 0}%</p>
                        <div className="mt-3 flex flex-wrap gap-2">
                          <button type="button" onClick={() => openGroup({ mode: "rule", key: rule.rule_name, label: rule.rule_name, count: rule.count, rule_id: rule.rule_id })} className="rounded-xl border border-line px-3 py-1.5 text-xs text-muted">
                            Open group
                          </button>
                          <button type="button" onClick={() => searchRelatedGroup({ mode: "rule", key: rule.rule_name, label: rule.rule_name, count: rule.count, rule_id: rule.rule_id })} className="rounded-xl border border-line px-3 py-1.5 text-xs text-muted">
                            Search related
                          </button>
                        </div>
                      </div>
                    ))
                  ) : (
                    <p className="text-sm text-muted">No noisy rules for the current filters.</p>
                  )}
                </div>
              </div>

            </div>
            ) : null}

              {selectedGroup ? (
                <div className="rounded-[28px] border border-line bg-abyss/50 p-5 lg:p-6" data-testid="detection-group-detail-main">
                  <button type="button" onClick={closeGroup} className="rounded-2xl border border-line bg-panel/40 px-4 py-2 text-sm text-muted">
                    Back to grouped detections
                  </button>
                  <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Group detail</p>
                  <h4 className="mt-2 break-words text-3xl font-semibold">{selectedGroup.label}</h4>
                  <p className="mt-1 text-sm text-muted">{groupDetectionsQuery.data?.total ?? selectedGroup.count} matching detections</p>
                  <div className="mt-4 flex flex-wrap gap-2">
                    <span className="rounded-full border border-line px-3 py-1 font-mono text-[11px] uppercase tracking-[0.14em] text-muted">{selectedGroup.mode.replace("_", " ")}</span>
                    {selectedGroup.severity ? <span className="rounded-full border border-line px-3 py-1 font-mono text-[11px] uppercase tracking-[0.14em] text-accent">{selectedGroup.severity}</span> : null}
                    <span className="rounded-full border border-line px-3 py-1 font-mono text-[11px] uppercase tracking-[0.14em] text-muted">new {groupStatusBreakdown.new}</span>
                    <span className="rounded-full border border-line px-3 py-1 font-mono text-[11px] uppercase tracking-[0.14em] text-muted">reviewed {groupStatusBreakdown.reviewed}</span>
                    <span className="rounded-full border border-line px-3 py-1 font-mono text-[11px] uppercase tracking-[0.14em] text-muted">dismissed {groupStatusBreakdown.dismissed}</span>
                  </div>
                  <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
                    <div className="rounded-2xl border border-line bg-panel/40 p-4"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">First seen</p><p className="mt-2 break-words text-sm text-white">{selectedGroup.first_seen || "-"}</p></div>
                    <div className="rounded-2xl border border-line bg-panel/40 p-4"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Last seen</p><p className="mt-2 break-words text-sm text-white">{selectedGroup.last_seen || "-"}</p></div>
                    <div className="rounded-2xl border border-line bg-panel/40 p-4"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Affected hosts</p><p className="mt-2 break-words text-sm text-white">{selectedGroup.unique_hosts ?? groupEntitySummary.hosts.length}{groupEntitySummary.hosts.length ? ` · ${groupEntitySummary.hosts.slice(0, 3).join(" · ")}` : ""}</p></div>
                    <div className="rounded-2xl border border-line bg-panel/40 p-4"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Source files</p><p className="mt-2 break-words text-sm text-white">{(selectedGroup.sample_source_files ?? groupEntitySummary.sourceFiles).slice(0, 3).join(" · ") || "-"}</p></div>
                  </div>
                  <div className="mt-4 flex flex-wrap gap-2">
                    <button type="button" onClick={() => searchRelatedGroup(selectedGroup)} className="rounded-2xl bg-accent px-3 py-2 text-sm font-semibold text-abyss">
                      Search related events
                    </button>
                    <button type="button" onClick={() => bulkStatusGroup("mark_reviewed", selectedGroup)} className="rounded-2xl border border-line bg-panel/40 px-3 py-2 text-sm text-muted">
                      Mark reviewed
                    </button>
                    <button type="button" onClick={() => bulkStatusGroup("mark_dismissed", selectedGroup)} className="rounded-2xl border border-line bg-panel/40 px-3 py-2 text-sm text-muted">
                      Dismiss
                    </button>
                    <button type="button" onClick={() => bulkStatusGroup("mark_new", selectedGroup)} className="rounded-2xl border border-line bg-panel/40 px-3 py-2 text-sm text-muted">
                      Reopen group
                    </button>
                    <button type="button" onClick={promoteVisibleGroupToFinding} className="rounded-2xl border border-line bg-panel/40 px-3 py-2 text-sm text-muted">
                      Promote to finding
                    </button>
                  </div>
                  <div className="mt-6 flex flex-wrap gap-2 border-b border-line pb-3">
                    {(["overview", "detections", "events", "rule", "notes"] as GroupDetailTab[]).map((tab) => (
                      <button key={tab} type="button" onClick={() => setGroupTab(tab)} className={`rounded-2xl px-4 py-2 text-sm ${groupTab === tab ? "bg-accent text-abyss" : "border border-line bg-panel/40 text-muted"}`}>
                        {tab === "rule" ? "Rule details" : tab[0].toUpperCase() + tab.slice(1)}
                      </button>
                    ))}
                  </div>
                  {groupTab === "overview" ? (
                    <div className="mt-4 grid gap-4 xl:grid-cols-2">
                      <div className="rounded-2xl border border-line bg-panel/40 p-4">
                        <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Why this group matters</p>
                        <p className="mt-3 text-sm text-muted">This group concentrates related detections by {selectedGroup.mode.replace("_", " ")}. Review samples, linked events and rule context before changing status in bulk.</p>
                      </div>
                      <div className="rounded-2xl border border-line bg-panel/40 p-4">
                        <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Top entities</p>
                        <p className="mt-3 break-words text-sm text-muted">{(selectedGroup.samples ?? []).join(" · ") || groupEntitySummary.hosts.concat(groupEntitySummary.users).slice(0, 8).join(" · ") || "No sample entities available."}</p>
                      </div>
                    </div>
                  ) : null}
                  {groupTab === "detections" ? (
                    <div className="mt-4 space-y-3">
                      {groupDetectionsQuery.isLoading ? <p className="text-sm text-muted">Loading group detections...</p> : null}
                      {groupDetections.length ? (
                        groupDetections.map((detection) => (
                          <article key={detection.id} onClick={() => setSelectedDetectionId(detection.id)} className="cursor-pointer rounded-2xl border border-line bg-panel/40 p-4">
                            <div className="flex flex-wrap items-start justify-between gap-4">
                              <div className="min-w-0">
                                <p className="break-words text-sm font-semibold">{detection.rule_name}</p>
                                <p className="mt-1 break-words text-xs text-muted">{detection.message || "No detection message."}</p>
                                <p className="mt-2 font-mono text-[11px] text-muted">{detection.status} · {detection.severity || "unknown"} · {detection.host_name || "-"} · {detection.event_id || detection.opensearch_id || "linked event unavailable"}</p>
                                {Object.keys(detection.matched_fields || {}).length ? <p className="mt-1 break-words text-xs text-muted">Matched fields: {Object.keys(detection.matched_fields).join(", ")}</p> : null}
                              </div>
                              <div className="flex flex-wrap gap-2" onClick={(event) => event.stopPropagation()}>{renderDetectionActions(detection)}</div>
                            </div>
                          </article>
                        ))
                      ) : groupDetectionsQuery.isLoading ? null : (
                        <p className="text-sm text-muted">No detections loaded for this group.</p>
                      )}
                      <PaginationControls
                        page={groupPage}
                        totalPages={groupDetectionsQuery.data?.total_pages ?? 0}
                        total={groupDetectionsQuery.data?.total ?? 0}
                        totalRelation="eq"
                        pageSize={25}
                        onPageChange={setGroupPage}
                        onPageSizeChange={() => undefined}
                      />
                    </div>
                  ) : null}
                  {groupTab === "events" ? (
                    <div className="mt-4 space-y-3">
                      {groupDetections.map((detection) => (
                        <article key={`${detection.id}-event`} className="rounded-2xl border border-line bg-panel/40 p-4">
                          <p className="break-words text-sm font-semibold">{detection.event_id || detection.opensearch_id || "Linked event unavailable"}</p>
                          <p className="mt-1 text-xs text-muted">{detection.message || detection.rule_name}</p>
                          <div className="mt-3 flex flex-wrap gap-2">
                            {detection.event_id || detection.opensearch_id ? <button type="button" onClick={() => void openEvent(detection.id)} className="rounded-2xl border border-line bg-abyss/80 px-3 py-2 text-sm text-muted">Open event</button> : <span className="rounded-2xl border border-line bg-abyss/80 px-3 py-2 text-sm text-muted">Linked event missing</span>}
                            <button type="button" onClick={() => searchRelatedGroup(selectedGroup)} className="rounded-2xl border border-line bg-abyss/80 px-3 py-2 text-sm text-muted">Open in Search</button>
                            {detection.event_id && selectedCaseId ? <button type="button" onClick={() => { window.location.href = `/cases/${selectedCaseId}/timeline?around_event=${encodeURIComponent(detection.event_id || "")}`; }} className="rounded-2xl border border-line bg-abyss/80 px-3 py-2 text-sm text-muted">Related activity</button> : null}
                          </div>
                        </article>
                      ))}
                    </div>
                  ) : null}
                  {groupTab === "rule" ? (
                    <div className="mt-4 grid gap-4 xl:grid-cols-2">
                      <div className="rounded-2xl border border-line bg-panel/40 p-4 text-sm text-muted">
                        <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">{selectedGroup.mode === "rule" ? "Rule details" : "Rules involved"}</p>
                        {(groupDetections.length ? groupDetections : []).slice(0, 5).map((detection) => (
                          <div key={`${detection.id}-rule`} className="mt-3 border-t border-line pt-3 first:border-t-0 first:pt-0">
                            <p className="break-words text-white">{detection.rule_title || detection.rule_name}</p>
                            <p className="break-words">Rule ID: <span className="text-white">{detection.rule_id || "-"}</span></p>
                            <p className="break-words">Condition: <span className="text-white">{detection.condition_summary || "-"}</span></p>
                            <p className="break-words">Source pack: <span className="text-white">{detection.rule_source_pack || "-"}</span></p>
                          </div>
                        ))}
                      </div>
                      <div className="rounded-2xl border border-line bg-panel/40 p-4 text-sm text-muted">
                        <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Logsource and mappings</p>
                        <pre className="mt-3 max-h-72 overflow-auto whitespace-pre-wrap break-all text-xs text-white">{JSON.stringify(groupDetections[0]?.raw?.expected_logsource ?? groupDetections[0]?.raw?.coverage ?? {}, null, 2)}</pre>
                      </div>
                    </div>
                  ) : null}
                  {groupTab === "notes" ? (
                    <div className="mt-4 grid gap-4 xl:grid-cols-2">
                      <div className="rounded-2xl border border-line bg-panel/40 p-4">
                        <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Finding draft</p>
                        <p className="mt-3 text-sm text-muted">Create a finding from this group. The draft carries detection count, rule names, affected hosts, time range and sample events.</p>
                        <button type="button" onClick={promoteVisibleGroupToFinding} className="mt-4 rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss">Promote group to finding</button>
                      </div>
                      <div className="rounded-2xl border border-line bg-panel/40 p-4">
                        <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Analyst note</p>
                        <p className="mt-3 text-sm text-muted">Group-level notes are not persisted yet. Use Promote to finding to capture the investigation narrative.</p>
                      </div>
                    </div>
                  ) : null}
                </div>
              ) : (
                <div className="rounded-3xl border border-line bg-abyss/50 p-5 text-sm text-muted">Open a group to inspect sample detections, review status, or create a finding draft.</div>
              )}
          </div>
        ) : null}
      </section>

      {viewMode === "raw" ? (
      <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
        <div className="mb-4 flex items-center justify-between gap-4">
          <div>
            <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Results</p>
            <p className="mt-1 text-sm text-muted">{detectionsQuery.data?.total ?? 0} detections</p>
          </div>
        </div>
        <PaginationControls
          page={page}
          totalPages={detectionsQuery.data?.total_pages ?? 0}
          total={detectionsQuery.data?.total ?? 0}
          totalRelation="eq"
          pageSize={pageSize}
          onPageChange={setPage}
          onPageSizeChange={setPageSize}
        />
        <div className="mt-4 space-y-4">
          {detections.length ? (
            detections.map((detection) => {
              const preview = (detection.raw?.event_preview as Record<string, unknown> | undefined) ?? null;
              const caseName = (cases ?? []).find((item) => item.id === detection.case_id)?.name ?? detection.case_id;
              return (
                <article key={detection.id} data-testid={`detection-card-${detection.id}`} onClick={() => setSelectedDetectionId(detection.id)} className="cursor-pointer rounded-3xl border border-line bg-abyss/40 p-5">
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex items-start gap-4" onClick={(event) => event.stopPropagation()}>
                      <input type="checkbox" checked={selectedIds.includes(detection.id)} onChange={() => toggleSelected(detection.id)} className="mt-1" />
                      <div>
                        <h3 className="text-base font-semibold">{detection.rule_name}</h3>
                        <p className="mt-2 text-sm text-muted">{detection.message ?? "No detection message."}</p>
                        <p className="mt-3 font-mono text-xs text-muted">
                          Case: {caseName} · Source: {detection.source_engine || detection.engine} · Engine: {detection.engine} · Severity: {detection.severity || "unknown"} · Status: {detection.status}
                        </p>
                        <p className="mt-1 font-mono text-xs text-muted">
                          Matched event/file: {detection.target_type === "event" ? `Indexed event ${detection.event_id ?? detection.opensearch_id ?? "-"}` : detection.target_type === "file" ? `File ${detection.target_path ?? "-"}` : "Unknown"}
                        </p>
                        {detection.rule_title || detection.rule_author || detection.rule_version ? <p className="mt-1 text-xs text-muted">Rule: {detection.rule_title || detection.rule_name} · {detection.rule_author || "unknown author"} · {detection.rule_version || "no version"}</p> : null}
                        {detection.host_name ? <p className="mt-1 text-xs text-muted">Host: {detection.host_name}</p> : null}
                        {detection.evidence_id ? <p className="mt-1 font-mono text-xs text-muted">Evidence: {detection.evidence_id}</p> : null}
                        {(detection.raw?.match_reason as string | undefined) ? <p className="mt-1 text-xs text-muted">Reason: {String(detection.raw.match_reason)}</p> : null}
                        {detection.condition_summary ? <p className="mt-1 text-xs text-muted">Condition: {detection.condition_summary}</p> : null}
                        {detection.matched_strings?.length ? <p className="mt-1 text-xs text-muted">Matched strings: {detection.matched_strings.length}</p> : null}
                        {Object.keys(detection.matched_fields || {}).length ? <p className="mt-1 text-xs text-muted">Matched fields: {Object.keys(detection.matched_fields).join(", ")}</p> : null}
                        {preview ? (
                          <div className="mt-3 rounded-2xl border border-line bg-panel/40 p-3 text-xs text-muted">
                            <p>Event preview: {String(preview.summary ?? "No summary")}</p>
                            <p className="mt-1 font-mono">{String(preview.timestamp ?? "-")} · {String(preview.host ?? "-")} · {String(preview.user ?? "-")} · {String(preview.event_category ?? "-")} / {String(preview.event_type ?? "-")}</p>
                          </div>
                        ) : null}
                      </div>
                    </div>
                    <span className="rounded-full border border-line px-3 py-1 font-mono text-[11px] uppercase tracking-[0.16em] text-accent">{detection.target_type}</span>
                  </div>
                  <div className="mt-4 flex flex-wrap gap-3" onClick={(event) => event.stopPropagation()}>
                    {renderDetectionActions(detection)}
                  </div>
                </article>
              );
            })
          ) : (
            <div className="rounded-3xl border border-line bg-panel/40 p-6 text-sm text-muted">No detections yet for the current filters. Run Sigma/YARA rules or clear the current filters.</div>
          )}
        </div>
      </section>
      ) : null}

      {selectedDetection ? (
        <ResponsiveDetailPanel
          open
          mode="drawer"
          widthClass="h-full w-full sm:w-[88vw] xl:w-[82vw] 2xl:w-[78vw]"
          heading="Detection detail"
          subheading="Wide investigation detail aligned with Search, Findings and Timeline."
          onClose={() => setSelectedDetectionId(null)}
        >
          <div data-testid="detection-detail-panel" className="space-y-4">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div className="min-w-0 flex-1">
                <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Detection detail</p>
                <h3 className="mt-2 break-words text-2xl font-semibold">{selectedDetection.rule_name}</h3>
                <p className="mt-3 break-words text-sm text-muted">{selectedDetection.message ?? "No detection message."}</p>
                <div className="mt-3 flex flex-wrap gap-2">
                  <span className="rounded-full border border-line px-2.5 py-1 font-mono text-[10px] uppercase tracking-[0.14em] text-accent">{selectedDetection.target_type}</span>
                  <span className="rounded-full border border-line px-2.5 py-1 font-mono text-[10px] uppercase tracking-[0.14em] text-muted">{selectedDetection.source_engine || selectedDetection.engine}</span>
                  <span className="rounded-full border border-line px-2.5 py-1 font-mono text-[10px] uppercase tracking-[0.14em] text-muted">{selectedDetection.severity || "unknown"}</span>
                  <span className="rounded-full border border-line px-2.5 py-1 font-mono text-[10px] uppercase tracking-[0.14em] text-muted">{selectedDetection.status}</span>
                </div>
              </div>
              <div className="min-w-0 w-full space-y-2 md:w-[280px]">
                <div className="rounded-2xl border border-line bg-abyss/70 p-3 text-sm text-muted">
                  <p>Risk score: <span className="font-semibold text-white">{selectedDetection.risk_score ?? 0}</span></p>
                  <p className="break-words">Matched at: <span className="text-white">{selectedDetection.matched_at || "-"}</span></p>
                  <p className="break-words">Host: <span className="text-white">{selectedDetection.host_name || "-"}</span></p>
                </div>
              </div>
            </div>

            <div className="rounded-2xl border border-line bg-abyss/60 p-4">
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Actions</p>
              <div className="mt-3 flex flex-wrap gap-3">{renderDetectionActions(selectedDetection)}</div>
            </div>

            <div className="grid gap-4 xl:grid-cols-2">
              <div className="rounded-2xl border border-line bg-abyss/60 p-4 text-sm text-muted">
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Rule</p>
                <div className="mt-3 space-y-2">
                  <p className="break-words">Rule title: <span className="text-white">{selectedDetection.rule_title || selectedDetection.rule_name}</span></p>
                  <p className="break-words">Rule ID: <span className="text-white">{selectedDetection.rule_id}</span></p>
                  <p className="break-words">Version: <span className="text-white">{selectedDetection.rule_version || "-"}</span></p>
                  <p className="break-words">Author: <span className="text-white">{selectedDetection.rule_author || "-"}</span></p>
                  <p className="break-words">Condition: <span className="text-white">{selectedDetection.condition_summary || "-"}</span></p>
                </div>
              </div>
              <div className="rounded-2xl border border-line bg-abyss/60 p-4 text-sm text-muted">
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Matched target</p>
                <div className="mt-3 space-y-2">
                  <p className="break-words">Case: <span className="text-white">{selectedDetection.case_id}</span></p>
                  <p className="break-words">Evidence: <span className="text-white">{selectedDetection.evidence_id || "-"}</span></p>
                  <p className="break-words">Event/file: <span className="text-white">{selectedDetection.target_type === "event" ? selectedDetection.event_id || selectedDetection.opensearch_id || "-" : selectedDetection.target_path || "-"}</span></p>
                  <p className="break-words">Reason: <span className="text-white">{String(selectedDetection.raw?.match_reason || "-")}</span></p>
                </div>
              </div>
            </div>

            <div className="grid gap-4 xl:grid-cols-2">
              <div className="rounded-2xl border border-line bg-abyss/60 p-4 text-sm text-muted">
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Expected logsource</p>
                <pre className="mt-3 max-h-40 overflow-auto whitespace-pre-wrap break-all text-xs text-white">{JSON.stringify(selectedDetection.raw?.expected_logsource ?? {}, null, 2)}</pre>
              </div>
              <div className="rounded-2xl border border-line bg-abyss/60 p-4 text-sm text-muted">
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Actual event source</p>
                <pre className="mt-3 max-h-40 overflow-auto whitespace-pre-wrap break-all text-xs text-white">{JSON.stringify(selectedDetection.raw?.actual_event_source ?? {}, null, 2)}</pre>
              </div>
            </div>

            {selectedDetection.matched_strings?.length || Object.keys(selectedDetection.matched_fields || {}).length ? (
              <div className="grid gap-4 xl:grid-cols-2">
                <div className="rounded-2xl border border-line bg-abyss/60 p-4 text-sm text-muted">
                  <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Matched fields</p>
                  <div className="mt-3 space-y-2">
                    {Object.entries(selectedDetection.matched_fields || {}).map(([key, value]) => (
                      <p key={key} className="break-words"><span className="text-white">{key}</span>: {JSON.stringify(value)}</p>
                    ))}
                  </div>
                </div>
                <div className="rounded-2xl border border-line bg-abyss/60 p-4 text-sm text-muted">
                  <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Matched strings</p>
                  <div className="mt-3 space-y-2">
                    {(selectedDetection.matched_strings || []).map((value, index) => (
                      <p key={`${selectedDetection.id}-string-${index}`} className="break-words text-white">{String(value)}</p>
                    ))}
                  </div>
                </div>
              </div>
            ) : null}

            <details className="rounded-2xl border border-line bg-abyss/60 p-4">
              <summary className="cursor-pointer font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Raw JSON</summary>
              <pre className="mt-3 max-h-[24rem] overflow-auto whitespace-pre-wrap break-all text-xs text-muted">{JSON.stringify(selectedDetection.raw ?? {}, null, 2)}</pre>
            </details>
          </div>
        </ResponsiveDetailPanel>
      ) : null}

      <EventDetailDrawer open={previewOpen} loading={previewLoading} error={previewError} event={previewEvent} onClose={() => setPreviewOpen(false)} />
      {bulkPreviewOpen ? (
        <div className="fixed inset-0 z-40 flex items-center justify-center bg-abyss/80 p-4" data-testid="detection-bulk-preview-modal">
          <div className="w-full max-w-3xl rounded-[28px] border border-line bg-panel p-6 shadow-panel">
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Detection cleanup preview</p>
                <h3 className="mt-2 text-2xl font-semibold">Delete detections safely</h3>
                <p className="mt-2 text-sm text-muted">Preview the impact before deleting detections. Findings and reports are not deleted automatically.</p>
              </div>
              <button type="button" onClick={() => setBulkPreviewOpen(false)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">
                Close
              </button>
            </div>
            {bulkPreviewLoading ? <p className="mt-6 text-sm text-muted">Preparing deletion preview...</p> : null}
            {bulkPreviewError ? <p className="mt-6 text-sm text-danger">{bulkPreviewError}</p> : null}
            {bulkPreview ? (
              <div className="mt-6 space-y-4">
                <div className="grid gap-3 md:grid-cols-4">
                  <div className="rounded-2xl border border-line bg-abyss/60 p-4"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Matched</p><p className="mt-2 text-2xl font-semibold">{bulkPreview.matched}</p></div>
                  <div className="rounded-2xl border border-line bg-abyss/60 p-4"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Orphaned rules</p><p className="mt-2 text-2xl font-semibold">{bulkPreview.orphaned_rule_count}</p></div>
                  <div className="rounded-2xl border border-line bg-abyss/60 p-4"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Statuses</p><p className="mt-2 text-sm text-muted">{Object.entries(bulkPreview.by_status).map(([key, value]) => `${key}: ${value}`).join(" · ") || "None"}</p></div>
                  <div className="rounded-2xl border border-line bg-abyss/60 p-4"><p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Severities</p><p className="mt-2 text-sm text-muted">{Object.entries(bulkPreview.by_severity).map(([key, value]) => `${key}: ${value}`).join(" · ") || "None"}</p></div>
                </div>
                <div className="grid gap-4 lg:grid-cols-2">
                  <div className="rounded-2xl border border-line bg-abyss/60 p-4">
                    <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Top rules</p>
                    <div className="mt-3 space-y-2 text-sm text-muted">
                      {bulkPreview.by_rule.length ? bulkPreview.by_rule.map((item) => <p key={`${item.rule_id ?? "unknown"}-${item.title}`}>{item.title}: <span className="text-white">{item.count}</span></p>) : <p>No rule breakdown available.</p>}
                    </div>
                  </div>
                  <div className="rounded-2xl border border-line bg-abyss/60 p-4">
                    <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Warnings</p>
                    <ul className="mt-3 space-y-2 text-sm text-muted">
                      {bulkPreview.warnings.map((warning) => <li key={warning}>{warning}</li>)}
                    </ul>
                  </div>
                </div>
                {bulkPreview.matched > 25 || pendingDeleteMode !== "selected" ? (
                  <div className="rounded-2xl border border-danger/40 bg-danger/10 p-4">
                    <p className="text-sm text-danger">Type <span className="font-semibold">DELETE {bulkPreview.matched} DETECTIONS</span> to confirm this bulk delete.</p>
                    <input value={deleteConfirmText} onChange={(event) => setDeleteConfirmText(event.target.value)} className="mt-3 w-full rounded-xl border border-line bg-panel/70 px-3 py-2 text-sm" />
                  </div>
                ) : null}
                <div className="flex flex-wrap gap-3">
                  <button
                    type="button"
                    onClick={() => void confirmBulkDelete()}
                    disabled={bulkDeleteMutation.isPending || (!!bulkPreview && (bulkPreview.matched > 25 || pendingDeleteMode !== "selected") && deleteConfirmText !== `DELETE ${bulkPreview.matched} DETECTIONS`)}
                    className="rounded-2xl border border-danger/40 bg-danger/10 px-4 py-2 text-sm text-danger disabled:opacity-40"
                  >
                    Confirm delete
                  </button>
                  <button type="button" onClick={() => setBulkPreviewOpen(false)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">
                    Cancel
                  </button>
                </div>
              </div>
            ) : null}
          </div>
        </div>
      ) : null}
      <CreateFindingDialog
        open={findingDialogOpen}
        onClose={() => setFindingDialogOpen(false)}
        caseId={findingDialogCaseId}
        detectionIds={findingDetectionIds}
        defaultTitle={findingDefaultTitle}
        defaultDescription={findingDefaultDescription}
        defaultSeverity="medium"
        onCreated={() => {
          setSelectedIds([]);
          setFindingDetectionIds([]);
        }}
      />
    </div>
  );
}
