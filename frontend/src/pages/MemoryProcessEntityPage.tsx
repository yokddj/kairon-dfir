import { useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { AlertCircle, GitBranch, Loader2 } from "lucide-react";
import { api, ApiError, type MemoryProcessEntity, type MemoryProcessEntityDetail } from "../api/client";
import InvestigationContext from "../components/InvestigationContext";
import { EntityPageLayout, type EntityPageSection } from "../components/entities/EntityPageLayout";
import { BreadcrumbPath, Field, HandlesSection, ModulesSection, NetworkSection } from "../components/memory/ProcessDetailModal";
import { useActiveCase } from "../context/ActiveCaseContext";
import { memoryEvidenceRoute } from "../lib/canonicalRoutes";
import { memoryProcessEntityRoute } from "../lib/entityRoutes";
import {
  describeIdentityStrength,
  describeProcessVisibility,
  processEntityLabel,
  processVisibilityToneClass,
  reportedValue as reported,
  sourcePluginBadge as sourceBadge,
} from "../lib/memoryProcessEntityPresentation";
import { useInvestigationBreadcrumbs } from "../lib/useInvestigationBreadcrumbs";

// The only capability this page's breadcrumb ever anchors to -- memory
// process entities are always reached under the Memory / Execution /
// Processes capability, per CAPABILITY_REGISTRY.
const PROCESSES_CAPABILITY_ID = "memory.processes";

// A related entity (parent/child) always carries its own process_entity_id
// in this payload, so it can always be turned into a real link via the same
// route builder used everywhere else -- never a link built from PID/name.
function RelatedEntityLink({ caseId, entity }: { caseId: string; entity: MemoryProcessEntity }) {
  const to = memoryProcessEntityRoute(caseId, entity.process_entity_id);
  const label = processEntityLabel(entity) ?? entity.process_entity_id;
  if (!to) return <span className="font-mono text-ink">{label}</span>;
  return (
    <Link to={to} className="font-mono text-accent hover:underline" data-testid="entity-related-link">
      {label}
    </Link>
  );
}

export default function MemoryProcessEntityPage() {
  const { caseId = "", entityId = "" } = useParams();
  const { setActiveCaseId, activeCase } = useActiveCase();

  useEffect(() => {
    if (caseId) setActiveCaseId(caseId);
  }, [caseId, setActiveCaseId]);

  const detailQuery = useQuery<MemoryProcessEntityDetail>({
    queryKey: ["entity", "memory-process-entity", caseId, entityId],
    queryFn: () => api.getCanonicalProcessEntityDetail(caseId, entityId),
    enabled: Boolean(caseId && entityId),
    retry: false,
    refetchOnWindowFocus: false,
  });

  const entity = detailQuery.data?.entity;
  const entityLabel = processEntityLabel(entity) ?? undefined;

  const breadcrumbs = useInvestigationBreadcrumbs({
    entityTrail: { capabilityId: PROCESSES_CAPABILITY_ID, entityLabel },
  });

  const contextCard = (
    <InvestigationContext
      caseId={caseId}
      caseName={activeCase?.name}
      evidenceId={entity?.evidence_id}
      current="Process entity"
      breadcrumbs={breadcrumbs}
      actions={
        caseId
          ? [
              { label: "Search", to: `/cases/${caseId}/search?source_category=Memory`, description: "Search memory-derived documents" },
              ...(entity?.evidence_id
                ? [{ label: "Memory evidence", to: memoryEvidenceRoute(caseId, entity.evidence_id, "processes"), description: "Open the memory evidence this entity was derived from" }]
                : []),
            ]
          : []
      }
    />
  );

  if (!caseId || !entityId) {
    return (
      <div className="rounded-[28px] border border-line bg-panel/70 p-8 text-sm text-muted shadow-panel">
        A case and a process entity id are required to open this page.
      </div>
    );
  }

  if (detailQuery.isLoading) {
    return (
      <div className="space-y-5">
        {contextCard}
        <div className="space-y-2" role="status" aria-live="polite" data-testid="memory-process-entity-loading">
          <p className="text-sm text-muted">
            <Loader2 className="mr-1 inline h-4 w-4 animate-spin" /> Loading process entity…
          </p>
          {Array.from({ length: 3 }).map((_, index) => (
            <div key={index} className="h-16 animate-pulse rounded-2xl border border-line bg-abyss/40" />
          ))}
        </div>
      </div>
    );
  }

  if (detailQuery.isError) {
    const isNotFound = detailQuery.error instanceof ApiError && detailQuery.error.status === 404;
    return (
      <div className="space-y-5">
        {contextCard}
        <div
          className="rounded-2xl border border-rose-400/30 bg-rose-500/10 p-4 text-sm text-rose-100"
          role="alert"
          data-testid={isNotFound ? "memory-process-entity-not-found" : "memory-process-entity-error"}
        >
          <AlertCircle className="mr-1 inline h-4 w-4" />
          {isNotFound
            ? "This memory process entity was not found. It may belong to a different case, evidence or run, or the canonical entity id is no longer valid."
            : (detailQuery.error as Error)?.message || "Failed to load this process entity."}
        </div>
      </div>
    );
  }

  const detail = detailQuery.data;
  if (!detail || !entity) {
    return (
      <div className="space-y-5">
        {contextCard}
        <div className="rounded-2xl border border-line bg-abyss/40 p-4 text-sm text-muted" data-testid="memory-process-entity-not-found">
          This memory process entity was not found.
        </div>
      </div>
    );
  }

  const sources = entity.sources ?? [];
  const findings = detail.findings ?? [];
  const sourceRecordRefs = detail.source_record_refs ?? [];
  const alternateCommandLines = detail.alternate_command_lines ?? [];

  const sections: Array<EntityPageSection | null | false | undefined> = [
    {
      id: "overview",
      title: "Overview",
      content: (
        <div className="grid gap-3 md:grid-cols-3">
          <Field label="PID" value={reported(entity.process?.pid)} mono />
          <Field label="PPID" value={reported(entity.process?.ppid)} mono />
          <Field label="Process name" value={reported(entity.process?.name)} />
          <Field label="Executable" value={reported(entity.process?.executable_name)} />
          <Field label="Create time" value={reported(entity.process?.create_time)} mono />
          <Field label="Exit time" value={reported(entity.process?.exit_time)} mono />
          <Field label="Session ID" value={reported(entity.process?.session_id)} mono />
          <Field label="Visibility" value={describeProcessVisibility(entity)} />
          <Field label="Confidence" value={reported(entity.confidence)} />
          <Field label="Identity strength" value={describeIdentityStrength(entity)} />
          <Field label="Sources" value={sources.map(sourceBadge).join(", ") || "—"} />
        </div>
      ),
    },
    {
      id: "parent-children",
      title: "Parent and children",
      content: (
        <div className="space-y-3">
          <div>
            <p className="text-[10px] uppercase tracking-[0.16em] text-muted">Parent</p>
            <div className="mt-1 text-sm">
              {detail.parent ? <RelatedEntityLink caseId={caseId} entity={detail.parent} /> : <span className="text-muted">None (root)</span>}
            </div>
          </div>
          <div>
            <p className="text-[10px] uppercase tracking-[0.16em] text-muted">Children ({detail.children.length})</p>
            {detail.children.length ? (
              <ul className="mt-1 grid gap-1 text-sm">
                {detail.children.map((child) => (
                  <li key={child.process_entity_id} className="rounded-md border border-line bg-abyss/60 p-2">
                    <RelatedEntityLink caseId={caseId} entity={child} />
                  </li>
                ))}
              </ul>
            ) : (
              <p className="mt-1 text-sm text-muted">No children recorded.</p>
            )}
          </div>
          <div className="grid gap-2 md:grid-cols-2">
            <Field label="Tree state" value={entity.tree?.is_root ? "Root" : entity.tree?.is_orphan ? "Orphan" : "Child"} />
            <Field label="Missing parent state" value={entity.tree?.is_unknown_parent ? "Yes" : "No"} />
          </div>
        </div>
      ),
    },
    {
      id: "tree-path",
      title: "Tree path",
      content: <BreadcrumbPath treePath={detail.tree_path} />,
    },
    {
      id: "command-line",
      title: "Command line",
      content: (
        <div className="space-y-2">
          <div className="rounded-2xl border border-line bg-abyss/40 p-4">
            <p className="text-[10px] uppercase tracking-[0.18em] text-muted">Canonical command line</p>
            {entity.process?.command_line ? (
              <pre className="mt-2 max-h-48 overflow-y-auto whitespace-pre-wrap break-all font-mono text-xs text-ink">
                {entity.process.command_line}
              </pre>
            ) : (
              <p className="mt-2 text-xs text-muted">No command-line observation recorded for this process.</p>
            )}
          </div>
          {alternateCommandLines.length ? (
            <p className="text-[10px] text-muted">{alternateCommandLines.length} additional command-line variant(s) observed across sources.</p>
          ) : null}
        </div>
      ),
    },
    {
      id: "network",
      title: "Network",
      content: <NetworkSection caseId={caseId} evidenceId={entity.evidence_id} runId={entity.scan_run_id} pid={entity.process?.pid ?? null} />,
    },
    {
      id: "handles",
      title: "Handles",
      content: <HandlesSection caseId={caseId} evidenceId={entity.evidence_id} runId={entity.scan_run_id} pid={entity.process?.pid ?? null} />,
    },
    {
      id: "modules",
      title: "Modules",
      content: <ModulesSection caseId={caseId} evidenceId={entity.evidence_id} runId={entity.scan_run_id} pid={entity.process?.pid ?? null} />,
    },
    {
      id: "observations",
      title: `Observations (${detail.observations.length})`,
      content: (
        <div className="max-w-full overflow-x-auto rounded-2xl border border-line bg-abyss/40">
          <table className="min-w-[700px] w-full divide-y divide-line text-xs" data-testid="entity-observations-table">
            <thead className="bg-abyss/70 text-left text-[10px] uppercase tracking-[0.14em] text-muted">
              <tr>
                <th className="px-2 py-2">Plugin</th>
                <th className="px-2 py-2">PID</th>
                <th className="px-2 py-2">Name</th>
                <th className="px-2 py-2">Create</th>
                <th className="px-2 py-2">Source reference</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line/60">
              {detail.observations.map((observation) => {
                const observed = observation.observed as { pid?: number | null; name?: string | null; create_time?: string | null } | undefined;
                return (
                  <tr key={observation.document_id || `${entity.process_entity_id}-${observation.plugin_name}`}>
                    <td className="px-2 py-1.5 text-ink">{sourceBadge(observation.plugin_name)}</td>
                    <td className="px-2 py-1.5 text-muted">{reported(observed?.pid)}</td>
                    <td className="px-2 py-1.5 text-ink">{reported(observed?.name)}</td>
                    <td className="px-2 py-1.5 text-muted">{reported(observed?.create_time)}</td>
                    <td className="px-2 py-1.5 text-muted">{reported(observation.source_record_id)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ),
    },
    {
      id: "findings",
      title: `Findings (${findings.length})`,
      content: findings.length ? (
        <ul className="flex flex-wrap gap-2" data-testid="entity-findings-list">
          {findings.map((finding) => (
            <li key={finding} className="rounded-md border border-amber-400/30 bg-amber-500/10 px-2 py-0.5 text-xs text-amber-100">
              {finding}
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-sm text-muted">No findings recorded for this entity.</p>
      ),
    },
    {
      id: "source-records",
      title: `Source records (${sourceRecordRefs.length})`,
      content: sourceRecordRefs.length ? (
        <ul className="space-y-2" data-testid="entity-source-records-list">
          {sourceRecordRefs.map((ref) => (
            <li key={ref} className="rounded-md border border-line bg-abyss/60 p-2 text-xs">
              <span className="font-mono text-ink">{ref}</span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-sm text-muted">No raw references recorded for this entity.</p>
      ),
    },
  ];

  return (
    <EntityPageLayout
      breadcrumbs={contextCard}
      header={
        <div>
          <p className="text-[10px] uppercase tracking-[0.18em] text-muted">Memory process entity</p>
          <h1 className="mt-1 flex flex-wrap items-center gap-2 text-xl font-semibold text-ink" data-testid="entity-page-title">
            <GitBranch className="h-4 w-4 text-muted" />
            {reported(entity.process?.name)} <span className="font-mono text-sm text-muted">PID {reported(entity.process?.pid)}</span>
          </h1>
          <div className="mt-2 flex flex-wrap items-center gap-2 text-[11px]">
            <span className={`rounded-md border px-2 py-0.5 ${processVisibilityToneClass(entity)}`} data-testid="entity-visibility">
              {describeProcessVisibility(entity)}
            </span>
            <span className="rounded-md border border-line bg-abyss/70 px-2 py-0.5 text-muted" data-testid="entity-identity-strength">
              Identity: {describeIdentityStrength(entity)}
            </span>
          </div>
        </div>
      }
      sections={sections}
    />
  );
}
