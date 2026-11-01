import { useEffect, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, Navigate, useParams, useSearchParams } from "react-router-dom";
import { HardDrive } from "lucide-react";

import { api, type Evidence } from "../api/client";
import EmptyState from "../components/EmptyState";
import { useActiveCase } from "../context/ActiveCaseContext";
import { browsableKind, isBrowsableEvidence } from "../lib/browsableEvidence";
import { diskFilesRoute } from "../lib/canonicalRoutes";

/** Every evidence of the case whose files can be browsed, by host. With a
 * single one there is nothing to choose: it opens the file explorer. */
export default function CaseFilesPage() {
  const { caseId = "" } = useParams();
  const [searchParams] = useSearchParams();
  const hostId = searchParams.get("host_id") || "";
  const { setActiveCaseId, caseContext } = useActiveCase();

  useEffect(() => {
    if (caseId) setActiveCaseId(caseId);
  }, [caseId, setActiveCaseId]);

  const evidencesQuery = useQuery({
    queryKey: ["case-evidences", caseId, "browsable"],
    queryFn: () => api.listEvidences(caseId),
    enabled: Boolean(caseId),
    staleTime: 15_000,
    refetchOnWindowFocus: false,
  });
  const hostNameById = useMemo(() => new Map((caseContext?.hosts ?? []).map((host) => [host.id, host.display_name || host.canonical_name])), [caseContext?.hosts]);
  const browsable = useMemo(
    () => (evidencesQuery.data ?? []).filter((item) => isBrowsableEvidence(item) && (!hostId || item.host_id === hostId)),
    [evidencesQuery.data, hostId],
  );
  const groups = useMemo(() => {
    const byHost = new Map<string, Evidence[]>();
    for (const item of browsable) {
      const name = (item.host_id && hostNameById.get(item.host_id)) || item.detected_host || item.provided_host || "Unassigned";
      byHost.set(name, [...(byHost.get(name) ?? []), item]);
    }
    return [...byHost.entries()].sort(([a], [b]) => a.localeCompare(b));
  }, [browsable, hostNameById]);

  if (browsable.length === 1) return <Navigate to={diskFilesRoute(caseId, browsable[0].id)} replace />;

  return (
    <div className="space-y-6">
      <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
        <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">Files</p>
        <h2 className="mt-2 text-3xl font-semibold">Browse evidence files</h2>
        <p className="mt-2 max-w-2xl text-sm text-muted">Disk images and collections of this case whose file system can be browsed, searched and exported.</p>
      </section>
      {evidencesQuery.isLoading ? <p className="text-sm text-muted">Loading evidence…</p> : null}
      {evidencesQuery.isError ? <p className="text-sm text-danger">The evidence of this case could not be loaded.</p> : null}
      {evidencesQuery.isSuccess && !browsable.length ? (
        <EmptyState
          title="No browsable evidence"
          description="Files can be browsed for disk images and for collections (archives, folders, AD1 images). This case has none yet."
          action={<Link to={`/cases/${caseId}/evidence`} className="rounded-2xl border border-line px-4 py-2 text-sm text-muted hover:text-ink">Go to evidence</Link>}
        />
      ) : null}
      {groups.map(([host, items]) => (
        <section key={host} className="rounded-[28px] border border-line bg-panel/70 p-5 shadow-panel">
          <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">{host}</p>
          <ul className="mt-3 space-y-2">
            {items.map((item) => (
              <li key={item.id}>
                <Link to={diskFilesRoute(caseId, item.id)} className="flex items-center gap-3 rounded-2xl border border-line bg-abyss/50 px-4 py-3 text-sm hover:border-accent/50">
                  <HardDrive size={16} className="shrink-0 text-accent" aria-hidden="true" />
                  <span className="min-w-0 flex-1 truncate text-ink">{item.original_filename}</span>
                  <span className="shrink-0 text-xs text-muted">{browsableKind(item)}</span>
                </Link>
              </li>
            ))}
          </ul>
        </section>
      ))}
    </div>
  );
}
