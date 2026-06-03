import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";

import DebugExportDialog from "../components/DebugExportDialog";
import { useActiveCase } from "../context/ActiveCaseContext";

export default function DebugExportPage() {
  const { caseId = "" } = useParams();
  const { setActiveCaseId } = useActiveCase();
  const [open, setOpen] = useState(false);

  useEffect(() => {
    if (caseId) setActiveCaseId(caseId);
  }, [caseId, setActiveCaseId]);

  if (!caseId) {
    return (
      <div className="rounded-[28px] border border-line bg-panel/70 p-8 shadow-panel text-sm text-muted">
        Select a case to export a debug pack.
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
        <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">Debug Export</p>
        <h2 className="mt-2 text-2xl font-semibold">Technical validation packs for ingest, graph, findings and rules.</h2>
        <p className="mt-2 max-w-3xl text-sm text-muted">
          Use debug export for technical validation and troubleshooting. For analyst-facing narrative output, use <span className="text-ink">Reports</span>.
        </p>
        <div className="mt-5 flex flex-wrap gap-3">
          <button onClick={() => setOpen(true)} className="rounded-2xl bg-accent px-4 py-3 text-sm font-semibold text-abyss">
            Export debug pack
          </button>
          <Link to={`/cases/${caseId}/reports`} className="rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm text-muted">
            Open Reports
          </Link>
          <Link to={`/cases/${caseId}/overview`} className="rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-sm text-muted">
            Back to Overview
          </Link>
        </div>
      </section>

      <section className="grid gap-4 md:grid-cols-3">
        <div className="rounded-2xl border border-line bg-panel/60 p-4 text-sm text-muted">
          <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Use for</p>
          <p className="mt-2">ingest regression, parser audit, timeline gaps, process graph validation and rules troubleshooting.</p>
        </div>
        <div className="rounded-2xl border border-line bg-panel/60 p-4 text-sm text-muted">
          <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Avoid confusion</p>
          <p className="mt-2">Debug packs are technical ZIP exports, not narrative case reports.</p>
        </div>
        <div className="rounded-2xl border border-line bg-panel/60 p-4 text-sm text-muted">
          <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Privacy</p>
          <p className="mt-2">They may include hostnames, usernames, paths and forensic metadata even with redaction enabled.</p>
        </div>
      </section>

      <DebugExportDialog
        open={open}
        onClose={() => setOpen(false)}
        caseId={caseId}
        title="Export case debug pack"
        defaultRequest={{
          scope: "case",
          max_events_per_type: 25,
          max_field_length: 2000,
          include_raw_samples: false,
          include_raw_xml: false,
          include_source_paths: true,
          include_cached_semiauto: true,
          rebuild_semiauto_for_export: false,
          redact_secrets: true,
          include_full_raw: false,
        }}
      />
    </div>
  );
}
