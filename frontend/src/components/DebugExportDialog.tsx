import { useEffect, useState } from "react";
import { api, type DebugExportRequest } from "../api/client";

type Props = {
  open: boolean;
  onClose: () => void;
  caseId: string;
  defaultRequest: DebugExportRequest;
  title?: string;
};

function extractFilename(contentDisposition: string | undefined, fallback: string) {
  const value = contentDisposition || "";
  const match = value.match(/filename=\"?([^\";]+)\"?/i);
  return match?.[1] || fallback;
}

export default function DebugExportDialog({ open, onClose, caseId, defaultRequest, title = "Export debug pack" }: Props) {
  const [payload, setPayload] = useState<DebugExportRequest>(defaultRequest);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      setPayload(defaultRequest);
      setError(null);
      setBusy(false);
    }
  }, [defaultRequest, open]);

  if (!open) return null;

  async function handleExport() {
    if (payload.include_full_raw && !window.confirm("Full raw content can contain sensitive forensic material and large data. Continue?")) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const canUseDirectDownload =
        payload.scope === "case" ||
        payload.scope === "evidence" ||
        payload.scope === "artifact_type" ||
        payload.scope === "semiauto";
      if (canUseDirectDownload) {
        const directUrl = api.buildDebugPackDownloadUrl(caseId, payload);
        const anchor = document.createElement("a");
        anchor.href = directUrl;
        anchor.download = `debug_pack_${caseId}.zip`;
        document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();
        onClose();
        return;
      }
      const result = await api.exportDebugPack(caseId, payload);
      const filename = extractFilename(result.filename, `debug_pack_${caseId}.zip`);
      const url = URL.createObjectURL(result.blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = filename;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
      onClose();
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Debug export failed.");
    } finally {
      setBusy(false);
    }
  }

  function update<K extends keyof DebugExportRequest>(key: K, value: DebugExportRequest[K]) {
    setPayload((current) => ({ ...current, [key]: value }));
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-abyss/80 px-4">
      <div className="w-full max-w-3xl rounded-[28px] border border-line bg-panel p-6 shadow-panel">
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">Validation / Debug Export</p>
            <h3 className="mt-2 text-2xl font-semibold">{title}</h3>
            <p className="mt-2 text-sm text-muted">Debug packs may contain hostnames, usernames, file paths, domains and forensic metadata. Review before sharing.</p>
          </div>
          <button onClick={onClose} className="rounded-full border border-line px-3 py-1 text-sm text-muted">Close</button>
        </div>
        <div className="mt-6 grid gap-4 md:grid-cols-2">
          <label className="block">
            <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Scope</span>
            <select value={payload.scope} onChange={(event) => update("scope", event.target.value as DebugExportRequest["scope"])} className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm">
              <option value="case">case</option>
              <option value="evidence">evidence</option>
              <option value="selected_events">selected_events</option>
              <option value="search">search</option>
              <option value="artifact_type">artifact_type</option>
              <option value="semiauto">semiauto</option>
            </select>
          </label>
          <label className="block">
            <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Max events per type</span>
            <input type="number" min={1} max={250} value={payload.max_events_per_type ?? 25} onChange={(event) => update("max_events_per_type", Number(event.target.value))} className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm" />
          </label>
          <label className="block">
            <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Max field length</span>
            <input type="number" min={200} max={20000} value={payload.max_field_length ?? 2000} onChange={(event) => update("max_field_length", Number(event.target.value))} className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm" />
          </label>
          <div className="grid gap-2 rounded-2xl border border-line bg-abyss/40 p-4 text-sm text-muted">
            <label className="flex items-center gap-2"><input type="checkbox" checked={payload.include_raw_samples ?? false} onChange={(event) => update("include_raw_samples", event.target.checked)} />Include raw samples</label>
            <label className="flex items-center gap-2"><input type="checkbox" checked={payload.include_raw_xml ?? false} onChange={(event) => update("include_raw_xml", event.target.checked)} />Include raw XML</label>
            <label className="flex items-center gap-2"><input type="checkbox" checked={payload.include_source_paths ?? true} onChange={(event) => update("include_source_paths", event.target.checked)} />Include source paths</label>
            <label className="flex items-center gap-2"><input type="checkbox" checked={payload.redact_secrets ?? true} onChange={(event) => update("redact_secrets", event.target.checked)} />Redact secrets</label>
            <label className="flex items-center gap-2"><input type="checkbox" checked={payload.include_cached_semiauto ?? true} onChange={(event) => update("include_cached_semiauto", event.target.checked)} />Include cached semiauto</label>
            <label className="flex items-center gap-2"><input type="checkbox" checked={payload.rebuild_semiauto_for_export ?? false} onChange={(event) => update("rebuild_semiauto_for_export", event.target.checked)} />Rebuild semiauto if missing</label>
            <label className="flex items-center gap-2"><input type="checkbox" checked={payload.include_full_raw ?? false} onChange={(event) => update("include_full_raw", event.target.checked)} />Include full raw (dangerous)</label>
          </div>
        </div>
        {error ? <div className="mt-4 rounded-2xl border border-danger/30 bg-danger/10 p-3 text-sm text-danger">{error}</div> : null}
        <div className="mt-6 flex flex-wrap justify-end gap-3">
          <button onClick={onClose} className="rounded-2xl border border-line px-4 py-2 text-sm text-muted">Cancel</button>
          <button onClick={handleExport} disabled={busy} className="rounded-2xl border border-accent/40 bg-accent/15 px-4 py-2 text-sm text-accent disabled:opacity-50">
            {busy ? "Generating..." : "Export debug pack"}
          </button>
        </div>
      </div>
    </div>
  );
}
