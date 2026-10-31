import { useEffect, useMemo, useState } from "react";
import type { FormEvent } from "react";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { FolderTree } from "lucide-react";

import { api, type DiskFileEntry, type DiskFileStatus, type DiskFileVolume } from "../api/client";
import { formatBytes } from "../lib/evidenceDetailFormatting";

const STATUS_LABEL: Record<DiskFileStatus, string> = {
  allocated: "",
  deleted: "Deleted",
  deleted_inode_reused: "Deleted · inode reused",
  deleted_metadata_lost: "Deleted · name only",
  deleted_journal: "Deleted · from journal",
};
const STATUS_HINT: Record<DiskFileStatus, string> = {
  allocated: "",
  deleted: "The inode was not reused: the content may still be recoverable (NTFS/FAT usually; ext3/ext4 clear the block pointers).",
  deleted_inode_reused: "The inode now belongs to another file. Its content is not this file's, so it is not exported.",
  deleted_metadata_lost: "Only the name survives in the directory.",
  deleted_journal: "No longer in the directory: the name comes from an older copy of it in the ext3/ext4 journal. The content can be rebuilt when the journal also kept the file's inode from that time.",
};
type SortKey = "name" | "size" | "mtime";

function fmtEpoch(value: number | null | undefined) {
  if (!value) return "-";
  return new Date(value * 1000).toISOString().replace("T", " ").slice(0, 19);
}

function volumeLabel(volume: DiskFileVolume) {
  if (volume.file_count !== undefined) return [volume.filesystem_type, `${volume.file_count.toLocaleString()} files`, formatBytes(volume.length_bytes)].join(" · ");
  const install = volume.installations[0];
  const name = volume.logical_volume ? `LV ${volume.logical_volume}` : `Partition ${volume.partition_index}`;
  const parts = [name, volume.filesystem_type ?? "unknown filesystem", formatBytes(volume.length_bytes)];
  if (install) parts.push(install.hostname ? `${install.hostname} (${install.distro ?? install.platform})` : install.distro ?? install.platform);
  return parts.join(" · ");
}

function parentOf(path: string) {
  const index = path.replace(/\/+$/, "").lastIndexOf("/");
  return index <= 0 ? "/" : path.slice(0, index);
}

function saveBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

export default function DiskFilesPage() {
  const { caseId = "", evidenceId = "" } = useParams();
  const [searchParams, setSearchParams] = useSearchParams();
  const path = searchParams.get("path") || "/";
  const inodeParam = searchParams.get("inode");
  const inode = inodeParam !== null && inodeParam !== "" ? Number(inodeParam) : null;
  const highlight = searchParams.get("file") ?? "";
  const searchTerm = searchParams.get("q") ?? "";
  const showDeleted = searchParams.get("deleted") !== "0";
  const [draft, setDraft] = useState(searchTerm);
  const [selected, setSelected] = useState<Record<string, DiskFileEntry>>({});
  const [sort, setSort] = useState<{ key: SortKey; desc: boolean }>({ key: "name", desc: false });
  const [exporting, setExporting] = useState(false);
  const [notice, setNotice] = useState<{ tone: "ok" | "error"; text: string } | null>(null);

  const volumesQuery = useQuery({ queryKey: ["disk-file-volumes", caseId, evidenceId], queryFn: () => api.getDiskFileVolumes(caseId, evidenceId), enabled: Boolean(caseId && evidenceId) });
  const volumes = volumesQuery.data?.volumes ?? [];
  const partitionParam = searchParams.get("partition");
  const volumeId = useMemo(() => {
    const requested = searchParams.get("volume");
    if (requested && volumes.some((volume) => volume.id === requested)) return requested;
    const byPartition = partitionParam !== null ? volumes.find((volume) => String(volume.partition_index) === partitionParam && volume.browsable) : undefined;
    return (byPartition ?? volumes.find((volume) => volume.browsable && volume.installations.length) ?? volumes.find((volume) => volume.browsable))?.id ?? "";
  }, [partitionParam, searchParams, volumes]);
  const volume = volumes.find((item) => item.id === volumeId);
  const isCollection = volumesQuery.data?.kind === "collection";

  const listingQuery = useQuery({
    queryKey: ["disk-files", caseId, evidenceId, volumeId, path, inode],
    queryFn: () => api.listDiskFiles(caseId, evidenceId, volumeId, { path, inode }),
    enabled: Boolean(volumeId) && !searchTerm,
    placeholderData: keepPreviousData,
  });
  const searchQuery = useQuery({
    queryKey: ["disk-files-find", caseId, evidenceId, volumeId, searchTerm, showDeleted],
    queryFn: () => api.findDiskFiles(caseId, evidenceId, volumeId, { q: searchTerm, include_deleted: showDeleted }),
    enabled: Boolean(volumeId && searchTerm),
  });

  useEffect(() => setSelected({}), [volumeId, path, inode, searchTerm]);
  useEffect(() => setDraft(searchTerm), [searchTerm]);

  function update(changes: Record<string, string | null>) {
    const next = new URLSearchParams(searchParams);
    for (const [key, value] of Object.entries(changes)) {
      if (value === null || value === "") next.delete(key);
      else next.set(key, value);
    }
    setSearchParams(next);
  }
  function openDirectory(entry: { path: string; inode?: number | null; status?: DiskFileStatus }) {
    // A deleted directory has no path that resolves any more: it is opened by inode.
    update({ path: entry.path, inode: entry.status && entry.status !== "allocated" && entry.inode ? String(entry.inode) : null, file: null, q: null, partition: null, volume: volumeId });
  }
  function submitSearch(event: FormEvent) {
    event.preventDefault();
    update({ q: draft.trim() || null, file: null });
  }

  const rows = useMemo(() => {
    const source = searchTerm ? searchQuery.data?.results ?? [] : listingQuery.data?.entries ?? [];
    const visible = showDeleted ? source : source.filter((entry) => entry.status === "allocated");
    const direction = sort.desc ? -1 : 1;
    return [...visible].sort((a, b) => {
      if (!searchTerm && (a.kind === "dir") !== (b.kind === "dir")) return a.kind === "dir" ? -1 : 1;
      if (sort.key === "size") return ((a.size ?? -1) - (b.size ?? -1)) * direction;
      if (sort.key === "mtime") return ((a.mtime ?? 0) - (b.mtime ?? 0)) * direction;
      return a.name.localeCompare(b.name) * direction;
    });
  }, [listingQuery.data, searchQuery.data, searchTerm, showDeleted, sort]);

  const selectedItems = Object.values(selected);
  const activeQuery = searchTerm ? searchQuery : listingQuery;
  const deletedCount = (searchTerm ? searchQuery.data?.results : listingQuery.data?.entries)?.filter((entry) => entry.status !== "allocated").length ?? 0;

  async function download(items: DiskFileEntry[]) {
    if (!items.length) return;
    setExporting(true);
    setNotice(null);
    try {
      const result = await api.exportDiskFiles(caseId, evidenceId, volumeId, items.map((item) => ({ path: item.path, inode: item.inode, parent_inode: item.parent_inode ?? null })), showDeleted);
      saveBlob(result.blob, result.filename);
      const [done, total] = result.summary.split("/");
      setNotice({ tone: "ok", text: `${result.filename}: ${done ?? "?"} of ${total ?? "?"} files exported. The details of each file (hashes, what could not be recovered and why) are in kairon-export.json inside the ZIP.` });
    } catch (error) {
      setNotice({ tone: "error", text: error instanceof Error ? error.message : String(error) });
    } finally {
      setExporting(false);
    }
  }

  function toggle(entry: DiskFileEntry) {
    setSelected((current) => {
      const next = { ...current };
      if (next[entry.path]) delete next[entry.path];
      else next[entry.path] = entry;
      return next;
    });
  }
  function sortBy(key: SortKey) {
    setSort((current) => ({ key, desc: current.key === key ? !current.desc : key !== "name" }));
  }

  const segments = path.split("/").filter(Boolean);
  const errorMessage = (volumesQuery.error ?? activeQuery.error) as Error | null;

  return (
    <div className="space-y-5">
      <section className="rounded-[28px] border border-line bg-panel p-6 shadow-panel">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p className="flex items-center gap-2 font-mono text-xs uppercase tracking-[0.18em] text-accent"><FolderTree size={14} /> {isCollection ? "Collection files" : "Disk files"}</p>
            <h2 className="mt-2 break-words text-2xl font-semibold">{volumesQuery.data?.image_name ?? "Disk image"}</h2>
            <p className="mt-1 text-sm text-muted">
              {isCollection
                ? volumesQuery.data?.format === "ad1"
                  ? "Browse the files of the AD1 logical image and export them. Times, MD5/SHA1, owner and attributes are the ones FTK recorded at acquisition. A logical image holds no deleted files or inodes. Read-only."
                  : "Browse the files of the collection and export them. A collection holds copies of files, not a filesystem: no deleted entries or inodes. Read-only."
                : "Browse the filesystem as it is in the image, including deleted entries, and export files. Read-only: the image is never modified."}
            </p>
          </div>
          <Link to={`/evidences/${evidenceId}`} className="rounded-2xl border border-line px-4 py-2 text-sm text-muted">Back to evidence</Link>
        </div>
        <div className="mt-4 rounded-2xl border border-amber/40 bg-amber/10 p-3 text-sm text-amber" data-testid="export-warning">
          Exports are downloaded as a ZIP protected with the password <span className="font-mono font-semibold">{volumesQuery.data?.archive_password ?? "infected"}</span>. They may contain malware: open them only inside an analysis environment.
        </div>
        {volumes.length ? (
          <label className="mt-4 block text-sm text-muted">
            Volume
            <select aria-label="Volume" value={volumeId} onChange={(event) => update({ volume: event.target.value, partition: null, path: null, inode: null, file: null, q: null })} className="mt-1 block w-full rounded-2xl border border-line bg-abyss px-3 py-2 text-ink">
              {volumes.map((item) => (
                <option key={item.id} value={item.id} disabled={!item.browsable}>{volumeLabel(item)}{item.browsable ? "" : ` — ${item.unavailable_reason}`}</option>
              ))}
            </select>
          </label>
        ) : null}
        {volumesQuery.data && !volumes.some((item) => item.browsable) ? (
          <p className="mt-4 rounded-2xl border border-line bg-abyss/70 p-3 text-sm text-muted" data-testid="no-browsable-volume">
            {volumes[0]?.unavailable_reason ?? "This image has no volume with a readable filesystem."}
          </p>
        ) : null}
      </section>

      {volume ? (
        <section className="rounded-[24px] border border-line bg-panel p-5 shadow-panel">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <nav aria-label="Path" className="flex flex-wrap items-center gap-1 font-mono text-sm" data-testid="path-bar">
              <button type="button" onClick={() => openDirectory({ path: "/" })} className="rounded-lg px-2 py-1 text-accent hover:bg-abyss">/</button>
              {segments.map((segment, index) => {
                const target = `/${segments.slice(0, index + 1).join("/")}`;
                return (
                  <span key={target} className="flex items-center gap-1">
                    {index ? <span className="text-muted">/</span> : null}
                    <button type="button" onClick={() => openDirectory({ path: target })} className="rounded-lg px-2 py-1 text-accent hover:bg-abyss">{segment}</button>
                  </span>
                );
              })}
              {inode !== null ? <span className="ml-2 rounded-full border border-danger/40 px-2 text-[11px] text-danger">deleted directory · inode {inode}</span> : null}
            </nav>
            <form onSubmit={submitSearch} className="flex flex-wrap items-center gap-2">
              <input aria-label="Find files" value={draft} onChange={(event) => setDraft(event.target.value)} placeholder="Name or glob (*.php, /etc/*cron*)" className="w-72 rounded-2xl border border-line bg-abyss px-3 py-2 text-sm" />
              <button type="submit" className="rounded-2xl border border-accent/40 bg-accent/10 px-3 py-2 text-sm text-accent">Find</button>
              {searchTerm ? <button type="button" onClick={() => update({ q: null })} className="rounded-2xl border border-line px-3 py-2 text-sm text-muted">Clear search</button> : null}
            </form>
          </div>
          <div className="mt-3 flex flex-wrap items-center justify-between gap-3 text-sm">
            {isCollection ? <span /> : <label className="flex items-center gap-2 text-muted">
              <input type="checkbox" checked={showDeleted} onChange={(event) => update({ deleted: event.target.checked ? null : "0" })} />
              Show deleted entries{deletedCount ? ` (${deletedCount})` : ""}
            </label>}
            <div className="flex items-center gap-2">
              {searchTerm && searchQuery.data ? (
                <span className="text-muted">{searchQuery.data.results.length} matches · {searchQuery.data.scanned.toLocaleString()} entries scanned{searchQuery.data.truncated ? " · stopped early, refine the pattern" : ""}</span>
              ) : null}
              {!searchTerm && listingQuery.data?.truncated ? <span className="text-amber">Showing {listingQuery.data.entries.length} of {listingQuery.data.total} entries</span> : null}
              <button type="button" disabled={!selectedItems.length || exporting} onClick={() => void download(selectedItems)} className="rounded-2xl border border-accent/40 bg-accent/10 px-3 py-2 text-accent disabled:opacity-40">
                {exporting ? "Exporting…" : `Download selected (${selectedItems.length})`}
              </button>
            </div>
          </div>
          {notice ? <p className={`mt-3 rounded-2xl border p-3 text-sm ${notice.tone === "ok" ? "border-mint/40 bg-mint/10 text-mint" : "border-danger/40 bg-danger/10 text-danger"}`} data-testid="export-notice">{notice.text}</p> : null}
          {errorMessage ? <p className="mt-3 rounded-2xl border border-danger/40 bg-danger/10 p-3 text-sm text-danger">{errorMessage.message}</p> : null}
          {activeQuery.isFetching && !rows.length ? <p className="mt-3 text-sm text-muted">{searchTerm ? "Searching the filesystem…" : "Reading directory…"}</p> : null}

          <div className="mt-4 overflow-x-auto">
            <table className="min-w-full text-left text-sm" data-testid="disk-files">
              <thead className="text-xs uppercase tracking-[0.14em] text-muted">
                <tr>
                  <th className="px-2 py-2"><span className="sr-only">Select</span></th>
                  <th className="px-3 py-2"><button type="button" onClick={() => sortBy("name")}>Name</button></th>
                  <th className="px-3 py-2">Status</th>
                  <th className="px-3 py-2"><button type="button" onClick={() => sortBy("size")}>Size</button></th>
                  <th className="whitespace-nowrap px-3 py-2"><button type="button" onClick={() => sortBy("mtime")}>Modified (UTC)</button></th>
                  <th className="whitespace-nowrap px-3 py-2">Accessed</th>
                  <th className="whitespace-nowrap px-3 py-2">Changed</th>
                  <th className="whitespace-nowrap px-3 py-2">Created</th>
                  <th className="px-3 py-2">Owner</th>
                  <th className="px-3 py-2">{isCollection ? "MD5 (acquisition)" : "Inode"}</th>
                  <th className="px-3 py-2"><span className="sr-only">Actions</span></th>
                </tr>
              </thead>
              <tbody>
                {!searchTerm && path !== "/" ? (
                  <tr className="border-t border-line">
                    <td />
                    <td className="px-3 py-2" colSpan={10}><button type="button" onClick={() => openDirectory({ path: parentOf(path) })} className="font-mono text-accent">..</button></td>
                  </tr>
                ) : null}
                {rows.map((entry) => {
                  const deleted = entry.status !== "allocated";
                  const exportable = entry.status !== "deleted_inode_reused" && entry.status !== "deleted_metadata_lost" && (entry.kind === "file" || (entry.kind === "dir" && !deleted)) && !(entry.status === "deleted_journal" && entry.journal_last_seq == null);
                  const canOpen = entry.kind === "dir" && (!deleted || entry.status === "deleted");
                  return (
                    <tr key={`${entry.path}-${entry.inode}`} data-testid="disk-file-row" className={`border-t border-line ${!searchTerm && entry.name === highlight ? "bg-accent/10" : ""} ${deleted ? "text-muted" : ""}`}>
                      <td className="px-2 py-2">
                        <input type="checkbox" aria-label={`Select ${entry.name}`} disabled={!exportable} checked={Boolean(selected[entry.path])} onChange={() => toggle(entry)} />
                      </td>
                      <td className="max-w-[28rem] px-3 py-2 font-mono">
                        {canOpen ? (
                          <button type="button" onClick={() => openDirectory(entry)} className={`break-all text-left ${deleted ? "text-danger line-through decoration-danger/40" : "text-accent"}`}>{searchTerm ? entry.path : entry.name}/</button>
                        ) : (
                          <span className={`break-all ${deleted ? "text-danger line-through decoration-danger/40" : "text-ink"}`}>{searchTerm ? entry.path : entry.name}{entry.kind === "symlink" ? " →" : ""}</span>
                        )}
                        {entry.attributes?.filter((attribute) => attribute === "hidden" || attribute === "system").map((attribute) => (
                          <span key={attribute} className="ml-2 rounded-full border border-line px-1.5 text-[10px] uppercase text-muted">{attribute}</span>
                        ))}
                        {searchTerm ? <button type="button" onClick={() => update({ q: null, path: parentOf(entry.path), inode: null, file: entry.name })} className="ml-2 text-[11px] text-muted underline">show in folder</button> : null}
                      </td>
                      <td className="whitespace-nowrap px-3 py-2">{deleted ? <span title={STATUS_HINT[entry.status]} className="rounded-full border border-danger/40 bg-danger/10 px-2 py-0.5 text-[11px] text-danger">{STATUS_LABEL[entry.status]}</span> : null}
                        {entry.status === "deleted_journal" && (entry.journal_last_seen || entry.journal_gone_by) ? (
                          <p className="mt-1 font-mono text-[11px] text-muted" data-testid="journal-times">
                            {entry.journal_last_seen ? `seen ${fmtEpoch(entry.journal_last_seen)}` : ""}{entry.journal_gone_by ? ` · gone by ${fmtEpoch(entry.journal_gone_by)}` : ""}
                          </p>
                        ) : null}
                      </td>
                      <td className="whitespace-nowrap px-3 py-2">{entry.kind === "dir" ? "" : entry.size === null ? "-" : entry.size === 0 ? "0" : formatBytes(entry.size)}</td>
                      <td className="whitespace-nowrap px-3 py-2 font-mono text-xs">{fmtEpoch(entry.mtime)}</td>
                      <td className="whitespace-nowrap px-3 py-2 font-mono text-xs text-muted">{fmtEpoch(entry.atime)}</td>
                      <td className="whitespace-nowrap px-3 py-2 font-mono text-xs text-muted">{fmtEpoch(entry.ctime)}</td>
                      <td className="whitespace-nowrap px-3 py-2 font-mono text-xs text-muted">{fmtEpoch(entry.crtime)}</td>
                      <td className="whitespace-nowrap px-3 py-2 font-mono text-xs text-muted" title={entry.owner_sid ?? undefined}>{entry.owner ?? (entry.uid !== null && entry.uid !== undefined ? `${entry.uid}:${entry.gid ?? "?"}` : "-")}</td>
                      <td className="px-3 py-2 font-mono text-xs text-muted" title={entry.sha1 ? `SHA1 ${entry.sha1}` : undefined}>{isCollection ? entry.md5 ?? "-" : entry.inode ?? "-"}</td>
                      <td className="whitespace-nowrap px-3 py-2">
                        {exportable ? <button type="button" disabled={exporting} onClick={() => void download([entry])} className="rounded-xl border border-line px-2 py-1 text-xs text-muted disabled:opacity-40">{entry.kind === "dir" ? "Download folder" : "Download"}</button> : null}
                      </td>
                    </tr>
                  );
                })}
                {!rows.length && activeQuery.isSuccess ? (
                  <tr><td colSpan={11} className="px-3 py-6 text-center text-sm text-muted">{searchTerm ? "No file matches." : "This directory is empty."}</td></tr>
                ) : null}
              </tbody>
            </table>
          </div>
        </section>
      ) : null}
    </div>
  );
}
