import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ChevronLeft, File, Folder, Loader2 } from "lucide-react";
import { api, type S3ObjectEntry } from "../api/client";

function bytes(value: number): string {
  if (value < 1024) return `${value} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let size = value / 1024;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size.toFixed(size >= 10 ? 0 : 1)} ${units[unit]}`;
}

const ARCHIVED = new Set(["GLACIER", "DEEP_ARCHIVE"]);

// Browses the instance's S3 source one "folder" (prefix) at a time and lets the analyst pick one object.
export function S3ObjectPicker({
  caseId,
  defaultBucket,
  selected,
  onSelect,
}: {
  caseId: string;
  defaultBucket: string;
  selected: { bucket: string; object: S3ObjectEntry } | null;
  onSelect: (value: { bucket: string; object: S3ObjectEntry } | null) => void;
}) {
  const [bucketInput, setBucketInput] = useState(defaultBucket);
  const [bucket, setBucket] = useState(defaultBucket);
  const [prefix, setPrefix] = useState("");
  const [token, setToken] = useState<string | null>(null);
  const [pages, setPages] = useState<{ prefixes: string[]; objects: S3ObjectEntry[] }>({ prefixes: [], objects: [] });

  const query = useQuery({
    queryKey: ["s3-objects", caseId, bucket, prefix, token],
    queryFn: () => api.listS3Objects(caseId, { bucket: bucket || undefined, prefix, token: token ?? undefined }),
    enabled: Boolean(bucket),
    retry: false,
  });

  useEffect(() => {
    if (!query.data) return;
    setPages((current) =>
      token
        ? { prefixes: [...current.prefixes, ...query.data.prefixes], objects: [...current.objects, ...query.data.objects] }
        : { prefixes: query.data.prefixes, objects: query.data.objects },
    );
  }, [query.data, token]);

  function open(nextPrefix: string) {
    setPrefix(nextPrefix);
    setToken(null);
    setPages({ prefixes: [], objects: [] });
  }

  const parent = prefix ? prefix.slice(0, prefix.slice(0, -1).lastIndexOf("/") + 1) : null;

  return (
    <div className="space-y-3" data-testid="s3-object-picker">
      <form
        className="flex gap-2"
        onSubmit={(event) => {
          event.preventDefault();
          setBucket(bucketInput.trim());
          onSelect(null);
          open("");
        }}
      >
        <input value={bucketInput} onChange={(event) => setBucketInput(event.target.value)} placeholder="bucket name" aria-label="Bucket" className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-ink" />
        <button type="submit" className="rounded-2xl border border-line px-4 py-2 text-xs text-muted hover:text-ink">
          Open
        </button>
      </form>
      {bucket ? (
        <div className="rounded-2xl border border-line bg-abyss/60">
          <div className="flex items-center gap-2 border-b border-line px-3 py-2 text-xs text-muted">
            {parent !== null ? (
              <button type="button" onClick={() => open(parent)} className="rounded-lg p-1 hover:bg-white/5 hover:text-ink" aria-label="Up one folder">
                <ChevronLeft size={14} />
              </button>
            ) : null}
            <span className="truncate font-mono">
              s3://{bucket}/{prefix}
            </span>
          </div>
          <ul className="max-h-64 overflow-y-auto text-sm">
            {pages.prefixes.map((item) => (
              <li key={item}>
                <button type="button" onClick={() => open(item)} className="flex w-full items-center gap-2 px-3 py-2 text-left text-ink hover:bg-white/5">
                  <Folder size={14} className="text-accent" />
                  {item.slice(prefix.length)}
                </button>
              </li>
            ))}
            {pages.objects.map((item) => {
              const archived = ARCHIVED.has(item.storage_class ?? "");
              const isSelected = selected?.bucket === bucket && selected.object.key === item.key;
              return (
                <li key={item.key}>
                  <button
                    type="button"
                    disabled={archived}
                    onClick={() => onSelect({ bucket, object: item })}
                    className={`flex w-full items-center gap-2 px-3 py-2 text-left disabled:opacity-50 ${isSelected ? "bg-accent/10 text-accent" : "text-ink hover:bg-white/5"}`}
                    title={archived ? "Archived (Glacier): restore it in S3 before importing" : item.key}
                  >
                    <File size={14} />
                    <span className="min-w-0 flex-1 truncate">{item.name}</span>
                    <span className="shrink-0 text-xs text-muted">{archived ? "archived" : bytes(item.size)}</span>
                  </button>
                </li>
              );
            })}
            {query.isFetching ? (
              <li className="flex items-center gap-2 px-3 py-2 text-xs text-muted">
                <Loader2 size={13} className="animate-spin" /> Listing...
              </li>
            ) : null}
            {!query.isFetching && !query.isError && pages.prefixes.length === 0 && pages.objects.length === 0 ? <li className="px-3 py-2 text-xs text-muted">Nothing here.</li> : null}
          </ul>
          {query.isError ? (
            <p className="border-t border-line px-3 py-2 text-xs text-danger" role="alert">
              {query.error instanceof Error ? query.error.message : "The bucket could not be listed."}
            </p>
          ) : null}
          {query.data?.next_token && !query.isFetching ? (
            <button type="button" onClick={() => setToken(query.data.next_token)} className="w-full border-t border-line px-3 py-2 text-xs text-muted hover:text-ink">
              Load more
            </button>
          ) : null}
        </div>
      ) : null}
      {selected ? (
        <p className="text-xs text-mint" data-testid="s3-selected">
          Selected: s3://{selected.bucket}/{selected.object.key} ({bytes(selected.object.size)})
        </p>
      ) : null}
    </div>
  );
}
