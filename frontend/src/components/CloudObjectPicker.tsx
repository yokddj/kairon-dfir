import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ChevronLeft, File, Folder, Loader2 } from "lucide-react";

export function formatBytes(value: number): string {
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

export type CloudObject = { key: string; name: string; size: number };

export type CloudListing<T extends CloudObject> = { prefixes: string[]; objects: T[]; next_token: string | null };

/**
 * Browses one remote store "folder" (prefix) at a time and lets the analyst pick one object.
 * Shared by the S3 bucket and Azure Blob container pickers, which supply how to list, what the
 * container is called and how an object's location reads.
 */
export function CloudObjectPicker<T extends CloudObject>({
  testIdPrefix,
  containerLabel,
  containerPlaceholder,
  defaultContainer,
  queryKey,
  list,
  location,
  isArchived,
  archivedTitle,
  selected,
  onSelect,
}: {
  testIdPrefix: string;
  containerLabel: string;
  containerPlaceholder: string;
  defaultContainer: string;
  queryKey: string;
  list: (container: string, prefix: string, token: string | null) => Promise<CloudListing<T>>;
  location: (container: string, key: string) => string;
  isArchived: (item: T) => boolean;
  archivedTitle: string;
  selected: { container: string; object: T } | null;
  onSelect: (value: { container: string; object: T } | null) => void;
}) {
  const [containerInput, setContainerInput] = useState(defaultContainer);
  const [container, setContainer] = useState(defaultContainer);
  const [prefix, setPrefix] = useState("");
  const [token, setToken] = useState<string | null>(null);
  const [pages, setPages] = useState<{ prefixes: string[]; objects: T[] }>({ prefixes: [], objects: [] });

  const query = useQuery({
    queryKey: [queryKey, container, prefix, token],
    queryFn: () => list(container, prefix, token),
    enabled: Boolean(container),
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
    <div className="space-y-3" data-testid={`${testIdPrefix}-object-picker`}>
      <form
        className="flex gap-2"
        onSubmit={(event) => {
          event.preventDefault();
          setContainer(containerInput.trim());
          onSelect(null);
          open("");
        }}
      >
        <input value={containerInput} onChange={(event) => setContainerInput(event.target.value)} placeholder={containerPlaceholder} aria-label={containerLabel} className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-ink" />
        <button type="submit" className="rounded-2xl border border-line px-4 py-2 text-xs text-muted hover:text-ink">
          Open
        </button>
      </form>
      {container ? (
        <div className="rounded-2xl border border-line bg-abyss/60">
          <div className="flex items-center gap-2 border-b border-line px-3 py-2 text-xs text-muted">
            {parent !== null ? (
              <button type="button" onClick={() => open(parent)} className="rounded-lg p-1 hover:bg-white/5 hover:text-ink" aria-label="Up one folder">
                <ChevronLeft size={14} />
              </button>
            ) : null}
            <span className="truncate font-mono">{location(container, prefix)}</span>
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
              const archived = isArchived(item);
              const isSelected = selected?.container === container && selected.object.key === item.key;
              return (
                <li key={item.key}>
                  <button
                    type="button"
                    disabled={archived}
                    onClick={() => onSelect({ container, object: item })}
                    className={`flex w-full items-center gap-2 px-3 py-2 text-left disabled:opacity-50 ${isSelected ? "bg-accent/10 text-accent" : "text-ink hover:bg-white/5"}`}
                    title={archived ? archivedTitle : item.key}
                  >
                    <File size={14} />
                    <span className="min-w-0 flex-1 truncate">{item.name}</span>
                    <span className="shrink-0 text-xs text-muted">{archived ? "archived" : formatBytes(item.size)}</span>
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
              {query.error instanceof Error ? query.error.message : `The ${containerLabel.toLowerCase()} could not be listed.`}
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
        <p className="text-xs text-mint" data-testid={`${testIdPrefix}-selected`}>
          Selected: {location(selected.container, selected.object.key)} ({formatBytes(selected.object.size)})
        </p>
      ) : null}
    </div>
  );
}
