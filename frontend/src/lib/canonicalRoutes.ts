export function caseRoute(caseId: string, suffix = "") {
  return `/cases/${caseId}${suffix}`;
}

export function windowsExecutionStoriesRoute(caseId: string, search?: string | URLSearchParams) {
  return appendSearch(caseRoute(caseId, "/w/execution/stories"), search);
}

export function windowsCommandHistoryRoute(caseId: string, search?: string | URLSearchParams) {
  return appendSearch(caseRoute(caseId, "/w/execution/command-history"), search);
}

// Command History for the whole case (every platform, disk and memory), linked from the sidebar.
export function commandHistoryRoute(caseId: string, search?: string | URLSearchParams) {
  return appendSearch(caseRoute(caseId, "/command-history"), search);
}

export function linuxCommandHistoryRoute(caseId: string, search?: string | URLSearchParams) {
  return appendSearch(caseRoute(caseId, "/l/execution/command-history"), search);
}

export function memoryWorkbenchRoute(caseId: string, search?: string | URLSearchParams) {
  return appendSearch(caseRoute(caseId, "/m"), search);
}

export function memoryEvidenceRoute(caseId: string, evidenceId: string, tab = "overview", search?: string | URLSearchParams) {
  return appendSearch(caseRoute(caseId, `/m/${evidenceId}/${tab}`), search);
}

function appendSearch(path: string, search?: string | URLSearchParams) {
  const query = typeof search === "string" ? search.replace(/^\?/, "") : search?.toString() || "";
  return query ? `${path}?${query}` : path;
}

export function diskFilesRoute(caseId: string, evidenceId: string, params?: URLSearchParams) {
  const query = params?.toString();
  return `/cases/${caseId}/evidence/${evidenceId}/files${query ? `?${query}` : ""}`;
}

/** Explorer link for an event parsed from a file inside a disk image, or "" when it was not. */
export function diskFileRouteForEvent(event: Record<string, unknown>) {
  const artifact = (event.artifact as Record<string, unknown> | undefined) ?? {};
  const caseId = String(event.case_id ?? "");
  const evidenceId = String(event.evidence_id ?? "");
  const volume = /^volume-(\d+)\//.exec(String(artifact.source_path ?? event.source_file ?? ""));
  const relative = String(artifact.original_source_path ?? "").replace(/\\/g, "/").replace(/^[A-Za-z]:/, "");
  if (!caseId || !evidenceId || !volume || !relative) return "";
  const original = relative.startsWith("/") ? relative : `/${relative}`;
  const index = original.lastIndexOf("/");
  return diskFilesRoute(caseId, evidenceId, new URLSearchParams({ partition: volume[1], path: original.slice(0, index) || "/", file: original.slice(index + 1) }));
}
