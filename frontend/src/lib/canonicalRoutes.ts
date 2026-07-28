export function caseRoute(caseId: string, suffix = "") {
  return `/cases/${caseId}${suffix}`;
}

export function windowsExecutionStoriesRoute(caseId: string, search?: string | URLSearchParams) {
  return appendSearch(caseRoute(caseId, "/w/execution/stories"), search);
}

export function windowsCommandHistoryRoute(caseId: string, search?: string | URLSearchParams) {
  return appendSearch(caseRoute(caseId, "/w/execution/command-history"), search);
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
