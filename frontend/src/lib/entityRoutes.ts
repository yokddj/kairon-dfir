// Route builders for Entity Pages. The only entity supported today is the
// canonical memory process entity (see MemoryProcessEntityPage) -- this file
// intentionally does not define a generic entity-route framework for kinds
// that have no real page or backend endpoint yet.

function encodeRouteSegment(value: string): string {
  return encodeURIComponent(value);
}

// Builds the case-scoped, path-addressable route for a canonical memory
// process entity. Both ids are required: an entity is meaningless without
// its case, and the identity itself is the entityId (not a query param), so
// the URL is shareable and survives a direct reload.
export function memoryProcessEntityRoute(caseId: string, entityId: string): string | null {
  if (!caseId || !entityId) return null;
  return `/cases/${encodeRouteSegment(caseId)}/entities/memory-process/${encodeRouteSegment(entityId)}`;
}
