import type { CaseCapability } from "../api/client";

export type CapabilityRouteMatch = {
  capability: CaseCapability;
  evidenceId: string | null;
};

type ParsedRoute = {
  segments: string[];
  requiredQuery: Array<[string, string]>;
};

function parseRoute(route: string): ParsedRoute {
  const [pathPart, queryPart = ""] = route.split("?");
  return {
    segments: pathPart.split("/").filter(Boolean),
    requiredQuery: Array.from(new URLSearchParams(queryPart).entries()),
  };
}

// Matches template segments (literal or ":param") against the actual path,
// one-for-one -- different segment counts never match, so a shorter or
// longer path can never coincidentally satisfy a template. Captures every
// ":param" (":caseId", ":evidenceId", or any future one) generically.
function matchSegments(template: string[], actual: string[]): Record<string, string> | null {
  if (template.length !== actual.length) return null;
  const params: Record<string, string> = {};
  for (let index = 0; index < template.length; index += 1) {
    const templateSegment = template[index];
    const actualSegment = actual[index];
    if (templateSegment.startsWith(":")) {
      params[templateSegment.slice(1)] = actualSegment;
    } else if (templateSegment !== actualSegment) {
      return null;
    }
  }
  return params;
}

// Every query param the capability route declares must be present on the
// actual URL with the exact same value. Extra params on the actual URL
// (secondary page state) never disqualify a match. A route that declares
// no query is satisfied by any actual query, including none -- this is
// what lets a Tier 1 lens (no query) stay distinct from a capability that
// reuses its pathname with a required query (e.g. ?preset=persistence):
// the lens's own plain URL never has that param, so the capability's
// requiredQuerySatisfied check fails and only the lens itself can render
// for it.
function requiredQuerySatisfied(requiredQuery: Array<[string, string]>, actualQuery: URLSearchParams): boolean {
  return requiredQuery.every(([key, value]) => actualQuery.get(key) === value);
}

// Resolves which capability (if any) the current pathname + query
// represent, and the :evidenceId it carries (if the matched route declares
// one). Never a plain substring/startsWith match -- always full segment
// count equality plus exact required-query satisfaction.
//
// Specificity, when more than one capability's route matches the same
// pathname+query: (1) more required query params wins -- a route that had
// to prove more about the URL is a more specific claim; (2) more static
// (non-":param") path segments wins; (3) stable registry order as the
// final, deterministic tie-break. Today's registry never actually produces
// a tie (see the test suite), but the rule is defined and tested so a
// future registry addition can't make matching nondeterministic.
export function matchCapabilityRoute(capabilities: CaseCapability[], pathname: string, search: string): CapabilityRouteMatch | null {
  const actualSegments = pathname.split("/").filter(Boolean);
  const actualQuery = new URLSearchParams(search);

  type Candidate = {
    capability: CaseCapability;
    params: Record<string, string>;
    requiredQueryCount: number;
    staticSegmentCount: number;
    registryIndex: number;
  };
  const candidates: Candidate[] = [];

  capabilities.forEach((capability, registryIndex) => {
    const { segments, requiredQuery } = parseRoute(capability.route);
    const params = matchSegments(segments, actualSegments);
    if (!params) return;
    if (!requiredQuerySatisfied(requiredQuery, actualQuery)) return;
    const staticSegmentCount = segments.filter((segment) => !segment.startsWith(":")).length;
    candidates.push({ capability, params, requiredQueryCount: requiredQuery.length, staticSegmentCount, registryIndex });
  });

  if (!candidates.length) return null;

  candidates.sort((a, b) => b.requiredQueryCount - a.requiredQueryCount || b.staticSegmentCount - a.staticSegmentCount || a.registryIndex - b.registryIndex);

  const best = candidates[0];
  return { capability: best.capability, evidenceId: best.params.evidenceId ?? null };
}

// Surface Home routes (workbench.overview_route, e.g. /cases/:caseId/w) are
// not capabilities -- they're not in CAPABILITY_REGISTRY at all -- so they
// need their own exact-pathname check, ignoring any query string the same
// way capability matching tolerates extra query params.
export function matchSurfaceHome<T extends { overview_route?: string }>(workbenches: T[], pathname: string): T | null {
  return workbenches.find((workbench) => workbench.overview_route === pathname) ?? null;
}
