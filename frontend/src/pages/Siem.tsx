import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type DfirCase, type SiemFieldFilter } from "../api/client";
import EventTable, { type SortField, type SortOrder } from "../components/EventTable";
import PaginationControls from "../components/PaginationControls";
import { useActiveCase } from "../context/ActiveCaseContext";
import { useTimezonePreference } from "../context/TimezoneContext";

type Mode = "query_string" | "dsl";
type FieldTab = "indexed" | "normalized" | "raw" | "missing";
type SiemTab = "dashboards" | "query_builder" | "field_explorer" | "saved_queries";

const sampleDsl = `{
  "query": {
    "bool": {
      "must": [
        { "match": { "event.message": "powershell" } }
      ],
      "filter": [
        { "term": { "event.category": "execution" } }
      ]
    }
  }
}`;

export default function Siem() {
  const queryClient = useQueryClient();
  const { activeCaseId } = useActiveCase();
  const { effectiveTimezone } = useTimezonePreference();
  const [tab, setTab] = useState<SiemTab>("dashboards");
  const [mode, setMode] = useState<Mode>("query_string");
  const [caseId, setCaseId] = useState(activeCaseId);
  const [query, setQuery] = useState('event.message:powershell AND event.category:execution');
  const [dslText, setDslText] = useState(sampleDsl);
  const [sortBy, setSortBy] = useState<SortField>("timestamp");
  const [sortOrder, setSortOrder] = useState<SortOrder>("desc");
  const [submittedQuery, setSubmittedQuery] = useState(query);
  const [submittedDsl, setSubmittedDsl] = useState(sampleDsl);
  const [timeFrom, setTimeFrom] = useState("");
  const [timeTo, setTimeTo] = useState("");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(100);
  const [parseError, setParseError] = useState<string | null>(null);
  const [fieldTab, setFieldTab] = useState<FieldTab>("indexed");
  const [fieldFilters, setFieldFilters] = useState<SiemFieldFilter[]>([]);
  const casesQuery = useQuery({ queryKey: ["cases"], queryFn: api.listCases });
  const statusQuery = useQuery({ queryKey: ["siem-external-status", caseId], queryFn: () => api.siemExternalStatus(caseId || undefined) });
  const diagnosticsQuery = useQuery({ queryKey: ["siem-external-diagnostics", caseId], queryFn: () => api.siemExternalDiagnostics(caseId || undefined) });
  const dashboardsAdminStatusQuery = useQuery({ queryKey: ["admin-opensearch-dashboards-status"], queryFn: api.getAdminOpenSearchDashboardsStatus });
  const fieldsQuery = useQuery({ queryKey: ["siem-fields", caseId], queryFn: () => api.siemFields(caseId || undefined) });
  const externalLinksQuery = useQuery({ queryKey: ["siem-external-links", caseId], queryFn: () => api.siemExternalLinks({ case_id: caseId || undefined }) });
  const historyQuery = useQuery({ queryKey: ["siem-history"], queryFn: api.listSiemQueryHistory });
  const savedQuery = useQuery({ queryKey: ["siem-saved"], queryFn: api.listSiemSavedSearches });
  const bootstrapMutation = useMutation({
    mutationFn: (repair: boolean) => api.bootstrapAdminOpenSearchDashboards({ repair }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["admin-opensearch-dashboards-status"] });
      await queryClient.invalidateQueries({ queryKey: ["siem-external-status"] });
      await queryClient.invalidateQueries({ queryKey: ["siem-external-diagnostics"] });
      await queryClient.invalidateQueries({ queryKey: ["siem-external-links"] });
    },
  });

  const payload = useMemo(() => {
    if (mode === "dsl") {
      return {
        case_id: caseId || undefined,
        mode,
        dsl: JSON.parse(submittedDsl),
        timezone: effectiveTimezone,
        time_from: timeFrom || undefined,
        time_to: timeTo || undefined,
        filters: fieldFilters,
        page,
        page_size: pageSize,
        sort_by: sortBy,
        sort_order: sortOrder,
      };
    }
    return {
      case_id: caseId || undefined,
      mode,
      query: submittedQuery,
      timezone: effectiveTimezone,
      time_from: timeFrom || undefined,
      time_to: timeTo || undefined,
      filters: fieldFilters,
      page,
      page_size: pageSize,
      sort_by: sortBy,
      sort_order: sortOrder,
    };
  }, [caseId, effectiveTimezone, fieldFilters, mode, page, pageSize, sortBy, sortOrder, submittedDsl, submittedQuery, timeFrom, timeTo]);

  const queryEnabled = mode === "query_string" || (mode === "dsl" && !parseError);
  const result = useQuery({
    queryKey: ["siem", payload],
    queryFn: () => api.siem(payload),
    enabled: queryEnabled && tab === "query_builder",
  });

  useEffect(() => {
    setCaseId((current) => current || activeCaseId);
  }, [activeCaseId]);

  function submit() {
    if (mode === "dsl") {
      try {
        JSON.parse(dslText);
        setParseError(null);
        setSubmittedDsl(dslText);
        void api.saveSiemQueryHistory({ mode, case_id: caseId || null, query: dslText, time_from: timeFrom || null, time_to: timeTo || null, saved_at: new Date().toISOString() });
      } catch (error) {
        setParseError(error instanceof Error ? error.message : "Invalid JSON DSL");
      }
      return;
    }
    setSubmittedQuery(query);
    void api.saveSiemQueryHistory({ mode, case_id: caseId || null, query, time_from: timeFrom || null, time_to: timeTo || null, saved_at: new Date().toISOString() });
  }

  function saveSearch() {
    try {
      void api.createSiemSavedSearch({
        id: crypto.randomUUID(),
        name: query.slice(0, 48) || "Saved search",
        query: mode === "dsl" ? dslText : query,
        mode,
        case_id: caseId || null,
        time_from: timeFrom || null,
        time_to: timeTo || null,
        dsl: mode === "dsl" ? JSON.parse(dslText) : null,
      });
      setParseError(null);
    } catch (error) {
      setParseError(error instanceof Error ? error.message : "Invalid JSON DSL");
    }
  }

  function handleSortChange(field: SortField) {
    if (field === sortBy) {
      setSortOrder((current) => (current === "asc" ? "desc" : "asc"));
      return;
    }
    setSortBy(field);
    setSortOrder(field === "timestamp" ? "desc" : "asc");
  }

  function addFieldFilter(field: string, value: string, operator: SiemFieldFilter["operator"] = "eq") {
    setFieldFilters((current) => [...current, { field, operator, value }]);
    setTab("query_builder");
  }

  function removeFieldFilter(index: number) {
    setFieldFilters((current) => current.filter((_, itemIndex) => itemIndex !== index));
  }

  return (
    <div className="space-y-6">
      <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
        <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">OpenSearch Console</p>
        <h2 className="mt-2 text-2xl font-semibold">Advanced OpenSearch view for direct inspection of indexed events.</h2>
        {!caseId ? <p className="mt-2 text-sm text-amber-300">No active case selected. OpenSearch links will open all `dfir-events-*` data.</p> : null}
        <p className="mt-2 text-sm text-muted">Advanced OpenSearch view. Use this to inspect indexed events directly. For normal investigation, use Search, Timeline, Findings and Artifact Search.</p>
        <div className="mt-4 rounded-2xl border border-line bg-abyss/50 p-4 text-sm text-muted">
          <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">When to use this view</p>
          <p className="mt-2">Use this for precise field-level queries, low-level pivots, dashboards and direct OpenSearch inspection. For the normal investigation workflow, stay in Search, Timeline, Findings and Artifact Search.</p>
        </div>
        <div className="mt-5 flex flex-wrap gap-2">
          {[
            ["dashboards", "OpenSearch Dashboards"],
            ["query_builder", "Query Builder"],
            ["field_explorer", "Field Explorer"],
            ["saved_queries", "Saved console queries"],
          ].map(([key, label]) => (
            <button key={key} type="button" onClick={() => setTab(key as SiemTab)} className={`rounded-full px-4 py-2 text-sm ${tab === key ? "bg-accent text-abyss" : "border border-line bg-white/5 text-muted"}`}>
              {label}
            </button>
          ))}
        </div>
      </section>

      {tab === "dashboards" ? (
        <section className="space-y-6">
          <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
            <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">OpenSearch Dashboards setup</p>
            <p className="mt-2 text-sm text-muted">Verify the Kairon DFIR events data view, repair it if needed, and jump directly into Discover without manual index-pattern creation.</p>
            <div className="mt-4 flex flex-wrap gap-3">
              <a href={dashboardsAdminStatusQuery.data?.dashboards.url || statusQuery.data?.public_url || "#"} target="_blank" rel="noreferrer" className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">
                Open OpenSearch Dashboards
              </a>
              <a href={externalLinksQuery.data?.discover_url || "#"} target="_blank" rel="noreferrer" className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">
                Open Discover
              </a>
              <button type="button" onClick={() => bootstrapMutation.mutate(Boolean(dashboardsAdminStatusQuery.data?.dashboards.data_view_exists))} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">
                {dashboardsAdminStatusQuery.data?.dashboards.data_view_exists ? "Create / Repair Data View" : "Create Data View"}
              </button>
            </div>
            {bootstrapMutation.data?.message ? <p className="mt-4 text-sm text-accent">{bootstrapMutation.data.message}</p> : null}
          </section>

          <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
            <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Checklist</p>
            <div className="mt-4 grid gap-3 md:grid-cols-2">
              <div className="rounded-2xl border border-line bg-abyss/70 p-4 text-sm text-muted">OpenSearch OK: {dashboardsAdminStatusQuery.data?.opensearch.available ? "yes" : "no"}</div>
              <div className="rounded-2xl border border-line bg-abyss/70 p-4 text-sm text-muted">Dashboards OK: {dashboardsAdminStatusQuery.data?.dashboards.available ? "yes" : "no"}</div>
              <div className="rounded-2xl border border-line bg-abyss/70 p-4 text-sm text-muted">Events index pattern: {dashboardsAdminStatusQuery.data?.opensearch.events_index_pattern || statusQuery.data?.index_pattern || "-"}</div>
              <div className="rounded-2xl border border-line bg-abyss/70 p-4 text-sm text-muted">Data View status: {dashboardsAdminStatusQuery.data?.dashboards.data_view_exists ? "ready" : "missing"}</div>
              <div className="rounded-2xl border border-line bg-abyss/70 p-4 text-sm text-muted">Events count: {dashboardsAdminStatusQuery.data?.opensearch.events_count ?? diagnosticsQuery.data?.case.events_count ?? 0}</div>
              <div className="rounded-2xl border border-line bg-abyss/70 p-4 text-sm text-muted">Time field: {dashboardsAdminStatusQuery.data?.dashboards.time_field || statusQuery.data?.time_field || "-"}</div>
              <div className="rounded-2xl border border-line bg-abyss/70 p-4 text-sm text-muted">Public URL: {dashboardsAdminStatusQuery.data?.dashboards.url || statusQuery.data?.public_url || "-"}</div>
              <div className="rounded-2xl border border-line bg-abyss/70 p-4 text-sm text-muted">Data View ID: {dashboardsAdminStatusQuery.data?.dashboards.data_view_id || "-"}</div>
            </div>
            {dashboardsAdminStatusQuery.data?.dashboards.warnings?.length ? (
              <div className="mt-4 rounded-2xl border border-line bg-abyss/70 p-4 text-sm text-muted">
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-accent">Warnings</p>
                <ul className="mt-2 space-y-2">
                  {dashboardsAdminStatusQuery.data.dashboards.warnings.map((warning) => (
                    <li key={warning}>{warning}</li>
                  ))}
                </ul>
              </div>
            ) : null}
            {!dashboardsAdminStatusQuery.data?.dashboards.available ? <p className="mt-4 text-sm text-amber-300">OpenSearch Dashboards is not available right now. The bootstrap action will not crash the app, but it needs Dashboards reachable with valid credentials.</p> : null}
          </section>
        </section>
      ) : null}

      {tab === "query_builder" ? (
        <section className="space-y-6">
          <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
            <div className="grid gap-4 xl:grid-cols-[280px_1fr]">
              <label className="block">
                <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Case</span>
                <select value={caseId} onChange={(event) => setCaseId(event.target.value)} className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm outline-none focus:border-accent/50">
                  <option value="">All cases</option>
                  {(casesQuery.data ?? []).map((item: DfirCase) => (
                    <option key={item.id} value={item.id}>
                      {item.name}
                    </option>
                  ))}
                </select>
              </label>
              {mode === "query_string" ? (
                <label className="block">
                  <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Query</span>
                  <input value={query} onChange={(event) => setQuery(event.target.value)} className="w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 font-mono text-sm outline-none focus:border-accent/50" />
                </label>
              ) : (
                <label className="block">
                  <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Raw OpenSearch DSL</span>
                  <textarea value={dslText} onChange={(event) => setDslText(event.target.value)} className="h-56 w-full rounded-2xl border border-line bg-abyss/80 px-4 py-3 font-mono text-sm outline-none focus:border-accent/50" />
                </label>
              )}
            </div>
            <div className="mt-4 flex flex-wrap gap-2">
              <button type="button" onClick={() => setMode("query_string")} className={`rounded-full px-4 py-2 text-sm ${mode === "query_string" ? "bg-accent text-abyss" : "border border-line bg-white/5 text-muted"}`}>
                Query String
              </button>
              <button type="button" onClick={() => setMode("dsl")} className={`rounded-full px-4 py-2 text-sm ${mode === "dsl" ? "bg-accent text-abyss" : "border border-line bg-white/5 text-muted"}`}>
                Raw DSL
              </button>
            </div>
            <div className="mt-4 grid gap-4 md:grid-cols-3">
              <input type="datetime-local" step="1" value={timeFrom} onChange={(event) => setTimeFrom(event.target.value)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm" />
              <input type="datetime-local" step="1" value={timeTo} onChange={(event) => setTimeTo(event.target.value)} className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm" />
              <button type="button" onClick={saveSearch} className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm text-muted">
                Save search
              </button>
            </div>
            <div className="mt-4 flex flex-wrap gap-3">
              <button type="button" onClick={submit} className="rounded-2xl bg-accent px-4 py-2 text-sm font-semibold text-abyss">
                Run query
              </button>
              <button type="button" onClick={() => navigator.clipboard.writeText(externalLinksQuery.data?.kql_or_lucene_query || "")} className="rounded-2xl border border-line bg-abyss/80 px-4 py-2 text-sm text-muted">
                Copy for Dashboards
              </button>
            </div>
            {fieldFilters.length ? (
              <div className="mt-4 flex flex-wrap gap-2">
                {fieldFilters.map((filter, index) => (
                  <button key={`${filter.field}-${filter.operator}-${filter.value}-${index}`} type="button" onClick={() => removeFieldFilter(index)} className="rounded-full border border-line px-3 py-1 text-xs text-muted">
                    {filter.field} {filter.operator} {String(filter.value ?? "")} ×
                  </button>
                ))}
              </div>
            ) : null}
            {parseError ? <p className="mt-3 text-sm text-danger">{parseError}</p> : null}
            {result.error instanceof Error ? <p className="mt-3 text-sm text-danger">{result.error.message}</p> : null}
          </section>

          <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
            <div className="mb-4 flex items-center justify-between gap-4">
              <div>
                <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Results</p>
                <p className="mt-1 text-sm text-muted">{result.data?.total_relation === "gte" ? `${result.data?.total ?? 0}+` : result.data?.total ?? 0} matching events</p>
              </div>
            </div>
            <PaginationControls page={page} totalPages={result.data?.total_pages ?? 0} total={result.data?.total ?? 0} totalRelation={result.data?.total_relation ?? "eq"} pageSize={pageSize} onPageChange={setPage} onPageSizeChange={setPageSize} />
            <EventTable items={result.data?.items ?? []} sortBy={sortBy} sortOrder={sortOrder} onSortChange={handleSortChange} />
          </section>
        </section>
      ) : null}

      {tab === "field_explorer" ? (
        <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
          <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Field Explorer</p>
          <div className="mt-4 flex flex-wrap gap-2">
            {(["indexed", "normalized", "raw", "missing"] as FieldTab[]).map((item) => (
              <button key={item} type="button" onClick={() => setFieldTab(item)} className={`rounded-full px-4 py-2 text-sm ${fieldTab === item ? "bg-accent text-abyss" : "border border-line bg-white/5 text-muted"}`}>
                {item}
              </button>
            ))}
          </div>
          <div className="mt-4 space-y-3 text-sm text-muted">
            {fieldTab === "indexed"
              ? (fieldsQuery.data?.indexed_fields ?? []).map((field) => (
                  <div key={field.name} className="rounded-2xl border border-line bg-abyss/70 p-4">
                    <div className="flex items-center justify-between gap-3">
                      <span className="font-mono">{field.name}</span>
                      <span>{field.type}</span>
                    </div>
                    <p className="mt-1 text-xs">searchable: {field.searchable ? "yes" : "no"} · aggregatable: {field.aggregatable ? "yes" : "no"}</p>
                    <div className="mt-2 flex flex-wrap gap-2">
                      {(field.sample_values ?? []).map((value) => (
                        <button key={`${field.name}-${value}`} type="button" onClick={() => addFieldFilter(field.name, value)} className="rounded-full border border-line px-3 py-1 text-xs">
                          {value}
                        </button>
                      ))}
                    </div>
                  </div>
                ))
              : null}
            {fieldTab === "normalized"
              ? (fieldsQuery.data?.normalized_fields ?? []).map((field) => (
                  <div key={field.name} className="rounded-2xl border border-line bg-abyss/70 p-4">
                    <div className="flex items-center justify-between gap-3">
                      <span className="font-mono">{field.name}</span>
                      <span>{field.type}</span>
                    </div>
                    <p className="mt-1 text-xs">searchable: {field.searchable ? "yes" : "no"} · aggregatable: {field.aggregatable ? "yes" : "no"}</p>
                  </div>
                ))
              : null}
            {fieldTab === "raw"
              ? (fieldsQuery.data?.raw_fields_sample ?? []).map((field) => (
                  <div key={field.name} className="rounded-2xl border border-line bg-abyss/70 p-4">
                    <div className="flex items-center justify-between gap-3">
                      <span className="font-mono">{field.name}</span>
                      <span>searchable: no</span>
                    </div>
                    <p className="mt-1 text-xs">sample: {field.sample_values.join(", ") || "-"}</p>
                  </div>
                ))
              : null}
            {fieldTab === "missing"
              ? (fieldsQuery.data?.missing_common_fields ?? []).map((field) => (
                  <div key={field.field} className="rounded-2xl border border-line bg-abyss/70 p-4">
                    <div className="flex items-center justify-between gap-3">
                      <span className="font-mono">{field.field}</span>
                      <span>missing: {field.missing_count}</span>
                    </div>
                  </div>
                ))
              : null}
          </div>
        </section>
      ) : null}

      {tab === "saved_queries" ? (
        <section className="grid gap-6 lg:grid-cols-2">
          <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
            <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Saved SIEM Queries</p>
            <div className="mt-4 space-y-3">
              {(savedQuery.data ?? []).map((item) => (
                <button key={String(item.id)} type="button" onClick={() => { setQuery(String(item.query ?? "*")); setTab("query_builder"); }} className="block w-full rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-left text-sm text-muted">
                  {String(item.name ?? item.query ?? "Saved search")}
                </button>
              ))}
            </div>
          </section>
          <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
            <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Query History</p>
            <div className="mt-4 space-y-3">
              {(historyQuery.data ?? []).map((item, index) => (
                <button key={`history-${index}`} type="button" onClick={() => { setQuery(String(item.query ?? "*")); setTab("query_builder"); }} className="block w-full rounded-2xl border border-line bg-abyss/70 px-4 py-3 text-left text-sm text-muted">
                  {String(item.query ?? "*")}
                </button>
              ))}
            </div>
          </section>
        </section>
      ) : null}
    </div>
  );
}
