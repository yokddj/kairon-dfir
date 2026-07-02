import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import Search from "./Search";

const searchCaseMock = vi.fn();
const searchFacetsMock = vi.fn();
const getSearchQuickFiltersMock = vi.fn();
const searchAroundEventMock = vi.fn();
const searchRelatedToFindingMock = vi.fn();
const getEventContextMock = vi.fn();
const markEventMock = vi.fn();
const deleteEventMarkingMock = vi.fn();

vi.mock("../api/client", () => ({
  api: {
    searchCase: (...args: unknown[]) => searchCaseMock(...args),
    searchFacets: (...args: unknown[]) => searchFacetsMock(...args),
    getSearchQuickFilters: (...args: unknown[]) => getSearchQuickFiltersMock(...args),
    searchAroundEvent: (...args: unknown[]) => searchAroundEventMock(...args),
    searchRelatedToFinding: (...args: unknown[]) => searchRelatedToFindingMock(...args),
    getEventContext: (...args: unknown[]) => getEventContextMock(...args),
    markEvent: (...args: unknown[]) => markEventMock(...args),
    deleteEventMarking: (...args: unknown[]) => deleteEventMarkingMock(...args),
  },
}));

vi.mock("../context/ActiveCaseContext", () => ({
  useActiveCase: () => ({
    activeCaseId: "case-1",
    selectedHost: "",
    selectedEvidenceId: "",
    setActiveCaseId: vi.fn(),
  }),
}));

vi.mock("../lib/time", () => ({
  copyToClipboard: vi.fn(),
  formatTimestamp: (value: string | null | undefined) => value || "No timestamp",
}));

function renderPage(initialEntries = ["/search"]) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter initialEntries={initialEntries}>
      <QueryClientProvider client={queryClient}>
        <Search />
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

const baseResponse = {
  query: {},
  query_syntax: {
    mode: "plain",
    parsed: true,
    errors: [],
    warnings: [],
    normalized_query: "",
    applied_filters: [],
  },
  total: 3,
  page_size: 50,
  next_cursor: null,
  warnings: [],
  facets: {
    artifact_type: { process: 1, dns: 1, browser: 1 },
    parser: { evtx_raw: 1, browser_chromium_history: 1 },
    source_file: { "Security.evtx": 1, History: 1 },
    event_type: { process_start: 1, dns_query: 1, file_downloaded: 1 },
    severity: { high: 2, medium: 1 },
    risk_bucket: { high: 2, medium: 1 },
    host: { "desktop-1": 2 },
    user: { dfir: 2 },
    finding_type: { office_powershell: 1 },
    status: { new: 1 },
  },
  results: [
    {
      kind: "event",
      id: "evt-process",
      timestamp: "2026-05-15T10:00:00Z",
      title: "Process created: chrome.exe -> payload.exe",
      summary: "payload.exe executed from Downloads",
      artifact_type: "process",
      parser: "evtx_raw",
      event_type: "process_start",
      severity: "high",
      risk_score: 90,
      host: "desktop-1",
      user: "dfir",
      source_file: "Security.evtx",
      matched_fields: ["file.path"],
      highlights: { "file.path": ["C:\\Users\\dfir\\Downloads\\payload.exe"] },
      raw: {
        id: "evt-process",
        search_doc_id: "search-doc-process",
        evidence_id: "ev-1",
        event: { message: "Process created: chrome.exe -> payload.exe" },
        windows: { event_id: 4688 },
        file: { path: "C:\\Users\\dfir\\Downloads\\payload.exe", name: "payload.exe" },
        process: { name: "payload.exe", path: "C:\\Users\\dfir\\Downloads\\payload.exe", command_line: "payload.exe", pid: 4242, parent_name: "chrome.exe", parent_pid: 3000, entity_id: "proc-entity-1" },
        host: { name: "desktop-1" },
        user: { name: "dfir" },
      },
    },
    {
      kind: "event",
      id: "evt-dns",
      timestamp: "2026-05-15T10:02:00Z",
      title: "DNS query observed: duckdns.org",
      summary: "PowerShell resolved duckdns.org",
      artifact_type: "dns",
      parser: "evtx_raw",
      event_type: "dns_query",
      severity: "medium",
      risk_score: 55,
      host: "desktop-1",
      user: "dfir",
      source_file: "Microsoft-Windows-DNS-Client%4Operational.evtx",
      matched_fields: ["dns.domain"],
      highlights: {},
      raw: {
        id: "evt-dns",
        dns: { domain: "duckdns.org", record_type: "A", ip: "185.10.10.10", status: "NOERROR" },
        process: { name: "powershell.exe" },
        host: { name: "desktop-1" },
        user: { name: "dfir" },
      },
    },
    {
      kind: "finding",
      id: "finding-1",
      timestamp: "2026-05-15T10:05:00Z",
      title: "Office spawned PowerShell",
      summary: "WINWORD.EXE spawned powershell.exe with encoded command.",
      artifact_type: "finding",
      parser: null,
      event_type: "office_powershell",
      severity: "high",
      risk_score: 95,
      host: "desktop-1",
      user: "dfir",
      matched_fields: ["finding"],
      highlights: {},
      raw: {
        status: "new",
        confidence: "high",
        related_process_node_ids: ["proc-1", "proc-2"],
        related_files: ["C:\\Users\\dfir\\Downloads\\payload.exe"],
        related_domains: ["duckdns.org"],
        related_users: ["dfir"],
        related_hosts: ["desktop-1"],
        timeline: [{ timestamp: "2026-05-15T10:01:00Z", event_type: "process_start", summary: "WINWORD.EXE -> powershell.exe" }],
      },
    },
  ],
};

describe("Search page", () => {
  beforeEach(() => {
    window.localStorage.clear();
    searchCaseMock.mockReset();
    searchFacetsMock.mockReset();
    getSearchQuickFiltersMock.mockReset();
    searchAroundEventMock.mockReset();
    searchRelatedToFindingMock.mockReset();
    getEventContextMock.mockReset();
    markEventMock.mockReset();
    deleteEventMarkingMock.mockReset();

    searchCaseMock.mockResolvedValue(baseResponse);
    markEventMock.mockResolvedValue({
      id: "mark-1",
      case_id: "case-1",
      evidence_id: "ev-1",
      event_id: "evt-process",
      status: "suspicious",
      labels: [],
      note: null,
      finding_id: null,
    });
    searchFacetsMock.mockResolvedValue({
      artifact_type: { browser: 53, windows_event: 219, scheduled_task: 1, prefetch: 1 },
      parser: { browser_chromium_history: 53, evtx_raw: 219, scheduled_task_xml: 1 },
      source_file: { History: 53, "Security.evtx": 219 },
      "host.name": { "desktop-1": 53 },
      "user.name": { dfir: 53 },
      evidence_id: { "ev-1": 53 },
    });
    getSearchQuickFiltersMock.mockResolvedValue({
      case_id: "case-1",
      items: [
        { id: "high_risk", label: "High risk events", params: { scope: "events", risk_min: 70 } },
        { id: "powershell_activity", label: "PowerShell activity", params: { scope: "events", process_name: "powershell.exe" } },
      ],
    });
    searchAroundEventMock.mockResolvedValue(baseResponse);
    searchRelatedToFindingMock.mockResolvedValue(baseResponse);
    getEventContextMock.mockResolvedValue({
      event_id: "evt-process",
      case_id: "case-1",
      evidence_id: "ev-1",
      available_context: {},
      counts: { related_detections: 1, related_findings: 1 },
      related_detections: [{ id: "det-1", rule_name: "Suspicious process", rule_title: "Suspicious process", severity: "high", status: "new", engine: "sigma", event_id: "evt-process" }],
      related_findings: [{ id: "finding-1", title: "Office spawned PowerShell", severity: "high", status: "new", finding_type: "office_powershell", risk_score: 95 }],
    });
  });

  it("renders search page with compact table layout", async () => {
    renderPage();
    expect(await screen.findByText(/Investigation Search/i)).toBeInTheDocument();
    expect(await screen.findByTestId("results-table")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /toggle facets/i })).toBeInTheDocument();
    expect(screen.queryByTestId("facets-panel")).not.toBeInTheDocument();
    expect(screen.queryByTestId("search-detail-panel")).not.toBeInTheDocument();
    expect(await screen.findByRole("button", { name: /High risk events/i })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: /^Artifact type$/i })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: /^Parser$/i })).toBeInTheDocument();
    expect(screen.getByLabelText(/^Source file$/i)).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/Search commands, paths, hashes, domains or text/i)).toBeInTheDocument();
    expect(screen.getByText(/Flags like -ep and -nop are treated as text/i)).toBeInTheDocument();
    expect(searchFacetsMock).toHaveBeenCalled();
  });

  it("shows a grouped summary for broad IOC terms", async () => {
    searchCaseMock.mockResolvedValueOnce({ ...baseResponse, total: 433 });

    renderPage(["/search?q=example-control"]);

    const summary = await screen.findByTestId("search-grouped-summary");
    expect(within(summary).getByText(/Grouped summary/i)).toBeInTheDocument();
    expect(within(summary).getByText(/^Host$/i)).toBeInTheDocument();
    expect(within(summary).getByText(/^Artifact$/i)).toBeInTheDocument();
    expect(within(summary).getByText(/^Source file$/i)).toBeInTheDocument();
  });

  it("shows evidence-prefiltered chips and lets parser/source_file filters flow into the request", async () => {
    renderPage(["/search?evidence_id=ev-1&artifact_type=browser&parser=browser_chromium_history&source_file=History"]);
    await screen.findByTestId("results-table");
    expect(searchCaseMock).toHaveBeenLastCalledWith(
      "case-1",
      expect.objectContaining({
        evidence_id: "ev-1",
        artifact_type: ["browser"],
        parser: ["browser_chromium_history"],
        source_file: "History",
      }),
    );
    const chips = screen.getByTestId("active-filter-chips");
    expect(within(chips).getByText(/evidence:/i)).toBeInTheDocument();
    expect(within(chips).getByText(/artifact: browser/i)).toBeInTheDocument();
    expect(within(chips).getByText(/parser: browser_chromium_history/i)).toBeInTheDocument();
    expect(within(chips).getByText(/source: History/i)).toBeInTheDocument();
  });

  it("renders memory source badges and sends source category filters", async () => {
    searchCaseMock.mockResolvedValueOnce({
      ...baseResponse,
      total: 1,
      facets: { ...baseResponse.facets, source_category: { Memory: 1 } },
      results: [
        {
          ...baseResponse.results[0],
          id: "memory:proc-6996",
          title: "Process started: powershell.exe",
          artifact_type: "memory_process_entity",
          parser: "windows.pslist",
          source_category: "Memory",
          source_plugin_or_parser: "windows.pslist",
          raw: { evidence_id: "mem-1", source_category: "Memory", source_plugin_or_parser: "windows.pslist" },
        },
      ],
    });
    renderPage(["/search?source_category=Memory&evidence_id=mem-1&q=6996"]);
    expect(await screen.findByText(/Memory: windows\.pslist/i)).toBeInTheDocument();
    await waitFor(() => expect(searchCaseMock).toHaveBeenCalledWith("case-1", expect.objectContaining({ source_category: "Memory", evidence_id: "mem-1", q: "6996" })));
  });

  it("passes negative filters from the url and shows NOT chips", async () => {
    renderPage(["/search?exclude_q=defender&exclude_artifact_type=mft&exclude_parser=evtx_raw&exclude_source_file=Security.evtx&exclude_host=noise-host&exclude_user=svc"]);
    await screen.findByTestId("results-table");
    expect(searchCaseMock).toHaveBeenLastCalledWith(
      "case-1",
      expect.objectContaining({
        exclude_q: "defender",
        exclude_artifact_type: ["mft"],
        exclude_parser: ["evtx_raw"],
        exclude_source_file: "Security.evtx",
        exclude_host: "noise-host",
        exclude_user: "svc",
      }),
    );
    const chips = screen.getByTestId("active-filter-chips");
    expect(within(chips).getByText(/NOT text: defender/i)).toBeInTheDocument();
    expect(within(chips).getByText(/NOT artifact: mft/i)).toBeInTheDocument();
    expect(within(chips).getByText(/NOT parser: evtx_raw/i)).toBeInTheDocument();
    expect(within(chips).getByText(/NOT source: Security\.evtx/i)).toBeInTheDocument();
  });

  it("preserves command phrase queries with hyphen flags as literal text", async () => {
    renderPage(["/search?q=powershell%20-ep%20bypass"]);
    await screen.findByTestId("results-table");
    expect(screen.getByDisplayValue("powershell -ep bypass")).toBeInTheDocument();
    expect(screen.queryByText(/NOT text: -ep/i)).not.toBeInTheDocument();
    expect(searchCaseMock).toHaveBeenLastCalledWith("case-1", expect.objectContaining({ q: "powershell -ep bypass" }));
  });

  it("passes command-like paths, relative paths and exclude_q unchanged", async () => {
    renderPage(["/search?q=%2E%5Cf%5Cscript.ps1&exclude_q=benign"]);
    await screen.findByTestId("results-table");
    expect(screen.getByDisplayValue(".\\f\\script.ps1")).toBeInTheDocument();
    expect(searchCaseMock).toHaveBeenLastCalledWith("case-1", expect.objectContaining({ q: ".\\f\\script.ps1", exclude_q: "benign" }));
  });

  it("supports advanced backend filters without changing default Search behavior", async () => {
    renderPage(["/search?artifact_type=amcache&backend_variant=advanced&parser_backend=amcacheparser_csv"]);
    await screen.findByTestId("results-table");
    expect(searchCaseMock).toHaveBeenLastCalledWith(
      "case-1",
      expect.objectContaining({
        artifact_type: ["amcache"],
        backend_variant: ["advanced"],
        parser_backend: ["amcacheparser_csv"],
      }),
    );
    const chips = screen.getByTestId("active-filter-chips");
    expect(within(chips).getByText(/backend: advanced/i)).toBeInTheDocument();
    expect(within(chips).getByText(/parser backend: amcacheparser_csv/i)).toBeInTheDocument();
  });

  it("keeps the evidence scope when applying quick filters", async () => {
    renderPage(["/search?evidence_id=ev-1"]);
    await screen.findByTestId("results-table");

    await userEvent.click(await screen.findByRole("button", { name: /High risk events/i }));

    await waitFor(() =>
      expect(searchCaseMock).toHaveBeenLastCalledWith(
        "case-1",
        expect.objectContaining({
          evidence_id: "ev-1",
          risk_min: 70,
          scope: "events",
        }),
      ),
    );
    expect(screen.getByTestId("active-filter-chips")).toHaveTextContent(/evidence: ev-1/i);
  });

  it("shows parser and source file in results and detail", async () => {
    renderPage(["/search?selected=evt-process"]);
    expect(await screen.findByTestId("results-table")).toBeInTheDocument();
    expect(screen.getAllByText(/evtx_raw/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Security\.evtx/i).length).toBeGreaterThan(0);
    const detailPanel = await screen.findByTestId("search-detail-panel");
    expect(within(detailPanel).getAllByText(/Parser/i).length).toBeGreaterThan(0);
    expect(within(detailPanel).getAllByText(/evtx_raw/i).length).toBeGreaterThan(0);
  });

  it("clear filters resets the query state", async () => {
    renderPage(["/search?evidence_id=ev-1&artifact_type=browser&parser=browser_chromium_history&source_file=History&exclude_artifact_type=mft"]);
    await screen.findByTestId("results-table");
    await userEvent.click(screen.getByRole("button", { name: /clear filters/i }));
    await waitFor(() =>
      expect(searchCaseMock).toHaveBeenLastCalledWith(
        "case-1",
        expect.not.objectContaining({
          evidence_id: "ev-1",
          exclude_artifact_type: ["mft"],
        }),
      ),
    );
  });

  it("uses global scoped facets for artifact type instead of only the current page", async () => {
    searchCaseMock.mockResolvedValue({
      ...baseResponse,
      facets: {
        ...baseResponse.facets,
        artifact_type: { browser: 1 },
      },
    });
    renderPage(["/search?evidence_id=ev-1"]);
    await screen.findByTestId("results-table");
    const artifactSelect = screen.getByRole("combobox", { name: /^Artifact type$/i });
    expect(within(artifactSelect).getByRole("option", { name: /windows_event \(219\)/i })).toBeInTheDocument();
    expect(within(artifactSelect).getByRole("option", { name: /scheduled_task \(1\)/i })).toBeInTheDocument();
  });

  it("does not expose technical exclude text fields in the primary UI", async () => {
    renderPage();
    await screen.findByTestId("results-table");
    expect(screen.queryByLabelText(/Exclude text/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/Exclude source file/i)).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /advanced filters/i }));
    expect(screen.queryByLabelText(/Exclude host/i)).not.toBeInTheDocument();
    expect(screen.getByLabelText(/Exclude condition/i)).toBeInTheDocument();
  });

  it("shows visible time filters and active time chip", async () => {
    renderPage(["/search?time_from=2026-05-15T10:00:00Z&time_to=2026-05-15T12:00:00Z"]);
    await screen.findByTestId("results-table");
    expect(screen.getByLabelText(/^Time from$/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/^Time to$/i)).toBeInTheDocument();
    expect(screen.getByText(/Some documents do not have a valid forensic timestamp and are excluded from time filters/i)).toBeInTheDocument();
    const chips = screen.getByTestId("active-filter-chips");
    expect(within(chips).getByText(/time: 2026-05-15T10:00:00Z → 2026-05-15T12:00:00Z/i)).toBeInTheDocument();
  });

  it("renders ntfs artifact label in results and detail", async () => {
    const ntfsResponse = {
      ...baseResponse,
      results: [
        {
          kind: "event",
          id: "evt-ntfs",
          timestamp: "2026-05-15T10:00:00Z",
          title: "Zone.Identifier observed",
          summary: "payload.exe marked from the Internet",
          artifact_type: "ntfs",
          event_type: "file_zone_identifier_observed",
          severity: "high",
          risk_score: 92,
          host: "desktop-1",
          user: "dfir",
          matched_fields: ["ntfs.host_url"],
          highlights: {},
          raw: {
            file: { path: "C:\\Users\\dfir\\Downloads\\payload.exe", name: "payload.exe", extension: ".exe" },
            ntfs: { zone_id: 3, host_url: "http://203.0.113.10/payload.exe", referrer_url: "http://suspicious.example/" },
            event: { message: "Zone.Identifier observed" },
          },
        },
      ],
    };
    searchCaseMock.mockResolvedValue(ntfsResponse);
    renderPage(["/search?selected=evt-ntfs"]);
    expect((await screen.findAllByText("NTFS")).length).toBeGreaterThan(0);
    expect(await screen.findByTestId("search-detail-panel")).toBeInTheDocument();
    expect(await screen.findByText(/Host URL:/i)).toBeInTheDocument();
    expect(screen.getByText("http://203.0.113.10/payload.exe")).toBeInTheDocument();
  });

  it("uses generic example placeholders in search filters", async () => {
    renderPage();
    await screen.findByTestId("results-table");
    expect(screen.getByPlaceholderText(/Search commands, paths, hashes, domains or text/i)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /search syntax/i }));
    expect(screen.getByText(/stable_event_id:/i)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /advanced filters/i }));
    expect(screen.getByPlaceholderText("TEST-WIN10-01")).toBeInTheDocument();
    expect(screen.getByPlaceholderText("user01")).toBeInTheDocument();
    expect(screen.getByPlaceholderText("198.51.100.10")).toBeInTheDocument();
  });

  it("advanced filters are collapsed by default", async () => {
    renderPage();
    await screen.findByTestId("results-table");
    expect(screen.queryByTestId("advanced-filters-panel")).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /advanced filters/i }));
    expect(screen.getByTestId("advanced-filters-panel")).toBeInTheDocument();
  });

  it("shows search syntax help examples", async () => {
    renderPage();
    await screen.findByTestId("results-table");
    await userEvent.click(screen.getByRole("button", { name: /search syntax/i }));
    const help = await screen.findByTestId("search-syntax-help");
    expect(within(help).getByText(/artifact\.type:ntfs risk_score>=70/i)).toBeInTheDocument();
    expect(within(help).getByText(/process\.name:powershell\.exe EncodedCommand/i)).toBeInTheDocument();
  });

  it("supports unified investigation page sizes from URL", async () => {
    renderPage(["/search?page_size=250"]);
    await screen.findByTestId("results-table");
    const pageSize = screen.getByLabelText(/Page size top/i) as HTMLSelectElement;
    expect(pageSize.value).toBe("250");
    expect(within(pageSize).getByRole("option", { name: "500" })).toBeInTheDocument();
  });

  it("renders backend query syntax chips for valid advanced query", async () => {
    searchCaseMock.mockResolvedValueOnce({
      ...baseResponse,
      query_syntax: {
        mode: "mixed",
        parsed: true,
        errors: [],
        warnings: [],
        normalized_query: "artifact.type:ntfs risk_score>=70",
        applied_filters: [
          { field: "artifact.type", operator: ":", value: "ntfs" },
          { field: "risk_score", operator: ">=", value: "70" },
        ],
      },
    });
    renderPage(["/search?q=artifact.type:ntfs%20risk_score%3E%3D70"]);
    const chips = await screen.findByTestId("query-syntax-chips");
    expect(within(chips).getByText("artifact.type : ntfs")).toBeInTheDocument();
    expect(within(chips).getByText("risk_score >= 70")).toBeInTheDocument();
  });

  it("shows inline parse errors for invalid advanced queries", async () => {
    searchCaseMock.mockRejectedValueOnce(
      new Error(
        JSON.stringify({
          error: "Invalid search query",
          message: "Invalid search query: unclosed quote near position 11.",
          examples: ['file.name:"invoice.docm"', "artifact.type:ntfs risk_score>=70"],
        }),
      ),
    );
    renderPage(['/search?q=file.name:%22invoice.docm']);
    const errorPanel = await screen.findByTestId("search-query-error");
    expect(within(errorPanel).getByText(/unclosed quote/i)).toBeInTheDocument();
    expect(within(errorPanel).getByText(/artifact\.type:ntfs risk_score>=70/i)).toBeInTheDocument();
  });

  it("selected result in url opens the detail panel and close hides it", async () => {
    renderPage(["/search?selected=evt-process"]);
    expect(await screen.findByTestId("search-detail-panel")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /close detail panel/i }));
    await waitFor(() => expect(screen.queryByTestId("search-detail-panel")).not.toBeInTheDocument());
    expect(document.body.style.overflow).toBe("");
  });

  it("event detail shows related activity and linked detections", async () => {
    renderPage(["/search?selected=evt-process"]);
    const related = await screen.findByTestId("related-activity-section");
    expect(within(related).getByText(/Related activity/i)).toBeInTheDocument();
    expect(within(related).getByRole("button", { name: /Around this event · ±30s/i })).toBeInTheDocument();
    expect(within(related).getByRole("button", { name: /Same host/i })).toBeInTheDocument();
    expect(within(related).getByRole("button", { name: /Same source file/i })).toBeInTheDocument();
    expect(within(related).getByRole("button", { name: /Same Windows event ID/i })).toBeInTheDocument();
    expect(await within(related).findByText(/Suspicious process/i)).toBeInTheDocument();
    expect(within(related).getByText(/Office spawned PowerShell/i)).toBeInTheDocument();
    expect(getEventContextMock).toHaveBeenCalledWith("case-1", "evt-process");
  });

  it("related activity same host creates a filter builder condition", async () => {
    renderPage(["/search?selected=evt-process"]);
    const related = await screen.findByTestId("related-activity-section");
    await userEvent.click(within(related).getByRole("button", { name: /Same host/i }));
    await waitFor(() => expect(searchCaseMock).toHaveBeenLastCalledWith("case-1", expect.objectContaining({ filters: expect.stringContaining('"host.name"') })));
    expect(JSON.parse(searchCaseMock.mock.calls.at(-1)?.[1]?.filters)).toEqual([{ field: "host.name", operator: "is", value: "desktop-1", negate: false }]);
  });

  it("event without a valid timestamp does not enable around actions", async () => {
    searchCaseMock.mockResolvedValueOnce({
      ...baseResponse,
      results: [
        {
          ...baseResponse.results[0],
          id: "evt-no-time",
          timestamp: null,
          raw: { ...(baseResponse.results[0] as { raw: Record<string, unknown> }).raw, timestamp_status: "suspicious" },
        },
      ],
    });
    renderPage(["/search?selected=evt-no-time"]);
    const related = await screen.findByTestId("related-activity-section");
    expect(within(related).getByText(/This event has no valid forensic timestamp/i)).toBeInTheDocument();
    expect(within(related).getByRole("button", { name: /Around this event · ±30s/i })).toBeDisabled();
  });

  it("shows observed host when canonical and observed names differ", async () => {
    searchCaseMock.mockResolvedValue({
      ...baseResponse,
      results: [
        {
          ...baseResponse.results[0],
          host: "hosta",
          raw: {
            ...(baseResponse.results[0] as { raw: Record<string, unknown> }).raw,
            host: { name: "hosta" },
            observed_host: { name: "DESKTOP-OLD01" },
          },
        },
      ],
    });
    renderPage(["/search?selected=evt-process"]);
    expect(await screen.findByTestId("search-detail-panel")).toBeInTheDocument();
    expect(screen.getByText(/Observed as:/i)).toBeInTheDocument();
    expect(screen.getByText("DESKTOP-OLD01")).toBeInTheDocument();
  });

  it("clicking a result opens the responsive detail drawer", async () => {
    renderPage();
    await userEvent.click(await screen.findByTestId("search-row-event-evt-process"));
    const overlay = await screen.findByTestId("responsive-detail-overlay");
    expect(overlay).toBeInTheDocument();
    expect(overlay.className).toContain("justify-center");
    const detailPanel = screen.getByTestId("search-detail-panel");
    expect(detailPanel).toBeInTheDocument();
    expect(screen.getByTestId("responsive-detail-panel-content").className).toContain("overflow-y-auto");
    expect(within(detailPanel).getAllByText(/Search detail/i)).not.toHaveLength(0);
    expect(document.body.style.overflow).toBe("hidden");
  });

  it("renders email artifact details with subject, sender and attachments", async () => {
    searchCaseMock.mockResolvedValueOnce({
      ...baseResponse,
      total: 1,
      results: [
        {
          kind: "event",
          id: "evt-email",
          timestamp: "2026-05-19T10:15:00Z",
          title: "Email message observed: Invoice",
          summary: "Suspicious email attachment observed",
          artifact_type: "email",
          event_type: "email_message",
          severity: "high",
          risk_score: 85,
          host: "TEST-WIN10-01",
          user: "user01",
          matched_fields: ["email.subject"],
          highlights: {},
          raw: {
            id: "evt-email",
            email: {
              subject: "Invoice",
              message_id: "<message-1@suspicious.example>",
              from: { address: "attacker@suspicious.example" },
              to: ["user01@example.local"],
              attachments: [{ file_name: "invoice.docm", extension: ".docm" }],
              headers: { spf_result: "fail", dmarc_result: "fail" },
            },
            host: { name: "TEST-WIN10-01" },
            user: { name: "user01" },
            artifact: { type: "email" },
            event: { category: "email", type: "email_message", message: "Email message observed: Invoice" },
          },
        },
      ],
    });

    renderPage();
    await userEvent.click(await screen.findByTestId("search-row-event-evt-email"));
    const detailPanel = await screen.findByTestId("search-detail-panel");
    expect(within(detailPanel).getByRole("heading", { name: /Email message observed: Invoice/i })).toBeInTheDocument();
    expect(within(detailPanel).getAllByText(/TEST-WIN10-01/i).length).toBeGreaterThan(0);
    expect(within(detailPanel).getAllByText(/invoice\.docm/i).length).toBeGreaterThan(0);
  });

  it("renders user activity label and detail fields for registry-backed events", async () => {
    searchCaseMock.mockResolvedValueOnce({
      ...baseResponse,
      total: 1,
      results: [
        {
          kind: "event",
          id: "evt-user-activity",
          timestamp: "2026-05-19T12:00:00Z",
          title: "Run dialog command observed",
          summary: "User executed a suspicious RunMRU PowerShell command.",
          artifact_type: "user_activity",
          event_type: "user_run_command_observed",
          severity: "high",
          risk_score: 92,
          host: "TEST-WIN10-01",
          user: "user01",
          matched_fields: ["process.command_line"],
          highlights: {},
          raw: {
            id: "evt-user-activity",
            artifact: { type: "user_activity", parser: "run_mru_registry" },
            event: { category: "user_activity", type: "user_run_command_observed", action: "run_dialog" },
            user: { name: "user01", sid: "S-1-5-21-1000" },
            process: { command_line: "powershell.exe -NoP -W Hidden -EncodedCommand AAAA", name: "powershell.exe" },
            registry: {
              hive: "NTUSER.DAT",
              key_path: "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU",
              value_name: "a",
              value_data: "powershell.exe -NoP -W Hidden -EncodedCommand AAAA",
            },
            file: { path: "C:\\Users\\user01\\Downloads\\invoice.docm", name: "invoice.docm" },
            suspicious_reasons: ["encoded powershell from RunMRU"],
          },
        },
      ],
    });

    renderPage();
    expect(await screen.findByText("User Activity")).toBeInTheDocument();
    await userEvent.click(await screen.findByTestId("search-row-event-evt-user-activity"));
    const detailPanel = await screen.findByTestId("search-detail-panel");
    expect(within(detailPanel).getByText(/Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU/i)).toBeInTheDocument();
    expect(within(detailPanel).getAllByText(/EncodedCommand AAAA/i).length).toBeGreaterThan(0);
    expect(within(detailPanel).getAllByText(/invoice\.docm/i).length).toBeGreaterThan(0);
  });

  it("renders windows ui label and detail fields for notifications and office alerts", async () => {
    searchCaseMock.mockResolvedValueOnce({
      ...baseResponse,
      total: 1,
      results: [
        {
          kind: "event",
          id: "evt-windows-ui",
          timestamp: "2026-05-19T13:30:00Z",
          title: "Office security alert observed",
          summary: "Protected View warning observed for invoice.docm",
          artifact_type: "windows_ui",
          event_type: "office_alert_observed",
          severity: "high",
          risk_score: 82,
          host: "TEST-WIN10-01",
          user: "user01",
          matched_fields: ["office.alert_text"],
          highlights: {},
          raw: {
            id: "evt-windows-ui",
            artifact: { type: "windows_ui", parser: "office_oalerts_evtx" },
            event: { category: "windows_ui", type: "office_alert_observed", action: "observed" },
            notification: {
              title: "Threat quarantined: Trojan:Win32/Test",
              body_preview: "payload.exe was quarantined",
            },
            office: {
              app: "Word",
              alert_text: "Protected View and Enable Content warning",
              document_path: "C:\\Users\\user01\\Downloads\\invoice.docm",
            },
            thumbnail: {
              source_path: "C:\\Users\\user01\\Downloads\\invoice.pdf.exe",
              cache_id: "thumb-123",
            },
            windows_search: {
              indexed_path: "C:\\Users\\user01\\Downloads\\invoice.docm",
              content_type: "application/vnd.ms-word.document.macroEnabled.12",
            },
            suspicious_reasons: ["office security warning for macro-enabled document"],
          },
        },
      ],
    });

    renderPage();
    expect(await screen.findByText("Windows UI")).toBeInTheDocument();
    await userEvent.click(await screen.findByTestId("search-row-event-evt-windows-ui"));
    const detailPanel = await screen.findByTestId("search-detail-panel");
    expect(within(detailPanel).getByText(/Threat quarantined: Trojan:Win32\/Test/i)).toBeInTheDocument();
    expect(within(detailPanel).getByText(/Protected View and Enable Content warning/i)).toBeInTheDocument();
    expect(within(detailPanel).getAllByText(/invoice\.docm/i).length).toBeGreaterThan(0);
  });

  it("detail drawer closes with Escape and restores body scroll", async () => {
    renderPage();
    await userEvent.click(await screen.findByTestId("search-row-event-evt-process"));
    expect(await screen.findByTestId("responsive-detail-overlay")).toBeInTheDocument();
    fireEvent.keyDown(window, { key: "Escape" });
    await waitFor(() => expect(screen.queryByTestId("responsive-detail-overlay")).not.toBeInTheDocument());
    expect(document.body.style.overflow).toBe("");
  });

  it("facets can be expanded and collapsed", async () => {
    renderPage();
    await screen.findByTestId("results-table");
    await userEvent.click(screen.getByRole("button", { name: /toggle facets/i }));
    expect(await screen.findByTestId("facets-panel")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /toggle facets/i }));
    await waitFor(() => expect(screen.queryByTestId("facets-panel")).not.toBeInTheDocument());
  });

  it("row actions are shown through a compact actions menu", async () => {
    renderPage();
    const row = await screen.findByTestId("search-row-event-evt-process");
    expect(within(row).getAllByRole("button", { name: "Actions" })).toHaveLength(1);
    expect(within(row).queryByRole("button", { name: /search same file/i })).not.toBeInTheDocument();
    await userEvent.click(within(row).getByRole("button", { name: "Actions" }));
    const menu = screen.getByTestId("search-actions-menu-evt-process");
    expect(await within(menu).findByRole("button", { name: /open details/i })).toBeInTheDocument();
    expect(within(menu).getByRole("button", { name: /open execution story for this exact event/i })).toBeInTheDocument();
    expect(within(menu).getByRole("button", { name: /open advanced process graph/i })).toBeInTheDocument();
    expect(within(menu).getByRole("button", { name: /show ±30 minutes around this event/i })).toBeInTheDocument();
    expect(within(menu).queryByRole("button", { name: /filter by host/i })).not.toBeInTheDocument();
    expect(within(menu).queryByRole("button", { name: /exclude source file/i })).not.toBeInTheDocument();
  });

  it("search row can mark an event suspicious", async () => {
    renderPage();
    const row = await screen.findByTestId("search-row-event-evt-process");
    await userEvent.click(within(row).getByRole("button", { name: "Actions" }));
    const menu = screen.getByTestId("search-actions-menu-evt-process");
    await userEvent.click(await within(menu).findByRole("button", { name: /mark suspicious/i }));
    await waitFor(() =>
      expect(markEventMock).toHaveBeenCalledWith(
        "evt-process",
        expect.objectContaining({
          case_id: "case-1",
          evidence_id: "ev-1",
          search_doc_id: "evt-process",
          status: "suspicious",
          host: "desktop-1",
        }),
      ),
    );
  });

  it("shows marking badges and filters marked events", async () => {
    searchCaseMock.mockResolvedValueOnce({
      ...baseResponse,
      results: [
        {
          ...baseResponse.results[0],
          marking: { id: "mark-1", case_id: "case-1", evidence_id: "ev-1", event_id: "evt-process", status: "important", labels: ["lead"], note: "review this", finding_id: null },
          raw: {
            ...baseResponse.results[0].raw,
            marking: { id: "mark-1", case_id: "case-1", evidence_id: "ev-1", event_id: "evt-process", status: "important", labels: ["lead"], note: "review this", finding_id: null },
          },
        },
      ],
    });
    renderPage();
    expect(await screen.findAllByText(/Important/i)).not.toHaveLength(0);
    await userEvent.click(screen.getByRole("button", { name: /marked only/i }));
    await waitFor(() => expect(searchCaseMock).toHaveBeenLastCalledWith("case-1", expect.objectContaining({ marked_only: true })));
    await userEvent.selectOptions(screen.getByLabelText(/Marking status/i), "suspicious");
    await waitFor(() => expect(searchCaseMock).toHaveBeenLastCalledWith("case-1", expect.objectContaining({ marked_only: true, marking_status: "suspicious" })));
  });

  it("inline visible values can create include and exclude builder filters", async () => {
    renderPage();
    const processRow = await screen.findByTestId("search-row-event-evt-process");
    await userEvent.click(within(processRow).getByRole("button", { name: /pivot host/i }));
    await userEvent.click(await screen.findByRole("button", { name: /filter by host/i }));
    await waitFor(() => expect(searchCaseMock).toHaveBeenLastCalledWith("case-1", expect.objectContaining({ filters: expect.stringContaining('"host.name"') })));
    expect(JSON.parse(searchCaseMock.mock.calls.at(-1)?.[1]?.filters)).toEqual([{ field: "host.name", operator: "is", value: "desktop-1", negate: false }]);

    await userEvent.click(within(await screen.findByTestId("search-row-event-evt-process")).getByRole("button", { name: /pivot source file/i }));
    await userEvent.click(await screen.findByRole("button", { name: /exclude source file/i }));
    await waitFor(() => expect(screen.getByTestId("active-filter-chips")).toHaveTextContent(/NOT Source file contains Security\.evtx/i));
  });

  it("timestamp header requests backend global sort instead of sorting only local rows", async () => {
    renderPage();
    const table = await screen.findByTestId("results-table");
    await userEvent.click(within(table).getByRole("button", { name: /^Timestamp/i }));
    await waitFor(() => expect(searchCaseMock).toHaveBeenLastCalledWith("case-1", expect.objectContaining({ sort: "timestamp_asc" })));
  });

  it("lets users resize columns, persists widths, and reset defaults", async () => {
    renderPage();
    const table = await screen.findByTestId("results-table");
    const resizeSource = within(table).getByRole("button", { name: /Resize Source file column/i });

    fireEvent.mouseDown(resizeSource, { clientX: 260 });
    fireEvent.mouseMove(window, { clientX: 340 });
    fireEvent.mouseUp(window);

    await waitFor(() => {
      const stored = JSON.parse(window.localStorage.getItem("dfir.search.columnWidths.results-table") || "{}");
      expect(stored.source_file).toBe(340);
    });

    await userEvent.click(within(table).getByRole("button", { name: /Reset columns/i }));
    await waitFor(() => {
      const stored = JSON.parse(window.localStorage.getItem("dfir.search.columnWidths.results-table") || "{}");
      expect(stored.source_file).toBe(260);
    });
  });

  it("uses the resized column width for content and supports wrapping densities", async () => {
    renderPage();
    const table = await screen.findByTestId("results-table");
    const row = await screen.findByTestId("search-row-event-evt-process");
    const sourcePivot = within(row).getByRole("button", { name: /pivot source file/i });
    const snippet = within(row).getByTestId("search-snippet-cell");

    expect(sourcePivot.className).toContain("w-full");
    expect(sourcePivot.className).toContain("whitespace-nowrap");
    expect(sourcePivot.className).not.toContain("max-w-[");
    expect(snippet).toHaveTextContent("payload.exe executed from Downloads");
    expect(snippet.className).toContain("w-full");
    expect(snippet.className).toContain("whitespace-nowrap");
    expect(snippet.className).not.toContain("max-w-[");

    await userEvent.selectOptions(screen.getByLabelText(/Density/i), "comfortable");
    expect(within(row).getByRole("button", { name: /pivot source file/i }).className).toContain("[-webkit-line-clamp:2]");
    expect(within(row).getByTestId("search-snippet-cell").className).toContain("[-webkit-line-clamp:2]");

    await userEvent.selectOptions(screen.getByLabelText(/Density/i), "expanded");
    expect(within(row).getByRole("button", { name: /pivot source file/i }).className).toContain("whitespace-pre-wrap");
    expect(within(row).getByTestId("search-snippet-cell").className).toContain("whitespace-pre-wrap");

    await userEvent.click(within(table).getByRole("button", { name: /Reset columns/i }));
    await waitFor(() => {
      const stored = JSON.parse(window.localStorage.getItem("dfir.search.columnWidths.results-table") || "{}");
      expect(stored.source_file).toBe(260);
    });
  });

  it("rebuilds pre-truncated snippets from full normalized fields", async () => {
    searchCaseMock.mockResolvedValueOnce({
      ...baseResponse,
      results: [
        {
          ...baseResponse.results[0],
          id: "evt-file-create",
          title: "Sysmon file created",
          summary: "Sysmon file created: C:\\Users\\LOCALA~1\\AppData\\Local\\Temp\\...",
          event_type: "sysmon_file_created",
          raw: {
            ...baseResponse.results[0].raw,
            file: { path: "C:\\Users\\LOCALA~1\\AppData\\Local\\Temp\\very-long-folder\\payload-stage-one.ps1" },
          },
        },
      ],
    });
    renderPage();
    const row = await screen.findByTestId("search-row-event-evt-file-create");
    const snippet = within(row).getByTestId("search-snippet-cell");

    expect(snippet).toHaveTextContent("Sysmon file created: C:\\Users\\LOCALA~1\\AppData\\Local\\Temp\\very-long-folder\\payload-stage-one.ps1");
    expect(snippet).not.toHaveTextContent(/Temp\\\.\.\./);
    expect(snippet).toHaveAttribute("title", "Sysmon file created: C:\\Users\\LOCALA~1\\AppData\\Local\\Temp\\very-long-folder\\payload-stage-one.ps1");
  });

  it("uses full raw source file when the row source field is pre-truncated", async () => {
    searchCaseMock.mockResolvedValueOnce({
      ...baseResponse,
      results: [
        {
          ...baseResponse.results[0],
          id: "evt-source-truncated",
          source_file: "HOSTA/C/Windows/System32/winevt/Logs/...",
          raw: {
            ...baseResponse.results[0].raw,
            source_file: "HOSTA/C/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx",
          },
        },
      ],
    });
    renderPage();
    const row = await screen.findByTestId("search-row-event-evt-source-truncated");
    const sourcePivot = within(row).getByRole("button", { name: /pivot source file/i });

    expect(sourcePivot).toHaveTextContent("HOSTA/C/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx");
    expect(sourcePivot).toHaveAttribute("title", "HOSTA/C/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx");
  });

  it("facet click applies filter", async () => {
    renderPage();
    await screen.findByTestId("results-table");
    await userEvent.click(screen.getByRole("button", { name: /toggle facets/i }));
    await screen.findByText(/\+ browser · 53/i);
    await userEvent.click(screen.getByRole("button", { name: /include artifact_type browser/i }));
    await waitFor(() => expect(searchCaseMock).toHaveBeenLastCalledWith("case-1", expect.objectContaining({ filters: expect.stringContaining('"artifact.type"') })));
    expect(JSON.parse(searchCaseMock.mock.calls.at(-1)?.[1]?.filters)).toEqual([{ field: "artifact.type", operator: "is", value: "browser", negate: false }]);
  });

  it("facet exclude applies NOT filter", async () => {
    renderPage();
    await screen.findByTestId("results-table");
    await userEvent.click(screen.getByRole("button", { name: /toggle facets/i }));
    await userEvent.click(await screen.findByRole("button", { name: /exclude artifact_type browser/i }));
    await waitFor(() => expect(searchCaseMock).toHaveBeenLastCalledWith("case-1", expect.objectContaining({ filters: expect.stringContaining('"artifact.type"') })));
    expect(JSON.parse(searchCaseMock.mock.calls.at(-1)?.[1]?.filters)).toEqual([{ field: "artifact.type", operator: "is", value: "browser", negate: true }]);
    expect(screen.getByTestId("active-filter-chips")).toHaveTextContent(/NOT Artifact type is browser/i);
  });

  it("filter builder creates include and exclude chips", async () => {
    renderPage();
    await screen.findByTestId("results-table");
    await userEvent.click(screen.getByRole("button", { name: /add filter/i }));
    await userEvent.selectOptions(screen.getByLabelText(/Filter field/i), "process.command_line");
    await userEvent.selectOptions(screen.getByLabelText(/Filter operator/i), "contains");
    await userEvent.type(screen.getByLabelText(/Filter value/i), "powershell");
    await userEvent.click(screen.getByRole("button", { name: /add condition/i }));
    await waitFor(() => expect(searchCaseMock).toHaveBeenLastCalledWith("case-1", expect.objectContaining({ filters: expect.stringContaining("process.command_line") })));
    expect(screen.getByTestId("active-filter-chips")).toHaveTextContent(/Command line contains powershell/i);

    await userEvent.selectOptions(screen.getByLabelText(/Filter field/i), "message");
    await userEvent.selectOptions(screen.getByLabelText(/Filter operator/i), "contains");
    await userEvent.clear(screen.getByLabelText(/Filter value/i));
    await userEvent.type(screen.getByLabelText(/Filter value/i), "defender");
    await userEvent.click(screen.getByLabelText(/Exclude condition/i));
    await userEvent.click(screen.getByRole("button", { name: /add condition/i }));
    await waitFor(() => expect(screen.getByTestId("active-filter-chips")).toHaveTextContent(/NOT Message \/ text contains defender/i));
  });

  it("exists operator hides value input and remove condition updates filters", async () => {
    renderPage();
    await screen.findByTestId("results-table");
    await userEvent.click(screen.getByRole("button", { name: /add filter/i }));
    await userEvent.selectOptions(screen.getByLabelText(/Filter field/i), "host.name");
    await userEvent.selectOptions(screen.getByLabelText(/Filter operator/i), "exists");
    expect(screen.queryByLabelText(/Filter value/i)).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /add condition/i }));
    await waitFor(() => expect(screen.getByTestId("active-filter-chips")).toHaveTextContent(/Host exists/i));
    await userEvent.click(within(screen.getByTestId("active-filter-chips")).getByText(/Host exists/i));
    await waitFor(() => expect(screen.queryByText(/Host exists/i)).not.toBeInTheDocument());
  });

  it("quick filter applies and refreshes", async () => {
    renderPage();
    await screen.findByTestId("results-table");
    await userEvent.click(screen.getByRole("button", { name: /PowerShell activity/i }));
    await waitFor(() => expect(searchCaseMock).toHaveBeenLastCalledWith("case-1", expect.objectContaining({ scope: "events", process_name: "powershell.exe" })));
  });

  it("artifact specialized view renders DNS columns", async () => {
    renderPage(["/search?tab=artifact_views&artifact_type=dns"]);
    const table = await screen.findByTestId("artifact-view-table");
    expect(within(table).getByText("Domain")).toBeInTheDocument();
    expect(within(table).getByText("Record Type")).toBeInTheDocument();
    expect(within(table).getByText("duckdns.org")).toBeInTheDocument();
  });

  it("findings render in table", async () => {
    renderPage(["/search?tab=findings"]);
    await screen.findByTestId("findings-table");
    const row = await screen.findByTestId("search-row-finding-finding-1");
    expect(within(row).getByText(/WINWORD\.EXE spawned powershell\.exe/i)).toBeInTheDocument();
    expect(within(row).getByText("office_powershell")).toBeInTheDocument();
    await userEvent.click(within(row).getByRole("button", { name: "Actions" }));
    expect(await within(screen.getByTestId("search-actions-menu-finding-1")).findByRole("button", { name: /open finding/i })).toBeInTheDocument();
  });

  it("source file inline pivot replaces search same file action", async () => {
    renderPage();
    const processRow = await screen.findByTestId("search-row-event-evt-process");
    await userEvent.click(within(processRow).getByRole("button", { name: /pivot source file/i }));
    await userEvent.click(await screen.findByRole("button", { name: /filter by source file/i }));
    await waitFor(() => expect(searchCaseMock).toHaveBeenLastCalledWith("case-1", expect.objectContaining({ filters: expect.stringContaining('"source_file"') })));
    expect(JSON.parse(searchCaseMock.mock.calls.at(-1)?.[1]?.filters)).toEqual([{ field: "source_file", operator: "contains", value: "Security.evtx", negate: false }]);
  });

  it("around-event actions open Search with quick timestamp windows", async () => {
    renderPage(["/search?exclude_artifact_type=mft&exclude_source_file=Security.evtx&exclude_q=defender"]);
    const processRow = await screen.findByTestId("search-row-event-evt-process");
    await userEvent.click(within(processRow).getByRole("button", { name: "Actions" }));
    const menu = screen.getByTestId("search-actions-menu-evt-process");
    expect(await within(menu).findByRole("button", { name: /show ±30 seconds around this event/i })).toBeInTheDocument();
    expect(within(menu).getByRole("button", { name: /show ±5 minutes around this event/i })).toBeInTheDocument();
    await userEvent.click(within(menu).getByRole("button", { name: /show ±30 minutes around this event/i }));
    await waitFor(() => expect(searchAroundEventMock).not.toHaveBeenCalled());
    await waitFor(() =>
      expect(searchCaseMock).toHaveBeenLastCalledWith(
        "case-1",
        expect.objectContaining({
          evidence_id: "ev-1",
          time_from: "2026-05-15T09:30:00.000Z",
          time_to: "2026-05-15T10:30:00.000Z",
          sort: "timestamp_asc",
          exclude_artifact_type: ["mft"],
          exclude_source_file: "Security.evtx",
          exclude_q: "defender",
        }),
      ),
    );
  });

  it("shows active filter chips from url params", async () => {
    renderPage(["/search?risk_min=70&host=desktop-1&process_name=powershell.exe"]);
    const chips = await screen.findByTestId("active-filter-chips");
    expect(within(chips).getByText(/risk >= 70/i)).toBeInTheDocument();
    expect(within(chips).getByText(/host: desktop-1/i)).toBeInTheDocument();
    expect(within(chips).getByText(/process: powershell.exe/i)).toBeInTheDocument();
  });

  it("risk presets and custom range update persistent risk filters", async () => {
    renderPage();
    await screen.findByTestId("results-table");
    expect(screen.getByTestId("risk-filter-panel")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /risk preset critical/i }));
    await waitFor(() => expect(searchCaseMock).toHaveBeenLastCalledWith("case-1", expect.objectContaining({ risk_min: 75, risk_max: 100 })));
    expect(screen.getByTestId("active-filter-chips")).toHaveTextContent(/risk 75-100/i);

    await userEvent.clear(screen.getByLabelText(/Risk min/i));
    await userEvent.type(screen.getByLabelText(/Risk min/i), "50");
    await userEvent.clear(screen.getByLabelText(/Risk max/i));
    await userEvent.type(screen.getByLabelText(/Risk max/i), "75");
    await waitFor(() => expect(searchCaseMock).toHaveBeenLastCalledWith("case-1", expect.objectContaining({ risk_min: 50, risk_max: 75 })));

    await userEvent.click(screen.getByRole("button", { name: /clear risk/i }));
    await waitFor(() => expect(screen.queryByText(/risk 50-75/i)).not.toBeInTheDocument());
  });

  it("URL params persist query and selected tab", async () => {
    renderPage(["/search?q=payload.exe&tab=timeline"]);
    expect(await screen.findByDisplayValue("payload.exe")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Search Timeline/i })).toBeInTheDocument();
    expect(await screen.findByTestId("timeline-view")).toBeInTheDocument();
    expect(screen.getByText(/Explore matching Search results over time/i)).toBeInTheDocument();
  });

  it("search pagination uses offset page next and previous navigation", async () => {
    searchCaseMock.mockImplementation(async (_caseId: string, params: Record<string, unknown>) => {
      if (params.page === 2) {
        return {
          ...baseResponse,
          total: 120,
          page: 2,
          has_next: false,
          next_cursor: null,
          results: [
            {
              ...baseResponse.results[1],
              id: "evt-page-2",
              title: "Second page event",
              summary: "offset page 2",
            },
          ],
        };
      }
      return {
        ...baseResponse,
        total: 120,
        page: 1,
        has_next: true,
        next_cursor: "cursor-page-2",
      };
    });

    renderPage();
    await screen.findByTestId("results-table");
    const topPagination = screen.getByTestId("search-pagination-top");
    expect(within(topPagination).getByText(/Page 1/i)).toBeInTheDocument();
    expect(within(topPagination).getByRole("button", { name: /Previous page top/i })).toBeInTheDocument();
    expect(within(topPagination).getByRole("button", { name: /Next page top/i })).toBeInTheDocument();
    await userEvent.click(within(topPagination).getByRole("button", { name: /Next page top/i }));
    await waitFor(() => expect(searchCaseMock).toHaveBeenLastCalledWith("case-1", expect.objectContaining({ page: 2, cursor: undefined })));
    expect(await screen.findByTestId("search-row-event-evt-page-2")).toBeInTheDocument();
    expect(screen.getByTestId("search-row-event-evt-page-2")).toHaveTextContent(/offset page 2/i);
    expect(within(screen.getByTestId("search-pagination-top")).getByText(/Page 2/i)).toBeInTheDocument();

    await userEvent.click(within(screen.getByTestId("search-pagination-top")).getByRole("button", { name: /Previous page top/i }));
    expect(await screen.findByTestId("search-row-event-evt-process")).toBeInTheDocument();
    await waitFor(() => expect(within(screen.getByTestId("search-pagination-top")).getByText(/Page 1/i)).toBeInTheDocument());
  });

  it("passes advanced queries unchanged to the api", async () => {
    renderPage(['/search?q=artifact.type:ntfs%20risk_score%3E%3D70']);
    await screen.findByTestId("results-table");
    expect(searchCaseMock).toHaveBeenCalledWith("case-1", expect.objectContaining({ q: "artifact.type:ntfs risk_score>=70" }));
  });

  it("changing page size resets pagination back to page 1", async () => {
    searchCaseMock.mockImplementation(async (_caseId: string, params: Record<string, unknown>) => {
      if (params.page === 2) {
        return {
          ...baseResponse,
          total: 120,
          page: 2,
          has_next: false,
          next_cursor: null,
          results: [{ ...baseResponse.results[1], id: "evt-page-2", title: "Second page event" }],
        };
      }
      return {
        ...baseResponse,
        total: 120,
        page: 1,
        has_next: true,
        next_cursor: "cursor-page-2",
      };
    });

    renderPage();
    await screen.findByTestId("results-table");
    await userEvent.click(within(screen.getByTestId("search-pagination-top")).getByRole("button", { name: /Next page top/i }));
    expect(await screen.findByTestId("search-row-event-evt-page-2")).toBeInTheDocument();
    await userEvent.selectOptions(screen.getByLabelText("Page size top"), "100");
    await waitFor(() => expect(searchCaseMock).toHaveBeenLastCalledWith("case-1", expect.objectContaining({ cursor: undefined, page: 1, page_size: 100 })));
    expect(within(screen.getByTestId("search-pagination-top")).getByText(/Page 1/i)).toBeInTheDocument();
  });

  it("does not show the empty-search message for a false empty paginated page", async () => {
    searchCaseMock.mockResolvedValueOnce({ ...baseResponse, total: 120, page: 2, page_size: 50, results: [], has_next: true });
    renderPage(["/search?page=2&page_size=50"]);
    expect(await screen.findByText(/Pagination returned an empty page/i)).toBeInTheDocument();
    expect(screen.queryByText(/No results yet/i)).not.toBeInTheDocument();
  });

  it("renders empty state", async () => {
    searchCaseMock.mockResolvedValueOnce({ ...baseResponse, total: 0, results: [] });
    renderPage();
    expect(await screen.findByText(/No results yet/i)).toBeInTheDocument();
  });
});
