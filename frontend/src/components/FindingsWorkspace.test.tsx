import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type React from "react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import FindingsWorkspace from "./FindingsWorkspace";

const notifyMock = vi.fn();
const navigateMock = vi.fn();

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return {
    ...actual,
    useNavigate: () => navigateMock,
  };
});

vi.mock("../context/NotificationsContext", () => ({
  useNotifications: () => ({ notify: notifyMock }),
}));

vi.mock("../context/TimezoneContext", () => ({
  useTimezonePreference: () => ({ timezone: "UTC" }),
}));

vi.mock("./EventTable", () => ({
  default: ({ items, onViewProcessTree }: { items: Array<Record<string, unknown>>; onViewProcessTree?: (item: Record<string, unknown>) => void }) => (
    <div data-testid="event-table">
      {items.length} related events
      {onViewProcessTree && items[0] ? (
        <button type="button" onClick={() => onViewProcessTree(items[0])}>
          View process tree
        </button>
      ) : null}
    </div>
  ),
}));

type FindingRecord = Record<string, any>;

let findingStore: FindingRecord[] = [];
let relatedEventsStore: Record<string, any>[] = [];
const listFindingsMock = vi.fn();
const getFindingMock = vi.fn();
const updateFindingMock = vi.fn();
const runCorrelationMock = vi.fn();
const searchMock = vi.fn();

vi.mock("../api/client", () => ({
  api: {
    listFindings: (...args: unknown[]) => listFindingsMock(...args),
    getFinding: (...args: unknown[]) => getFindingMock(...args),
    updateFinding: (...args: unknown[]) => updateFindingMock(...args),
    runCorrelation: (...args: unknown[]) => runCorrelationMock(...args),
    search: (...args: unknown[]) => searchMock(...args),
  },
}));

function baseFinding(overrides: Partial<FindingRecord>): FindingRecord {
  return {
    id: "finding-1",
    case_id: "case-1",
    evidence_id: "ev-1",
    finding_type: "download_execute_detect",
    title: "Downloaded file executed and detected: payload.exe",
    summary: "payload.exe was downloaded, executed and later detected.",
    severity: "high",
    confidence: "high",
    status: "new",
    risk_score: 90,
    time_start: "2026-05-15T10:00:00Z",
    time_end: "2026-05-15T10:30:00Z",
    timeline: [
      { timestamp: "2026-05-15T10:00:00Z", event_id: "evt-1", artifact_type: "browser", event_type: "file_downloaded", summary: "Browser download observed" },
      { timestamp: "2026-05-15T10:05:00Z", event_id: "evt-2", artifact_type: "process", event_type: "process_start", summary: "Process created: chrome.exe -> payload.exe" },
    ],
    related_event_ids: ["evt-1", "evt-2"],
    related_artifact_ids: ["art-1"],
    related_evidence_ids: ["ev-1"],
    related_process_node_ids: ["{PAY-1}"],
    related_files: ["C:\\Users\\dfir\\Downloads\\payload.exe"],
    related_domains: ["evil.example"],
    related_ips: [],
    related_users: ["dfir"],
    related_hosts: ["desktop-test"],
    reasons: ["Downloaded file later executed", "Executed file later detected by Defender"],
    tags: ["correlation_engine", "download"],
    recommended_triage: ["review process tree", "review DNS/SRUM"],
    source: "correlation_engine",
    correlation_version: "v1",
    data_quality: [],
    created_at: "2026-05-16T10:00:00Z",
    updated_at: "2026-05-16T10:01:00Z",
    ...overrides,
  };
}

function renderWorkspace(props: Partial<React.ComponentProps<typeof FindingsWorkspace>> = {}) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={queryClient}>
        <FindingsWorkspace caseId="case-1" {...props} />
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("FindingsWorkspace", () => {
  beforeEach(() => {
    notifyMock.mockReset();
    navigateMock.mockReset();
    findingStore = [];
    relatedEventsStore = [];
    listFindingsMock.mockImplementation(async () => [...findingStore]);
    getFindingMock.mockImplementation(async (_caseId: string, findingId: string) => findingStore.find((item) => item.id === findingId));
    updateFindingMock.mockImplementation(async (_caseId: string, findingId: string, payload: FindingRecord) => {
      findingStore = findingStore.map((item) => (item.id === findingId ? { ...item, ...payload } : item));
      return findingStore.find((item) => item.id === findingId);
    });
    runCorrelationMock.mockResolvedValue({
      report: {
        findings_generated: 4,
        findings_deduplicated: 2,
        process_graph_available: true,
        by_type: { download_execute_detect: 1 },
        by_severity: { high: 1 },
        by_status: { new: 1 },
        scope: {
          case_id: "case-1",
          all_hosts: true,
          hosts: ["HOSTA", "HOSTB"],
          evidence_ids: ["ev-1", "ev-2"],
          sources: ["windows_event", "defender"],
          scope_type: "case_all_evidence",
          scope_reason: "all_case",
        },
        effective_scope: { case_id: "case-1", all_hosts: true, host: null, canonical_host: null, evidence_id: null },
        request_scope: { host: null, evidence_id: null },
        scope_reason: "all_case",
        correlation_run_id: "run-1",
        cache_key: "cache-all",
        reused_previous_run: false,
        counts: {
          candidates_scanned: 120,
          matched: 42,
          returned: 25,
          deduplicated: 2,
          hidden_by_limit: 17,
          has_more: true,
        },
        limits: {
          page: 1,
          page_size: 25,
          max_results: 25,
          max_candidates: 20000,
          reason: "default_safety",
        },
        source_breakdown: { windows_event: 100, defender: 20 },
        host_breakdown: { HOSTA: 80, HOSTB: 40 },
        result_source_breakdown: { download_execute_detect: 30, suspicious_process_chain: 12 },
        result_host_breakdown: { HOSTA: 22, HOSTB: 20 },
        pagination: { page: 1, page_size: 25, has_more: true, next_page: 2 },
      },
      findings: [],
    });
    searchMock.mockImplementation(async () => ({ items: [...relatedEventsStore], total: relatedEventsStore.length, page: 1, page_size: 50 }));
  });

  it("renders findings list with severity, confidence and status ordered by priority", async () => {
    findingStore = [
      baseFinding({ id: "low-1", title: "Low finding", severity: "low", confidence: "low", risk_score: 10 }),
      baseFinding({ id: "high-1", title: "High finding", severity: "high", confidence: "high", risk_score: 80 }),
      baseFinding({ id: "dismissed-1", title: "Dismissed finding", severity: "high", status: "dismissed", risk_score: 99 }),
    ];

    renderWorkspace();
    await waitFor(() => expect(screen.getAllByText("High finding").length).toBeGreaterThan(0));
    const cards = screen.getAllByTestId(/finding-card-/);
    const findingTitles = cards.map((node) => node.textContent ?? "");
    expect(findingTitles[0]).toContain("High finding");
    expect(screen.getAllByText("dismissed").length).toBeGreaterThan(0);
  });

  it("filters findings by severity and status", async () => {
    findingStore = [
      baseFinding({ id: "high-new", title: "High new", severity: "high", status: "new", finding_type: "download_execute_detect" }),
      baseFinding({ id: "high-dismissed", title: "High dismissed", severity: "high", status: "dismissed", finding_type: "download_execute_detect" }),
      baseFinding({ id: "medium-confirmed", title: "Medium confirmed", severity: "medium", status: "confirmed", finding_type: "cloud_exfil_candidate" }),
    ];

    renderWorkspace();
    await waitFor(() => expect(screen.getAllByText("High new").length).toBeGreaterThan(0));
    await userEvent.selectOptions(screen.getByLabelText("Severity"), "high");
    await userEvent.selectOptions(screen.getByLabelText("Status"), "dismissed");
    expect(screen.getAllByText("High dismissed").length).toBeGreaterThan(0);
    expect(screen.queryByText("High new")).not.toBeInTheDocument();
    expect(screen.queryByText("Medium confirmed")).not.toBeInTheDocument();
  });

  it("renders detail timeline, reasons and entities", async () => {
    findingStore = [baseFinding({ title: "Office -> PowerShell", finding_type: "office_powershell", related_domains: ["payload-update-free-ddns.duckdns.org"], related_hosts: ["desktop-corr"] })];
    relatedEventsStore = [{ id: "evt-1" }, { id: "evt-2" }];

    renderWorkspace();
    await waitFor(() => expect(screen.getAllByText("Office -> PowerShell").length).toBeGreaterThan(0));
    await userEvent.click(screen.getByTestId(`finding-card-${findingStore[0].id}`));
    const reasonsSection = screen.getByText("Reasons").closest("div");
    expect(reasonsSection).not.toBeNull();
    expect(within(reasonsSection as HTMLElement).getByText("Downloaded file later executed")).toBeInTheDocument();
    expect(screen.getByText("review process tree")).toBeInTheDocument();
    expect(screen.getByText("payload-update-free-ddns.duckdns.org")).toBeInTheDocument();
    expect(screen.getByText("desktop-corr")).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText("2 related events")).toBeInTheDocument());
  });

  it("updates status and keeps the finding visible", async () => {
    findingStore = [baseFinding({ id: "status-1", title: "Status target", status: "new" })];

    renderWorkspace();
    await waitFor(() => expect(screen.getAllByText("Status target").length).toBeGreaterThan(0));
    await userEvent.click(screen.getByTestId("finding-card-status-1"));
    await userEvent.selectOptions(screen.getByLabelText("Finding status"), "dismissed");
    await waitFor(() => expect(updateFindingMock).toHaveBeenCalled());
    await waitFor(() => expect(screen.getAllByText("dismissed").length).toBeGreaterThan(0));
  });

  it("runs correlation and refreshes findings", async () => {
    findingStore = [baseFinding({ title: "Correlation target" })];
    renderWorkspace();
    await waitFor(() => expect(screen.getAllByText("Correlation target").length).toBeGreaterThan(0));
    await userEvent.click(screen.getAllByRole("button", { name: /run correlation/i })[0]);
    await waitFor(() => expect(runCorrelationMock).toHaveBeenCalled());
    expect(runCorrelationMock).toHaveBeenCalledWith("case-1", expect.objectContaining({ host: undefined, evidence_id: undefined, page: 1, page_size: 25 }));
    await waitFor(() => expect(notifyMock).toHaveBeenCalledWith(expect.objectContaining({ title: "Correlation completed" })));
    expect(await screen.findByText(/Showing 25 of 42 correlated items/i)).toBeInTheDocument();
    expect(screen.getByText(/Scope: all hosts/i)).toBeInTheDocument();
    expect(screen.getByText(/candidates scanned: 120/i)).toBeInTheDocument();
    expect(screen.getByText(/cache cache-all/i)).toBeInTheDocument();
    expect(screen.getByText("Sources scanned")).toBeInTheDocument();
    expect(screen.getByText("Hosts scanned")).toBeInTheDocument();
    expect(screen.getByText("windows_event")).toBeInTheDocument();
    expect(screen.getAllByText("HOSTA").length).toBeGreaterThan(0);
    await userEvent.click(screen.getByRole("button", { name: /load more/i }));
    await waitFor(() => expect(runCorrelationMock).toHaveBeenLastCalledWith("case-1", expect.objectContaining({ page: 2, page_size: 25 })));
  });

  it("passes host when host scope is active and displays effective scope", async () => {
    findingStore = [baseFinding({ title: "HOSTA target", related_hosts: ["HOSTA"] })];
    runCorrelationMock.mockResolvedValueOnce({
      report: {
        findings_generated: 5,
        findings_deduplicated: 1,
        effective_scope: { case_id: "case-1", host: "HOSTA", canonical_host: "hosta", evidence_id: null, all_hosts: false },
        request_scope: { host: "HOSTA", evidence_id: null },
        scope_reason: "host",
        correlation_run_id: "run-hosta",
        cache_key: "cache-hosta",
        reused_previous_run: false,
        counts: { candidates_scanned: 20000, matched: 5, returned: 5, deduplicated: 1, hidden_by_limit: 0, has_more: false },
        limits: { page: 1, page_size: 25, reason: "none" },
        source_breakdown: {},
        host_breakdown: { HOSTA: 20000 },
        result_host_breakdown: { HOSTA: 5 },
      },
      findings: [],
    });
    renderWorkspace({ host: "HOSTA" });
    await waitFor(() => expect(screen.getAllByText("HOSTA target").length).toBeGreaterThan(0));
    await userEvent.click(screen.getAllByRole("button", { name: /run correlation/i })[0]);
    await waitFor(() => expect(runCorrelationMock).toHaveBeenCalledWith("case-1", expect.objectContaining({ host: "HOSTA", evidence_id: undefined })));
    expect(await screen.findByText(/Scope: hosta/i)).toBeInTheDocument();
    expect(screen.getByText(/cache cache-hosta/i)).toBeInTheDocument();
  });

  it("sends evidence filter together with host when both scopes are active", async () => {
    findingStore = [baseFinding({ title: "Scoped target", evidence_id: "ev-hosta", related_hosts: ["HOSTA"] })];
    renderWorkspace({ host: "HOSTA", evidenceId: "ev-hosta" });
    await waitFor(() => expect(screen.getAllByText("Scoped target").length).toBeGreaterThan(0));
    await userEvent.click(screen.getAllByRole("button", { name: /run correlation/i })[0]);
    await waitFor(() => expect(runCorrelationMock).toHaveBeenCalledWith("case-1", expect.objectContaining({ host: "HOSTA", evidence_id: "ev-hosta" })));
  });

  it("warns when backend effective scope differs from selected host", async () => {
    findingStore = [baseFinding({ title: "Mismatch target", related_hosts: ["HOSTA"] })];
    runCorrelationMock.mockResolvedValueOnce({
      report: {
        findings_generated: 22,
        findings_deduplicated: 0,
        effective_scope: { case_id: "case-1", host: null, canonical_host: null, evidence_id: null, all_hosts: false },
        request_scope: { host: "HOSTA", evidence_id: null },
        scope_reason: "all_case",
        correlation_run_id: "run-mismatch",
        cache_key: "cache-mismatch",
        reused_previous_run: false,
        counts: { candidates_scanned: 20000, matched: 22, returned: 22, deduplicated: 0, hidden_by_limit: 0, has_more: false },
        limits: { page: 1, page_size: 25, reason: "none" },
      },
      findings: [],
    });
    renderWorkspace({ host: "HOSTA" });
    await waitFor(() => expect(screen.getAllByText("Mismatch target").length).toBeGreaterThan(0));
    await userEvent.click(screen.getAllByRole("button", { name: /run correlation/i })[0]);
    expect(await screen.findByText(/Backend effective scope differs/i)).toBeInTheDocument();
  });

  it("shows empty state when there are no findings", async () => {
    findingStore = [];
    renderWorkspace();
    expect(await screen.findByText("No findings yet")).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: /run correlation/i }).length).toBeGreaterThan(0);
  });

  it("shows process graph link when related process nodes exist", async () => {
    findingStore = [baseFinding({ title: "Process graph finding", related_process_node_ids: ["{PS-1}", "{PAY-1}"] })];
    renderWorkspace();
    await waitFor(() => expect(screen.getAllByText("Process graph finding").length).toBeGreaterThan(0));
    await userEvent.click(screen.getByTestId(`finding-card-${findingStore[0].id}`));
    expect(screen.getByRole("button", { name: /open in process graph/i })).toBeInTheDocument();
  });

  it("opens process tree from related finding event when process context exists", async () => {
    findingStore = [baseFinding({ title: "Finding with process event" })];
    relatedEventsStore = [{ id: "evt-1", evidence_id: "ev-1", process: { pid: 4242, name: "powershell.exe" } }];

    renderWorkspace();
    await waitFor(() => expect(screen.getAllByText("Finding with process event").length).toBeGreaterThan(0));
    await userEvent.click(screen.getByTestId(`finding-card-${findingStore[0].id}`));
    await waitFor(() => expect(screen.getByText("1 related events")).toBeInTheDocument());
    await userEvent.click(screen.getAllByRole("button", { name: /view process tree/i })[0]);
    expect(navigateMock).toHaveBeenCalledWith("/cases/case-1/process-graph?mode=process_focus&evidence_id=ev-1&pid=4242&process_name=powershell.exe");
  });

  it("prefers process node ids over process name when opening process graph from related event", async () => {
    findingStore = [baseFinding({ title: "Finding with precise process node" })];
    relatedEventsStore = [{ id: "evt-1", evidence_id: "ev-1", related_process_node_ids: ["{PS-1}"], process: { pid: 4242, name: "powershell.exe" } }];

    renderWorkspace();
    await waitFor(() => expect(screen.getAllByText("Finding with precise process node").length).toBeGreaterThan(0));
    await userEvent.click(screen.getByTestId(`finding-card-${findingStore[0].id}`));
    await waitFor(() => expect(screen.getByText("1 related events")).toBeInTheDocument());
    await userEvent.click(screen.getAllByRole("button", { name: /view process tree/i })[0]);
    expect(navigateMock).toHaveBeenCalledWith("/cases/case-1/process-graph?mode=process_focus&evidence_id=ev-1&process_node_id=%7BPS-1%7D");
  });

  it("responsive finding drawer closes cleanly", async () => {
    findingStore = [baseFinding({ id: "responsive-1", title: "Responsive finding" })];
    renderWorkspace();
    await waitFor(() => expect(screen.getByText("Responsive finding")).toBeInTheDocument());
    await userEvent.click(screen.getByTestId("finding-card-responsive-1"));
    expect(await screen.findByTestId("responsive-detail-overlay")).toBeInTheDocument();
    expect(document.body.style.overflow).toBe("hidden");
    await userEvent.click(screen.getByRole("button", { name: /close detail panel/i }));
    await waitFor(() => expect(screen.queryByTestId("responsive-detail-overlay")).not.toBeInTheDocument());
    expect(document.body.style.overflow).toBe("");
  });
});
