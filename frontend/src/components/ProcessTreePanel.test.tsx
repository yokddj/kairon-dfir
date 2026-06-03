import type { ComponentProps } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import ProcessTreePanel from "./ProcessTreePanel";

const getProcessTreeMock = vi.fn();
const expandProcessTreeMock = vi.fn();
const getFocusedProcessTreeMock = vi.fn();
const getExecutionStoryMock = vi.fn();
const listFindingsMock = vi.fn();
const queryClients: QueryClient[] = [];

vi.mock("../api/client", () => ({
  api: {
    getProcessTree: (...args: unknown[]) => getProcessTreeMock(...args),
    expandProcessTree: (...args: unknown[]) => expandProcessTreeMock(...args),
    getFocusedProcessTree: (...args: unknown[]) => getFocusedProcessTreeMock(...args),
    getExecutionStory: (...args: unknown[]) => getExecutionStoryMock(...args),
    listFindings: (...args: unknown[]) => listFindingsMock(...args),
  },
}));

function LocationProbe() {
  const location = useLocation();
  return <div data-testid="location-probe">{`${location.pathname}${location.search}`}</div>;
}

function renderPanel(props: Partial<ComponentProps<typeof ProcessTreePanel>> = {}, path = "/cases/case-1/process-graph") {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
        gcTime: Infinity,
      },
    },
  });
  queryClients.push(queryClient);
  return render(
    <MemoryRouter initialEntries={[path]}>
      <QueryClientProvider client={queryClient}>
        <Routes>
          <Route
            path="/cases/:caseId/process-graph"
            element={
              <>
                <LocationProbe />
                <ProcessTreePanel
                  caseId="case-1"
                  evidences={[{ id: "ev-1", case_id: "case-1", original_filename: "example-collection.zip", stored_path: "", original_path: null, storage_mode: "uploaded", is_external: false, copy_to_storage: true, evidence_type: "zip", sha256: "", size_bytes: 1, file_count: null, ingest_status: "completed", detected_host: "TEST-WIN10-01", detected_user: null, source_tool: "raw_collection", path_validation: {}, ingest_source: {}, metadata_json: {}, error_log: {}, created_at: "2026-05-18T09:00:00Z", processed_at: "2026-05-18T09:10:00Z" }]}
                  selectedHost="TEST-WIN10-01"
                  selectedEvidenceId="ev-1"
                  {...props}
                />
              </>
            }
          />
          <Route path="/cases/:caseId/search" element={<LocationProbe />} />
          <Route path="/cases/:caseId/timeline" element={<LocationProbe />} />
          <Route path="/cases/:caseId/findings" element={<LocationProbe />} />
          <Route path="/cases/:caseId/command-history" element={<LocationProbe />} />
        </Routes>
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

const baseBundle = {
  graph: {
    case_id: "case-1",
    evidence_id: "ev-1",
    scope: "evidence",
    summary: {
      nodes_count: 4,
      edges_count: 2,
      root_nodes_count: 2,
      high_risk_nodes_count: 1,
      suspicious_chains_count: 1,
      warnings: [],
      warnings_summary: {},
      warnings_samples: [],
    },
    nodes: [
      {
        id: "office",
        pid: 100,
        name: "winword.exe",
        path: "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
        command_line: "WINWORD.EXE",
        user: "alex",
        sid: null,
        host: "TEST-WIN10-01",
        first_seen: "2026-05-15T10:00:00Z",
        last_seen: "2026-05-15T10:00:00Z",
        source_events: ["evt-office"],
        risk_score: 15,
        risk_reasons: [],
        badges: [],
        data_quality: [],
        confidence: "high",
        parent_name: null,
        parent_pid: null,
      },
      {
        id: "ps",
        pid: 200,
        name: "powershell.exe",
        path: "C:\\Users\\alex\\Downloads\\payload.exe",
        command_line: "powershell.exe -EncodedCommand AAAA",
        user: "alex",
        sid: null,
        host: "TEST-WIN10-01",
        first_seen: "2026-05-15T10:01:00Z",
        last_seen: "2026-05-15T10:01:00Z",
        source_events: ["evt-ps"],
        risk_score: 95,
        risk_reasons: ["Office spawned script interpreter", "Process uses encoded PowerShell"],
        badges: ["office_child", "suspicious_chain", "powershell", "encoded_command", "lolbin"],
        data_quality: [],
        confidence: "high",
        parent_name: "winword.exe",
        parent_pid: 100,
        parent_link_status: "linked",
        parent_link_reason: "Linked exactly by Sysmon ProcessGuid / ParentProcessGuid.",
        parent_link_confidence: "high",
        parent_fields: { parent_name: "winword.exe", parent_pid: 100, parent_entity_id: "office", host: "TEST-WIN10-01" },
      },
      {
        id: "edge-parent",
        pid: 300,
        name: "msedge.exe",
        path: "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
        command_line: "msedge.exe",
        user: "alex",
        sid: null,
        host: "TEST-WIN10-01",
        first_seen: "2026-05-15T10:03:00Z",
        last_seen: "2026-05-15T10:03:00Z",
        source_events: ["evt-edge-parent"],
        risk_score: 5,
        risk_reasons: [],
        badges: [],
        data_quality: [],
        confidence: "high",
        parent_name: null,
        parent_pid: null,
      },
      {
        id: "edge-child",
        pid: 301,
        name: "msedge.exe",
        path: "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
        command_line: "msedge.exe --type=renderer",
        user: "alex",
        sid: null,
        host: "TEST-WIN10-01",
        first_seen: "2026-05-15T10:03:05Z",
        last_seen: "2026-05-15T10:03:05Z",
        source_events: ["evt-edge-child"],
        risk_score: 20,
        risk_reasons: [],
        badges: ["browser_internal_child", "low_noise_process"],
        data_quality: ["noisy_browser_child"],
        confidence: "high",
        parent_name: "msedge.exe",
        parent_pid: 300,
      },
    ],
    edges: [
      { id: "edge-1", source: "office", target: "ps", type: "spawned", confidence: "high", reason: "sysmon_parent_process_guid", source_event_id: "evt-ps" },
      { id: "edge-2", source: "edge-parent", target: "edge-child", type: "spawned", confidence: "high", reason: "sysmon_parent_process_guid", source_event_id: "evt-edge-child" },
    ],
  },
  report: {},
  sample_chains: [
    {
      chain: [
        { id: "office", name: "winword.exe", path: "C:\\Program Files\\Microsoft Office\\WINWORD.EXE", command_line: "WINWORD.EXE", risk_score: 15, badges: [] },
        { id: "ps", name: "powershell.exe", path: "C:\\Users\\alex\\Downloads\\payload.exe", command_line: "powershell.exe -EncodedCommand AAAA", risk_score: 95, badges: ["office_child", "suspicious_chain"] },
      ],
      edge: { source: "office", target: "ps", type: "spawned", confidence: "high", reason: "sysmon_parent_process_guid", source_event_id: "evt-ps" },
      reasons: ["Office spawned script interpreter"],
    },
    {
      chain: [
        { id: "edge-parent", name: "msedge.exe", path: "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe", command_line: "msedge.exe", risk_score: 5, badges: [] },
        { id: "edge-child", name: "msedge.exe", path: "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe", command_line: "msedge.exe --type=renderer", risk_score: 20, badges: ["browser_internal_child"] },
      ],
      edge: { source: "edge-parent", target: "edge-child", type: "spawned", confidence: "high", reason: "sysmon_parent_process_guid", source_event_id: "evt-edge-child" },
      reasons: [],
    },
  ],
};

const baseExecutionStory = {
  target: baseBundle.graph.nodes[1],
  target_node_id: "ps",
  default_selected_node_id: "ps",
  story: {
    summary: "powershell.exe PID 200 was launched by winword.exe PID 100 and launched no direct children.",
    parent_sentence: "This powershell.exe PID 200 was launched by winword.exe PID 100.",
    children_sentence: "It launched no direct children.",
    activity_sentence: "No activity groups were observed.",
    risk_sentence: "Suspicious because Process uses encoded PowerShell.",
  },
  parents: [baseBundle.graph.nodes[0]],
  children: [],
  siblings: [],
  activity_groups: { items: [], omitted_counts: {} },
  commands: [],
  source_events: ["evt-ps"],
  visual_tree: {
    nodes: baseBundle.graph.nodes.slice(0, 2),
    edges: [baseBundle.graph.edges[0]],
  },
  quality: {
    confidence: "high",
    missing_parent: false,
    ambiguous_pid: false,
    warnings: [],
    identity_resolution: { method: "process_guid", confidence: "high", ambiguous_candidates: [], parent_explanation: "This powershell.exe PID 200 was launched by winword.exe PID 100." },
    exact_story: true,
    origin: "search_event",
    filter_scope: "exact_chain",
    visual_tree_contains_target: true,
  },
};

describe("ProcessTreePanel", () => {
  beforeEach(() => {
    getProcessTreeMock.mockResolvedValue(baseBundle);
    expandProcessTreeMock.mockResolvedValue({
      base_node: null,
      added_nodes: [],
      added_edges: [],
      activity_groups: [],
      omitted_counts: {},
      warnings: [],
      summary: {},
    });
    getFocusedProcessTreeMock.mockResolvedValue({
      focus_node: null,
      parents: [],
      children: [],
      siblings: [],
      activity_groups: [],
      nodes: [],
      edges: [],
      omitted_counts: {},
      warnings: [],
      identity_resolution: { method: "pid_timestamp_host", confidence: "high", ambiguous_candidates: [], parent_explanation: "" },
    });
    getExecutionStoryMock.mockResolvedValue(baseExecutionStory);
    listFindingsMock.mockResolvedValue([
      {
        id: "finding-1",
        case_id: "case-1",
        title: "Office spawned PowerShell",
        severity: "high",
        status: "confirmed",
        risk_score: 95,
        related_process_node_ids: ["ps"],
      },
    ]);
  });

  afterEach(() => {
    for (const client of queryClients.splice(0)) {
      client.clear();
      if ("destroy" in client && typeof client.destroy === "function") client.destroy();
    }
    vi.clearAllMocks();
  });

  it("renders suspicious view and suppresses browser internal chains by default", async () => {
    renderPanel();
    expect((await screen.findAllByText(/^Execution Story$/i)).length).toBeGreaterThan(0);
    expect(await screen.findByText("winword.exe → powershell.exe")).toBeInTheDocument();
    expect(screen.getByText(/Graph canvas/i)).toBeInTheDocument();
    expect(screen.getByTestId("process-graph-mode-banner")).toHaveTextContent(/Process search/i);
    expect(screen.queryByText("msedge.exe → msedge.exe")).not.toBeInTheDocument();
  });

  it("renders Execution Story overview without making node clicks change the target", async () => {
    renderPanel();
    expect((await screen.findAllByText(/Execution Story/i)).length).toBeGreaterThan(0);
    expect(await screen.findByText(/Investigating/i)).toBeInTheDocument();
    expect((await screen.findAllByText(/This powershell.exe PID 200 was launched by winword.exe PID 100/i)).length).toBeGreaterThan(0);
    await userEvent.click((await screen.findAllByRole("button", { name: /^Focus$/i }))[0]);
    await userEvent.click(await screen.findByRole("button", { name: /^Make target$/i }));
    await waitFor(() =>
      expect(getExecutionStoryMock).toHaveBeenCalledWith(
        "case-1",
        expect.objectContaining({
          process_guid: "ps",
          source_event_id: "evt-ps",
          pid: 200,
          q: undefined,
        }),
      ),
    );
    await userEvent.click(screen.getAllByText("winword.exe")[0]);
    expect(screen.getAllByText(/This powershell.exe PID 200 was launched by winword.exe PID 100/i).length).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: /^Advanced graph$/i })).toBeInTheDocument();
  });

  it("primary search accepts an exact PID and builds a story", async () => {
    renderPanel();
    await userEvent.clear(screen.getByPlaceholderText(/powershell.exe, 12720/i));
    await userEvent.type(screen.getByPlaceholderText(/powershell.exe, 12720/i), "11784");
    await userEvent.click(screen.getByRole("button", { name: /^Build story$/i }));
    await waitFor(() => expect(getExecutionStoryMock).toHaveBeenCalledWith("case-1", expect.objectContaining({ pid: 11784 })));
  });

  it("auto-builds the exact story when opened from a Search source event", async () => {
    renderPanel({
      initialEvidenceId: "ev-1",
      initialPid: "200",
      initialProcessGuid: "ps",
      initialSourceEventId: "search-doc-1",
      initialTimestamp: "2024-03-22T11:24:00Z",
      openedFromSearchEventId: "search-doc-1",
      initialMode: "focused",
    });

    await waitFor(() =>
      expect(getExecutionStoryMock).toHaveBeenCalledWith(
        "case-1",
        expect.objectContaining({
          evidence_id: "ev-1",
          host: "TEST-WIN10-01",
          pid: 200,
          process_guid: "ps",
          source_event_id: "search-doc-1",
          timestamp: "2024-03-22T11:24:00Z",
        }),
      ),
    );
    expect(await screen.findByText("Opened from Search event")).toBeInTheDocument();
    expect((await screen.findAllByText("Exact story")).length).toBeGreaterThan(0);
    expect(screen.getByText(/Risk filters only affect candidate search, suspicious chain suggestions and extra context/i)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /Back to Search event/i }));
    expect(screen.getByTestId("location-probe")).toHaveTextContent("/cases/case-1/search?event_id=search-doc-1");
  });

  it("renders lightweight generic event guidance with candidate process actions", async () => {
    getExecutionStoryMock.mockResolvedValueOnce({
      ...baseExecutionStory,
      target: null,
      target_node_id: null,
      default_selected_node_id: null,
      parents: [],
      children: [],
      siblings: [],
      activity_groups: { items: [], omitted_counts: {} },
      visual_tree: { nodes: [], edges: [] },
      event_summary: {
        source: "Microsoft-Windows-PowerShell / Operational / EventID 4103",
        host: "HOSTA",
        timestamp: "2024-03-22T11:26:45Z",
        title: "PowerShell module logging",
      },
      candidate_processes: [baseBundle.graph.nodes[1]],
      quality: {
        ...baseExecutionStory.quality,
        exact_story: false,
        target_quality: "related",
        response_mode: "lightweight",
        activity_lazy: true,
        identity_resolution: { method: "source_event_id_process_context", confidence: "medium", ambiguous_candidates: [], parent_explanation: "" },
      },
    });
    renderPanel({
      initialEvidenceId: "ev-1",
      initialSourceEventId: "search-doc-1",
      openedFromSearchEventId: "search-doc-1",
      initialMode: "focused",
    });

    expect(await screen.findByText(/This is not an exact process creation event/i)).toBeInTheDocument();
    expect(screen.getByText(/Candidate processes/i)).toBeInTheDocument();
    await userEvent.click(await screen.findByTitle(/Build exact story from this process/i));
    await waitFor(() => expect(getExecutionStoryMock).toHaveBeenCalledTimes(2));
    expect(getExecutionStoryMock).toHaveBeenLastCalledWith("case-1", expect.objectContaining({ process_guid: "ps", source_event_id: "evt-ps" }));
  });

  it("uses the exact story target as the default selected detail instead of stale canvas state", async () => {
    renderPanel({
      initialEvidenceId: "ev-1",
      initialHighlightedNodeIds: ["edge-child"],
      initialPid: "200",
      initialProcessGuid: "ps",
      initialSourceEventId: "search-doc-1",
      initialTimestamp: "2024-03-22T11:24:00Z",
      openedFromSearchEventId: "search-doc-1",
      initialMode: "focused",
    });

    await waitFor(() => expect(getExecutionStoryMock).toHaveBeenCalled());
    expect(await screen.findByText(/Exact story: powershell.exe/i)).toBeInTheDocument();
    const detail = await screen.findByTestId("selected-node-detail");
    expect(within(detail).getAllByText(/powershell.exe PID 200/i).length).toBeGreaterThan(0);
    expect(within(detail).queryByText(/Story target remains/i)).not.toBeInTheDocument();
    expect(within(detail).queryByText(/msedge.exe/i)).not.toBeInTheDocument();
  });

  it("renders summary badges from the visible graph model", async () => {
    renderPanel();
    await screen.findByText("winword.exe → powershell.exe");
    const totalBadge = screen.getByText("Total graph").parentElement as HTMLElement;
    const nodesBadge = screen.getByText("Visible nodes").parentElement as HTMLElement;
    const edgesBadge = screen.getByText("Visible edges").parentElement as HTMLElement;
    const chainsBadge = screen.getByText("Chains").parentElement as HTMLElement;
    expect(within(totalBadge).getByText("4")).toBeInTheDocument();
    expect(within(nodesBadge).getByText("2")).toBeInTheDocument();
    expect(within(edgesBadge).getByText("1")).toBeInTheDocument();
    expect(within(chainsBadge).getByText("1")).toBeInTheDocument();
  });

  it("full mode reveals low-noise browser internals", async () => {
    renderPanel();
    await screen.findByText("winword.exe → powershell.exe");
    await userEvent.selectOptions(screen.getByRole("combobox", { name: /graph mode/i }), "full");
    await userEvent.click(screen.getByRole("button", { name: /^Back to results$/i }));
    expect(await screen.findByTestId("process-graph-mode-banner")).toHaveTextContent(/Advanced graph/i);
    expect(screen.getByTestId("process-graph-mode-banner")).toHaveTextContent(/Filters and noise controls may hide context/i);
    expect(await screen.findAllByText("msedge.exe")).not.toHaveLength(0);
  });

  it("selecting a suspicious chain focuses the node detail and related finding", async () => {
    renderPanel();
    await userEvent.click(await screen.findByRole("button", { name: /^Focus$/i }));
    expect((await screen.findAllByText(/Command:/i)).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Parent status:/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/Linked exactly by Sysmon ProcessGuid/i)).toBeInTheDocument();
    expect(screen.getByText("Office spawned PowerShell")).toBeInTheDocument();
    expect(screen.getByTestId("process-graph-mode-banner")).toHaveTextContent(/Process search/i);
    expect(screen.getByText(/Focused on suspicious chain:/i)).toBeInTheDocument();
  });

  it("small layouts open selected node detail in a responsive drawer", async () => {
    renderPanel();
    await userEvent.click((await screen.findAllByRole("button", { name: /^Focus$/i }))[0]);
    expect(await screen.findByTestId("responsive-detail-overlay")).toBeInTheDocument();
    expect(document.body.style.overflow).toBe("hidden");
    await userEvent.click(screen.getByRole("button", { name: /close detail panel/i }));
    await waitFor(() => expect(screen.queryByTestId("responsive-detail-overlay")).not.toBeInTheDocument());
    expect(document.body.style.overflow).toBe("");
  });

  it("renders empty state when graph has no nodes", async () => {
    getProcessTreeMock.mockResolvedValueOnce({
      ...baseBundle,
      graph: {
        ...baseBundle.graph,
        nodes: [],
        edges: [],
        summary: { ...baseBundle.graph.summary, nodes_count: 0, edges_count: 0, suspicious_chains_count: 0 },
      },
      sample_chains: [],
    });
    renderPanel();
    expect(await screen.findByText(/No process graph nodes found for the current filters/i)).toBeInTheDocument();
  });

  it("renders aggregated warning summaries without crashing", async () => {
    getProcessTreeMock.mockResolvedValueOnce({
      ...baseBundle,
      graph: {
        ...baseBundle.graph,
        summary: {
          ...baseBundle.graph.summary,
          warnings_summary: {
            ambiguous_parent_candidates: 217,
          },
          warnings_samples: ["node A", "node B"],
        },
      },
    });
    renderPanel();
    expect(await screen.findByText(/217 ambiguous parent candidates/i)).toBeInTheDocument();
  });

  it("shows structured orphan parent diagnostics", async () => {
    getProcessTreeMock.mockResolvedValueOnce({
      ...baseBundle,
      graph: {
        ...baseBundle.graph,
        summary: {
          ...baseBundle.graph.summary,
          warnings_summary: { parent_not_found: 1 },
          orphan_diagnostics: [
            {
              id: "cmd-orphan",
              process_name: "cmd.exe",
              pid: 444,
              timestamp: "2026-05-15T10:02:00Z",
              command_line: "cmd.exe /c psexec.exe",
              parent_fields: { parent_name: "explorer.exe", parent_pid: 333, parent_entity_id: null },
              parent_link_status: "parent_not_found",
              parent_link_reason: "Parent PID/name was present, but no earlier matching parent event was found in the graph context.",
              parent_link_confidence: "none",
            },
          ],
        },
      },
    });
    renderPanel();
    expect(await screen.findByText(/Diagnostics · 1 parent links need review/i)).toBeInTheDocument();
    expect(screen.getAllByText(/cmd.exe/).length).toBeGreaterThan(0);
    expect(screen.getByText(/explorer.exe/)).toBeInTheDocument();
  });

  it("does not crash when optional node fields are undefined", async () => {
    getProcessTreeMock.mockResolvedValueOnce({
      ...baseBundle,
      graph: {
        ...baseBundle.graph,
        nodes: [
          {
            ...baseBundle.graph.nodes[0],
            command_line: undefined,
            path: undefined,
            parent_name: undefined,
            source_events: undefined,
          },
          baseBundle.graph.nodes[1],
        ],
        edges: [baseBundle.graph.edges[0]],
      },
      sample_chains: [baseBundle.sample_chains[0]],
    });
    renderPanel();
    expect((await screen.findAllByText(/^Execution Story$/i)).length).toBeGreaterThan(0);
  });

  it("renders fallback when the graph renderer throws", async () => {
    renderPanel({ debugThrowRenderError: true });
    expect(await screen.findByText(/Process graph could not be rendered/i)).toBeInTheDocument();
  });

  it("open selected in Search and Timeline navigate correctly", async () => {
    const first = renderPanel();
    await userEvent.click((await screen.findAllByRole("button", { name: /^Focus$/i }))[0]);
    await userEvent.click(screen.getByRole("button", { name: /Open selected in Search/i }));
    await waitFor(() => expect(screen.getByTestId("location-probe").textContent).toContain("/cases/case-1/search"));

    first.unmount();
    renderPanel();
    await userEvent.click((await screen.findAllByRole("button", { name: /^Focus$/i }))[0]);
    await userEvent.click(screen.getByRole("button", { name: /Open selected in Timeline/i }));
    await waitFor(() => expect(screen.getByTestId("location-probe").textContent).toContain("/cases/case-1/timeline"));
  });

  it("initial highlighted node opens focused detail", async () => {
    renderPanel({ initialHighlightedNodeIds: ["ps"] });
    expect((await screen.findAllByText(/Command:/i)).length).toBeGreaterThan(0);
  });

  it("shows truncation warning when graph exceeds render limit", async () => {
    const largeNodes = Array.from({ length: 140 }, (_, index) => ({
      id: `node-${index}`,
      pid: 1000 + index,
      name: `proc-${index}.exe`,
      path: `C:\\Users\\alex\\proc-${index}.exe`,
      command_line: `proc-${index}.exe`,
      user: "alex",
      sid: null,
      host: "TEST-WIN10-01",
      first_seen: "2026-05-15T10:00:00Z",
      last_seen: "2026-05-15T10:00:00Z",
      source_events: [`evt-${index}`],
      risk_score: 80,
      risk_reasons: ["Synthetic suspicious process"],
      badges: ["suspicious_chain"],
      data_quality: [],
      confidence: "high",
      parent_name: null,
      parent_pid: null,
    }));
    const largeEdges = Array.from({ length: 139 }, (_, index) => ({
      id: `edge-${index}`,
      source: `node-${index}`,
      target: `node-${index + 1}`,
      type: "spawned",
      confidence: "high",
      reason: "synthetic_chain",
      source_event_id: `evt-${index + 1}`,
    }));
    getProcessTreeMock.mockResolvedValueOnce({
      graph: {
        ...baseBundle.graph,
        nodes: largeNodes,
        edges: largeEdges,
        summary: { ...baseBundle.graph.summary, nodes_count: 140, edges_count: 139, high_risk_nodes_count: 140, suspicious_chains_count: 1 },
      },
      report: {},
      sample_chains: [
        {
          chain: largeNodes.map((node) => ({
            id: node.id,
            name: node.name,
            path: node.path,
            command_line: node.command_line,
            risk_score: node.risk_score,
            badges: node.badges,
          })),
          edge: largeEdges[largeEdges.length - 1],
          reasons: ["Synthetic oversized suspicious chain"],
        },
      ],
    });
    renderPanel();
    await userEvent.click(await screen.findByRole("button", { name: /^Focus$/i }));
    expect(await screen.findByText(/Graph truncated to 120 nodes/i)).toBeInTheDocument();
  });

  it("focused process route renders process focus chip", async () => {
    renderPanel({ initialMode: "focused", initialHighlightedNodeIds: ["ps"], initialProcessName: "powershell.exe" }, "/cases/case-1/process-graph?mode=process_focus&process_node_id=ps");
    expect(await screen.findByText(/Focused on process:/i)).toBeInTheDocument();
    expect(screen.getByTestId("process-graph-mode-banner")).toHaveTextContent(/Process search/i);
  });

  it("focused finding route renders finding focus chip", async () => {
    renderPanel({ initialFindingId: "finding-1", initialMode: "focused", initialHighlightedNodeIds: ["ps"] }, "/cases/case-1/process-graph?mode=finding_focus&finding_id=finding-1&node_id=ps");
    expect(await screen.findByText(/Focused on finding:/i)).toBeInTheDocument();
  });

  it("focused mode can expand parent context", async () => {
    const expandedBundle = {
      ...baseBundle,
      graph: {
        ...baseBundle.graph,
        summary: { ...baseBundle.graph.summary, nodes_count: 5, edges_count: 3 },
        nodes: [
          {
            id: "launcher",
            pid: 50,
            name: "explorer.exe",
            path: "C:\\Windows\\explorer.exe",
            command_line: "explorer.exe",
            user: "alex",
            sid: null,
            host: "TEST-WIN10-01",
            first_seen: "2026-05-15T09:59:00Z",
            last_seen: "2026-05-15T09:59:00Z",
            source_events: ["evt-launcher"],
            risk_score: 5,
            risk_reasons: [],
            badges: [],
            data_quality: [],
            confidence: "high",
            parent_name: null,
            parent_pid: null,
          },
          ...baseBundle.graph.nodes,
        ],
        edges: [{ id: "edge-0", source: "launcher", target: "office", type: "spawned", confidence: "high", reason: "test", source_event_id: "evt-office" }, ...baseBundle.graph.edges],
      },
    };
    getProcessTreeMock.mockResolvedValueOnce(expandedBundle);
    renderPanel();
    await userEvent.click((await screen.findAllByRole("button", { name: /^Focus$/i }))[0]);
    expect(screen.getByText(/Showing \d+ of \d+ visible nodes/i)).toBeInTheDocument();
    const parentButtons = screen.getAllByRole("button", { name: /^Parents$/i });
    await userEvent.click(parentButtons[0]);
    expect(await screen.findByText(/Showing \d+ of \d+ visible nodes/i)).toBeInTheDocument();
  });

  it("groups repeated ambiguous warnings instead of rendering spam", async () => {
    getProcessTreeMock.mockResolvedValueOnce({
      ...baseBundle,
      graph: {
        ...baseBundle.graph,
        summary: {
          ...baseBundle.graph.summary,
          warnings: Array.from({ length: 100 }, (_, index) => `Ambiguous parent candidates for node node-${index}`),
          warnings_summary: { ambiguous_parent_candidates: 100, parent_not_found: 0, possible_pid_reuse: 0 },
          warnings_samples: Array.from({ length: 10 }, (_, index) => `Ambiguous parent candidates for node node-${index}`),
        },
      },
    });
    renderPanel();
    expect(await screen.findByText(/100 ambiguous parent candidates/i)).toBeInTheDocument();
    expect(screen.queryByText(/node-50/)).not.toBeInTheDocument();
  });

  it("shows a clear empty state when the API returns no nodes", async () => {
    getProcessTreeMock.mockResolvedValueOnce({
      graph: {
        case_id: "case-1",
        evidence_id: "ev-1",
        scope: "evidence",
        summary: { nodes_count: 0, edges_count: 0, root_nodes_count: 0, high_risk_nodes_count: 0, suspicious_chains_count: 0, warnings: [], warnings_summary: {}, warnings_samples: [] },
        nodes: [],
        edges: [],
      },
      report: {},
      sample_chains: [],
    });
    renderPanel();
    expect(await screen.findByText(/No process graph nodes found for the current filters/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Reset filters/i })).toBeInTheDocument();
  });

  it("node detail exposes controlled expansion actions", async () => {
    renderPanel();
    await userEvent.click((await screen.findAllByRole("button", { name: /^Focus$/i }))[0]);
    expect((await screen.findAllByText(/This powershell.exe PID 200 was launched by winword.exe PID 100/i)).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/ProcessGuid:/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Children:/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Siblings:/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Activity:/i).length).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: /^Make target$/i })).toBeInTheDocument();
    expect((await screen.findAllByRole("button", { name: /^Children$/i })).length).toBeGreaterThan(0);
    expect(screen.getAllByRole("button", { name: /^Parents$/i }).length).toBeGreaterThan(0);
    expect(screen.getAllByRole("button", { name: /^Siblings$/i }).length).toBeGreaterThan(0);
    expect(screen.getAllByRole("button", { name: /^Activity$/i }).length).toBeGreaterThan(0);
  });

  it("can build an execution story from the selected node", async () => {
    getExecutionStoryMock.mockResolvedValueOnce(baseExecutionStory);
    renderPanel();
    await userEvent.click((await screen.findAllByRole("button", { name: /^Focus$/i }))[0]);
    await userEvent.click(await screen.findByRole("button", { name: /^Make target$/i }));
    await waitFor(() =>
      expect(getExecutionStoryMock).toHaveBeenCalledWith(
        "case-1",
        expect.objectContaining({
          process_guid: "ps",
          source_event_id: "evt-ps",
          pid: 200,
          q: undefined,
        }),
      ),
    );
    expect((await screen.findAllByText(/This powershell.exe PID 200 was launched by winword.exe PID 100/i)).length).toBeGreaterThan(0);
  });

  it("has PID and ProcessGuid filters for focused tree builds", async () => {
    renderPanel();
    await userEvent.click(await screen.findByRole("button", { name: /Advanced filters/i }));
    await userEvent.type(screen.getByPlaceholderText("1234"), "200");
    await userEvent.type(screen.getByPlaceholderText(/\{guid\}/i), "ps");
    await userEvent.click(screen.getByRole("button", { name: /^Build story$/i }));
    await waitFor(() => expect(getExecutionStoryMock).toHaveBeenCalledWith("case-1", expect.objectContaining({ pid: 200, process_guid: "ps" })));
  });

  it("expand children adds returned nodes without duplicating repeated expansions", async () => {
    expandProcessTreeMock.mockResolvedValue({
      base_node: null,
      added_nodes: [
        {
          id: "child-cmd",
          pid: 300,
          name: "cmd.exe",
          path: "C:\\Windows\\System32\\cmd.exe",
          command_line: "cmd.exe /c whoami",
          user: "alex",
          sid: null,
          host: "TEST-WIN10-01",
          first_seen: "2026-05-15T10:02:00Z",
          last_seen: "2026-05-15T10:02:00Z",
          source_events: ["evt-cmd"],
          risk_score: 45,
          risk_reasons: ["Command shell spawned"],
          badges: ["shell"],
          data_quality: [],
          confidence: "high",
          parent_name: "powershell.exe",
          parent_pid: 200,
        },
      ],
      added_edges: [{ id: "ps-child-cmd", source: "ps", target: "child-cmd", type: "parent_child", confidence: "high", reason: "test child" }],
      activity_groups: [],
      omitted_counts: {},
      warnings: [],
      summary: {},
    });
    renderPanel();
    await userEvent.click((await screen.findAllByRole("button", { name: /^Focus$/i }))[0]);
    const childButtons = await screen.findAllByRole("button", { name: /^Children$/i });
    await userEvent.click(childButtons[childButtons.length - 1]);
    const firstRenderCount = (await screen.findAllByText("cmd.exe")).length;
    expect(firstRenderCount).toBeGreaterThan(0);
    const updatedChildButtons = screen.getAllByRole("button", { name: /^Children$/i });
    await userEvent.click(updatedChildButtons[updatedChildButtons.length - 1]);
    await waitFor(() => expect(expandProcessTreeMock).toHaveBeenCalledTimes(2));
    expect(screen.getAllByText("cmd.exe")).toHaveLength(firstRenderCount);
  });

  it("show activity renders grouped activity returned by expansion", async () => {
    expandProcessTreeMock.mockResolvedValueOnce({
      base_node: null,
      added_nodes: [],
      added_edges: [],
      activity_groups: [{ id: "activity-group:ps:file", source: "ps", group: "file", count: 12, source_process: "powershell.exe" }],
      omitted_counts: { file: 12 },
      warnings: [],
      summary: {},
    });
    renderPanel();
    await userEvent.click((await screen.findAllByRole("button", { name: /^Focus$/i }))[0]);
    const activityButtons = await screen.findAllByRole("button", { name: /^Activity$/i });
    await userEvent.click(activityButtons[activityButtons.length - 1]);
    expect(await screen.findByText(/Collapsed activity/i)).toBeInTheDocument();
    expect(screen.getByText(/file: 12/i)).toBeInTheDocument();
  });
});
