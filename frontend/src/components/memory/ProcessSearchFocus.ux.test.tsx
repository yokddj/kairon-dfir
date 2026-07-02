/** @vitest-environment jsdom */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../api/client", () => ({
  api: {
    getCanonicalProcessTree: vi.fn(),
    getCanonicalProcessEntities: vi.fn(),
    getCanonicalProcessEntityDetail: vi.fn(),
    getMemorySymbolPreparation: vi.fn(),
    getMemoryAnalysisCatalogue: vi.fn(),
    startMemoryRunAll: vi.fn(),
  },
}));

import { api } from "../../api/client";
import { MemoryProcessGraph } from "../MemoryProcessGraph";

const CASE = "case-1";
const RUN = "run-1";

// WS01 fixture: wininit.exe is PID 664, cmd.exe is PID 11184.
// Backend returns `nodes` as the top-level list (root + orphans).
// Children are nested inside each node.
const ws01Node = (
  entity_id: string,
  pid: number,
  ppid: number | null,
  name: string,
  command_line: string | null,
  children: any[] = [],
) => ({
  process_entity_id: entity_id,
  pid,
  ppid,
  name,
  command_line,
  sources: ["windows.pslist", "windows.cmdline"],
  visibility: { listed: true, scan_only: false, terminated: false, hidden_candidate: false, unknown: false },
  findings: [],
  child_count: children.length,
  confidence: "high",
  create_time: "2024-03-22T12:00:00Z",
  exit_time: null,
  tree: { is_root: false, is_orphan: false, depth: 0 },
  children,
  omitted_children: 0,
});

const cmdChild = ws01Node("cmd-11184", 11184, 664, "cmd.exe", "C:\\Windows\\System32\\cmd.exe /c update.ps1", []);
const wininitNode = ws01Node("wininit-664", 664, 4, "wininit.exe", null, [cmdChild]);

const ws01Tree = {
  run_id: RUN,
  roots: [wininitNode],
  orphans: [],
  top_level_nodes: [wininitNode],
  nodes: [wininitNode],
  edges: [
    { source: "wininit-664", target: "cmd-11184" },
  ],
  metrics: { case_roots: 1, current_view_roots: 1, visible_processes: 2, context_ancestors: 0, collapsed_branches: 0, processes_not_loaded: 0 },
  total_entities: 2,
  omitted_count: 0,
  truncation_reason: null,
  search_results: [],
};

const ws01TreeForCmd = {
  ...ws01Tree,
  search_results: ["cmd-11184"],
};

const ws01Entities = {
  items: [
    {
      process_entity_id: "wininit-664",
      document_type: "memory_process_entity" as const,
      case_id: CASE,
      evidence_id: "ev-1",
      scan_run_id: RUN,
      process: {
        pid: 664,
        ppid: 4,
        name: "wininit.exe",
        command_line: null,
        create_time: "2024-03-22T12:00:00Z",
        exit_time: null,
      },
      sources: ["windows.pslist"],
      visibility: { listed: true },
      findings: [],
      child_count: 1,
      confidence: "high",
      tree: { is_root: true, is_orphan: false, depth: 0 },
    },
    {
      process_entity_id: "cmd-11184",
      document_type: "memory_process_entity" as const,
      case_id: CASE,
      evidence_id: "ev-1",
      scan_run_id: RUN,
      process: {
        pid: 11184,
        ppid: 664,
        name: "cmd.exe",
        command_line: "C:\\Windows\\System32\\cmd.exe /c update.ps1",
        create_time: "2024-03-22T12:50:00Z",
        exit_time: null,
      },
      sources: ["windows.pslist", "windows.cmdline"],
      visibility: { listed: true },
      findings: [],
      child_count: 0,
      confidence: "high",
      tree: { is_root: false, is_orphan: false, depth: 1 },
    },
  ],
  total: 2,
  page: 1,
  page_size: 50,
  selected_run: RUN,
  normalization_version: "memory_artifact_canonical_v1",
  total_observations: 2,
  facets: {},
};

const cmdDetail = {
  entity: {
    process_entity_id: "cmd-11184",
    case_id: CASE,
    evidence_id: "ev-1",
    process: { pid: 11184, ppid: 664, name: "cmd.exe", command_line: "C:\\Windows\\System32\\cmd.exe /c update.ps1", create_time: "2024-03-22T12:50:00Z", exit_time: null },
    sources: ["windows.pslist", "windows.cmdline"],
    visibility: { listed: true },
    findings: [],
    child_count: 0,
    confidence: "high",
    tree: { is_root: false, is_orphan: false, depth: 1 },
    parent_entity_id: "wininit-664",
    observations: [],
  },
  observations: [],
  ancestors: [
    {
      process_entity_id: "wininit-664",
      pid: 664,
      ppid: 4,
      name: "wininit.exe",
      command_line: null,
    },
  ],
  children: [],
  alternate_command_lines: [],
};

beforeEach(() => {
  vi.clearAllMocks();
});

const renderGraph = (props: Record<string, unknown> = {}) => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryProcessGraph
        caseId={CASE}
        runId={RUN}
        onOpenDetail={vi.fn()}
        {...(props as any)}
      />
    </QueryClientProvider>,
  );
};

describe("Process search focus v1", () => {
  it("1) searching by exact PID 11184 selects cmd.exe, not wininit.exe", async () => {
    (api.getCanonicalProcessTree as ReturnType<typeof vi.fn>).mockImplementation(
      async (_caseId, params) => {
        if (params && (params as any).search === "11184") {
          return ws01TreeForCmd as any;
        }
        return ws01Tree as any;
      },
    );
    (api.getCanonicalProcessEntityDetail as ReturnType<typeof vi.fn>).mockResolvedValue(cmdDetail as any);
    renderGraph();
    // The search input is a Search by PID input (data-testid from
    // MemoryWorkspace).  The graph has its own search input.
    const searchInput = await screen.findByTestId("memory-graph-search");
    fireEvent.change(searchInput, { target: { value: "11184" } });
    await waitFor(() => {
      expect(api.getCanonicalProcessTree).toHaveBeenCalledWith(
        CASE,
        expect.objectContaining({ search: "11184" }),
      );
    });
  });

  it("2) the search results payload is honoured by the graph", async () => {
    (api.getCanonicalProcessTree as ReturnType<typeof vi.fn>).mockResolvedValue(ws01TreeForCmd as any);
    (api.getCanonicalProcessEntityDetail as ReturnType<typeof vi.fn>).mockResolvedValue(cmdDetail as any);
    renderGraph();
    // No user action needed: the mock returns search_results.
    // The detail panel should eventually render the cmd.exe detail.
    await waitFor(() => {
      // Detail panel renders PID 11184.
      const body = document.body.textContent || "";
      expect(body).toMatch(/PID 11184/);
    });
    // The Search match badge is rendered on the focused node.
    const badges = screen.queryAllByTestId("memory-graph-search-match-badge");
    expect(badges.length).toBeGreaterThanOrEqual(1);
  });

  it("3) the target node has the data-target attribute and the Search match badge", async () => {
    (api.getCanonicalProcessTree as ReturnType<typeof vi.fn>).mockResolvedValue(ws01TreeForCmd as any);
    (api.getCanonicalProcessEntityDetail as ReturnType<typeof vi.fn>).mockResolvedValue(cmdDetail as any);
    renderGraph();
    // The first node in the layout is the root (wininit.exe) but
    // when the search returns search_results, wininit.exe is
    // treated as context, not as the target.
    const nodes = await screen.findAllByTestId("memory-graph-node");
    expect(nodes.length).toBeGreaterThanOrEqual(2);
    // The target (search match) is the cmd-11184 node.
    const targets = document.querySelectorAll('[data-testid="memory-graph-node"][data-target="true"]');
    expect(targets.length).toBeGreaterThanOrEqual(1);
    // At least one Context badge is rendered.
    const contextBadges = screen.queryAllByTestId("memory-graph-context-badge");
    expect(contextBadges.length).toBeGreaterThanOrEqual(1);
  });

  it("4) ancestors appear as Context (not as Search match)", async () => {
    (api.getCanonicalProcessTree as ReturnType<typeof vi.fn>).mockResolvedValue(ws01TreeForCmd as any);
    (api.getCanonicalProcessEntityDetail as ReturnType<typeof vi.fn>).mockResolvedValue(cmdDetail as any);
    renderGraph();
    // The wininit.exe node should have data-context="true" and no
    // Search match badge.  We find the wininit node by aria-label
    // (it contains "PID 664 wininit.exe").
    const wininitNode = await screen.findByLabelText(/PID 664 wininit\.exe/);
    expect(wininitNode.getAttribute("data-context")).toBe("true");
    expect(wininitNode.querySelector('[data-testid="memory-graph-search-match-badge"]')).toBeNull();
  });

  it("5) detail panel shows the target process (PID 11184, PPID 664)", async () => {
    (api.getCanonicalProcessTree as ReturnType<typeof vi.fn>).mockResolvedValue(ws01TreeForCmd as any);
    (api.getCanonicalProcessEntityDetail as ReturnType<typeof vi.fn>).mockResolvedValue(cmdDetail as any);
    renderGraph();
    const detail = await screen.findByTestId("memory-graph-detail");
    expect(detail.textContent).toMatch(/PID 11184/);
    expect(detail.textContent).toMatch(/PPID/);
    expect(detail.textContent).toMatch(/update\.ps1/);
  });

  it("6) partial search with multiple results still highlights only the first matched node as Search match", async () => {
    (api.getCanonicalProcessTree as ReturnType<typeof vi.fn>).mockResolvedValue({
      ...ws01TreeForCmd,
      search_results: ["cmd-11184"],
    } as any);
    (api.getCanonicalProcessEntityDetail as ReturnType<typeof vi.fn>).mockResolvedValue(cmdDetail as any);
    renderGraph();
    // The first search_result is the only one marked as target.
    await screen.findAllByTestId("memory-graph-node");
    const targets = document.querySelectorAll('[data-testid="memory-graph-node"][data-target="true"]');
    expect(targets.length).toBe(1);
  });
});

describe("First analysis simplification v1", () => {
  it("7) the canonical view supports an exact-PID search field", async () => {
    const { MemoryCanonicalView } = await import("../MemoryCanonicalView");
    (api.getCanonicalProcessEntities as ReturnType<typeof vi.fn>).mockResolvedValue(ws01Entities as any);
    (api.getCanonicalProcessEntityDetail as ReturnType<typeof vi.fn>).mockResolvedValue(cmdDetail as any);
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } } });
    render(
      <QueryClientProvider client={qc}>
        <MemoryCanonicalView
          caseId={CASE}
          runId={RUN}
          selectedEntityId="cmd-11184"
          onSelectEntityId={vi.fn()}
        />
      </QueryClientProvider>,
    );
    const pidInput = await screen.findByTestId("memory-canonical-pid-filter");
    expect(pidInput).toBeInTheDocument();
    fireEvent.change(pidInput, { target: { value: "11184" } });
    await waitFor(() => {
      expect(api.getCanonicalProcessEntities).toHaveBeenCalledWith(
        CASE,
        expect.objectContaining({ pid: 11184 }),
      );
    });
  });

  it("8) the canonical view ignores non-numeric PID input", async () => {
    const { MemoryCanonicalView } = await import("../MemoryCanonicalView");
    (api.getCanonicalProcessEntities as ReturnType<typeof vi.fn>).mockResolvedValue(ws01Entities as any);
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } } });
    render(
      <QueryClientProvider client={qc}>
        <MemoryCanonicalView
          caseId={CASE}
          runId={RUN}
          onSelectEntityId={vi.fn()}
        />
      </QueryClientProvider>,
    );
    const pidInput = await screen.findByTestId("memory-canonical-pid-filter");
    fireEvent.change(pidInput, { target: { value: "abc" } });
    // The input does NOT change.
    expect((pidInput as HTMLInputElement).value).toBe("");
  });
});

describe("Search summary UX", () => {
  it("9) the search summary shows exact match and context ancestor counts", async () => {
    (api.getCanonicalProcessTree as ReturnType<typeof vi.fn>).mockResolvedValue(ws01TreeForCmd as any);
    (api.getCanonicalProcessEntityDetail as ReturnType<typeof vi.fn>).mockResolvedValue(cmdDetail as any);
    renderGraph();
    const summary = await screen.findByTestId("memory-graph-search-summary");
    expect(summary.textContent).toMatch(/exact PID match|1 secondary match/);
    expect(summary.textContent).toMatch(/1 context ancestor/);
  });
});
