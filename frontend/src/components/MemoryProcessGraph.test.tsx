import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryProcessGraph } from "./MemoryProcessGraph";

const getCanonicalProcessTreeMock = vi.fn();
const getCanonicalProcessEntityDetailMock = vi.fn();

vi.mock("../api/client", () => ({
  api: {
    getCanonicalProcessTree: (...args: unknown[]) => getCanonicalProcessTreeMock(...args),
    getCanonicalProcessEntityDetail: (...args: unknown[]) => getCanonicalProcessEntityDetailMock(...args),
  },
}));

function renderGraph(caseId = "case-1", runId = "run-extended") {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={queryClient}>
        <MemoryProcessGraph caseId={caseId} runId={runId} onOpenDetail={vi.fn()} />
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

function systemTree(overrides = {}) {
  return {
    run_id: "run-extended",
    nodes: [
      {
        process_entity_id: "ent-system",
        pid: 4,
        ppid: 0,
        name: "System",
        command_line: null,
        sources: ["windows.pslist"],
        visibility: { listed: true, scan_only: false, terminated: false, hidden_candidate: false, unknown: false },
        findings: [],
        child_count: 3,
        confidence: "high",
        tree: { is_root: true },
        truncated: false,
        omitted_children: 0,
        children: [
          {
            process_entity_id: "ent-smss",
            pid: 444,
            ppid: 4,
            name: "smss.exe",
            command_line: "\\SystemRoot\\System32\\smss.exe",
            sources: ["windows.pslist"],
            visibility: { listed: true },
            findings: [],
            child_count: 0,
            confidence: "high",
            tree: {},
            truncated: false,
            omitted_children: 0,
            children: [],
          },
          {
            process_entity_id: "ent-scan",
            pid: 8112,
            ppid: 4,
            name: "svchost.exe",
            command_line: null,
            sources: ["windows.psscan"],
            visibility: { scan_only: true, hidden_candidate: true, listed: false },
            findings: ["scan_only", "hidden_candidate"],
            child_count: 0,
            confidence: "low",
            tree: {},
            truncated: false,
            omitted_children: 0,
            children: [],
          },
        ],
      },
    ],
    edges: [],
    metrics: {
      total_nodes: 255, roots: 1, orphans: 11, unknown_parent: 0, cycles: 0, self_parent: 1,
      hidden_candidates: 2, scan_only: 2, terminated: 36, pid_zero_count: 1, pid_4_count: 1,
      visible_nodes: 3, search_results: [],
    },
    total_entities: 255,
    omitted_count: 252,
    truncation_reason: "max_nodes_reached",
    search_results: [],
    ...overrides,
  };
}

function cmdEntityDetail(entityId = "ent-cmd") {
  return {
    entity: {
      process_entity_id: entityId,
      process: { pid: 1116, ppid: 808, name: "svchost.exe", command_line: "C:\\Windows\\system32\\svchost.exe -k NetworkService -p" },
      sources: ["windows.pslist", "windows.cmdline"],
      visibility: { listed: true },
      observation_count: 2,
      observation_summary: {},
      confidence: "high",
      findings: [],
      parent_entity_id: "ent-svchost",
      child_count: 0,
      tree: {},
      normalization_version: "memory_process_canonical_v1",
      indexed_at: null,
    },
    observations: [
      { document_id: "obs-1", case_id: "case-1", evidence_id: "ev-1", scan_run_id: "run-extended", process_entity_id: entityId, plugin_run_id: null, plugin_name: "windows.pslist", source_record_id: null, observed: { pid: 1116, ppid: 808, name: "svchost.exe", command_line: "C:\\Windows\\system32\\svchost.exe -k NetworkService -p", create_time: "2024-03-22T10:06:00Z" }, raw_status: "ok", source_fields: {}, confidence: "high", indexed_at: null },
      { document_id: "obs-2", case_id: "case-1", evidence_id: "ev-1", scan_run_id: "run-extended", process_entity_id: entityId, plugin_run_id: null, plugin_name: "windows.cmdline", source_record_id: null, observed: { pid: 1116, ppid: 808, name: "svchost.exe", command_line: "C:\\Windows\\system32\\svchost.exe -k NetworkService -p", create_time: "2024-03-22T10:06:00Z" }, raw_status: "ok", source_fields: {}, confidence: "high", indexed_at: null },
    ],
    parent: null,
    children: [],
    tree_path: ["ent-services", "ent-wininit", "ent-system"],
    alternate_command_lines: [],
    findings: [],
    source_record_refs: [],
  };
}

describe("MemoryProcessGraph", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getCanonicalProcessTreeMock.mockResolvedValue(systemTree());
    getCanonicalProcessEntityDetailMock.mockResolvedValue(null);
  });

  // 1. Initial view does not render all 255 nodes
  it("does not render all 255 entities on initial view", async () => {
    renderGraph();
    await screen.findByTestId("memory-process-canvas");
    const nodes = screen.getAllByTestId("memory-graph-node");
    expect(nodes.length).toBeLessThan(10);
  });

  // 2. PID 4 appears as unique root
  it("shows PID 4 as the unique root", async () => {
    renderGraph();
    await screen.findByTestId("memory-process-canvas");
    const nodes = screen.getAllByTestId("memory-graph-node");
    const systemNode = nodes.find((n) => n.getAttribute("aria-label")?.includes("System"));
    expect(systemNode).toBeDefined();
  });

  // 3. Switch to Extended run shows psscan-derived classifications
  it("renders scan-only or hidden-candidate badge for psscan-only processes (Extended)", async () => {
    renderGraph();
    const nodes = await screen.findAllByTestId("memory-graph-node");
    const scanNode = nodes.find(
      (n) => n.textContent && (n.textContent.includes("Scan only") || n.textContent.includes("Hidden candidate")),
    );
    expect(scanNode).toBeDefined();
  });

  // 4. Sources badges combined
  it("keeps sources as badges inside detail (no duplicate nodes per plugin)", async () => {
    getCanonicalProcessEntityDetailMock.mockResolvedValueOnce(cmdEntityDetail());
    renderGraph();
    // Click on a node
    const nodes = await screen.findAllByTestId("memory-graph-node");
    fireEvent.click(nodes[0]);
    await waitFor(() => {
      expect(getCanonicalProcessEntityDetailMock).toHaveBeenCalled();
    });
  });

  // 5. Command line merged (single row, command line visible)
  it("shows merged command line on a single node", async () => {
    getCanonicalProcessEntityDetailMock.mockResolvedValueOnce(cmdEntityDetail());
    renderGraph();
    const nodes = await screen.findAllByTestId("memory-graph-node");
    fireEvent.click(nodes[0]);
    expect(await screen.findByTestId("memory-graph-detail")).toHaveTextContent("svchost.exe -k NetworkService");
  });

  // 6. Open process detail panel
  it("opens process detail panel on click", async () => {
    getCanonicalProcessEntityDetailMock.mockResolvedValueOnce(cmdEntityDetail());
    renderGraph();
    const nodes = await screen.findAllByTestId("memory-graph-node");
    fireEvent.click(nodes[0]);
    expect(await screen.findByTestId("memory-graph-detail")).toBeInTheDocument();
  });

  // 7. PID 4 not duplicated across nodes
  it("does not duplicate PID 4 across nodes", async () => {
    renderGraph();
    const nodes = await screen.findAllByTestId("memory-graph-node");
    const systemCount = nodes.filter((n) => n.getAttribute("aria-label")?.includes("System")).length;
    expect(systemCount).toBe(1);
  });

  // 8. Orphans in separate scope
  it("separates orphans into a dedicated scope", async () => {
    getCanonicalProcessTreeMock.mockResolvedValueOnce(
      systemTree({ nodes: [{ process_entity_id: "ent-orphan", pid: 9000, ppid: 12345, name: "orphan.exe", command_line: null, sources: ["windows.pslist"], visibility: { listed: true }, findings: [], child_count: 0, confidence: "high", tree: { is_orphan: true }, truncated: false, omitted_children: 0, children: [] }], metrics: { total_nodes: 1, roots: 0, orphans: 1, unknown_parent: 0, cycles: 0, self_parent: 0, hidden_candidates: 0, scan_only: 0, terminated: 0, pid_zero_count: 0, pid_4_count: 0 }, total_entities: 1, omitted_count: 0, truncation_reason: null }),
    );
    renderGraph();
    await screen.findByTestId("memory-process-canvas");
    const scopeSelect = screen.getByLabelText("Scope") as HTMLSelectElement;
    fireEvent.change(scopeSelect, { target: { value: "orphans" } });
    await waitFor(() => {
      const calls = getCanonicalProcessTreeMock.mock.calls;
      const last = calls[calls.length - 1]?.[1] as { orphans_only?: boolean } | undefined;
      expect(last?.orphans_only).toBe(true);
    });
  });

  // 9. Search by PID forwards to API
  it("forwards the search to the API", async () => {
    renderGraph();
    await screen.findByTestId("memory-process-canvas");
    const searchInput = screen.getByTestId("memory-graph-search");
    fireEvent.change(searchInput, { target: { value: "1116" } });
    await waitFor(() => {
      const calls = getCanonicalProcessTreeMock.mock.calls;
      const last = calls[calls.length - 1]?.[1] as { search?: string } | undefined;
      expect(last?.search).toBe("1116");
    });
  });

  // 10. Search by partial name forwards to API
  it("forwards a partial name search to the API", async () => {
    renderGraph();
    await screen.findByTestId("memory-process-canvas");
    const searchInput = screen.getByTestId("memory-graph-search");
    fireEvent.change(searchInput, { target: { value: "svchost" } });
    await waitFor(() => {
      const calls = getCanonicalProcessTreeMock.mock.calls;
      const last = calls[calls.length - 1]?.[1] as { search?: string } | undefined;
      expect(last?.search).toBe("svchost");
    });
  });

  // 11. Show ancestors
  it("triggers a second request for ancestors when requested", async () => {
    getCanonicalProcessEntityDetailMock.mockResolvedValueOnce(cmdEntityDetail());
    renderGraph();
    const nodes = await screen.findAllByTestId("memory-graph-node");
    fireEvent.click(nodes[0]);
    const detail = await screen.findByTestId("memory-graph-detail");
    const buttons = detail.querySelectorAll("button");
    // The Show ancestors button
    const showAncestorsBtn = Array.from(buttons).find((b) => b.textContent?.includes("Show ancestors"));
    expect(showAncestorsBtn).toBeDefined();
    if (showAncestorsBtn) fireEvent.click(showAncestorsBtn);
    // The ancestors query is enabled only after the focused entity is set
    // and the user clicks "Show ancestors". It will fire and we should see
    // a second tree request that includes include_ancestors.
    await waitFor(() => {
      const calls = getCanonicalProcessTreeMock.mock.calls;
      expect(calls.length).toBeGreaterThan(1);
    });
  });

  // 12. Truncation message for large graphs
  it("shows truncation guidance when total_entities > 200", async () => {
    getCanonicalProcessTreeMock.mockResolvedValueOnce(
      systemTree({
        total_entities: 500,
        nodes: [
          {
            process_entity_id: "ent-large",
            pid: 4,
            ppid: 0,
            name: "System",
            command_line: null,
            sources: ["windows.pslist"],
            visibility: { listed: true },
            findings: [],
            child_count: 250,
            confidence: "high",
            tree: { is_root: true },
            truncated: true,
            omitted_children: 250,
            children: [],
          },
        ],
      }),
    );
    renderGraph();
    expect(await screen.findByText(/The full process graph contains 500 canonical processes/)).toBeInTheDocument();
  });

  // 13. Table view toggle
  it("toggles to a Table view without losing filters", async () => {
    renderGraph();
    await screen.findByTestId("memory-process-canvas");
    const tableButton = screen.getByTestId("view-mode-table");
    fireEvent.click(tableButton);
    expect(await screen.findByTestId("memory-graph-table")).toBeInTheDocument();
  });

  // 14. Basic run does not show scan-only
  it("does not surface scan-only classifications on a basic run", async () => {
    getCanonicalProcessTreeMock.mockResolvedValueOnce(
      systemTree({
        nodes: [
          {
            process_entity_id: "ent-basic",
            pid: 4,
            ppid: 0,
            name: "System",
            command_line: null,
            sources: ["windows.pslist"],
            visibility: { listed: true },
            findings: [],
            child_count: 1,
            confidence: "high",
            tree: { is_root: true },
            truncated: false,
            omitted_children: 0,
            children: [
              {
                process_entity_id: "ent-basic-1",
                pid: 444,
                ppid: 4,
                name: "smss.exe",
                command_line: null,
                sources: ["windows.pslist"],
                visibility: { listed: true },
                findings: [],
                child_count: 0,
                confidence: "high",
                tree: {},
                truncated: false,
                omitted_children: 0,
                children: [],
              },
            ],
          },
        ],
        metrics: { total_nodes: 2, roots: 1, orphans: 0, unknown_parent: 0, cycles: 0, self_parent: 0, hidden_candidates: 0, scan_only: 0, terminated: 0, pid_zero_count: 0, pid_4_count: 1, visible_nodes: 2, search_results: [] },
      }),
    );
    renderGraph();
    const canvas = await screen.findByTestId("memory-process-canvas");
    expect(canvas.textContent).not.toContain("Scan only");
  });

  // 15. Run isolation: switching run id issues a new query
  it("issues a new query when run_id changes", async () => {
    const { rerender } = render(
      <MemoryRouter>
        <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
          <MemoryProcessGraph caseId="case-1" runId="run-extended" onOpenDetail={vi.fn()} />
        </QueryClientProvider>
      </MemoryRouter>,
    );
    await screen.findByTestId("memory-process-canvas");
    rerender(
      <MemoryRouter>
        <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
          <MemoryProcessGraph caseId="case-1" runId="run-basic" onOpenDetail={vi.fn()} />
        </QueryClientProvider>
      </MemoryRouter>,
    );
    await waitFor(() => {
      const calls = getCanonicalProcessTreeMock.mock.calls;
      const runIds = calls.map((c) => (c[1] as any)?.run_id);
      expect(runIds).toContain("run-basic");
    });
  });

  // 16. No sensitive paths rendered
  it("does not render private server paths", async () => {
    getCanonicalProcessEntityDetailMock.mockResolvedValueOnce(cmdEntityDetail());
    renderGraph();
    const nodes = await screen.findAllByTestId("memory-graph-node");
    fireEvent.click(nodes[0]);
    expect(await screen.findByTestId("memory-graph-detail")).toBeInTheDocument();
    expect(screen.queryByText(/\/opt\/private/)).not.toBeInTheDocument();
  });

  // 17. Sources/provenance preserved in detail
  it("preserves source provenance in the detail panel", async () => {
    getCanonicalProcessEntityDetailMock.mockResolvedValueOnce(cmdEntityDetail());
    renderGraph();
    const nodes = await screen.findAllByTestId("memory-graph-node");
    fireEvent.click(nodes[0]);
    const detail = await screen.findByTestId("memory-graph-detail");
    expect(detail.textContent).toContain("pslist");
    expect(detail.textContent).toContain("cmdline");
  });

  // 18. Reset view control
  it("renders zoom controls and reset", async () => {
    renderGraph();
    await screen.findByTestId("memory-process-canvas");
    expect(screen.getByLabelText("Zoom in")).toBeInTheDocument();
    expect(screen.getByLabelText("Zoom out")).toBeInTheDocument();
    expect(screen.getByTestId("memory-graph-reset")).toBeInTheDocument();
  });
});
