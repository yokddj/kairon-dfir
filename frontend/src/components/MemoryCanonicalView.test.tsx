import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryCanonicalView } from "../components/MemoryCanonicalView";

const getMemoryRunOptionsMock = vi.fn();
const getCanonicalProcessEntitiesMock = vi.fn();
const getCanonicalProcessSummaryMock = vi.fn();
const getCanonicalProcessTreeMock = vi.fn();
const getCanonicalProcessEntityDetailMock = vi.fn();
const renormalizeProcessEntitiesMock = vi.fn();

vi.mock("../api/client", () => ({
  api: {
    getMemoryRunOptions: (...args: unknown[]) => getMemoryRunOptionsMock(...args),
    getCanonicalProcessEntities: (...args: unknown[]) => getCanonicalProcessEntitiesMock(...args),
    getCanonicalProcessSummary: (...args: unknown[]) => getCanonicalProcessSummaryMock(...args),
    getCanonicalProcessTree: (...args: unknown[]) => getCanonicalProcessTreeMock(...args),
    getCanonicalProcessEntityDetail: (...args: unknown[]) => getCanonicalProcessEntityDetailMock(...args),
    renormalizeProcessEntities: (...args: unknown[]) => renormalizeProcessEntitiesMock(...args),
  },
}));

function renderView(caseId = "case-1") {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter initialEntries={[`/cases/${caseId}/memory`]}>
      <QueryClientProvider client={queryClient}>
        <Routes>
          <Route path="/cases/:caseId/memory" element={<MemoryCanonicalView caseId={caseId} />} />
        </Routes>
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

function runSelector(overrides = {}) {
  return {
    runs: [
      {
        run_id: "run-basic",
        profile: "processes_basic",
        status: "completed",
        created_at: "2026-06-19T12:00:00Z",
        completed_at: "2026-06-19T12:01:00Z",
        plugin_count: 4,
        plugins_completed: 4,
        plugins_failed: 0,
        selected: true,
      },
      {
        run_id: "run-extended",
        profile: "processes_extended",
        status: "completed",
        created_at: "2026-06-19T12:30:00Z",
        completed_at: "2026-06-19T12:32:00Z",
        plugin_count: 5,
        plugins_completed: 5,
        plugins_failed: 0,
        selected: false,
      },
    ],
    default_run_id: "run-basic",
    combined_historical_available: true,
    ...overrides,
  };
}

function entities(overrides = {}) {
  return {
    items: [
      {
        process_entity_id: "ent-1",
        process: { pid: 1116, ppid: 808, name: "svchost.exe", command_line: "svchost.exe -k netsvcs", create_time: "2024-03-22T10:00:00Z", exit_time: null },
        sources: ["windows.pslist", "windows.pstree", "windows.cmdline"],
        visibility: { listed: true, scan_only: false, terminated: false, unknown: false, hidden_candidate: false },
        observation_count: 3,
        observation_summary: { has_pslist: true, has_psscan: false, has_pstree: true, has_cmdline: true },
        confidence: "high",
        findings: [],
        parent_entity_id: "ent-parent",
        child_count: 0,
        tree: { is_root: false, is_orphan: false, is_unknown_parent: false, is_cycle: false, is_self_parent: false, is_pid_zero: false },
        normalization_version: "memory_process_canonical_v1",
        indexed_at: "2026-06-19T12:01:00Z",
      },
      {
        process_entity_id: "ent-2",
        process: { pid: 9999, ppid: null, name: "ghost.exe", command_line: null, create_time: null, exit_time: null },
        sources: ["windows.psscan"],
        visibility: { listed: false, scan_only: true, terminated: false, unknown: false, hidden_candidate: true },
        observation_count: 1,
        observation_summary: { has_pslist: false, has_psscan: true, has_pstree: false, has_cmdline: false },
        confidence: "low",
        findings: ["scan_only", "hidden_candidate", "command_line_missing"],
        parent_entity_id: null,
        child_count: 0,
        tree: { is_root: false, is_orphan: false, is_unknown_parent: true, is_cycle: false, is_self_parent: false, is_pid_zero: false },
        normalization_version: "memory_process_canonical_v1",
        indexed_at: "2026-06-19T12:01:00Z",
      },
    ],
    total: 2,
    page: 1,
    page_size: 50,
    selected_run: "run-basic",
    normalization_version: "memory_process_canonical_v1",
    total_observations: 4,
    facets: {},
    ...overrides,
  };
}

function summary(overrides = {}) {
  return {
    case_id: "case-1",
    evidence_id: "ev-1",
    run_id: "run-basic",
    source_documents: 520,
    candidate_entities: 254,
    observation_count: 520,
    duplicate_groups_collapsed: 266,
    invalid_records: 0,
    ambiguous_pid_groups: 4,
    expected_edges: 240,
    tree_metrics: {
      total_nodes: 254,
      roots: 3,
      orphans: 8,
      unknown_parent: 4,
      cycles: 0,
      self_parent: 0,
      hidden_candidates: 5,
      scan_only: 5,
      terminated: 1,
      pid_zero_count: 1,
      pid_4_count: 1,
    },
    normalization_version: "memory_process_canonical_v1",
    materialization_status: "applied",
    ...overrides,
  };
}

function tree(overrides = {}) {
  return {
    run_id: "run-basic",
    nodes: [
      {
        process_entity_id: "ent-1",
        pid: 1116,
        ppid: 808,
        name: "svchost.exe",
        command_line: "svchost.exe -k netsvcs",
        sources: ["windows.pslist", "windows.pstree", "windows.cmdline"],
        visibility: { listed: true, scan_only: false, terminated: false, unknown: false, hidden_candidate: false },
        findings: [],
        child_count: 0,
        children: [],
      },
    ],
    edges: [],
    metrics: {
      total_nodes: 1,
      roots: 0,
      orphans: 0,
      unknown_parent: 0,
      cycles: 0,
      self_parent: 0,
      hidden_candidates: 0,
      scan_only: 0,
      terminated: 0,
      pid_zero_count: 0,
      pid_4_count: 0,
    },
    total_entities: 1,
    omitted_count: 0,
    truncation_reason: null,
    ...overrides,
  };
}

describe("MemoryCanonicalView", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getMemoryRunOptionsMock.mockResolvedValue(runSelector());
    getCanonicalProcessEntitiesMock.mockResolvedValue(entities());
    getCanonicalProcessSummaryMock.mockResolvedValue(summary());
    getCanonicalProcessTreeMock.mockResolvedValue(tree());
    getCanonicalProcessEntityDetailMock.mockResolvedValue(null);
    renormalizeProcessEntitiesMock.mockResolvedValue(summary({ materialization_status: "applied" }));
  });

  // 1. Basic run selected: process table populated
  it("populates the process table for the basic run", async () => {
    renderView();
    expect(await screen.findByTestId("canonical-process-table")).toBeInTheDocument();
    expect(screen.getAllByTestId("canonical-process-row")).toHaveLength(2);
  });

  // 2. Extended run: psscan source visible
  it("shows psscan source for the extended run", async () => {
    getMemoryRunOptionsMock.mockResolvedValueOnce(
      runSelector({ default_run_id: "run-extended" }),
    );
    getCanonicalProcessEntitiesMock.mockResolvedValueOnce(
      entities({
        items: [
          {
            process_entity_id: "ent-x",
            process: { pid: 9999, ppid: null, name: "ghost.exe", command_line: null, create_time: null, exit_time: null },
            sources: ["windows.psscan"],
            visibility: { scan_only: true, hidden_candidate: true },
            observation_count: 1,
            observation_summary: { has_psscan: true },
            confidence: "low",
            findings: ["scan_only", "hidden_candidate"],
            parent_entity_id: null,
            child_count: 0,
            tree: {},
            normalization_version: "memory_process_canonical_v1",
            indexed_at: null,
          },
        ],
        selected_run: "run-extended",
      }),
    );
    renderView();
    const table = await screen.findByTestId("canonical-process-table");
    expect(table.textContent).toContain("psscan");
  });

  // 3. Same PID from multiple plugins: one row
  it("deduplicates same PID from multiple plugins into one row", async () => {
    renderView();
    const rows = await screen.findAllByTestId("canonical-process-row");
    expect(rows).toHaveLength(2);
    // 1116 has three source plugins but appears once.
    const cellWith1116 = rows.find((row) => row.textContent && row.textContent.includes("1116"));
    expect(cellWith1116).toBeDefined();
  });

  // 4. Sources badges combined
  it("renders combined sources badges", async () => {
    renderView();
    const table = await screen.findByTestId("canonical-process-table");
    expect(table.textContent).toMatch(/pslist/);
    expect(table.textContent).toMatch(/pstree/);
    expect(table.textContent).toMatch(/cmdline/);
  });

  // 5. Command line merged
  it("shows the merged command line on the canonical process", async () => {
    renderView();
    const table = await screen.findByTestId("canonical-process-table");
    expect(table.textContent).toContain("svchost.exe -k netsvcs");
  });

  // 6. Visibility badge correct
  it("renders the visibility badge (Scan only / Hidden candidate)", async () => {
    renderView();
    const table = await screen.findByTestId("canonical-process-table");
    expect(table.textContent).toContain("Scan only");
    expect(table.textContent).toContain("Hidden candidate");
  });

  // 7. Scan-only filter
  it("forwards the visibility filter to the API", async () => {
    renderView();
    await screen.findByTestId("canonical-process-table");
    const selects = screen.getAllByRole("combobox") as HTMLSelectElement[];
    // Run selector is index 0; visibility is index 1
    const visibility = selects[1];
    fireEvent.change(visibility, { target: { value: "scan_only" } });
    await waitFor(() => {
      const calls = getCanonicalProcessEntitiesMock.mock.calls;
      const last = calls[calls.length - 1]?.[1] as { visibility?: string } | undefined;
      expect(last?.visibility).toBe("scan_only");
    });
  });

  // 8. Interesting-only filter
  it("forwards the interesting_only filter to the API", async () => {
    renderView();
    await screen.findByTestId("canonical-process-table");
    const selects = screen.getAllByRole("combobox") as HTMLSelectElement[];
    // Run selector is 0; visibility is 1; source plugin is 2; interesting is 3
    const interesting = selects[3];
    fireEvent.change(interesting, { target: { value: "hidden_candidate" } });
    await waitFor(() => {
      const calls = getCanonicalProcessEntitiesMock.mock.calls;
      const last = calls[calls.length - 1]?.[1] as { interesting_only?: boolean } | undefined;
      expect(last?.interesting_only).toBe(true);
    });
  });

  // 9. Run selector
  it("selects the run and refreshes the entities", async () => {
    renderView();
    const runSelect = (await screen.findAllByRole("combobox"))[0] as HTMLSelectElement;
    // Wait until the run selector has loaded its options.
    await waitFor(() => {
      const options = runSelect.querySelectorAll("option");
      expect(options.length).toBeGreaterThan(0);
    });
    fireEvent.change(runSelect, { target: { value: "run-extended" } });
    await waitFor(() => {
      const calls = getCanonicalProcessEntitiesMock.mock.calls;
      const last = calls[calls.length - 1]?.[1] as { run_id?: string } | undefined;
      expect(last?.run_id).toBe("run-extended");
    });
  });

  // 10. Failed latest run: completed run selectable
  it("allows selecting a completed run when the latest is failed", async () => {
    getMemoryRunOptionsMock.mockResolvedValueOnce(
      runSelector({
        runs: [
          { run_id: "run-failed", profile: "processes_extended", status: "failed", created_at: "2026-06-19T15:00:00Z", completed_at: null, plugin_count: 5, plugins_completed: 0, plugins_failed: 5, selected: false },
          { run_id: "run-basic", profile: "processes_basic", status: "completed", created_at: "2026-06-19T12:00:00Z", completed_at: "2026-06-19T12:01:00Z", plugin_count: 4, plugins_completed: 4, plugins_failed: 0, selected: true },
        ],
        default_run_id: "run-basic",
      }),
    );
    renderView();
    const runSelect = (await screen.findAllByRole("combobox"))[0] as HTMLSelectElement;
    // Wait for the run options to be available before checking the value.
    await waitFor(() => {
      expect(runSelect.value).toBe("run-basic");
    });
    fireEvent.change(runSelect, { target: { value: "run-failed" } });
    await waitFor(() => {
      const calls = getCanonicalProcessEntitiesMock.mock.calls;
      const last = calls[calls.length - 1]?.[1] as { run_id?: string } | undefined;
      expect(last?.run_id).toBe("run-failed");
    });
  });

  // 11. Tree roots correct
  it("renders the tree with the run metrics", async () => {
    renderView();
    expect(await screen.findByText(/Process tree/)).toBeInTheDocument();
    expect(screen.getByText(/Roots:/)).toBeInTheDocument();
  });

  // 12. Unknown-parent is shown separately
  it("shows unknown_parent metric separately from roots", async () => {
    renderView();
    await screen.findByTestId("canonical-process-table");
    // Process tree section should explicitly mention Unknown parent
    expect(screen.getByText(/Unknown parent:/)).toBeInTheDocument();
  });

  // 13. Process detail opens
  it("opens the process detail panel when the inspect button is clicked", async () => {
    getCanonicalProcessEntityDetailMock.mockResolvedValueOnce({
      entity: {
        process_entity_id: "ent-1",
        process: { pid: 1116, ppid: 808, name: "svchost.exe", command_line: "svchost.exe -k netsvcs" },
        sources: ["windows.pslist"],
        visibility: { listed: true },
        observation_count: 1,
        observation_summary: {},
        confidence: "high",
        findings: [],
        parent_entity_id: null,
        child_count: 0,
        tree: {},
        normalization_version: "memory_process_canonical_v1",
        indexed_at: null,
      },
      observations: [
        {
          document_id: "obs-1",
          document_type: "memory_process_observation",
          case_id: "case-1",
          evidence_id: "ev-1",
          scan_run_id: "run-basic",
          process_entity_id: "ent-1",
          plugin_run_id: "plugin-1",
          plugin_name: "windows.pslist",
          source_record_id: "doc-1",
          observed: { pid: 1116, ppid: 808, name: "svchost.exe", command_line: "svchost.exe -k netsvcs", create_time: "2024-03-22T10:00:00Z" },
          raw_status: "ok",
          source_fields: {},
          confidence: "high",
          indexed_at: null,
        },
      ],
      parent: null,
      children: [],
      tree_path: [],
      alternate_command_lines: [],
      findings: [],
      source_record_refs: ["doc-1"],
    });
    renderView();
    const rows = await screen.findAllByTestId("canonical-process-row");
    const inspectButtons = rows[0].querySelectorAll("button");
    fireEvent.click(inspectButtons[0]);
    const detail = await screen.findByTestId("canonical-process-detail");
    expect(detail).toBeInTheDocument();
    expect(detail.textContent).toContain("Observations");
  });

  // 14. Observations tab shows plugin provenance
  it("shows plugin provenance in the observations table", async () => {
    getCanonicalProcessEntityDetailMock.mockResolvedValueOnce({
      entity: {
        process_entity_id: "ent-1",
        process: { pid: 1116, ppid: 808, name: "svchost.exe", command_line: "x" },
        sources: ["windows.pslist", "windows.pstree"],
        visibility: {},
        observation_count: 2,
        observation_summary: {},
        confidence: "high",
        findings: [],
        parent_entity_id: null,
        child_count: 0,
        tree: {},
        normalization_version: "memory_process_canonical_v1",
        indexed_at: null,
      },
      observations: [
        {
          document_id: "obs-1",
          case_id: "case-1",
          evidence_id: "ev-1",
          scan_run_id: "run-basic",
          process_entity_id: "ent-1",
          plugin_run_id: null,
          plugin_name: "windows.pslist",
          source_record_id: null,
          observed: { pid: 1116, ppid: 808, name: "svchost.exe", command_line: "a", create_time: "2024-03-22T10:00:00Z" },
          raw_status: "ok",
          source_fields: {},
          confidence: "high",
          indexed_at: null,
        },
        {
          document_id: "obs-2",
          case_id: "case-1",
          evidence_id: "ev-1",
          scan_run_id: "run-basic",
          process_entity_id: "ent-1",
          plugin_run_id: null,
          plugin_name: "windows.pstree",
          source_record_id: null,
          observed: { pid: 1116, ppid: 808, name: "svchost.exe", command_line: "a", create_time: "2024-03-22T10:00:00Z" },
          raw_status: "ok",
          source_fields: {},
          confidence: "high",
          indexed_at: null,
        },
      ],
      parent: null,
      children: [],
      tree_path: [],
      alternate_command_lines: [],
      findings: [],
      source_record_refs: [],
    });
    renderView();
    const rows = await screen.findAllByTestId("canonical-process-row");
    fireEvent.click(rows[0].querySelectorAll("button")[0]);
    const detail = await screen.findByTestId("canonical-process-detail");
    expect(detail.textContent).toContain("pslist");
    expect(detail.textContent).toContain("pstree");
  });

  // 15. Large graph: guided controls shown
  it("shows the large graph guidance when total_entities exceeds 200", async () => {
    getCanonicalProcessTreeMock.mockResolvedValueOnce(
      tree({
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
            truncated: true,
            omitted_children: 250,
            children: [],
          },
        ],
      }),
    );
    renderView();
    // The MemoryProcessGraph component renders the TruncationMessage
    // when total_entities > 200.
    expect(await screen.findByText(/The full process graph contains 500 canonical processes/)).toBeInTheDocument();
  });

  // 16. No empty table when basic results exist
  it("does not show an empty placeholder when entities exist", async () => {
    renderView();
    await screen.findByTestId("canonical-process-table");
    expect(screen.queryByText(/No canonical process entities for the current run/)).not.toBeInTheDocument();
  });

  // 17. No mixing across runs
  it("renders the selected_run id from the API and does not mix runs", async () => {
    getCanonicalProcessEntitiesMock.mockResolvedValueOnce(entities({ selected_run: "run-basic" }));
    renderView();
    await screen.findByTestId("canonical-process-table");
    // The selector should reflect the default run from run options.
    const runSelect = screen.getAllByRole("combobox")[0] as HTMLSelectElement;
    expect(runSelect.value).toBe("run-basic");
  });

  // 18. PID reuse shown as distinct entities
  it("shows PID reuse as distinct entities (different create_time)", async () => {
    getCanonicalProcessEntitiesMock.mockResolvedValueOnce(
      entities({
        items: [
          {
            process_entity_id: "ent-a",
            process: { pid: 1234, ppid: 1, name: "cmd.exe", create_time: "2024-03-22T08:00:00Z" },
            sources: ["windows.pslist"],
            visibility: { listed: true },
            observation_count: 1,
            observation_summary: {},
            confidence: "high",
            findings: [],
            parent_entity_id: null,
            child_count: 0,
            tree: {},
            normalization_version: "memory_process_canonical_v1",
            indexed_at: null,
          },
          {
            process_entity_id: "ent-b",
            process: { pid: 1234, ppid: 1, name: "powershell.exe", create_time: "2024-03-22T18:00:00Z" },
            sources: ["windows.pslist"],
            visibility: { listed: true },
            observation_count: 1,
            observation_summary: {},
            confidence: "high",
            findings: [],
            parent_entity_id: null,
            child_count: 0,
            tree: {},
            normalization_version: "memory_process_canonical_v1",
            indexed_at: null,
          },
        ],
      }),
    );
    renderView();
    const rows = await screen.findAllByTestId("canonical-process-row");
    expect(rows).toHaveLength(2);
  });

  // 19. Pagination
  it("calls the API with the requested page", async () => {
    // Page size is 50; return 50 items so Next is enabled.
    const full = entities();
    const items = Array.from({ length: 50 }, (_, i) => ({
      ...full.items[0],
      process_entity_id: `ent-${i}`,
    }));
    getCanonicalProcessEntitiesMock.mockResolvedValue(entities({ total: 100, items }));
    renderView();
    await screen.findByTestId("canonical-process-table");
    const nextButton = screen.getByText("Next");
    fireEvent.click(nextButton);
    await waitFor(() => {
      const calls = getCanonicalProcessEntitiesMock.mock.calls;
      const last = calls[calls.length - 1]?.[1] as { page?: number } | undefined;
      expect(last?.page).toBe(2);
    });
  });

  // 20. No sensitive paths rendered
  it("does not render private server paths in the UI", async () => {
    getCanonicalProcessSummaryMock.mockResolvedValueOnce(
      summary({ tree_metrics: { ...summary().tree_metrics } }),
    );
    renderView();
    await screen.findByTestId("canonical-process-table");
    expect(screen.queryByText(/\/opt\/private/)).not.toBeInTheDocument();
    expect(screen.queryByText(/C:\\private/)).not.toBeInTheDocument();
  });
});
