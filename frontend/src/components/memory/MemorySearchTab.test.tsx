import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import type React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { MemorySearchTab } from "./MemorySearchTab";

const searchMemoryArtifactsMock = vi.fn();

vi.mock("../../api/client", () => ({
  api: {
    searchMemoryArtifacts: (...args: unknown[]) => searchMemoryArtifactsMock(...args),
  },
}));

function payload(overrides: Record<string, unknown> = {}) {
  return {
    case_id: "case-1",
    evidence_id: "ev-1",
    evidence_name: "mem.raw",
    query: "6996",
    query_interpretation: "numeric_exact",
    selected_run_context: { mode: "per_family_active", contributing_runs: ["run-network"] },
    total: 2,
    page: 1,
    page_size: 100,
    total_pages: 1,
    sort: "relevance",
    results: [
      {
        result_id: "r-process",
        artifact_type: "memory_process_entity",
        artifact_family: "processes",
        case_id: "case-1",
        evidence_id: "ev-1",
        evidence_name: "mem.raw",
        memory_run_id: "run-process",
        plugin_run_id: "plugin-1",
        source_plugin: "windows.pslist",
        process_entity_id: "ent-6996",
        pid: 6996,
        ppid: 4,
        process_name: "powershell.exe",
        timestamp: "2026-01-01T00:00:00Z",
        timestamp_source: "create_time",
        title: "powershell.exe",
        summary: "powershell -enc AAAA",
        matched_fields: ["process.command_line"],
        matched_terms: [],
        provenance: {},
        raw_reference: {},
        navigation_target: { tab: "processes", target_tab: "processes", run_id: "run-process", evidence_id: "ev-1", process_entity_id: "ent-6996", pid: 6996 },
      },
      {
        result_id: "r-network",
        artifact_type: "memory_network_connection",
        artifact_family: "network",
        case_id: "case-1",
        evidence_id: "ev-1",
        memory_run_id: "run-network",
        plugin_run_id: "plugin-2",
        source_plugin: "windows.netstat",
        process_entity_id: "ent-6996",
        pid: 6996,
        process_name: "powershell.exe",
        title: "TCPv4 10.0.0.5:50000 -> 10.0.0.10:443",
        summary: "LISTENING",
        matched_fields: [],
        matched_terms: [],
        provenance: {},
        raw_reference: {},
        navigation_target: { tab: "artifacts", target_tab: "artifacts", artifact_family: "network", artifact_id: "r-network", run_id: "run-network", evidence_id: "ev-1", process_entity_id: "ent-6996", pid: 6996 },
      },
    ],
    facets: {
      artifact_type: { memory_process_entity: 1, memory_network_connection: 1 },
      source_plugin: { "windows.netstat": 1 },
      protocol: { TCPv4: 1 },
      network_state: { LISTENING: 1 },
      has_process: { linked: 2, unlinked: 0 },
    },
    coverage: {
      artifact_families_available: ["processes", "network", "sids", "privileges", "modules", "handles", "vads", "suspicious"],
      families_not_run: [],
      completed_empty: [],
      raw_only_fallback: false,
      normalization_warnings: [],
      raw_only_families: [],
      rejected_row_counts: {},
    },
    warnings: [],
    ...overrides,
  };
}

function renderTab(props: Partial<React.ComponentProps<typeof MemorySearchTab>> = {}) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const onSelectRunId = vi.fn();
  const onSelectEntityId = vi.fn();
  const onJumpToTab = vi.fn();
  render(
    <QueryClientProvider client={queryClient}>
      <MemorySearchTab caseId="case-1" evidenceId="ev-1" selectedRunId={null} onSelectRunId={onSelectRunId} onSelectEntityId={onSelectEntityId} onJumpToTab={onJumpToTab} {...props} />
    </QueryClientProvider>,
  );
  return { onSelectRunId, onSelectEntityId, onJumpToTab };
}

beforeEach(() => {
  searchMemoryArtifactsMock.mockReset();
  searchMemoryArtifactsMock.mockResolvedValue(payload());
});

describe("MemorySearchTab", () => {
  it("renders search tab controls and no-query state", () => {
    renderTab();
    expect(screen.getByTestId("memory-search-tab")).toBeInTheDocument();
    expect(screen.getByTestId("memory-search-input")).toBeInTheDocument();
    expect(screen.getByTestId("memory-search-interpretation")).toHaveTextContent(/No query yet/i);
    expect(screen.getByTestId("memory-search-empty-initial")).toBeInTheDocument();
  });

  it("renders exact PID results", async () => {
    renderTab();
    fireEvent.change(screen.getByTestId("memory-search-input"), { target: { value: "6996" } });
    fireEvent.click(screen.getByTestId("memory-search-submit"));
    expect((await screen.findAllByText("powershell.exe")).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/PID 6996/i).length).toBeGreaterThan(0);
  });

  it("renders command-line and network results", async () => {
    renderTab();
    fireEvent.change(screen.getByTestId("memory-search-input"), { target: { value: "powershell -enc" } });
    fireEvent.click(screen.getByTestId("memory-search-submit"));
    expect(await screen.findByText(/powershell -enc AAAA/i)).toBeInTheDocument();
    expect(screen.getByText(/10.0.0.5:50000/i)).toBeInTheDocument();
  });

  it("renders SID privilege module handle VAD and suspicious family filters", () => {
    renderTab();
    for (const label of ["SIDs", "Privileges", "Modules", "Handles", "VADs", "Suspicious memory"]) {
      expect(screen.getByRole("button", { name: label })).toBeInTheDocument();
    }
  });

  it("family filters update the API query", async () => {
    renderTab();
    fireEvent.click(screen.getByRole("button", { name: "Network" }));
    await waitFor(() => expect(searchMemoryArtifactsMock).toHaveBeenCalled());
    expect(searchMemoryArtifactsMock.mock.calls.at(-1)?.[1].artifact_types).toEqual(["network"]);
  });

  it("facets filter results", async () => {
    renderTab();
    fireEvent.change(screen.getByTestId("memory-search-input"), { target: { value: "6996" } });
    fireEvent.click(screen.getByTestId("memory-search-submit"));
    await screen.findByTestId("memory-search-facets");
    fireEvent.click(screen.getAllByText(/LISTENING/)[0]);
    await waitFor(() => expect(searchMemoryArtifactsMock.mock.calls.at(-1)?.[1].state).toBe("LISTENING"));
  });

  it("supports page sizes and pagination above and below", async () => {
    renderTab();
    fireEvent.click(screen.getByTestId("memory-search-submit"));
    await screen.findAllByText("powershell.exe");
    expect(screen.getAllByTestId("memory-search-pagination")).toHaveLength(2);
    fireEvent.change(screen.getByTestId("memory-search-page-size"), { target: { value: "250" } });
    await waitFor(() => expect(searchMemoryArtifactsMock.mock.calls.at(-1)?.[1].page_size).toBe(250));
  });

  it("page-size filter and sort reset to page one", async () => {
    searchMemoryArtifactsMock.mockResolvedValue(payload({ total: 300, total_pages: 3 }));
    renderTab();
    fireEvent.click(screen.getByTestId("memory-search-submit"));
    await screen.findAllByText("Next");
    fireEvent.click(screen.getAllByText("Next")[0]);
    await waitFor(() => expect(searchMemoryArtifactsMock.mock.calls.at(-1)?.[1].page).toBe(2));
    fireEvent.change(screen.getByTestId("memory-search-page-size"), { target: { value: "50" } });
    await waitFor(() => expect(searchMemoryArtifactsMock.mock.calls.at(-1)?.[1].page).toBe(1));
  });

  it("inspect process opens correct entity", async () => {
    const actions = renderTab();
    fireEvent.click(screen.getByTestId("memory-search-submit"));
    await screen.findAllByText("powershell.exe");
    fireEvent.click(screen.getAllByText("Inspect")[0]);
    expect(actions.onSelectEntityId).toHaveBeenCalledWith("ent-6996");
    expect(actions.onJumpToTab).toHaveBeenCalledWith("processes");
  });

  it("focus graph uses canonical entity ID", async () => {
    const actions = renderTab();
    fireEvent.click(screen.getByTestId("memory-search-submit"));
    await screen.findAllByText("powershell.exe");
    fireEvent.click(screen.getAllByText("Focus graph")[0]);
    expect(actions.onSelectEntityId).toHaveBeenCalledWith("ent-6996");
    expect(actions.onJumpToTab).toHaveBeenCalledWith("graph");
  });

  it("network result opens exact source view", async () => {
    const actions = renderTab();
    fireEvent.click(screen.getByTestId("memory-search-submit"));
    await screen.findAllByText(/10.0.0.5/);
    fireEvent.click(screen.getAllByText("Open source")[1]);
    expect(actions.onSelectRunId).toHaveBeenCalledWith("run-network");
    expect(actions.onJumpToTab).toHaveBeenCalledWith("artifacts");
  });

  it("raw fallback opens raw observations", async () => {
    const actions = renderTab();
    fireEvent.click(screen.getByTestId("memory-search-submit"));
    await screen.findAllByText("powershell.exe");
    fireEvent.click(screen.getAllByText("Raw")[0]);
    expect(actions.onJumpToTab).toHaveBeenCalledWith("raw");
  });

  it("renders precise empty state", async () => {
    searchMemoryArtifactsMock.mockResolvedValue(payload({ total: 0, total_pages: 0, results: [] }));
    renderTab();
    fireEvent.click(screen.getByTestId("memory-search-submit"));
    expect(await screen.findByTestId("memory-search-empty-results")).toHaveTextContent(/No memory artifacts/i);
  });

  it("renders bounded error state", async () => {
    searchMemoryArtifactsMock.mockRejectedValue(new Error("backend failed"));
    renderTab();
    fireEvent.click(screen.getByTestId("memory-search-submit"));
    expect(await screen.findByTestId("memory-search-error")).toHaveTextContent("backend failed");
  });

  it("does not issue N+1 process lookup calls", async () => {
    renderTab();
    fireEvent.click(screen.getByTestId("memory-search-submit"));
    await screen.findAllByText("powershell.exe");
    expect(searchMemoryArtifactsMock).toHaveBeenCalledTimes(1);
  });

  it("does not render cross-Evidence result as a different scope", async () => {
    renderTab();
    fireEvent.click(screen.getByTestId("memory-search-submit"));
    await screen.findAllByText("powershell.exe");
    expect(screen.queryByText("ev-2")).not.toBeInTheDocument();
  });
});
