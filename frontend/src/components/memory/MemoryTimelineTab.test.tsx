import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import type React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryTimelineTab } from "./MemoryTimelineTab";
import { MEMORY_TABS } from "../../lib/memoryWorkspaceState";

const getMemoryTimelineMock = vi.fn();

vi.mock("../../api/client", () => ({
  api: {
    getMemoryTimeline: (...args: unknown[]) => getMemoryTimelineMock(...args),
  },
}));

function event(overrides: Record<string, unknown> = {}) {
  return {
    event_id: "evt-start",
    case_id: "case-1",
    evidence_id: "ev-1",
    memory_context_id: "run-1",
    memory_run_id: "run-1",
    artifact_type: "memory_process_entity",
    artifact_family: "processes",
    event_kind: "process_start",
    occurred_at: "2024-03-22T12:00:00Z",
    occurred_at_end: null,
    timestamp_source: "process.create_time",
    timestamp_semantics: "process creation time reported by memory plugin",
    timestamp_precision: "second",
    timestamp_confidence: "observed",
    timestamp_timezone: "UTC",
    is_undated: false,
    process_entity_id: "ent-6996",
    pid: 6996,
    ppid: 9132,
    process_name: "powershell.exe",
    executable_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    command_line_summary: "powershell.exe -NoP -EncodedCommand AAAA",
    local_endpoint: null,
    remote_endpoint: null,
    source_plugin: "windows.pslist",
    source_parser: null,
    title: "Process started: powershell.exe",
    summary: "powershell.exe -NoP -EncodedCommand AAAA",
    provenance: { document_id: "proc-1" },
    raw_reference: { document_id: "proc-1" },
    navigation_target: { tab: "processes", run_id: "run-1", evidence_id: "ev-1", process_entity_id: "ent-6996", pid: 6996 },
    normalization_warnings: [],
    correlations: [
      {
        correlation_id: "corr-1",
        left_artifact_id: "evt-start",
        right_artifact_id: "disk-1",
        left_artifact_type: "memory_process_entity",
        right_artifact_type: "windows_event",
        process_entity_id: "ent-6996",
        correlation_type: "memory_process_to_event_log_process_creation",
        confidence: "high",
        confidence_score: 85,
        reasons: ["same PID", "same normalized process name", "timestamps within 2.0 seconds"],
        matched_fields: ["pid", "process.name", "timestamp"],
        time_delta_seconds: 2,
        contradictory_fields: [],
        source_provenance: {},
        created_by_rule_version: "memory_correlation_v1",
        navigation_targets: {},
      },
    ],
    ...overrides,
  };
}

function payload(overrides: Record<string, unknown> = {}) {
  return {
    items: [
      event(),
      event({ event_id: "evt-exit", event_kind: "process_exit", title: "Process exited: powershell.exe", occurred_at: "2024-03-22T12:05:00Z", correlations: [] }),
      event({ event_id: "evt-net", artifact_type: "memory_network_connection", artifact_family: "network", event_kind: "network_connection", title: "TCP connection", source_plugin: "windows.netscan", local_endpoint: { address: "192.168.1.10", port: 49722 }, remote_endpoint: { address: "13.107.42.14", port: 443 }, summary: "ESTABLISHED", correlations: [] }),
      event({ event_id: "evt-cmd", artifact_type: "memory_process_observation", artifact_family: "raw_observations", event_kind: "command_line", title: "Command line observed: powershell.exe", summary: "powershell.exe <script>", correlations: [] }),
    ],
    total: 4,
    page: 1,
    page_size: 100,
    total_pages: 1,
    time_range: { sort_order: "asc" },
    selected_evidence: { id: "ev-1" },
    selected_memory_context: { memory_run_id: "run-1" },
    event_kind_counts: { process_start: 1, process_exit: 1, network_connection: 1, command_line: 1 },
    artifact_family_counts: { processes: 2, network: 1, raw_observations: 1 },
    timestamp_quality_summary: { timestamped: 4, undated: 1, second: 4 },
    correlated_event_count: 1,
    undated_count: 1,
    warnings: [],
    coverage: {},
    ...overrides,
  };
}

function renderTab(props: Partial<React.ComponentProps<typeof MemoryTimelineTab>> = {}) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const onSelectRunId = vi.fn();
  const onSelectEntityId = vi.fn();
  const onJumpToTab = vi.fn();
  render(<QueryClientProvider client={queryClient}><MemoryTimelineTab caseId="case-1" evidenceId="ev-1" selectedRunId={null} selectedEntityId={null} onSelectRunId={onSelectRunId} onSelectEntityId={onSelectEntityId} onJumpToTab={onJumpToTab} {...props} /></QueryClientProvider>);
  return { onSelectRunId, onSelectEntityId, onJumpToTab };
}

beforeEach(() => {
  getMemoryTimelineMock.mockReset();
  getMemoryTimelineMock.mockResolvedValue(payload());
});

describe("MemoryTimelineTab", () => {
  it("timeline tab appears after search", () => {
    expect(MEMORY_TABS.map((tab) => tab.key).slice(0, 3)).toEqual(["overview", "search", "timeline"]);
  });

  it("loads current Evidence and renders timeline controls and events", async () => {
    renderTab();
    expect(screen.getByTestId("memory-timeline-tab")).toBeInTheDocument();
    expect(await screen.findByText("Process started: powershell.exe")).toBeInTheDocument();
    expect(screen.getByText("Process exited: powershell.exe")).toBeInTheDocument();
    expect(screen.getByTestId("memory-timeline-endpoints")).toHaveTextContent("192.168.1.10:49722 -> 13.107.42.14:443");
    expect(screen.getByText(/powershell.exe <script>/)).toBeInTheDocument();
    expect(screen.getAllByTestId("memory-timeline-precision")[0]).toHaveTextContent("second/observed");
    expect(getMemoryTimelineMock).toHaveBeenCalledWith("case-1", expect.objectContaining({ evidence_id: "ev-1" }));
  });

  it("renders correlation badges and detail with matched fields and contradictions", async () => {
    renderTab();
    fireEvent.click(await screen.findByTestId("memory-timeline-correlation-badge"));
    expect(screen.getByTestId("memory-correlation-detail")).toBeInTheDocument();
    expect(screen.getByText("memory_process_to_event_log_process_creation")).toBeInTheDocument();
    expect(screen.getAllByTestId("memory-correlation-matched-field").map((el) => el.textContent)).toContain("pid");
    expect(screen.getByTestId("memory-correlation-contradiction")).toHaveTextContent("None");
    expect(screen.getByText("timestamps within 2.0 seconds")).toBeInTheDocument();
  });

  it("renders contradictions in correlation detail", async () => {
    getMemoryTimelineMock.mockResolvedValue(payload({ items: [event({ correlations: [{ ...(event().correlations[0] as any), contradictory_fields: ["mismatched executable path"] }] })] }));
    renderTab();
    fireEvent.click(await screen.findByTestId("memory-timeline-correlation-badge"));
    expect(screen.getByTestId("memory-correlation-contradiction")).toHaveTextContent("mismatched executable path");
  });

  it("filters server side and resets page", async () => {
    renderTab();
    await screen.findByText("Process started: powershell.exe");
    fireEvent.change(screen.getAllByDisplayValue("All")[0], { target: { value: "process_start" } });
    await waitFor(() => expect(getMemoryTimelineMock).toHaveBeenLastCalledWith("case-1", expect.objectContaining({ event_kinds: ["process_start"], page: 1 })));
  });

  it("supports family confidence correlated-only time and include-undated filters", async () => {
    renderTab();
    await screen.findByText("Process started: powershell.exe");
    fireEvent.change(screen.getAllByDisplayValue("All")[1], { target: { value: "network" } });
    fireEvent.change(screen.getByDisplayValue("Default"), { target: { value: "high" } });
    fireEvent.click(screen.getByLabelText(/Correlated only/i));
    fireEvent.click(screen.getByLabelText(/Include undated/i));
    await waitFor(() => expect(getMemoryTimelineMock).toHaveBeenLastCalledWith("case-1", expect.objectContaining({ artifact_families: ["network"], correlation_confidence: "high", has_correlations: true, include_undated: true })));
  });

  it("keeps undated events in an explicit section", async () => {
    getMemoryTimelineMock.mockResolvedValue(payload({ items: [event({ event_id: "undated", is_undated: true, occurred_at: null, title: "Undated VAD", artifact_family: "vads", event_kind: "vad_observation", correlations: [] })], total: 1 }));
    renderTab();
    expect(await screen.findByTestId("memory-timeline-undated")).toBeInTheDocument();
    expect(screen.getByTestId("memory-timeline-undated-event")).toHaveTextContent("Undated VAD");
  });

  it("supports page sizes and top and bottom pagination", async () => {
    getMemoryTimelineMock.mockResolvedValue(payload({ total: 200, total_pages: 2 }));
    renderTab();
    await screen.findByText("Process started: powershell.exe");
    expect(screen.getAllByTestId("memory-timeline-pagination")).toHaveLength(2);
    fireEvent.change(screen.getByTestId("memory-timeline-page-size"), { target: { value: "250" } });
    await waitFor(() => expect(getMemoryTimelineMock).toHaveBeenLastCalledWith("case-1", expect.objectContaining({ page_size: 250, page: 1 })));
    const nextButtons = await screen.findAllByText("Next");
    fireEvent.click(nextButtons[0]);
    await waitFor(() => expect(getMemoryTimelineMock).toHaveBeenLastCalledWith("case-1", expect.objectContaining({ page: 2 })));
  });

  it("navigation actions select exact process run and tabs", async () => {
    const { onSelectRunId, onSelectEntityId, onJumpToTab } = renderTab();
    await screen.findByText("Process started: powershell.exe");
    fireEvent.click(screen.getAllByText("Open process")[0]);
    expect(onSelectRunId).toHaveBeenCalledWith("run-1");
    expect(onSelectEntityId).toHaveBeenCalledWith("ent-6996");
    expect(onJumpToTab).toHaveBeenCalledWith("processes");
    fireEvent.click(screen.getAllByText("Focus graph")[0]);
    expect(onJumpToTab).toHaveBeenCalledWith("graph");
    fireEvent.click(screen.getAllByText("Open raw")[0]);
    expect(onJumpToTab).toHaveBeenCalledWith("raw");
    fireEvent.click(screen.getAllByText("Open Search result")[0]);
    expect(onJumpToTab).toHaveBeenCalledWith("search");
  });

  it("distinguishes empty timestamped state", async () => {
    getMemoryTimelineMock.mockResolvedValue(payload({ items: [], total: 0, timestamp_quality_summary: { timestamped: 0, undated: 3 }, undated_count: 3 }));
    renderTab();
    expect(await screen.findByTestId("memory-timeline-empty")).toHaveTextContent("No timestamped timeline data");
  });

  it("does not render cross-Evidence rows returned outside scope", async () => {
    getMemoryTimelineMock.mockResolvedValue(payload({ items: [event({ evidence_id: "ev-1" })] }));
    renderTab();
    await screen.findByText("Process started: powershell.exe");
    expect(screen.queryByText("ev-2")).not.toBeInTheDocument();
  });
});
