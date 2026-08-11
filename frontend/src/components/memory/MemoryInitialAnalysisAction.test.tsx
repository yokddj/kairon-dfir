/** @vitest-environment jsdom */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { type MemoryEvidencePreparation, type MemoryScanRun } from "../../api/client";
import { MemoryInitialAnalysisAction } from "./MemoryInitialAnalysisAction";

const getMemoryEvidencePreparationMock = vi.fn();
const listMemoryRunsMock = vi.fn();
const startMemoryScanMock = vi.fn();
const navigateMock = vi.fn();

vi.mock("../../api/client", () => ({
  api: {
    getMemoryEvidencePreparation: (...args: unknown[]) => getMemoryEvidencePreparationMock(...args),
    listMemoryRuns: (...args: unknown[]) => listMemoryRunsMock(...args),
    startMemoryScan: (...args: unknown[]) => startMemoryScanMock(...args),
  },
}));

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return { ...actual, useNavigate: () => navigateMock };
});

const CASE = "case-1";
const EVIDENCE = "ev-1";

function preparation(overrides: Partial<MemoryEvidencePreparation> = {}): MemoryEvidencePreparation {
  return {
    evidence_id: EVIDENCE,
    platform: "linux",
    architecture: "x64",
    readiness: "ready",
    requires_symbols: true,
    can_start_analysis: true,
    human_message: "This evidence is ready to analyze.",
    has_vmware_companion: false,
    vmware_companion_id: null,
    vmware_companion_type: null,
    vmware_companion_filename: null,
    vmware_companion_sha256: null,
    vmware_companion_size_bytes: null,
    vmware_companion_recommended: false,
    vmware_companion_warning: null,
    zero_result_warning_code: null,
    zero_result_warning_message: null,
    zero_result_warning_plugin: null,
    ...overrides,
  };
}

function run(overrides: Partial<MemoryScanRun> = {}): MemoryScanRun {
  return {
    id: "run-1",
    case_id: CASE,
    evidence_id: EVIDENCE,
    backend: "volatility3",
    profile: "processes_basic",
    status: "completed",
    requested_plugin_count: 2,
    plugin_count: 2,
    plugins_completed: 2,
    plugins_failed: 0,
    plugins_skipped: 0,
    started_at: new Date().toISOString(),
    completed_at: new Date().toISOString(),
    duration_ms: 1200,
    output_dir: null,
    metadata_json: {},
    error_log: {},
    backend_version: null,
    worker_task_id: null,
    cancellation_requested: false,
    created_at: new Date().toISOString(),
    ...overrides,
  };
}

function startResponse(overrides: Partial<MemoryScanRun> = {}) {
  const scanRun = run({ status: "queued", plugins_completed: 0, ...overrides });
  return { accepted: true, evidence_id: EVIDENCE, run_id: scanRun.id, status: scanRun.status, message: "queued", run: scanRun };
}

function renderAction() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryInitialAnalysisAction caseId={CASE} evidenceId={EVIDENCE} />
    </QueryClientProvider>,
  );
}

describe("MemoryInitialAnalysisAction", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    listMemoryRunsMock.mockResolvedValue([]);
  });

  it("shows Start memory analysis when preparation is ready and no run exists yet", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(preparation());
    renderAction();
    expect(await screen.findByTestId("memory-initial-analysis-start-button")).toBeInTheDocument();
  });

  it("does not show Start when preparation is not ready", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(preparation({ readiness: "symbols_required", can_start_analysis: false }));
    renderAction();
    await waitFor(() => expect(getMemoryEvidencePreparationMock).toHaveBeenCalled());
    expect(screen.queryByTestId("memory-initial-analysis-start-button")).not.toBeInTheDocument();
  });

  it("does not show Start when can_start_analysis is false even if readiness says ready", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(preparation({ readiness: "ready", can_start_analysis: false }));
    renderAction();
    await waitFor(() => expect(getMemoryEvidencePreparationMock).toHaveBeenCalled());
    expect(screen.queryByTestId("memory-initial-analysis-start-button")).not.toBeInTheDocument();
  });

  it("clicking Start calls startMemoryScan with processes_basic, never metadata_only or network_basic", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(preparation());
    startMemoryScanMock.mockResolvedValue(startResponse());
    renderAction();
    await userEvent.click(await screen.findByTestId("memory-initial-analysis-start-button"));
    await waitFor(() => expect(startMemoryScanMock).toHaveBeenCalledWith(CASE, EVIDENCE, "processes_basic"));
    for (const call of startMemoryScanMock.mock.calls) {
      expect(call[2]).toBe("processes_basic");
    }
  });

  it("double click only calls startMemoryScan once", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(preparation());
    let resolveStart: (value: unknown) => void = () => {};
    startMemoryScanMock.mockImplementation(() => new Promise((resolve) => { resolveStart = resolve; }));
    renderAction();
    const button = await screen.findByTestId("memory-initial-analysis-start-button");
    await userEvent.click(button);
    await userEvent.click(button);
    resolveStart(startResponse());
    await waitFor(() => expect(startMemoryScanMock).toHaveBeenCalledTimes(1));
  });

  it("shows a pending run as Starting analysis...", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(preparation());
    listMemoryRunsMock.mockResolvedValue([run({ status: "pending", plugins_completed: 0 })]);
    renderAction();
    expect(await screen.findByTestId("memory-initial-analysis-starting")).toBeInTheDocument();
    expect(screen.queryByTestId("memory-initial-analysis-start-button")).not.toBeInTheDocument();
  });

  it("shows a queued run as Starting analysis...", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(preparation());
    listMemoryRunsMock.mockResolvedValue([run({ status: "queued", plugins_completed: 0 })]);
    renderAction();
    expect(await screen.findByTestId("memory-initial-analysis-starting")).toBeInTheDocument();
  });

  it("shows a running run with real N/M plugin progress", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(preparation());
    listMemoryRunsMock.mockResolvedValue([run({ status: "running", plugins_completed: 1, plugin_count: 2 })]);
    renderAction();
    expect(await screen.findByTestId("memory-initial-analysis-running")).toBeInTheDocument();
    expect(await screen.findByTestId("memory-initial-analysis-progress")).toHaveTextContent("1 / 2 plugins completed");
  });

  it("shows an indeterminate state instead of a fabricated percentage when plugin_count is 0", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(preparation());
    listMemoryRunsMock.mockResolvedValue([run({ status: "running", plugins_completed: 0, plugin_count: 0 })]);
    renderAction();
    expect(await screen.findByTestId("memory-initial-analysis-indeterminate")).toBeInTheDocument();
    expect(screen.queryByTestId("memory-initial-analysis-progress")).not.toBeInTheDocument();
  });

  it("shows completed with a View memory results button, without navigating automatically", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(preparation());
    listMemoryRunsMock.mockResolvedValue([run({ status: "completed" })]);
    renderAction();
    const el = await screen.findByTestId("memory-initial-analysis-completed");
    expect(el).toHaveTextContent("Initial analysis completed");
    expect(navigateMock).not.toHaveBeenCalled();

    await userEvent.click(screen.getByTestId("memory-initial-analysis-view-results-button"));
    expect(navigateMock).toHaveBeenCalledWith("/cases/case-1/m/ev-1/overview");
  });

  it("treats completed_with_errors as a success path, not a failure", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(preparation());
    listMemoryRunsMock.mockResolvedValue([run({ status: "completed_with_errors" })]);
    renderAction();
    const el = await screen.findByTestId("memory-initial-analysis-completed-with-errors");
    expect(el).toHaveTextContent("Initial analysis completed with warnings");
    expect(screen.getByTestId("memory-initial-analysis-view-results-button")).toBeInTheDocument();
    expect(screen.queryByTestId("memory-initial-analysis-retry-button")).not.toBeInTheDocument();
  });

  it("shows failed with a Retry action", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(preparation());
    listMemoryRunsMock.mockResolvedValue([run({ status: "failed" })]);
    renderAction();
    const el = await screen.findByTestId("memory-initial-analysis-failed");
    expect(el).toHaveTextContent("Initial analysis failed");
    expect(screen.getByTestId("memory-initial-analysis-retry-button")).toBeInTheDocument();
    expect(screen.queryByTestId("memory-initial-analysis-view-results-button")).not.toBeInTheDocument();
  });

  it("shows timed_out with a Retry action", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(preparation());
    listMemoryRunsMock.mockResolvedValue([run({ status: "timed_out" })]);
    renderAction();
    const el = await screen.findByTestId("memory-initial-analysis-timed-out");
    expect(el).toHaveTextContent("Initial analysis timed out");
    expect(screen.getByTestId("memory-initial-analysis-retry-button")).toBeInTheDocument();
  });

  it("Retry after failed calls startMemoryScan again, still with processes_basic", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(preparation());
    listMemoryRunsMock.mockResolvedValue([run({ status: "failed" })]);
    startMemoryScanMock.mockResolvedValue(startResponse({ id: "run-2" }));
    renderAction();
    await userEvent.click(await screen.findByTestId("memory-initial-analysis-retry-button"));
    await waitFor(() => expect(startMemoryScanMock).toHaveBeenCalledWith(CASE, EVIDENCE, "processes_basic"));
  });

  it("refresh/reopen with a running run shows the running state, never Start, and never re-submits", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(preparation());
    listMemoryRunsMock.mockResolvedValue([run({ status: "running", plugins_completed: 1, plugin_count: 2 })]);
    renderAction();
    expect(await screen.findByTestId("memory-initial-analysis-running")).toBeInTheDocument();
    expect(screen.queryByTestId("memory-initial-analysis-start-button")).not.toBeInTheDocument();
    expect(startMemoryScanMock).not.toHaveBeenCalled();
  });

  it("refresh/reopen with a completed run shows View memory results, never Start", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(preparation());
    listMemoryRunsMock.mockResolvedValue([run({ status: "completed" })]);
    renderAction();
    expect(await screen.findByTestId("memory-initial-analysis-completed")).toBeInTheDocument();
    expect(screen.queryByTestId("memory-initial-analysis-start-button")).not.toBeInTheDocument();
  });

  it("uses the exact same mutation for Linux and Windows evidence -- no platform branching", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(preparation({ platform: "windows" }));
    startMemoryScanMock.mockResolvedValue(startResponse());
    renderAction();
    await userEvent.click(await screen.findByTestId("memory-initial-analysis-start-button"));
    await waitFor(() => expect(startMemoryScanMock).toHaveBeenCalledWith(CASE, EVIDENCE, "processes_basic"));
  });

  it("an absent VMware companion does not block Start when preparation is already ready", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(
      preparation({ has_vmware_companion: false, vmware_companion_recommended: true, vmware_companion_warning: "A matching .vmsn or .vmss file may be required for reliable analysis." }),
    );
    renderAction();
    expect(await screen.findByTestId("memory-initial-analysis-start-button")).toBeInTheDocument();
  });
});
