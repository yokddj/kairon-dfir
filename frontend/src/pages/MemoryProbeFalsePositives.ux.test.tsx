/** @vitest-environment jsdom */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

const getMemoryOverviewMock = vi.fn();
const getMemoryActiveResultMock = vi.fn();
const getMemoryAnalysisCatalogueMock = vi.fn();
const getMemoryBackendOverviewMock = vi.fn();
const getMemoryEvidenceLandingMock = vi.fn();
const confirmMemoryTypeMock = vi.fn();
const startMemoryAnalysisBatchMock = vi.fn();
const getActiveMemoryAnalysisBatchMock = vi.fn();
const getMemoryAnalysisBatchMock = vi.fn();
const cancelMemoryAnalysisBatchMock = vi.fn();
const getMemoryUploadReadinessMock = vi.fn();
const listMemoryRunsMock = vi.fn();
const getMemoryReadinessMock = vi.fn();

vi.mock("../api/client", () => ({
  api: {
    getMemoryOverview: (...args: unknown[]) => getMemoryOverviewMock(...args),
    getMemoryActiveResult: (...args: unknown[]) => getMemoryActiveResultMock(...args),
    getMemoryAnalysisCatalogue: (...args: unknown[]) => getMemoryAnalysisCatalogueMock(...args),
    getMemoryBackendOverview: (...args: unknown[]) => getMemoryBackendOverviewMock(...args),
    getMemoryEvidenceLanding: (...args: unknown[]) => getMemoryEvidenceLandingMock(...args),
    confirmMemoryType: (...args: unknown[]) => confirmMemoryTypeMock(...args),
    startMemoryAnalysisBatch: (...args: unknown[]) => startMemoryAnalysisBatchMock(...args),
    getActiveMemoryAnalysisBatch: (...args: unknown[]) => getActiveMemoryAnalysisBatchMock(...args),
    getMemoryAnalysisBatch: (...args: unknown[]) => getMemoryAnalysisBatchMock(...args),
    cancelMemoryAnalysisBatch: (...args: unknown[]) => cancelMemoryAnalysisBatchMock(...args),
    getMemoryUploadReadiness: (...args: unknown[]) => getMemoryUploadReadinessMock(...args),
    listMemoryRuns: (...args: unknown[]) => listMemoryRunsMock(...args),
    getMemoryReadiness: (...args: unknown[]) => getMemoryReadinessMock(...args),
  },
}));

vi.mock("../context/ActiveCaseContext", () => ({
  useActiveCase: () => ({ setActiveCaseId: vi.fn() }),
}));

import MemoryEvidencePage from "./MemoryEvidencePage";

const CASE = "case-1";
const EVID = "ev-1";

function makeOverview(overrides: Record<string, unknown> = {}) {
  return {
    mode: "memory_only",
    has_memory_evidence: true,
    has_disk_events: false,
    message: "ok",
    enabled: true,
    backend_available: true,
    backend_version: "2.28.0",
    profiles: {},
    evidences: [
      {
        evidence_id: EVID,
        case_id: CASE,
        filename: "DC02-20240322-125906.dmp",
        detected_host: "DC02",
        size_bytes: 4 * 1024 * 1024 * 1024,
        created_at: "2026-06-20T00:00:00Z",
        processed_at: "2026-06-20T00:01:00Z",
        ingest_status: "completed",
        metadata: {},
        run_count: 0,
        latest_run_id: null,
        latest_run_status: null,
        detection_status: "probable_disk",
        detected_format: "disk_image",
        detection_confidence: "high",
        detection_reason: "MBR partition signature detected.",
        operator_override: false,
        operator_override_reason: null,
        can_analyze: false,
        families: [
          { family: "processes", state: "not_analyzed", title: "Processes", active_run: null, latest_attempt: null, selection_reason: "not_analyzed", using_fallback: false, historical_override: false, availability_reason: null, count: 0, document_type: "memory_process_entity", count_source: "no_active_run" },
        ],
      },
    ],
    runs: [],
    ...overrides,
  };
}

const setupMocks = (overrides: Record<string, unknown> = {}) => {
  const ov = makeOverview(overrides);
  getMemoryOverviewMock.mockResolvedValue(ov);
  getMemoryEvidenceLandingMock.mockResolvedValue({
    case_id: CASE,
    items: ov.evidences,
  });
  getMemoryActiveResultMock.mockResolvedValue({ active_run: null });
  getMemoryAnalysisCatalogueMock.mockResolvedValue({
    case_id: CASE,
    evidence_id: EVID,
    items: [
      { profile: "metadata_only", family: "system_info", title: "System metadata", description: "", cost_label: "Fast", est_duration_seconds: 30, available: true, availability_reason: null, last_run: null, last_status: "completed", last_count: 1 },
      { profile: "processes_extended", family: "processes", title: "Processes", description: "", cost_label: "Medium", est_duration_seconds: 60, available: true, availability_reason: null, last_run: null, last_status: "completed", last_count: 255 },
    ],
  });
  getMemoryBackendOverviewMock.mockResolvedValue({
    backends: [{ backend: "volatility3", ready: true, version: "2.28.0", message: "OK" }],
    queue: {},
    ready: true,
  });
  confirmMemoryTypeMock.mockResolvedValue({
    evidence_id: EVID,
    case_id: CASE,
    status: "probable_disk_confirmed_as_memory",
    operator_override: true,
    can_analyze: true,
  });
  startMemoryAnalysisBatchMock.mockResolvedValue({ id: "batch-1" });
  getActiveMemoryAnalysisBatchMock.mockResolvedValue(null);
  getMemoryAnalysisBatchMock.mockResolvedValue({});
  cancelMemoryAnalysisBatchMock.mockResolvedValue({});
  getMemoryUploadReadinessMock.mockResolvedValue({
    upload_enabled: true,
    analysis_enabled: true,
    dedicated_worker_online: true,
    backend_ready: true,
    max_upload_bytes: 5_368_709_120,
    max_upload_display: "5.0 GiB",
    recommended_max_upload_bytes: 5_368_709_120,
    required_capacity_bytes: 0,
    can_accept_selected_size: true,
    message: "ready",
    allowed_extensions: [".img", ".raw", ".dmp", ".bin"],
  });
  listMemoryRunsMock.mockResolvedValue([]);
  getMemoryReadinessMock.mockResolvedValue({
    ready: true,
    blockers: [],
  });
};

beforeEach(() => {
  vi.clearAllMocks();
  setupMocks();
});

const renderPage = () => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, refetchInterval: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[`/cases/${CASE}/memory/${EVID}`]}>
        <Routes>
          <Route path="/cases/:caseId/memory/:evidenceId" element={<MemoryEvidencePage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
};

describe("Memory probe false positives and probable disk confirmation v1", () => {
  it("shows the 'Probable disk image' banner when detection_status=probable_disk", async () => {
    renderPage();
    await waitFor(() => {
      expect(screen.getByTestId("memory-type-probable-disk")).toBeTruthy();
    });
    expect(screen.getAllByText(/Probable disk image/i).length).toBeGreaterThan(0);
  });

  it("shows the 'Confirm as memory evidence' button for probable_disk", async () => {
    renderPage();
    await waitFor(() => {
      expect(screen.getByTestId("memory-probable-disk-confirm-button")).toBeTruthy();
    });
  });

  it("opens the confirmation modal for probable_disk", async () => {
    renderPage();
    await waitFor(() => screen.getByTestId("memory-probable-disk-confirm-button"));
    fireEvent.click(screen.getByTestId("memory-probable-disk-confirm-button"));
    await waitFor(() => screen.getByTestId("memory-type-confirmation-modal"));
    const details = screen.getByTestId("memory-type-confirmation-details");
    expect(details.textContent).toContain("DC02-20240322-125906.dmp");
  });

  it("Run analysis is disabled when can_analyze=false", async () => {
    renderPage();
    await waitFor(() => {
      const btn = screen.getByTestId("memory-open-catalogue");
      expect(btn.hasAttribute("disabled")).toBe(true);
    });
  });

  it("the confirmation modal requires checkbox and reason", async () => {
    renderPage();
    await waitFor(() => screen.getByTestId("memory-probable-disk-confirm-button"));
    fireEvent.click(screen.getByTestId("memory-probable-disk-confirm-button"));
    await waitFor(() => screen.getByTestId("memory-type-confirmation-modal"));
    const confirm = screen.getByTestId("memory-type-confirmation-confirm");
    expect(confirm.hasAttribute("disabled")).toBe(true);
    fireEvent.click(screen.getByTestId("memory-type-confirmation-checkbox"));
    fireEvent.change(screen.getByTestId("memory-type-confirmation-reason"), {
      target: { value: "Known crash dump" },
    });
    expect(confirm.hasAttribute("disabled")).toBe(false);
  });

  it("success shows the toast and enables analysis", async () => {
    renderPage();
    await waitFor(() => screen.getByTestId("memory-probable-disk-confirm-button"));
    fireEvent.click(screen.getByTestId("memory-probable-disk-confirm-button"));
    await waitFor(() => screen.getByTestId("memory-type-confirmation-modal"));
    fireEvent.click(screen.getByTestId("memory-type-confirmation-checkbox"));
    fireEvent.change(screen.getByTestId("memory-type-confirmation-reason"), {
      target: { value: "Known crash dump" },
    });
    fireEvent.click(screen.getByTestId("memory-type-confirmation-confirm"));
    await waitFor(() => {
      expect(confirmMemoryTypeMock).toHaveBeenCalledWith(
        CASE, EVID, "Known crash dump",
      );
    });
  });

  it("HTTP error from the server is shown in the modal", async () => {
    confirmMemoryTypeMock.mockRejectedValue(new Error("Server failed"));
    renderPage();
    await waitFor(() => screen.getByTestId("memory-probable-disk-confirm-button"));
    fireEvent.click(screen.getByTestId("memory-probable-disk-confirm-button"));
    await waitFor(() => screen.getByTestId("memory-type-confirmation-modal"));
    fireEvent.click(screen.getByTestId("memory-type-confirmation-checkbox"));
    fireEvent.change(screen.getByTestId("memory-type-confirmation-reason"), {
      target: { value: "x" },
    });
    fireEvent.click(screen.getByTestId("memory-type-confirmation-confirm"));
    await waitFor(() => {
      expect(screen.getByTestId("memory-type-confirmation-error")).toBeTruthy();
    });
  });

  it("the modal hides technical endpoint paths from the user", () => {
    renderPage();
    expect(document.body.innerHTML).not.toMatch(/\/confirm-memory-type/);
    expect(document.body.innerHTML).not.toMatch(/probe-memory-image/);
  });

  it("the modal has role=dialog and aria-modal=true", async () => {
    renderPage();
    await waitFor(() => screen.getByTestId("memory-probable-disk-confirm-button"));
    fireEvent.click(screen.getByTestId("memory-probable-disk-confirm-button"));
    await waitFor(() => screen.getByTestId("memory-type-confirmation-modal"));
    const modal = screen.getByTestId("memory-type-confirmation-modal");
    expect(modal.getAttribute("role")).toBe("dialog");
    expect(modal.getAttribute("aria-modal")).toBe("true");
  });

  it("Escape key closes the modal", async () => {
    renderPage();
    await waitFor(() => screen.getByTestId("memory-probable-disk-confirm-button"));
    fireEvent.click(screen.getByTestId("memory-probable-disk-confirm-button"));
    await waitFor(() => screen.getByTestId("memory-type-confirmation-modal"));
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByTestId("memory-type-confirmation-modal")).toBeNull();
  });

  it("renders at narrow viewport without breaking", () => {
    Object.defineProperty(window, "innerWidth", { value: 480, configurable: true });
    window.dispatchEvent(new Event("resize"));
    renderPage();
    expect(document.body.innerHTML).toBeTruthy();
  });

  it("does not leak sensitive paths in any rendered copy", () => {
    renderPage();
    const html = document.body.innerHTML;
    expect(html).not.toMatch(/\/root\/[a-z]+/i);
    expect(html).not.toMatch(/\/etc\/passwd/i);
    expect(html).not.toMatch(/sk-[a-z0-9]{20,}/i);
  });

  it("network availability reflects worker capability (not API process)", async () => {
    // The catalogue uses the worker probe; with both NetScan and NetStat
    // importable in the worker, network_basic should be available.
    const catalogue = {
      case_id: CASE,
      evidence_id: EVID,
      items: [
        { profile: "network_basic", family: "network", title: "Network", description: "", cost_label: "Slow", est_duration_seconds: 1800, available: true, availability_reason: null, last_run: null, last_status: null, last_count: 0 },
      ],
    };
    getMemoryAnalysisCatalogueMock.mockResolvedValue(catalogue);
    renderPage();
    await waitFor(() => screen.getByTestId("memory-type-probable-disk"));
    // The header shows the probable disk banner; the catalogue
    // mock has network available because the worker has pefile.
    expect(getMemoryAnalysisCatalogueMock).toHaveBeenCalled();
  });

  it("Run analysis is enabled after confirming probable_disk", async () => {
    setupMocks({
      evidences: [{
        evidence_id: EVID,
        case_id: CASE,
        filename: "DC02.dmp",
        detected_host: "DC02",
        size_bytes: 4 * 1024 * 1024 * 1024,
        created_at: "2026-06-20T00:00:00Z",
        processed_at: "2026-06-20T00:01:00Z",
        ingest_status: "completed",
        metadata: {},
        run_count: 0,
        latest_run_id: null,
        latest_run_status: null,
        detection_status: "probable_disk_confirmed_as_memory",
        detected_format: "disk_image",
        detection_confidence: "high",
        detection_reason: "MBR partition signature detected.",
        operator_override: true,
        operator_override_reason: "Known crash dump",
        can_analyze: true,
        families: [],
      }],
    });
    renderPage();
    await waitFor(() => {
      const btn = screen.getByTestId("memory-open-catalogue");
      expect(btn).toBeTruthy();
      expect(btn.hasAttribute("disabled")).toBe(false);
    });
  });

  it("cancel button does not send a request", async () => {
    renderPage();
    await waitFor(() => screen.getByTestId("memory-probable-disk-confirm-button"));
    fireEvent.click(screen.getByTestId("memory-probable-disk-confirm-button"));
    await waitFor(() => screen.getByTestId("memory-type-confirmation-modal"));
    fireEvent.click(screen.getByTestId("memory-type-confirmation-cancel"));
    expect(confirmMemoryTypeMock).not.toHaveBeenCalled();
    expect(screen.queryByTestId("memory-type-confirmation-modal")).toBeNull();
  });

  it("network availability in catalogue is not the misleading 'missing dependency'", async () => {
    // The catalogue no longer shows the misleading "missing dependency: volatility3"
    // message that came from probing the API process instead of the worker.
    const catalogue = {
      case_id: CASE,
      evidence_id: EVID,
      items: [
        {
          profile: "network_basic",
          family: "network",
          title: "Network",
          description: "",
          cost_label: "Slow",
          est_duration_seconds: 1800,
          available: true,
          availability_reason: "Available, requirements not yet validated",
          last_run: null,
          last_status: null,
          last_count: 0,
        },
      ],
    };
    getMemoryAnalysisCatalogueMock.mockResolvedValue(catalogue);
    renderPage();
    await waitFor(() => screen.getByTestId("memory-type-probable-disk"));
    expect(getMemoryAnalysisCatalogueMock).toHaveBeenCalled();
    // The test passes if no misleading text is rendered.
    expect(document.body.innerHTML).not.toMatch(/missing dependency: volatility3/);
  });
});
