/** @vitest-environment jsdom */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../../api/client";
import { MemoryAnalysisCatalogueModal } from "./MemoryAnalysisCatalogueModal";
import { MemoryEvidenceHeader } from "./MemoryEvidenceHeader";

vi.mock("../../api/client", () => ({
  api: {
    startMemoryScan: vi.fn(),
    startMemoryRunAll: vi.fn(),
    getMemoryAnalysisCatalogue: vi.fn(),
    getMemoryOverview: vi.fn(),
    getMemoryBackendOverview: vi.fn(),
    getMemoryEvidenceReadiness: vi.fn(),
    getActiveMemoryAnalysisBatch: vi.fn(),
    getMemoryAnalysisBatch: vi.fn(),
  },
}));

const CASE = "case-1";
const EVIDENCE = "ev-1";

const freshCatalogue = {
  case_id: CASE,
  evidence_id: EVIDENCE,
  items: [
    { profile: "metadata_only", family: "system_info", title: "System metadata", description: "", cost_label: "Fast", est_duration_seconds: 20, available: true, availability_reason: null, last_run: null, last_status: null, last_count: 0 },
    { profile: "processes_basic", family: "processes", title: "Standard process analysis", description: "", cost_label: "Medium", est_duration_seconds: 90, available: true, availability_reason: null, last_run: null, last_status: null, last_count: 0 },
    { profile: "processes_extended", family: "processes", title: "Extended process analysis", description: "", cost_label: "Medium", est_duration_seconds: 240, available: true, availability_reason: null, last_run: null, last_status: null, last_count: 0 },
    { profile: "network_basic", family: "network", title: "Network connections", description: "", cost_label: "Medium", est_duration_seconds: 90, available: false, availability_reason: "No compatible Windows network plugin is available.", last_run: null, last_status: null, last_count: 0 },
    { profile: "modules_basic", family: "modules", title: "Process modules (DLLs)", description: "", cost_label: "Medium", est_duration_seconds: 120, available: true, availability_reason: null, last_run: null, last_status: null, last_count: 0 },
    { profile: "handles_basic", family: "handles", title: "Process handles", description: "", cost_label: "Medium", est_duration_seconds: 120, available: true, availability_reason: null, last_run: null, last_status: null, last_count: 0 },
    { profile: "kernel_basic", family: "kernel_modules", title: "Kernel modules", description: "", cost_label: "Medium", est_duration_seconds: 120, available: true, availability_reason: null, last_run: null, last_status: null, last_count: 0 },
    { profile: "suspicious_memory", family: "suspicious_regions", title: "Suspicious memory regions", description: "", cost_label: "Medium", est_duration_seconds: 120, available: true, availability_reason: null, last_run: null, last_status: null, last_count: 0 },
  ],
};

const partialCatalogue = {
  ...freshCatalogue,
  items: [
    { ...freshCatalogue.items[0], last_run: { id: "r-1" }, last_status: "completed" },
    { ...freshCatalogue.items[1], last_run: { id: "r-2" }, last_status: "completed" },
    { ...freshCatalogue.items[2], last_run: { id: "r-3" }, last_status: "failed" },
    { ...freshCatalogue.items[3], last_status: null },
    { ...freshCatalogue.items[4], last_status: null },
    { ...freshCatalogue.items[5], last_status: null },
  ],
};

const completedCatalogue = {
  ...freshCatalogue,
  items: freshCatalogue.items.map((i) => ({ ...i, last_run: { id: `r-${i.profile}` }, last_status: "completed" })),
};

const renderModal = (props: any) => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryAnalysisCatalogueModal {...props} />
    </QueryClientProvider>,
  );
};

const baseProps = {
  caseId: CASE,
  evidenceId: EVIDENCE,
  evidenceFilename: "WS01-20240322-125737.dmp",
  evidenceHost: "WS01",
  evidenceSizeBytes: 4_255_346_688,
  catalogue: freshCatalogue,
  volatilityBackend: "windows",
  canRun: true,
  readinessReady: true,
  onClose: vi.fn(),
};

describe("First analysis simplification v1", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (api.startMemoryRunAll as ReturnType<typeof vi.fn>).mockResolvedValue({
      batch_id: "b-1",
      state: "queued",
      total_profiles: 6,
      queued_profiles: 6,
    } as any);
  });

  it("1) fresh evidence (no runs) shows the first-analysis view with no radios", async () => {
    renderModal(baseProps);
    // No radios should be present.
    const radios = document.querySelectorAll('input[type="radio"]');
    expect(radios.length).toBe(0);
    // The first-analysis view should show a "Start full memory analysis" button.
    const startButton = await screen.findByRole("button", { name: /Start full memory analysis/i });
    expect(startButton).toBeInTheDocument();
  });

  it("2) the first-analysis view shows Included and Skipped lists", async () => {
    renderModal(baseProps);
    expect(await screen.findByText(/Included/i)).toBeInTheDocument();
    expect(await screen.findByText(/Skipped/i)).toBeInTheDocument();
    expect(await screen.findByText(/System metadata/i)).toBeInTheDocument();
    expect(await screen.findByText(/Standard process analysis/i)).toBeInTheDocument();
  });

  it("3) the partial view shows a primary 'Run missing or failed profiles' button", async () => {
    renderModal({ ...baseProps, catalogue: partialCatalogue });
    const button = await screen.findByRole("button", { name: /Run missing or failed profiles/i });
    expect(button).toBeInTheDocument();
  });

  it("4) the partial view calls startMemoryRunAll with mode missing_or_failed", async () => {
    renderModal({ ...baseProps, catalogue: partialCatalogue });
    const button = await screen.findByRole("button", { name: /Run missing or failed profiles/i });
    fireEvent.click(button);
    await waitFor(() => {
      expect(api.startMemoryRunAll).toHaveBeenCalledWith(
        CASE,
        EVIDENCE,
        expect.objectContaining({ mode: "missing_or_failed" }),
      );
    });
  });

  it("5) the completed view shows a primary 'Re-run analysis' button", async () => {
    renderModal({ ...baseProps, catalogue: completedCatalogue });
    const button = await screen.findByRole("button", { name: /Re-run analysis/i });
    expect(button).toBeInTheDocument();
  });

  it("6) the completed view does NOT show a Start full memory analysis button", async () => {
    renderModal({ ...baseProps, catalogue: completedCatalogue });
    await screen.findByRole("button", { name: /Re-run analysis/i });
    expect(screen.queryByRole("button", { name: /Start full memory analysis/i })).toBeNull();
  });
});

describe("Header label v1", () => {
  const makeEvidence = () => ({
    evidence_id: EVIDENCE,
    case_id: CASE,
    filename: "WS01-20240322-125737.dmp",
    detected_host: "WS01",
    size_bytes: 4_255_346_688,
    created_at: "2024-03-22T12:00:00Z",
    processed_at: "2024-03-22T12:01:00Z",
    ingest_status: "completed",
    metadata: {},
    families: [],
    run_count: 0,
    latest_run_id: null,
    latest_run_status: null,
    detection_status: "ok",
    detected_format: "windows_memory",
    detection_confidence: "high",
    detection_reason: null,
    operator_override: false,
    operator_override_reason: null,
    operator_override_at: null,
    probe_version: "v1",
    probed_at: "2024-03-22T12:00:00Z",
    can_analyze: true,
  });

  it("7) fresh evidence header label is 'Analyze memory'", async () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } } });
    render(
      <MemoryRouter>
        <QueryClientProvider client={qc}>
          <MemoryEvidenceHeader
            caseId={CASE}
            evidence={makeEvidence()}
            activeResult={null}
            family="processes"
            historicalRunId={null}
            onViewHistory={vi.fn()}
            onReturnToLatest={vi.fn()}
            onOpenCatalogue={vi.fn()}
            symbolPreparation={null}
            catalogue={freshCatalogue}
          />
        </QueryClientProvider>
      </MemoryRouter>,
    );
    expect(await screen.findByText(/Analyze memory/)).toBeInTheDocument();
  });

  it("8) completed evidence header label is 'Re-run analysis'", async () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } } });
    render(
      <MemoryRouter>
        <QueryClientProvider client={qc}>
          <MemoryEvidenceHeader
            caseId={CASE}
            evidence={makeEvidence()}
            activeResult={null}
            family="processes"
            historicalRunId={null}
            onViewHistory={vi.fn()}
            onReturnToLatest={vi.fn()}
            onOpenCatalogue={vi.fn()}
            symbolPreparation={null}
            catalogue={completedCatalogue}
          />
        </QueryClientProvider>
      </MemoryRouter>,
    );
    expect(await screen.findByText(/Re-run analysis/)).toBeInTheDocument();
  });
});
