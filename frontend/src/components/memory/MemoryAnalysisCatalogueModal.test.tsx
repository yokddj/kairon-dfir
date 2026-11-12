/** @vitest-environment jsdom */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { api } from "../../api/client";
import { MemoryAnalysisCatalogueModal } from "./MemoryAnalysisCatalogueModal";

vi.mock("../../api/client", () => ({
  api: {
    startMemoryScan: vi.fn(async () => ({ accepted: true, evidence_id: "ev-1", status: "queued", message: "queued" })),
    startMemoryRunAll: vi.fn(),
    getMemProcFSScan: vi.fn(async () => ({ exists: false, files: [], notices: [] })),
  },
}));

const item = (profile: string, extra: Record<string, unknown>) => ({
  profile, family: profile, title: profile, description: "", cost_label: "Medium", est_duration_seconds: 60, available: true, availability_reason: null,
  last_run: { id: `r-${profile}` }, last_status: "completed", last_count: 1, volatility_on_request: true, ...extra,
});

const catalogue = {
  case_id: "case-1",
  evidence_id: "ev-1",
  items: [
    item("metadata_only", { engine: "memprocfs" }),
    item("processes_extended", { engine: "memprocfs", volatility_extras: ["windows.psscan"] }),
    item("suspicious_memory", { engine: "volatility", volatility_only: true }),
  ],
};

function renderModal(extra: Record<string, unknown> = {}) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={qc}>
        <MemoryAnalysisCatalogueModal caseId="case-1" evidenceId="ev-1" evidenceFilename="m.dd" evidenceHost="H" evidenceSizeBytes={1} catalogue={catalogue as never} volatilityBackend={null as never} canRun onClose={vi.fn()} {...extra} />
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("engine choice in the analysis catalogue (Windows)", () => {
  it("runs on MemProcFS by default and asks for Volatility only on request", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    renderModal();
    fireEvent.click(await screen.findByTestId("memory-completed-advanced"));
    expect(await screen.findByTestId("catalogue-engine-processes_extended")).toHaveTextContent("MemProcFS");
    expect(screen.getByTestId("catalogue-engine-note-processes_extended")).toHaveTextContent("pool scan");
    expect(screen.getByTestId("catalogue-engine-note-suspicious_memory")).toHaveTextContent("Only Volatility");

    fireEvent.click(screen.getByTestId("memory-catalogue-run-processes_extended"));
    await waitFor(() => expect(api.startMemoryScan).toHaveBeenLastCalledWith("case-1", "ev-1", "processes_extended", undefined, false));
    fireEvent.click(screen.getByTestId("memory-catalogue-run-volatility-processes_extended"));
    await waitFor(() => expect(api.startMemoryScan).toHaveBeenLastCalledWith("case-1", "ev-1", "processes_extended", "volatility", false));
    fireEvent.click(screen.getByTestId("memory-catalogue-run-suspicious_memory"));
    await waitFor(() => expect(api.startMemoryScan).toHaveBeenLastCalledWith("case-1", "ev-1", "suspicious_memory", "volatility", false));
  });
});

describe("a new MemProcFS scan from the analysis catalogue", () => {
  const saved = { exists: true, scanned_at: "2026-11-12T13:14:37Z", yara_rules: false, files: [], notices: ["yara_rules_missing"], total_bytes: 0 };

  it("offers it only when the image has a saved scan, unticked", async () => {
    renderModal();
    await screen.findByTestId("memory-completed-advanced");
    expect(screen.queryByTestId("memprocfs-rescan-option")).not.toBeInTheDocument();
  });

  it("asks a MemProcFS analysis for a new scan when ticked, never a Volatility one", async () => {
    vi.mocked(api.getMemProcFSScan).mockResolvedValue(saved as never);
    vi.spyOn(window, "confirm").mockReturnValue(true);
    renderModal();
    const checkbox = (await screen.findByTestId("memprocfs-rescan-checkbox")) as HTMLInputElement;
    expect(checkbox.checked).toBe(false);
    expect(screen.getByTestId("memprocfs-rescan-option")).toHaveTextContent("made without the YARA rules");
    fireEvent.click(checkbox);
    fireEvent.click(await screen.findByTestId("memory-completed-advanced"));
    fireEvent.click(await screen.findByTestId("memory-catalogue-run-processes_extended"));
    await waitFor(() => expect(api.startMemoryScan).toHaveBeenLastCalledWith("case-1", "ev-1", "processes_extended", undefined, true));
    fireEvent.click(screen.getByTestId("memory-catalogue-run-volatility-processes_extended"));
    await waitFor(() => expect(api.startMemoryScan).toHaveBeenLastCalledWith("case-1", "ev-1", "processes_extended", "volatility", false));
  });

  it("opens ticked when the MemProcFS tab asked for a new scan", async () => {
    vi.mocked(api.getMemProcFSScan).mockResolvedValue(saved as never);
    renderModal({ initialRescan: true });
    expect(((await screen.findByTestId("memprocfs-rescan-checkbox")) as HTMLInputElement).checked).toBe(true);
  });
});
