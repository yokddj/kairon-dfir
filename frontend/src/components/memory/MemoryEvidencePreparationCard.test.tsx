/** @vitest-environment jsdom */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api, type MemoryEvidencePreparation } from "../../api/client";
import { MemoryEvidencePreparationCard } from "./MemoryEvidencePreparationCard";

const getMemoryEvidencePreparationMock = vi.fn();
const getLinuxSymbolRequirementMock = vi.fn();
const validateLinuxEvidenceSymbolsMock = vi.fn();
const getLinuxSymbolValidationStatusMock = vi.fn();
const attachVmwareCompanionMock = vi.fn();
const deleteVmwareCompanionMock = vi.fn();

vi.mock("../../api/client", () => ({
  api: {
    getMemoryEvidencePreparation: (...args: unknown[]) => getMemoryEvidencePreparationMock(...args),
    getLinuxSymbolRequirement: (...args: unknown[]) => getLinuxSymbolRequirementMock(...args),
    validateLinuxEvidenceSymbols: (...args: unknown[]) => validateLinuxEvidenceSymbolsMock(...args),
    getLinuxSymbolValidationStatus: (...args: unknown[]) => getLinuxSymbolValidationStatusMock(...args),
    attachVmwareCompanion: (...args: unknown[]) => attachVmwareCompanionMock(...args),
    deleteVmwareCompanion: (...args: unknown[]) => deleteVmwareCompanionMock(...args),
  },
}));

const CASE = "case-1";
const EVIDENCE = "ev-1";

function preparation(overrides: Partial<MemoryEvidencePreparation> = {}): MemoryEvidencePreparation {
  return {
    evidence_id: EVIDENCE,
    platform: "windows",
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

function renderCard() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryEvidencePreparationCard caseId={CASE} evidenceId={EVIDENCE} />
    </QueryClientProvider>,
  );
}

// The card renders an intermediate data-ui-state="loading" render while
// the query is in flight -- wait for the specific terminal state rather
// than the first element findByTestId happens to see.
async function waitForState(state: string) {
  await waitFor(() => expect(screen.getByTestId("memory-evidence-preparation-card").getAttribute("data-ui-state")).toBe(state));
  return screen.getByTestId("memory-evidence-preparation-card");
}

describe("MemoryEvidencePreparationCard (Phase 2, read-only)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getLinuxSymbolRequirementMock.mockResolvedValue({ expected_identity: null });
  });

  it("fetches from the Phase 1/2 endpoint scoped to case and evidence", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(preparation());
    renderCard();
    await waitFor(() => expect(getMemoryEvidencePreparationMock).toHaveBeenCalledWith(CASE, EVIDENCE));
  });

  it("READY: shows the exact required copy and good tone", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(preparation({ readiness: "ready", can_start_analysis: true }));
    renderCard();
    await waitForState("ready");
    expect(screen.getByTestId("memory-evidence-preparation-status")).toHaveTextContent("✓ Ready for analysis");
  });

  it("SYMBOLS_REQUIRED: shows the exact required copy", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(
      preparation({ readiness: "symbols_required", can_start_analysis: false, requires_symbols: true }),
    );
    renderCard();
    await waitForState("symbols_required");
    expect(screen.getByTestId("memory-evidence-preparation-status")).toHaveTextContent(
      "⚠ Additional resources are required before analysis can begin.",
    );
  });

  it("AWAITING_USER: shows the exact required copy", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(
      preparation({ readiness: "awaiting_user", can_start_analysis: false, platform: "unknown", architecture: "unknown" }),
    );
    renderCard();
    await waitForState("awaiting_user");
    expect(screen.getByTestId("memory-evidence-preparation-status")).toHaveTextContent("User confirmation required.");
  });

  it("BLOCKED: shows the exact required copy", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(
      preparation({ readiness: "blocked", can_start_analysis: false }),
    );
    renderCard();
    await waitForState("blocked");
    expect(screen.getByTestId("memory-evidence-preparation-status")).toHaveTextContent("Preparation cannot continue.");
  });

  it("FAILED: shows the exact required copy", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(
      preparation({ readiness: "failed", can_start_analysis: false }),
    );
    renderCard();
    await waitForState("failed");
    expect(screen.getByTestId("memory-evidence-preparation-status")).toHaveTextContent("Preparation failed.");
  });

  it("INSPECTING: shows the exact required copy", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(
      preparation({ readiness: "inspecting", can_start_analysis: false, platform: "unknown", architecture: "unknown" }),
    );
    renderCard();
    await waitForState("inspecting");
    expect(screen.getByTestId("memory-evidence-preparation-status")).toHaveTextContent("Inspecting memory...");
  });

  it("shows platform, architecture, requires_symbols and the human message", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(
      preparation({
        platform: "linux",
        architecture: "x64",
        readiness: "symbols_required",
        requires_symbols: true,
        can_start_analysis: false,
        human_message: "This Linux dump requires Volatility symbols (ISF) Kairon does not currently have.",
      }),
    );
    renderCard();
    const card = await waitForState("symbols_required");
    expect(card).toHaveTextContent("Linux");
    expect(card).toHaveTextContent("X64");
    expect(card).toHaveTextContent("Not ready yet");
    expect(card).toHaveTextContent("Yes");
    expect(screen.getByTestId("memory-evidence-preparation-message")).toHaveTextContent(
      "This Linux dump requires Volatility symbols (ISF) Kairon does not currently have.",
    );
  });

  it("shows 'Ready to analyze' and 'No' when analysis can start without symbols", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(
      preparation({ readiness: "ready", can_start_analysis: true, requires_symbols: false }),
    );
    renderCard();
    const card = await waitForState("ready");
    expect(card).toHaveTextContent("Ready to analyze");
  });

  it("renders no action buttons at all -- this is a read-only view", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(preparation({ readiness: "symbols_required" }));
    renderCard();
    await waitForState("symbols_required");
    expect(screen.queryAllByRole("button")).toHaveLength(0);
  });

  it("shows a neutral unavailable message when the fetch fails, without a retry button", async () => {
    getMemoryEvidencePreparationMock.mockRejectedValue(new Error("network error"));
    renderCard();
    const card = await waitForState("unavailable");
    expect(card).toHaveTextContent(/not available/i);
    expect(screen.queryAllByRole("button")).toHaveLength(0);
  });
});

describe("MemoryEvidencePreparationCard + Linux symbol upload (Phase 3)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getLinuxSymbolRequirementMock.mockResolvedValue({ expected_identity: null });
  });

  it("shows the Linux symbol upload panel when platform is linux and readiness is symbols_required", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(
      preparation({ platform: "linux", readiness: "symbols_required", can_start_analysis: false }),
    );
    renderCard();
    await waitForState("symbols_required");
    expect(await screen.findByTestId("linux-symbol-upload-panel")).toBeInTheDocument();
  });

  it("never shows the panel for Windows evidence, even when symbols_required", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(
      preparation({ platform: "windows", readiness: "symbols_required", can_start_analysis: false }),
    );
    renderCard();
    await waitForState("symbols_required");
    expect(screen.queryByTestId("linux-symbol-upload-panel")).not.toBeInTheDocument();
  });

  it("never shows the panel for Linux evidence that is already READY (cached symbols) -- no uploader for available symbols", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(
      preparation({ platform: "linux", readiness: "ready", can_start_analysis: true }),
    );
    renderCard();
    await waitForState("ready");
    expect(screen.queryByTestId("linux-symbol-upload-panel")).not.toBeInTheDocument();
  });

  it("never shows the panel for Linux evidence in any other non-symbols_required state", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(
      preparation({ platform: "linux", readiness: "inspecting", can_start_analysis: false }),
    );
    renderCard();
    await waitForState("inspecting");
    expect(screen.queryByTestId("linux-symbol-upload-panel")).not.toBeInTheDocument();
  });

  it("a successful VALID validation refetches preparation and the card flips to READY without a manual reload", async () => {
    getMemoryEvidencePreparationMock
      .mockResolvedValueOnce(preparation({ platform: "linux", readiness: "symbols_required", can_start_analysis: false }))
      .mockResolvedValueOnce(preparation({ platform: "linux", readiness: "ready", can_start_analysis: true, human_message: "Compatible Linux symbols are already available." }));
    validateLinuxEvidenceSymbolsMock.mockResolvedValue({ validation_id: "val-1", status: "queued" });
    getLinuxSymbolValidationStatusMock.mockResolvedValue({
      status: "valid",
      expected_identity: { kernel_release: "6.8.0-test", architecture: "x64", banner: null, build_id: "build-a" },
      detected_identity: { kernel_release: "6.8.0-test", architecture: "x64", banner: null, build_id: "build-a" },
      compatible: true,
      reason: "",
      cached: false,
      cache_key: "abc123",
    });

    renderCard();
    await waitForState("symbols_required");
    const input = screen.getByTestId("linux-symbol-file-input");
    await userEvent.upload(input, new File(["{}"], "kernel.json"));
    await userEvent.click(screen.getByTestId("linux-symbol-validate-button"));

    // The enqueue call succeeding starts polling; the terminal VALID status
    // triggers onValidated -> invalidateQueries, which refetches preparation
    // a second time (no manual reload) and the card settles on READY, with
    // the Linux panel no longer shown.
    await waitFor(() => expect(validateLinuxEvidenceSymbolsMock).toHaveBeenCalled());
    await waitFor(() => expect(getLinuxSymbolValidationStatusMock).toHaveBeenCalled());
    await waitFor(() => expect(getMemoryEvidencePreparationMock).toHaveBeenCalledTimes(2), { timeout: 5000 });
    await waitForState("ready");
    expect(screen.queryByTestId("linux-symbol-upload-panel")).not.toBeInTheDocument();
  });
});

describe("MemoryEvidencePreparationCard + VMware companion (Phase 2)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getLinuxSymbolRequirementMock.mockResolvedValue({ expected_identity: null });
  });

  it("does not render the VMware section for evidence with no VMware signal", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(preparation());
    renderCard();
    await waitForState("ready");
    expect(screen.queryByTestId("vmware-companion-section")).not.toBeInTheDocument();
  });

  it("shows the VMware section, not-provided, when recommended -- platform-agnostic, unlike the Linux symbol panel", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(
      preparation({ platform: "windows", vmware_companion_recommended: true, vmware_companion_warning: "A matching .vmsn or .vmss file may be required for reliable analysis." }),
    );
    renderCard();
    await waitForState("ready");
    expect(await screen.findByTestId("vmware-companion-not-provided")).toBeInTheDocument();
  });

  it("shows Associated when a companion is already attached", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(
      preparation({
        has_vmware_companion: true,
        vmware_companion_id: "companion-1",
        vmware_companion_type: "vmware_vmsn",
        vmware_companion_filename: "memory.vmsn",
        vmware_companion_sha256: "a".repeat(64),
        vmware_companion_size_bytes: 1024,
      }),
    );
    renderCard();
    await waitForState("ready");
    expect(await screen.findByTestId("vmware-companion-associated")).toHaveTextContent("Associated");
  });

  it("a successful attach refetches preparation and the section flips to Associated without a manual reload", async () => {
    getMemoryEvidencePreparationMock
      .mockResolvedValueOnce(preparation({ vmware_companion_recommended: true }))
      .mockResolvedValueOnce(
        preparation({
          has_vmware_companion: true,
          vmware_companion_id: "companion-1",
          vmware_companion_type: "vmware_vmsn",
          vmware_companion_filename: "memory.vmsn",
          vmware_companion_sha256: "a".repeat(64),
          vmware_companion_size_bytes: 2048,
        }),
      );
    attachVmwareCompanionMock.mockResolvedValue({ id: "companion-1", companion_type: "vmware_vmsn" });

    renderCard();
    await waitForState("ready");
    await userEvent.click(await screen.findByTestId("vmware-companion-add-button"));
    await userEvent.upload(screen.getByTestId("vmware-companion-file-input"), new File(["x"], "memory.vmsn"));
    await userEvent.click(screen.getByTestId("vmware-companion-attach-button"));

    await waitFor(() => expect(getMemoryEvidencePreparationMock).toHaveBeenCalledTimes(2), { timeout: 5000 });
    expect(await screen.findByTestId("vmware-companion-associated")).toBeInTheDocument();
  });

  it("does not block the READY/can_start_analysis state shown alongside it", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(
      preparation({ readiness: "ready", can_start_analysis: true, vmware_companion_recommended: true }),
    );
    renderCard();
    const card = await waitForState("ready");
    expect(card).toHaveTextContent("Ready to analyze");
    expect(screen.getByTestId("memory-evidence-preparation-status")).toHaveTextContent("✓ Ready for analysis");
  });
});

describe("MemoryEvidencePreparationCard + zero-result warning (Phase 2)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getLinuxSymbolRequirementMock.mockResolvedValue({ expected_identity: null });
  });

  it("shows nothing when there is no zero-result warning", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(preparation());
    renderCard();
    await waitForState("ready");
    expect(screen.queryByTestId("zero-result-warning-banner")).not.toBeInTheDocument();
  });

  it("shows 'Completed with warning' with the plugin and message, never as a failure", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(
      preparation({
        zero_result_warning_code: "VMWARE_METADATA_MAY_BE_REQUIRED",
        zero_result_warning_message: "Volatility reported that VMware snapshot metadata (.vmsn/.vmss) may be required to fully process this memory image.",
        zero_result_warning_plugin: "linux.pslist",
      }),
    );
    renderCard();
    await waitForState("ready");

    const banner = await screen.findByTestId("zero-result-warning-banner");
    expect(banner).toHaveTextContent("Completed with warning");
    expect(banner).toHaveTextContent("0 results recovered");
    expect(banner).toHaveTextContent("linux.pslist");
    expect(banner).toHaveTextContent("may be required to fully process this memory image");
    expect(screen.getByTestId("zero-result-warning-cta")).toHaveTextContent("Add VMware metadata");
  });

  it("the CTA scrolls to the VmwareCompanionSection rather than opening a second flow", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue(
      preparation({
        vmware_companion_recommended: true,
        vmware_companion_warning: "A matching .vmsn or .vmss file may be required for reliable analysis.",
        zero_result_warning_code: "VMWARE_METADATA_MAY_BE_REQUIRED",
        zero_result_warning_message: "Volatility reported that VMware snapshot metadata may be required.",
        zero_result_warning_plugin: "linux.pslist",
      }),
    );
    renderCard();
    await waitForState("ready");
    const section = await screen.findByTestId("vmware-companion-section");
    const scrollSpy = vi.fn();
    section.scrollIntoView = scrollSpy;

    await userEvent.click(screen.getByTestId("zero-result-warning-cta"));

    expect(scrollSpy).toHaveBeenCalledTimes(1);
  });
});
