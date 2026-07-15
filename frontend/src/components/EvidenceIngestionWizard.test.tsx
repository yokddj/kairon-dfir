import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import EvidenceIngestionWizard from "./EvidenceIngestionWizard";
import type { PreflightReport } from "../api/client";

const preflightEvidenceMock = vi.fn();
const uploadEvidenceMock = vi.fn();
const uploadDiskImageMock = vi.fn();
const uploadEvidenceFolderMock = vi.fn();
const registerEvidencePathMock = vi.fn();
const getCaseHostsMock = vi.fn();
const createCaseHostMock = vi.fn();

vi.mock("../api/client", () => ({
  api: {
    preflightEvidence: (...args: unknown[]) => preflightEvidenceMock(...args),
    uploadEvidence: (...args: unknown[]) => uploadEvidenceMock(...args),
    uploadDiskImage: (...args: unknown[]) => uploadDiskImageMock(...args),
    uploadEvidenceFolder: (...args: unknown[]) => uploadEvidenceFolderMock(...args),
    registerEvidencePath: (...args: unknown[]) => registerEvidencePathMock(...args),
    getCaseHosts: (...args: unknown[]) => getCaseHostsMock(...args),
    createCaseHost: (...args: unknown[]) => createCaseHostMock(...args),
  },
}));

const notifyMock = vi.fn();
vi.mock("../context/NotificationsContext", () => ({
  useNotifications: () => ({ notify: notifyMock }),
}));

function readyReport(overrides: Partial<PreflightReport> = {}): PreflightReport {
  return {
    token: "tok-1",
    original_filename: "collection.zip",
    classification: {
      category: "archive",
      format_key: "archive",
      confidence: "high",
      reason: "Detected archive container: .zip",
      chain: ["Archive"],
      platform: "linux",
      hostname: "web01",
      distro: "Ubuntu 24.04 LTS",
      version: null,
      volumes: null,
      installations: null,
      expected_parsers: ["linux auth", "linux cron", "linux ssh"],
      warnings: [],
    },
    pipeline_preview: ["Archive", "Evidence Classification", "Linux Discovery", "Artifact Discovery", "Normalization", "Indexing", "Search", "Timeline"],
    resource_check: {
      file_size_bytes: 4200,
      compressed_size_bytes: 4200,
      estimated_extracted_bytes: 3300,
      estimated_temp_storage_bytes: 3300,
      estimated_final_size_bytes: 3300,
      estimated_processing_seconds: 30,
      estimated_artifact_count: 3,
      detected_archive_depth: 1,
      detected_backing_chain_depth: null,
      available_disk_space_bytes: 5_000_000_000,
      configured_upload_limit_bytes: 2_000_000_000,
      configured_extraction_limit_bytes: 10_000_000_000,
      configured_archive_depth_limit: 5,
      configured_backing_chain_limit: 3,
      temp_directory: "/app/data/tmp",
    },
    status: "ready",
    status_checks: [
      { label: "Supported", ok: true, detail: "Detected archive container: .zip" },
      { label: "Within upload limit", ok: true, detail: "4.1 KB of 1.9 GB allowed" },
      { label: "Enough storage", ok: true, detail: "4.7 GB available, ~3.8 KB needed" },
    ],
    diagnostics: [],
    ...overrides,
  };
}

function renderWizard(props: Partial<React.ComponentProps<typeof EvidenceIngestionWizard>> = {}) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  const onClose = vi.fn();
  render(
    <MemoryRouter>
      <QueryClientProvider client={queryClient}>
        <EvidenceIngestionWizard open caseId="case-1" onClose={onClose} {...props} />
      </QueryClientProvider>
    </MemoryRouter>,
  );
  return { onClose };
}

async function goToFileStep(cardName: RegExp) {
  await userEvent.click(screen.getByRole("button", { name: cardName }));
  await userEvent.click(screen.getByRole("button", { name: "Continue" })); // platform
  await userEvent.click(screen.getByRole("button", { name: "Continue" })); // host
}

describe("EvidenceIngestionWizard", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getCaseHostsMock.mockResolvedValue({ hosts: [{ id: "host-1", display_name: "WS-01" }] });
    preflightEvidenceMock.mockResolvedValue(readyReport());
  });

  it("navigates forward and back through steps", async () => {
    renderWizard();
    expect(screen.getByText("What are you adding?")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: /Artifact Collection/ }));
    expect(await screen.findByText("Platform")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Back" }));
    expect(await screen.findByText("What are you adding?")).toBeInTheDocument();
  });

  it("cancel closes the wizard", async () => {
    const { onClose } = renderWizard();
    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(onClose).toHaveBeenCalled();
  });

  it("defaults platform to Auto Detect (recommended)", async () => {
    renderWizard();
    await userEvent.click(screen.getByRole("button", { name: /Artifact Collection/ }));
    const autoCard = await screen.findByRole("button", { name: /Auto-detect \(Recommended\)/ });
    expect(autoCard.className).toContain("border-accent");
  });

  it("runs preflight and shows classification + pipeline preview", async () => {
    renderWizard();
    await goToFileStep(/Artifact Collection/);

    const file = new File(["zip-bytes"], "collection.zip", { type: "application/zip" });
    const input = screen.getByLabelText(/Select a file/i, { exact: false }) || document.querySelector('input[type="file"]');
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, file);
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));

    const report = await screen.findByTestId("preflight-report");
    expect(within(report).getByText(/web01/)).toBeInTheDocument();
    expect(within(report).getByText(/Archive → Evidence Classification → Linux Discovery/)).toBeInTheDocument();
    expect(within(report).getByText("Ready to process")).toBeInTheDocument();
    expect(preflightEvidenceMock).toHaveBeenCalledWith("case-1", { file }, { declaredPlatform: "auto" });
  });

  it("shows blocking diagnostics and requires manual override to continue", async () => {
    preflightEvidenceMock.mockResolvedValue(readyReport({
      status: "blocked",
      status_checks: [{ label: "Supported", ok: false, detail: "We could not confidently determine the evidence type." }],
      diagnostics: [{
        problem: "Low confidence classification",
        reason: "We could not confidently determine the evidence type. You can continue with a manual override.",
        current_configuration: {},
        required_configuration: {},
        configuration_key: null,
        configuration_file: null,
        how_to_fix: ["Use the Advanced options override to set platform/classification manually"],
      }],
    }));
    renderWizard();
    await goToFileStep(/Artifact Collection/);
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, new File(["x"], "mystery.bin"));
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));

    await screen.findByTestId("preflight-report");
    expect(screen.getByText("Low confidence classification")).toBeInTheDocument();
    const continueButton = screen.getByRole("button", { name: "Continue" });
    expect(continueButton).toBeDisabled();

    await userEvent.click(screen.getByRole("checkbox", { name: /Continue with a manual override/i }));
    expect(continueButton).toBeEnabled();
  });

  it("shows a diagnostic with configuration guidance for a disk-full / storage warning", async () => {
    preflightEvidenceMock.mockResolvedValue(readyReport({
      status: "blocked",
      status_checks: [{ label: "Enough storage", ok: false, detail: "10 B available, ~5.0 GB needed" }],
      diagnostics: [{
        problem: "Temporary storage too low",
        reason: "Processing this evidence needs approximately 5.0 GB of free space in the temp directory, but only 10 B is available.",
        current_configuration: { available: "10 B", temp_directory: "/app/data/tmp" },
        required_configuration: { available: "5.0 GB" },
        configuration_key: "BACKEND_TEMP_DIR",
        configuration_file: "backend/.env",
        how_to_fix: ["Free space on the temp directory's volume", "Or move BACKEND_TEMP_DIR to a volume with more free space", "Restart the backend after changing BACKEND_TEMP_DIR"],
      }],
    }));
    renderWizard();
    await goToFileStep(/Disk Image/);
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, new File(["x"], "disk.E01"));
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));

    await screen.findByTestId("preflight-report");
    expect(screen.getByText("Temporary storage too low")).toBeInTheDocument();
    expect(screen.getByText("BACKEND_TEMP_DIR")).toBeInTheDocument();
    expect(screen.getByText(/backend\/\.env/)).toBeInTheDocument();
  });

  it("disk image flow calls uploadDiskImage on Start Processing", async () => {
    uploadDiskImageMock.mockResolvedValue({ id: "evidence-1", original_filename: "disk.E01" });
    renderWizard();
    await goToFileStep(/Disk Image/);
    const file = new File(["x"], "disk.E01");
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, file);
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));
    await screen.findByTestId("preflight-report");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));

    await screen.findByText("Confirmation");
    await userEvent.click(screen.getByRole("button", { name: "Start Processing" }));

    await waitFor(() => expect(uploadDiskImageMock).toHaveBeenCalledWith("case-1", [file], expect.objectContaining({})));
  });

  it("artifact collection flow calls uploadEvidence on Start Processing", async () => {
    uploadEvidenceMock.mockResolvedValue({ id: "evidence-2", original_filename: "collection.zip" });
    renderWizard();
    await goToFileStep(/Artifact Collection/);
    const file = new File(["x"], "collection.zip");
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, file);
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));
    await screen.findByTestId("preflight-report");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));

    await screen.findByText("Confirmation");
    await userEvent.click(screen.getByRole("button", { name: "Start Processing" }));

    await waitFor(() => expect(uploadEvidenceMock).toHaveBeenCalledWith("case-1", file, expect.objectContaining({ evidenceIntent: "raw" })));
  });

  it("lets the analyst assign an existing host before continuing", async () => {
    renderWizard();
    await userEvent.click(screen.getByRole("button", { name: /Artifact Collection/ }));
    await userEvent.click(screen.getByRole("button", { name: "Continue" })); // platform -> host step

    await screen.findByText("Host");
    await userEvent.click(screen.getByRole("radio", { name: "Assign existing host" }));
    expect(screen.getByRole("option", { name: "WS-01" })).toBeInTheDocument();
  });

  it("folder flow calls uploadEvidenceFolder on Start Processing", async () => {
    uploadEvidenceFolderMock.mockResolvedValue({ id: "evidence-4", original_filename: "3 files" });
    preflightEvidenceMock.mockResolvedValue(readyReport({ pipeline_preview: ["Folder", "Evidence Classification", "Linux Discovery", "Artifact Discovery", "Normalization", "Indexing", "Search", "Timeline"] }));
    renderWizard();
    await goToFileStep(/Folder/);
    const files = [new File(["a"], "a.log"), new File(["b"], "b.log")];
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, files);
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));
    await screen.findByTestId("preflight-report");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));

    await screen.findByText("Confirmation");
    await userEvent.click(screen.getByRole("button", { name: "Start Processing" }));

    await waitFor(() => expect(uploadEvidenceFolderMock).toHaveBeenCalledWith("case-1", files, expect.objectContaining({})));
  });

  it("server path flow calls registerEvidencePath on Start Processing", async () => {
    registerEvidencePathMock.mockResolvedValue({ id: "evidence-5", original_filename: "disk.E01" });
    renderWizard();
    await goToFileStep(/Existing Server Path/);
    await userEvent.type(screen.getByLabelText(/Server path/i), "/mnt/evidence/disk.E01");
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));
    await screen.findByTestId("preflight-report");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));

    await screen.findByText("Confirmation");
    await userEvent.click(screen.getByRole("button", { name: "Start Processing" }));

    await waitFor(() => expect(registerEvidencePathMock).toHaveBeenCalledWith("case-1", expect.objectContaining({ path: "/mnt/evidence/disk.E01", start_ingest: true })));
    expect(preflightEvidenceMock).toHaveBeenCalledWith("case-1", { serverPath: "/mnt/evidence/disk.E01" }, { declaredPlatform: "auto" });
  });

  it("memory flow requires authorization acknowledgement before Start Processing is enabled", async () => {
    uploadEvidenceMock.mockResolvedValue({ id: "evidence-3", original_filename: "capture.mem" });
    preflightEvidenceMock.mockResolvedValue(readyReport({ original_filename: "capture.mem", pipeline_preview: ["Memory Dump", "Evidence Classification", "Memory Registration", "Memory Analysis (manual, after ingestion)"] }));
    renderWizard();
    await goToFileStep(/Memory Dump/);
    const file = new File(["x"], "capture.mem");
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, file);
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));
    await screen.findByTestId("preflight-report");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));

    await screen.findByText("Confirmation");
    const startButton = screen.getByRole("button", { name: "Start Processing" });
    expect(startButton).toBeDisabled();

    await userEvent.click(screen.getByRole("checkbox", { name: /authorized to handle this RAM evidence/i }));
    expect(startButton).toBeEnabled();

    await userEvent.click(startButton);
    await waitFor(() => expect(uploadEvidenceMock).toHaveBeenCalledWith("case-1", file, expect.objectContaining({ memoryAuthorizationAcknowledged: true })));
  });
});
