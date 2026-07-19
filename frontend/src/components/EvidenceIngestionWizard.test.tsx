import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import EvidenceIngestionWizard from "./EvidenceIngestionWizard";
import type { EvidenceUploadSessionCreateResponse, IngestionReadiness, PreflightReport } from "../api/client";

const createEvidenceUploadSessionMock = vi.fn();
const promoteEvidenceUploadSessionMock = vi.fn();
const runEvidenceIndexingPlanMock = vi.fn();
const cancelEvidenceUploadSessionMock = vi.fn();
const rerunEvidenceUploadPreflightMock = vi.fn();
const getIngestionReadinessMock = vi.fn();
const getCaseHostsMock = vi.fn();
const createCaseHostMock = vi.fn();
const navigateMock = vi.fn();

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return { ...actual, useNavigate: () => navigateMock };
});

vi.mock("../api/client", () => ({
  api: {
    createEvidenceUploadSession: (...args: unknown[]) => createEvidenceUploadSessionMock(...args),
    promoteEvidenceUploadSession: (...args: unknown[]) => promoteEvidenceUploadSessionMock(...args),
    runEvidenceIndexingPlan: (...args: unknown[]) => runEvidenceIndexingPlanMock(...args),
    cancelEvidenceUploadSession: (...args: unknown[]) => cancelEvidenceUploadSessionMock(...args),
    rerunEvidenceUploadPreflight: (...args: unknown[]) => rerunEvidenceUploadPreflightMock(...args),
    getIngestionReadiness: (...args: unknown[]) => getIngestionReadinessMock(...args),
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
      container: "ZIP archive",
      contained_object: "Ubuntu 24.04 LTS artifact collection (3 matched file(s))",
      platform: "linux",
      hostname: "web01",
      distro: "Ubuntu 24.04 LTS",
      version: null,
      volumes: null,
      partitions: null,
      filesystems: [],
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
      estimated_duration_bucket: "fast",
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
    evidence_options: [],
    ...overrides,
  };
}

function readyHealth(overrides: Partial<IngestionReadiness> = {}): IngestionReadiness {
  return {
    checks: [
      { label: "Storage", ok: true, detail: "100.0 GB available" },
      { label: "Search", ok: true, detail: "OpenSearch cluster status: green" },
      { label: "Database", ok: true, detail: "Reachable" },
      { label: "Workers", ok: true, detail: "Active worker(s) on the ingest/rules/analysis queues" },
      { label: "Memory Worker", ok: true, detail: "Active worker on the memory queue" },
    ],
    available_disk_space_bytes: 100_000_000_000,
    configured_upload_limit_bytes: 2_000_000_000,
    configured_extraction_limit_bytes: 10_000_000_000,
    ready: true,
    critical_ready: true,
    ...overrides,
  };
}

function sessionResponse(overrides: Partial<EvidenceUploadSessionCreateResponse> = {}): EvidenceUploadSessionCreateResponse {
  return {
    session: {
      id: "session-1",
      case_id: "case-1",
      status: "staged",
      original_filename: "collection.zip",
      is_folder: false,
      is_server_path: false,
      size_bytes: 4200,
      sha256: "a".repeat(64),
      client_sha256: null,
      client_sha256_mismatch: false,
      declared_platform: null,
      expires_at: new Date(Date.now() + 3600_000).toISOString(),
      created_at: new Date().toISOString(),
    },
    preflight: readyReport(),
    health: readyHealth(),
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

async function passHealthCheck() {
  await screen.findByTestId("health-check");
  const continueButton = await screen.findByRole("button", { name: "Continue" });
  await waitFor(() => expect(continueButton).toBeEnabled());
  await userEvent.click(continueButton);
}

async function goToFileStep(cardName: RegExp) {
  await passHealthCheck();
  await userEvent.click(screen.getByRole("button", { name: cardName }));
  await userEvent.click(screen.getByRole("button", { name: "Continue" })); // platform
  await userEvent.click(screen.getByRole("button", { name: "Continue" })); // host
}

describe("EvidenceIngestionWizard", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    navigateMock.mockReset();
    getCaseHostsMock.mockResolvedValue({ hosts: [{ id: "host-1", display_name: "WS-01" }] });
    getIngestionReadinessMock.mockResolvedValue(readyHealth());
    createEvidenceUploadSessionMock.mockResolvedValue(sessionResponse());
    runEvidenceIndexingPlanMock.mockResolvedValue({ accepted: true, evidence_id: "evidence-1", profile: "recommended", run_id: "plan-1", status: "queued", queued_jobs: [{ step_id: "linux_artifacts", run_id: "job-1", status: "queued" }], plan: { run_id: "plan-1", profile: "recommended", status: "queued", steps: [], excluded: [], queued_jobs: [] } });
    cancelEvidenceUploadSessionMock.mockResolvedValue({ status: "cancelled", session_id: "session-1" });
  });

  it("shows the server health check first and blocks continuing when a critical dependency is down", async () => {
    getIngestionReadinessMock.mockResolvedValue(readyHealth({
      critical_ready: false,
      ready: false,
      checks: [
        { label: "Storage", ok: false, detail: "Temp storage is not writable: OSError" },
        { label: "Search", ok: true, detail: "OpenSearch cluster status: green" },
        { label: "Database", ok: true, detail: "Reachable" },
        { label: "Workers", ok: true, detail: "Active worker(s)" },
        { label: "Memory Worker", ok: true, detail: "Active worker" },
      ],
    }));
    renderWizard();

    await screen.findByTestId("health-check");
    expect(await screen.findByText(/Temp storage is not writable/)).toBeInTheDocument();
    expect(screen.getByText(/Processing cannot begin/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Continue" })).toBeDisabled();
  });

  it("allows continuing past health check once critical dependencies are ready", async () => {
    renderWizard();
    await passHealthCheck();
    expect(await screen.findByText("What are you adding?")).toBeInTheDocument();
  });

  it("navigates forward and back through steps", async () => {
    renderWizard();
    await passHealthCheck();
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

  it("cancels the upload session on close after a session was created", async () => {
    const { onClose } = renderWizard();
    await goToFileStep(/Artifact Collection/);
    const file = new File(["zip-bytes"], "collection.zip", { type: "application/zip" });
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, file);
    await waitFor(() => expect(screen.queryByTestId("sha256-progress")).not.toBeInTheDocument());
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));
    await screen.findByTestId("preflight-report");

    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));

    expect(cancelEvidenceUploadSessionMock).toHaveBeenCalledWith("case-1", "session-1");
    expect(onClose).toHaveBeenCalled();
  });

  it("defaults platform to Auto Detect (recommended)", async () => {
    renderWizard();
    await passHealthCheck();
    await userEvent.click(screen.getByRole("button", { name: /Artifact Collection/ }));
    const autoCard = await screen.findByRole("button", { name: /Auto-detect \(Recommended\)/ });
    expect(autoCard.className).toContain("border-accent");
  });

  it("computes a client-side SHA-256 progressively after file selection and reuses it when inspecting", async () => {
    renderWizard();
    await goToFileStep(/Artifact Collection/);

    const file = new File(["zip-bytes"], "collection.zip", { type: "application/zip" });
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, file);

    await waitFor(() => expect(screen.getByTestId("sha256-ready")).toBeInTheDocument());
    expect(screen.getByTestId("sha256-ready").textContent).toMatch(/SHA-256: [0-9a-f]{64}/);

    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));
    await screen.findByTestId("preflight-report");

    expect(createEvidenceUploadSessionMock).toHaveBeenCalledWith(
      "case-1",
      { file },
      expect.objectContaining({ declaredPlatform: "auto", clientSha256: expect.stringMatching(/^[0-9a-f]{64}$/) }),
    );
  });

  it("runs preflight and shows the richer inspection report", async () => {
    renderWizard();
    await goToFileStep(/Artifact Collection/);

    const file = new File(["zip-bytes"], "collection.zip", { type: "application/zip" });
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, file);
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));

    const report = await screen.findByTestId("preflight-report");
    expect(within(report).getByText(/web01/)).toBeInTheDocument();
    expect(within(report).getByText(/Archive → Evidence Classification → Linux Discovery/)).toBeInTheDocument();
    expect(within(report).getByText("ZIP archive")).toBeInTheDocument();
    expect(within(report).getByText(/artifact collection/)).toBeInTheDocument();
    expect(within(report).getByText(/Fast \(under 2 minutes\)/)).toBeInTheDocument();
    expect(within(report).getByText("Ready to process")).toBeInTheDocument();
  });

  it("renders preflight when the backend includes empty evidence options", async () => {
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
    createEvidenceUploadSessionMock.mockResolvedValue(sessionResponse({
      preflight: readyReport({ evidence_options: [] }),
    }));
    renderWizard();
    await goToFileStep(/Artifact Collection/);

    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, new File(["x"], "collection.zip"));
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));

    expect(await screen.findByTestId("preflight-report")).toBeInTheDocument();
    expect(screen.getByText("Ready to process")).toBeInTheDocument();
    expect(consoleError).not.toHaveBeenCalled();
    consoleError.mockRestore();
  });

  it("normalizes preflight when the backend omits evidence options", async () => {
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
    const { evidence_options: _evidenceOptions, ...preflightWithoutOptions } = readyReport();
    createEvidenceUploadSessionMock.mockResolvedValue(sessionResponse({
      preflight: preflightWithoutOptions as PreflightReport,
    }));
    renderWizard();
    await goToFileStep(/Artifact Collection/);

    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, new File(["x"], "collection.zip"));
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));

    expect(await screen.findByTestId("preflight-report")).toBeInTheDocument();
    expect(screen.getByText("Ready to process")).toBeInTheDocument();
    expect(consoleError).not.toHaveBeenCalled();
    consoleError.mockRestore();
  });

  it("shows a hash mismatch warning when the server-staged hash disagrees with the client hash", async () => {
    createEvidenceUploadSessionMock.mockResolvedValue(sessionResponse({
      session: { ...sessionResponse().session, client_sha256_mismatch: true },
    }));
    renderWizard();
    await goToFileStep(/Artifact Collection/);
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, new File(["x"], "collection.zip"));
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));

    await screen.findByTestId("preflight-report");
    expect(screen.getByTestId("hash-mismatch-warning")).toBeInTheDocument();
  });

  it("shows blocking diagnostics with severity and requires manual override to continue", async () => {
    createEvidenceUploadSessionMock.mockResolvedValue(sessionResponse({
      preflight: readyReport({
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
          severity: "recommendation",
        }],
      }),
    }));
    renderWizard();
    await goToFileStep(/Artifact Collection/);
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, new File(["x"], "mystery.bin"));
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));

    await screen.findByTestId("preflight-report");
    expect(screen.getByText(/Recommendation: Low confidence classification/)).toBeInTheDocument();
    const continueButton = screen.getByRole("button", { name: "Continue" });
    expect(continueButton).toBeDisabled();

    await userEvent.click(screen.getByRole("checkbox", { name: /Continue with a manual override/i }));
    expect(continueButton).toBeEnabled();
  });

  it("shows a blocking diagnostic with configuration guidance for a disk-full / storage warning", async () => {
    createEvidenceUploadSessionMock.mockResolvedValue(sessionResponse({
      preflight: readyReport({
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
          severity: "blocking",
        }],
      }),
    }));
    renderWizard();
    await goToFileStep(/Disk Image/);
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, new File(["x"], "disk.E01"));
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));

    await screen.findByTestId("preflight-report");
    expect(screen.getByText(/Blocking: Temporary storage too low/)).toBeInTheDocument();
    expect(screen.getByText("BACKEND_TEMP_DIR")).toBeInTheDocument();
    expect(screen.getByText(/backend\/\.env/)).toBeInTheDocument();
  });

  it("disk image flow promotes the upload session on Start Processing", async () => {
    promoteEvidenceUploadSessionMock.mockResolvedValue({ id: "evidence-1", original_filename: "disk.E01" });
    createEvidenceUploadSessionMock.mockResolvedValue(sessionResponse({
      session: { ...sessionResponse().session, id: "session-disk", original_filename: "disk.E01" },
      preflight: readyReport({ original_filename: "disk.E01" }),
    }));
    renderWizard();
    await goToFileStep(/Disk Image/);
    const file = new File(["x"], "disk.E01");
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, file);
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));
    await screen.findByTestId("preflight-report");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));

    await screen.findByText("Confirmation");
    await userEvent.click(screen.getByRole("button", { name: "Start Processing" }));

    await waitFor(() => expect(promoteEvidenceUploadSessionMock).toHaveBeenCalledWith("case-1", "session-disk", expect.objectContaining({})));
    await waitFor(() => expect(runEvidenceIndexingPlanMock).toHaveBeenCalledWith("evidence-1", { profile: "recommended" }));
  });

  it("artifact collection flow promotes the upload session on Start Processing", async () => {
    promoteEvidenceUploadSessionMock.mockResolvedValue({ id: "evidence-2", original_filename: "collection.zip" });
    renderWizard();
    await goToFileStep(/Artifact Collection/);
    const file = new File(["x"], "collection.zip");
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, file);
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));
    await screen.findByTestId("preflight-report");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));

    await screen.findByText("Confirmation");
    await userEvent.click(screen.getByRole("button", { name: "Start Processing" }));

    await waitFor(() => expect(promoteEvidenceUploadSessionMock).toHaveBeenCalledWith("case-1", "session-1", expect.objectContaining({})));
    await waitFor(() => expect(runEvidenceIndexingPlanMock).toHaveBeenCalledWith("evidence-2", { profile: "recommended" }));
    expect(cancelEvidenceUploadSessionMock).not.toHaveBeenCalled();
  });

  it("can start the advanced custom indexing profile from the wizard", async () => {
    promoteEvidenceUploadSessionMock.mockResolvedValue({ id: "evidence-custom", original_filename: "collection.zip" });
    renderWizard();
    await goToFileStep(/Artifact Collection/);
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, new File(["x"], "collection.zip"));
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));
    await screen.findByTestId("preflight-report");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));

    await screen.findByText("Confirmation");
    await userEvent.click(screen.getByRole("radio", { name: /Custom indexing/i }));
    await userEvent.click(screen.getByRole("button", { name: "Start Processing" }));

    await waitFor(() => expect(runEvidenceIndexingPlanMock).toHaveBeenCalledWith("evidence-custom", { profile: "advanced_custom" }));
  });

  it("can save evidence without starting indexing", async () => {
    promoteEvidenceUploadSessionMock.mockResolvedValue({ id: "evidence-skip", original_filename: "collection.zip" });
    renderWizard();
    await goToFileStep(/Artifact Collection/);
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, new File(["x"], "collection.zip"));
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));
    await screen.findByTestId("preflight-report");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));

    await screen.findByText("Confirmation");
    await userEvent.click(screen.getByRole("radio", { name: /Save without indexing/i }));
    await userEvent.click(screen.getByRole("button", { name: "Save Evidence" }));

    await waitFor(() => expect(promoteEvidenceUploadSessionMock).toHaveBeenCalledWith("case-1", "session-1", expect.objectContaining({})));
    expect(runEvidenceIndexingPlanMock).not.toHaveBeenCalled();
  });

  it("lets the analyst assign an existing host before continuing", async () => {
    renderWizard();
    await passHealthCheck();
    await userEvent.click(screen.getByRole("button", { name: /Artifact Collection/ }));
    await userEvent.click(screen.getByRole("button", { name: "Continue" })); // platform -> host step

    await screen.findByText("Host");
    await userEvent.click(screen.getByRole("radio", { name: "Assign existing host" }));
    expect(screen.getByRole("option", { name: "WS-01" })).toBeInTheDocument();
  });

  it("keeps Auto Assign available for non-memory evidence", async () => {
    renderWizard();
    await passHealthCheck();
    await userEvent.click(screen.getByRole("button", { name: /Artifact Collection/ }));
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));

    expect(await screen.findByRole("radio", { name: "Auto Assign" })).toBeInTheDocument();
  });

  it("requires an explicit host before memory evidence can continue", async () => {
    renderWizard();
    await passHealthCheck();
    await userEvent.click(screen.getByRole("button", { name: /Memory Dump/ }));
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));

    expect(screen.queryByRole("radio", { name: "Auto Assign" })).not.toBeInTheDocument();
    expect(await screen.findByTestId("memory-host-required-message")).toHaveTextContent(/require a source host/i);
    const continueButton = screen.getByRole("button", { name: "Continue" });
    expect(continueButton).toBeDisabled();

    await userEvent.click(screen.getByRole("radio", { name: "Assign existing host" }));
    expect(continueButton).toBeEnabled();
  });

  it("folder flow promotes the upload session on Start Processing", async () => {
    promoteEvidenceUploadSessionMock.mockResolvedValue({ id: "evidence-4", original_filename: "3 files" });
    createEvidenceUploadSessionMock.mockResolvedValue(sessionResponse({
      preflight: readyReport({ pipeline_preview: ["Folder", "Evidence Classification", "Linux Discovery", "Artifact Discovery", "Normalization", "Indexing", "Search", "Timeline"] }),
    }));
    renderWizard();
    await goToFileStep(/Folder/);
    const files = [new File(["a"], "a.log"), new File(["b"], "b.log")];
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, files);
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));
    await screen.findByTestId("preflight-report");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));

    await screen.findByText("Confirmation");
    await userEvent.click(screen.getByRole("button", { name: "Start Processing" }));

    expect(createEvidenceUploadSessionMock).toHaveBeenCalledWith("case-1", { files, folderUpload: true }, expect.objectContaining({}));
    await waitFor(() => expect(promoteEvidenceUploadSessionMock).toHaveBeenCalled());
    await waitFor(() => expect(runEvidenceIndexingPlanMock).toHaveBeenCalledWith("evidence-4", { profile: "recommended" }));
  });

  it("server path flow registers via the upload session on Start Processing", async () => {
    promoteEvidenceUploadSessionMock.mockResolvedValue({ id: "evidence-5", original_filename: "disk.E01" });
    renderWizard();
    await goToFileStep(/Existing Server Path/);
    await userEvent.type(screen.getByLabelText(/Server path/i), "/mnt/evidence/disk.E01");
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));
    await screen.findByTestId("preflight-report");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));

    await screen.findByText("Confirmation");
    await userEvent.click(screen.getByRole("button", { name: "Start Processing" }));

    expect(createEvidenceUploadSessionMock).toHaveBeenCalledWith("case-1", { serverPath: "/mnt/evidence/disk.E01" }, { declaredPlatform: "auto" });
    await waitFor(() => expect(promoteEvidenceUploadSessionMock).toHaveBeenCalledWith("case-1", "session-1", expect.objectContaining({})));
    await waitFor(() => expect(runEvidenceIndexingPlanMock).toHaveBeenCalledWith("evidence-5", { profile: "recommended" }));
  });

  it("memory flow requires authorization acknowledgement before Start Processing is enabled", async () => {
    promoteEvidenceUploadSessionMock.mockResolvedValue({ id: "evidence-3", original_filename: "capture.mem", evidence_type: "memory_dump" });
    createEvidenceUploadSessionMock.mockResolvedValue(sessionResponse({
      preflight: readyReport({ original_filename: "capture.mem", pipeline_preview: ["Memory Dump", "Evidence Classification", "Memory Registration", "Memory Analysis (manual, after ingestion)"] }),
    }));
    renderWizard();
    await passHealthCheck();
    await userEvent.click(screen.getByRole("button", { name: /Memory Dump/ }));
    await userEvent.click(screen.getByRole("button", { name: "Continue" })); // platform
    await userEvent.click(screen.getByRole("radio", { name: "Assign existing host" }));
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));
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
    await waitFor(() => expect(promoteEvidenceUploadSessionMock).toHaveBeenCalledWith("case-1", "session-1", expect.objectContaining({ host_id: "host-1", memory_authorization_acknowledged: true })));
    expect(runEvidenceIndexingPlanMock).not.toHaveBeenCalled();
    await waitFor(() => expect(navigateMock).toHaveBeenCalledWith("/cases/case-1/memory/evidence-3"));
  });
});
