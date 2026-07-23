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
const listResumableEvidenceUploadsMock = vi.fn();
const createResumableEvidenceUploadSessionMock = vi.fn();
const getEvidenceUploadSessionMock = vi.fn();
const getMemoryUploadStatusMock = vi.fn();
const uploadMemoryUploadChunkMock = vi.fn();
const finalizeMemoryUploadMock = vi.fn();
const getEvidenceMock = vi.fn();
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
    listResumableEvidenceUploads: (...args: unknown[]) => listResumableEvidenceUploadsMock(...args),
    createResumableEvidenceUploadSession: (...args: unknown[]) => createResumableEvidenceUploadSessionMock(...args),
    getEvidenceUploadSession: (...args: unknown[]) => getEvidenceUploadSessionMock(...args),
    getMemoryUploadStatus: (...args: unknown[]) => getMemoryUploadStatusMock(...args),
    uploadMemoryUploadChunk: (...args: unknown[]) => uploadMemoryUploadChunkMock(...args),
    finalizeMemoryUpload: (...args: unknown[]) => finalizeMemoryUploadMock(...args),
    getEvidence: (...args: unknown[]) => getEvidenceMock(...args),
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
    createCaseHostMock.mockResolvedValue({ host: { id: "host-created", display_name: "NEW-HOST" }, created: true });
    runEvidenceIndexingPlanMock.mockResolvedValue({ accepted: true, evidence_id: "evidence-1", profile: "recommended", run_id: "plan-1", status: "queued", queued_jobs: [{ step_id: "linux_artifacts", run_id: "job-1", status: "queued" }], plan: { run_id: "plan-1", profile: "recommended", status: "queued", steps: [], excluded: [], queued_jobs: [] } });
    cancelEvidenceUploadSessionMock.mockResolvedValue({ status: "cancelled", session_id: "session-1" });
    listResumableEvidenceUploadsMock.mockResolvedValue({ case_id: "case-1", sessions: [] });
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

  it("leaves the upload session available when the wizard is closed after inspection", async () => {
    const { onClose } = renderWizard();
    await goToFileStep(/Artifact Collection/);
    const file = new File(["zip-bytes"], "collection.zip", { type: "application/zip" });
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, file);
    await waitFor(() => expect(screen.queryByTestId("sha256-progress")).not.toBeInTheDocument());
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));
    await screen.findByTestId("preflight-report");

    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));

    expect(cancelEvidenceUploadSessionMock).not.toHaveBeenCalled();
    expect(onClose).toHaveBeenCalled();
  });

  it("defaults platform to Auto Detect (recommended)", async () => {
    renderWizard();
    await passHealthCheck();
    await userEvent.click(screen.getByRole("button", { name: /Artifact Collection/ }));
    const autoCard = await screen.findByRole("button", { name: /Auto-detect \(Recommended\)/ });
    expect(autoCard.className).toContain("border-accent");
  });

  it("starts upload without waiting for a client-side SHA-256 pass", async () => {
    renderWizard();
    await goToFileStep(/Artifact Collection/);

    const file = new File(["zip-bytes"], "collection.zip", { type: "application/zip" });
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, file);

    expect(screen.queryByTestId("sha256-ready")).not.toBeInTheDocument();
    expect(screen.queryByTestId("sha256-progress")).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));
    await screen.findByTestId("preflight-report");

    expect(createEvidenceUploadSessionMock).toHaveBeenCalledWith("case-1", { file }, expect.objectContaining({ declaredPlatform: "auto" }));
    expect(createEvidenceUploadSessionMock.mock.calls[0][2]).not.toHaveProperty("clientSha256");
  });

  it("shows explicit upload and preflight stages instead of a generic inspecting state", async () => {
    let resolveSession: ((value: EvidenceUploadSessionCreateResponse) => void) | undefined;
    createEvidenceUploadSessionMock.mockImplementationOnce((_caseId, _input, options) => {
      options?.onProgress?.({ loaded: 2100, total: 4200, lengthComputable: true });
      return new Promise<EvidenceUploadSessionCreateResponse>((resolve) => {
        resolveSession = resolve;
      });
    });
    renderWizard();
    await goToFileStep(/Artifact Collection/);

    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, new File(["zip-bytes"], "collection.zip", { type: "application/zip" }));
    await waitFor(() => expect(screen.queryByTestId("sha256-progress")).not.toBeInTheDocument());
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));

    const panel = await screen.findByTestId("inspection-progress-panel");
    expect(within(panel).getByText(/Uploading evidence to staging storage/i)).toBeInTheDocument();
    expect(within(panel).getByText(/Uploading evidence 50%/i)).toBeInTheDocument();
    expect(within(panel).getByText(/Scanning contents, detecting platform, discovering hosts/i)).toBeInTheDocument();

    resolveSession?.(sessionResponse());
    expect(await screen.findByTestId("preflight-report")).toBeInTheDocument();
  });

  it("keeps the selected evidence visible and offers retry when preflight inspection fails", async () => {
    createEvidenceUploadSessionMock.mockRejectedValueOnce(new Error("archive could not be inspected"));
    createEvidenceUploadSessionMock.mockResolvedValueOnce(sessionResponse());
    renderWizard();
    await goToFileStep(/Artifact Collection/);

    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, new File(["zip-bytes"], "collection.zip", { type: "application/zip" }));
    await waitFor(() => expect(screen.queryByTestId("sha256-progress")).not.toBeInTheDocument());
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));

    const panel = await screen.findByTestId("inspection-progress-panel");
    expect(within(panel).getByText(/Inspection failed/i)).toBeInTheDocument();
    expect(within(panel).getByText(/archive could not be inspected/i)).toBeInTheDocument();
    expect(screen.getByText("collection.zip")).toBeInTheDocument();

    await userEvent.click(within(panel).getByRole("button", { name: /Retry inspection/i }));
    expect(await screen.findByTestId("preflight-report")).toBeInTheDocument();
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

  it("uses a detected hostname as the host assignment before recommended indexing", async () => {
    promoteEvidenceUploadSessionMock.mockResolvedValue({ id: "evidence-detected", original_filename: "collection.zip" });
    renderWizard();
    await goToFileStep(/Artifact Collection/);
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, new File(["x"], "collection.zip"));
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));
    await screen.findByTestId("preflight-report");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));

    expect(await screen.findByTestId("detected-hostname")).toHaveTextContent("web01");
    await userEvent.click(screen.getByRole("button", { name: "Start Processing" }));

    await waitFor(() => expect(promoteEvidenceUploadSessionMock).toHaveBeenCalledWith("case-1", "session-1", expect.objectContaining({ provided_host: "web01" })));
    await waitFor(() => expect(runEvidenceIndexingPlanMock).toHaveBeenCalledWith("evidence-detected", { profile: "recommended" }));
  });

  it("auto assigns a detected hostname to an existing matching host", async () => {
    getCaseHostsMock.mockResolvedValue({ hosts: [{ id: "host-web01", display_name: "web01", canonical_name: "web01", aliases: [], all_names: ["web01"] }] });
    promoteEvidenceUploadSessionMock.mockResolvedValue({ id: "evidence-existing", original_filename: "collection.zip" });
    renderWizard();
    await goToFileStep(/Artifact Collection/);
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, new File(["x"], "collection.zip"));
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));
    await screen.findByTestId("preflight-report");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));

    expect(await screen.findByLabelText(/Auto assign to web01/i)).toBeChecked();
    await userEvent.click(screen.getByRole("button", { name: "Start Processing" }));

    await waitFor(() => expect(promoteEvidenceUploadSessionMock).toHaveBeenCalledWith("case-1", "session-1", expect.objectContaining({ host_id: "host-web01" })));
  });

  it("requires explicit selection when multiple hosts match the detected hostname", async () => {
    getCaseHostsMock.mockResolvedValue({ hosts: [
      { id: "host-a", display_name: "WEB01", canonical_name: "web01", aliases: [], all_names: ["web01"] },
      { id: "host-b", display_name: "web01.local", canonical_name: "web01-local", aliases: ["web01"], all_names: ["web01.local", "web01"] },
    ] });
    promoteEvidenceUploadSessionMock.mockResolvedValue({ id: "evidence-multi", original_filename: "collection.zip" });
    renderWizard();
    await goToFileStep(/Artifact Collection/);
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, new File(["x"], "collection.zip"));
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));
    await screen.findByTestId("preflight-report");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));

    expect(await screen.findByTestId("multiple-host-matches")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Start Processing" })).toBeDisabled();
    await userEvent.click(screen.getByRole("radio", { name: /Assign to existing host/i }));
    await userEvent.selectOptions(screen.getByRole("combobox"), "host-b");
    await userEvent.click(screen.getByRole("button", { name: "Start Processing" }));

    await waitFor(() => expect(promoteEvidenceUploadSessionMock).toHaveBeenCalledWith("case-1", "session-1", expect.objectContaining({ host_id: "host-b" })));
  });

  it("blocks indexing when no hostname is detected until a host is provided", async () => {
    createEvidenceUploadSessionMock.mockResolvedValue(sessionResponse({ preflight: readyReport({ classification: { ...readyReport().classification, hostname: null } }) }));
    promoteEvidenceUploadSessionMock.mockResolvedValue({ id: "evidence-created", original_filename: "collection.zip" });
    renderWizard();
    await goToFileStep(/Artifact Collection/);
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, new File(["x"], "collection.zip"));
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));
    await screen.findByTestId("preflight-report");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));

    expect(await screen.findByTestId("missing-hostname")).toBeInTheDocument();
    const startButton = screen.getByRole("button", { name: "Start Processing" });
    expect(startButton).toBeDisabled();
    await userEvent.type(screen.getByPlaceholderText("WS-01"), "NEW-HOST");
    expect(startButton).toBeEnabled();
    await userEvent.click(startButton);

    await waitFor(() => expect(createCaseHostMock).toHaveBeenCalledWith("case-1", { host_name: "NEW-HOST", reason: "Created during evidence ingestion wizard" }));
    await waitFor(() => expect(promoteEvidenceUploadSessionMock).toHaveBeenCalledWith("case-1", "session-1", expect.objectContaining({ host_id: "host-created" })));
  });

  it("allows keeping evidence unassigned when saving without indexing", async () => {
    createEvidenceUploadSessionMock.mockResolvedValue(sessionResponse({ preflight: readyReport({ classification: { ...readyReport().classification, hostname: null } }) }));
    promoteEvidenceUploadSessionMock.mockResolvedValue({ id: "evidence-unassigned", original_filename: "collection.zip" });
    renderWizard();
    await goToFileStep(/Artifact Collection/);
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, new File(["x"], "collection.zip"));
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));
    await screen.findByTestId("preflight-report");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));

    await userEvent.click(screen.getByRole("radio", { name: /Save without indexing/i }));
    await userEvent.click(screen.getByRole("radio", { name: /Keep unassigned/i }));
    await userEvent.click(screen.getByRole("button", { name: "Save Evidence" }));

    await waitFor(() => expect(promoteEvidenceUploadSessionMock).toHaveBeenCalledWith("case-1", "session-1", expect.not.objectContaining({ host_id: expect.any(String), provided_host: expect.any(String) })));
    expect(runEvidenceIndexingPlanMock).not.toHaveBeenCalled();
  });

  it("does not promote a second evidence record when indexing is retried after promotion", async () => {
    promoteEvidenceUploadSessionMock.mockResolvedValue({ id: "evidence-retry", original_filename: "collection.zip" });
    runEvidenceIndexingPlanMock.mockRejectedValueOnce(new Error("worker unavailable"));
    runEvidenceIndexingPlanMock.mockResolvedValueOnce({ accepted: true, evidence_id: "evidence-retry", profile: "recommended", run_id: "plan-2", status: "queued", queued_jobs: [{ step_id: "linux_artifacts", run_id: "job-2", status: "queued" }], plan: { run_id: "plan-2", profile: "recommended", status: "queued", steps: [], excluded: [], queued_jobs: [] } });
    renderWizard();
    await goToFileStep(/Artifact Collection/);
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, new File(["x"], "collection.zip"));
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));
    await screen.findByTestId("preflight-report");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));

    await userEvent.click(screen.getByRole("button", { name: "Start Processing" }));
    await waitFor(() => expect(runEvidenceIndexingPlanMock).toHaveBeenCalledTimes(1));
    expect(await screen.findByText("worker unavailable")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Start Processing" }));

    await waitFor(() => expect(runEvidenceIndexingPlanMock).toHaveBeenCalledTimes(2));
    expect(promoteEvidenceUploadSessionMock).toHaveBeenCalledTimes(1);
    expect(runEvidenceIndexingPlanMock).toHaveBeenNthCalledWith(2, "evidence-retry", { profile: "recommended" });
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

    await waitFor(() => expect(runEvidenceIndexingPlanMock).toHaveBeenCalledWith("evidence-custom", { profile: "fast" }));
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

async function sha256HexForTest(bytesData: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytesData);
  return Array.from(new Uint8Array(digest), (value) => value.toString(16).padStart(2, "0")).join("");
}

function resumableUnifiedSession(overrides: Partial<import("../api/client").ResumableUploadSessionRead> = {}): import("../api/client").ResumableUploadSessionRead {
  return {
    id: "resume-session-1",
    case_id: "case-1",
    backend: "unified",
    category: "memory_dump",
    original_filename: "capture.mem",
    expected_size_bytes: 32,
    bytes_received: 16,
    progress_percent: 50,
    status: "uploading",
    current_stage: "uploading",
    created_at: new Date(Date.now() - 60_000).toISOString(),
    updated_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 3600_000).toISOString(),
    resumable: true,
    cancellable: true,
    promoted_evidence_id: null,
    failure_message: null,
    unified: {
      memory_upload_id: "memory-upload-1",
      chunk_size_bytes: 16,
      total_chunks: 2,
      received_chunks: [0],
      missing_chunks: [1],
      default_concurrency: 2,
      max_concurrency: 4,
      expected_sha256: null,
      verification_chunk_index: 0,
      verification_chunk_size: 16,
      verification_chunk_sha256: null, // filled per-test with the real hash of the first 16 bytes
    },
    ...overrides,
  };
}

describe("EvidenceIngestionWizard resumable upload discovery", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    navigateMock.mockReset();
    getCaseHostsMock.mockResolvedValue({ hosts: [{ id: "host-1", display_name: "WS-01" }] });
    getIngestionReadinessMock.mockResolvedValue(readyHealth({ unified_upload_evidence_memory_dump: true }));
    cancelEvidenceUploadSessionMock.mockResolvedValue({ status: "cancelled", session_id: "resume-session-1" });
  });

  it("surfaces an interrupted upload without needing a resume_session URL parameter and lets the analyst pick it up", async () => {
    const firstSixteen = new TextEncoder().encode("0123456789ABCDEF");
    const verificationHash = await sha256HexForTest(firstSixteen);
    const candidate = resumableUnifiedSession({ unified: { ...resumableUnifiedSession().unified!, verification_chunk_sha256: verificationHash } });
    listResumableEvidenceUploadsMock.mockResolvedValue({ case_id: "case-1", sessions: [candidate] });

    renderWizard();
    await passHealthCheck();

    const panel = await screen.findByTestId("resumable-uploads-panel");
    expect(within(panel).getByText("capture.mem")).toBeInTheDocument();
    expect(within(panel).getByText(/uploading/)).toBeInTheDocument();

    await userEvent.click(within(panel).getByTestId("resume-upload-select"));
    await screen.findByTestId("resume-upload-step");
    expect(screen.getByText(/capture.mem/)).toBeInTheDocument();
  });

  it("rejects a re-selected file whose size does not match the original upload", async () => {
    listResumableEvidenceUploadsMock.mockResolvedValue({ case_id: "case-1", sessions: [resumableUnifiedSession()] });
    renderWizard();
    await passHealthCheck();
    await userEvent.click(await screen.findByTestId("resume-upload-select"));
    await screen.findByTestId("resume-upload-step");

    const wrongSizeFile = new File(["short"], "capture.mem");
    await userEvent.upload(screen.getByTestId("resume-file-input"), wrongSizeFile);

    expect(await screen.findByTestId("resume-file-error")).toHaveTextContent(/expected/i);
    expect(screen.getByTestId("resume-upload-button")).toBeDisabled();
  });

  it("rejects a re-selected file with the right size but different content via the verification chunk hash", async () => {
    const candidate = resumableUnifiedSession({
      unified: { ...resumableUnifiedSession().unified!, verification_chunk_sha256: "f".repeat(64) },
    });
    listResumableEvidenceUploadsMock.mockResolvedValue({ case_id: "case-1", sessions: [candidate] });
    renderWizard();
    await passHealthCheck();
    await userEvent.click(await screen.findByTestId("resume-upload-select"));
    await screen.findByTestId("resume-upload-step");

    const rightSizeWrongContent = new File(["Z".repeat(32)], "capture.mem");
    await userEvent.upload(screen.getByTestId("resume-file-input"), rightSizeWrongContent);

    expect(await screen.findByTestId("resume-file-error")).toHaveTextContent(/does not match/i);
    expect(screen.getByTestId("resume-upload-button")).toBeDisabled();
  });

  it("resumes from the missing chunk after verifying the re-selected file, then registers evidence", async () => {
    const chunk0 = new TextEncoder().encode("0123456789ABCDEF");
    const chunk1 = new TextEncoder().encode("FEDCBA9876543210");
    const wholeFile = new Uint8Array(32);
    wholeFile.set(chunk0, 0);
    wholeFile.set(chunk1, 16);
    const verificationHash = await sha256HexForTest(chunk0);
    const candidate = resumableUnifiedSession({ unified: { ...resumableUnifiedSession().unified!, verification_chunk_sha256: verificationHash } });
    listResumableEvidenceUploadsMock.mockResolvedValue({ case_id: "case-1", sessions: [candidate] });

    // Stateful: chunk 0 already landed before the reload; the mock tracks
    // what's actually been "uploaded" so runResumableUpload's own stall
    // detection (comparing missing-chunk counts across polls) sees real
    // progress instead of a fixed response that never changes.
    const receivedChunks = new Set<number>([0]);
    const statusFor = (overrides: Partial<{ status: string; evidence_id: string | null }> = {}) => ({
      upload_id: "memory-upload-1", case_id: "case-1", evidence_id: overrides.evidence_id ?? null, status: overrides.status ?? "uploading",
      bytes_received: receivedChunks.size * 16, expected_bytes: 32, chunk_size_bytes: 16, total_chunks: 2,
      received_chunks: Array.from(receivedChunks).sort(), missing_chunks: [0, 1].filter((i) => !receivedChunks.has(i)),
      filename: "capture.mem", updated_at: new Date().toISOString(), failure_code: null, failure_message: null, message: "", retryable: true,
    });
    getMemoryUploadStatusMock.mockImplementation(async () => statusFor());
    uploadMemoryUploadChunkMock.mockImplementation(async (_caseId: string, _uploadId: string, chunkIndex: number) => {
      receivedChunks.add(chunkIndex);
      return statusFor();
    });
    finalizeMemoryUploadMock.mockResolvedValue({
      upload_id: "memory-upload-1", case_id: "case-1", evidence_id: "evidence-resumed", status: "completed",
      bytes_received: 32, expected_bytes: 32, chunk_size_bytes: 16, total_chunks: 2,
      received_chunks: [0, 1], missing_chunks: [], filename: "capture.mem", updated_at: new Date().toISOString(),
      failure_code: null, failure_message: null, message: "", retryable: false,
    });
    getEvidenceUploadSessionMock.mockResolvedValue({
      session: { ...sessionResponse().session, id: "resume-session-1", status: "promoted", promoted_evidence_id: "evidence-resumed", category: "memory_dump", backend: "unified" },
      health: null,
      unified: null,
    });
    getEvidenceMock.mockResolvedValue({ id: "evidence-resumed", original_filename: "capture.mem", evidence_type: "memory_dump" });

    renderWizard();
    await passHealthCheck();
    await userEvent.click(await screen.findByTestId("resume-upload-select"));
    await screen.findByTestId("resume-upload-step");

    const file = new File([wholeFile], "capture.mem");
    await userEvent.upload(screen.getByTestId("resume-file-input"), file);
    const resumeButton = await screen.findByTestId("resume-upload-button");
    await waitFor(() => expect(resumeButton).toBeEnabled());

    await userEvent.click(resumeButton);

    await waitFor(() => expect(uploadMemoryUploadChunkMock).toHaveBeenCalledWith("case-1", "memory-upload-1", 1, expect.anything(), expect.anything()));
    // Only the missing chunk (index 1) is re-uploaded -- the already-received
    // chunk 0 is never retransmitted.
    expect(uploadMemoryUploadChunkMock).not.toHaveBeenCalledWith("case-1", "memory-upload-1", 0, expect.anything(), expect.anything());
    await waitFor(() => expect(finalizeMemoryUploadMock).toHaveBeenCalledWith("case-1", "memory-upload-1"));
    await waitFor(() => expect(navigateMock).toHaveBeenCalledWith("/cases/case-1/memory/evidence-resumed"));
  });

  it("cancels an interrupted upload from the discovery panel", async () => {
    listResumableEvidenceUploadsMock.mockResolvedValue({ case_id: "case-1", sessions: [resumableUnifiedSession()] });
    renderWizard();
    await passHealthCheck();
    const panel = await screen.findByTestId("resumable-uploads-panel");

    await userEvent.click(within(panel).getByRole("button", { name: "Cancel" }));

    await waitFor(() => expect(cancelEvidenceUploadSessionMock).toHaveBeenCalledWith("case-1", "resume-session-1"));
  });

  it("excludes a session that reached 100% from the interrupted/active uploads panel", async () => {
    const finishedCandidate = resumableUnifiedSession({ id: "resume-session-done", progress_percent: 100, status: "staged" });
    listResumableEvidenceUploadsMock.mockResolvedValue({ case_id: "case-1", sessions: [finishedCandidate] });

    renderWizard();
    await passHealthCheck();

    expect(screen.queryByTestId("resumable-uploads-panel")).not.toBeInTheDocument();
  });

  it("keeps an in-progress session visible alongside one that already reached 100%", async () => {
    const inProgress = resumableUnifiedSession();
    const finishedCandidate = resumableUnifiedSession({ id: "resume-session-done", original_filename: "done.mem", progress_percent: 100, status: "staged" });
    listResumableEvidenceUploadsMock.mockResolvedValue({ case_id: "case-1", sessions: [inProgress, finishedCandidate] });

    renderWizard();
    await passHealthCheck();

    const panel = await screen.findByTestId("resumable-uploads-panel");
    expect(within(panel).getByText("capture.mem")).toBeInTheDocument();
    expect(within(panel).queryByText("done.mem")).not.toBeInTheDocument();
  });
});

describe("EvidenceIngestionWizard unified disk_image uploads", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    navigateMock.mockReset();
    getCaseHostsMock.mockResolvedValue({ hosts: [{ id: "host-1", display_name: "WS-01" }] });
    getIngestionReadinessMock.mockResolvedValue(readyHealth({ unified_upload_evidence_disk_image: true }));
    listResumableEvidenceUploadsMock.mockResolvedValue({ case_id: "case-1", sessions: [] });
  });

  it("routes a single disk image file through the unified chunk-index transport and kicks off recommended indexing", async () => {
    const payload = new Uint8Array(24).fill(7);
    createResumableEvidenceUploadSessionMock.mockResolvedValue({
      session: { ...sessionResponse().session, id: "disk-session-1", status: "created", original_filename: "image.raw", size_bytes: 24, category: "disk_image", backend: "unified" },
      health: readyHealth({ unified_upload_evidence_disk_image: true }),
      unified: { memory_upload_id: "disk-upload-1", chunk_size_bytes: 32, total_chunks: 1, default_concurrency: 2, max_concurrency: 4 },
    });
    // Stateful, like the resumable-discovery tests above: runResumableUpload's
    // own stall watchdog compares missing-chunk counts across polls, so a
    // fixed getStatus() response that never reflects the chunk that was just
    // uploaded reads as "no progress" and trips a false stall failure.
    const receivedChunks = new Set<number>();
    const statusFor = () => ({
      upload_id: "disk-upload-1", case_id: "case-1", evidence_id: null, status: "uploading",
      bytes_received: receivedChunks.size * 24, expected_bytes: 24, chunk_size_bytes: 32, total_chunks: 1,
      received_chunks: Array.from(receivedChunks).sort(), missing_chunks: [0].filter((i) => !receivedChunks.has(i)),
      filename: "image.raw", updated_at: new Date().toISOString(), failure_code: null, failure_message: null, message: "", retryable: true,
    });
    getMemoryUploadStatusMock.mockImplementation(async () => statusFor());
    uploadMemoryUploadChunkMock.mockImplementation(async (_caseId: string, _uploadId: string, chunkIndex: number) => {
      receivedChunks.add(chunkIndex);
      return statusFor();
    });
    finalizeMemoryUploadMock.mockResolvedValue({
      upload_id: "disk-upload-1", case_id: "case-1", evidence_id: "evidence-disk-1", status: "completed",
      bytes_received: 24, expected_bytes: 24, chunk_size_bytes: 32, total_chunks: 1,
      received_chunks: [0], missing_chunks: [], filename: "image.raw", updated_at: new Date().toISOString(),
      failure_code: null, failure_message: null, message: "", retryable: false,
    });
    getEvidenceUploadSessionMock.mockResolvedValue({
      session: { ...sessionResponse().session, id: "disk-session-1", status: "promoted", promoted_evidence_id: "evidence-disk-1", category: "disk_image", backend: "unified" },
      health: null,
      unified: null,
    });
    getEvidenceMock.mockResolvedValue({ id: "evidence-disk-1", original_filename: "image.raw", evidence_type: "disk_image" });
    runEvidenceIndexingPlanMock.mockResolvedValue({ accepted: true, evidence_id: "evidence-disk-1", profile: "recommended", run_id: "plan-disk-1", status: "queued", queued_jobs: [{ step_id: "raw_disk_image", run_id: "job-1", status: "queued" }], plan: { run_id: "plan-disk-1", profile: "recommended", status: "queued", steps: [], excluded: [], queued_jobs: [] } });

    renderWizard();
    await goToFileStep(/Disk Image/);
    const file = new File([payload], "image.raw");
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, file);
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));

    expect(createResumableEvidenceUploadSessionMock).toHaveBeenCalledWith("case-1", expect.objectContaining({ filename: "image.raw", intake_category: "disk_image" }));
    await waitFor(() => expect(uploadMemoryUploadChunkMock).toHaveBeenCalledWith("case-1", "disk-upload-1", 0, expect.anything(), expect.anything()));
    await waitFor(() => expect(finalizeMemoryUploadMock).toHaveBeenCalledWith("case-1", "disk-upload-1"));
    await waitFor(() => expect(runEvidenceIndexingPlanMock).toHaveBeenCalledWith("evidence-disk-1", { profile: "recommended" }));
    await waitFor(() => expect(navigateMock).toHaveBeenCalledWith("/evidences/evidence-disk-1"));
  });

  it("keeps a multi-segment disk image selection (files.length > 1) on the legacy staged flow even with the flag enabled", async () => {
    createEvidenceUploadSessionMock.mockResolvedValue(sessionResponse({
      preflight: readyReport({ pipeline_preview: ["Disk Image", "Evidence Classification"] }),
    }));
    renderWizard();
    await goToFileStep(/Disk Image/);
    const files = [new File(["a"], "image.E01"), new File(["b"], "image.E02")];
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, files);
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));

    await screen.findByTestId("preflight-report");
    expect(createResumableEvidenceUploadSessionMock).not.toHaveBeenCalled();
    expect(createEvidenceUploadSessionMock).toHaveBeenCalledWith("case-1", { files, folderUpload: false }, expect.objectContaining({}));
  });

  it("still registers evidence and navigates away even when automatic indexing kickoff fails", async () => {
    const payload = new Uint8Array(8).fill(9);
    createResumableEvidenceUploadSessionMock.mockResolvedValue({
      session: { ...sessionResponse().session, id: "disk-session-2", status: "created", original_filename: "image2.raw", size_bytes: 8, category: "disk_image", backend: "unified" },
      health: readyHealth({ unified_upload_evidence_disk_image: true }),
      unified: { memory_upload_id: "disk-upload-2", chunk_size_bytes: 32, total_chunks: 1, default_concurrency: 2, max_concurrency: 4 },
    });
    const receivedChunks = new Set<number>();
    const statusFor = () => ({
      upload_id: "disk-upload-2", case_id: "case-1", evidence_id: null, status: "uploading",
      bytes_received: receivedChunks.size * 8, expected_bytes: 8, chunk_size_bytes: 32, total_chunks: 1,
      received_chunks: Array.from(receivedChunks).sort(), missing_chunks: [0].filter((i) => !receivedChunks.has(i)),
      filename: "image2.raw", updated_at: new Date().toISOString(), failure_code: null, failure_message: null, message: "", retryable: true,
    });
    getMemoryUploadStatusMock.mockImplementation(async () => statusFor());
    uploadMemoryUploadChunkMock.mockImplementation(async (_caseId: string, _uploadId: string, chunkIndex: number) => {
      receivedChunks.add(chunkIndex);
      return statusFor();
    });
    finalizeMemoryUploadMock.mockResolvedValue({
      upload_id: "disk-upload-2", case_id: "case-1", evidence_id: "evidence-disk-2", status: "completed",
      bytes_received: 8, expected_bytes: 8, chunk_size_bytes: 32, total_chunks: 1,
      received_chunks: [0], missing_chunks: [], filename: "image2.raw", updated_at: new Date().toISOString(),
      failure_code: null, failure_message: null, message: "", retryable: false,
    });
    getEvidenceUploadSessionMock.mockResolvedValue({
      session: { ...sessionResponse().session, id: "disk-session-2", status: "promoted", promoted_evidence_id: "evidence-disk-2", category: "disk_image", backend: "unified" },
      health: null,
      unified: null,
    });
    getEvidenceMock.mockResolvedValue({ id: "evidence-disk-2", original_filename: "image2.raw", evidence_type: "disk_image" });
    runEvidenceIndexingPlanMock.mockRejectedValue(new Error("worker unavailable"));

    renderWizard();
    await goToFileStep(/Disk Image/);
    const file = new File([payload], "image2.raw");
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, file);
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));

    await waitFor(() => expect(runEvidenceIndexingPlanMock).toHaveBeenCalledWith("evidence-disk-2", { profile: "recommended" }));
    await waitFor(() => expect(navigateMock).toHaveBeenCalledWith("/evidences/evidence-disk-2"));
  });
});

describe("EvidenceIngestionWizard unified single-file archive uploads", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    navigateMock.mockReset();
    getCaseHostsMock.mockResolvedValue({ hosts: [{ id: "host-1", display_name: "WS-01" }] });
    getIngestionReadinessMock.mockResolvedValue(readyHealth({ unified_upload_evidence_archive: true }));
    listResumableEvidenceUploadsMock.mockResolvedValue({ case_id: "case-1", sessions: [] });
  });

  it("routes a single .zip file under Artifact Collection through the unified transport with intake_category archive", async () => {
    const payload = new Uint8Array(24).fill(3);
    createResumableEvidenceUploadSessionMock.mockResolvedValue({
      session: { ...sessionResponse().session, id: "archive-session-1", status: "created", original_filename: "collection.zip", size_bytes: 24, category: "archive", backend: "unified" },
      health: readyHealth({ unified_upload_evidence_archive: true }),
      unified: { memory_upload_id: "archive-upload-1", chunk_size_bytes: 32, default_concurrency: 2, max_concurrency: 4, total_chunks: 1 },
    });
    const receivedChunks = new Set<number>();
    const statusFor = () => ({
      upload_id: "archive-upload-1", case_id: "case-1", evidence_id: null, status: "uploading",
      bytes_received: receivedChunks.size * 24, expected_bytes: 24, chunk_size_bytes: 32, total_chunks: 1,
      received_chunks: Array.from(receivedChunks).sort(), missing_chunks: [0].filter((i) => !receivedChunks.has(i)),
      filename: "collection.zip", updated_at: new Date().toISOString(), failure_code: null, failure_message: null, message: "", retryable: true,
    });
    getMemoryUploadStatusMock.mockImplementation(async () => statusFor());
    uploadMemoryUploadChunkMock.mockImplementation(async (_caseId: string, _uploadId: string, chunkIndex: number) => {
      receivedChunks.add(chunkIndex);
      return statusFor();
    });
    finalizeMemoryUploadMock.mockResolvedValue({
      upload_id: "archive-upload-1", case_id: "case-1", evidence_id: "evidence-archive-1", status: "completed",
      bytes_received: 24, expected_bytes: 24, chunk_size_bytes: 32, total_chunks: 1,
      received_chunks: [0], missing_chunks: [], filename: "collection.zip", updated_at: new Date().toISOString(),
      failure_code: null, failure_message: null, message: "", retryable: false,
    });
    getEvidenceUploadSessionMock.mockResolvedValue({
      session: { ...sessionResponse().session, id: "archive-session-1", status: "promoted", promoted_evidence_id: "evidence-archive-1", category: "archive", backend: "unified" },
      health: null,
      unified: null,
    });
    getEvidenceMock.mockResolvedValue({ id: "evidence-archive-1", original_filename: "collection.zip", evidence_type: "velociraptor_zip" });
    runEvidenceIndexingPlanMock.mockResolvedValue({ accepted: true, evidence_id: "evidence-archive-1", profile: "recommended", run_id: "plan-archive-1", status: "queued", queued_jobs: [{ step_id: "raw_collection", run_id: "job-1", status: "queued" }], plan: { run_id: "plan-archive-1", profile: "recommended", status: "queued", steps: [], excluded: [], queued_jobs: [] } });

    renderWizard();
    await goToFileStep(/Artifact Collection/);
    const file = new File([payload], "collection.zip");
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, file);
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));

    expect(createResumableEvidenceUploadSessionMock).toHaveBeenCalledWith("case-1", expect.objectContaining({ filename: "collection.zip", intake_category: "archive" }));
    await waitFor(() => expect(finalizeMemoryUploadMock).toHaveBeenCalledWith("case-1", "archive-upload-1"));
    await waitFor(() => expect(runEvidenceIndexingPlanMock).toHaveBeenCalledWith("evidence-archive-1", { profile: "recommended" }));
    await waitFor(() => expect(navigateMock).toHaveBeenCalledWith("/evidences/evidence-archive-1"));
  });

  it("keeps a non-archive single file under Artifact Collection (e.g. a .csv) on the legacy path even with the flag enabled", async () => {
    renderWizard();
    await goToFileStep(/Artifact Collection/);
    const file = new File(["a,b,c"], "notes.csv");
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, file);
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));

    await waitFor(() => expect(createEvidenceUploadSessionMock).toHaveBeenCalled());
    expect(createResumableEvidenceUploadSessionMock).not.toHaveBeenCalledWith("case-1", expect.objectContaining({ intake_category: "archive" }));
  });

  it("keeps a .zip file on the legacy path when UNIFIED_UPLOAD_EVIDENCE_ARCHIVE is disabled", async () => {
    getIngestionReadinessMock.mockResolvedValue(readyHealth({ unified_upload_evidence_archive: false }));
    createEvidenceUploadSessionMock.mockResolvedValue(sessionResponse({
      preflight: readyReport({ original_filename: "collection.zip" }),
    }));
    renderWizard();
    await goToFileStep(/Artifact Collection/);
    const file = new File([new Uint8Array(8)], "collection.zip");
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, file);
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));

    await screen.findByTestId("preflight-report");
    expect(createResumableEvidenceUploadSessionMock).not.toHaveBeenCalled();
  });
});

describe("EvidenceIngestionWizard advanced options", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    navigateMock.mockReset();
    getCaseHostsMock.mockResolvedValue({ hosts: [{ id: "host-1", display_name: "WS-01" }] });
    listResumableEvidenceUploadsMock.mockResolvedValue({ case_id: "case-1", sessions: [] });
    createEvidenceUploadSessionMock.mockResolvedValue(sessionResponse());
    runEvidenceIndexingPlanMock.mockResolvedValue({ accepted: true, evidence_id: "evidence-adv", profile: "recommended", run_id: "plan-adv", status: "queued", queued_jobs: [], plan: { run_id: "plan-adv", profile: "recommended", status: "queued", steps: [], excluded: [], queued_jobs: [] } });
  });

  it("hides advanced options when the flag is false", async () => {
    getIngestionReadinessMock.mockResolvedValue(readyHealth({ wizard_advanced_options_enabled: false }));
    renderWizard();
    await goToFileStep(/Artifact Collection/);
    const file = new File(["x"], "notes.csv");
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, file);

    expect(screen.queryByTestId("wizard-advanced-options")).not.toBeInTheDocument();
  });

  it("shows advanced options for Artifact Collection when the flag is true", async () => {
    getIngestionReadinessMock.mockResolvedValue(readyHealth({ wizard_advanced_options_enabled: true }));
    renderWizard();
    await goToFileStep(/Artifact Collection/);
    const file = new File(["x"], "notes.csv");
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, file);

    const panel = await screen.findByTestId("wizard-advanced-options");
    expect(within(panel).getByTestId("evidence-intent-raw")).toBeInTheDocument();
    expect(within(panel).getByTestId("ingest-mode-full-forensic")).toBeInTheDocument();
    // notes.csv is neither .evtx nor an eligible archive -- EVTX profile
    // must not be offered for it.
    expect(within(panel).queryByTestId("evtx-profile-full")).not.toBeInTheDocument();
  });

  it("does not show advanced options for Disk Image even when the flag is true", async () => {
    getIngestionReadinessMock.mockResolvedValue(readyHealth({ wizard_advanced_options_enabled: true }));
    renderWizard();
    await goToFileStep(/Disk Image/);
    const file = new File(["x"], "disk.raw");
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, file);

    expect(screen.queryByTestId("wizard-advanced-options")).not.toBeInTheDocument();
  });

  it("shows the EVTX profile option for a .evtx file but not for a plain single file", async () => {
    getIngestionReadinessMock.mockResolvedValue(readyHealth({ wizard_advanced_options_enabled: true }));
    renderWizard();
    await goToFileStep(/Artifact Collection/);
    const file = new File(["x"], "Security.evtx");
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, file);

    const panel = await screen.findByTestId("wizard-advanced-options");
    expect(within(panel).getByTestId("evtx-profile-full")).toBeInTheDocument();
  });

  it("submits raw/full_forensic defaults when advanced options are shown but left untouched", async () => {
    getIngestionReadinessMock.mockResolvedValue(readyHealth({ wizard_advanced_options_enabled: true }));
    promoteEvidenceUploadSessionMock.mockResolvedValue({ id: "evidence-adv-1", original_filename: "notes.csv" });
    renderWizard();
    await goToFileStep(/Artifact Collection/);
    const file = new File(["x"], "notes.csv");
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, file);
    await screen.findByTestId("wizard-advanced-options");
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));
    await screen.findByTestId("preflight-report");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));
    await screen.findByText("Confirmation");
    await userEvent.click(screen.getByRole("button", { name: "Start Processing" }));

    await waitFor(() => expect(promoteEvidenceUploadSessionMock).toHaveBeenCalledWith(
      "case-1", "session-1",
      expect.objectContaining({ evidence_intent: "raw", ingest_mode: "full_forensic" }),
    ));
  });

  it("submits explicit parsed/usable_search selections through promote", async () => {
    getIngestionReadinessMock.mockResolvedValue(readyHealth({ wizard_advanced_options_enabled: true }));
    promoteEvidenceUploadSessionMock.mockResolvedValue({ id: "evidence-adv-2", original_filename: "export.csv" });
    renderWizard();
    await goToFileStep(/Artifact Collection/);
    const file = new File(["x"], "export.csv");
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, file);
    const panel = await screen.findByTestId("wizard-advanced-options");
    await userEvent.click(within(panel).getByTestId("evidence-intent-parsed"));
    await userEvent.click(within(panel).getByTestId("ingest-mode-usable-search"));
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));
    await screen.findByTestId("preflight-report");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));
    await screen.findByText("Confirmation");
    await userEvent.click(screen.getByRole("button", { name: "Start Processing" }));

    await waitFor(() => expect(promoteEvidenceUploadSessionMock).toHaveBeenCalledWith(
      "case-1", "session-1",
      expect.objectContaining({ evidence_intent: "parsed", ingest_mode: "usable_search" }),
    ));
  });

  it("submits the selected EVTX profile through promote", async () => {
    getIngestionReadinessMock.mockResolvedValue(readyHealth({ wizard_advanced_options_enabled: true }));
    promoteEvidenceUploadSessionMock.mockResolvedValue({ id: "evidence-adv-3", original_filename: "Security.evtx" });
    renderWizard();
    await goToFileStep(/Artifact Collection/);
    const file = new File(["x"], "Security.evtx");
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, file);
    const panel = await screen.findByTestId("wizard-advanced-options");
    await userEvent.click(within(panel).getByTestId("evtx-profile-fast"));
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));
    await screen.findByTestId("preflight-report");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));
    await screen.findByText("Confirmation");
    await userEvent.click(screen.getByRole("button", { name: "Start Processing" }));

    await waitFor(() => expect(promoteEvidenceUploadSessionMock).toHaveBeenCalledWith(
      "case-1", "session-1",
      expect.objectContaining({ evtx_profile: "fast_high_value" }),
    ));
  });
});
