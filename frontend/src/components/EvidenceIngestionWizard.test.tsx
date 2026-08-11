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
const getMemoryEvidencePreparationMock = vi.fn();
const listMemoryRunsMock = vi.fn();
const startMemoryScanMock = vi.fn();
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
    getMemoryEvidencePreparation: (...args: unknown[]) => getMemoryEvidencePreparationMock(...args),
    listMemoryRuns: (...args: unknown[]) => listMemoryRunsMock(...args),
    startMemoryScan: (...args: unknown[]) => startMemoryScanMock(...args),
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
  await screen.findByTestId("ingestion-health-chip");
  await screen.findByRole("heading", { name: "Select Evidence" });
}

async function goToFileStep(cardName: RegExp) {
  void cardName;
  await passHealthCheck();
  expect(await screen.findByRole("heading", { name: "Select Evidence" })).toBeInTheDocument();
}

async function openEvidenceAdvancedOptions() {
  await userEvent.click(screen.getByText(/Advanced — evidence options/i));
  return screen.findByTestId("host-assignment-panel");
}

async function reachMemoryPreparationStep(evidence: { id: string; original_filename: string }) {
  promoteEvidenceUploadSessionMock.mockResolvedValue({ id: evidence.id, original_filename: evidence.original_filename, evidence_type: "memory_dump" });
  createEvidenceUploadSessionMock.mockResolvedValue(sessionResponse({
    preflight: readyReport({ original_filename: evidence.original_filename, classification: { ...readyReport().classification, category: "memory_dump" } }),
  }));
  renderWizard();
  await goToFileStep(/Memory Dump/);
  await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, new File(["x"], evidence.original_filename));
  await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));
  await screen.findByTestId("preflight-report");
  await userEvent.click(screen.getByRole("checkbox", { name: /authorized to handle this RAM evidence/i }));
  await userEvent.click(screen.getByRole("button", { name: "Start Processing" }));
  await screen.findByRole("heading", { name: "Evidence registered" });
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
    getMemoryEvidencePreparationMock.mockResolvedValue({
      evidence_id: "evidence-3",
      platform: "windows",
      architecture: "x64",
      readiness: "ready",
      requires_symbols: true,
      can_start_analysis: true,
      human_message: "This evidence is ready to analyze.",
    });
    listMemoryRunsMock.mockResolvedValue([]);
  });

  it("shows a critical health interruption only when a critical dependency is down", async () => {
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
    expect(screen.getByText(/Critical dependency unavailable/)).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Select Evidence" })).not.toBeInTheDocument();
  });

  it("shows Select Evidence immediately when critical dependencies are ready", async () => {
    renderWizard();
    expect(await screen.findByRole("heading", { name: "Select Evidence" })).toBeInTheDocument();
    await waitFor(() => expect(screen.getByTestId("ingestion-health-chip")).toHaveTextContent("All systems ready"));
  });

  it("keeps Select Evidence available when only non-critical dependencies warn", async () => {
    getIngestionReadinessMock.mockResolvedValue(readyHealth({
      critical_ready: true,
      ready: false,
      checks: [
        { label: "Storage", ok: true, detail: "100.0 GB available" },
        { label: "Search", ok: false, detail: "OpenSearch cluster status: yellow" },
        { label: "Database", ok: true, detail: "Reachable" },
        { label: "Workers", ok: true, detail: "Active worker(s)" },
        { label: "Memory Worker", ok: true, detail: "Active worker" },
      ],
    }));
    renderWizard();

    expect(await screen.findByRole("heading", { name: "Select Evidence" })).toBeInTheDocument();
    await waitFor(() => expect(screen.getByTestId("ingestion-health-chip")).toHaveTextContent("Partial systems ready"));
    expect(screen.queryByTestId("health-check")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Inspect evidence" })).toBeDisabled();
  });

  it("does not render a step counter or a health-check step on the golden path", async () => {
    renderWizard();
    await passHealthCheck();
    expect(screen.getByRole("heading", { name: "Select Evidence" })).toBeInTheDocument();
    expect(screen.queryByText(/Step \d+ of \d+/i)).not.toBeInTheDocument();
    expect(screen.queryByText("Server Health Check")).not.toBeInTheDocument();
  });

  it("cancel closes the wizard", async () => {
    const { onClose } = renderWizard();
    await userEvent.click(screen.getByRole("button", { name: "Close" }));
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

    await userEvent.click(screen.getByRole("button", { name: "Close" }));

    expect(cancelEvidenceUploadSessionMock).not.toHaveBeenCalled();
    expect(onClose).toHaveBeenCalled();
  });

  it("defaults the wizard to automatic evidence detection", async () => {
    renderWizard();
    await passHealthCheck();
    expect(await screen.findByText(/Kairon will inspect each item and decide the evidence kind/i)).toBeInTheDocument();
  });

  it("does not show evidence-type choices before preflight", async () => {
    renderWizard();
    await passHealthCheck();

    expect(await screen.findByRole("heading", { name: "Select Evidence" })).toBeInTheDocument();
    expect(screen.queryByText(/What are you adding\?/i)).not.toBeInTheDocument();
    expect(screen.queryByText("Disk Image")).not.toBeInTheDocument();
    expect(screen.queryByText("Memory Dump")).not.toBeInTheDocument();
    expect(screen.queryByText("Artifact Collection")).not.toBeInTheDocument();
    expect(screen.queryByText("Existing Server Path")).not.toBeInTheDocument();
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
    expect(within(panel).getByText(/Analysing evidence/i)).toBeInTheDocument();
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
    expect(within(report).getAllByText(/web01/).length).toBeGreaterThan(0);
    expect(within(report).getByText(/Archive → Evidence Classification → Linux Discovery/)).toBeInTheDocument();
    expect(within(report).getAllByText("ZIP archive").length).toBeGreaterThan(0);
    expect(within(report).getByText(/artifact collection/)).toBeInTheDocument();
    expect(within(report).getByText(/Fast \(under 2 minutes\)/)).toBeInTheDocument();
    expect(within(report).getByText("Ready to process")).toBeInTheDocument();
  });

  it("labels partitions with friendly sequential numbers and a container-format hint, distinct from logical volumes", async () => {
    createEvidenceUploadSessionMock.mockResolvedValueOnce(sessionResponse({
      preflight: readyReport({
        classification: {
          ...readyReport().classification,
          category: "disk_image",
          container: "EWF disk image",
          contained_object: "2 volume(s), no OS installation detected (1 of 2 could not be read as a supported filesystem)",
          platform: "unknown",
          hostname: null,
          distro: null,
          volumes: 2,
          partitions: 2,
          filesystems: [],
          installations: 0,
          volume_diagnostics: [
            { volume_id: 3, size_bytes: 254803968, filesystem: null, ok: true, status: "readable", explanation: "Readable filesystem.", detected_signature: null, kind: "partition", name: null, container_volume_id: null },
            { volume_id: 7, size_bytes: 33568063488, filesystem: null, ok: false, status: "unreadable", explanation: "Detected signature: LVM2 physical volume. Kairon does not currently parse this container format, so operating system detection cannot continue inside this volume.", detected_signature: "LVM2 physical volume", kind: "partition", name: null, container_volume_id: null },
          ],
        },
      }),
    }));
    renderWizard();
    await goToFileStep(/Artifact Collection/);

    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, new File(["disk-bytes"], "disk.dd"));
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));

    const report = await screen.findByTestId("preflight-report");
    // Only "Partitions" is shown -- not a redundant duplicate "Volumes" line
    // for what is, today, the same count.
    expect(within(report).getByText("Partitions:")).toBeInTheDocument();
    expect(within(report).queryByText("Volumes:")).not.toBeInTheDocument();

    const diagnostics = within(report).getByTestId("volume-diagnostics");
    expect(within(diagnostics).getByText("Partition Discovery")).toBeInTheDocument();
    // Friendly, sequential display numbering (1, 2) rather than raw pytsk3
    // partition indices (3, 7) -- pytsk3 enumerates partition-table and
    // unallocated-space entries too, so its own indices are not sequential.
    expect(within(diagnostics).getByText(/Partition 1/)).toBeInTheDocument();
    expect(within(diagnostics).getByText(/Partition 2/)).toBeInTheDocument();
    expect(within(diagnostics).queryByText(/Partition 3/)).not.toBeInTheDocument();
    expect(within(diagnostics).queryByText(/Partition 7/)).not.toBeInTheDocument();
    expect(within(diagnostics).queryByText(/Volume 3/)).not.toBeInTheDocument();
    expect(within(diagnostics).queryByText(/Volume 7/)).not.toBeInTheDocument();
    // The container-format hint (renamed from "Detected signature") reads
    // as a source description, not a raw technical term.
    expect(within(diagnostics).getByText("Container format:")).toBeInTheDocument();
    expect(within(diagnostics).getByText("LVM2 physical volume")).toBeInTheDocument();
  });

  it("presents a successfully-parsed LVM container and its logical volumes as a discovery, not a warning (LVM V1 UX alignment)", async () => {
    // Modeled directly on the real CyberDefenders Webserver.E01 result:
    // partition 7 is the LVM Physical Volume (VulnOSv2-vg), containing a
    // readable "root" logical volume and an unreadable "swap_1" one.
    createEvidenceUploadSessionMock.mockResolvedValueOnce(sessionResponse({
      preflight: readyReport({
        classification: {
          ...readyReport().classification,
          category: "disk_image",
          container: "EWF disk image",
          contained_object: "1 OS installation(s) across 4 volume(s)",
          platform: "linux",
          hostname: "VulnOSv2",
          distro: "Ubuntu 14.04.4 LTS",
          volumes: 4,
          partitions: 2,
          logical_volumes: 2,
          filesystems: ["ext4"],
          installations: 1,
          volume_diagnostics: [
            { volume_id: 3, size_bytes: 254803968, filesystem: "ext4", ok: true, status: "readable", explanation: "Readable ext4 filesystem.", detected_signature: null, kind: "partition", name: null, container_volume_id: null },
            {
              volume_id: 7,
              size_bytes: 33568063488,
              filesystem: null,
              ok: true,
              status: "container",
              explanation: "LVM2 physical volume, parsed successfully. 1 of 2 logical volumes found inside were read as supported filesystems -- see below.",
              detected_signature: "LVM2 physical volume",
              kind: "partition",
              name: null,
              container_volume_id: null,
            },
            { volume_id: 10700001, size_bytes: 8000000000, filesystem: "ext4", ok: true, status: "readable", explanation: "Readable ext4 filesystem.", detected_signature: null, kind: "logical_volume", name: "root", container_volume_id: 7 },
            { volume_id: 10700002, size_bytes: 1000000000, filesystem: null, ok: false, status: "unreadable", explanation: "Kairon could not identify a supported filesystem inside this logical volume, so operating system detection cannot continue inside it.", detected_signature: null, kind: "logical_volume", name: "swap_1", container_volume_id: 7 },
          ],
        },
      }),
    }));
    renderWizard();
    await goToFileStep(/Artifact Collection/);

    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, new File(["disk-bytes"], "webserver.e01"));
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));

    const report = await screen.findByTestId("preflight-report");
    expect(within(report).getByText("Logical volumes:")).toBeInTheDocument();
    // "Partitions" counts real partitions only -- the two logical volumes
    // are counted and labeled separately.
    expect(within(report).getByText("Partitions:").closest("p")).toHaveTextContent("Partitions: 2");
    expect(within(report).getByText("Logical volumes:").closest("p")).toHaveTextContent("Logical volumes: 2");

    const diagnostics = within(report).getByTestId("volume-diagnostics");
    // The obsolete "Kairon does not yet discover logical volumes" wording
    // must never appear anywhere in this section.
    expect(within(diagnostics).queryByText(/does not yet discover/i)).not.toBeInTheDocument();
    expect(within(diagnostics).queryByText(/does not currently parse this container format/i)).not.toBeInTheDocument();

    // The container itself is presented as a successful discovery.
    expect(within(diagnostics).getByText(/parsed successfully/i)).toBeInTheDocument();
    expect(within(diagnostics).getByText(/1 of 2 logical volumes found inside were read/i)).toBeInTheDocument();
    const containerRow = within(diagnostics).getByText(/parsed successfully/i).closest('[data-testid="volume-diagnostic-row"]') as HTMLElement;
    expect(containerRow).toHaveClass("border-mint/30"); // success styling, not a warning

    // Logical volumes are labeled distinctly from partitions, and reference
    // the partition (container) they were found inside of.
    expect(within(diagnostics).getByText(/Logical Volume — root/)).toBeInTheDocument();
    expect(within(diagnostics).getByText(/Logical Volume — swap_1/)).toBeInTheDocument();
    expect(within(diagnostics).getAllByText(/inside Partition 2/).length).toBe(2);

    // Partial success is shown, not total failure: "root" reads as
    // successful (mint), "swap_1" as a specific, non-alarming failure (amber).
    const rootRow = within(diagnostics).getByText(/Logical Volume — root/).closest('[data-testid="volume-diagnostic-row"]') as HTMLElement;
    const swapRow = within(diagnostics).getByText(/Logical Volume — swap_1/).closest('[data-testid="volume-diagnostic-row"]') as HTMLElement;
    expect(rootRow).toHaveClass("border-mint/30");
    expect(swapRow).toHaveClass("border-amber/30");
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
    const startButton = screen.getByRole("button", { name: "Start Processing" });
    expect(startButton).toBeDisabled();

    await userEvent.selectOptions(within(screen.getByTestId("manual-override-panel")).getByRole("combobox"), "collection");
    await userEvent.click(screen.getByRole("checkbox", { name: /Continue with a manual override/i }));
    expect(startButton).toBeEnabled();
  });

  it("promotes each detected file separately in a multi-file auto-detect batch", async () => {
    const archiveFile = new File(["zip-bytes"], "collection.zip", { type: "application/zip" });
    const diskFile = new File(["disk-bytes"], "disk.E01");
    createEvidenceUploadSessionMock
      .mockResolvedValueOnce(sessionResponse({
        session: { ...sessionResponse().session, id: "session-archive", original_filename: "collection.zip" },
        preflight: readyReport({ token: "tok-archive", original_filename: "collection.zip" }),
      }))
      .mockResolvedValueOnce(sessionResponse({
        session: { ...sessionResponse().session, id: "session-disk", original_filename: "disk.E01" },
        preflight: readyReport({
          token: "tok-disk",
          original_filename: "disk.E01",
          classification: {
            ...readyReport().classification,
            category: "disk_image",
            container: "EWF disk image",
            contained_object: "1 OS installation(s)",
            hostname: "diskhost",
            chain: ["Disk Image"],
          },
          pipeline_preview: ["Disk Image", "Evidence Classification", "Partition Discovery", "Indexing"],
        }),
      }));
    promoteEvidenceUploadSessionMock
      .mockResolvedValueOnce({ id: "evidence-archive", original_filename: "collection.zip", evidence_type: "archive" })
      .mockResolvedValueOnce({ id: "evidence-disk", original_filename: "disk.E01", evidence_type: "disk_image" });

    renderWizard();
    await goToFileStep(/Artifact Collection/);
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, [archiveFile, diskFile]);
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));

    await screen.findByTestId("preflight-report");
    expect(screen.getAllByTestId("detection-result-row")).toHaveLength(2);
    expect(screen.getByText("collection.zip")).toBeInTheDocument();
    expect(screen.getByText("disk.E01")).toBeInTheDocument();

    await screen.findByRole("heading", { name: "Confirm evidence" });
    await userEvent.click(screen.getByRole("button", { name: "Start Processing" }));

    expect(createEvidenceUploadSessionMock).toHaveBeenNthCalledWith(1, "case-1", { file: archiveFile }, expect.objectContaining({ declaredPlatform: "auto" }));
    expect(createEvidenceUploadSessionMock).toHaveBeenNthCalledWith(2, "case-1", { file: diskFile }, expect.objectContaining({ declaredPlatform: "auto" }));
    await waitFor(() => expect(promoteEvidenceUploadSessionMock).toHaveBeenCalledTimes(2));
    expect(promoteEvidenceUploadSessionMock).toHaveBeenNthCalledWith(1, "case-1", "session-archive", expect.objectContaining({ provided_host: "web01" }));
    expect(promoteEvidenceUploadSessionMock).toHaveBeenNthCalledWith(2, "case-1", "session-disk", expect.objectContaining({ provided_host: "diskhost" }));
    await waitFor(() => expect(runEvidenceIndexingPlanMock).toHaveBeenCalledTimes(2));
  });

  it("requires an explicit acknowledgement when a forced route conflicts with disk-memory detection", async () => {
    createEvidenceUploadSessionMock.mockResolvedValue(sessionResponse({
      preflight: readyReport({
        token: "tok-memory",
        original_filename: "capture.mem",
        classification: {
          ...readyReport().classification,
          category: "memory_dump",
          container: "Raw memory candidate",
          confidence: "low",
          reason: "Ambiguous raw memory candidate",
          chain: ["Memory Dump"],
        },
      }),
    }));
    renderWizard();
    await goToFileStep(/Artifact Collection/);

    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, new File(["mem"], "capture.mem"));
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));

    await screen.findByTestId("preflight-report");
    const startButton = screen.getByRole("button", { name: "Start Processing" });
    await userEvent.selectOptions(within(screen.getByTestId("manual-override-panel")).getByRole("combobox"), "disk_image");
    expect(screen.getByTestId("wrong-route-warning")).toBeInTheDocument();
    expect(startButton).toBeDisabled();

    await userEvent.click(screen.getByRole("checkbox", { name: /Process anyway/i }));
    await userEvent.click(screen.getByRole("checkbox", { name: /authorized to handle this RAM evidence/i }));
    expect(startButton).toBeEnabled();
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
      preflight: readyReport({ original_filename: "disk.E01", classification: { ...readyReport().classification, category: "disk_image", chain: ["Disk Image"], container: "EWF disk image" } }),
    }));
    renderWizard();
    await goToFileStep(/Disk Image/);
    const file = new File(["x"], "disk.E01");
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, file);
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));
    await screen.findByTestId("preflight-report");
    await screen.findByRole("heading", { name: "Confirm evidence" });
    expect(screen.queryByTestId("host-required-message")).not.toBeInTheDocument();
    expect(screen.getByText("Ready to process")).toBeInTheDocument();
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
    await screen.findByRole("heading", { name: "Confirm evidence" });
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
    expect(screen.getAllByText(/web01/).length).toBeGreaterThan(0);
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
    const hostPanel = await openEvidenceAdvancedOptions();
    expect(within(hostPanel).getByLabelText(/Auto assign to web01/i)).toBeChecked();
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
    const hostPanel = await openEvidenceAdvancedOptions();
    expect(within(hostPanel).getByTestId("host-assignment-guidance")).toHaveTextContent(/Multiple hosts match/i);
    expect(screen.getByRole("button", { name: "Start Processing" })).toBeDisabled();
    await userEvent.click(within(hostPanel).getByRole("radio", { name: /Existing host/i }));
    await userEvent.selectOptions(within(hostPanel).getByRole("combobox"), "host-b");
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
    const hostPanel = await openEvidenceAdvancedOptions();
    expect(within(hostPanel).getByTestId("host-assignment-guidance")).toHaveTextContent(/Enter a hostname/i);
    const startButton = screen.getByRole("button", { name: "Start Processing" });
    expect(startButton).toBeDisabled();
    await userEvent.type(within(hostPanel).getByPlaceholderText("DESKTOP-7FQ2A1"), "NEW-HOST");
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
    const hostPanel = await openEvidenceAdvancedOptions();
    await userEvent.click(screen.getByRole("radio", { name: /Save only/i }));
    await userEvent.click(within(hostPanel).getByRole("radio", { name: /Keep unassigned/i }));
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
    await screen.findByRole("heading", { name: "Confirm evidence" });
    await openEvidenceAdvancedOptions();
    await userEvent.click(screen.getByRole("radio", { name: /Custom/i }));
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
    await screen.findByRole("heading", { name: "Confirm evidence" });
    await openEvidenceAdvancedOptions();
    await userEvent.click(screen.getByRole("radio", { name: /Save only/i }));
    await userEvent.click(screen.getByRole("button", { name: "Save Evidence" }));

    await waitFor(() => expect(promoteEvidenceUploadSessionMock).toHaveBeenCalledWith("case-1", "session-1", expect.objectContaining({})));
    expect(runEvidenceIndexingPlanMock).not.toHaveBeenCalled();
  });

  it.skip("lets the analyst assign an existing host before continuing", async () => {
    renderWizard();
    await passHealthCheck();
    await userEvent.click(screen.getByRole("button", { name: /Artifact Collection/ }));
    await userEvent.click(screen.getByRole("button", { name: "Continue" })); // platform -> host step

    await screen.findByText("Host");
    await userEvent.click(screen.getByRole("radio", { name: "Assign existing host" }));
    expect(screen.getByRole("option", { name: "WS-01" })).toBeInTheDocument();
  });

  it.skip("keeps Auto Assign available for non-memory evidence", async () => {
    renderWizard();
    await passHealthCheck();
    await userEvent.click(screen.getByRole("button", { name: /Artifact Collection/ }));
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));

    expect(await screen.findByRole("radio", { name: "Auto Assign" })).toBeInTheDocument();
  });

  it.skip("requires an explicit host before memory evidence can continue", async () => {
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

  it.skip("folder flow promotes the upload session on Start Processing", async () => {
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

  it.skip("server path flow registers via the upload session on Start Processing", async () => {
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
      preflight: readyReport({ original_filename: "capture.mem", classification: { ...readyReport().classification, category: "memory_dump" }, pipeline_preview: ["Memory Dump", "Evidence Classification", "Memory Registration", "Memory Analysis (manual, after ingestion)"] }),
    }));
    renderWizard();
    await goToFileStep(/Memory Dump/);
    const file = new File(["x"], "capture.mem");
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, file);
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));
    await screen.findByTestId("preflight-report");
    await screen.findByRole("heading", { name: "Confirm evidence" });
    const startButton = screen.getByRole("button", { name: "Start Processing" });
    expect(startButton).toBeDisabled();

    await userEvent.click(screen.getByRole("checkbox", { name: /authorized to handle this RAM evidence/i }));
    expect(startButton).toBeEnabled();

    await userEvent.click(startButton);
    await waitFor(() => expect(promoteEvidenceUploadSessionMock).toHaveBeenCalledWith("case-1", "session-1", expect.objectContaining({ provided_host: "web01", memory_authorization_acknowledged: true })));
    expect(runEvidenceIndexingPlanMock).not.toHaveBeenCalled();

    // Registering memory evidence no longer navigates away immediately --
    // it shows a read-only Memory Preparation step first (Phase 2).
    expect(navigateMock).not.toHaveBeenCalled();
    await screen.findByRole("heading", { name: "Evidence registered" });
    await waitFor(() => expect(getMemoryEvidencePreparationMock).toHaveBeenCalledWith("case-1", "evidence-3"));
    expect(await screen.findByTestId("memory-evidence-preparation-card")).toHaveTextContent(/Ready for analysis/i);

    await userEvent.click(screen.getByRole("button", { name: "Continue" }));
    await waitFor(() => expect(navigateMock).toHaveBeenCalledWith("/cases/case-1/m/evidence-3/overview"));
  });

  it("shows the SYMBOLS_REQUIRED preparation status when the backend reports it", async () => {
    promoteEvidenceUploadSessionMock.mockResolvedValue({ id: "evidence-3", original_filename: "capture.mem", evidence_type: "memory_dump" });
    getMemoryEvidencePreparationMock.mockResolvedValue({
      evidence_id: "evidence-3",
      platform: "linux",
      architecture: "x64",
      readiness: "symbols_required",
      requires_symbols: true,
      can_start_analysis: false,
      human_message: "This Linux dump requires Volatility symbols (ISF) Kairon does not currently have.",
    });
    createEvidenceUploadSessionMock.mockResolvedValue(sessionResponse({
      preflight: readyReport({ original_filename: "capture.mem", classification: { ...readyReport().classification, category: "memory_dump" } }),
    }));
    renderWizard();
    await goToFileStep(/Memory Dump/);
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, new File(["x"], "capture.mem"));
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));
    await screen.findByTestId("preflight-report");
    await userEvent.click(screen.getByRole("checkbox", { name: /authorized to handle this RAM evidence/i }));
    await userEvent.click(screen.getByRole("button", { name: "Start Processing" }));

    const card = await screen.findByTestId("memory-evidence-preparation-card");
    expect(card).toHaveAttribute("data-ui-state", "symbols_required");
    expect(card).toHaveTextContent(/Additional resources are required/i);
    expect(card).toHaveTextContent(/Volatility symbols/i);
    // No action buttons on this read-only view.
    expect(screen.queryByRole("button", { name: /upload/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /validate/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /retry/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /start analysis/i })).not.toBeInTheDocument();
  });

  // ---------------------------------------------------------------------
  // Phase 3A: Start memory analysis golden path from step 6
  // ---------------------------------------------------------------------

  it("shows Start memory analysis as the primary action once preparation is ready, with Continue demoted to secondary", async () => {
    await reachMemoryPreparationStep({ id: "evidence-3", original_filename: "capture.mem" });

    const startButton = await screen.findByTestId("memory-initial-analysis-start-button");
    expect(startButton).toBeInTheDocument();

    const continueButton = screen.getByTestId("memory-preparation-continue-button");
    expect(continueButton).toBeInTheDocument();
    expect(continueButton.className).not.toContain("bg-accent");
  });

  it("does not show Start memory analysis, and keeps Continue as the primary action, when preparation is not ready", async () => {
    getMemoryEvidencePreparationMock.mockResolvedValue({
      evidence_id: "evidence-3",
      platform: "linux",
      architecture: "x64",
      readiness: "symbols_required",
      requires_symbols: true,
      can_start_analysis: false,
      human_message: "This Linux dump requires Volatility symbols (ISF) Kairon does not currently have.",
    });
    await reachMemoryPreparationStep({ id: "evidence-3", original_filename: "capture.mem" });

    expect(screen.queryByTestId("memory-initial-analysis-start-button")).not.toBeInTheDocument();
    const continueButton = await screen.findByTestId("memory-preparation-continue-button");
    expect(continueButton.className).toContain("bg-accent");
  });

  it("clicking Start memory analysis calls startMemoryScan with processes_basic, never metadata_only", async () => {
    startMemoryScanMock.mockResolvedValue({
      accepted: true, evidence_id: "evidence-3", run_id: "run-1", status: "queued", message: "queued",
      run: { id: "run-1", case_id: "case-1", evidence_id: "evidence-3", backend: "volatility3", profile: "processes_basic", status: "queued", requested_plugin_count: 2, plugin_count: 2, plugins_completed: 0, plugins_failed: 0, plugins_skipped: 0, started_at: null, completed_at: null, duration_ms: null, output_dir: null, metadata_json: {}, error_log: {}, backend_version: null, worker_task_id: null, cancellation_requested: false, created_at: new Date().toISOString() },
    });
    await reachMemoryPreparationStep({ id: "evidence-3", original_filename: "capture.mem" });

    await userEvent.click(await screen.findByTestId("memory-initial-analysis-start-button"));

    await waitFor(() => expect(startMemoryScanMock).toHaveBeenCalledWith("case-1", "evidence-3", "processes_basic"));
    expect(startMemoryScanMock).not.toHaveBeenCalledWith("case-1", "evidence-3", "metadata_only");
  });

  it("refresh/reopen with an already-completed initial analysis shows View memory results, not Start", async () => {
    listMemoryRunsMock.mockResolvedValue([
      { id: "run-1", case_id: "case-1", evidence_id: "evidence-3", backend: "volatility3", profile: "processes_basic", status: "completed", requested_plugin_count: 2, plugin_count: 2, plugins_completed: 2, plugins_failed: 0, plugins_skipped: 0, started_at: new Date().toISOString(), completed_at: new Date().toISOString(), duration_ms: 900, output_dir: null, metadata_json: {}, error_log: {}, backend_version: null, worker_task_id: null, cancellation_requested: false, created_at: new Date().toISOString() },
    ]);
    await reachMemoryPreparationStep({ id: "evidence-3", original_filename: "capture.mem" });

    expect(await screen.findByTestId("memory-initial-analysis-completed")).toBeInTheDocument();
    expect(screen.queryByTestId("memory-initial-analysis-start-button")).not.toBeInTheDocument();
    expect(startMemoryScanMock).not.toHaveBeenCalled();

    expect(navigateMock).not.toHaveBeenCalled();
    await userEvent.click(screen.getByTestId("memory-initial-analysis-view-results-button"));
    await waitFor(() => expect(navigateMock).toHaveBeenCalledWith("/cases/case-1/m/evidence-3/overview"));
  });

  it("never shows the Memory Preparation step or card for non-memory evidence", async () => {
    promoteEvidenceUploadSessionMock.mockResolvedValue({ id: "evidence-disk-x", original_filename: "disk.E01", evidence_type: "disk_image" });
    createEvidenceUploadSessionMock.mockResolvedValue(sessionResponse({
      session: { ...sessionResponse().session, id: "session-disk-x", original_filename: "disk.E01" },
      preflight: readyReport({ original_filename: "disk.E01", classification: { ...readyReport().classification, category: "disk_image", chain: ["Disk Image"], container: "EWF disk image" } }),
    }));
    renderWizard();
    await goToFileStep(/Disk Image/);
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, new File(["x"], "disk.E01"));
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));
    await screen.findByTestId("preflight-report");
    await userEvent.click(screen.getByRole("button", { name: "Start Processing" }));

    await waitFor(() => expect(navigateMock).toHaveBeenCalledWith("/cases/case-1?tab=processing&evidence_id=evidence-disk-x"));
    expect(screen.queryByTestId("memory-evidence-preparation-card")).not.toBeInTheDocument();
    expect(screen.queryByTestId("memory-evidence-preparation-step")).not.toBeInTheDocument();
    expect(getMemoryEvidencePreparationMock).not.toHaveBeenCalled();
  });

  it("shows a visible host requirement for memory evidence with no detected host", async () => {
    createEvidenceUploadSessionMock.mockResolvedValue(sessionResponse({
      preflight: readyReport({
        original_filename: "capture.mem",
        classification: { ...readyReport().classification, category: "memory_dump", hostname: null, chain: ["Memory Dump"], container: "Raw memory candidate" },
        pipeline_preview: ["Memory Dump", "Evidence Classification", "Memory Registration", "Memory Analysis (manual, after ingestion)"],
      }),
    }));
    renderWizard();
    await goToFileStep(/Memory Dump/);
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, new File(["x"], "capture.mem"));
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));
    await screen.findByTestId("preflight-report");

    expect(screen.getByTestId("host-required-message")).toHaveTextContent(/This evidence must be associated with a host before processing/i);
    expect(screen.getByTestId("host-assignment-panel")).toBeInTheDocument();
    expect(screen.getByText(/Status:/).parentElement).toHaveTextContent(/action required/i);
    expect(screen.queryByText("Ready to process")).not.toBeInTheDocument();
    const startButton = screen.getByRole("button", { name: "Start Processing" });
    expect(startButton).toBeDisabled();
    expect(screen.getByTestId("host-assignment-guidance")).toHaveTextContent(/Enter a hostname/i);
  });

  it("marks memory evidence ready after selecting an existing host", async () => {
    createEvidenceUploadSessionMock.mockResolvedValue(sessionResponse({
      preflight: readyReport({ classification: { ...readyReport().classification, category: "memory_dump", hostname: null, chain: ["Memory Dump"], container: "Raw memory candidate" } }),
    }));
    renderWizard();
    await goToFileStep(/Memory Dump/);
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, new File(["x"], "capture.mem"));
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));
    await screen.findByTestId("preflight-report");

    const hostPanel = screen.getByTestId("host-assignment-panel");
    await userEvent.click(within(hostPanel).getByRole("radio", { name: /Existing host/i }));
    await userEvent.selectOptions(within(hostPanel).getByRole("combobox"), "host-1");

    expect(screen.queryByTestId("host-required-message")).not.toBeInTheDocument();
    expect(screen.getByText(/Assign to host:/).parentElement).toHaveTextContent("WS-01");
    expect(screen.getByText("Ready to process")).toBeInTheDocument();
    const startButton = screen.getByRole("button", { name: "Start Processing" });
    expect(startButton).toBeDisabled();
    await userEvent.click(screen.getByRole("checkbox", { name: /authorized to handle this RAM evidence/i }));
    expect(startButton).toBeEnabled();
  });

  it("marks memory evidence ready after entering a new host", async () => {
    promoteEvidenceUploadSessionMock.mockResolvedValue({ id: "evidence-new-host", original_filename: "capture.mem", evidence_type: "memory_dump" });
    createEvidenceUploadSessionMock.mockResolvedValue(sessionResponse({
      preflight: readyReport({ classification: { ...readyReport().classification, category: "memory_dump", hostname: null, chain: ["Memory Dump"], container: "Raw memory candidate" } }),
    }));
    renderWizard();
    await goToFileStep(/Memory Dump/);
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, new File(["x"], "capture.mem"));
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));
    await screen.findByTestId("preflight-report");

    const hostPanel = screen.getByTestId("host-assignment-panel");
    await userEvent.click(within(hostPanel).getByRole("radio", { name: /New host/i }));
    await userEvent.type(within(hostPanel).getByPlaceholderText("DESKTOP-7FQ2A1"), "MEMHOST-01");

    expect(screen.queryByTestId("host-required-message")).not.toBeInTheDocument();
    expect(screen.getByText(/Assign to host:/).parentElement).toHaveTextContent("MEMHOST-01");
    expect(screen.getByText("Ready to process")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("checkbox", { name: /authorized to handle this RAM evidence/i }));
    await userEvent.click(screen.getByRole("button", { name: "Start Processing" }));

    await waitFor(() => expect(createCaseHostMock).toHaveBeenCalledWith("case-1", { host_name: "MEMHOST-01", reason: "Created during evidence ingestion wizard" }));
    await waitFor(() => expect(promoteEvidenceUploadSessionMock).toHaveBeenCalledWith("case-1", "session-1", expect.objectContaining({ host_id: "host-created", memory_authorization_acknowledged: true })));
  });

  describe("generalized host requirement (any evidence type, not just memory)", () => {
    it("shows a visible host requirement for a non-memory archive with no detected host, without opening Advanced", async () => {
      createEvidenceUploadSessionMock.mockResolvedValue(sessionResponse({
        preflight: readyReport({
          original_filename: "windows-artifacts.zip",
          classification: { ...readyReport().classification, category: "archive", platform: "windows", hostname: null, chain: ["Archive"], container: "ZIP archive" },
        }),
      }));
      renderWizard();
      await goToFileStep(/Artifact Collection/);
      await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, new File(["x"], "windows-artifacts.zip"));
      await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));
      await screen.findByTestId("preflight-report");

      // Visible without ever opening "Advanced -- evidence options".
      expect(screen.getByTestId("host-required-message")).toHaveTextContent(/This evidence must be associated with a host before processing/i);
      expect(screen.getByTestId("host-assignment-panel")).toBeInTheDocument();
      expect(screen.queryByText("Ready to process")).not.toBeInTheDocument();
      const startButton = screen.getByRole("button", { name: "Start Processing" });
      expect(startButton).toBeDisabled();
      expect(screen.getByTestId("start-processing-host-reason")).toHaveTextContent(/Select a host before starting processing/i);
    });

    it("enables Start Processing and sends the selected host once a host is chosen for a non-memory archive", async () => {
      promoteEvidenceUploadSessionMock.mockResolvedValue({ id: "evidence-win-archive", original_filename: "windows-artifacts.zip" });
      createEvidenceUploadSessionMock.mockResolvedValue(sessionResponse({
        preflight: readyReport({
          original_filename: "windows-artifacts.zip",
          classification: { ...readyReport().classification, category: "archive", platform: "windows", hostname: null, chain: ["Archive"], container: "ZIP archive" },
        }),
      }));
      renderWizard();
      await goToFileStep(/Artifact Collection/);
      await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, new File(["x"], "windows-artifacts.zip"));
      await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));
      await screen.findByTestId("preflight-report");

      const hostPanel = screen.getByTestId("host-assignment-panel");
      await userEvent.click(within(hostPanel).getByRole("radio", { name: /Existing host/i }));
      await userEvent.selectOptions(within(hostPanel).getByRole("combobox", { name: "Existing host" }), "host-1");

      expect(screen.queryByTestId("host-required-message")).not.toBeInTheDocument();
      expect(screen.getByText("Ready to process")).toBeInTheDocument();
      const startButton = screen.getByRole("button", { name: "Start Processing" });
      expect(startButton).toBeEnabled();

      await userEvent.click(startButton);
      await waitFor(() => expect(promoteEvidenceUploadSessionMock).toHaveBeenCalledWith("case-1", "session-1", expect.objectContaining({ host_id: "host-1" })));
    });

    it("does not require or show a mandatory host selector when the evidence already has a detected host", async () => {
      // Default readyReport() already carries a detected hostname ("web01").
      renderWizard();
      await goToFileStep(/Artifact Collection/);
      await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, new File(["x"], "collection.zip"));
      await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));
      await screen.findByTestId("preflight-report");

      expect(screen.queryByTestId("host-required-message")).not.toBeInTheDocument();
      expect(screen.getByText("Ready to process")).toBeInTheDocument();
      expect(screen.getByRole("button", { name: "Start Processing" })).toBeEnabled();
      // The panel is still reachable (optional), just not forced open.
      expect(await openEvidenceAdvancedOptions()).toBeInTheDocument();
    });

    it("does not render a duplicate host selector when Advanced is opened while the host requirement is already visible", async () => {
      createEvidenceUploadSessionMock.mockResolvedValue(sessionResponse({
        preflight: readyReport({
          classification: { ...readyReport().classification, category: "archive", platform: "windows", hostname: null },
        }),
      }));
      renderWizard();
      await goToFileStep(/Artifact Collection/);
      await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, new File(["x"], "collection.zip"));
      await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));
      await screen.findByTestId("preflight-report");
      expect(screen.getByTestId("host-assignment-panel")).toBeInTheDocument();

      await userEvent.click(screen.getByText(/Advanced — evidence options/i));

      expect(screen.getAllByTestId("host-assignment-panel")).toHaveLength(1);
    });

    it("does not render a duplicate host selector for memory evidence either", async () => {
      createEvidenceUploadSessionMock.mockResolvedValue(sessionResponse({
        preflight: readyReport({
          original_filename: "capture.mem",
          classification: { ...readyReport().classification, category: "memory_dump", hostname: null, chain: ["Memory Dump"], container: "Raw memory candidate" },
        }),
      }));
      renderWizard();
      await goToFileStep(/Memory Dump/);
      await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, new File(["x"], "capture.mem"));
      await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));
      await screen.findByTestId("preflight-report");
      expect(screen.getByTestId("host-assignment-panel")).toBeInTheDocument();

      await userEvent.click(screen.getByText(/Advanced — evidence options/i));

      expect(screen.getAllByTestId("host-assignment-panel")).toHaveLength(1);
    });

    it("does not show 'Ready to process' while a non-memory host requirement is unmet, and shows it once resolved", async () => {
      createEvidenceUploadSessionMock.mockResolvedValue(sessionResponse({
        preflight: readyReport({
          classification: { ...readyReport().classification, category: "collection", platform: "windows", hostname: null },
        }),
      }));
      renderWizard();
      await goToFileStep(/Artifact Collection/);
      await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, new File(["x"], "collection.zip"));
      await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));
      await screen.findByTestId("preflight-report");

      expect(screen.queryByText("Ready to process")).not.toBeInTheDocument();
      const statusLine = screen.getByText(/Status:/).parentElement!;
      expect(statusLine).toHaveTextContent(/action required/i);

      const hostPanel = screen.getByTestId("host-assignment-panel");
      await userEvent.click(within(hostPanel).getByRole("radio", { name: /Existing host/i }));
      await userEvent.selectOptions(within(hostPanel).getByRole("combobox", { name: "Existing host" }), "host-1");

      expect(screen.getByText("Ready to process")).toBeInTheDocument();
      expect(screen.getByText(/Status:/).parentElement).toHaveTextContent(/ready/i);
    });
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
    getMemoryEvidencePreparationMock.mockResolvedValue({
      evidence_id: "evidence-resumed",
      platform: "windows",
      architecture: "x64",
      readiness: "ready",
      requires_symbols: true,
      can_start_analysis: true,
      human_message: "This evidence is ready to analyze.",
    });
    listMemoryRunsMock.mockResolvedValue([]);
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

    // Same Phase 2 behavior as the legacy flow: memory evidence lands on
    // the read-only Memory Preparation step before the wizard navigates.
    await screen.findByRole("heading", { name: "Evidence registered" });
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));
    await waitFor(() => expect(navigateMock).toHaveBeenCalledWith("/cases/case-1/m/evidence-resumed/overview"));
  });

  it("cancels an interrupted upload from the discovery panel", async () => {
    listResumableEvidenceUploadsMock.mockResolvedValue({ case_id: "case-1", sessions: [resumableUnifiedSession()] });
    renderWizard();
    await passHealthCheck();
    const panel = await screen.findByTestId("resumable-uploads-panel");

    await userEvent.click(within(panel).getByRole("button", { name: "Cancel" }));

    await waitFor(() => expect(cancelEvidenceUploadSessionMock).toHaveBeenCalledWith("case-1", "resume-session-1"));
  });

  it("hides the entire interrupted uploads section when there are no unfinished uploads", async () => {
    listResumableEvidenceUploadsMock.mockResolvedValue({ case_id: "case-1", sessions: [] });

    renderWizard();
    await passHealthCheck();

    expect(screen.queryByTestId("resumable-uploads-panel")).not.toBeInTheDocument();
    expect(screen.queryByText(/Interrupted uploads/i)).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Select Evidence" })).toBeInTheDocument();
  });

  it("filters completed and promoted evidence out of the interrupted uploads panel", async () => {
    const completed = resumableUnifiedSession({ id: "resume-session-completed", original_filename: "completed.mem", progress_percent: 100, status: "completed", resumable: false, cancellable: false });
    const completedWithWarnings = resumableUnifiedSession({ id: "resume-session-warnings", original_filename: "warnings.mem", progress_percent: 100, status: "completed_with_warnings", resumable: false, cancellable: false });
    const promoted = resumableUnifiedSession({ id: "resume-session-promoted", original_filename: "evidence.mem", progress_percent: 100, status: "promoted", resumable: false, cancellable: false, promoted_evidence_id: "evidence-1" });
    listResumableEvidenceUploadsMock.mockResolvedValue({ case_id: "case-1", sessions: [completed, completedWithWarnings, promoted] });

    renderWizard();
    await passHealthCheck();

    expect(screen.queryByTestId("resumable-uploads-panel")).not.toBeInTheDocument();
    expect(screen.queryByText("completed.mem")).not.toBeInTheDocument();
    expect(screen.queryByText("warnings.mem")).not.toBeInTheDocument();
    expect(screen.queryByText("evidence.mem")).not.toBeInTheDocument();
  });

  it("keeps interrupted and paused uploads visible while excluding completed evidence", async () => {
    const inProgress = resumableUnifiedSession();
    const paused = resumableUnifiedSession({ id: "resume-session-paused", original_filename: "paused.mem", progress_percent: 62, status: "paused" });
    const promoted = resumableUnifiedSession({ id: "resume-session-done", original_filename: "done.mem", progress_percent: 100, status: "promoted", resumable: false, cancellable: false, promoted_evidence_id: "evidence-done" });
    listResumableEvidenceUploadsMock.mockResolvedValue({ case_id: "case-1", sessions: [inProgress, paused, promoted] });

    renderWizard();
    await passHealthCheck();

    const panel = await screen.findByTestId("resumable-uploads-panel");
    expect(within(panel).getByText("capture.mem")).toBeInTheDocument();
    expect(within(panel).getByText("paused.mem")).toBeInTheDocument();
    expect(within(panel).queryByText("done.mem")).not.toBeInTheDocument();
    expect(within(panel).getAllByTestId("resume-upload-select")).toHaveLength(2);
  });

  it("shows a staged upload awaiting confirmation because it still needs investigator action", async () => {
    const staged = resumableUnifiedSession({ original_filename: "awaiting-confirmation.mem", progress_percent: 100, status: "staged", resumable: false, cancellable: true });
    listResumableEvidenceUploadsMock.mockResolvedValue({ case_id: "case-1", sessions: [staged] });

    renderWizard();
    await passHealthCheck();

    const panel = await screen.findByTestId("resumable-uploads-panel");
    expect(within(panel).getByText("awaiting-confirmation.mem")).toBeInTheDocument();
    expect(within(panel).getByTestId("resume-upload-select")).toBeInTheDocument();
  });

  it("excludes uploads that do not belong to the current case", async () => {
    const otherCasePaused = resumableUnifiedSession({ id: "resume-other-case", case_id: "case-2", original_filename: "other-case.mem", status: "paused", progress_percent: 62 });
    const currentCaseInterrupted = resumableUnifiedSession({ id: "resume-current-case", original_filename: "current-case.mem", status: "interrupted", progress_percent: 31 });
    listResumableEvidenceUploadsMock.mockResolvedValue({ case_id: "case-1", sessions: [otherCasePaused, currentCaseInterrupted] });

    renderWizard();
    await passHealthCheck();

    const panel = await screen.findByTestId("resumable-uploads-panel");
    expect(within(panel).getByText("current-case.mem")).toBeInTheDocument();
    expect(within(panel).queryByText("other-case.mem")).not.toBeInTheDocument();
  });

  it("does not show cancelled or other-case completed uploads", async () => {
    const cancelled = resumableUnifiedSession({ id: "resume-cancelled", original_filename: "cancelled.mem", status: "cancelled", progress_percent: 40, resumable: false, cancellable: false });
    const otherCaseCompleted = resumableUnifiedSession({ id: "resume-other-complete", case_id: "case-2", original_filename: "other-completed.mem", status: "completed", progress_percent: 100, resumable: false, cancellable: false });
    listResumableEvidenceUploadsMock.mockResolvedValue({ case_id: "case-1", sessions: [cancelled, otherCaseCompleted] });

    renderWizard();
    await passHealthCheck();

    expect(screen.queryByTestId("resumable-uploads-panel")).not.toBeInTheDocument();
    expect(screen.queryByText("cancelled.mem")).not.toBeInTheDocument();
    expect(screen.queryByText("other-completed.mem")).not.toBeInTheDocument();
  });
});

describe.skip("EvidenceIngestionWizard unified disk_image uploads", () => {
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
    await userEvent.click(screen.getByText(/Advanced import options/i));
    const file = new File(["x"], "notes.csv");
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, file);

    const panel = await screen.findByTestId("wizard-advanced-options");
    expect(within(panel).getByTestId("evidence-intent-raw")).toBeInTheDocument();
    expect(within(panel).getByTestId("ingest-mode-full-forensic")).toBeInTheDocument();
    // notes.csv is neither .evtx nor an eligible archive -- EVTX profile
    // must not be offered for it.
    expect(within(panel).queryByTestId("evtx-profile-full")).not.toBeInTheDocument();
  });

  it("keeps generic advanced options hidden until explicitly expanded", async () => {
    getIngestionReadinessMock.mockResolvedValue(readyHealth({ wizard_advanced_options_enabled: true }));
    renderWizard();
    await goToFileStep(/Disk Image/);

    expect(screen.queryByTestId("wizard-advanced-options")).not.toBeInTheDocument();
    await userEvent.click(screen.getByText(/Advanced import options/i));
    expect(screen.getByTestId("wizard-advanced-options")).toBeInTheDocument();
  });

  it("shows the EVTX profile option for a .evtx file but not for a plain single file", async () => {
    getIngestionReadinessMock.mockResolvedValue(readyHealth({ wizard_advanced_options_enabled: true }));
    renderWizard();
    await goToFileStep(/Artifact Collection/);
    await userEvent.click(screen.getByText(/Advanced import options/i));
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
    await userEvent.click(screen.getByText(/Advanced import options/i));
    const file = new File(["x"], "notes.csv");
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, file);
    await screen.findByTestId("wizard-advanced-options");
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));
    await screen.findByTestId("preflight-report");
    await screen.findByRole("heading", { name: "Confirm evidence" });
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
    await userEvent.click(screen.getByText(/Advanced import options/i));
    const file = new File(["x"], "export.csv");
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, file);
    const panel = await screen.findByTestId("wizard-advanced-options");
    await userEvent.click(within(panel).getByTestId("evidence-intent-parsed"));
    await userEvent.click(within(panel).getByTestId("ingest-mode-usable-search"));
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));
    await screen.findByTestId("preflight-report");
    await screen.findByRole("heading", { name: "Confirm evidence" });
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
    await userEvent.click(screen.getByText(/Advanced import options/i));
    const file = new File(["x"], "Security.evtx");
    await userEvent.upload(document.querySelector('input[type="file"]') as HTMLInputElement, file);
    const panel = await screen.findByTestId("wizard-advanced-options");
    await userEvent.click(within(panel).getByTestId("evtx-profile-fast"));
    await userEvent.click(screen.getByRole("button", { name: "Inspect evidence" }));
    await screen.findByTestId("preflight-report");
    await screen.findByRole("heading", { name: "Confirm evidence" });
    await userEvent.click(screen.getByRole("button", { name: "Start Processing" }));

    await waitFor(() => expect(promoteEvidenceUploadSessionMock).toHaveBeenCalledWith(
      "case-1", "session-1",
      expect.objectContaining({ evtx_profile: "fast_high_value" }),
    ));
  });
});
