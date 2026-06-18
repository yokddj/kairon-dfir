import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import EvidenceUpload from "./EvidenceUpload";

const navigateMock = vi.fn();
const getStorageCapabilitiesMock = vi.fn();
const getSystemStatusMock = vi.fn();
const validateEvidencePathMock = vi.fn();
const registerEvidencePathMock = vi.fn();
const uploadEvidenceMock = vi.fn();
const uploadEvidenceFolderMock = vi.fn();
const discoverVelociraptorZipMock = vi.fn();
const discoverVelociraptorFolderMock = vi.fn();

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return {
    ...actual,
    useNavigate: () => navigateMock,
  };
});

vi.mock("../api/client", () => ({
  api: {
    getStorageCapabilities: (...args: unknown[]) => getStorageCapabilitiesMock(...args),
    getSystemStatus: (...args: unknown[]) => getSystemStatusMock(...args),
    validateEvidencePath: (...args: unknown[]) => validateEvidencePathMock(...args),
    registerEvidencePath: (...args: unknown[]) => registerEvidencePathMock(...args),
    uploadEvidence: (...args: unknown[]) => uploadEvidenceMock(...args),
    uploadEvidenceFolder: (...args: unknown[]) => uploadEvidenceFolderMock(...args),
    discoverVelociraptorZip: (...args: unknown[]) => discoverVelociraptorZipMock(...args),
    discoverVelociraptorFolder: (...args: unknown[]) => discoverVelociraptorFolderMock(...args),
  },
}));

function renderComponent() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={queryClient}>
        <EvidenceUpload caseId="case-1" />
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

async function openAdvancedOptions() {
  await userEvent.click(screen.getByText(/Advanced options/i));
}

async function selectPrimaryFile(file: File) {
  await userEvent.click(screen.getByRole("button", { name: /Add evidence file/i }));
  const input = document.querySelector('input[type="file"]') as HTMLInputElement;
  await userEvent.upload(input, file);
}

function makeFile(contents: string, name: string, type = "application/octet-stream") {
  const file = new File([contents], name, { type });
  Object.defineProperty(file, "arrayBuffer", {
    value: () => Promise.resolve(new TextEncoder().encode(contents).buffer),
  });
  return file;
}

describe("EvidenceUpload", () => {
  beforeEach(() => {
    vi.unstubAllEnvs();
    navigateMock.mockReset();
    uploadEvidenceMock.mockReset();
    uploadEvidenceFolderMock.mockReset();
    discoverVelociraptorZipMock.mockReset();
    discoverVelociraptorFolderMock.mockReset();
    getSystemStatusMock.mockReset();
    getStorageCapabilitiesMock.mockResolvedValue({
      allow_host_path_import: true,
      allowed_roots: ["/mnt/evidence", "/data/evidence"],
      max_upload_size: 123,
      memory_upload_max_bytes: 5368709120,
      supports_mounted_path: true,
      restart_enabled: false,
      can_edit_deployment_settings: false,
      restart_commands: [],
      enable_instructions: { env: {}, commands: [] },
      allowed_root_details: [],
    });
    getSystemStatusMock.mockResolvedValue({
      evtx_parser_backends: {
        evtxecmd: { available: true, version: "2026.5.0", supports_csv: true, supports_json: false },
        evtx_raw_python: { available: true, role: "fallback" },
      },
      cpu: { percent: 0, count: 4 },
      memory: { total: 1, used: 0, percent: 0 },
      disk: { data_dir_total: 1, data_dir_used: 0, data_dir_percent: 0 },
      queues: {},
      opensearch: { available: true, cluster_status: "green", heap_used_percent: null, indices: 1, docs_count: 0 },
      workers: { active: 1, known: ["worker"] },
      settings: {},
      deployment: {},
    });
    validateEvidencePathMock.mockResolvedValue({
      valid: true,
      exists: true,
      readable: true,
      is_directory: true,
      is_file: false,
      within_allowed_root: true,
      allowed_roots: ["/mnt/evidence", "/data/evidence"],
      looks_like_client_path: false,
      path_style: "server_absolute",
      suggested_action: null,
      message: "Path is valid and readable. It can be registered without copying.",
      resolved_path: "/mnt/evidence/CASE001",
      size_bytes: null,
      file_count: 42,
      warnings: [],
    });
    registerEvidencePathMock.mockResolvedValue({ id: "ev-1" });
    uploadEvidenceMock.mockResolvedValue({ id: "ev-2", evidence_type: "evtx", metadata_json: {}, ingest_status: "pending" });
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("shows a simple four-step upload wizard", () => {
    renderComponent();
    expect(screen.getByTestId("upload-wizard-simple-flow")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: /Select case/i })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: /Identify host/i })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: /Add evidence/i })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: /Review and index/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Index evidence/i })).toBeDisabled();
  });

  it("requires host before starting the primary indexing path", async () => {
    renderComponent();
    await selectPrimaryFile(makeFile("evtx", "Security.evtx"));
    expect(screen.getByLabelText(/Host name required/i)).toBeRequired();
    expect(screen.getByRole("button", { name: /Index evidence/i })).toBeDisabled();
    expect(uploadEvidenceMock).not.toHaveBeenCalled();
  });

  it("indexes a selected file with core indexing metadata and provided host", async () => {
    renderComponent();
    await userEvent.type(screen.getByLabelText(/Host name required/i), "HOSTA");
    await selectPrimaryFile(makeFile("evtx", "Security.evtx"));
    expect(await screen.findByText(/Detected: Windows Event Log/i)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /Index evidence/i }));
    await waitFor(() =>
      expect(uploadEvidenceMock).toHaveBeenCalledWith(
        "case-1",
        expect.any(File),
        expect.objectContaining({
          evidenceIntent: "raw",
          evtxProfile: "full",
          ingestMode: "usable_search",
          packaging: "single_file",
          providedHost: "HOSTA",
        }),
      ),
    );
    expect(await screen.findByRole("button", { name: /Search evidence/i })).toBeInTheDocument();
  });

  it("detects a memory image, shows privacy warning, and does not auto-run analysis", async () => {
    uploadEvidenceMock.mockResolvedValueOnce({ id: "ev-memory", evidence_type: "memory_dump", metadata_json: {}, ingest_status: "completed" });
    renderComponent();
    await userEvent.type(screen.getByLabelText(/Host name required/i), "HOSTA");
    await selectPrimaryFile(makeFile("memory", "authorized.mem"));

    expect(await screen.findByText(/Detected: Memory image/i)).toBeInTheDocument();
    expect(screen.getByText(/Memory images may contain credentials, personal data, encryption material, browser data, and other sensitive information/i)).toBeInTheDocument();
    expect(screen.getByText(/Configured upload limit: 5\.0 GB/i)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /Index evidence/i }));

    await waitFor(() => expect(uploadEvidenceMock).toHaveBeenCalled());
    expect(await screen.findByText(/Memory image uploaded and finalized/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Open Memory Analysis/i })).toBeInTheDocument();
    expect(discoverVelociraptorZipMock).not.toHaveBeenCalled();
  });

  it("keeps advanced options collapsed by default", () => {
    renderComponent();
    expect(screen.getByText(/Advanced options/i)).toBeInTheDocument();
    expect(screen.queryByText(/What are you adding/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Artifact category selection/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/EVTX indexing profile/i)).not.toBeInTheDocument();
  });

  it("shows full forensic processing only under advanced processing", async () => {
    renderComponent();
    expect(screen.queryByText(/Run advanced forensic processing/i)).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /Advanced processing/i }));
    expect(screen.getByText(/Run advanced forensic processing/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Select Advanced/i })).toBeInTheDocument();
  });

  it("does not show EVTX profile choices in the primary flow when EvtxECmd is available", () => {
    renderComponent();
    expect(screen.getByText(/EVTX: Full coverage with EvtxECmd if event logs are found/i)).toBeInTheDocument();
    expect(screen.queryByText(/^Fast EVTX Search$/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/^Full EVTX Indexing$/i)).not.toBeInTheDocument();
  });

  it("shows EVTX advanced beta choices only after advanced options are opened", async () => {
    renderComponent();
    await openAdvancedOptions();
    await userEvent.click(screen.getByText(/Single file/i));
    await userEvent.click(screen.getByRole("button", { name: /Advanced\/Beta EVTX options/i }));
    expect(screen.getByText(/^Fast EVTX Search$/i)).toBeInTheDocument();
    expect(screen.getByText(/^Full EVTX Indexing$/i)).toBeInTheDocument();
  });

  it("surfaces a Python fallback warning when EvtxECmd is unavailable", async () => {
    getSystemStatusMock.mockResolvedValueOnce({
      evtx_parser_backends: {
        evtxecmd: { available: false, version: "", supports_csv: false, supports_json: false },
        evtx_raw_python: { available: true, role: "fallback" },
      },
      cpu: { percent: 0, count: 4 },
      memory: { total: 1, used: 0, percent: 0 },
      disk: { data_dir_total: 1, data_dir_used: 0, data_dir_percent: 0 },
      queues: {},
      opensearch: { available: true, cluster_status: "green", heap_used_percent: null, indices: 1, docs_count: 0 },
      workers: { active: 1, known: ["worker"] },
    });
    renderComponent();
    await openAdvancedOptions();
    expect(await screen.findByText(/Python EVTX fallback/i)).toBeInTheDocument();
    expect(screen.getByText(/may be slow on large evidence/i)).toBeInTheDocument();
  });

  it("preserves advanced raw archive mode when explicitly selected", async () => {
    discoverVelociraptorZipMock.mockResolvedValue({
      evidence: { id: "ev-discovery", evidence_type: "velociraptor_zip", metadata_json: { current_phase: "waiting_selection" }, ingest_status: "pending" },
      discovery: { collection_id: "ev-discovery", collection_root: "/tmp", hostname: null, candidates: [], summary: { total_candidates: 1 }, total_files_scanned: 1, warnings: [] },
    });
    renderComponent();
    await userEvent.type(screen.getByLabelText(/Host name required/i), "HOSTA");
    await userEvent.click(screen.getByRole("button", { name: /Advanced processing/i }));
    await userEvent.click(screen.getByRole("button", { name: /Select Advanced/i }));
    await openAdvancedOptions();
    await userEvent.click(screen.getByRole("button", { name: /^Compressed archive ZIP\/TAR\/7z/i }));
    await userEvent.click(screen.getByRole("button", { name: /Upload RAW evidence archive/i }));
    const input = document.querySelector('input[type="file"]') as HTMLInputElement;
    await userEvent.upload(input, makeFile("raw", "HOSTA.zip", "application/zip"));
    await userEvent.click(screen.getByRole("button", { name: /Index evidence/i }));
    await waitFor(() =>
      expect(discoverVelociraptorZipMock).toHaveBeenCalledWith(
        "case-1",
        expect.any(File),
        expect.objectContaining({ ingestMode: "full_forensic", providedHost: "HOSTA" }),
      ),
    );
  });

  it("keeps server path registration in advanced options and requires host", async () => {
    renderComponent();
    await openAdvancedOptions();
    await userEvent.click(screen.getByRole("button", { name: /^Server-mounted path Evidence already available/i }));
    expect(screen.getByRole("button", { name: /Validate path/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Register path and ingest/i })).toBeDisabled();
    await userEvent.type(screen.getByLabelText(/Host name required/i), "HOSTA");
    await userEvent.type(screen.getByPlaceholderText("/mnt/evidence/case001 or /mnt/evidence/case001/archive.7z"), "/mnt/evidence/CASE001");
    await userEvent.click(screen.getByRole("button", { name: /Validate path/i }));
    await waitFor(() => expect(validateEvidencePathMock).toHaveBeenCalled());
    expect(await screen.findByText(/within allowed root:/i)).toBeInTheDocument();
  });

  it("links to system settings when mounted path import is disabled", async () => {
    getStorageCapabilitiesMock.mockResolvedValueOnce({
      allow_host_path_import: false,
      allowed_roots: ["/mnt/evidence"],
      max_upload_size: 123,
      supports_mounted_path: true,
      restart_enabled: false,
      can_edit_deployment_settings: false,
      restart_commands: [],
      enable_instructions: { env: {}, commands: [] },
      allowed_root_details: [],
    });
    renderComponent();
    await openAdvancedOptions();
    await userEvent.click(screen.getByRole("button", { name: /^Server-mounted path Evidence already available/i }));
    expect((await screen.findAllByText(/Mounted path import is disabled/i)).length).toBeGreaterThan(0);
    await userEvent.click(screen.getByRole("button", { name: /Open System \/ Performance/i }));
    expect(navigateMock).toHaveBeenCalledWith("/system/performance?tab=evidence-storage");
  });
});
