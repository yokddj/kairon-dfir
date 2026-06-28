import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import MemoryUploadPage from "./MemoryUploadPage";

const getMemoryUploadReadinessMock = vi.fn();
const getActiveMemoryUploadMock = vi.fn();
const getMemoryUploadStatusMock = vi.fn();
const createMemoryUploadSessionMock = vi.fn();
const uploadMemoryUploadChunkMock = vi.fn();
const finalizeMemoryUploadMock = vi.fn();
const reconcileMemoryUploadMock = vi.fn();
const retryMemoryUploadRegistrationMock = vi.fn();
const getEvidenceMock = vi.fn();
const cancelMemoryUploadMock = vi.fn();
const navigateMock = vi.fn();

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return {
    ...actual,
    useNavigate: () => navigateMock,
  };
});

vi.mock("../api/client", () => ({
  api: {
    getMemoryUploadReadiness: (...args: unknown[]) => getMemoryUploadReadinessMock(...args),
    getActiveMemoryUpload: (...args: unknown[]) => getActiveMemoryUploadMock(...args),
    getMemoryUploadStatus: (...args: unknown[]) => getMemoryUploadStatusMock(...args),
    createMemoryUploadSession: (...args: unknown[]) => createMemoryUploadSessionMock(...args),
    uploadMemoryUploadChunk: (...args: unknown[]) => uploadMemoryUploadChunkMock(...args),
    finalizeMemoryUpload: (...args: unknown[]) => finalizeMemoryUploadMock(...args),
    reconcileMemoryUpload: (...args: unknown[]) => reconcileMemoryUploadMock(...args),
    retryMemoryUploadRegistration: (...args: unknown[]) => retryMemoryUploadRegistrationMock(...args),
    getEvidence: (...args: unknown[]) => getEvidenceMock(...args),
    cancelMemoryUpload: (...args: unknown[]) => cancelMemoryUploadMock(...args),
  },
}));

vi.mock("../context/ActiveCaseContext", () => ({
  useActiveCase: () => ({ setActiveCaseId: vi.fn() }),
}));

function readiness(overrides = {}) {
  return {
    case_id: "case-1",
    upload_enabled: true,
    max_upload_bytes: 34_359_738_368,
    max_upload_display: "32 GiB",
    recommended_chunk_size_bytes: 67_108_864,
    resumable: true,
    max_parallel_chunks: 2,
    case_quota_bytes: 107_374_182_400,
    case_quota_remaining_bytes: 107_374_182_400,
    allowed_extensions: [".raw", ".mem", ".vmem", ".dmp", ".lime"],
    staging_available_bytes: 200 * 1024 * 1024 * 1024,
    canonical_storage_available_bytes: 200 * 1024 * 1024 * 1024,
    memory_output_available_bytes: 200 * 1024 * 1024 * 1024,
    recommended_max_upload_bytes: 34_359_738_368,
    required_capacity_bytes: 0,
    can_accept_selected_size: true,
    finalization_strategy: "atomic_move",
    analysis_enabled: true,
    dedicated_worker_online: true,
    backend_ready: true,
    message: "Memory image upload is available and the dedicated memory worker is ready.",
    ...overrides,
  };
}

function uploadStatus(overrides = {}) {
  return {
    upload_id: "upload-1",
    case_id: "case-1",
    evidence_id: null,
    status: "created",
    bytes_received: 0,
    expected_bytes: 6,
    expected_sha256: null,
    chunk_size_bytes: 4,
    total_chunks: 2,
    received_chunk_count: 0,
    received_chunks: [],
    missing_chunks: [0, 1],
    progress_percent: 0,
    filename: "authorized.mem",
    extension: ".mem",
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 3600_000).toISOString(),
    finalized_at: null,
    failure_code: null,
    failure_message: null,
    message: "Upload session created. Ready to receive chunks.",
    retryable: false,
    ...overrides,
  };
}

function conflictError(detail: Record<string, unknown>) {
  return { status: 409, errorCode: "MEMORY_UPLOAD_ACTIVE_SESSION_EXISTS", detail, message: "Another upload session for this memory image is already active." };
}

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <MemoryRouter initialEntries={["/cases/case-1/memory/upload"]}>
      <QueryClientProvider client={queryClient}>
        <Routes>
          <Route path="/cases/:caseId/memory/upload" element={<MemoryUploadPage />} />
        </Routes>
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("MemoryUploadPage", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    localStorage.clear();
    getMemoryUploadReadinessMock.mockResolvedValue(readiness());
    getActiveMemoryUploadMock.mockResolvedValue(null);
    getMemoryUploadStatusMock.mockResolvedValue(uploadStatus());
    createMemoryUploadSessionMock.mockResolvedValue(uploadStatus());
    uploadMemoryUploadChunkMock.mockResolvedValue(uploadStatus({ status: "uploading", bytes_received: 6, received_chunk_count: 2, received_chunks: [0, 1], missing_chunks: [] }));
    finalizeMemoryUploadMock.mockResolvedValue(uploadStatus({ status: "completed", evidence_id: "ev-memory", bytes_received: 6, missing_chunks: [], received_chunk_count: 2, progress_percent: 100, message: "Memory image uploaded and registered." }));
    reconcileMemoryUploadMock.mockResolvedValue(uploadStatus({ status: "finalizing", bytes_received: 6, missing_chunks: [] }));
    retryMemoryUploadRegistrationMock.mockResolvedValue(uploadStatus({ status: "completed", evidence_id: "ev-memory", message: "Memory image uploaded and registered." }));
    getEvidenceMock.mockResolvedValue({ id: "ev-memory", evidence_type: "memory_dump", size_bytes: 6, sha256: "0".repeat(64) });
    cancelMemoryUploadMock.mockResolvedValue(uploadStatus({ status: "cancelled" }));
  });

  it("renders resumable readiness metadata", async () => {
    renderPage();
    expect(await screen.findByRole("heading", { name: /Add memory image/i })).toBeInTheDocument();
    expect(await screen.findByText(/32 GiB/i)).toBeInTheDocument();
    expect(await screen.findByText(/64\.0 MiB/i)).toBeInTheDocument();
    expect(await screen.findByText(/Case quota remaining/i)).toBeInTheDocument();
  });

  it("creates a resumable upload session for the selected memory image", async () => {
    renderPage();
    await screen.findByText(/Memory image upload is available/i);
    await userEvent.type(screen.getByLabelText(/Source host/i), "HOSTA");
    await userEvent.click(screen.getByLabelText(/I confirm that I own this memory image/i));
    await userEvent.upload(screen.getByLabelText(/Memory image file/i), new File(["memory"], "authorized.mem"));

    await userEvent.click(screen.getByRole("button", { name: /Upload memory image/i }));

    await waitFor(() => expect(createMemoryUploadSessionMock).toHaveBeenCalledWith("case-1", expect.objectContaining({ filename: "authorized.mem", expected_size_bytes: 6, provided_host: "HOSTA", authorization_acknowledged: true })));
    expect(await screen.findByRole("button", { name: /Resume upload/i })).toBeInTheDocument();
  });

  it("surfaces the stored resumable session prompt after refresh", async () => {
    localStorage.setItem("kairon-memory-upload:case-1", JSON.stringify({ uploadId: "upload-1", filename: "authorized.mem", expectedBytes: 6, providedHost: "HOSTA" }));
    renderPage();
    expect(await screen.findByText(/Upload paused/i)).toBeInTheDocument();
    expect(await screen.findByText(/Reselect the same authorized\.mem file to continue from chunk 1 of 2/i)).toBeInTheDocument();
  });

  it("shows retry evidence registration when canonical upload is preserved", async () => {
    getActiveMemoryUploadMock.mockResolvedValue(uploadStatus({
      status: "failed",
      failure_code: "evidence_registration_failed",
      canonical_preserved: true,
      last_registration_error_code: "MEMORY_EVIDENCE_REGISTRATION_FAILED",
      last_registration_error_class: "RuntimeError",
      is_active: true,
      message: "Canonical upload is preserved; evidence registration can be retried.",
    }));
    renderPage();
    expect(await screen.findByTestId("memory-upload-retry-registration")).toBeInTheDocument();
  });

  it("renders active-session conflict panel with resume and cancel options", async () => {
    createMemoryUploadSessionMock.mockRejectedValue(conflictError({
      existing_upload_id: "conflict-1",
      filename: "authorized.mem",
      expected_bytes: 6,
      received_bytes: 4,
      received_chunk_count: 1,
      total_chunks: 2,
      status: "uploading",
      resumable: true,
      expires_at: new Date(Date.now() + 3600_000).toISOString(),
      cancellable: true,
    }));
    renderPage();
    await screen.findByText(/Memory image upload is available/i);
    await userEvent.type(screen.getByLabelText(/Source host/i), "HOSTA");
    await userEvent.click(screen.getByLabelText(/I confirm that I own this memory image/i));
    await userEvent.upload(screen.getByLabelText(/Memory image file/i), new File(["memory"], "authorized.mem"));

    await userEvent.click(screen.getByRole("button", { name: /Upload memory image/i }));

    const panel = await screen.findByTestId("memory-active-session-conflict");
    expect(panel).toHaveTextContent(/Existing upload found/);
    expect(panel).toHaveTextContent(/authorized\.mem/);
    expect(screen.getByTestId("memory-conflict-resume")).toBeInTheDocument();
    expect(screen.getByTestId("memory-conflict-cancel-restart")).toBeInTheDocument();
  });

  it("resume existing upload reuses existing upload ID", async () => {
    createMemoryUploadSessionMock.mockRejectedValue(conflictError({
      existing_upload_id: "conflict-1",
      filename: "authorized.mem",
      expected_bytes: 6,
      received_bytes: 4,
      received_chunk_count: 1,
      total_chunks: 2,
      status: "uploading",
      resumable: true,
      expires_at: new Date(Date.now() + 3600_000).toISOString(),
      cancellable: true,
    }));
    getMemoryUploadStatusMock.mockResolvedValue(uploadStatus({ upload_id: "conflict-1", status: "uploading", bytes_received: 4, received_chunk_count: 1, received_chunks: [0], missing_chunks: [1] }));
    renderPage();
    await screen.findByText(/Memory image upload is available/i);
    await userEvent.type(screen.getByLabelText(/Source host/i), "HOSTA");
    await userEvent.click(screen.getByLabelText(/I confirm that I own this memory image/i));
    await userEvent.upload(screen.getByLabelText(/Memory image file/i), new File(["memory"], "authorized.mem"));

    await userEvent.click(screen.getByRole("button", { name: /Upload memory image/i }));
    await screen.findByTestId("memory-active-session-conflict");

    await userEvent.click(screen.getByTestId("memory-conflict-resume"));

    await waitFor(() => expect(getMemoryUploadStatusMock).toHaveBeenCalledWith("case-1", "conflict-1"));
    expect(createMemoryUploadSessionMock).toHaveBeenCalledTimes(1); // only the initial failed call
  });

  it("resume validates file match before proceeding", async () => {
    createMemoryUploadSessionMock.mockRejectedValue(conflictError({
      existing_upload_id: "conflict-1",
      filename: "authorized.mem",
      expected_bytes: 100,
      received_bytes: 0,
      received_chunk_count: 0,
      total_chunks: 1,
      status: "uploading",
      resumable: true,
      expires_at: new Date(Date.now() + 3600_000).toISOString(),
      cancellable: true,
    }));
    renderPage();
    await screen.findByText(/Memory image upload is available/i);
    await userEvent.type(screen.getByLabelText(/Source host/i), "HOSTA");
    await userEvent.click(screen.getByLabelText(/I confirm that I own this memory image/i));
    await userEvent.upload(screen.getByLabelText(/Memory image file/i), new File(["memory"], "authorized.mem"));

    await userEvent.click(screen.getByRole("button", { name: /Upload memory image/i }));
    await screen.findByTestId("memory-active-session-conflict");

    await userEvent.click(screen.getByTestId("memory-conflict-resume"));

    expect(await screen.findByText(/does not match the existing upload session/i)).toBeInTheDocument();
  });

  it("cancel and restart shows confirmation then cancels and creates new session", async () => {
    createMemoryUploadSessionMock
      .mockRejectedValueOnce(conflictError({
        existing_upload_id: "conflict-1",
        filename: "authorized.mem",
        expected_bytes: 6,
        received_bytes: 4,
        received_chunk_count: 1,
        total_chunks: 2,
        status: "uploading",
        resumable: true,
        expires_at: new Date(Date.now() + 3600_000).toISOString(),
        cancellable: true,
      }))
      .mockResolvedValueOnce(uploadStatus({ upload_id: "new-upload-2" }));
    cancelMemoryUploadMock.mockResolvedValue(uploadStatus({ status: "cancelled", upload_id: "conflict-1" }));
    renderPage();
    await screen.findByText(/Memory image upload is available/i);
    await userEvent.type(screen.getByLabelText(/Source host/i), "HOSTA");
    await userEvent.click(screen.getByLabelText(/I confirm that I own this memory image/i));
    await userEvent.upload(screen.getByLabelText(/Memory image file/i), new File(["memory"], "authorized.mem"));

    await userEvent.click(screen.getByRole("button", { name: /Upload memory image/i }));
    await screen.findByTestId("memory-active-session-conflict");

    await userEvent.click(screen.getByTestId("memory-conflict-cancel-restart"));
    expect(screen.getByTestId("memory-conflict-confirm-restart")).toBeInTheDocument();
    expect(screen.getByTestId("memory-conflict-keep-existing")).toBeInTheDocument();

    await userEvent.click(screen.getByTestId("memory-conflict-confirm-restart"));

    await waitFor(() => expect(cancelMemoryUploadMock).toHaveBeenCalledWith("case-1", "conflict-1", "Operator requested restart"));
    await waitFor(() => expect(createMemoryUploadSessionMock).toHaveBeenCalledTimes(2));
  });

  it("cancel failure prevents new session creation", async () => {
    createMemoryUploadSessionMock.mockRejectedValue(conflictError({
      existing_upload_id: "conflict-1",
      filename: "authorized.mem",
      expected_bytes: 6,
      received_bytes: 4,
      received_chunk_count: 1,
      total_chunks: 2,
      status: "uploading",
      resumable: true,
      expires_at: new Date(Date.now() + 3600_000).toISOString(),
      cancellable: true,
    }));
    cancelMemoryUploadMock.mockRejectedValue(new Error("cancel failed"));
    renderPage();
    await screen.findByText(/Memory image upload is available/i);
    await userEvent.type(screen.getByLabelText(/Source host/i), "HOSTA");
    await userEvent.click(screen.getByLabelText(/I confirm that I own this memory image/i));
    await userEvent.upload(screen.getByLabelText(/Memory image file/i), new File(["memory"], "authorized.mem"));

    await userEvent.click(screen.getByRole("button", { name: /Upload memory image/i }));
    await screen.findByTestId("memory-active-session-conflict");

    await userEvent.click(screen.getByTestId("memory-conflict-cancel-restart"));
    await userEvent.click(screen.getByTestId("memory-conflict-confirm-restart"));

    await waitFor(() => expect(cancelMemoryUploadMock).toHaveBeenCalled());
    expect(createMemoryUploadSessionMock).toHaveBeenCalledTimes(1); // only the initial failed call
    expect(await screen.findByText(/cancel failed/i)).toBeInTheDocument();
  });

  it("select another file dismisses conflict and opens file picker", async () => {
    createMemoryUploadSessionMock.mockRejectedValue(conflictError({
      existing_upload_id: "conflict-1",
      filename: "authorized.mem",
      expected_bytes: 6,
      received_bytes: 0,
      received_chunk_count: 0,
      total_chunks: 2,
      status: "uploading",
      resumable: true,
      expires_at: new Date(Date.now() + 3600_000).toISOString(),
      cancellable: true,
    }));
    renderPage();
    await screen.findByText(/Memory image upload is available/i);
    await userEvent.type(screen.getByLabelText(/Source host/i), "HOSTA");
    await userEvent.click(screen.getByLabelText(/I confirm that I own this memory image/i));
    await userEvent.upload(screen.getByLabelText(/Memory image file/i), new File(["memory"], "authorized.mem"));

    await userEvent.click(screen.getByRole("button", { name: /Upload memory image/i }));
    await screen.findByTestId("memory-active-session-conflict");

    await userEvent.click(screen.getByTestId("memory-conflict-select-another"));

    await waitFor(() => expect(screen.queryByTestId("memory-active-session-conflict")).not.toBeInTheDocument());
  });

  it("keep existing upload dismisses confirmation without cancelling", async () => {
    createMemoryUploadSessionMock.mockRejectedValue(conflictError({
      existing_upload_id: "conflict-1",
      filename: "authorized.mem",
      expected_bytes: 6,
      received_bytes: 4,
      received_chunk_count: 1,
      total_chunks: 2,
      status: "uploading",
      resumable: true,
      expires_at: new Date(Date.now() + 3600_000).toISOString(),
      cancellable: true,
    }));
    renderPage();
    await screen.findByText(/Memory image upload is available/i);
    await userEvent.type(screen.getByLabelText(/Source host/i), "HOSTA");
    await userEvent.click(screen.getByLabelText(/I confirm that I own this memory image/i));
    await userEvent.upload(screen.getByLabelText(/Memory image file/i), new File(["memory"], "authorized.mem"));

    await userEvent.click(screen.getByRole("button", { name: /Upload memory image/i }));
    await screen.findByTestId("memory-active-session-conflict");

    await userEvent.click(screen.getByTestId("memory-conflict-cancel-restart"));
    await screen.findByTestId("memory-conflict-keep-existing");

    await userEvent.click(screen.getByTestId("memory-conflict-keep-existing"));

    await waitFor(() => expect(screen.queryByTestId("memory-conflict-confirm-restart")).not.toBeInTheDocument());
    expect(cancelMemoryUploadMock).not.toHaveBeenCalled();
    expect(screen.getByTestId("memory-active-session-conflict")).toBeInTheDocument();
  });
});
