import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import { ApiError } from "../api/client";
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
const runResumableUploadMock = vi.fn();

vi.mock("../features/memory/runResumableUpload", async () => {
  const actual = await vi.importActual<typeof import("../features/memory/runResumableUpload")>("../features/memory/runResumableUpload");
  return {
    ...actual,
    runResumableUpload: (...args: unknown[]) => runResumableUploadMock(...args),
  };
});

let _actualRunResumableUpload: typeof import("../features/memory/runResumableUpload").runResumableUpload;
beforeAll(async () => {
  const mod = await vi.importActual<typeof import("../features/memory/runResumableUpload")>("../features/memory/runResumableUpload");
  _actualRunResumableUpload = mod.runResumableUpload;
});

vi.mock("../api/client", async () => {
  const actual = await vi.importActual<typeof import("../api/client")>("../api/client");
  return {
    ...actual,
    api: {
      ...actual.api,
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
  };
});

vi.mock("../features/memory/runResumableUpload", async () => {
  const actual = await vi.importActual<typeof import("../features/memory/runResumableUpload")>("../features/memory/runResumableUpload");
  return {
    ...actual,
    runResumableUpload: (...args: unknown[]) => runResumableUploadMock(...args),
  };
});

vi.mock("../context/ActiveCaseContext", () => ({
  useActiveCase: () => ({ setActiveCaseId: vi.fn() }),
}));

function readiness(overrides = {}) {
  return {
    case_id: "case-1",
    upload_enabled: true,
    max_upload_bytes: 34_359_738_368,
    max_upload_display: "32 GiB",
    recommended_chunk_size_bytes: 8_388_608,
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

function chunkBytes(expectedBytes: number, chunkSize: number, chunkIndex: number) {
  const start = chunkIndex * chunkSize;
  const end = Math.min(expectedBytes, start + chunkSize);
  return Math.max(0, end - start);
}

function createUploadLoopController({
  uploadId = "upload-1",
  expectedBytes,
  chunkSize,
  totalChunks,
  receivedChunks = [],
}: {
  uploadId?: string;
  expectedBytes: number;
  chunkSize: number;
  totalChunks: number;
  receivedChunks?: number[];
}) {
  let received = [...receivedChunks].sort((a, b) => a - b);

  const buildStatus = (overrides = {}) => uploadStatus({
    upload_id: uploadId,
    status: "uploading",
    bytes_received: received.reduce((total, chunkIndex) => total + chunkBytes(expectedBytes, chunkSize, chunkIndex), 0),
    expected_bytes: expectedBytes,
    chunk_size_bytes: chunkSize,
    total_chunks: totalChunks,
    received_chunk_count: received.length,
    received_chunks: [...received],
    missing_chunks: Array.from({ length: totalChunks }, (_, index) => index).filter((index) => !received.includes(index)),
    progress_percent: Math.round((received.reduce((total, chunkIndex) => total + chunkBytes(expectedBytes, chunkSize, chunkIndex), 0) / expectedBytes) * 100),
    message: received.length === totalChunks ? "Upload transferred; verifying and finalizing" : "Upload session created. Ready to receive chunks.",
    ...overrides,
  });

  return {
    currentStatus: () => buildStatus(),
    getStatus: vi.fn(() => Promise.resolve(buildStatus())),
    uploadChunk: vi.fn((_caseId: string, _uploadId: string, chunkIndex: number) => {
      if (!received.includes(chunkIndex)) {
        received = [...received, chunkIndex].sort((a, b) => a - b);
      }
      return Promise.resolve(buildStatus());
    }),
    finalize: vi.fn(() => Promise.resolve(uploadStatus({
      upload_id: uploadId,
      status: "completed",
      evidence_id: "ev-memory",
      bytes_received: expectedBytes,
      expected_bytes: expectedBytes,
      chunk_size_bytes: chunkSize,
      total_chunks: totalChunks,
      received_chunk_count: totalChunks,
      received_chunks: Array.from({ length: totalChunks }, (_, index) => index),
      missing_chunks: [],
      progress_percent: 100,
      message: "Memory image uploaded and registered.",
    }))),
  };
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

async function clickPrimaryButton(name: RegExp) {
  const button = screen.getByRole("button", { name });
  fireEvent.click(button);
}

describe("MemoryUploadPage", () => {
  afterEach(() => {
    cleanup();
  });

  beforeEach(() => {
    vi.resetAllMocks();
    localStorage.clear();
    runResumableUploadMock.mockImplementation((...args: Parameters<typeof _actualRunResumableUpload>) =>
      _actualRunResumableUpload(...args)
    );
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
    expect(await screen.findByText(/8\.0 MiB/i)).toBeInTheDocument();
    expect(await screen.findByText(/Case quota remaining/i)).toBeInTheDocument();
  });

  it("creates a resumable upload session for the selected memory image", async () => {
    const loop = createUploadLoopController({ expectedBytes: 6, chunkSize: 4, totalChunks: 2 });
    createMemoryUploadSessionMock.mockResolvedValue(loop.currentStatus());
    getMemoryUploadStatusMock.mockImplementation(loop.getStatus);
    uploadMemoryUploadChunkMock.mockImplementation(loop.uploadChunk);
    finalizeMemoryUploadMock.mockImplementation(loop.finalize);
    renderPage();
    await screen.findByText(/Memory image upload is available/i);
    await userEvent.type(screen.getByLabelText(/Source host/i), "HOSTA");
    await userEvent.click(screen.getByLabelText(/I confirm that I own this memory image/i));
    await userEvent.upload(screen.getByLabelText(/Memory image file/i), new File(["memory"], "authorized.mem"));

    await clickPrimaryButton(/Upload memory image/i);

    await waitFor(() => expect(createMemoryUploadSessionMock).toHaveBeenCalledWith("case-1", expect.objectContaining({ filename: "authorized.mem", expected_size_bytes: 6, provided_host: "HOSTA", authorization_acknowledged: true })));
    await waitFor(() => expect(finalizeMemoryUploadMock).toHaveBeenCalledWith("case-1", "upload-1"));
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

    await clickPrimaryButton(/Upload memory image/i);

    const panel = await screen.findByTestId("memory-active-session-conflict");
    expect(panel).toHaveTextContent(/Existing upload found/);
    expect(panel).toHaveTextContent(/authorized\.mem/);
    expect(screen.getByTestId("memory-conflict-resume")).toBeInTheDocument();
    expect(screen.getByTestId("memory-conflict-cancel-restart")).toBeInTheDocument();
  });

  it("resume existing upload reuses existing upload ID", async () => {
    const loop = createUploadLoopController({ uploadId: "conflict-1", expectedBytes: 6, chunkSize: 4, totalChunks: 2, receivedChunks: [0] });
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
    getMemoryUploadStatusMock.mockImplementation(loop.getStatus);
    uploadMemoryUploadChunkMock.mockImplementation(loop.uploadChunk);
    finalizeMemoryUploadMock.mockImplementation(loop.finalize);
    renderPage();
    await screen.findByText(/Memory image upload is available/i);
    await userEvent.type(screen.getByLabelText(/Source host/i), "HOSTA");
    await userEvent.click(screen.getByLabelText(/I confirm that I own this memory image/i));
    await userEvent.upload(screen.getByLabelText(/Memory image file/i), new File(["memory"], "authorized.mem"));

    await clickPrimaryButton(/Upload memory image/i);
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

    await clickPrimaryButton(/Upload memory image/i);
    await screen.findByTestId("memory-active-session-conflict");

    await userEvent.click(screen.getByTestId("memory-conflict-resume"));

    expect(await screen.findByText(/does not match the existing upload session/i)).toBeInTheDocument();
  });

  it("cancel and restart shows confirmation then cancels and creates new session", async () => {
    const loop = createUploadLoopController({ uploadId: "new-upload-2", expectedBytes: 6, chunkSize: 4, totalChunks: 2 });
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
      .mockResolvedValueOnce(loop.currentStatus());
    cancelMemoryUploadMock.mockResolvedValue(uploadStatus({ status: "cancelled", upload_id: "conflict-1" }));
    getMemoryUploadStatusMock.mockImplementation(loop.getStatus);
    uploadMemoryUploadChunkMock.mockImplementation(loop.uploadChunk);
    finalizeMemoryUploadMock.mockImplementation(loop.finalize);
    renderPage();
    await screen.findByText(/Memory image upload is available/i);
    await userEvent.type(screen.getByLabelText(/Source host/i), "HOSTA");
    await userEvent.click(screen.getByLabelText(/I confirm that I own this memory image/i));
    await userEvent.upload(screen.getByLabelText(/Memory image file/i), new File(["memory"], "authorized.mem"));

    await clickPrimaryButton(/Upload memory image/i);
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

    await clickPrimaryButton(/Upload memory image/i);
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

    await clickPrimaryButton(/Upload memory image/i);
    await screen.findByTestId("memory-active-session-conflict");

    await userEvent.click(screen.getByTestId("memory-conflict-select-another"));

    await waitFor(() => expect(screen.queryByTestId("memory-active-session-conflict")).not.toBeInTheDocument());
  });

  it("new upload sends all chunks sequentially", async () => {
    const loop = createUploadLoopController({ expectedBytes: 12, chunkSize: 4, totalChunks: 3 });
    createMemoryUploadSessionMock.mockResolvedValue(loop.currentStatus());
    getMemoryUploadStatusMock.mockImplementation(loop.getStatus);
    uploadMemoryUploadChunkMock.mockImplementation(loop.uploadChunk);
    finalizeMemoryUploadMock.mockImplementation(loop.finalize);
    renderPage();
    await screen.findByText(/Memory image upload is available/i);
    await userEvent.type(screen.getByLabelText(/Source host/i), "HOSTA");
    await userEvent.click(screen.getByLabelText(/I confirm that I own this memory image/i));
    await userEvent.upload(screen.getByLabelText(/Memory image file/i), new File(["123456789012"], "authorized.mem"));

    await clickPrimaryButton(/Upload memory image/i);

    await waitFor(() => {
      expect(uploadMemoryUploadChunkMock).toHaveBeenCalledWith(
        "case-1", "upload-1", 0, expect.any(Blob), expect.objectContaining({}),
      );
      expect(uploadMemoryUploadChunkMock).toHaveBeenCalledWith(
        "case-1", "upload-1", 1, expect.any(Blob), expect.objectContaining({}),
      );
      expect(uploadMemoryUploadChunkMock).toHaveBeenCalledWith(
        "case-1", "upload-1", 2, expect.any(Blob), expect.objectContaining({}),
      );
    });
    expect(finalizeMemoryUploadMock).toHaveBeenCalledWith("case-1", "upload-1");
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

    await clickPrimaryButton(/Upload memory image/i);
    await screen.findByTestId("memory-active-session-conflict");

    await userEvent.click(screen.getByTestId("memory-conflict-cancel-restart"));
    await screen.findByTestId("memory-conflict-keep-existing");

    await userEvent.click(screen.getByTestId("memory-conflict-keep-existing"));

    await waitFor(() => expect(screen.queryByTestId("memory-conflict-confirm-restart")).not.toBeInTheDocument());
    expect(cancelMemoryUploadMock).not.toHaveBeenCalled();
    expect(screen.getByTestId("memory-active-session-conflict")).toBeInTheDocument();
  });

  it("status query uploading does not overwrite idle stage when file matches (deadlock regression)", async () => {
    localStorage.setItem("kairon-memory-upload:case-1", JSON.stringify({ uploadId: "upload-1", filename: "authorized.mem", expectedBytes: 6, providedHost: "HOSTA" }));
    getMemoryUploadStatusMock.mockResolvedValue(uploadStatus({ status: "uploading", bytes_received: 4, received_chunk_count: 1, expected_bytes: 6 }));
    renderPage();
    await screen.findByText(/Memory image upload is available/i);
    await userEvent.type(screen.getByLabelText(/Source host/i), "HOSTA");
    await userEvent.click(screen.getByLabelText(/I confirm that I own this memory image/i));
    await userEvent.upload(screen.getByLabelText(/Memory image file/i), new File(["memory"], "authorized.mem"));

    await waitFor(() => expect(getMemoryUploadStatusMock).toHaveBeenCalledWith("case-1", "upload-1"));
    const button = screen.getByRole("button", { name: /Resume upload/i });
    expect(button).toBeEnabled();
  });

  it("multi-chunk upload after conflict resume sends all missing chunks", async () => {
    const loop = createUploadLoopController({ uploadId: "conflict-1", expectedBytes: 12, chunkSize: 4, totalChunks: 3, receivedChunks: [0, 1] });
    createMemoryUploadSessionMock.mockRejectedValue(conflictError({
      existing_upload_id: "conflict-1",
      filename: "authorized.mem",
      expected_bytes: 12,
      received_bytes: 8,
      received_chunk_count: 2,
      total_chunks: 3,
      status: "uploading",
      resumable: true,
      expires_at: new Date(Date.now() + 3600_000).toISOString(),
      cancellable: true,
    }));
    getMemoryUploadStatusMock.mockImplementation(loop.getStatus);
    uploadMemoryUploadChunkMock.mockImplementation(loop.uploadChunk);
    finalizeMemoryUploadMock.mockImplementation(loop.finalize);
    renderPage();
    await screen.findByText(/Memory image upload is available/i);
    await userEvent.type(screen.getByLabelText(/Source host/i), "HOSTA");
    await userEvent.click(screen.getByLabelText(/I confirm that I own this memory image/i));
    await userEvent.upload(screen.getByLabelText(/Memory image file/i), new File(["123456789012"], "authorized.mem"));

    await clickPrimaryButton(/Upload memory image/i);
    await screen.findByTestId("memory-active-session-conflict");

    await userEvent.click(screen.getByTestId("memory-conflict-resume"));

    await waitFor(() => {
      expect(uploadMemoryUploadChunkMock).toHaveBeenCalledWith(
        "case-1", "conflict-1", 2, expect.any(Blob), expect.objectContaining({}),
      );
    });
    expect(finalizeMemoryUploadMock).toHaveBeenCalledWith("case-1", "conflict-1");
  });

  it("one resume click invokes controller with existing upload ID and file", async () => {
    localStorage.setItem("kairon-memory-upload:case-1", JSON.stringify({ uploadId: "resume-1", filename: "authorized.mem", expectedBytes: 20, providedHost: "HOSTA" }));
    getMemoryUploadStatusMock.mockResolvedValue(uploadStatus({ upload_id: "resume-1", expected_bytes: 20, chunk_size_bytes: 4, total_chunks: 5, received_chunks: [0, 1], received_chunk_count: 2, bytes_received: 8, missing_chunks: [2, 3, 4], status: "uploading" }));
    renderPage();
    await screen.findByText(/Memory image upload is available/i);
    fireEvent.change(screen.getByLabelText(/Source host/i), { target: { value: "HOSTA" } });
    fireEvent.click(screen.getByLabelText(/I confirm that I own this memory image/i));
    fireEvent.change(screen.getByLabelText(/Memory image file/i), { target: { files: [new File(["12345678901234567890"], "authorized.mem")] } });
    fireEvent.click(screen.getByRole("button", { name: /Resume upload/i }));

    await waitFor(() => expect(runResumableUploadMock).toHaveBeenCalledTimes(1));
    expect(runResumableUploadMock).toHaveBeenCalledWith(
      expect.objectContaining({
        uploadId: "resume-1",
        file: expect.any(File),
      })
    );
    expect(createMemoryUploadSessionMock).not.toHaveBeenCalled();
  });

  it("one resume click pauses on timed out chunk without creating a new session", async () => {
    const uploadId = "recover-page-1";
    const expectedBytes = 24;
    const chunkSize = 4;
    const totalChunks = 6;
    let received = [0, 1, 2];

    const buildStatus = () => uploadStatus({
      upload_id: uploadId,
      status: "uploading",
      expected_bytes: expectedBytes,
      bytes_received: received.reduce((total, chunkIndex) => total + chunkBytes(expectedBytes, chunkSize, chunkIndex), 0),
      chunk_size_bytes: chunkSize,
      total_chunks: totalChunks,
      received_chunk_count: received.length,
      received_chunks: [...received],
      missing_chunks: Array.from({ length: totalChunks }, (_, index) => index).filter((index) => !received.includes(index)),
    });

    localStorage.setItem("kairon-memory-upload:case-1", JSON.stringify({ uploadId, filename: "authorized.mem", expectedBytes, providedHost: "HOSTA" }));
    getMemoryUploadStatusMock.mockImplementation(() => Promise.resolve(buildStatus()));
    uploadMemoryUploadChunkMock.mockImplementation((_caseId: string, _uploadId: string, chunkIndex: number) => {
      if (!received.includes(chunkIndex)) {
        received = [...received, chunkIndex].sort((a, b) => a - b);
      }
      return Promise.reject(new Error("Upload timed out. Your network may be unavailable."));
    });
    finalizeMemoryUploadMock.mockResolvedValue(uploadStatus({
      upload_id: uploadId,
      status: "completed",
      evidence_id: "ev-memory",
      expected_bytes: expectedBytes,
      bytes_received: expectedBytes,
      chunk_size_bytes: chunkSize,
      total_chunks: totalChunks,
      received_chunk_count: totalChunks,
      received_chunks: [0, 1, 2, 3, 4, 5],
      missing_chunks: [],
      progress_percent: 100,
      message: "Memory image uploaded and registered.",
    }));

    renderPage();
    await screen.findByText(/Memory image upload is available/i);
    fireEvent.change(screen.getByLabelText(/Source host/i), { target: { value: "HOSTA" } });
    fireEvent.click(screen.getByLabelText(/I confirm that I own this memory image/i));
    fireEvent.change(screen.getByLabelText(/Memory image file/i), { target: { files: [new File([new Uint8Array(expectedBytes).fill(0x41)], "authorized.mem")] } });
    fireEvent.click(screen.getByRole("button", { name: /Resume upload/i }));

    await waitFor(() => expect(screen.getAllByText(/Upload timed out/i).length).toBeGreaterThan(0), { timeout: 6000 });
    expect(runResumableUploadMock).toHaveBeenCalledTimes(1);
    expect(createMemoryUploadSessionMock).not.toHaveBeenCalled();
    expect(uploadMemoryUploadChunkMock.mock.calls.map((call) => call[2])).toEqual([3, 3, 3, 3]);
    expect(finalizeMemoryUploadMock).not.toHaveBeenCalled();
  }, 10_000);

  it("pauses upload without creating new session when controller fails", async () => {
    const failedStatus = uploadStatus({ upload_id: "resume-3", expected_bytes: 16, chunk_size_bytes: 4, total_chunks: 4, received_chunks: [0, 1], received_chunk_count: 2, bytes_received: 8, missing_chunks: [2, 3], status: "uploading" });
    runResumableUploadMock.mockResolvedValue({ type: "failed", message: "Chunk already exists." });
    localStorage.setItem("kairon-memory-upload:case-1", JSON.stringify({ uploadId: "resume-3", filename: "authorized.mem", expectedBytes: 16, providedHost: "HOSTA" }));
    getMemoryUploadStatusMock.mockResolvedValue(failedStatus);
    renderPage();
    await screen.findByText(/Memory image upload is available/i);
    fireEvent.change(screen.getByLabelText(/Source host/i), { target: { value: "HOSTA" } });
    fireEvent.click(screen.getByLabelText(/I confirm that I own this memory image/i));
    fireEvent.change(screen.getByLabelText(/Memory image file/i), { target: { files: [new File(["1234567890123456"], "authorized.mem")] } });
    fireEvent.click(screen.getByRole("button", { name: /Resume upload/i }));

    await waitFor(() => expect(runResumableUploadMock).toHaveBeenCalledTimes(1));
    expect(createMemoryUploadSessionMock).not.toHaveBeenCalled();
  });

  it("shows completed UI when controller returns completed result", async () => {
    const uploadId = "completed-ui-1";
    const completedStatus = uploadStatus({
      upload_id: uploadId,
      status: "completed",
      evidence_id: "ev-completed",
      bytes_received: 12,
      expected_bytes: 12,
      chunk_size_bytes: 4,
      total_chunks: 3,
      received_chunk_count: 3,
      received_chunks: [0, 1, 2],
      missing_chunks: [],
      progress_percent: 100,
      message: "Memory image uploaded and registered.",
    });
    runResumableUploadMock.mockResolvedValue({ type: "completed", status: completedStatus });
    localStorage.setItem(
      "kairon-memory-upload:case-1",
      JSON.stringify({
        uploadId,
        filename: "authorized.mem",
        expectedBytes: 12,
        providedHost: "HOSTA",
      }),
    );
    getMemoryUploadStatusMock.mockResolvedValue(
      uploadStatus({
        upload_id: uploadId,
        status: "uploading",
        bytes_received: 4,
        expected_bytes: 12,
        received_chunk_count: 1,
        total_chunks: 3,
        received_chunks: [0],
        missing_chunks: [1, 2],
      }),
    );
    renderPage();
    await screen.findByText(/Memory image upload is available/i);
    fireEvent.change(screen.getByLabelText(/Source host/i), {
      target: { value: "HOSTA" },
    });
    fireEvent.click(screen.getByLabelText(/I confirm that I own this memory image/i));
    fireEvent.change(screen.getByLabelText(/Memory image file/i), {
      target: { files: [new File([new Uint8Array(12).fill(0x41)], "authorized.mem")] },
    });
    await waitFor(() => {
      expect(screen.getByRole("button", { name: /Resume upload/i })).not.toBeDisabled();
    });
    fireEvent.click(screen.getByRole("button", { name: /Resume upload/i }));

    await waitFor(() => {
      expect(screen.getByText(/Upload completed/)).toBeTruthy();
    });
    expect(createMemoryUploadSessionMock).not.toHaveBeenCalled();
  });

  it("clicking Check status shows Checking then restores", async () => {
    const uploadId = "check-status-1";
    getActiveMemoryUploadMock.mockResolvedValue({
      is_active: true,
      upload_id: uploadId,
      filename: "authorized.mem",
      status: "uploading",
      stale: false,
    });
    getMemoryUploadStatusMock.mockResolvedValue(
      uploadStatus({
        upload_id: uploadId,
        status: "uploading",
        bytes_received: 67108864,
        expected_bytes: 1024,
        received_chunk_count: 1,
        total_chunks: 4,
        received_chunks: [0],
        missing_chunks: [1, 2, 3],
      }),
    );
    localStorage.setItem(
      "kairon-memory-upload:case-1",
      JSON.stringify({
        uploadId,
        filename: "authorized.mem",
        expectedBytes: 20,
        providedHost: "HOSTA",
      }),
    );
    renderPage();
    await screen.findByText(/Memory image upload is available/i);

    const checkButton = screen.getByTestId("memory-active-check-status");
    expect(checkButton.textContent).toBe("Check status");

    fireEvent.click(checkButton);
    await waitFor(() => {
      expect(checkButton.textContent).toBe("Checking…");
    });
    await waitFor(() => {
      expect(checkButton.textContent).toBe("Check status");
    });
    expect(getActiveMemoryUploadMock).toHaveBeenCalled();
    expect(getMemoryUploadStatusMock).toHaveBeenCalled();
  });

  it("clicking Check status in upload section calls API and updates progress", async () => {
    const uploadId = "check-status-2";
    getMemoryUploadStatusMock.mockResolvedValue(
      uploadStatus({
        upload_id: uploadId,
        status: "uploading",
        bytes_received: 8,
        expected_bytes: 12,
        received_chunk_count: 2,
        total_chunks: 3,
        received_chunks: [0, 1],
        missing_chunks: [2],
      }),
    );
    localStorage.setItem(
      "kairon-memory-upload:case-1",
      JSON.stringify({
        uploadId,
        filename: "authorized.mem",
        expectedBytes: 12,
        providedHost: "HOSTA",
      }),
    );
    renderPage();
    await screen.findByText(/Memory image upload is available/i);

    const checkButton = screen.getByTestId("memory-upload-check-status");
    expect(checkButton).toBeTruthy();
    expect(checkButton.textContent).toBe("Check status");

    fireEvent.click(checkButton);
    await waitFor(() => {
      expect(checkButton.textContent).toBe("Checking…");
    });
    await waitFor(() => {
      expect(checkButton.textContent).toBe("Check status");
    });
    expect(getMemoryUploadStatusMock).toHaveBeenCalled();
    expect(createMemoryUploadSessionMock).not.toHaveBeenCalled();
    expect(screen.getByText(/Kairon has safely stored 8 B of 12 B/)).toBeTruthy();
  });

  it("clicking Check status shows Checking state on API error", async () => {
    const uploadId = "check-status-3";
    getMemoryUploadStatusMock.mockResolvedValue(
      uploadStatus({
        upload_id: uploadId,
        status: "uploading",
        bytes_received: 4,
        expected_bytes: 12,
        received_chunk_count: 1,
        total_chunks: 3,
        received_chunks: [0],
        missing_chunks: [1, 2],
      }),
    );
    localStorage.setItem(
      "kairon-memory-upload:case-1",
      JSON.stringify({
        uploadId,
        filename: "authorized.mem",
        expectedBytes: 12,
        providedHost: "HOSTA",
      }),
    );
    renderPage();
    await screen.findByText(/Memory image upload is available/i);

    const checkButton = screen.getByTestId("memory-upload-check-status");
    getMemoryUploadStatusMock.mockRejectedValue(new Error("Backend unavailable"));
    fireEvent.click(checkButton);
    await waitFor(() => {
      expect(checkButton.textContent).toBe("Checking…");
    });
    await waitFor(() => {
      expect(checkButton.textContent).toBe("Check status");
    });
    expect(getMemoryUploadStatusMock).toHaveBeenCalled();
    expect(createMemoryUploadSessionMock).not.toHaveBeenCalled();
  });
});
