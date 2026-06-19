import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import MemoryUploadPage from "./MemoryUploadPage";

const getMemoryUploadReadinessMock = vi.fn();
const uploadEvidenceMock = vi.fn();
const getMemoryUploadStatusMock = vi.fn();
const reconcileMemoryUploadMock = vi.fn();
const getEvidenceMock = vi.fn();
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
    uploadEvidence: (...args: unknown[]) => uploadEvidenceMock(...args),
    getMemoryUploadStatus: (...args: unknown[]) => getMemoryUploadStatusMock(...args),
    reconcileMemoryUpload: (...args: unknown[]) => reconcileMemoryUploadMock(...args),
    getEvidence: (...args: unknown[]) => getEvidenceMock(...args),
  },
}));

vi.mock("../context/ActiveCaseContext", () => ({
  useActiveCase: () => ({ setActiveCaseId: vi.fn() }),
}));

function readiness(overrides = {}) {
  return {
    case_id: "case-1",
    upload_enabled: true,
    max_upload_bytes: 5368709120,
    max_upload_display: "5 GiB",
    allowed_extensions: [".raw", ".mem", ".vmem", ".dmp", ".lime"],
    staging_available_bytes: 13 * 1024 * 1024 * 1024,
    canonical_storage_available_bytes: 13 * 1024 * 1024 * 1024,
    memory_output_available_bytes: 13 * 1024 * 1024 * 1024,
    recommended_max_upload_bytes: 5 * 1024 * 1024 * 1024,
    required_capacity_bytes: 2 * 1024 * 1024 * 1024,
    can_accept_selected_size: true,
    finalization_strategy: "atomic_move",
    analysis_enabled: true,
    dedicated_worker_online: true,
    backend_ready: true,
    message: "Memory image upload is available and the dedicated memory worker is ready.",
    ...overrides,
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

describe("MemoryUploadPage", () => {
  beforeEach(() => {
    navigateMock.mockReset();
    getMemoryUploadReadinessMock.mockReset();
    uploadEvidenceMock.mockReset();
    getMemoryUploadStatusMock.mockReset();
    reconcileMemoryUploadMock.mockReset();
    getEvidenceMock.mockReset();
    localStorage.clear();
    getMemoryUploadReadinessMock.mockResolvedValue(readiness());
    uploadEvidenceMock.mockResolvedValue({ id: "ev-memory", evidence_type: "memory_dump", size_bytes: 6, sha256: "0".repeat(64) });
    getMemoryUploadStatusMock.mockImplementation(() => new Promise(() => undefined));
    getEvidenceMock.mockResolvedValue({ id: "ev-memory", evidence_type: "memory_dump", size_bytes: 6, sha256: "0".repeat(64) });
  });

  it("renders dedicated memory upload readiness and privacy acknowledgement", async () => {
    renderPage();

    expect(await screen.findByRole("heading", { name: /Add memory image/i })).toBeInTheDocument();
    expect(await screen.findByText(/Memory image upload is available/i)).toBeInTheDocument();
    expect(screen.getByText(/5 GiB/i)).toBeInTheDocument();
    expect(screen.getByText(/Memory images may contain credentials, personal data, encryption material, browser data, access tokens/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/I confirm that I own this memory image/i)).toBeInTheDocument();
  });

  it("uploads an authorized memory image and opens Memory Analysis", async () => {
    renderPage();
    await screen.findByText(/Memory image upload is available/i);
    await userEvent.type(screen.getByLabelText(/Source host/i), "HOSTA");
    await userEvent.click(screen.getByLabelText(/I confirm that I own this memory image/i));
    await userEvent.upload(screen.getByLabelText(/Memory image file/i), new File(["memory"], "authorized.mem"));

    await userEvent.click(screen.getByRole("button", { name: /Upload memory image/i }));

    await waitFor(() => expect(uploadEvidenceMock).toHaveBeenCalledWith("case-1", expect.any(File), expect.objectContaining({ memoryAuthorizationAcknowledged: true, providedHost: "HOSTA" })));
    expect(await screen.findByText(/Upload completed/i)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /Open Memory Analysis/i }));
    expect(navigateMock).toHaveBeenCalledWith("/cases/case-1/memory?evidence_id=ev-memory");
  });

  it("disables upload when storage is insufficient", async () => {
    getMemoryUploadReadinessMock.mockResolvedValue(readiness({ can_accept_selected_size: false, message: "Server storage capacity is below the recommended threshold for the selected memory image." }));
    renderPage();

    expect(await screen.findByText(/below the recommended threshold/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Upload memory image/i })).toBeDisabled();
  });

  it("shows transferred bytes as verifying before final evidence completion", async () => {
    let resolveUpload: ((value: unknown) => void) | undefined;
    uploadEvidenceMock.mockImplementation((_caseId, file, options) => {
      options.onProgress({ loaded: file.size, total: file.size });
      return new Promise((resolve) => { resolveUpload = resolve; });
    });
    renderPage();
    await screen.findByText(/Memory image upload is available/i);
    await userEvent.type(screen.getByLabelText(/Source host/i), "HOSTA");
    await userEvent.click(screen.getByLabelText(/I confirm that I own this memory image/i));
    await userEvent.upload(screen.getByLabelText(/Memory image file/i), new File(["memory"], "authorized.mem"));
    await userEvent.click(screen.getByRole("button", { name: /Upload memory image/i }));

    expect(await screen.findByText(/Upload transferred; verifying and finalizing/i)).toBeInTheDocument();
    expect(screen.queryByText(/Upload completed/i)).not.toBeInTheDocument();
    resolveUpload?.({ id: "ev-memory", evidence_type: "memory_dump", size_bytes: 6, sha256: "0".repeat(64) });
    expect(await screen.findByText(/Upload completed/i)).toBeInTheDocument();
  });

  it("shows a durable finalization failure after 100% transfer without recommending re-upload", async () => {
    getMemoryUploadStatusMock.mockResolvedValue({ upload_id: "upload-1", status: "failed", bytes_received: 6, expected_bytes: 6, evidence_id: null, failure_code: "finalization_timeout", message: "Finalization timed out safely.", updated_at: new Date().toISOString(), retryable: true });
    reconcileMemoryUploadMock.mockResolvedValue({ upload_id: "upload-1", status: "finalizing", bytes_received: 6, expected_bytes: 6, evidence_id: null, failure_code: null, message: "Finalizing.", updated_at: new Date().toISOString(), retryable: false });
    uploadEvidenceMock.mockImplementation((_caseId, file, options) => {
      options.onProgress({ loaded: file.size, total: file.size });
      return Promise.reject(new Error("Capacity changed during finalization."));
    });
    renderPage();
    await screen.findByText(/Memory image upload is available/i);
    await userEvent.type(screen.getByLabelText(/Source host/i), "HOSTA");
    await userEvent.click(screen.getByLabelText(/I confirm that I own this memory image/i));
    await userEvent.upload(screen.getByLabelText(/Memory image file/i), new File(["memory"], "authorized.mem"));
    await userEvent.click(screen.getByRole("button", { name: /Upload memory image/i }));

    expect(await screen.findByText(/Finalization timed out safely/i)).toBeInTheDocument();
    expect(screen.queryByText(/Upload completed/i)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Open Memory Analysis/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Retry upload/i })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Retry finalization/i })).toBeInTheDocument();
  });

  it("uses binary GiB units for selected and capacity values", async () => {
    const selected = new File(["x"], "authorized.mem");
    Object.defineProperty(selected, "size", { value: 4 * 1024 * 1024 * 1024 });
    getMemoryUploadReadinessMock.mockResolvedValue(readiness({ required_capacity_bytes: 6 * 1024 * 1024 * 1024 }));
    renderPage();
    await userEvent.upload(screen.getByLabelText(/Memory image file/i), selected);

    expect(await screen.findByText(/Size: 4\.0 GiB/i)).toBeInTheDocument();
    expect(screen.getByText("6.0 GiB")).toBeInTheDocument();
  });

  it("resumes status polling after refresh and exposes completed evidence", async () => {
    localStorage.setItem("kairon-memory-upload:case-1", "11111111-1111-4111-8111-111111111111");
    getMemoryUploadStatusMock.mockResolvedValue({ upload_id: "11111111-1111-4111-8111-111111111111", status: "completed", bytes_received: 6, expected_bytes: 6, evidence_id: "ev-memory", failure_code: null, message: "Memory image uploaded and registered.", updated_at: new Date().toISOString(), retryable: false });
    renderPage();

    expect(await screen.findByText(/Upload completed/i)).toBeInTheDocument();
    expect(getMemoryUploadStatusMock).toHaveBeenCalledWith("case-1", "11111111-1111-4111-8111-111111111111");
    expect(await screen.findByRole("button", { name: /Open Memory Analysis/i })).toBeInTheDocument();
  });

  it("polls an active upload and disables duplicate submission", async () => {
    localStorage.setItem("kairon-memory-upload:case-1", "22222222-2222-4222-8222-222222222222");
    getMemoryUploadStatusMock.mockResolvedValue({ upload_id: "22222222-2222-4222-8222-222222222222", status: "finalizing", bytes_received: 6, expected_bytes: 6, evidence_id: null, failure_code: null, message: "The file has been transferred. Kairon is finalizing the evidence.", updated_at: new Date().toISOString(), retryable: false });
    renderPage();

    expect(await screen.findByText(/Kairon is finalizing the evidence/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Upload memory image/i })).toBeDisabled();
    expect(screen.getByRole("button", { name: /Check status/i })).toBeInTheDocument();
  });

  it("stops on an inconsistent terminal state without offering unsafe finalization", async () => {
    localStorage.setItem("kairon-memory-upload:case-1", "33333333-3333-4333-8333-333333333333");
    getMemoryUploadStatusMock.mockResolvedValue({ upload_id: "33333333-3333-4333-8333-333333333333", status: "inconsistent", bytes_received: 6, expected_bytes: 6, evidence_id: null, failure_code: "staging_and_canonical_present", message: "Both staged and canonical files require review.", updated_at: new Date().toISOString(), retryable: false });
    renderPage();

    expect(await screen.findByText(/require review/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Retry finalization/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Open Memory Analysis/i })).not.toBeInTheDocument();
  });
});
