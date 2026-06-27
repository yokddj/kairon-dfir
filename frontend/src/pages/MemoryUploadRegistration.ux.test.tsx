/** @vitest-environment jsdom */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useParams, useSearchParams } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../api/client", () => ({
  api: {
    getMemoryUploadReadiness: vi.fn(),
    getMemoryUploadStatus: vi.fn(),
    getActiveMemoryUpload: vi.fn(),
    cancelMemoryUpload: vi.fn(),
    reconcileMemoryUpload: vi.fn(),
    retryMemoryUploadRegistration: vi.fn(),
    reconcileCaseMemoryUploads: vi.fn(),
  },
}));

vi.mock("../context/ActiveCaseContext", () => ({
  useActiveCase: () => ({ setActiveCaseId: vi.fn() }),
}));

import { api } from "../api/client";
import MemoryUploadPage from "./MemoryUploadPage";

const CASE = "case-1";
const UPLOAD_ID = "upload-preserved";
const EVIDENCE_ID = "evidence-1";

const setupReadiness = () => {
  (api.getMemoryUploadReadiness as ReturnType<typeof vi.fn>).mockResolvedValue({
    upload_enabled: true,
    analysis_enabled: true,
    dedicated_worker_online: true,
    backend_ready: true,
    max_upload_bytes: 5_368_709_120,
    max_upload_display: "5.0 GiB",
    recommended_max_upload_bytes: 5_368_709_120,
    required_capacity_bytes: 0,
    can_accept_selected_size: true,
    message: "ready",
    allowed_extensions: [".raw", ".mem", ".dmp", ".dump", ".bin", ".img", ".vmem", ".lime"],
  });
  (api.getActiveMemoryUpload as ReturnType<typeof vi.fn>).mockResolvedValue(null);
};

const setupFailedRegistration = (overrides: Record<string, unknown> = {}) => {
  localStorage.setItem(`kairon-memory-upload:${CASE}`, UPLOAD_ID);
  const payload = {
    upload_id: UPLOAD_ID,
    case_id: CASE,
    evidence_id: null,
    status: "failed",
    failure_code: "evidence_registration_failed",
    failure_message: "Canonical upload is preserved; evidence registration can be retried.",
    retryable: true,
    bytes_received: 4_000,
    expected_bytes: 4_000,
    filename: "mem.img",
    extension: ".img",
    created_at: "2024-01-01T00:00:00Z",
    updated_at: "2024-01-01T00:00:00Z",
    stage: "failed_registration",
    registration_state: null,
    registration_attempts: 1,
    canonical_preserved: true,
    last_registration_error_code: "MEMORY_EVIDENCE_REGISTRATION_FAILED",
    last_registration_error_class: "RuntimeError",
    is_active: true,
    cancellable: false,
    message: "Canonical upload is preserved; evidence registration can be retried.",
  };
  (api.getMemoryUploadStatus as ReturnType<typeof vi.fn>).mockResolvedValue({ ...payload, ...overrides });
  (api.getActiveMemoryUpload as ReturnType<typeof vi.fn>).mockResolvedValue({ ...payload, ...overrides });
};

beforeEach(() => {
  vi.clearAllMocks();
  localStorage.clear();
  setupReadiness();
});

const renderPage = (initialEntry: string = `/cases/${CASE}/memory/upload`) => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, refetchInterval: false } } });
  const MemoryAnalysis = () => {
    const { evidenceId: _e } = useParams();
    const [params] = useSearchParams();
    const eid = _e || params.get("evidence_id") || "none";
    return (
      <div data-testid="memory-analysis-page">
        Memory Analysis Page · /memory/{eid}
      </div>
    );
  };
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[initialEntry]}>
        <Routes>
          <Route path="/cases/:caseId/memory/upload" element={<MemoryUploadPage />} />
          <Route path="/cases/:caseId/memory" element={<MemoryAnalysis />} />
          <Route path="/cases/:caseId/memory/:evidenceId" element={<MemoryAnalysis />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
};

describe("Memory upload evidence-registration recovery v1", () => {
  it("1) shows the 'Retry evidence registration' button when registration failed and canonical is preserved", async () => {
    setupFailedRegistration();
    renderPage();
    const button = await screen.findByTestId("memory-upload-retry-registration");
    expect(button).toBeInTheDocument();
    expect(button.textContent).toMatch(/Retry evidence registration/);
  });

  it("2) does NOT show the retry-registration button when the upload is not failed", async () => {
    (api.getMemoryUploadStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      upload_id: UPLOAD_ID,
      case_id: CASE,
      evidence_id: EVIDENCE_ID,
      status: "completed",
      failure_code: null,
      retryable: false,
      bytes_received: 4_000,
      expected_bytes: 4_000,
      filename: "mem.img",
      extension: ".img",
      created_at: "2024-01-01T00:00:00Z",
      updated_at: "2024-01-01T00:00:00Z",
      is_active: true,
      cancellable: false,
      message: "Memory image uploaded and registered.",
    });
    (api.getActiveMemoryUpload as ReturnType<typeof vi.fn>).mockResolvedValue({
      upload_id: UPLOAD_ID,
      case_id: CASE,
      evidence_id: EVIDENCE_ID,
      status: "completed",
      failure_code: null,
      retryable: false,
      bytes_received: 4_000,
      expected_bytes: 4_000,
      filename: "mem.img",
      extension: ".img",
      is_active: true,
      cancellable: false,
    });
    renderPage();
    await screen.findByTestId("memory-active-upload-panel");
    expect(screen.queryByTestId("memory-upload-retry-registration")).toBeNull();
  });

  it("3) does NOT show the retry-registration button when canonical_preserved is false", async () => {
    setupFailedRegistration({ canonical_preserved: false });
    renderPage();
    await screen.findByTestId("memory-active-upload-panel");
    expect(screen.queryByTestId("memory-upload-retry-registration")).toBeNull();
  });

  it("4) clicking the retry-registration button calls the API exactly once with the active upload id", async () => {
    setupFailedRegistration();
    (api.retryMemoryUploadRegistration as ReturnType<typeof vi.fn>).mockResolvedValue({
      upload_id: UPLOAD_ID,
      case_id: CASE,
      evidence_id: EVIDENCE_ID,
      status: "completed",
      stage: "completed",
      registration_state: null,
      registration_attempts: 2,
      canonical_preserved: true,
      failure_code: null,
      failure_message: null,
      retryable: false,
      bytes_received: 4_000,
      expected_bytes: 4_000,
      filename: "mem.img",
      extension: ".img",
      created_at: "2024-01-01T00:00:00Z",
      updated_at: "2024-01-01T00:00:00Z",
      is_active: true,
      cancellable: false,
      message: "Memory image uploaded and registered.",
    });
    renderPage();
    const button = await screen.findByTestId("memory-upload-retry-registration");
    fireEvent.click(button);
    await waitFor(() => expect(api.retryMemoryUploadRegistration).toHaveBeenCalledTimes(1));
    expect(api.retryMemoryUploadRegistration).toHaveBeenCalledWith(CASE, UPLOAD_ID);
  });

  it("5) double-clicking the retry-registration button does not enqueue duplicate requests in flight", async () => {
    setupFailedRegistration();
    let resolveRequest!: (value: unknown) => void;
    (api.retryMemoryUploadRegistration as ReturnType<typeof vi.fn>).mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveRequest = resolve;
        }),
    );
    renderPage();
    const button = await screen.findByTestId("memory-upload-retry-registration");
    fireEvent.click(button);
    fireEvent.click(button);
    fireEvent.click(button);
    // At most one request was enqueued: subsequent clicks must
    // either be debounced client-side or refused by the server.
    await waitFor(() => expect(api.retryMemoryUploadRegistration).toHaveBeenCalled());
    expect(api.retryMemoryUploadRegistration).toHaveBeenCalledTimes(1);
    resolveRequest({
      upload_id: UPLOAD_ID,
      case_id: CASE,
      evidence_id: EVIDENCE_ID,
      status: "completed",
      stage: "completed",
      registration_state: null,
      registration_attempts: 2,
      canonical_preserved: true,
      failure_code: null,
      failure_message: null,
      retryable: false,
      bytes_received: 4_000,
      expected_bytes: 4_000,
      filename: "mem.img",
      extension: ".img",
      created_at: "2024-01-01T00:00:00Z",
      updated_at: "2024-01-01T00:00:00Z",
      is_active: false,
      cancellable: false,
      message: "Memory image uploaded and registered.",
    });
  });

  it("6) on success the page navigates to the evidence view and clears the localStorage upload id", async () => {
    setupFailedRegistration();
    (api.retryMemoryUploadRegistration as ReturnType<typeof vi.fn>).mockResolvedValue({
      upload_id: UPLOAD_ID,
      case_id: CASE,
      evidence_id: EVIDENCE_ID,
      status: "completed",
      stage: "completed",
      registration_state: null,
      registration_attempts: 2,
      canonical_preserved: true,
      failure_code: null,
      failure_message: null,
      retryable: false,
      bytes_received: 4_000,
      expected_bytes: 4_000,
      filename: "mem.img",
      extension: ".img",
      created_at: "2024-01-01T00:00:00Z",
      updated_at: "2024-01-01T00:00:00Z",
      is_active: false,
      cancellable: false,
      message: "Memory image uploaded and registered.",
    });
    renderPage();
    const button = await screen.findByTestId("memory-upload-retry-registration");
    fireEvent.click(button);
    await waitFor(() =>
      expect(screen.getByTestId("memory-analysis-page").textContent).toContain(`/memory/${EVIDENCE_ID}`),
    );
    expect(localStorage.getItem(`kairon-memory-upload:${CASE}`)).toBeNull();
  });

  it("7) shows the registration stage display with the v9 column value", async () => {
    setupFailedRegistration({ stage: "failed_registration" });
    renderPage();
    const stage = await screen.findByTestId("memory-upload-registration-stage");
    expect(stage.textContent).toBe("failed_registration");
  });

  it("8) shows the canonical-preserved banner and structured technical details", async () => {
    setupFailedRegistration({
      last_registration_error_code: "MEMORY_EVIDENCE_REGISTRATION_DB_CONSTRAINT",
      last_registration_error_class: "IntegrityError",
    });
    renderPage();
    expect(await screen.findByTestId("memory-upload-canonical-preserved")).toBeInTheDocument();
    const details = screen.getByTestId("memory-upload-technical-details");
    expect(details.textContent).toContain("MEMORY_EVIDENCE_REGISTRATION_DB_CONSTRAINT");
    expect(details.textContent).toContain("IntegrityError");
  });

  it("9) on error: stays on the page, surfaces the error, and does not navigate", async () => {
    setupFailedRegistration();
    (api.retryMemoryUploadRegistration as ReturnType<typeof vi.fn>).mockRejectedValue(
      new Error("MEMORY_EVIDENCE_REGISTRATION_RETRY_FAILED"),
    );
    renderPage();
    const button = await screen.findByTestId("memory-upload-retry-registration");
    fireEvent.click(button);
    await waitFor(() =>
      expect(button).not.toBeDisabled(),
    );
    expect(screen.queryByTestId("memory-analysis-page")).toBeNull();
    expect(button).toBeInTheDocument();
  });

  it("10) does NOT trigger a file picker on retry (no re-upload)", async () => {
    setupFailedRegistration();
    (api.retryMemoryUploadRegistration as ReturnType<typeof vi.fn>).mockResolvedValue({
      upload_id: UPLOAD_ID,
      case_id: CASE,
      evidence_id: EVIDENCE_ID,
      status: "completed",
      stage: "completed",
      registration_state: null,
      registration_attempts: 2,
      canonical_preserved: true,
      failure_code: null,
      failure_message: null,
      retryable: false,
      bytes_received: 4_000,
      expected_bytes: 4_000,
      filename: "mem.img",
      extension: ".img",
      created_at: "2024-01-01T00:00:00Z",
      updated_at: "2024-01-01T00:00:00Z",
      is_active: false,
      cancellable: false,
      message: "Memory image uploaded and registered.",
    });
    // Spy on the file input's click method: if the retry button
    // delegates to the file picker (e.g. by opening it), the spy
    // will be called.
    const clickSpy = vi.fn();
    const originalQuery = document.querySelector.bind(document);
    const fileInputDescriptor = Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype,
      "click",
    );
    Object.defineProperty(HTMLInputElement.prototype, "click", {
      configurable: true,
      value: function click(this: HTMLInputElement) {
        if (this.getAttribute("data-testid") === "memory-image-file-input") {
          clickSpy();
        } else if (fileInputDescriptor?.value) {
          fileInputDescriptor.value.call(this);
        }
      },
    });
    try {
      renderPage();
      const button = await screen.findByTestId("memory-upload-retry-registration");
      fireEvent.click(button);
      await waitFor(() =>
      expect(screen.getByTestId("memory-analysis-page").textContent).toContain(`/memory/${EVIDENCE_ID}`),
      );
      // The retry button must NOT have triggered the file picker.
      expect(clickSpy).not.toHaveBeenCalled();
      // The file input was never opened, no extra bytes were sent.
      expect(originalQuery("input[data-testid='memory-image-file-input']")).toBeNull();
    } finally {
      if (fileInputDescriptor) {
        Object.defineProperty(HTMLInputElement.prototype, "click", fileInputDescriptor);
      }
    }
  });

  it("11) structured error code from the API is shown in the technical details", async () => {
    setupFailedRegistration({
      last_registration_error_code: "MEMORY_EVIDENCE_REGISTRATION_DB_CONSTRAINT",
      last_registration_error_class: "IntegrityError",
    });
    renderPage();
    const details = await screen.findByTestId("memory-upload-technical-details");
    expect(details.textContent).toContain("code=MEMORY_EVIDENCE_REGISTRATION_DB_CONSTRAINT");
    expect(details.textContent).toContain("class=IntegrityError");
  });

  it("12) sensitive paths are not leaked in the registration recovery UI", async () => {
    setupFailedRegistration();
    renderPage();
    await screen.findByTestId("memory-upload-retry-registration");
    const body = document.body.textContent || "";
    expect(body).not.toMatch(/\/evidence\/[a-f0-9-]{36}/i);
    expect(body).not.toMatch(/\/app\/data\//);
    expect(body).not.toMatch(/tmp|kairon\/data/i);
  });
});
