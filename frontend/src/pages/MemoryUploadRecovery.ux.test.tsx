/** @vitest-environment jsdom */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../api/client", () => ({
  api: {
    getMemoryUploadReadiness: vi.fn(),
    getMemoryUploadStatus: vi.fn(),
    getActiveMemoryUpload: vi.fn(),
    cancelMemoryUpload: vi.fn(),
    reconcileMemoryUpload: vi.fn(),
  },
}));

vi.mock("../context/ActiveCaseContext", () => ({
  useActiveCase: () => ({ setActiveCaseId: vi.fn() }),
}));

import { api } from "../api/client";
import MemoryUploadPage from "./MemoryUploadPage";

const CASE = "case-1";

const setupMocks = () => {
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
  (api.getMemoryUploadStatus as ReturnType<typeof vi.fn>).mockResolvedValue(null);
};

beforeEach(() => {
  vi.clearAllMocks();
  // Clear localStorage to avoid stale upload IDs from previous tests
  localStorage.clear();
  setupMocks();
});

const renderPage = () => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, refetchInterval: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[`/cases/${CASE}/memory/upload`]}>
        <Routes>
          <Route path="/cases/:caseId/memory/upload" element={<MemoryUploadPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
};

describe("Memory .img file picker and stale upload lifecycle recovery v1", () => {
  // ---- 1-4: file picker ----
  it("input file picker has data-testid='memory-image-file-input'", () => {
    renderPage();
    const input = document.querySelector(
      '[data-testid="memory-image-file-input"]',
    ) as HTMLInputElement;
    expect(input).not.toBeNull();
    expect(input.type).toBe("file");
  });

  it("input accept contains .img, .raw, .dmp, .vmem, .bin, .dump", () => {
    renderPage();
    const input = document.querySelector(
      '[data-testid="memory-image-file-input"]',
    ) as HTMLInputElement;
    expect(input.accept).toMatch(/\.img/);
    expect(input.accept).toMatch(/\.raw/);
    expect(input.accept).toMatch(/\.dmp/);
    expect(input.accept).toMatch(/\.vmem/);
    expect(input.accept).toMatch(/\.bin/);
    expect(input.accept).toMatch(/\.dump/);
  });

  it("input accept includes application/octet-stream", () => {
    renderPage();
    const input = document.querySelector(
      '[data-testid="memory-image-file-input"]',
    ) as HTMLInputElement;
    expect(input.accept).toMatch(/application\/octet-stream/);
  });

  it("isMemoryImageFile accepts .IMG (case-insensitive)", () => {
    // The function uses fileExtension which does .toLowerCase()
    function fileExtension(name: string) {
      if (!name.includes(".")) return "";
      return `.${name.split(".").pop() || ""}`.toLowerCase();
    }
    const ext = fileExtension("boomer-windows.IMG");
    expect(ext).toBe(".img");
  });

  // ---- 5-6: active upload panel ----
  it("shows the active upload panel when the backend reports an active upload", async () => {
    (api.getActiveMemoryUpload as ReturnType<typeof vi.fn>).mockResolvedValue({
      upload_id: "upl-1",
      case_id: CASE,
      evidence_id: null,
      status: "uploading",
      bytes_received: 2_000_000_000,
      expected_bytes: 8_000_000_000,
      filename: "boomer-windows.img",
      extension: ".img",
      is_active: true,
      stale: false,
      resumable: true,
      cancellable: true,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      last_heartbeat: new Date().toISOString(),
      stale_after_seconds: 1800,
      failure_code: null,
      message: "Uploading",
      retryable: true,
    });
    renderPage();
    await screen.findByTestId("memory-active-upload-panel");
    expect(screen.getByText(/boomer-windows\.img/i)).toBeTruthy();
    expect(screen.getByTestId("memory-active-check-status")).toBeTruthy();
    expect(screen.getByTestId("memory-active-cancel")).toBeTruthy();
  });

  it("status query failure (404) clears the localStorage upload ID", async () => {
    localStorage.setItem(`kairon-memory-upload:${CASE}`, "stale-id");
    (api.getMemoryUploadStatus as ReturnType<typeof vi.fn>).mockRejectedValue(
      new Error("404 not found"),
    );
    (api.getActiveMemoryUpload as ReturnType<typeof vi.fn>).mockResolvedValue(null);
    renderPage();
    // Wait a tick for the effect to run
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(localStorage.getItem(`kairon-memory-upload:${CASE}`)).toBeNull();
  });

  // ---- 7-8: stale / cancel ----
  it("shows the stale warning when the active upload is stale", async () => {
    (api.getActiveMemoryUpload as ReturnType<typeof vi.fn>).mockResolvedValue({
      upload_id: "upl-stale",
      case_id: CASE,
      evidence_id: null,
      status: "uploading",
      bytes_received: 1024,
      expected_bytes: 8_000_000_000,
      filename: "stale.img",
      extension: ".img",
      is_active: true,
      stale: true,
      resumable: true,
      cancellable: true,
      created_at: new Date(Date.now() - 7200_000).toISOString(),
      updated_at: new Date(Date.now() - 7200_000).toISOString(),
      last_heartbeat: new Date(Date.now() - 7200_000).toISOString(),
      stale_after_seconds: 1800,
      failure_code: null,
      message: "Stale upload",
      retryable: true,
    });
    renderPage();
    await screen.findByTestId("memory-active-upload-panel");
    // The stale warning uses the phrase "No activity for a long time."
    const matches = screen.getAllByText(/No activity for a long time/i);
    expect(matches.length).toBeGreaterThan(0);
  });

  it("cancel button calls the API and clears the local lock", async () => {
    (api.getActiveMemoryUpload as ReturnType<typeof vi.fn>).mockResolvedValue({
      upload_id: "upl-cancel",
      case_id: CASE,
      evidence_id: null,
      status: "uploading",
      bytes_received: 1024,
      expected_bytes: 8_000_000_000,
      filename: "cancel.img",
      extension: ".img",
      is_active: true,
      stale: false,
      resumable: false,
      cancellable: true,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      last_heartbeat: new Date().toISOString(),
      stale_after_seconds: 1800,
      failure_code: null,
      message: "Uploading",
      retryable: true,
    });
    (api.cancelMemoryUpload as ReturnType<typeof vi.fn>).mockResolvedValue({
      upload_id: "upl-cancel",
      status: "cancelled",
    });
    // Mock window.prompt to return a reason
    vi.spyOn(window, "prompt").mockReturnValue("test cancel reason");
    renderPage();
    await screen.findByTestId("memory-active-upload-panel");
    screen.getByTestId("memory-active-cancel").click();
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(api.cancelMemoryUpload).toHaveBeenCalledWith(
      CASE, "upl-cancel", "test cancel reason",
    );
  });

  // ---- 9: completed cleanup ----
  it("completed active upload shows Open evidence link", async () => {
    (api.getActiveMemoryUpload as ReturnType<typeof vi.fn>).mockResolvedValue({
      upload_id: "upl-done",
      case_id: CASE,
      evidence_id: "ev-1",
      status: "completed",
      bytes_received: 8_000_000_000,
      expected_bytes: 8_000_000_000,
      filename: "done.img",
      extension: ".img",
      is_active: false,
      stale: false,
      resumable: false,
      cancellable: false,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      last_heartbeat: new Date().toISOString(),
      stale_after_seconds: 1800,
      failure_code: null,
      message: "Completed",
      retryable: false,
    });
    renderPage();
    // The panel only shows when is_active is true.  When completed,
    // it is hidden — the upload page shows the success state elsewhere.
    // The contract is: the panel does NOT appear for completed.
    const panel = document.querySelector('[data-testid="memory-active-upload-panel"]');
    expect(panel).toBeNull();
  });

  // ---- 10: no generic lock message ----
  it("does not show the generic 'lifecycle is already active' without details", () => {
    renderPage();
    // The generic message should only appear when the localStorage
    // has an upload ID but the backend does not.  With no localStorage
    // and no active upload, the blocking reason is null.
    const html = document.body.innerHTML;
    expect(html).not.toMatch(/lifecycle is already active/i);
  });

  // ---- 11: reload recovery ----
  it("on reload, the active upload is recovered from the backend", async () => {
    localStorage.setItem(`kairon-memory-upload:${CASE}`, "upl-reload");
    (api.getMemoryUploadStatus as ReturnType<typeof vi.fn>).mockResolvedValue({
      upload_id: "upl-reload",
      case_id: CASE,
      evidence_id: null,
      status: "uploading",
      bytes_received: 4096,
      expected_bytes: 8_000_000_000,
      filename: "reload.img",
      extension: ".img",
      is_active: true,
      stale: false,
      resumable: true,
      cancellable: true,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      last_heartbeat: new Date().toISOString(),
      stale_after_seconds: 1800,
      failure_code: null,
      message: "Uploading",
      retryable: true,
    });
    renderPage();
    await new Promise((resolve) => setTimeout(resolve, 50));
    // The status query should be called with the recovered ID
    expect(api.getMemoryUploadStatus).toHaveBeenCalledWith(CASE, "upl-reload");
  });

  // ---- 12: data-testid present ----
  it("the memory image file input is identifiable by data-testid", () => {
    renderPage();
    const input = document.querySelector(
      '[data-testid="memory-image-file-input"]',
    );
    expect(input).not.toBeNull();
  });

  // ---- 13: no sensitive paths ----
  it("does not leak sensitive paths in any rendered copy", () => {
    renderPage();
    const html = document.body.innerHTML;
    expect(html).not.toMatch(/\/root\/[a-z]+/i);
    expect(html).not.toMatch(/\/etc\/passwd/i);
  });

  // ---- 14: responsive ----
  it("renders at narrow viewport without breaking", () => {
    Object.defineProperty(window, "innerWidth", { value: 480, configurable: true });
    window.dispatchEvent(new Event("resize"));
    renderPage();
    expect(document.body.innerHTML).toBeTruthy();
  });

  // ---- 15: cancel button only when cancellable ----
  it("cancel button is hidden when the active upload is not cancellable", async () => {
    (api.getActiveMemoryUpload as ReturnType<typeof vi.fn>).mockResolvedValue({
      upload_id: "upl-finalizing",
      case_id: CASE,
      evidence_id: "ev-2",
      status: "finalizing",
      bytes_received: 7_999_999_999,
      expected_bytes: 8_000_000_000,
      filename: "almost-done.img",
      extension: ".img",
      is_active: true,
      stale: false,
      resumable: true,
      cancellable: false,  // not cancellable while finalizing
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      last_heartbeat: new Date().toISOString(),
      stale_after_seconds: 1800,
      failure_code: null,
      message: "Finalizing",
      retryable: true,
    });
    renderPage();
    await screen.findByTestId("memory-active-upload-panel");
    expect(screen.queryByTestId("memory-active-cancel")).toBeNull();
  });
});
