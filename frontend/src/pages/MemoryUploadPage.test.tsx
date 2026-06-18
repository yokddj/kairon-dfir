import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import MemoryUploadPage from "./MemoryUploadPage";

const getMemoryUploadReadinessMock = vi.fn();
const uploadEvidenceMock = vi.fn();
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
    getMemoryUploadReadinessMock.mockResolvedValue(readiness());
    uploadEvidenceMock.mockResolvedValue({ id: "ev-memory", evidence_type: "memory_dump", size_bytes: 6, sha256: "0".repeat(64) });
  });

  it("renders dedicated memory upload readiness and privacy acknowledgement", async () => {
    renderPage();

    expect(await screen.findByRole("heading", { name: /Add memory image/i })).toBeInTheDocument();
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
});
