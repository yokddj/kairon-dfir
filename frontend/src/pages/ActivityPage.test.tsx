import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import ActivityPage from "./ActivityPage";
import type { ActivityCenterResponse } from "../api/client";

const listCasesMock = vi.fn();
const listActivityMock = vi.fn();
const getCaseActivityMock = vi.fn();
const cancelEvidenceUploadSessionMock = vi.fn();
const retryEvidenceOperationMock = vi.fn();
const dismissEvidenceOperationMock = vi.fn();
const navigateMock = vi.fn();

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return { ...actual, useNavigate: () => navigateMock };
});

vi.mock("../api/client", () => ({
  api: {
    listCases: (...args: unknown[]) => listCasesMock(...args),
    listActivity: (...args: unknown[]) => listActivityMock(...args),
    getCaseActivity: (...args: unknown[]) => getCaseActivityMock(...args),
    cancelEvidenceUploadSession: (...args: unknown[]) => cancelEvidenceUploadSessionMock(...args),
    retryEvidenceOperation: (...args: unknown[]) => retryEvidenceOperationMock(...args),
    dismissEvidenceOperation: (...args: unknown[]) => dismissEvidenceOperationMock(...args),
  },
}));

vi.mock("../context/ActiveCaseContext", () => ({
  useActiveCase: () => ({ activeCaseId: "case-1", setActiveCaseId: vi.fn() }),
}));

vi.mock("../context/TimezoneContext", () => ({
  useTimezonePreference: () => ({ effectiveTimezone: "UTC" }),
}));

function activityResponse(overrides: Partial<ActivityCenterResponse> = {}): ActivityCenterResponse {
  return {
    case_id: "case-1",
    summary: { Uploads: 1 },
    operations: [],
    ...overrides,
  };
}

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(
    <MemoryRouter>
      <QueryClientProvider client={queryClient}>
        <ActivityPage />
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("ActivityPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    listCasesMock.mockResolvedValue([{ id: "case-1", name: "Case One" }]);
    listActivityMock.mockResolvedValue([]);
    cancelEvidenceUploadSessionMock.mockResolvedValue({ status: "cancelled", session_id: "upload-session-1" });
  });

  it("enables Continue wizard and Cancel for an upload operation that is actively uploading, not only when interrupted", async () => {
    // Regression test: app.services.evidence_operations._operation_status()
    // projects an in-progress EvidenceUploadSession onto "uploading",
    // "waiting_upload", "preflight", or "waiting_user" -- it never actually
    // produces "running" (that's the fallback for other operation kinds).
    // Gating these buttons on ["running", "paused"] left them disabled for
    // every upload except an interrupted one.
    getCaseActivityMock.mockResolvedValue(activityResponse({
      operations: [{
        id: "op-1",
        case_id: "case-1",
        kind: "upload",
        category: "Uploads",
        status: "uploading",
        stage: "uploading",
        label: "capture.mem",
        progress: 40,
        bytes_received: 400,
        expected_size_bytes: 1000,
        current_owner: "browser",
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        last_activity_at: new Date().toISOString(),
        elapsed_seconds: 12,
        details: { upload_session_id: "upload-session-1" },
      }],
    }));

    renderPage();

    const continueButton = await screen.findByRole("button", { name: "Continue wizard" });
    await waitFor(() => expect(continueButton).toBeEnabled());
    const cancelButton = screen.getByRole("button", { name: "Cancel" });
    expect(cancelButton).toBeEnabled();

    await userEvent.click(continueButton);
    expect(navigateMock).toHaveBeenCalledWith("/cases/case-1?tab=evidences&resume_session=upload-session-1");

    await userEvent.click(cancelButton);
    await waitFor(() => expect(cancelEvidenceUploadSessionMock).toHaveBeenCalledWith("case-1", "upload-session-1"));
  });

  it("keeps Continue wizard and Cancel disabled once an upload operation is completed", async () => {
    getCaseActivityMock.mockResolvedValue(activityResponse({
      operations: [{
        id: "op-2",
        case_id: "case-1",
        kind: "upload",
        category: "Completed",
        status: "completed",
        stage: "completed",
        label: "capture.mem",
        progress: 100,
        bytes_received: 1000,
        expected_size_bytes: 1000,
        current_owner: "database",
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        last_activity_at: new Date().toISOString(),
        elapsed_seconds: 60,
        details: { upload_session_id: "upload-session-2", promoted_evidence_id: "evidence-2" },
      }],
    }));

    renderPage();

    const continueButton = await screen.findByRole("button", { name: "Continue wizard" });
    expect(continueButton).toBeDisabled();
    expect(screen.getByRole("button", { name: "Cancel" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Dismiss completed" })).toBeEnabled();
  });
});
