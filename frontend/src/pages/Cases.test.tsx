import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import Cases from "./Cases";

const listCasesMock = vi.fn();
const createCaseMock = vi.fn();
const updateCaseMock = vi.fn();
const archiveCaseMock = vi.fn();
const unarchiveCaseMock = vi.fn();
const closeCaseMock = vi.fn();
const reopenCaseMock = vi.fn();
const deleteCaseMock = vi.fn();

vi.mock("../api/client", () => ({
  api: {
    listCases: (...args: unknown[]) => listCasesMock(...args),
    createCase: (...args: unknown[]) => createCaseMock(...args),
    updateCase: (...args: unknown[]) => updateCaseMock(...args),
    archiveCase: (...args: unknown[]) => archiveCaseMock(...args),
    unarchiveCase: (...args: unknown[]) => unarchiveCaseMock(...args),
    closeCase: (...args: unknown[]) => closeCaseMock(...args),
    reopenCase: (...args: unknown[]) => reopenCaseMock(...args),
    deleteCase: (...args: unknown[]) => deleteCaseMock(...args),
  },
}));

vi.mock("../context/ActiveCaseContext", () => ({
  useActiveCase: () => ({
    activeCaseId: "",
    clearActiveCase: vi.fn(),
    setActiveCase: vi.fn(),
  }),
}));

const notifyMock = vi.fn();
vi.mock("../context/NotificationsContext", () => ({
  useNotifications: () => ({ notify: notifyMock }),
}));

function caseItem(overrides: Record<string, unknown> = {}) {
  return {
    id: "case-1",
    name: "Memory Lab",
    description: "CTF memory investigation",
    status: "active",
    priority: "high",
    tags: ["ctf", "memory"],
    case_notes: "Initial notes",
    mode: "investigation",
    timezone: null,
    evidence_count: 2,
    host_count: 1,
    processing_summary: { completed: 1, failed: 1 },
    detections_count: 0,
    findings_count: 0,
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-02T00:00:00Z",
    ...overrides,
  };
}

function renderPage(initialPath = "/cases") {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter initialEntries={[initialPath]}>
      <QueryClientProvider client={queryClient}>
        <Cases />
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("Cases page", () => {
  let deletedIds: Set<string>;

  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(window, "confirm").mockReturnValue(true);
    deletedIds = new Set();
    listCasesMock.mockImplementation((params) => {
      const cases = [
        caseItem(),
        caseItem({ id: "case-2", name: "Archived Ransomware", status: "archived", priority: "critical", tags: ["ransomware", "windows"], description: "Archived case" }),
      ].filter((item) => !deletedIds.has(item.id));
      return params?.include_archived ? cases : cases.filter((item) => item.status !== "archived");
    });
    createCaseMock.mockImplementation((payload) => caseItem({ id: "created", ...payload }));
    updateCaseMock.mockImplementation((_id, payload) => caseItem({ ...payload }));
    archiveCaseMock.mockImplementation((id) => caseItem({ id, status: "archived" }));
    unarchiveCaseMock.mockImplementation((id) => caseItem({ id, status: "active" }));
    closeCaseMock.mockImplementation((id) => caseItem({ id, status: "closed" }));
    reopenCaseMock.mockImplementation((id) => caseItem({ id, status: "active" }));
    deleteCaseMock.mockImplementation((id: string) => {
      deletedIds.add(id);
      return Promise.resolve({ status: "deleted", case_id: id, cleanup: {} });
    });
  });

  it("uses generic placeholders for case creation", async () => {
    renderPage();
    expect(screen.getByPlaceholderText("ACME Incident 001")).toBeInTheDocument();
    expect(screen.getByPlaceholderText("Short description of the investigation scope")).toBeInTheDocument();
    expect(await screen.findByText("Memory Lab")).toBeInTheDocument();
  });

  it("shows status priority tags and operational counts", async () => {
    renderPage();
    const card = (await screen.findByText("Memory Lab")).closest('[data-testid="case-card"]')!;
    expect(card).toHaveTextContent("active");
    expect(card).toHaveTextContent("high");
    expect(card).toHaveTextContent("#ctf");
    expect(card).toHaveTextContent("2 evidences");
    expect(card).toHaveTextContent("1 hosts");
  });

  it("passes search status priority tag include archived and sort filters to API", async () => {
    renderPage("/cases?q=memory&status=active&priority=high&tag=ctf&include_archived=true&sort=priority");
    await screen.findByText("Memory Lab");
    expect(listCasesMock).toHaveBeenCalledWith(expect.objectContaining({ q: "memory", status: "active", priority: "high", tag: "ctf", include_archived: true, sort: "priority" }));
    expect(screen.getByText("Archived Ransomware")).toBeInTheDocument();
  });

  it("updates filters from controls without breaking case links", async () => {
    renderPage();
    await userEvent.type(await screen.findByPlaceholderText(/Search name/i), "ram");
    await userEvent.selectOptions(screen.getByLabelText(/Status filter/i), "active");
    await userEvent.selectOptions(screen.getByLabelText(/Priority filter/i), "high");
    expect(await screen.findByRole("link", { name: /Memory Lab/i })).toHaveAttribute("href", "/cases/case-1/overview");
    await waitFor(() => expect(listCasesMock).toHaveBeenLastCalledWith(expect.objectContaining({ q: "ram", status: "active", priority: "high" })));
  });

  it("include archived shows archived cases", async () => {
    renderPage();
    expect(await screen.findByText("Memory Lab")).toBeInTheDocument();
    expect(screen.queryByText("Archived Ransomware")).not.toBeInTheDocument();
    await userEvent.click(screen.getByLabelText(/Include archived/i));
    expect(await screen.findByText("Archived Ransomware")).toBeInTheDocument();
  });

  it("archive close and reopen actions call API", async () => {
    renderPage();
    await screen.findByText("Memory Lab");
    await userEvent.click(screen.getAllByRole("button", { name: "Archive" })[0]);
    await waitFor(() => expect(archiveCaseMock).toHaveBeenCalledWith("case-1"));
    await userEvent.click(screen.getAllByRole("button", { name: "Close" })[0]);
    await waitFor(() => expect(closeCaseMock).toHaveBeenCalledWith("case-1"));
  });

  it("edit case saves description tags priority and status", async () => {
    renderPage();
    await userEvent.click((await screen.findAllByRole("button", { name: /Edit case/i }))[0]);
    const dialog = screen.getByRole("dialog", { name: /Edit case/i });
    await userEvent.selectOptions(within(dialog).getByLabelText(/Priority/i), "critical");
    await userEvent.clear(within(dialog).getByLabelText(/Tags/i));
    await userEvent.type(within(dialog).getByLabelText(/Tags/i), "ctf, memory, lab");
    await userEvent.clear(within(dialog).getByLabelText(/Description/i));
    await userEvent.type(within(dialog).getByLabelText(/Description/i), "Updated description");
    await userEvent.click(within(dialog).getByRole("button", { name: /Save case/i }));
    await waitFor(() => expect(updateCaseMock).toHaveBeenCalledWith("case-1", expect.objectContaining({ priority: "critical", tags: ["ctf", "memory", "lab"], description: "Updated description" })));
  });

  it("shows clear empty state", async () => {
    listCasesMock.mockResolvedValueOnce([]);
    renderPage("/cases?q=missing");
    expect(await screen.findByText(/No active cases match your filters/i)).toBeInTheDocument();
  });

  describe("Delete Case", () => {
    it("shows a Delete button on every case card", async () => {
      renderPage();
      await screen.findByText("Memory Lab");
      expect(screen.getAllByRole("button", { name: "Delete" }).length).toBeGreaterThan(0);
    });

    it("opens a confirmation dialog with the deletion scope", async () => {
      renderPage();
      await screen.findByText("Memory Lab");
      await userEvent.click(screen.getAllByRole("button", { name: "Delete" })[0]);
      const dialog = await screen.findByRole("dialog", { name: "Delete Case" });
      expect(within(dialog).getByText(/permanently delete this investigation/i)).toBeInTheDocument();
      expect(within(dialog).getByText("Evidence")).toBeInTheDocument();
      expect(within(dialog).getByText("Memory images")).toBeInTheDocument();
      expect(within(dialog).getByText("Search index")).toBeInTheDocument();
    });

    it("keeps Delete disabled until the exact case name is typed", async () => {
      renderPage();
      await screen.findByText("Memory Lab");
      await userEvent.click(screen.getAllByRole("button", { name: "Delete" })[0]);
      const dialog = await screen.findByRole("dialog", { name: "Delete Case" });
      const confirmButton = within(dialog).getByRole("button", { name: "Delete Case" });
      expect(confirmButton).toBeDisabled();

      await userEvent.type(within(dialog).getByRole("textbox"), "Memory La");
      expect(confirmButton).toBeDisabled();
      expect(deleteCaseMock).not.toHaveBeenCalled();

      await userEvent.type(within(dialog).getByRole("textbox"), "b");
      expect(confirmButton).toBeEnabled();
    });

    it("deletes the case, shows a toast, and removes the card without a refresh", async () => {
      renderPage();
      await screen.findByText("Memory Lab");
      await userEvent.click(screen.getAllByRole("button", { name: "Delete" })[0]);
      const dialog = await screen.findByRole("dialog", { name: "Delete Case" });
      await userEvent.type(within(dialog).getByRole("textbox"), "Memory Lab");
      await userEvent.click(within(dialog).getByRole("button", { name: "Delete Case" }));

      await waitFor(() => expect(deleteCaseMock).toHaveBeenCalledWith("case-1"));
      await waitFor(() => expect(notifyMock).toHaveBeenCalledWith(expect.objectContaining({ title: "Case deleted", description: "Case deleted successfully.", tone: "success" })));
      await waitFor(() => expect(screen.queryByText("Memory Lab")).not.toBeInTheDocument());
    });

    it("shows a clear error message when deletion fails", async () => {
      deleteCaseMock.mockRejectedValueOnce(new Error("Case cannot be deleted while processing is active."));
      renderPage();
      await screen.findByText("Memory Lab");
      await userEvent.click(screen.getAllByRole("button", { name: "Delete" })[0]);
      const dialog = await screen.findByRole("dialog", { name: "Delete Case" });
      await userEvent.type(within(dialog).getByRole("textbox"), "Memory Lab");
      await userEvent.click(within(dialog).getByRole("button", { name: "Delete Case" }));

      expect(await within(dialog).findByText("Case cannot be deleted while processing is active.")).toBeInTheDocument();
      expect(screen.getByTestId("case-card")).toHaveTextContent("Memory Lab");
    });
  });
});
