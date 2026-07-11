import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type React from "react";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import FindingsWorkspace from "./FindingsWorkspace";

const listFindingsPageMock = vi.fn();
const createFindingMock = vi.fn();
const updateFindingMock = vi.fn();
const deleteFindingMock = vi.fn();
const runCorrelationMock = vi.fn();
const searchMock = vi.fn();
const extractAndResolveIndicatorsMock = vi.fn();

vi.mock("../api/client", () => ({
  api: {
    listFindingsPage: (...args: unknown[]) => listFindingsPageMock(...args),
    createFinding: (...args: unknown[]) => createFindingMock(...args),
    updateFinding: (...args: unknown[]) => updateFindingMock(...args),
    deleteFinding: (...args: unknown[]) => deleteFindingMock(...args),
    runCorrelation: (...args: unknown[]) => runCorrelationMock(...args),
    search: (...args: unknown[]) => searchMock(...args),
    extractAndResolveIndicators: (...args: unknown[]) => extractAndResolveIndicatorsMock(...args),
  },
}));

vi.mock("../context/NotificationsContext", () => ({
  useNotifications: () => ({ notify: vi.fn() }),
}));

vi.mock("../context/TimezoneContext", () => ({
  useTimezonePreference: () => ({ effectiveTimezone: "UTC" }),
}));

vi.mock("./ResponsiveDetailPanel", () => ({
  default: ({ children }: { children: React.ReactNode }) => <div role="dialog">{children}</div>,
}));

vi.mock("./IndicatorResolutionPanel", () => ({ default: () => <div /> }));
vi.mock("./EventTable", () => ({ default: () => <div /> }));
vi.mock("./PaginationControls", () => ({ default: () => <div /> }));

function finding(overrides: Record<string, unknown> = {}) {
  return {
    id: "finding-1",
    case_id: "case-1",
    title: "Suspicious memory artifact",
    body: "Suspicious process in memory",
    description: "Suspicious process in memory",
    severity: "high",
    status: "draft",
    tags: ["memory", "ctf"],
    linked_evidence_id: "evidence-1",
    linked_host_id: "host-1",
    source_view: "memory",
    event_ids: [],
    detection_ids: [],
    evidence_id: "evidence-1",
    timeline: [],
    related_event_ids: [],
    related_artifact_ids: [],
    related_process_node_ids: [],
    related_files: [],
    related_domains: [],
    related_ips: [],
    related_users: [],
    related_hosts: [],
    reasons: [],
    mitre: [],
    recommended_triage: [],
    data_quality: [],
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    ...overrides,
  };
}

function renderWorkspace(route = "/cases/case-1/findings") {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter initialEntries={[route]}>
      <QueryClientProvider client={queryClient}>
        <FindingsWorkspace caseId="case-1" evidenceId="evidence-1" hostId="host-1" />
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("FindingsWorkspace", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(window, "confirm").mockReturnValue(true);
    listFindingsPageMock.mockResolvedValue({ items: [], total: 0, page: 1, page_size: 100, total_pages: 0 });
    createFindingMock.mockImplementation((_caseId, payload) => Promise.resolve(finding({ id: "created", ...payload })));
    updateFindingMock.mockImplementation((_caseId, id, payload) => Promise.resolve(finding({ id, ...payload })));
    deleteFindingMock.mockResolvedValue(undefined);
    runCorrelationMock.mockResolvedValue({ report: { findings_generated: 0 }, findings: [] });
    searchMock.mockResolvedValue({ items: [] });
    extractAndResolveIndicatorsMock.mockResolvedValue({ indicators: [] });
  });

  it("shows empty state and creates a finding", async () => {
    renderWorkspace();
    expect(await screen.findByText("No findings yet.")).toBeInTheDocument();
    await userEvent.click(screen.getAllByRole("button", { name: /Create finding/i })[0]);
    const dialog = screen.getByRole("dialog", { name: /Finding editor/i });
    await userEvent.type(within(dialog).getByLabelText(/Title/i), "Manual note");
    await userEvent.type(within(dialog).getByLabelText(/Body/i), "Needs later review");
    await userEvent.selectOptions(within(dialog).getByLabelText(/Severity/i), "critical");
    await userEvent.type(within(dialog).getByLabelText(/Tags/i), "memory, confirmed");
    await userEvent.click(within(dialog).getByRole("button", { name: /Save finding/i }));
    await waitFor(() => expect(createFindingMock).toHaveBeenCalledWith("case-1", expect.objectContaining({ title: "Manual note", severity: "critical", tags: ["memory", "confirmed"], linked_evidence_id: "evidence-1", linked_host_id: "host-1" })));
  });

  it("filters by severity status and tag", async () => {
    listFindingsPageMock.mockResolvedValue({ items: [finding()], total: 1, page: 1, page_size: 100, total_pages: 1 });
    renderWorkspace();
    await screen.findByText("Suspicious memory artifact");
    await userEvent.selectOptions(screen.getByLabelText(/Severity/i), "high");
    await userEvent.selectOptions(screen.getByLabelText(/Status/i), "draft");
    await userEvent.selectOptions(screen.getByLabelText(/Finding tag filter/i), "memory");
    await waitFor(() => expect(listFindingsPageMock).toHaveBeenLastCalledWith("case-1", expect.objectContaining({ severity: "high", status: "draft", tag: "memory" })));
  });

  it("edits and archives a finding", async () => {
    listFindingsPageMock.mockResolvedValue({ items: [finding()], total: 1, page: 1, page_size: 100, total_pages: 1 });
    renderWorkspace();
    await screen.findByText("Suspicious memory artifact");
    await userEvent.click(screen.getByText("Edit"));
    const dialog = screen.getByRole("dialog", { name: /Finding editor/i });
    await userEvent.clear(within(dialog).getByLabelText(/Title/i));
    await userEvent.type(within(dialog).getByLabelText(/Title/i), "Updated finding");
    await userEvent.click(within(dialog).getByRole("button", { name: /Save finding/i }));
    await waitFor(() => expect(updateFindingMock).toHaveBeenCalledWith("case-1", "finding-1", expect.objectContaining({ title: "Updated finding" })));
    await userEvent.click(screen.getByText("Archive"));
    await waitFor(() => expect(deleteFindingMock).toHaveBeenCalledWith("case-1", "finding-1"));
  });

  it("opens contextual create form from URL", async () => {
    renderWorkspace("/cases/case-1/findings?create=1&evidence_id=evidence-1&host_id=host-1&source_view=memory&title=Suspicious%20memory%20artifact");
    const dialog = await screen.findByRole("dialog", { name: /Finding editor/i });
    expect(within(dialog).getByLabelText(/Title/i)).toHaveValue("Suspicious memory artifact");
    expect(within(dialog).getByLabelText(/Linked evidence/i)).toHaveValue("evidence-1");
    expect(within(dialog).getByLabelText(/Linked host/i)).toHaveValue("host-1");
  });
});
