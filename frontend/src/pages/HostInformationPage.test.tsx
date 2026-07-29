import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import HostInformationPage from "./HostInformationPage";
import type { CaseHostFactsResponse } from "../api/client";

const getCaseHostFactsMock = vi.fn();
const useActiveCaseMock = vi.fn();

vi.mock("../api/client", () => ({
  api: {
    getCaseHostFacts: (...args: unknown[]) => getCaseHostFactsMock(...args),
  },
}));

vi.mock("../context/ActiveCaseContext", () => ({
  useActiveCase: () => useActiveCaseMock(),
}));

type HostSummary = { id: string; display_name: string; canonical_name: string };

function host(overrides: Partial<HostSummary> = {}): HostSummary {
  return { id: "host-1", display_name: "webserver-01", canonical_name: "webserver-01", ...overrides };
}

function activeCaseValue(hosts: HostSummary[], loading = false) {
  return {
    setActiveCaseId: vi.fn(),
    caseContext: { hosts },
    isCaseContextLoading: loading,
  };
}

function observation(overrides: Partial<CaseHostFactsResponse["facts"][number]["observations"][number]> = {}) {
  return {
    id: "obs-1",
    source_kind: "hostname",
    parser: "linux_os_info",
    source_path: "/etc/hostname",
    raw_value: "webserver-01",
    normalized_value: "webserver-01",
    confidence: "high",
    status: "confirmed",
    observed_at: "2026-01-01T00:00:00Z",
    event_id: null,
    evidence_id: "ev-1",
    artifact_id: "art-1",
    host_id: "host-1",
    provenance: {},
    created_at: "2026-01-01T00:00:00Z",
    ...overrides,
  };
}

function factsResponse(facts: CaseHostFactsResponse["facts"]): CaseHostFactsResponse {
  return { case_id: "case-1", scope: "host", host_id: "host-1", facts };
}

function renderPage(path = "/cases/case-1/host-information") {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter initialEntries={[path]}>
      <QueryClientProvider client={queryClient}>
        <Routes>
          <Route path="/cases/:caseId/host-information" element={<HostInformationPage />} />
        </Routes>
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("HostInformationPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("shows an empty state when the case has no identified hosts", async () => {
    useActiveCaseMock.mockReturnValue(activeCaseValue([]));
    renderPage();
    expect(await screen.findByTestId("no-hosts-state")).toBeInTheDocument();
    expect(getCaseHostFactsMock).not.toHaveBeenCalled();
  });

  it("prompts for a selection when a case has multiple hosts and none is chosen yet", async () => {
    useActiveCaseMock.mockReturnValue(activeCaseValue([host({ id: "host-1" }), host({ id: "host-2", display_name: "db-02" })]));
    renderPage();
    expect(await screen.findByTestId("no-host-selected-state")).toBeInTheDocument();
    expect(screen.getByTestId("host-selector")).toBeInTheDocument();
    expect(getCaseHostFactsMock).not.toHaveBeenCalled();
  });

  it("auto-selects the only host in a single-host case and fetches its facts exactly once", async () => {
    useActiveCaseMock.mockReturnValue(activeCaseValue([host()]));
    getCaseHostFactsMock.mockResolvedValue(factsResponse([]));
    renderPage();

    await waitFor(() => expect(getCaseHostFactsMock).toHaveBeenCalledTimes(1));
    expect(getCaseHostFactsMock).toHaveBeenCalledWith("case-1", { host_id: "host-1" });
    // No selector should be rendered when there is nothing to choose between.
    expect(screen.queryByTestId("host-selector")).not.toBeInTheDocument();
  });

  it("renders all four fact groups with their scoped labels", async () => {
    useActiveCaseMock.mockReturnValue(activeCaseValue([host()]));
    getCaseHostFactsMock.mockResolvedValue(factsResponse([]));
    renderPage();

    const groups = await screen.findByTestId("host-fact-groups");
    for (const label of ["Identity", "Operating System", "Platform", "Time"]) {
      expect(within(groups).getByText(label)).toBeInTheDocument();
    }
    for (const label of ["Hostname", "FQDN", "Distribution", "Version", "Kernel", "Architecture", "Timezone"]) {
      expect(within(groups).getByText(label)).toBeInTheDocument();
    }
  });

  it("renders a confirmed fact with its preferred value, status, and observation count", async () => {
    useActiveCaseMock.mockReturnValue(activeCaseValue([host()]));
    getCaseHostFactsMock.mockResolvedValue(
      factsResponse([
        {
          fact_type: "host.hostname",
          status: "confirmed",
          preferred_value: "webserver-01",
          supporting: [observation()],
          conflicting: [],
          invalid: [],
          observations: [observation()],
        },
      ]),
    );
    renderPage();

    const preferred = await screen.findByTestId("fact-preferred-value");
    expect(preferred).toHaveTextContent("webserver-01");
    const statusPills = screen.getAllByTestId("fact-status");
    expect(statusPills.some((el) => el.textContent === "Confirmed")).toBe(true);
    expect(screen.getAllByText("1 observation").length).toBeGreaterThan(0);
  });

  it("renders an unobserved fact as explicitly not collected, never fabricated", async () => {
    useActiveCaseMock.mockReturnValue(activeCaseValue([host()]));
    getCaseHostFactsMock.mockResolvedValue(factsResponse([]));
    renderPage();

    await screen.findByTestId("host-fact-groups");
    const missingValues = screen.getAllByTestId("fact-missing-value");
    expect(missingValues.length).toBe(7);
    for (const el of missingValues) expect(el).toHaveTextContent("Not collected");
    const statusPills = screen.getAllByTestId("fact-status");
    expect(statusPills.every((el) => el.textContent === "Not collected")).toBe(true);
  });

  it("shows conflicting observations as visually distinct groups, never merged", async () => {
    useActiveCaseMock.mockReturnValue(activeCaseValue([host()]));
    const supportingObs = observation({ id: "obs-support", raw_value: "webserver-01", normalized_value: "webserver-01" });
    const conflictingObs = observation({ id: "obs-conflict", raw_value: "old-hostname", normalized_value: "old-hostname", source_kind: "hostnamectl", status: "conflicting" });
    getCaseHostFactsMock.mockResolvedValue(
      factsResponse([
        {
          fact_type: "host.hostname",
          status: "conflicting",
          preferred_value: "webserver-01",
          supporting: [supportingObs],
          conflicting: [conflictingObs],
          invalid: [],
          observations: [supportingObs, conflictingObs],
        },
      ]),
    );
    renderPage();

    await screen.findByTestId("host-fact-groups");
    const statusPills = screen.getAllByTestId("fact-status");
    expect(statusPills.some((el) => el.textContent === "Conflicting")).toBe(true);

    await userEvent.click(screen.getByText("Show sources"));
    const observations = await screen.findAllByTestId("fact-observation");
    const supportingCards = observations.filter((el) => el.dataset.kind === "supporting");
    const conflictingCards = observations.filter((el) => el.dataset.kind === "conflicting");
    expect(supportingCards).toHaveLength(1);
    expect(conflictingCards).toHaveLength(1);
    expect(within(supportingCards[0]).getByText("webserver-01")).toBeInTheDocument();
    expect(within(conflictingCards[0]).getByText("old-hostname")).toBeInTheDocument();
  });

  it("builds provenance pivot links into Search and Artifact Views without inventing a new search engine", async () => {
    useActiveCaseMock.mockReturnValue(activeCaseValue([host()]));
    getCaseHostFactsMock.mockResolvedValue(
      factsResponse([
        {
          fact_type: "host.hostname",
          status: "confirmed",
          preferred_value: "webserver-01",
          supporting: [observation()],
          conflicting: [],
          invalid: [],
          observations: [observation()],
        },
      ]),
    );
    renderPage();

    const preferred = await screen.findByTestId("fact-preferred-value");
    expect(preferred).toHaveAttribute("href", "/cases/case-1/search?host_id=host-1&q=webserver-01");

    await userEvent.click(screen.getByText("Show sources"));
    const searchLink = await screen.findByTestId("pivot-search");
    expect(searchLink).toHaveAttribute("href", "/cases/case-1/search?host_id=host-1&q=webserver-01");
    const artifactLink = screen.getByTestId("pivot-artifact");
    expect(artifactLink).toHaveAttribute("href", "/cases/case-1/artifacts?q=%2Fetc%2Fhostname");
  });

  it("switches hosts through the selector, updates the URL, and fetches facts per host without duplicate requests", async () => {
    useActiveCaseMock.mockReturnValue(activeCaseValue([host({ id: "host-1", display_name: "webserver-01" }), host({ id: "host-2", display_name: "db-02" })]));
    getCaseHostFactsMock.mockResolvedValue(factsResponse([]));
    renderPage("/cases/case-1/host-information?host_id=host-1");

    await waitFor(() => expect(getCaseHostFactsMock).toHaveBeenCalledTimes(1));
    expect(getCaseHostFactsMock).toHaveBeenLastCalledWith("case-1", { host_id: "host-1" });

    await userEvent.selectOptions(screen.getByTestId("host-selector"), "host-2");
    await waitFor(() => expect(getCaseHostFactsMock).toHaveBeenCalledTimes(2));
    expect(getCaseHostFactsMock).toHaveBeenLastCalledWith("case-1", { host_id: "host-2" });

    // Switching back to a previously-fetched host must not re-issue the request --
    // React Query's cache is the mechanism satisfying "no duplicate API requests".
    await userEvent.selectOptions(screen.getByTestId("host-selector"), "host-1");
    await waitFor(() => expect(screen.getByRole("heading", { name: "webserver-01" })).toBeInTheDocument());
    expect(getCaseHostFactsMock).toHaveBeenCalledTimes(2);
  });
});
