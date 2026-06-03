import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import CaseHostsPage from "./CaseHostsPage";

const getCaseHostsMock = vi.fn();
const getCaseHostAuditMock = vi.fn();
const mergeCaseHostsMock = vi.fn();
const renameCaseHostMock = vi.fn();
const splitCaseHostAliasMock = vi.fn();

vi.mock("../api/client", () => ({
  api: {
    getCaseHosts: (...args: unknown[]) => getCaseHostsMock(...args),
    getCaseHostAudit: (...args: unknown[]) => getCaseHostAuditMock(...args),
    mergeCaseHosts: (...args: unknown[]) => mergeCaseHostsMock(...args),
    renameCaseHost: (...args: unknown[]) => renameCaseHostMock(...args),
    splitCaseHostAlias: (...args: unknown[]) => splitCaseHostAliasMock(...args),
  },
}));

vi.mock("../context/ActiveCaseContext", () => ({
  useActiveCase: () => ({
    setActiveCaseId: vi.fn(),
  }),
}));

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter initialEntries={["/cases/case-1/hosts"]}>
      <QueryClientProvider client={queryClient}>
        <Routes>
          <Route path="/cases/:caseId/hosts" element={<CaseHostsPage />} />
        </Routes>
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

const hostsPayload = {
  case_id: "case-1",
  host_candidates: [
    {
      candidate_type: "short_hostname_match",
      shared_short_names: ["hosta"],
    },
  ],
  hosts: [
    {
      id: "host-1",
      canonical_name: "hosta",
      display_name: "hosta",
      confidence: "manual",
      source: "manual",
      event_count: 123,
      evidence_count: 2,
      findings_count: 4,
      high_risk_count: 2,
      aliases: ["hosta.example.local"],
      alias_rows: [
        { id: "alias-1", alias: "hosta", normalized_alias: "hosta", is_primary: true, event_count: 80 },
        { id: "alias-2", alias: "hosta.example.local", normalized_alias: "hosta.example.local", is_primary: false, event_count: 43 },
      ],
      all_names: ["hosta", "hosta.example.local"],
      alias_count: 1,
    },
    {
      id: "host-2",
      canonical_name: "desktop-old01",
      display_name: "DESKTOP-OLD01",
      confidence: "high",
      source: "observed",
      event_count: 15,
      evidence_count: 1,
      findings_count: 0,
      high_risk_count: 0,
      aliases: [],
      alias_rows: [{ id: "alias-3", alias: "DESKTOP-OLD01", normalized_alias: "desktop-old01", is_primary: true, event_count: 15 }],
      all_names: ["DESKTOP-OLD01"],
      alias_count: 0,
    },
  ],
};

describe("CaseHostsPage", () => {
  beforeEach(() => {
    getCaseHostsMock.mockResolvedValue(hostsPayload);
    getCaseHostAuditMock.mockResolvedValue({ case_id: "case-1", items: [] });
    mergeCaseHostsMock.mockResolvedValue({ case_id: "case-1", host: hostsPayload.hosts[0] });
    renameCaseHostMock.mockResolvedValue({ case_id: "case-1", host: hostsPayload.hosts[0] });
    splitCaseHostAliasMock.mockResolvedValue({ case_id: "case-1", detached_host: hostsPayload.hosts[1], source_host_id: "host-1" });
  });

  it("lists detected hosts and unresolved candidates", async () => {
    renderPage();
    expect(await screen.findByText(/Manage host aliases/i)).toBeInTheDocument();
    expect(await screen.findByLabelText("Select DESKTOP-OLD01")).toBeInTheDocument();
    expect((await screen.findAllByText(/short_hostname_match/i)).length).toBeGreaterThan(0);
  });

  it("merges selected hosts into the chosen canonical host", async () => {
    renderPage();
    await screen.findByLabelText("Select DESKTOP-OLD01");
    await userEvent.click(await screen.findByLabelText("Select hosta"));
    await userEvent.click(await screen.findByLabelText("Select DESKTOP-OLD01"));
    await userEvent.click(screen.getByRole("button", { name: /Merge selected hosts/i }));
    await waitFor(() => expect(mergeCaseHostsMock).toHaveBeenCalled());
  });
});
