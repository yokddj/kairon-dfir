import type { ReactNode } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import Topbar from "./Topbar";

const listCasesMock = vi.fn();

const activeCaseState: any = {
  activeCase: { id: "case-1", name: "Case Alpha" },
  activeCaseId: "case-1",
  selectedHostId: "host-1",
  selectedHost: "TEST-WIN10-01",
  selectedEvidenceId: "ev-1",
  caseContext: {
    case: { id: "case-1", name: "Case Alpha" },
    hosts: [{ id: "host-1", canonical_name: "TEST-WIN10-01", display_name: "TEST-WIN10-01", confidence: "manual", source: "manual", event_count: 15000, evidence_count: 1, findings_count: 8, high_risk_count: 4, aliases: ["desktop-old01"], alias_rows: [{ id: "alias-1", alias: "TEST-WIN10-01", normalized_alias: "test-win10-01", is_primary: true, event_count: 15000 }], all_names: ["TEST-WIN10-01", "desktop-old01"], alias_count: 1 }],
    evidences: [{ id: "ev-1", name: "Collection.zip", status: "completed", storage_mode: "uploaded", is_external: false, events_indexed: 15000, parser_errors: 0, detected_host: "TEST-WIN10-01" }],
    summary: { events_indexed: 15000, findings_total: 8, findings_high: 4, parser_errors: 0, warnings: [] },
  },
  isCaseContextLoading: false,
  setActiveCase: vi.fn(),
  setActiveCaseId: vi.fn(),
  clearActiveCase: vi.fn(),
  setSelectedHostId: vi.fn(),
  setSelectedHost: vi.fn(),
  clearSelectedHost: vi.fn(),
  setSelectedEvidenceId: vi.fn(),
  clearSelectedEvidenceId: vi.fn(),
};

vi.mock("../api/client", () => ({
  API_BASE_URL: "http://127.0.0.1:8000/api",
  api: {
    listCases: (...args: unknown[]) => listCasesMock(...args),
  },
}));

vi.mock("../context/ActiveCaseContext", () => ({
  useActiveCase: () => activeCaseState,
}));

vi.mock("../context/TimezoneContext", () => ({
  useTimezonePreference: () => ({
    timezoneMode: "utc",
    setTimezoneMode: vi.fn(),
    effectiveTimezone: "UTC",
    userTimezone: "Europe/Madrid",
  }),
}));

function renderWithProviders(node: ReactNode) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={queryClient}>{node}</QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("Topbar", () => {
  beforeEach(() => {
    listCasesMock.mockResolvedValue([{ id: "case-1", name: "Case Alpha" }]);
    activeCaseState.activeCase = { id: "case-1", name: "Case Alpha" };
    activeCaseState.activeCaseId = "case-1";
    activeCaseState.selectedHostId = "host-1";
    activeCaseState.selectedHost = "TEST-WIN10-01";
    activeCaseState.selectedEvidenceId = "ev-1";
  });

  it("renders topbar with active case, host and evidence selectors", async () => {
    renderWithProviders(<Topbar />);
    expect(await screen.findByRole("combobox", { name: /active case/i })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: /host filter/i })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: /evidence filter/i })).toBeInTheDocument();
    expect(screen.getByText(/Case: Case Alpha/i)).toBeInTheDocument();
    expect(screen.getByText(/includes 1 aliases/i)).toBeInTheDocument();
  });
});
