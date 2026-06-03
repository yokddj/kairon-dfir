import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

let Siem: (typeof import("./Siem"))["default"];

const apiMocks = vi.hoisted(() => ({
  listCases: vi.fn(),
  siemExternalStatus: vi.fn(),
  siemExternalDiagnostics: vi.fn(),
  getAdminOpenSearchDashboardsStatus: vi.fn(),
  siemFields: vi.fn(),
  siemExternalLinks: vi.fn(),
  listSiemQueryHistory: vi.fn(),
  listSiemSavedSearches: vi.fn(),
  bootstrapAdminOpenSearchDashboards: vi.fn(),
}));

vi.mock("../api/client", () => ({
  api: apiMocks,
}));

vi.mock("../context/ActiveCaseContext", () => ({
  useActiveCase: () => ({ activeCaseId: "case-1" }),
}));

vi.mock("../context/TimezoneContext", () => ({
  useTimezonePreference: () => ({ effectiveTimezone: "UTC" }),
}));

const readyStatus = {
  opensearch: { available: true, events_index_pattern: "dfir-events-*", events_count: 321, indices: ["dfir-events-case-1"] },
  dashboards: {
    available: true,
    url: "http://dashboards.test",
    data_view_exists: true,
    data_view_id: "dfir-events",
    data_view_title: "dfir-events-*",
    time_field: "@timestamp",
    warnings: [],
    recommended_columns: ["@timestamp", "case_id"],
  },
};

beforeAll(async () => {
  Siem = (await import("./Siem")).default;
});

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <Siem />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("Siem", () => {
  beforeEach(() => {
    apiMocks.listCases.mockReset();
    apiMocks.siemExternalStatus.mockReset();
    apiMocks.siemExternalDiagnostics.mockReset();
    apiMocks.getAdminOpenSearchDashboardsStatus.mockReset();
    apiMocks.siemFields.mockReset();
    apiMocks.siemExternalLinks.mockReset();
    apiMocks.listSiemQueryHistory.mockReset();
    apiMocks.listSiemSavedSearches.mockReset();
    apiMocks.bootstrapAdminOpenSearchDashboards.mockReset();

    apiMocks.listCases.mockResolvedValue([{ id: "case-1", name: "Case Alpha" }]);
    apiMocks.siemExternalStatus.mockResolvedValue({ public_url: "http://dashboards.test", available: true, index_pattern: "dfir-events-*", time_field: "@timestamp" });
    apiMocks.siemExternalDiagnostics.mockResolvedValue({ opensearch: { available: true, indices: ["dfir-events-case-1"], docs_count: 321 }, dashboards: { data_view: { exists: true } }, case: { events_count: 321 } });
    apiMocks.getAdminOpenSearchDashboardsStatus.mockResolvedValue(readyStatus);
    apiMocks.siemFields.mockResolvedValue({ indexed_fields: [], normalized_fields: [], raw_fields_sample: [], unmapped_raw_fields: [], missing_common_fields: [] });
    apiMocks.siemExternalLinks.mockResolvedValue({ discover_url: "http://dashboards.test/app/discover", case_filter: 'case_id:"case-1"' });
    apiMocks.listSiemQueryHistory.mockResolvedValue([]);
    apiMocks.listSiemSavedSearches.mockResolvedValue([]);
    apiMocks.bootstrapAdminOpenSearchDashboards.mockResolvedValue({
      created: true,
      updated: false,
      message: "DFIR Events data view is ready",
      status: readyStatus,
    });
  });

  it("shows setup card", async () => {
    renderPage();
    expect(await screen.findByText(/OpenSearch Dashboards setup/i)).toBeInTheDocument();
  });

  it("shows ready status when data view exists", async () => {
    renderPage();
    await waitFor(() => expect(screen.getByText(/Data View status: ready/i)).toBeInTheDocument());
  });

  it("shows create button when data view is missing", async () => {
    apiMocks.getAdminOpenSearchDashboardsStatus.mockResolvedValue({
      ...readyStatus,
      dashboards: { ...readyStatus.dashboards, data_view_exists: false, data_view_id: null },
    });
    renderPage();
    expect(await screen.findByRole("button", { name: /Create Data View/i })).toBeInTheDocument();
  });

  it("clicking bootstrap calls endpoint and refreshes status", async () => {
    renderPage();
    await waitFor(() => expect(screen.getByText(/Data View status: ready/i)).toBeInTheDocument());
    await userEvent.click(screen.getByRole("button", { name: /Create \/ Repair Data View|Create Data View/i }));
    await waitFor(() => expect(apiMocks.bootstrapAdminOpenSearchDashboards).toHaveBeenCalled());
    expect(await screen.findByText(/DFIR Events data view is ready/i)).toBeInTheDocument();
  });

  it("shows clear warning when dashboards are unavailable", async () => {
    apiMocks.getAdminOpenSearchDashboardsStatus.mockResolvedValue({
      ...readyStatus,
      dashboards: { ...readyStatus.dashboards, available: false, warnings: ["dashboards_unreachable"] },
    });
    renderPage();
    await waitFor(() => expect(screen.getByText(/Dashboards OK: no/i)).toBeInTheDocument());
    expect(screen.getByText(/OpenSearch Dashboards is not available right now/i)).toBeInTheDocument();
  });

  it("renders open discover link", async () => {
    renderPage();
    await waitFor(() => expect(screen.getByRole("link", { name: /Open Discover/i })).toHaveAttribute("href", "http://dashboards.test/app/discover"));
  });
});
