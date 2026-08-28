import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

let Siem: (typeof import("./Siem"))["default"];

const apiMocks = vi.hoisted(() => ({
  listCases: vi.fn(),
  siemFields: vi.fn(),
  siemExternalLinks: vi.fn(),
  listSiemQueryHistory: vi.fn(),
  listSiemSavedSearches: vi.fn(),
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
    apiMocks.siemFields.mockReset();
    apiMocks.siemExternalLinks.mockReset();
    apiMocks.listSiemQueryHistory.mockReset();
    apiMocks.listSiemSavedSearches.mockReset();

    apiMocks.listCases.mockResolvedValue([{ id: "case-1", name: "Case Alpha" }]);
    apiMocks.siemFields.mockResolvedValue({ indexed_fields: [], normalized_fields: [], raw_fields_sample: [], unmapped_raw_fields: [], missing_common_fields: [] });
    apiMocks.siemExternalLinks.mockResolvedValue({ discover_url: "http://dashboards.test/app/discover", case_filter: 'case_id:"case-1"' });
    apiMocks.listSiemQueryHistory.mockResolvedValue([]);
    apiMocks.listSiemSavedSearches.mockResolvedValue([]);
  });

  it("opens on the query builder, with no OpenSearch Dashboards tab", async () => {
    renderPage();
    expect(await screen.findByRole("button", { name: /Query Builder/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Field Explorer/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Saved console queries/i })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /OpenSearch Dashboards/i })).not.toBeInTheDocument();
  });

  it("offers no link into the OpenSearch console", async () => {
    renderPage();
    await screen.findByRole("button", { name: /Query Builder/i });
    expect(screen.queryByRole("link", { name: /Open Discover/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /Open OpenSearch Dashboards/i })).not.toBeInTheDocument();
  });

  it("switches to the field explorer", async () => {
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: /Field Explorer/i }));
    await waitFor(() => expect(apiMocks.siemFields).toHaveBeenCalled());
  });
});
