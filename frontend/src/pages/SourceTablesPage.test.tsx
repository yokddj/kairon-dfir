import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import SourceTablesPage from "./SourceTablesPage";

const listSourceTablesMock = vi.fn();
const getSourceTableMock = vi.fn();
const querySourceTableRowsMock = vi.fn();

vi.mock("../api/client", () => ({
  api: {
    listSourceTables: (...args: unknown[]) => listSourceTablesMock(...args),
    getSourceTable: (...args: unknown[]) => getSourceTableMock(...args),
    querySourceTableRows: (...args: unknown[]) => querySourceTableRowsMock(...args),
    deleteSourceTable: vi.fn(),
    sourceTableColumnValues: vi.fn(),
    exportSourceTable: vi.fn(),
  },
}));

vi.mock("../context/ActiveCaseContext", () => ({
  useActiveCase: () => ({ activeCaseId: "", activeCase: null }),
}));

const table = {
  id: "t1",
  case_id: "case-1",
  evidence_id: "ev-1",
  source_path: "EvtxECmd/out.csv",
  name: "out.csv",
  artifact_type: "evtx_csv",
  status: "ready",
  columns: [
    { index: 0, name: "TimeCreated", numeric: false },
    { index: 1, name: "EventId", numeric: true },
  ],
  row_count: 2,
  error: null,
  created_at: null,
  updated_at: null,
};

function renderAt(path: string) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/cases/:caseId/tables" element={<SourceTablesPage />} />
          <Route path="/cases/:caseId/tables/:tableId" element={<SourceTablesPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("SourceTablesPage", () => {
  beforeEach(() => {
    listSourceTablesMock.mockReset();
    getSourceTableMock.mockReset();
    querySourceTableRowsMock.mockReset();
    localStorage.clear();
    globalThis.ResizeObserver = class {
      observe() {}
      disconnect() {}
      unobserve() {}
    } as unknown as typeof ResizeObserver;
  });

  it("lists the case tables and links the ready ones", async () => {
    listSourceTablesMock.mockResolvedValue({ items: [table, { ...table, id: "t2", source_path: "*", name: "All CSV files", status: "pending", columns: [], row_count: 0 }] });
    renderAt("/cases/case-1/tables");
    expect(await screen.findByRole("link", { name: "out.csv" })).toHaveAttribute("href", "/cases/case-1/tables/t1");
    expect(screen.getByText("Every CSV of the evidence (waiting for the ingest)")).toBeInTheDocument();
  });

  it("shows every column and filters a column by its contents", async () => {
    getSourceTableMock.mockResolvedValue(table);
    querySourceTableRowsMock.mockResolvedValue({ total: 1, rows: [{ row: 1, values: ["2024-01-01 10:00:00", "4624"] }], next_cursor: null });
    renderAt("/cases/case-1/tables/t1");

    expect(await screen.findByText("4624")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "EventId" })).toBeInTheDocument();

    await userEvent.type(screen.getByLabelText("Filter EventId"), "46");
    await waitFor(() =>
      expect(querySourceTableRowsMock).toHaveBeenLastCalledWith(
        "case-1",
        "t1",
        expect.objectContaining({ filters: [{ column: 1, op: "contains", value: "46" }] }),
      ),
    );

    await userEvent.click(screen.getByRole("button", { name: "EventId" }));
    await waitFor(() =>
      expect(querySourceTableRowsMock).toHaveBeenLastCalledWith("case-1", "t1", expect.objectContaining({ sort_column: 1, sort_order: "asc" })),
    );
  });
});
