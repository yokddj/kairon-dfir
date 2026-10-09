import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import SourceTablesPage from "./SourceTablesPage";

const listSourceTablesMock = vi.fn();
const getSourceTableMock = vi.fn();
const querySourceTableRowsMock = vi.fn();
const listEvidencesMock = vi.fn();
const listArtifactsMock = vi.fn();
const requestSourceTablesMock = vi.fn();

vi.mock("../api/client", () => ({
  api: {
    listSourceTables: (...args: unknown[]) => listSourceTablesMock(...args),
    getSourceTable: (...args: unknown[]) => getSourceTableMock(...args),
    querySourceTableRows: (...args: unknown[]) => querySourceTableRowsMock(...args),
    deleteSourceTable: vi.fn(),
    listEvidences: (...args: unknown[]) => listEvidencesMock(...args),
    listArtifacts: (...args: unknown[]) => listArtifactsMock(...args),
    requestSourceTables: (...args: unknown[]) => requestSourceTablesMock(...args),
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
    listEvidencesMock.mockReset().mockResolvedValue([]);
    listArtifactsMock.mockReset().mockResolvedValue([]);
    requestSourceTablesMock.mockReset().mockResolvedValue({ items: [] });
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

  it("flags empty columns and hides them all at once", async () => {
    getSourceTableMock.mockResolvedValue({
      ...table,
      columns: [...table.columns, { index: 2, name: "PayloadData5", numeric: false, empty: true }, { index: 3, name: "PayloadData6", numeric: false, empty: true }],
    });
    querySourceTableRowsMock.mockResolvedValue({ total: 1, rows: [{ row: 1, values: ["2024-01-01 10:00:00", "4624", "", ""] }], next_cursor: null });
    renderAt("/cases/case-1/tables/t1");

    expect(await screen.findByRole("button", { name: "PayloadData5" })).toHaveAttribute("title", "PayloadData5 — no values in the whole file");
    await userEvent.click(screen.getByRole("button", { name: "hide 2 empty columns" }));
    expect(screen.queryByRole("button", { name: "PayloadData5" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "PayloadData6" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "EventId" })).toBeInTheDocument();
    expect(screen.getByText(/2\/4 columns/)).toBeInTheDocument();
  });
  it("lists the case's CSVs without a table, by evidence, with a Full table button", async () => {
    listSourceTablesMock.mockResolvedValue({ items: [table] });
    listEvidencesMock.mockResolvedValue([
      { id: "ev-1", original_filename: "kape.zip" },
      { id: "ev-2", original_filename: "memory.dmp" },
    ]);
    listArtifactsMock.mockResolvedValue([
      { evidence_id: "ev-1", name: "out.csv", source_path: "EvtxECmd/out.csv", artifact_type: "evtx_csv" },
      { evidence_id: "ev-1", name: "mft.csv", source_path: "MFTECmd/mft.csv", artifact_type: "mft" },
      { evidence_id: "ev-1", name: "Amcache.hve", source_path: "C/Windows/AppCompat/Programs/Amcache.hve", artifact_type: "amcache" },
    ]);
    renderAt("/cases/case-1/tables");

    const section = await screen.findByTestId("source-table-add");
    expect(section.textContent).toContain("kape.zip");
    expect(section.textContent).toContain("MFTECmd/mft.csv");
    expect(section.textContent).not.toContain("EvtxECmd/out.csv");
    expect(section.textContent).not.toContain("memory.dmp");
    await userEvent.click(screen.getByRole("button", { name: "Full table" }));
    await waitFor(() => expect(requestSourceTablesMock).toHaveBeenCalledWith("case-1", "ev-1", ["MFTECmd/mft.csv"]));
  });

  it("hides the section when every CSV already has a table", async () => {
    listSourceTablesMock.mockResolvedValue({ items: [table] });
    listEvidencesMock.mockResolvedValue([{ id: "ev-1", original_filename: "kape.zip" }]);
    listArtifactsMock.mockResolvedValue([{ evidence_id: "ev-1", name: "out.csv", source_path: "EvtxECmd/out.csv", artifact_type: "evtx_csv" }]);
    renderAt("/cases/case-1/tables");
    await screen.findByText("out.csv");
    await waitFor(() => expect(listArtifactsMock).toHaveBeenCalled());
    expect(screen.queryByText("MFTECmd/mft.csv")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Full table" })).not.toBeInTheDocument();
  });
});
