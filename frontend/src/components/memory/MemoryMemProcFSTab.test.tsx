import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { MemoryMemProcFSTable } from "../../api/client";
import { MemoryMemProcFSTab } from "./MemoryMemProcFSTab";

const getMemoryMemProcFSTableMock = vi.fn();

vi.mock("../../api/client", () => ({
  api: { getMemoryMemProcFSTable: (...args: unknown[]) => getMemoryMemProcFSTableMock(...args) },
}));

const TABLES = [
  { key: "tasks", label: "Scheduled tasks", group: "Persistence", description: "Every scheduled task.", count: 2 },
  { key: "netdns", label: "DNS cache", group: "Network", description: "Resolved names.", count: 1 },
  { key: "yara", label: "YARA matches", group: "Detection", description: "YARA.", count: 0 },
];

function result(overrides: Partial<MemoryMemProcFSTable> = {}): MemoryMemProcFSTable {
  return {
    table: "tasks",
    tables: TABLES,
    columns: [{ key: "TaskName", label: "Task" }, { key: "CommandLine", label: "Command" }],
    items: [{ TaskName: "Updater", CommandLine: "powershell.exe", User: "bob" }],
    total: 1,
    hidden: 0,
    page: 1,
    page_size: 50,
    run: { id: "run-fe" },
    available: true,
    ...overrides,
  };
}

function renderTab() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryMemProcFSTab caseId="case-1" evidenceId="ev-1" />
    </QueryClientProvider>,
  );
}

describe("MemoryMemProcFSTab", () => {
  beforeEach(() => {
    getMemoryMemProcFSTableMock.mockReset();
    getMemoryMemProcFSTableMock.mockResolvedValue(result());
  });

  it("lists the inventories by group and shows the scheduled tasks first", async () => {
    renderTab();
    await waitFor(() => expect(screen.getAllByTestId("memory-memprocfs-row")).toHaveLength(1));
    expect(screen.getByTestId("memory-memprocfs-table-tasks").getAttribute("aria-pressed")).toBe("true");
    expect(screen.getByTestId("memory-memprocfs-table").textContent).toContain("Updater");
    expect(getMemoryMemProcFSTableMock).toHaveBeenCalledWith("case-1", "ev-1", expect.objectContaining({ table: "tasks", page: 1 }));
  });

  it("switches table and says how many unreadable DNS entries were hidden", async () => {
    renderTab();
    getMemoryMemProcFSTableMock.mockResolvedValue(result({ table: "netdns", columns: [{ key: "Name", label: "Name" }], items: [{ Name: "wpad.nullsec.link" }], hidden: 2 }));
    fireEvent.click(await screen.findByTestId("memory-memprocfs-table-netdns"));
    await waitFor(() => expect(getMemoryMemProcFSTableMock).toHaveBeenLastCalledWith("case-1", "ev-1", expect.objectContaining({ table: "netdns" })));
    expect((await screen.findByTestId("memory-memprocfs-hidden")).textContent).toContain("2 unreadable entries");
  });

  it("asks to run Find Evil again when the run has no inventories", async () => {
    getMemoryMemProcFSTableMock.mockResolvedValue(result({ available: false, items: [], total: 0 }));
    renderTab();
    expect((await screen.findByTestId("memory-memprocfs-unavailable")).textContent).toContain("Run Find Evil again");
  });
});
