import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { MemProcFSScanStatus } from "../../api/client";
import { MEMPROCFS_RESCAN_EVENT, MemoryMemProcFSScanPanel } from "./MemoryMemProcFSScanPanel";

const getScan = vi.fn();
const rescan = vi.fn();
const download = vi.fn();
const listTables = vi.fn();
const requestTables = vi.fn();

vi.mock("../../api/client", () => ({
  api: {
    getMemProcFSScan: (...args: unknown[]) => getScan(...args),
    rescanMemProcFS: (...args: unknown[]) => rescan(...args),
    downloadMemProcFSScan: (...args: unknown[]) => download(...args),
    listSourceTables: (...args: unknown[]) => listTables(...args),
    requestSourceTables: (...args: unknown[]) => requestTables(...args),
  },
}));

const scan: MemProcFSScanStatus = {
  evidence_id: "ev-1",
  exists: true,
  scanned_at: "2026-11-12T10:00:00Z",
  memprocfs_version: "5.19.3",
  yara_rules: false,
  findevil: true,
  notices: [],
  files: [
    { path: "forensic/timeline_ntfs.csv", size: 2048, tabular: true, source_path: "memprocfs/forensic/timeline_ntfs.csv" },
    { path: "forensic/evtx/System.evtx", size: 4096, tabular: false, source_path: "memprocfs/forensic/evtx/System.evtx" },
  ],
  total_bytes: 6144,
};

function renderPanel() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <MemoryMemProcFSScanPanel caseId="case-1" evidenceId="ev-1" />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("MemoryMemProcFSScanPanel", () => {
  beforeEach(() => {
    for (const mock of [getScan, rescan, download, listTables, requestTables]) mock.mockReset();
    getScan.mockResolvedValue(scan);
    listTables.mockResolvedValue({ items: [] });
    requestTables.mockResolvedValue({ items: [], queued: true });
    rescan.mockResolvedValue({ accepted: true });
    download.mockResolvedValue({ blob: new Blob(["x"]), filename: "f" });
    globalThis.URL.createObjectURL = vi.fn(() => "blob:x");
    globalThis.URL.revokeObjectURL = vi.fn();
  });

  it("says how the saved scan was made and shows nothing without one", async () => {
    renderPanel();
    expect(await screen.findByText(/Saved MemProcFS scan of 2026-11-12 10:00:00 UTC/)).toHaveTextContent("YARA rules not included");
    expect(screen.queryByTestId("memory-memprocfs-scan-notice")).not.toBeInTheDocument();
  });

  it("renders nothing when there is no scan", async () => {
    getScan.mockResolvedValue({ ...scan, exists: false, files: [] });
    const { container } = renderPanel();
    await waitFor(() => expect(getScan).toHaveBeenCalled());
    expect(container.querySelector("[data-testid='memory-memprocfs-scan']")).toBeNull();
  });

  it("warns when the YARA rules were enabled after the scan and opens the catalogue to rescan", async () => {
    getScan.mockResolvedValue({ ...scan, notices: ["yara_rules_missing"] });
    const heard: unknown[] = [];
    const listener = (event: Event) => heard.push((event as CustomEvent).detail);
    window.addEventListener(MEMPROCFS_RESCAN_EVENT, listener);
    renderPanel();
    expect(await screen.findByTestId("memory-memprocfs-scan-notice")).toHaveTextContent("made without MemProcFS's YARA rules");
    expect(screen.queryByTestId("memory-memprocfs-rescan")).not.toBeInTheDocument();
    fireEvent.click(screen.getByTestId("memory-memprocfs-rescan-link"));
    window.removeEventListener(MEMPROCFS_RESCAN_EVENT, listener);
    expect(heard).toEqual([{ evidenceId: "ev-1" }]);
    expect(rescan).not.toHaveBeenCalled();
  });

  it("lists the files, downloads them and opens a CSV as a full table", async () => {
    renderPanel();
    fireEvent.click(await screen.findByTestId("memory-memprocfs-scan-files-toggle"));
    const list = await screen.findByTestId("memory-memprocfs-scan-files");
    expect(list).toHaveTextContent("forensic/timeline_ntfs.csv");
    fireEvent.click(screen.getByRole("button", { name: "Full table" }));
    await waitFor(() => expect(requestTables).toHaveBeenCalledWith("case-1", "ev-1", ["memprocfs/forensic/timeline_ntfs.csv"]));
    fireEvent.click(screen.getAllByRole("button", { name: "Download" })[1]);
    await waitFor(() => expect(download).toHaveBeenCalledWith("case-1", "ev-1", "forensic/evtx/System.evtx"));
    fireEvent.click(screen.getByTestId("memory-memprocfs-scan-download-all"));
    await waitFor(() => expect(download).toHaveBeenCalledWith("case-1", "ev-1", null));
  });
});
