import { render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import DiskFilesPage from "./DiskFilesPage";
import { diskFileRouteForEvent } from "../lib/canonicalRoutes";

const getDiskFileVolumes = vi.fn();
const listDiskFiles = vi.fn();
const findDiskFiles = vi.fn();
const exportDiskFiles = vi.fn();

vi.mock("../api/client", () => ({
  api: {
    getDiskFileVolumes: (...args: unknown[]) => getDiskFileVolumes(...args),
    listDiskFiles: (...args: unknown[]) => listDiskFiles(...args),
    findDiskFiles: (...args: unknown[]) => findDiskFiles(...args),
    exportDiskFiles: (...args: unknown[]) => exportDiskFiles(...args),
  },
}));

function renderPage(path = "/cases/case-1/evidence/ev-1/files") {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/cases/:caseId/evidence/:evidenceId/files" element={<DiskFilesPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const volumes = {
  evidence_id: "ev-1",
  format: "raw",
  image_name: "victoria-v8.sda1.img",
  archive_password: "infected",
  volumes: [
    { id: "vol-swap", partition_index: 1, filesystem_type: null, length_bytes: 1024, browsable: false, unavailable_reason: "No filesystem Kairon can read was found on this volume.", installations: [] },
    { id: "vol-root", partition_index: 0, filesystem_type: "ext3", length_bytes: 954100224, browsable: true, unavailable_reason: null, installations: [{ platform: "linux", hostname: "victoria", distro: "Debian GNU/Linux 5.0", root_path: "/" }] },
  ],
};

function entry(name: string, extra: Record<string, unknown> = {}) {
  return { name, path: `/tmp/${name}`, inode: 100, parent_inode: 2, kind: "file", status: "allocated", size: 1063, uid: 0, gid: 0, mtime: 1570273993, atime: null, ctime: null, crtime: null, ...extra };
}

describe("DiskFilesPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getDiskFileVolumes.mockResolvedValue(volumes);
    listDiskFiles.mockResolvedValue({
      path: "/tmp",
      inode: null,
      total: 4,
      truncated: false,
      entries: [
        entry("c.pl", { inode: 11 }),
        entry("ccm0efZD.c", { inode: 12, status: "deleted", size: 0 }),
        entry("ucf.config.48161", { inode: 13, status: "deleted_inode_reused", size: null }),
        entry("37292.c", { inode: 14, status: "deleted_journal", size: null, mtime: null, journal_last_seen: 1570274625, journal_gone_by: 1570274632, journal_last_seq: 36258 }),
      ],
    });
    exportDiskFiles.mockResolvedValue({ blob: new Blob(["zip"]), filename: "kairon-ev-1-c.pl.zip", summary: "1/1" });
    URL.createObjectURL = vi.fn(() => "blob:x");
    URL.revokeObjectURL = vi.fn();
  });

  it("opens the volume with an installation, marks deleted entries and warns about the archive", async () => {
    renderPage("/cases/case-1/evidence/ev-1/files?path=/tmp");
    const rows = await screen.findAllByTestId("disk-file-row");
    expect(listDiskFiles).toHaveBeenCalledWith("case-1", "ev-1", "vol-root", { path: "/tmp", inode: null });
    expect(rows).toHaveLength(4);
    const byName = (name: string) => rows.find((row) => within(row).queryByText(name))!;
    expect(within(byName("ccm0efZD.c")).getByText("Deleted")).toBeInTheDocument();
    expect(within(byName("ucf.config.48161")).getByText("Deleted · inode reused")).toBeInTheDocument();
    // A name only the journal remembers, with when it was last listed and when it was gone.
    expect(within(byName("37292.c")).getByText("Deleted · from journal")).toBeInTheDocument();
    expect(within(byName("37292.c")).getByTestId("journal-times")).toHaveTextContent("seen 2019-10-05 11:23:45 · gone by 2019-10-05 11:23:52");
    expect(within(byName("37292.c")).getByRole("checkbox")).toBeEnabled();
    // A reused inode's content is another file's: it cannot be selected for export.
    expect(within(byName("ucf.config.48161")).getByRole("checkbox")).toBeDisabled();
    expect(screen.getByTestId("export-warning")).toHaveTextContent("infected");
    expect(screen.getByRole("option", { name: /No filesystem Kairon can read/ })).toBeDisabled();
  });

  it("hides deleted entries on demand and downloads the selection", async () => {
    renderPage("/cases/case-1/evidence/ev-1/files?path=/tmp");
    await screen.findAllByTestId("disk-file-row");
    await userEvent.click(screen.getByLabelText(/Show deleted entries/));
    await waitFor(() => expect(screen.getAllByTestId("disk-file-row")).toHaveLength(1));
    await userEvent.click(screen.getByLabelText("Select c.pl"));
    await userEvent.click(screen.getByRole("button", { name: "Download selected (1)" }));
    await waitFor(() => expect(exportDiskFiles).toHaveBeenCalledWith("case-1", "ev-1", "vol-root", [{ path: "/tmp/c.pl", inode: 11, parent_inode: 2 }], false));
    expect(await screen.findByTestId("export-notice")).toHaveTextContent("1 of 1 files exported");
  });

  it("searches the whole volume", async () => {
    findDiskFiles.mockResolvedValue({ results: [entry("rk.tar", { path: "/tmp/rk.tar" })], scanned: 34555, truncated: false });
    renderPage();
    await screen.findAllByTestId("disk-file-row");
    await userEvent.type(screen.getByLabelText("Find files"), "*.tar");
    await userEvent.click(screen.getByRole("button", { name: "Find" }));
    await waitFor(() => expect(findDiskFiles).toHaveBeenCalledWith("case-1", "ev-1", "vol-root", { q: "*.tar", include_deleted: true }));
    expect(await screen.findByText("/tmp/rk.tar")).toBeInTheDocument();
    expect(screen.getByText(/34[.,]555 entries scanned/)).toBeInTheDocument();
  });
});

describe("diskFileRouteForEvent", () => {
  it("links an event parsed from a disk image to its file", () => {
    const href = diskFileRouteForEvent({
      case_id: "case-1",
      evidence_id: "ev-1",
      artifact: { source_path: "volume-0/linux/var/log/auth.log", original_source_path: "/var/log/auth.log" },
    });
    expect(href).toBe("/cases/case-1/evidence/ev-1/files?partition=0&path=%2Fvar%2Flog&file=auth.log");
  });

  it("gives nothing for an event that did not come from a disk image", () => {
    expect(diskFileRouteForEvent({ case_id: "case-1", evidence_id: "ev-1", source_file: "Security.evtx", artifact: { original_source_path: "Security.evtx" } })).toBe("");
  });
});
