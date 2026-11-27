import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";

const listEvidencesMock = vi.fn();
const summaryMock = vi.fn();
const searchMock = vi.fn();
vi.mock("../api/client", () => ({
  api: {
    listEvidences: (...args: unknown[]) => listEvidencesMock(...args),
    getFseventsSummary: (...args: unknown[]) => summaryMock(...args),
    searchFsevents: (...args: unknown[]) => searchMock(...args),
  },
}));

import FseventsPage from "./FseventsPage";

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/cases/case-1/mac/filesystem/fsevents"]}>
        <Routes>
          <Route path="/cases/:caseId/mac/filesystem/fsevents" element={<FseventsPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("FseventsPage", () => {
  it("searches the macOS evidence and lists the records", async () => {
    const user = userEvent.setup();
    listEvidencesMock.mockResolvedValue([{ id: "ev-mac", original_filename: "uac.tar.gz", effective_platform: "macos" }, { id: "ev-win", original_filename: "win.zip", effective_platform: "windows" }]);
    summaryMock.mockResolvedValue({ evidence_id: "ev-mac", available: true, volumes: [{ volume: "/System/Volumes/Data", page_files: 2 }] });
    searchMock.mockResolvedValue({
      evidence_id: "ev-mac", path_contains: "Downloads", changes: ["removed"], item_type: null, total_matches: 1, truncated: false,
      records_scanned_in_matching_pages: 10, elapsed_seconds: 0.5,
      records: [{ path: "Users/alice/Downloads/tool.dmg", event_id: 1002, flags: "0x800002", changes: ["removed"], item_type: "file", unknown_flags: [], node_id: 7, page_file: "0400", page_written: "2026-01-05T10:00:00+00:00", version: 3, volume: "/System/Volumes/Data" }],
    });
    renderPage();
    await user.type(await screen.findByTestId("fsevents-path-input"), "Downloads");
    await user.click(screen.getByLabelText("Removed"));
    await user.click(screen.getByTestId("fsevents-search-button"));
    const rows = await screen.findAllByTestId("fsevents-row");
    expect(rows).toHaveLength(1);
    expect(rows[0]).toHaveTextContent("Users/alice/Downloads/tool.dmg");
    expect(searchMock).toHaveBeenCalledWith("case-1", "ev-mac", expect.objectContaining({ path_contains: "Downloads", changes: ["removed"] }));
  });
});
