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
    getBodyfileSummary: (...args: unknown[]) => summaryMock(...args),
    searchBodyfile: (...args: unknown[]) => searchMock(...args),
  },
}));

import BodyfilePage from "./BodyfilePage";

describe("BodyfilePage", () => {
  it("searches the bodyfile of a Linux or macOS evidence", async () => {
    const user = userEvent.setup();
    listEvidencesMock.mockResolvedValue([{ id: "ev-lin", original_filename: "uac-linux.tar.gz", effective_platform: "linux" }]);
    summaryMock.mockResolvedValue({ evidence_id: "ev-lin", available: true, size_bytes: 10 });
    searchMock.mockResolvedValue({
      evidence_id: "ev-lin", available: true, total_matches: 1, truncated: false, elapsed_seconds: 1.2,
      records: [{ path: "/tmp/.x/payload", link_target: null, md5: null, inode: "9", mode: "-rwxr-xr-x", uid: "0", gid: "0", size: 2048, atime: null, mtime: "2026-01-02T00:00:00+00:00", ctime: null, crtime: null }],
    });
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <MemoryRouter initialEntries={["/cases/case-1/files/bodyfile"]}>
          <Routes>
            <Route path="/cases/:caseId/files/bodyfile" element={<BodyfilePage />} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    );
    await user.type(await screen.findByTestId("bodyfile-path-input"), "/tmp/");
    await user.click(screen.getByTestId("bodyfile-search-button"));
    const rows = await screen.findAllByTestId("bodyfile-row");
    expect(rows[0]).toHaveTextContent("/tmp/.x/payload");
    expect(rows[0]).toHaveTextContent("2.0 KB");
    expect(searchMock).toHaveBeenCalledWith("case-1", "ev-lin", expect.objectContaining({ path_contains: "/tmp/", sort: "mtime" }));
  });
});
