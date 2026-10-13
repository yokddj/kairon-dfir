import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "../../api/client";
import { MemoryFilesTab } from "./MemoryFilesTab";

function renderTab() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryFilesTab caseId="case-1" evidenceId="ev-1" />
    </QueryClientProvider>,
  );
}

function mockPlatform(platform: string, items: unknown[]) {
  vi.spyOn(api, "getMemoryEvidencePreparation").mockResolvedValue({ platform } as never);
  vi.spyOn(api, "getMemoryActiveResult").mockResolvedValue({ items, total: items.length, analysis_state: "analyzed_with_results" } as never);
  vi.spyOn(api, "listMemoryFileExtractions").mockResolvedValue({ items: [] } as never);
}

describe("MemoryFilesTab", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("on Linux describes the page cache and shows type, size and cached pages", async () => {
    mockPlatform("linux", [
      { document_id: "d1", name: "/tmp/.x/payload", offset: "0x9ee0c1fc6f68", file_type: "REG", file_size: 2048, cached_pages: 1, modified_at: "2024-07-03T19:28:17+00:00" },
    ]);
    renderTab();
    expect(await screen.findByText("/tmp/.x/payload")).toBeInTheDocument();
    expect(screen.getByText(/linux\.pagecache\.Files/)).toBeInTheDocument();
    expect(screen.getByText("Cached pages")).toBeInTheDocument();
    expect(screen.getByText("2.0 KB")).toBeInTheDocument();
    expect(screen.getByTestId("memory-file-path-input")).toHaveAttribute("placeholder", "/tmp/.x/payload");
    expect(screen.queryByText(/windows\.filescan/)).not.toBeInTheDocument();
  });

  it("on Windows keeps the filescan wording and columns", async () => {
    mockPlatform("windows", [{ document_id: "d1", name: "\\Windows\\Temp\\a.ps1", offset: "0xabc" }]);
    renderTab();
    expect(await screen.findByText("\\Windows\\Temp\\a.ps1")).toBeInTheDocument();
    expect(screen.getAllByText(/windows\.filescan/).length).toBeGreaterThan(0);
    expect(screen.queryByText("Cached pages")).not.toBeInTheDocument();
  });
});
