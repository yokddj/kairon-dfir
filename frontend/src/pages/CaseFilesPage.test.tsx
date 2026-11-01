import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import CaseFilesPage from "./CaseFilesPage";

const listEvidencesMock = vi.fn();

vi.mock("../context/ActiveCaseContext", () => ({
  useActiveCase: () => ({ setActiveCaseId: vi.fn(), caseContext: { hosts: [{ id: "h-1", display_name: "ws01", canonical_name: "ws01" }, { id: "h-2", display_name: "srv01", canonical_name: "srv01" }] } }),
}));

vi.mock("../api/client", () => ({
  api: { listEvidences: (...args: unknown[]) => listEvidencesMock(...args) },
}));

function renderPage(entry = "/cases/case-1/files") {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[entry]}>
        <Routes>
          <Route path="/cases/:caseId/files" element={<CaseFilesPage />} />
          <Route path="/cases/:caseId/evidence/:evidenceId/files" element={<p>explorer</p>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const evidences = [
  { id: "ev-1", evidence_type: "disk_image", original_filename: "ws01.E01", host_id: "h-1", disk_image: { format: "e01" } },
  { id: "ev-2", evidence_type: "velociraptor_zip", original_filename: "srv01.ad1", host_id: "h-2", disk_image: null },
  { id: "ev-3", evidence_type: "evtx", original_filename: "Security.evtx", host_id: "h-1", disk_image: null },
];

describe("CaseFilesPage", () => {
  beforeEach(() => listEvidencesMock.mockReset());

  it("lists browsable evidence by host", async () => {
    listEvidencesMock.mockResolvedValue(evidences);
    renderPage();
    expect(await screen.findByRole("link", { name: /ws01\.E01/ })).toHaveAttribute("href", "/cases/case-1/evidence/ev-1/files");
    expect(screen.getByRole("link", { name: /srv01\.ad1/ })).toHaveTextContent("AD1 logical image");
    expect(screen.getByText("ws01")).toBeInTheDocument();
    expect(screen.queryByText("Security.evtx")).not.toBeInTheDocument();
  });

  it("opens the explorer when the host has a single browsable evidence", async () => {
    listEvidencesMock.mockResolvedValue(evidences);
    renderPage("/cases/case-1/files?host_id=h-2");
    expect(await screen.findByText("explorer")).toBeInTheDocument();
  });

  it("says when nothing can be browsed", async () => {
    listEvidencesMock.mockResolvedValue([evidences[2]]);
    renderPage();
    expect(await screen.findByText("No browsable evidence")).toBeInTheDocument();
  });
});
