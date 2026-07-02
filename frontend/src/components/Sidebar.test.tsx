import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import Sidebar from "./Sidebar";

const activeCaseState: any = {
  activeCaseId: "case-1",
  activeCase: { id: "case-1", name: "Case Alpha" },
  caseContext: { summary: { validation_matrix: { show_validation_matrix: false } } },
  setActiveCaseId: vi.fn(),
};

vi.mock("../context/ActiveCaseContext", () => ({
  useActiveCase: () => activeCaseState,
}));

vi.mock("../api/client", () => ({
  api: {
    listMemoryEvidences: vi.fn().mockResolvedValue([]),
  },
}));

function renderSidebar() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={["/cases/case-1/overview"]}>
        <Sidebar />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("Memory navigation", () => {
  beforeEach(() => {
    activeCaseState.activeCaseId = "case-1";
    activeCaseState.activeCase = { id: "case-1", name: "Case Alpha" };
    activeCaseState.caseContext = { summary: { validation_matrix: { show_validation_matrix: false } } };
  });

  it("renders expanded Memory specialist entries when a case is active", async () => {
    renderSidebar();
    const memory = screen.getByText("Memory").closest("section")!;
    expect(await within(memory).findByRole("link", { name: /Memory Overview/i })).toHaveAttribute("href", "/cases/case-1/memory?tab=overview");
    for (const label of ["Processes", "Process Graph", "Network", "Modules & DLLs", "Handles", "Suspicious Memory", "VADs", "System", "Runs", "Raw Observations"]) {
      expect(within(memory).getByText(label)).toBeInTheDocument();
    }
  });

  it("keeps global Search, Command History and Incident Timeline in Investigation", () => {
    renderSidebar();
    const investigation = screen.getByText("Investigation").closest("section")!;
    expect(within(investigation).getByText("Search")).toBeInTheDocument();
    expect(within(investigation).getByText("Command History")).toBeInTheDocument();
    expect(within(investigation).getByText("Incident Timeline")).toBeInTheDocument();

    const memory = screen.getByText("Memory").closest("section")!;
    expect(within(memory).queryByText("Memory Search")).not.toBeInTheDocument();
    expect(within(memory).queryByText("Memory Timeline")).not.toBeInTheDocument();
  });

  it("does not remove the Memory section when no memory evidence exists", async () => {
    renderSidebar();
    expect(await screen.findByRole("link", { name: /Memory Overview/i })).toBeInTheDocument();
  });

  it("falls back to the cases list when no active case is set", () => {
    activeCaseState.activeCaseId = "";
    activeCaseState.activeCase = null;
    renderSidebar();
    expect(screen.queryByRole("link", { name: /Memory Overview/i })).not.toBeInTheDocument();
  });

  it("uses min-h-screen so the sidebar only scrolls when content exceeds the viewport", () => {
    const { container } = renderSidebar();
    const classTokens = (container.querySelector("aside")?.className || "").split(/\s+/);
    expect(classTokens).toContain("min-h-screen");
    expect(classTokens).not.toContain("h-screen");
  });
});
