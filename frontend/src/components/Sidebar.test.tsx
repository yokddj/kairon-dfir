import type { ReactNode } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import Sidebar from "./Sidebar";

const activeCaseState: any = {
  activeCaseId: "case-1",
  activeCase: { id: "case-1", name: "Case Alpha" },
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
  });

  it("renders the Memory Analysis entry when a case is active", async () => {
    renderSidebar();
    const link = await screen.findByRole("link", { name: /Memory Analysis/i });
    expect(link).toHaveAttribute("href", "/cases/case-1/memory");
  });

  it("does not remove the Memory entry when no memory evidence exists", async () => {
    renderSidebar();
    expect(await screen.findByRole("link", { name: /Memory Analysis/i })).toBeInTheDocument();
  });

  it("falls back to the cases list when no active case is set", async () => {
    activeCaseState.activeCaseId = "";
    activeCaseState.activeCase = null;
    renderSidebar();
    // The Memory entry is hidden because it requires a case.
    expect(screen.queryByRole("link", { name: /Memory Analysis/i })).not.toBeInTheDocument();
  });
});
