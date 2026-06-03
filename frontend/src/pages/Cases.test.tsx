import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";

import Cases from "./Cases";

const listCasesMock = vi.fn().mockResolvedValue([]);
const createCaseMock = vi.fn();
const deleteCaseMock = vi.fn();

vi.mock("../api/client", () => ({
  api: {
    listCases: (...args: unknown[]) => listCasesMock(...args),
    createCase: (...args: unknown[]) => createCaseMock(...args),
    deleteCase: (...args: unknown[]) => deleteCaseMock(...args),
  },
}));

vi.mock("../context/ActiveCaseContext", () => ({
  useActiveCase: () => ({
    activeCaseId: "",
    clearActiveCase: vi.fn(),
  }),
}));

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={queryClient}>
        <Cases />
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("Cases page", () => {
  it("uses generic placeholders for case creation", async () => {
    renderPage();
    expect(screen.getByPlaceholderText("ACME Incident 001")).toBeInTheDocument();
    expect(screen.getByPlaceholderText("Short description of the investigation scope")).toBeInTheDocument();
  });
});
