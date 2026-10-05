import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";

import DocsPage from "./DocsPage";

const listDocsMock = vi.fn();
const getDocMock = vi.fn();

const activeCaseState: { activeCase: { id: string; name: string } | null } = { activeCase: null };
vi.mock("../context/ActiveCaseContext", () => ({ useActiveCase: () => activeCaseState }));

vi.mock("../api/client", () => ({
  api: {
    listDocs: (...args: unknown[]) => listDocsMock(...args),
    getDoc: (...args: unknown[]) => getDocMock(...args),
  },
}));

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter initialEntries={["/docs"]}>
      <QueryClientProvider client={queryClient}>
        <DocsPage />
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("DocsPage", () => {
  it("renders updated docs catalog and navigates through new internal links", async () => {
    listDocsMock.mockResolvedValue([
      { slug: "index", title: "Documentation Kairon DFIR", summary: "Main docs index" },
      { slug: "user-guide", title: "User Guide", summary: "Analyst workflow" },
      { slug: "rules-sigma-yara", title: "Rules Sigma YARA", summary: "Rules engine docs" },
      { slug: "demo-mvp", title: "Demo MVP", summary: "Demo guide" },
    ]);
    getDocMock.mockImplementation(async (slug: string) => {
      if (slug === "index") {
        return {
          slug,
          title: "Documentation Kairon DFIR",
          summary: "Main docs index",
          content: "# Docs\n\n[User guide](user_guide.md)\n\n[Rules](rules_sigma_yara.md)\n\n[Demo](demo_mvp.md)",
        };
      }
      if (slug === "user-guide") {
        return { slug, title: "User Guide", summary: "Analyst workflow", content: "# User Guide\n\nCurrent workflow" };
      }
      if (slug === "demo-mvp") {
        return { slug, title: "Demo MVP", summary: "Demo guide", content: "# Demo\n\nSynthetic walkthrough" };
      }
      return { slug, title: "Rules Sigma YARA", summary: "Rules engine docs", content: "# Rules\n\nSigma and YARA" };
    });

    renderPage();

    expect(await screen.findAllByText("Documentation Kairon DFIR")).toHaveLength(2);
    expect(screen.getByText("User Guide")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /Rules Sigma YARA/i }));
    await waitFor(() => expect(screen.getAllByText("Rules Sigma YARA")).toHaveLength(2));

    fireEvent.click(screen.getByRole("button", { name: /Demo MVP/i }));
    await waitFor(() => expect(screen.getAllByText("Demo MVP")).toHaveLength(2));
  });

  it("turns guide searches into a button that runs them on the active case", async () => {
    listDocsMock.mockResolvedValue([{ slug: "investigation-guide", title: "Guía de investigación", summary: "" }]);
    getDocMock.mockResolvedValue({ slug: "investigation-guide", title: "Guía de investigación", content: "# Guide\n\n```kairon\neventid:4624 AND logontype:10\n```\n" });
    activeCaseState.activeCase = { id: "case-1", name: "Case" };
    renderPage();
    const link = await screen.findByRole("link", { name: "Search" });
    expect(link).toHaveAttribute("href", `/cases/case-1/search?q=${encodeURIComponent("eventid:4624 AND logontype:10")}`);
    expect(screen.getByText("eventid:4624 AND logontype:10")).toBeInTheDocument();
  });

  it("asks for a case before a guide search can run", async () => {
    listDocsMock.mockResolvedValue([{ slug: "investigation-guide", title: "Guía de investigación", summary: "" }]);
    getDocMock.mockResolvedValue({ slug: "investigation-guide", title: "Guía de investigación", content: "```kairon\neventid:4625\n```\n" });
    activeCaseState.activeCase = null;
    renderPage();
    expect(await screen.findByText("Select a case to run it")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Search" })).not.toBeInTheDocument();
  });
});
