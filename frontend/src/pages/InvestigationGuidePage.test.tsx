import { fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import guide from "../../../docs/data/investigation-guide.json";
import { getArtifactDefinition } from "../lib/artifactRegistry";
import InvestigationGuidePage, { guideSearchHref, guideViewHref } from "./InvestigationGuidePage";

const activeCaseState: { activeCase: { id: string; name: string } | null } = { activeCase: null };
vi.mock("../context/ActiveCaseContext", () => ({ useActiveCase: () => activeCaseState }));

function renderPage() {
  return render(
    <MemoryRouter>
      <InvestigationGuidePage />
    </MemoryRouter>,
  );
}

describe("InvestigationGuidePage", () => {
  beforeEach(() => {
    activeCaseState.activeCase = { id: "case-1", name: "Case One" };
  });

  it("shows every topic as a card with its question", () => {
    renderPage();
    for (const topic of guide.topics) expect(screen.getAllByRole("heading", { name: topic.question }).length).toBeGreaterThan(0);
  });

  it("runs a search on the active case", () => {
    renderPage();
    const run = screen.getByRole("link", { name: "Run: Remote Desktop logons (type 10)" });
    expect(run).toHaveAttribute("href", guideSearchHref("case-1", "eventid:4624 AND logontype:10"));
  });

  it("opens the right Artifact View", () => {
    renderPage();
    const card = screen.getByRole("heading", { name: "What ran on the host?" }).closest("article") as HTMLElement;
    expect(within(card).getByRole("link", { name: "Prefetch" })).toHaveAttribute("href", "/cases/case-1/artifact-search?artifact_type=prefetch");
  });

  it("filters by platform, category and text", () => {
    renderPage();
    fireEvent.click(screen.getByRole("button", { name: "Linux" }));
    expect(screen.queryByRole("heading", { name: "What ran on the host?" })).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "What was run as root?" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "All" }));
    fireEvent.change(screen.getByLabelText("Filter the guide"), { target: { value: "4625" } });
    expect(screen.getByRole("heading", { name: "Who logged on, and from where?" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "What was installed?" })).not.toBeInTheDocument();
  });

  it("asks for a case before anything can run", () => {
    activeCaseState.activeCase = null;
    renderPage();
    expect(screen.getByText("Select a case to run the searches and open the views")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /^Run:/ })).not.toBeInTheDocument();
  });

  it("links only to artifact views that exist", () => {
    for (const topic of guide.topics) {
      for (const view of topic.views) {
        if (view.target === "artifacts") expect(getArtifactDefinition(view.artifact_type), `${topic.id}: ${view.artifact_type}`).toBeTruthy();
        else expect(guideViewHref("c", view)).toMatch(/^\/cases\/c\/[a-z-]+$/);
      }
    }
  });
});
