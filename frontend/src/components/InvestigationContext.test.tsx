import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import InvestigationContext, { InvestigationBreadcrumbs } from "./InvestigationContext";

describe("InvestigationContext", () => {
  it("renders breadcrumbs and active scope", () => {
    render(
      <MemoryRouter>
        <InvestigationContext
          caseId="case-1"
          caseName="Case Alpha"
          host="HOST-01"
          evidenceId="evidence-123456789"
          evidenceName="collection.zip"
          current="Search"
        />
      </MemoryRouter>,
    );

    expect(screen.getByRole("navigation", { name: /investigation breadcrumbs/i })).toBeInTheDocument();
    expect(screen.getAllByText("Case Alpha")).toHaveLength(2);
    expect(screen.getByText("Filtered by HOST-01")).toBeInTheDocument();
    expect(screen.getByText("collection.zip")).toBeInTheDocument();
  });

  it("preserves host and evidence scope on pivot links", () => {
    render(
      <MemoryRouter>
        <InvestigationContext
          caseId="case-1"
          host="HOST-01"
          evidenceId="ev-1"
          current="Artifact Views"
          actions={[{ label: "Search", to: "/cases/case-1/search?artifact_type=evtx" }]}
        />
      </MemoryRouter>,
    );

    expect(screen.getByRole("link", { name: "Search" })).toHaveAttribute("href", "/cases/case-1/search?artifact_type=evtx&host=HOST-01&evidence_id=ev-1");
  });

  it("supports custom breadcrumb links", () => {
    render(
      <MemoryRouter>
        <InvestigationBreadcrumbs items={[{ label: "Cases", to: "/cases" }, { label: "Evidence" }]} />
      </MemoryRouter>,
    );

    const nav = screen.getByRole("navigation", { name: /investigation breadcrumbs/i });
    expect(within(nav).getByRole("link", { name: "Cases" })).toHaveAttribute("href", "/cases");
    expect(within(nav).getByText("Evidence")).toBeInTheDocument();
  });
});
