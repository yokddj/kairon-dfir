import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { EntityPageLayout } from "./EntityPageLayout";

describe("EntityPageLayout", () => {
  it("renders sections in the given order, each with an accessible heading", () => {
    render(
      <EntityPageLayout
        header={<h1>powershell.exe</h1>}
        sections={[
          { id: "overview", title: "Overview", content: <p>overview body</p> },
          { id: "relationships", title: "Relationships", content: <p>relationships body</p> },
        ]}
      />,
    );
    const sections = screen.getAllByRole("region");
    expect(sections).toHaveLength(2);
    expect(within(sections[0]).getByRole("heading", { name: "Overview" })).toBeInTheDocument();
    expect(within(sections[0]).getByText("overview body")).toBeInTheDocument();
    expect(within(sections[1]).getByRole("heading", { name: "Relationships" })).toBeInTheDocument();
  });

  it("omits falsy sections entirely instead of rendering an empty panel", () => {
    render(
      <EntityPageLayout
        header={<h1>powershell.exe</h1>}
        sections={[
          { id: "overview", title: "Overview", content: <p>overview body</p> },
          false,
          null,
          undefined,
        ]}
      />,
    );
    expect(screen.getAllByRole("region")).toHaveLength(1);
    expect(screen.queryByText("Findings")).toBeNull();
  });

  it("renders the header and breadcrumbs slots", () => {
    render(
      <EntityPageLayout
        breadcrumbs={<nav data-testid="crumbs">Case / Memory</nav>}
        header={<h1 data-testid="header-title">powershell.exe</h1>}
        sections={[]}
      />,
    );
    expect(screen.getByTestId("crumbs")).toBeInTheDocument();
    expect(screen.getByTestId("header-title")).toBeInTheDocument();
  });

  it("renders the investigation context slot only when provided", () => {
    const { rerender } = render(<EntityPageLayout header={<h1>x</h1>} sections={[]} />);
    expect(screen.queryByTestId("entity-page-investigation-context")).toBeNull();

    rerender(
      <EntityPageLayout header={<h1>x</h1>} sections={[]} investigationContext={<p>context body</p>} />,
    );
    expect(screen.getByTestId("entity-page-investigation-context")).toBeInTheDocument();
  });
});
