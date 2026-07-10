import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";

import ParserCoveragePage from "./ParserCoveragePage";

function renderPage() {
  return render(
    <MemoryRouter initialEntries={["/parser-coverage"]}>
      <ParserCoveragePage />
    </MemoryRouter>,
  );
}

describe("ParserCoveragePage", () => {
  it("renders the parser coverage matrix", () => {
    renderPage();

    expect(screen.getByTestId("parser-coverage-page")).toBeInTheDocument();
    expect(screen.getByText("Windows Event Logs / EVTX")).toBeInTheDocument();
    expect(screen.getByText("Memory analysis")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Open documentation/i })).toHaveAttribute("href", "/docs/parser-coverage");
  });

  it("filters by search text", async () => {
    renderPage();

    await userEvent.type(screen.getByPlaceholderText(/Search family/i), "PowerShell");

    expect(screen.getByText("PowerShell artifacts")).toBeInTheDocument();
    expect(screen.queryByText("Browser activity")).not.toBeInTheDocument();
  });

  it("filters by status and input format", async () => {
    renderPage();

    await userEvent.selectOptions(screen.getByDisplayValue("All statuses"), "unsupported");
    expect(screen.getByText("Linux/macOS triage placeholders")).toBeInTheDocument();
    expect(screen.queryByText("Windows Event Logs / EVTX")).not.toBeInTheDocument();

    await userEvent.selectOptions(screen.getByDisplayValue("All formats"), "EVTX");
    expect(screen.getByText(/No parser coverage entries match/i)).toBeInTheDocument();
  });

  it("shows columns required by the matrix", () => {
    renderPage();
    const header = screen.getByRole("row", { name: /Family Status Input formats Source tools Views Host-aware Timeline Limitations/i });

    expect(within(header).getByText("Family")).toBeInTheDocument();
    expect(within(header).getByText("Status")).toBeInTheDocument();
    expect(within(header).getByText("Input formats")).toBeInTheDocument();
    expect(within(header).getByText("Limitations")).toBeInTheDocument();
  });
});
