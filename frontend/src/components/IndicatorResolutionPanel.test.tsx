import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";

import IndicatorResolutionPanel from "./IndicatorResolutionPanel";

describe("IndicatorResolutionPanel", () => {
  it("renders resolution badges, explanation and pivots", () => {
    render(
      <MemoryRouter>
        <IndicatorResolutionPanel
          data={{
            case_id: "case-1",
            indicators: [{ indicator: ".\\f\\script.ps1", type: "path", normalized: ".\\f\\script.ps1" }],
            results: [
              {
                indicator: ".\\f\\script.ps1",
                type: "path",
                status: "command_only",
                sources_found: ["command_history"],
                counts_by_source: { mft: 0, command_history: 2 },
                hosts: ["HOSTA"],
                evidence_ids: ["ev-1"],
                confidence: "medium",
                explanation: "Referenced by command, but no exact filesystem artifact was confirmed.",
                suggested_pivots: [{ label: "Search command references", url: "/cases/case-1/search?q=script.ps1", type: "command" }],
              },
            ],
          }}
        />
      </MemoryRouter>,
    );

    expect(screen.getByText("Evidence resolution")).toBeInTheDocument();
    expect(screen.getByText(".\\f\\script.ps1")).toBeInTheDocument();
    expect(screen.getByText("command_only")).toBeInTheDocument();
    expect(screen.getByText(/command_history: 2/i)).toBeInTheDocument();
    expect(screen.getByText(/no exact filesystem artifact/i)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Search command references/i })).toHaveAttribute("href", "/cases/case-1/search?q=script.ps1");
  });
});
