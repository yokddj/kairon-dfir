import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, useLocation } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { useHostContext } from "./useHostContext";

const setSelectedHost = vi.fn();
const setSelectedHostId = vi.fn();
const clearSelectedHost = vi.fn();

let activeCaseState: Record<string, unknown>;

vi.mock("../context/ActiveCaseContext", () => ({
  useActiveCase: () => activeCaseState,
}));

function Harness() {
  const location = useLocation();
  const { activeHost, activeHostId, setHostFilter, clearHostFilter, withHostScope } = useHostContext();
  return (
    <div>
      <div data-testid="host-id">{activeHostId}</div>
      <div data-testid="host-name">{activeHost}</div>
      <div data-testid="location">{location.pathname + location.search}</div>
      <div data-testid="scoped-link">{withHostScope("/cases/case-1/search?query=powershell")}</div>
      <button type="button" onClick={() => setHostFilter("host-ws02")}>Set WS02</button>
      <button type="button" onClick={clearHostFilter}>Clear</button>
    </div>
  );
}

function renderHarness(initialEntry: string) {
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <Harness />
    </MemoryRouter>,
  );
}

describe("useHostContext", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    activeCaseState = {
      selectedHost: "",
      selectedHostId: "",
      caseContext: {
        hosts: [
          { id: "host-ws01", canonical_name: "ws-01", display_name: "WS-01", aliases: ["WS-01.local"], all_names: ["WS-01", "WS-01.local"] },
          { id: "host-ws02", canonical_name: "ws-02", display_name: "WS-02", aliases: [], all_names: ["WS-02"] },
        ],
      },
      setSelectedHost,
      setSelectedHostId,
      clearSelectedHost,
    };
  });

  it("resolves URL host_id into active host context and scoped links", () => {
    renderHarness("/cases/case-1/search?host_id=host-ws01&host=stale-name");

    expect(screen.getByTestId("host-id")).toHaveTextContent("host-ws01");
    expect(screen.getByTestId("host-name")).toHaveTextContent("WS-01");
    expect(screen.getByTestId("scoped-link")).toHaveTextContent("/cases/case-1/search?query=powershell&host_id=host-ws01&host=WS-01");
    expect(setSelectedHostId).toHaveBeenCalledWith("host-ws01");
    expect(setSelectedHost).toHaveBeenCalledWith("WS-01");
  });

  it("updates and clears host filter in the URL", async () => {
    const user = userEvent.setup();
    renderHarness("/cases/case-1/search?query=cmd&page=3&selected=row-1");

    await user.click(screen.getByRole("button", { name: "Set WS02" }));

    expect(screen.getByTestId("location")).toHaveTextContent("/cases/case-1/search?query=cmd&page=1&host_id=host-ws02&host=WS-02");
    expect(setSelectedHostId).toHaveBeenCalledWith("host-ws02");
    expect(setSelectedHost).toHaveBeenCalledWith("WS-02");

    await user.click(screen.getByRole("button", { name: "Clear" }));

    expect(screen.getByTestId("location")).toHaveTextContent("/cases/case-1/search?query=cmd&page=1");
    expect(clearSelectedHost).toHaveBeenCalled();
  });
});
