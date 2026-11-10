import { act, render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { TimeRangeProvider, useOptionalTimeRangeContext } from "../context/TimeRangeContext";
import { useGlobalTimeRange } from "./useGlobalTimeRange";

let activeCaseId = "case-1";
vi.mock("../context/ActiveCaseContext", () => ({ useActiveCase: () => ({ activeCaseId }) }));

let navigateTo: (to: string) => void = () => undefined;
let setRange: (range: { from: string; to: string }) => void = () => undefined;
let clearGlobal: () => void = () => undefined;

function View({ name }: { name: string }) {
  const { timeFrom, timeTo, setTimeRange } = useGlobalTimeRange();
  const location = useLocation();
  const navigate = useNavigate();
  const context = useOptionalTimeRangeContext();
  navigateTo = navigate;
  setRange = setTimeRange;
  clearGlobal = () => context?.clearTimeRange();
  return (
    <div>
      <p data-testid="view">{name}</p>
      <p data-testid="range">{`${timeFrom}|${timeTo}`}</p>
      <p data-testid="url">{location.search}</p>
    </div>
  );
}

function renderApp(initial: string) {
  return render(
    <MemoryRouter initialEntries={[initial]}>
      <TimeRangeProvider>
        <Routes>
          <Route path="/search" element={<View name="search" />} />
          <Route path="/timeline" element={<View name="timeline" />} />
          <Route path="/artifacts" element={<View name="artifacts" />} />
        </Routes>
      </TimeRangeProvider>
    </MemoryRouter>,
  );
}

const FROM = "2026-05-15T08:00:00.000Z";
const TO = "2026-05-15T12:00:00.000Z";

describe("useGlobalTimeRange", () => {
  beforeEach(() => {
    localStorage.clear();
    activeCaseId = "case-1";
  });

  it("keeps a window set in one view when moving to another", () => {
    renderApp("/search");
    act(() => setRange({ from: FROM, to: TO }));
    expect(screen.getByTestId("url").textContent).toContain("time_from=");
    act(() => navigateTo("/timeline"));
    expect(screen.getByTestId("view").textContent).toBe("timeline");
    expect(screen.getByTestId("range").textContent).toBe(`${FROM}|${TO}`);
    expect(screen.getByTestId("url").textContent).toContain(encodeURIComponent(FROM));
  });

  it("adopts the window of a deep link as the case window", () => {
    renderApp(`/timeline?time_from=${encodeURIComponent(FROM)}&time_to=${encodeURIComponent(TO)}`);
    expect(screen.getByTestId("range").textContent).toBe(`${FROM}|${TO}`);
    act(() => navigateTo("/artifacts"));
    expect(screen.getByTestId("range").textContent).toBe(`${FROM}|${TO}`);
  });

  it("clearing from outside the view (top-bar chip) drops it from the URL", () => {
    renderApp("/search");
    act(() => setRange({ from: FROM, to: TO }));
    act(() => clearGlobal());
    expect(screen.getByTestId("range").textContent).toBe("|");
    expect(screen.getByTestId("url").textContent).not.toContain("time_from");
  });

  it("is stored per case and survives a reload", () => {
    const first = renderApp("/search");
    act(() => setRange({ from: FROM, to: "" }));
    first.unmount();
    renderApp("/timeline");
    expect(screen.getByTestId("range").textContent).toBe(`${FROM}|`);
  });

  it("does not leak a window into another case", () => {
    const first = renderApp("/search");
    act(() => setRange({ from: FROM, to: TO }));
    first.unmount();
    activeCaseId = "case-2";
    renderApp("/search");
    expect(screen.getByTestId("range").textContent).toBe("|");
  });
});
