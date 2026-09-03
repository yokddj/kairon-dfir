import { act, renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";

import {
  DEFAULT_COLUMN_WIDTH,
  MIN_COLUMN_WIDTH,
  useResizableColumns,
} from "./useResizableColumns";

const columns = [
  { key: "host", defaultWidth: 150 },
  { key: "command", defaultWidth: 420 },
  { key: "risk" },
];

beforeEach(() => localStorage.clear());

describe("useResizableColumns", () => {
  it("starts from each column's own default", () => {
    const { result } = renderHook(() => useResizableColumns("events.generic", columns));

    expect(result.current.widths.host).toBe(150);
    expect(result.current.widths.command).toBe(420);
    expect(result.current.widths.risk).toBe(DEFAULT_COLUMN_WIDTH);
  });

  it("remembers a width across remounts", () => {
    const first = renderHook(() => useResizableColumns("events.generic", columns));
    act(() => first.result.current.nudge("host", 60));
    first.unmount();

    const second = renderHook(() => useResizableColumns("events.generic", columns));

    expect(second.result.current.widths.host).toBe(210);
  });

  it("keeps each table's widths separate", () => {
    const generic = renderHook(() => useResizableColumns("events.generic", columns));
    act(() => generic.result.current.nudge("host", 100));

    const other = renderHook(() => useResizableColumns("artifacts.motw", columns));

    expect(other.result.current.widths.host).toBe(150);
  });

  it("never lets a column be dragged away to nothing", () => {
    const { result } = renderHook(() => useResizableColumns("events.generic", columns));

    act(() => result.current.nudge("host", -10_000));

    expect(result.current.widths.host).toBe(MIN_COLUMN_WIDTH);
  });

  it("resets back to the defaults", () => {
    const { result } = renderHook(() => useResizableColumns("events.generic", columns));
    act(() => result.current.nudge("command", 200));
    expect(result.current.isCustomised).toBe(true);

    act(() => result.current.reset());

    expect(result.current.widths.command).toBe(420);
    expect(result.current.isCustomised).toBe(false);
  });

  it("reports nothing customised before the analyst touches anything", () => {
    const { result } = renderHook(() => useResizableColumns("events.generic", columns));

    expect(result.current.isCustomised).toBe(false);
  });

  it("ignores a stored width that is corrupt or absurd", () => {
    localStorage.setItem(
      "kairon.columnWidths.events.generic",
      JSON.stringify({ host: 5, command: "wide", risk: 260 }),
    );

    const { result } = renderHook(() => useResizableColumns("events.generic", columns));

    expect(result.current.widths.host).toBe(150, "below the minimum, so the default stands");
    expect(result.current.widths.command).toBe(420);
    expect(result.current.widths.risk).toBe(260);
  });

  it("survives unreadable storage", () => {
    localStorage.setItem("kairon.columnWidths.events.generic", "{not json");

    const { result } = renderHook(() => useResizableColumns("events.generic", columns));

    expect(result.current.widths.host).toBe(150);
  });

  it("tracks which column is being dragged", () => {
    const { result } = renderHook(() => useResizableColumns("events.generic", columns));

    expect(result.current.resizingKey).toBeNull();
    act(() => result.current.startResize("command", 400));
    expect(result.current.resizingKey).toBe("command");
  });

  it("widens the column as the pointer moves right", () => {
    const { result } = renderHook(() => useResizableColumns("events.generic", columns));

    act(() => result.current.startResize("host", 400));
    act(() => window.dispatchEvent(new MouseEvent("mousemove", { clientX: 500 })));

    expect(result.current.widths.host).toBe(250);
  });

  it("stops resizing when the button is released", () => {
    const { result } = renderHook(() => useResizableColumns("events.generic", columns));

    act(() => result.current.startResize("host", 400));
    act(() => window.dispatchEvent(new MouseEvent("mouseup")));
    act(() => window.dispatchEvent(new MouseEvent("mousemove", { clientX: 900 })));

    expect(result.current.resizingKey).toBeNull();
    expect(result.current.widths.host).toBe(150);
  });
});
