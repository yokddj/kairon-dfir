import { describe, expect, it } from "vitest";
import { fromDateTimeLocalValue, toDateTimeLocalValue } from "./time";

describe("datetime-local conversion in the display timezone", () => {
  it("reads the wall-clock input in the selected timezone, not the browser's", () => {
    expect(fromDateTimeLocalValue("2026-05-15T10:00", "UTC")).toBe("2026-05-15T10:00:00.000Z");
    expect(fromDateTimeLocalValue("2026-05-15T10:00", "Europe/Madrid")).toBe("2026-05-15T08:00:00.000Z");
    expect(fromDateTimeLocalValue("2026-01-15T10:00:30", "Europe/Madrid")).toBe("2026-01-15T09:00:30.000Z");
    expect(fromDateTimeLocalValue("2026-05-15T10:00", "America/New_York")).toBe("2026-05-15T14:00:00.000Z");
  });

  it("shows a UTC instant as wall-clock time in the selected timezone", () => {
    expect(toDateTimeLocalValue("2026-05-15T08:00:00.000Z", "Europe/Madrid")).toBe("2026-05-15T10:00");
    expect(toDateTimeLocalValue("2026-05-15T08:00:05.000Z", "UTC")).toBe("2026-05-15T08:00:05");
  });

  it("round-trips across a DST change", () => {
    const iso = fromDateTimeLocalValue("2026-03-29T03:30", "Europe/Madrid");
    expect(iso).toBe("2026-03-29T01:30:00.000Z");
    expect(toDateTimeLocalValue(iso, "Europe/Madrid")).toBe("2026-03-29T03:30");
  });

  it("keeps values that already carry an offset", () => {
    expect(fromDateTimeLocalValue("2026-05-15T10:00:00+02:00", "UTC")).toBe("2026-05-15T08:00:00.000Z");
    expect(fromDateTimeLocalValue("", "UTC")).toBe("");
  });
});
