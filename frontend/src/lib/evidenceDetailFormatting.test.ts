import { describe, expect, it } from "vitest";

import { formatIndexingPhaseForDisplay } from "./evidenceDetailFormatting";

describe("formatIndexingPhaseForDisplay", () => {
  it("maps every disk-image current_action to an analyst-facing label", () => {
    expect(formatIndexingPhaseForDisplay("detecting_format")).toBe("Detecting image format");
    expect(formatIndexingPhaseForDisplay("hashing")).toBe("Hashing evidence");
    expect(formatIndexingPhaseForDisplay("inspecting_image")).toBe("Inspecting disk image");
    expect(formatIndexingPhaseForDisplay("discovering_volumes")).toBe("Discovering volumes");
    expect(formatIndexingPhaseForDisplay("materializing_disk_image_files")).toBe("Extracting filesystem contents");
  });

  it("still maps pre-existing non-disk-image phases unchanged", () => {
    expect(formatIndexingPhaseForDisplay("completed")).toBe("Evidence ready for investigation");
    expect(formatIndexingPhaseForDisplay("processing")).toBe("Indexing in progress");
    expect(formatIndexingPhaseForDisplay("extracting_selected")).toBe("Extracting selected artifacts");
  });

  it("falls back to a safe, humanized label for an unknown action instead of raw snake_case", () => {
    expect(formatIndexingPhaseForDisplay("some_future_unmapped_action")).toBe("some future unmapped action");
  });

  it("falls back to Unknown for empty/missing phase", () => {
    expect(formatIndexingPhaseForDisplay(null)).toBe("Unknown");
    expect(formatIndexingPhaseForDisplay(undefined)).toBe("Unknown");
    expect(formatIndexingPhaseForDisplay("")).toBe("Unknown");
  });
});
