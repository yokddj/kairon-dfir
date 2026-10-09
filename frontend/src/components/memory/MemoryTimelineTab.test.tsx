import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { MemoryEvidenceTimeline } from "../../api/client";
import { MemoryTimelineTab } from "./MemoryTimelineTab";

const getMemoryEvidenceTimelineMock = vi.fn();

vi.mock("../../api/client", () => ({
  api: { getMemoryEvidenceTimeline: (...args: unknown[]) => getMemoryEvidenceTimelineMock(...args) },
}));
vi.mock("../../context/TimezoneContext", () => ({ useTimezonePreference: () => ({ effectiveTimezone: "UTC" }) }));

const KINDS = [
  { key: "processes", producer: "volatility", label: "Process", default: true },
  { key: "eventlog", producer: "memprocfs", label: "Event log", default: true },
  { key: "ntfs", producer: "memprocfs", label: "NTFS", default: false },
];

function page(overrides: Partial<MemoryEvidenceTimeline> = {}): MemoryEvidenceTimeline {
  return {
    items: [
      { id: "vol-1", timestamp: "2025-03-07T19:41:23Z", producer: "volatility", kind: "processes", kind_label: "Process", title: "Process started: DumpIt.exe", pid: 2164, process_name: "DumpIt.exe" },
      { id: "memprocfs-2", timestamp: "2025-03-07T19:41:33Z", producer: "memprocfs", kind: "eventlog", kind_label: "Event log", title: "Security event 4688: NewProcessName=cmd.exe", pid: 4 },
    ],
    next_cursor: "cursor-2",
    page_size: 100,
    order: "asc",
    selected_kinds: ["processes", "eventlog"],
    total: 300,
    counts: { processes: 168, eventlog: 132, ntfs: 73739 },
    kinds: KINDS,
    ...overrides,
  };
}

function renderTab() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryTimelineTab caseId="case-1" evidenceId="ev-1" />
    </QueryClientProvider>,
  );
}

describe("MemoryTimelineTab", () => {
  beforeEach(() => {
    getMemoryEvidenceTimelineMock.mockReset();
    getMemoryEvidenceTimelineMock.mockResolvedValue(page());
  });

  it("lists Volatility and MemProcFS events of this evidence in one table", async () => {
    renderTab();
    await waitFor(() => expect(screen.getAllByTestId("memory-timeline-row")).toHaveLength(2));
    expect(screen.getByText("Volatility")).toBeTruthy();
    expect(screen.getByText("MemProcFS")).toBeTruthy();
    expect(screen.getByTestId("memory-timeline-summary").textContent).toContain("300 events");
    expect(getMemoryEvidenceTimelineMock.mock.calls[0][0]).toBe("case-1");
    expect(getMemoryEvidenceTimelineMock.mock.calls[0][1]).toBe("ev-1");
  });

  it("shows NTFS off by default and asks for it when turned on", async () => {
    renderTab();
    const ntfs = await screen.findByTestId("memory-timeline-kind-ntfs");
    expect(ntfs.getAttribute("aria-pressed")).toBe("false");
    expect(ntfs.textContent).toContain("73,739");
    fireEvent.click(ntfs);
    await waitFor(() => expect(getMemoryEvidenceTimelineMock).toHaveBeenLastCalledWith("case-1", "ev-1", expect.objectContaining({ kinds: ["processes", "eventlog", "ntfs"], cursor: null })));
  });

  it("pages forward with the cursor and back to the previous page", async () => {
    renderTab();
    fireEvent.click(await screen.findByTestId("memory-timeline-next"));
    await waitFor(() => expect(getMemoryEvidenceTimelineMock).toHaveBeenLastCalledWith("case-1", "ev-1", expect.objectContaining({ cursor: "cursor-2" })));
    fireEvent.click(await screen.findByTestId("memory-timeline-prev"));
    await waitFor(() => expect(screen.getByTestId("memory-timeline-summary").textContent).toContain("page 1"));
  });

  it("says what to run when the image has no dated event yet", async () => {
    getMemoryEvidenceTimelineMock.mockResolvedValue(page({ items: [], next_cursor: null, total: 0, counts: { processes: 0, eventlog: 0, ntfs: 0 } }));
    renderTab();
    expect((await screen.findByTestId("memory-timeline-empty")).textContent).toContain("Find Evil");
  });
});
