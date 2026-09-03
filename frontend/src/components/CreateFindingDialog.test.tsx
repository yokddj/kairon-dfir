import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import CreateFindingDialog from "./CreateFindingDialog";
import type { FindingPrefill } from "../lib/findingPrefill";

const createFindingMock = vi.fn();

vi.mock("../api/client", () => ({
  api: {
    createFinding: (...args: unknown[]) => createFindingMock(...args),
  },
}));

function renderDialog(prefill: FindingPrefill, options?: { container?: HTMLElement }) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  const onClose = vi.fn();
  const onCreated = vi.fn();
  render(
    <QueryClientProvider client={queryClient}>
      <CreateFindingDialog open caseId="case-1" prefill={prefill} onClose={onClose} onCreated={onCreated} />
    </QueryClientProvider>,
    options,
  );
  return { onClose, onCreated };
}

function longPrefill(): FindingPrefill {
  const longText = Array.from({ length: 80 }, (_, index) => `Downloaded suspicious-${index}.exe from http://evil.example/${index}`).join("\n");
  return {
    title: "Potential malware download",
    body: longText,
    severity: "medium",
    status: "draft",
    tags: ["browser", "download"],
    linked_evidence_id: "evidence-1",
    linked_host_id: "host-1",
    linked_artifact_family: "browser",
    linked_artifact_type: "history",
    linked_event_id: "evt-download-1",
    event_ids: ["evt-download-1"],
    source_view: "search",
    source_route: "/cases/case-1/search?selected=evt-download-1",
    source_timestamp: "2026-05-15T10:00:00Z",
    source_label: "Search result",
    source_summary: longText,
    source_snapshot_json: {
      timestamp: "2026-05-15T10:00:00Z",
      family: "browser",
      type: "history",
      summary: longText,
      fields: {
        url: "http://evil.example/suspicious.exe",
        file_name: "suspicious.exe",
      },
    },
  };
}

describe("CreateFindingDialog", () => {
  beforeEach(() => {
    createFindingMock.mockReset();
    createFindingMock.mockResolvedValue({
      id: "finding-1",
      case_id: "case-1",
      title: "Potential malware download",
      severity: "medium",
      status: "draft",
      created_at: "2026-01-01T00:00:00Z",
      updated_at: "2026-01-01T00:00:00Z",
    });
  });

  it("keeps actions visible while long source content scrolls", async () => {
    const { onCreated } = renderDialog(longPrefill());

    expect(screen.getByRole("button", { name: /Create finding/i })).toBeInTheDocument();
    const scrollRegion = screen.getByTestId("create-finding-scroll-region");
    expect(scrollRegion.className).toContain("overflow-y-auto");
    expect(scrollRegion.className).toContain("min-h-0");

    const actionBar = screen.getByTestId("create-finding-action-bar");
    expect(actionBar.className).toContain("sticky");
    expect(within(actionBar).getByRole("button", { name: /Create finding/i })).toBeInTheDocument();
    expect(within(actionBar).getByRole("button", { name: /Cancel/i })).toBeInTheDocument();
    expect(screen.getByText(/Source artifact\/event/i).closest("details")).not.toHaveAttribute("open");

    await userEvent.click(within(actionBar).getByRole("button", { name: /Create finding/i }));

    await waitFor(() => expect(createFindingMock).toHaveBeenCalled());
    expect(createFindingMock).toHaveBeenCalledWith("case-1", expect.objectContaining({
      title: "Potential malware download",
      source_summary: expect.stringContaining("Downloaded suspicious-0.exe"),
      source_snapshot_json: expect.objectContaining({ family: "browser" }),
    }));
    await waitFor(() => expect(onCreated).toHaveBeenCalled());
  });

  it("escapes an ancestor that would otherwise clip its fixed positioning", () => {
    // `filter`/`backdrop-filter`/`transform`/`will-change` on an ancestor create a new CSS
    // containing block, so a `position: fixed` dialog rendered inline inside one of those (e.g. a
    // panel styled with backdrop-blur) gets clipped to that ancestor's box instead of the
    // viewport, pushing its action buttons out of the reachable area. The dialog portals to
    // document.body specifically so this can't happen regardless of where it's mounted from.
    const filteredAncestor = document.createElement("div");
    filteredAncestor.setAttribute("data-testid", "filtered-ancestor");
    filteredAncestor.style.backdropFilter = "blur(4px)";
    document.body.appendChild(filteredAncestor);

    renderDialog(longPrefill(), { container: filteredAncestor });

    const dialog = screen.getByRole("dialog", { name: /create finding from source/i });
    expect(filteredAncestor.contains(dialog)).toBe(false);
    expect(document.body.contains(dialog)).toBe(true);
  });
});
