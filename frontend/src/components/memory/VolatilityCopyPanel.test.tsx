import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api, type VolatilityViewStatus } from "../../api/client";
import { VolatilityCopyPanel } from "./VolatilityCopyPanel";

vi.mock("../../api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../api/client")>();
  return { ...actual, api: { ...actual.api, getVolatilityView: vi.fn(), removeVolatilityView: vi.fn() } };
});

const base: VolatilityViewStatus = { evidence_id: "e1", needed: false, layer: null, status: "none", bytes: null, message: null, updated_at: null };

function renderPanel() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <VolatilityCopyPanel caseId="c1" evidenceId="e1" />
    </QueryClientProvider>,
  );
}

describe("VolatilityCopyPanel", () => {
  beforeEach(() => {
    vi.mocked(api.getVolatilityView).mockReset();
    vi.mocked(api.removeVolatilityView).mockReset();
  });

  it("shows nothing when Volatility reads the image, pinned layer or not", async () => {
    vi.mocked(api.getVolatilityView).mockResolvedValue({ ...base, layer: { page_map_offset: "0x1ae000", source: "MemProcFS" } });
    renderPanel();
    await waitFor(() => expect(api.getVolatilityView).toHaveBeenCalled());
    expect(screen.queryByTestId("volatility-copy-panel")).not.toBeInTheDocument();
  });

  it("says when Volatility cannot read the image, without offering a copy", async () => {
    vi.mocked(api.getVolatilityView).mockResolvedValue({ ...base, needed: true });
    renderPanel();
    expect(await screen.findByText("Volatility cannot read this image")).toBeInTheDocument();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });

  it("offers to remove an old copy", async () => {
    vi.mocked(api.getVolatilityView).mockResolvedValue({ ...base, status: "created", bytes: 34 * 2 ** 30, layer: { page_map_offset: "0x1ae000", source: "MemProcFS" } });
    vi.mocked(api.removeVolatilityView).mockResolvedValue({ ...base, status: "removing" });
    renderPanel();
    expect(await screen.findByText(/no longer needed/)).toBeInTheDocument();
    expect(screen.getByText(/0x1ae000/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Remove the copy" }));
    await waitFor(() => expect(api.removeVolatilityView).toHaveBeenCalledWith("c1", "e1"));
  });
});
