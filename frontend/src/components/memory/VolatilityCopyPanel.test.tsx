import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api, type VolatilityViewStatus } from "../../api/client";
import { VolatilityCopyPanel } from "./VolatilityCopyPanel";

vi.mock("../../api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../api/client")>();
  return { ...actual, api: { ...actual.api, getVolatilityView: vi.fn(), createVolatilityView: vi.fn(), removeVolatilityView: vi.fn() } };
});

const base: VolatilityViewStatus = { evidence_id: "e1", needed: true, enabled: true, status: "none", estimated_bytes: 40 * 2 ** 30, bytes: null, message: null, updated_at: null };

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
    vi.mocked(api.createVolatilityView).mockReset();
  });

  it("shows nothing when Volatility reads the image", async () => {
    vi.mocked(api.getVolatilityView).mockResolvedValue({ ...base, needed: false });
    renderPanel();
    await waitFor(() => expect(api.getVolatilityView).toHaveBeenCalled());
    expect(screen.queryByTestId("volatility-copy-panel")).not.toBeInTheDocument();
  });

  it("offers the copy with its size and writes it only on request", async () => {
    vi.mocked(api.getVolatilityView).mockResolvedValue(base);
    vi.mocked(api.createVolatilityView).mockResolvedValue({ ...base, status: "queued" });
    renderPanel();
    const button = await screen.findByRole("button", { name: /Create the copy for Volatility \(about 40 GiB\)/ });
    expect(api.createVolatilityView).not.toHaveBeenCalled();
    await userEvent.click(button);
    await waitFor(() => expect(api.createVolatilityView).toHaveBeenCalledWith("c1", "e1"));
  });

  it("says why the copy could not be made", async () => {
    vi.mocked(api.getVolatilityView).mockResolvedValue({ ...base, status: "skipped_disk_space", message: "Not enough free space: about 45 GiB needed, 20 GiB available." });
    renderPanel();
    expect(await screen.findByRole("alert")).toHaveTextContent("Not enough free space");
  });
});
