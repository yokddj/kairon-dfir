import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { MemoryCapabilityGate } from "./MemoryCapabilityGate";

const getSystemCapabilitiesMock = vi.fn();

vi.mock("../api/client", () => ({
  api: {
    getSystemCapabilities: () => getSystemCapabilitiesMock(),
  },
}));

function renderGate() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryCapabilityGate>
        <p>memory page</p>
      </MemoryCapabilityGate>
    </QueryClientProvider>,
  );
}

describe("MemoryCapabilityGate", () => {
  beforeEach(() => {
    getSystemCapabilitiesMock.mockReset();
  });

  it("renders the memory page when Memory is enabled", async () => {
    getSystemCapabilitiesMock.mockResolvedValue({ memory: { enabled: true } });
    renderGate();
    expect(await screen.findByText("memory page")).toBeInTheDocument();
  });

  it("says Memory is not enabled instead of rendering the page", async () => {
    getSystemCapabilitiesMock.mockResolvedValue({ memory: { enabled: false } });
    renderGate();
    expect(await screen.findByText("Memory Analysis is not enabled")).toBeInTheDocument();
    expect(screen.queryByText("memory page")).not.toBeInTheDocument();
  });

  it("keeps the page when the capability state cannot be read", async () => {
    getSystemCapabilitiesMock.mockRejectedValue(new Error("boom"));
    renderGate();
    await vi.waitFor(() => expect(getSystemCapabilitiesMock).toHaveBeenCalled());
    expect(await screen.findByText("memory page")).toBeInTheDocument();
  });
});
