/** @vitest-environment jsdom */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { MemoryStackView } from "./MemoryStackView";

const getMemoryStackMock = vi.fn();

vi.mock("../../api/client", () => ({
  api: { getMemoryStack: (...args: unknown[]) => getMemoryStackMock(...args) },
}));

function renderStack(onOpenValue = vi.fn()) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryStackView caseId="case-1" evidenceId="ev-1" family="handles" groupFacets={[{ value: "Mutant", count: 12 }]} onOpenValue={onOpenValue} />
    </QueryClientProvider>,
  );
  return onOpenValue;
}

describe("MemoryStackView", () => {
  it("lists each value once with how many processes have it, and opens its records", async () => {
    getMemoryStackMock.mockResolvedValue({
      family: "handles", total_values: 2, truncated: false, run_process_count: 153, page: 1, page_size: 50,
      items: [
        { value: "Global\\RareMutex", group: "Mutant", occurrences: 1, process_count: 1, process_names: ["evil.exe"] },
        { value: "MACHINE", group: "Key", occurrences: 209, process_count: 150, process_names: ["svchost.exe", "explorer.exe"] },
      ],
    });
    const onOpenValue = renderStack();

    const rows = await screen.findAllByTestId("memory-stack-row");
    expect(rows[0]).toHaveTextContent("1 / 153");
    expect(rows[0]).toHaveTextContent("Global\\RareMutex");
    expect(screen.getByTestId("memory-stack-summary")).toHaveTextContent("2 distinct object names across 153 processes");
    expect(getMemoryStackMock).toHaveBeenLastCalledWith("case-1", "ev-1", expect.objectContaining({ family: "handles", order: "rare" }));

    fireEvent.click(screen.getAllByTestId("memory-stack-open")[0]);
    expect(onOpenValue).toHaveBeenCalledWith("Global\\RareMutex", "Mutant");

    fireEvent.change(screen.getByTestId("memory-stack-group"), { target: { value: "Mutant" } });
    await waitFor(() => expect(getMemoryStackMock).toHaveBeenLastCalledWith("case-1", "ev-1", expect.objectContaining({ group: "Mutant", page: 1 })));
  });
});
