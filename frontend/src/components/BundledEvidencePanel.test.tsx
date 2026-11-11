import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import BundledEvidencePanel, { type BundledEvidenceItem } from "./BundledEvidencePanel";

const registerBundledMemory = vi.fn();
vi.mock("../api/client", () => ({ api: { registerBundledMemory: (...args: unknown[]) => registerBundledMemory(...args) } }));

function renderPanel(items: BundledEvidenceItem[]) {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter>
        <BundledEvidencePanel caseId="case-1" evidenceId="ev-1" items={items} defaultHost="HOST01" hostNames={["HOST01", "HOST02"]} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const memory: BundledEvidenceItem = { path: "host02/ram/host02-capture.dd", kind: "memory_dump", label: "Memory image", size_bytes: 32 * 1024 ** 3 };
const pcap: BundledEvidenceItem = { path: "cap.pcap", kind: "pcap", label: "Packet capture", size_bytes: 1000 };

describe("BundledEvidencePanel", () => {
  beforeEach(() => {
    registerBundledMemory.mockReset().mockResolvedValue({ status: "queued", upload_session_id: "s1" });
  });

  it("registers a memory image with the chosen host, without a re-upload", async () => {
    renderPanel([memory, pcap]);
    const [memoryRow, pcapRow] = screen.getAllByTestId("bundled-evidence-item");
    expect(memoryRow).toHaveTextContent("32 GB");
    expect(within(pcapRow).queryByRole("button")).not.toBeInTheDocument();
    await userEvent.click(within(memoryRow).getByRole("button", { name: "Analyse as memory evidence" }));
    const host = screen.getByLabelText("Host it was captured on");
    expect(host).toHaveValue("HOST01");
    await userEvent.clear(host);
    await userEvent.type(host, "HOST02");
    await userEvent.click(screen.getByRole("button", { name: "Analyse as memory evidence" }));
    await waitFor(() => expect(registerBundledMemory).toHaveBeenCalledWith("case-1", "ev-1", { path: memory.path, provided_host: "HOST02" }));
  });

  it("shows progress, failure with its reason, and a link once registered", () => {
    const { rerender } = renderPanel([{ ...memory, registration_status: "running" }]);
    expect(screen.getByTestId("bundled-memory-progress")).toBeInTheDocument();
    rerender(
      <QueryClientProvider client={new QueryClient()}>
        <MemoryRouter>
          <BundledEvidencePanel caseId="case-1" evidenceId="ev-1" items={[{ ...memory, registration_status: "failed", registration_error: "The inspection did not confirm a memory image" }]} defaultHost="" hostNames={[]} />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    expect(screen.getByText(/did not confirm a memory image/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Try again as memory evidence" })).toBeInTheDocument();
    rerender(
      <QueryClientProvider client={new QueryClient()}>
        <MemoryRouter>
          <BundledEvidencePanel caseId="case-1" evidenceId="ev-1" items={[{ ...memory, registration_status: "registered", registered_evidence_id: "ev-mem" }]} defaultHost="" hostNames={[]} />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    expect(screen.getByTestId("bundled-memory-registered")).toHaveAttribute("href", expect.stringContaining("ev-mem"));
  });

  it("shows the server's refusal", async () => {
    registerBundledMemory.mockImplementation(() => Promise.reject(new Error("The extracted file is no longer on the server")));
    renderPanel([memory]);
    await userEvent.click(screen.getByRole("button", { name: "Analyse as memory evidence" }));
    await userEvent.click(screen.getByRole("button", { name: "Analyse as memory evidence" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("no longer on the server");
  });
});
