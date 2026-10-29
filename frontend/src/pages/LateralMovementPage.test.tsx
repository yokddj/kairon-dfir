import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import LateralMovementPage from "./LateralMovementPage";

const getLateralMovementMock = vi.fn();

vi.mock("../api/client", () => ({
  api: { getLateralMovement: (...args: unknown[]) => getLateralMovementMock(...args) },
}));

vi.mock("../context/ActiveCaseContext", () => ({
  useActiveCase: () => ({ setActiveCaseId: vi.fn() }),
}));

function edge(overrides: Record<string, unknown>) {
  return {
    target_host: "SRV-A", source_ip: "10.0.0.5", source_hosts: ["WKS-A"], source_workstations: [], workstation_hosts: [],
    workstation_mismatch: false, source_ambiguous: false, user: "alice", domain: "CORP", method: "Network logon (type 3: SMB, WinRM, PsExec, WMI...)",
    logon_type: "3", successes: 4, failures: 0, first_seen: "2026-01-01T10:00:00.000Z", last_seen: "2026-01-01T10:05:00.000Z", routine_reason: null,
    ...overrides,
  };
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/cases/case-1/lateral-movement"]}>
        <Routes>
          <Route path="/cases/:caseId/lateral-movement" element={<LateralMovementPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("LateralMovementPage", () => {
  beforeEach(() => {
    getLateralMovementMock.mockReset();
  });

  it("lists remote logons, hides routine ones until asked, and links to their events", async () => {
    getLateralMovementMock.mockResolvedValue({
      case_id: "case-1",
      truncated: false,
      addresses: [{ ip: "10.0.0.5", hosts: ["WKS-A"], ambiguous: false }, { ip: "10.0.0.9", hosts: ["WKS-B", "WKS-C"], ambiguous: true }],
      edges: [
        edge({}),
        edge({ user: "WKS-A$", routine_reason: "machine account", successes: 50 }),
        edge({ source_ip: "203.0.113.9", source_hosts: [], target_host: "linux-web", user: "root", domain: null, method: "sshd (password)", logon_type: null, successes: 0, failures: 30 }),
        edge({ source_ip: "10.0.0.9", source_hosts: ["WKS-B", "WKS-C"], source_ambiguous: true, source_workstations: ["kali"], workstation_mismatch: true, user: "bob" }),
      ],
    });
    renderPage();

    expect(await screen.findByTestId("lateral-summary")).toHaveTextContent("3 of 4 connections · 1 routine hidden");
    const rows = screen.getAllByTestId("lateral-row");
    expect(rows[0]).toHaveTextContent("WKS-A");
    expect(rows[0]).toHaveTextContent("CORP\\alice");
    expect(rows[0]).toHaveTextContent("4 succeeded");
    expect(rows[1]).toHaveTextContent("Not a case host");
    expect(rows[1]).toHaveTextContent("30 failed");
    expect(rows[2]).toHaveTextContent("WKS-B or WKS-C");
    expect(screen.getByTestId("lateral-ambiguous")).toBeInTheDocument();
    expect(screen.getByTestId("lateral-mismatch")).toHaveTextContent("Workstation name is not the host holding this address");
    const link = screen.getAllByRole("link", { name: /events/i })[0];
    expect(link.getAttribute("href")).toContain("host=SRV-A");
    expect(link.getAttribute("href")).toContain("ip=10.0.0.5");
    expect(link.getAttribute("href")).toContain("user=alice");
    expect(screen.getByTestId("lateral-addresses")).toHaveTextContent("10.0.0.9 → WKS-B, WKS-C");

    fireEvent.click(screen.getByLabelText(/show routine/i));
    expect(screen.getAllByTestId("lateral-row")).toHaveLength(4);
    expect(screen.getByText("Routine: machine account")).toBeInTheDocument();

    fireEvent.click(screen.getByLabelText(/only with failed attempts/i));
    expect(screen.getAllByTestId("lateral-row")).toHaveLength(1);
  });

  it("says when there is nothing to show", async () => {
    getLateralMovementMock.mockResolvedValue({ case_id: "case-1", edges: [], addresses: [], truncated: false });
    renderPage();
    expect(await screen.findByTestId("lateral-empty")).toHaveTextContent("No remote logons found.");
  });
});
