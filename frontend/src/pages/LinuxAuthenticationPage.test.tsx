import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import LinuxAuthenticationPage from "./LinuxAuthenticationPage";

const getLinuxAuthenticationMock = vi.fn();

vi.mock("../api/client", () => ({
  api: {
    getLinuxAuthentication: (...args: unknown[]) => getLinuxAuthenticationMock(...args),
  },
}));

vi.mock("../context/ActiveCaseContext", () => ({
  useActiveCase: () => ({ activeCaseId: "", activeCase: null }),
}));

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={["/cases/case-1/linux-authentication"]}>
        <Routes>
          <Route path="/cases/:caseId/linux-authentication" element={<LinuxAuthenticationPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const response = {
  case_id: "case-1",
  overview: {
    successful_logins: 1,
    failed_attempts: 32,
    effective_failed_attempts: 32,
    reconstructed_sessions: 1,
    suspected_brute_force_groups: 1,
    distinct_source_ips: 1,
    last_successful_login: { username: "mail", event_time: "2026-10-05T13:23:34Z" },
    lastlog_source_ip_count: 2,
    lastlog_supported: true,
  },
  sessions: [{ id: "s1", username: "mail", source_ip: "192.168.210.131", source_port: 57708, service: "sshd", start: "2026-10-05T13:23:34Z", end: "2026-10-05T13:24:34Z", duration_seconds: 60, status: "complete", confidence: "reconstructed", evidence_sources: ["/var/log/auth.log"] }],
  failed_authentication: [{ id: "f1", event_time: "2026-02-06T15:16:26Z", event_type: "login_failure", authentication_result: "failure", service: "sshd", process: "sshd", username: "ulysses", attempted_username: "ulysses", source_ip: "192.168.56.1", source_port: 34431, destination_host: "victoria", terminal: "ssh", message: "Failed password for invalid user ulysses", source_file: "/var/log/auth.log", artifact_type: "auth_log", explicit_failure_count: 1, effective_failure_count: 1 }],
  brute_force: [{ id: "bf1", target_account: "ulysses", source_ip: "192.168.56.1", service: "sshd", first_seen: "2026-02-06T15:16:20Z", last_seen: "2026-02-06T15:21:10Z", explicit_failed_events: 32, pam_aggregate_failures: 7, effective_attempts: 32, distinct_usernames: ["ulysses"], distinct_source_ips: ["192.168.56.1"], followed_by_success: false, successful_username: null, time_to_success_seconds: null, status: "suspected" }],
  last_login: [{ id: "l1", event_time: "2026-10-05T13:23:34Z", event_type: "login_success", authentication_result: "success", service: "login", process: "login", username: "mail", attempted_username: "mail", source_ip: "192.168.210.131", source_port: null, destination_host: "VulnOSv2", terminal: "pts/0", message: "lastlog", source_file: "/var/log/lastlog", artifact_type: "lastlog" }],
  events: [],
};

describe("LinuxAuthenticationPage", () => {
  beforeEach(() => {
    getLinuxAuthenticationMock.mockReset();
    getLinuxAuthenticationMock.mockResolvedValue(response);
  });

  it("renders investigation sections and derived answers", async () => {
    renderPage();
    expect(await screen.findByRole("heading", { name: /Authentication Investigation/i })).toBeInTheDocument();
    expect((await screen.findAllByText("mail")).length).toBeGreaterThan(0);
    expect(screen.getByText("57708")).toBeInTheDocument();
    expect(screen.getByText("1m")).toBeInTheDocument();
    expect(screen.getAllByText("ulysses").length).toBeGreaterThan(0);
    expect(screen.getAllByText("32").length).toBeGreaterThan(0);
    expect(screen.getByText("pts/0")).toBeInTheDocument();
  });

  it("uses structured filters", async () => {
    renderPage();
    await screen.findByRole("heading", { name: /Authentication Investigation/i });
    await userEvent.type(screen.getByLabelText("Attempted username"), "ulysses");
    await userEvent.type(screen.getByLabelText("Source IP"), "192.168.56.1");
    await userEvent.click(screen.getByLabelText("Brute-force only"));
    await waitFor(() => expect(getLinuxAuthenticationMock).toHaveBeenLastCalledWith("case-1", expect.objectContaining({ attempted_username: "ulysses", source_ip: "192.168.56.1", brute_force_only: true })));
  });
});
