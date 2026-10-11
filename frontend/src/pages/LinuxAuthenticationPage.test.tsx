import { render, screen, waitFor, within } from "@testing-library/react";
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

function renderPage(path = "/cases/case-1/linux-authentication") {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/cases/:caseId/linux-authentication" element={<LinuxAuthenticationPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const response = {
  case_id: "case-1",
  truncated: false,
  overview: {
    successful_logins: 4, failed_attempts: 1509, accounts_with_logins: 1, accounts_targeted: 2, source_ips: 1, attack_campaigns: 1,
    sessions: 4, privileged_actions: 1, account_changes: 1, findings: { critical: 1, high: 1 }, first_event: "2019-10-05T10:39:26Z", last_event: "2019-10-05T11:24:11Z",
  },
  coverage: [
    { carrier: "auth_log", label: "auth.log / secure", events: 2353, files: 1, first: "2019-10-05T10:39:26Z", last: "2019-10-05T11:24:11Z" },
    { carrier: "journal", label: "systemd journal", events: 0, files: 0, first: null, last: null },
  ],
  findings: [
    { id: "f1", severity: "critical", kind: "success_after_attack", title: "Successful login after brute force from 192.168.210.131", detail: "1509 failed attempts, then mail logged in.", time: "2019-10-05T11:13:53Z", account: "mail", source_ip: "192.168.210.131", event_ids: ["ev-1"] },
    { id: "f2", severity: "high", kind: "privileged_account_change", title: "mail added to sudo", detail: "add 'mail' to group 'sudo'", time: "2019-10-05T11:09:18Z", account: "mail", source_ip: "", event_ids: ["ev-2"] },
  ],
  accounts: [
    { username: "mail", uid: 8, shell: "/bin/bash", kind: "system", known_account: true, logins: 4, failed_attempts: 1, methods: ["password"], sources: [{ source_ip: "192.168.210.131", logins: 4 }],
      first_login: "2019-10-05T11:13:53Z", last_login: "2019-10-05T11:23:34Z", last_failure: null, sudo_commands: 0, sudo_denied: 0, su_to: [{ target: "root", count: 5 }], changes: 3, lastlog: null },
  ],
  sources: [
    { source_ip: "192.168.210.131", first_seen: "2019-10-05T10:39:26Z", last_seen: "2019-10-05T11:24:11Z", failed_attempts: 1509, accounts_tried: [{ username: "root", attempts: 1508 }],
      accounts_tried_count: 2, logins: 4, login_accounts: ["mail"], pattern: "brute_force", campaigns: 1, first_login: "2019-10-05T11:13:53Z" },
  ],
  campaigns: [
    { id: "c1", source_ip: "192.168.210.131", pattern: "brute_force", first_seen: "2019-10-05T10:39:26Z", last_seen: "2019-10-05T11:20:59Z", attempts: 1509,
      accounts: [{ username: "root", attempts: 1508 }, { username: "mail", attempts: 1 }], account_count: 2, services: ["sshd"], followed_by_success: true,
      success_account: "mail", success_time: "2019-10-05T11:13:53Z", seconds_to_success: -426, success_during_campaign: true, event_ids: ["ev-1"] },
  ],
  sessions: [
    { id: "s1", kind: "ssh", username: "mail", source_ip: "192.168.210.131", source_port: 57708, service: "sshd", method: "password", terminal: "pts/1", host: "victoria",
      start: "2019-10-05T11:23:34Z", end: "2019-10-05T11:24:11Z", duration_seconds: 37, status: "closed", carriers: ["auth_log", "wtmp"], event_ids: ["ev-3"] },
  ],
  failures: [{ source_ip: "192.168.210.131", username: "root", service: "sshd", attempts: 1508, connections: 232, first_seen: "2019-10-05T10:39:26Z", last_seen: "2019-10-05T10:52:52Z", event_ids: ["ev-4"] }],
  privilege: [{ id: "p1", time: "2019-10-05T11:14:04Z", tool: "su", user: "mail", target: "root", command: "", cwd: "", terminal: "pts/1", result: "allowed", reason: "", carrier: "auth_log" }],
  account_changes: [{ id: "ev-2", time: "2019-10-05T11:09:18Z", action: "group_member_added", account: "mail", group: "sudo", by: "", details: {}, privileged: true, tool: "usermod", carrier: "auth_log", message: "add 'mail' to group 'sudo'", account_kind: "system" }],
  events: { total: 120, offset: 0, limit: 50, items: [
    { id: "ev-9", time: "2019-10-05T11:24:11Z", carrier: "auth_log", kind: "session_close", result: "success", username: "mail", source_ip: "", service: "sshd", process: "sshd", message: "pam_unix(sshd:session): session closed for user mail" },
  ] },
};

describe("LinuxAuthenticationPage", () => {
  beforeEach(() => {
    getLinuxAuthenticationMock.mockReset();
    getLinuxAuthenticationMock.mockResolvedValue(response);
  });

  it("opens on findings, overview and data coverage", async () => {
    renderPage();
    const findings = await screen.findByTestId("auth-findings");
    expect(within(findings).getAllByTestId("auth-finding")).toHaveLength(2);
    expect(within(findings).getByText(/Successful login after brute force/)).toBeInTheDocument();
    expect(within(findings).getAllByRole("link", { name: "event 1" })[0]).toHaveAttribute("href", `/cases/case-1/search?q=${encodeURIComponent('event_id:"ev-1"')}`);
    expect(within(screen.getByTestId("auth-coverage")).getByText("not present")).toBeInTheDocument();
    expect(within(screen.getByTestId("auth-overview")).getByText("1509")).toBeInTheDocument();
  });

  it("focuses the whole page on an account picked from a finding", async () => {
    renderPage();
    const findings = await screen.findByTestId("auth-findings");
    await userEvent.click(within(findings).getAllByRole("button", { name: "account mail" })[0]);
    await waitFor(() => expect(getLinuxAuthenticationMock).toHaveBeenLastCalledWith("case-1", expect.objectContaining({ username: "mail" })));
    expect(within(screen.getByTestId("active-filters")).getByText("Account: mail ×")).toBeInTheDocument();
  });

  it("shows each tab's own view", async () => {
    renderPage();
    await screen.findByTestId("auth-findings");
    await userEvent.click(screen.getByRole("tab", { name: /Accounts/ }));
    expect(within(screen.getByTestId("auth-accounts")).getByText(/system · 8/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("tab", { name: /Sessions/ }));
    expect(within(screen.getByTestId("auth-sessions")).getByText("37s")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("tab", { name: /Failed logins/ }));
    expect(within(screen.getByTestId("auth-campaigns")).getByText(/login as mail during the attack/)).toBeInTheDocument();
    expect(within(screen.getByTestId("auth-failures")).getByText("1508")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("tab", { name: /sudo \/ su/ }));
    expect(within(screen.getByTestId("auth-privilege")).getByText("root")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("tab", { name: /Account changes/ }));
    expect(within(screen.getByTestId("auth-changes")).getByText("Added to group")).toBeInTheDocument();
  });

  it("pages and groups the raw events", async () => {
    renderPage("/cases/case-1/linux-authentication?tab=events");
    await screen.findByTestId("auth-events");
    expect(screen.getByText("1–50 of 120")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Next" }));
    await waitFor(() => expect(getLinuxAuthenticationMock).toHaveBeenLastCalledWith("case-1", expect.objectContaining({ offset: 50 })));
    await userEvent.selectOptions(screen.getByLabelText("Event group"), "failures");
    await waitFor(() => expect(getLinuxAuthenticationMock).toHaveBeenLastCalledWith("case-1", expect.objectContaining({ event_group: "failures", offset: 0 })));
  });
});
