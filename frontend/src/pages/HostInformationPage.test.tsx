import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import HostInformationPage from "./HostInformationPage";
import type { CaseHostFactsResponse, CaseHostNetworkResponse, CaseHostUsersResponse, HostNetworkAddress, HostUserFieldResolution } from "../api/client";

const getCaseHostFactsMock = vi.fn();
const getCaseHostUsersMock = vi.fn();
const getCaseHostNetworkMock = vi.fn();
const useActiveCaseMock = vi.fn();

vi.mock("../api/client", () => ({
  api: {
    getCaseHostFacts: (...args: unknown[]) => getCaseHostFactsMock(...args),
    getCaseHostUsers: (...args: unknown[]) => getCaseHostUsersMock(...args),
    getCaseHostNetwork: (...args: unknown[]) => getCaseHostNetworkMock(...args),
  },
}));

vi.mock("../context/ActiveCaseContext", () => ({
  useActiveCase: () => useActiveCaseMock(),
}));

type HostSummary = { id: string; display_name: string; canonical_name: string };

function host(overrides: Partial<HostSummary> = {}): HostSummary {
  return { id: "host-1", display_name: "webserver-01", canonical_name: "webserver-01", ...overrides };
}

function activeCaseValue(hosts: HostSummary[], loading = false) {
  return {
    setActiveCaseId: vi.fn(),
    caseContext: { hosts },
    isCaseContextLoading: loading,
  };
}

function observation(overrides: Partial<CaseHostFactsResponse["facts"][number]["observations"][number]> = {}) {
  return {
    id: "obs-1",
    source_kind: "hostname",
    parser: "linux_os_info",
    source_path: "/etc/hostname",
    raw_value: "webserver-01",
    normalized_value: "webserver-01",
    confidence: "high",
    status: "confirmed",
    observed_at: "2026-01-01T00:00:00Z",
    event_id: null,
    evidence_id: "ev-1",
    artifact_id: "art-1",
    host_id: "host-1",
    provenance: {},
    created_at: "2026-01-01T00:00:00Z",
    ...overrides,
  };
}

function factsResponse(facts: CaseHostFactsResponse["facts"]): CaseHostFactsResponse {
  return { case_id: "case-1", scope: "host", host_id: "host-1", facts };
}

function fieldResolution(field: string, overrides: Partial<HostUserFieldResolution> = {}): HostUserFieldResolution {
  return { field, status: "observed", preferred_value: null, supporting: [], conflicting: [], observations: [], ...overrides };
}

function userObservation(overrides: Partial<CaseHostUsersResponse["users"][number]["identity"]["uid"]["observations"][number]> = {}) {
  return {
    id: "uobs-1",
    source_kind: "passwd",
    parser: "linux_identity_raw",
    source_path: "/etc/passwd",
    observed_at: "2026-01-01T00:00:00Z",
    event_id: null,
    evidence_id: "ev-1",
    artifact_id: "art-1",
    host_id: "host-1",
    created_at: "2026-01-01T00:00:00Z",
    ...overrides,
  };
}

function userEntry(overrides: Partial<CaseHostUsersResponse["users"][number]> = {}): CaseHostUsersResponse["users"][number] {
  return {
    username: "alice",
    is_synthetic_username: false,
    identity: {
      uid: fieldResolution("uid", { status: "observed", preferred_value: "1000", observations: [userObservation()] }),
      id_kind: fieldResolution("id_kind", { status: "observed", preferred_value: "uid" }),
      primary_gid: fieldResolution("primary_gid", { status: "observed", preferred_value: "1000" }),
      gecos: fieldResolution("gecos", { status: "missing" }),
      home: fieldResolution("home", { status: "observed", preferred_value: "/home/alice" }),
      shell: fieldResolution("shell", { status: "observed", preferred_value: "/bin/bash" }),
    },
    attributes: {},
    primary_group_name: null,
    secondary_groups: [],
    password_status: fieldResolution("password_status", { status: "missing", preferred_value: "unavailable" }),
    account_status: fieldResolution("account_status", { status: "missing", preferred_value: null }),
    last_login: null,
    shell_classification: "login",
    effective_sudo: { has_sudo: false, via: null, granting_groups: [], observations: [] },
    ...overrides,
  };
}

function usersResponse(users: CaseHostUsersResponse["users"]): CaseHostUsersResponse {
  return { case_id: "case-1", scope: "host", host_id: "host-1", users };
}

function networkSource(overrides: Partial<HostNetworkAddress["sources"][number]> = {}): HostNetworkAddress["sources"][number] {
  return {
    source_kind: "sysmon_network_connection",
    source_label: "Sysmon network connection (Event ID 3)",
    observation_count: 1611,
    first_seen: "2024-03-22T11:21:41Z",
    last_seen: "2024-03-22T19:48:41Z",
    evidence_id: "ev-1",
    artifact_id: "art-1",
    ...overrides,
  };
}

function networkAddress(overrides: Partial<HostNetworkAddress> = {}): HostNetworkAddress {
  return {
    ip: "192.168.20.41",
    ip_version: 4,
    classification: "private",
    is_private: true,
    is_public: false,
    is_loopback: false,
    is_link_local: false,
    is_multicast: false,
    is_unspecified: false,
    first_seen: "2024-03-22T11:21:41Z",
    last_seen: "2024-03-22T19:48:41Z",
    observation_count: 1611,
    sources: [networkSource()],
    ...overrides,
  };
}

function networkResponse(addresses: HostNetworkAddress[]): CaseHostNetworkResponse {
  return { case_id: "case-1", host_id: "host-1", addresses };
}

function renderPage(path = "/cases/case-1/host-information") {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter initialEntries={[path]}>
      <QueryClientProvider client={queryClient}>
        <Routes>
          <Route path="/cases/:caseId/host-information" element={<HostInformationPage />} />
        </Routes>
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("HostInformationPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getCaseHostUsersMock.mockResolvedValue(usersResponse([]));
    getCaseHostNetworkMock.mockResolvedValue(networkResponse([]));
  });

  it("shows an empty state when the case has no identified hosts", async () => {
    useActiveCaseMock.mockReturnValue(activeCaseValue([]));
    renderPage();
    expect(await screen.findByTestId("no-hosts-state")).toBeInTheDocument();
    expect(getCaseHostFactsMock).not.toHaveBeenCalled();
  });

  it("prompts for a selection when a case has multiple hosts and none is chosen yet", async () => {
    useActiveCaseMock.mockReturnValue(activeCaseValue([host({ id: "host-1" }), host({ id: "host-2", display_name: "db-02" })]));
    renderPage();
    expect(await screen.findByTestId("no-host-selected-state")).toBeInTheDocument();
    expect(screen.getByTestId("host-selector")).toBeInTheDocument();
    expect(getCaseHostFactsMock).not.toHaveBeenCalled();
  });

  it("auto-selects the only host in a single-host case and fetches its facts exactly once", async () => {
    useActiveCaseMock.mockReturnValue(activeCaseValue([host()]));
    getCaseHostFactsMock.mockResolvedValue(factsResponse([]));
    renderPage();

    await waitFor(() => expect(getCaseHostFactsMock).toHaveBeenCalledTimes(1));
    expect(getCaseHostFactsMock).toHaveBeenCalledWith("case-1", { host_id: "host-1" });
    // No selector should be rendered when there is nothing to choose between.
    expect(screen.queryByTestId("host-selector")).not.toBeInTheDocument();
  });

  it("renders all four fact groups with their scoped labels", async () => {
    useActiveCaseMock.mockReturnValue(activeCaseValue([host()]));
    getCaseHostFactsMock.mockResolvedValue(factsResponse([]));
    renderPage();

    const groups = await screen.findByTestId("host-fact-groups");
    for (const label of ["Identity", "Operating System", "Platform", "Time"]) {
      expect(within(groups).getByText(label)).toBeInTheDocument();
    }
    for (const label of ["Hostname", "FQDN", "Distribution", "Version", "Kernel", "Architecture", "Timezone"]) {
      expect(within(groups).getByText(label)).toBeInTheDocument();
    }
  });

  it("renders a confirmed fact with its preferred value, status, and observation count", async () => {
    useActiveCaseMock.mockReturnValue(activeCaseValue([host()]));
    getCaseHostFactsMock.mockResolvedValue(
      factsResponse([
        {
          fact_type: "host.hostname",
          status: "confirmed",
          preferred_value: "webserver-01",
          supporting: [observation()],
          conflicting: [],
          invalid: [],
          observations: [observation()],
        },
      ]),
    );
    renderPage();

    const preferred = await screen.findByTestId("fact-preferred-value");
    expect(preferred).toHaveTextContent("webserver-01");
    const statusPills = screen.getAllByTestId("fact-status");
    expect(statusPills.some((el) => el.textContent === "Confirmed")).toBe(true);
    expect(screen.getAllByText("1 observation").length).toBeGreaterThan(0);
  });

  it("renders an unobserved fact as explicitly not collected, never fabricated", async () => {
    useActiveCaseMock.mockReturnValue(activeCaseValue([host()]));
    getCaseHostFactsMock.mockResolvedValue(factsResponse([]));
    renderPage();

    await screen.findByTestId("host-fact-groups");
    const missingValues = screen.getAllByTestId("fact-missing-value");
    expect(missingValues.length).toBe(7);
    for (const el of missingValues) expect(el).toHaveTextContent("Not collected");
    const statusPills = screen.getAllByTestId("fact-status");
    expect(statusPills.every((el) => el.textContent === "Not collected")).toBe(true);
  });

  it("shows conflicting observations as visually distinct groups, never merged", async () => {
    useActiveCaseMock.mockReturnValue(activeCaseValue([host()]));
    const supportingObs = observation({ id: "obs-support", raw_value: "webserver-01", normalized_value: "webserver-01" });
    const conflictingObs = observation({ id: "obs-conflict", raw_value: "old-hostname", normalized_value: "old-hostname", source_kind: "hostnamectl", status: "conflicting" });
    getCaseHostFactsMock.mockResolvedValue(
      factsResponse([
        {
          fact_type: "host.hostname",
          status: "conflicting",
          preferred_value: "webserver-01",
          supporting: [supportingObs],
          conflicting: [conflictingObs],
          invalid: [],
          observations: [supportingObs, conflictingObs],
        },
      ]),
    );
    renderPage();

    await screen.findByTestId("host-fact-groups");
    const statusPills = screen.getAllByTestId("fact-status");
    expect(statusPills.some((el) => el.textContent === "Conflicting")).toBe(true);

    await userEvent.click(screen.getByText("Show sources"));
    const observations = await screen.findAllByTestId("fact-observation");
    const supportingCards = observations.filter((el) => el.dataset.kind === "supporting");
    const conflictingCards = observations.filter((el) => el.dataset.kind === "conflicting");
    expect(supportingCards).toHaveLength(1);
    expect(conflictingCards).toHaveLength(1);
    expect(within(supportingCards[0]).getByText("webserver-01")).toBeInTheDocument();
    expect(within(conflictingCards[0]).getByText("old-hostname")).toBeInTheDocument();
  });

  it("builds provenance pivot links into Search and Artifact Views without inventing a new search engine", async () => {
    useActiveCaseMock.mockReturnValue(activeCaseValue([host()]));
    getCaseHostFactsMock.mockResolvedValue(
      factsResponse([
        {
          fact_type: "host.hostname",
          status: "confirmed",
          preferred_value: "webserver-01",
          supporting: [observation()],
          conflicting: [],
          invalid: [],
          observations: [observation()],
        },
      ]),
    );
    renderPage();

    const preferred = await screen.findByTestId("fact-preferred-value");
    expect(preferred).toHaveAttribute("href", "/cases/case-1/search?host_id=host-1&q=webserver-01");

    await userEvent.click(screen.getByText("Show sources"));
    const searchLink = await screen.findByTestId("pivot-search");
    expect(searchLink).toHaveAttribute("href", "/cases/case-1/search?host_id=host-1&q=webserver-01");
    const artifactLink = screen.getByTestId("pivot-artifact");
    expect(artifactLink).toHaveAttribute("href", "/cases/case-1/artifacts?q=%2Fetc%2Fhostname");
  });

  it("switches hosts through the selector, updates the URL, and fetches facts per host without duplicate requests", async () => {
    useActiveCaseMock.mockReturnValue(activeCaseValue([host({ id: "host-1", display_name: "webserver-01" }), host({ id: "host-2", display_name: "db-02" })]));
    getCaseHostFactsMock.mockResolvedValue(factsResponse([]));
    renderPage("/cases/case-1/host-information?host_id=host-1");

    await waitFor(() => expect(getCaseHostFactsMock).toHaveBeenCalledTimes(1));
    expect(getCaseHostFactsMock).toHaveBeenLastCalledWith("case-1", { host_id: "host-1" });

    await userEvent.selectOptions(screen.getByTestId("host-selector"), "host-2");
    await waitFor(() => expect(getCaseHostFactsMock).toHaveBeenCalledTimes(2));
    expect(getCaseHostFactsMock).toHaveBeenLastCalledWith("case-1", { host_id: "host-2" });

    // Switching back to a previously-fetched host must not re-issue the request --
    // React Query's cache is the mechanism satisfying "no duplicate API requests".
    await userEvent.selectOptions(screen.getByTestId("host-selector"), "host-1");
    await waitFor(() => expect(screen.getByRole("heading", { name: "webserver-01" })).toBeInTheDocument());
    expect(getCaseHostFactsMock).toHaveBeenCalledTimes(2);
  });

  describe("User Inventory", () => {
    beforeEach(() => {
      useActiveCaseMock.mockReturnValue(activeCaseValue([host()]));
      getCaseHostFactsMock.mockResolvedValue(factsResponse([]));
    });

    it("shows an empty state when no local accounts were identified", async () => {
      getCaseHostUsersMock.mockResolvedValue(usersResponse([]));
      renderPage();
      expect(await screen.findByTestId("user-inventory-empty")).toBeInTheDocument();
    });

    it("renders one row per user with identity fields, never duplicating an account", async () => {
      getCaseHostUsersMock.mockResolvedValue(usersResponse([
        userEntry({ username: "alice" }),
        userEntry({ username: "bob", identity: { ...userEntry().identity, uid: fieldResolution("uid", { preferred_value: "1001" }) } }),
      ]));
      renderPage();
      const rows = await screen.findAllByTestId("user-row");
      expect(rows).toHaveLength(2);
      expect(rows.map((row) => row.dataset.username)).toEqual(["alice", "bob"]);
    });

    it("shows an unresolved lastlog uid as a synthetic, non-fabricated entry", async () => {
      getCaseHostUsersMock.mockResolvedValue(usersResponse([userEntry({ username: "uid:1234", is_synthetic_username: true })]));
      renderPage();
      const row = await screen.findByTestId("user-row");
      expect(row).toHaveTextContent("uid:1234");
      expect(screen.queryByTestId("user-username-link")).not.toBeInTheDocument();
    });

    it("renders Not observed for last login when no lastlog record exists, never fabricating one", async () => {
      getCaseHostUsersMock.mockResolvedValue(usersResponse([userEntry({ last_login: null })]));
      renderPage();
      const lastLoginCell = await screen.findByTestId("user-last-login");
      expect(lastLoginCell).toHaveTextContent("Not observed");
    });

    it("renders a locked account with the Locked status pill", async () => {
      getCaseHostUsersMock.mockResolvedValue(usersResponse([
        userEntry({
          username: "backdoor",
          account_status: fieldResolution("account_status", { status: "observed", preferred_value: "locked" }),
          password_status: fieldResolution("password_status", { status: "observed", preferred_value: "locked" }),
        }),
      ]));
      renderPage();
      const statusPill = await screen.findByTestId("user-account-status");
      expect(statusPill).toHaveTextContent("Locked");
    });

    it("renders a disabled SAM account with the Disabled status pill", async () => {
      getCaseHostUsersMock.mockResolvedValue(usersResponse([
        userEntry({
          username: "Administrator",
          account_status: fieldResolution("account_status", { status: "observed", preferred_value: "disabled" }),
        }),
      ]));
      renderPage();
      const statusPill = await screen.findByTestId("user-account-status");
      expect(statusPill).toHaveTextContent("Disabled");
    });

    it("labels a Windows account's identifier as RID instead of UID, with no platform branch of its own", async () => {
      getCaseHostUsersMock.mockResolvedValue(usersResponse([
        userEntry({
          username: "bob",
          identity: {
            ...userEntry().identity,
            uid: fieldResolution("uid", { status: "observed", preferred_value: "1001" }),
            id_kind: fieldResolution("id_kind", { status: "observed", preferred_value: "rid" }),
            primary_gid: fieldResolution("primary_gid", { status: "missing" }),
            shell: fieldResolution("shell", { status: "missing" }),
          },
          attributes: {
            rid: fieldResolution("rid", { status: "observed", preferred_value: "1001" }),
            sid: fieldResolution("sid", { status: "observed", preferred_value: "S-1-5-21-1-2-3-1001" }),
          },
        }),
      ]));
      renderPage();
      const uidCell = await screen.findByTestId("user-uid");
      expect(uidCell).toHaveTextContent("1001");
      expect(uidCell).toHaveTextContent("RID");
      // Shell/Primary group are POSIX-only -- an all-Windows list must not
      // render those columns at all (never a fake "unknown" value).
      expect(screen.queryByTestId("user-shell")).not.toBeInTheDocument();
      expect(screen.queryByText("Primary group")).not.toBeInTheDocument();

      await userEvent.click(screen.getByTestId("user-expand-toggle"));
      const fieldDetails = await screen.findAllByTestId("user-field-detail");
      const ridDetail = fieldDetails.find((el) => el.dataset.field === "rid");
      const sidDetail = fieldDetails.find((el) => el.dataset.field === "sid");
      expect(ridDetail).toHaveTextContent("1001");
      expect(sidDetail).toHaveTextContent("S-1-5-21-1-2-3-1001");
    });

    it("expands to show secondary groups and per-field provenance, with conflicts surfaced not hidden", async () => {
      getCaseHostUsersMock.mockResolvedValue(usersResponse([
        userEntry({
          username: "alice",
          secondary_groups: [{ group_name: "sudo", gid: "27", observations: [userObservation()] }],
          identity: {
            ...userEntry().identity,
            uid: fieldResolution("uid", {
              status: "conflicting",
              preferred_value: "1000",
              observations: [userObservation({ id: "o1", source_path: "/etc/passwd" }), userObservation({ id: "o2", source_path: "/etc/passwd.bak" })],
            }),
          },
        }),
      ]));
      renderPage();
      await screen.findByTestId("user-row");
      expect(screen.getByText("Conflicting sources")).toBeInTheDocument();

      await userEvent.click(screen.getByTestId("user-expand-toggle"));
      expect(await screen.findByTestId("user-secondary-groups")).toHaveTextContent("sudo");
      const fieldDetails = screen.getAllByTestId("user-field-detail");
      const uidDetail = fieldDetails.find((el) => el.dataset.field === "uid");
      expect(uidDetail).toHaveAttribute("data-status", "conflicting");
      const observations = within(uidDetail!).getAllByTestId("user-observation");
      expect(observations).toHaveLength(2);
    });

    it("pivots the username into Search reusing existing Search infrastructure", async () => {
      getCaseHostUsersMock.mockResolvedValue(usersResponse([userEntry({ username: "alice" })]));
      renderPage();
      const link = await screen.findByTestId("user-username-link");
      expect(link).toHaveAttribute("href", "/cases/case-1/search?host_id=host-1&q=alice");
    });

    it("sorts by UID when the UID header is clicked", async () => {
      getCaseHostUsersMock.mockResolvedValue(usersResponse([
        userEntry({ username: "bob", identity: { ...userEntry().identity, uid: fieldResolution("uid", { preferred_value: "1001" }) } }),
        userEntry({ username: "alice", identity: { ...userEntry().identity, uid: fieldResolution("uid", { preferred_value: "1000" }) } }),
      ]));
      renderPage();
      await screen.findAllByTestId("user-row");
      // Default sort is by username: alice before bob.
      let rows = screen.getAllByTestId("user-row");
      expect(rows.map((row) => row.dataset.username)).toEqual(["alice", "bob"]);

      await userEvent.click(screen.getByTestId("user-sort-uid"));
      rows = screen.getAllByTestId("user-row");
      expect(rows.map((row) => row.dataset.username)).toEqual(["alice", "bob"]);

      await userEvent.click(screen.getByTestId("user-sort-uid"));
      rows = screen.getAllByTestId("user-row");
      expect(rows.map((row) => row.dataset.username)).toEqual(["bob", "alice"]);
    });

    it("filters users by the lightweight text filter without an extra API call", async () => {
      getCaseHostUsersMock.mockResolvedValue(usersResponse([userEntry({ username: "alice" }), userEntry({ username: "bob" })]));
      renderPage();
      await screen.findAllByTestId("user-row");
      await userEvent.type(screen.getByTestId("user-filter-input"), "ali");
      const rows = screen.getAllByTestId("user-row");
      expect(rows).toHaveLength(1);
      expect(rows[0].dataset.username).toBe("alice");
      expect(getCaseHostUsersMock).toHaveBeenCalledTimes(1);
    });

    it("refreshes the inventory when the host changes and never merges users across hosts", async () => {
      useActiveCaseMock.mockReturnValue(activeCaseValue([host({ id: "host-1", display_name: "webserver-01" }), host({ id: "host-2", display_name: "db-02" })]));
      getCaseHostUsersMock.mockImplementation((_caseId: string, params: { host_id?: string }) =>
        Promise.resolve(usersResponse([userEntry({ username: params.host_id === "host-1" ? "alice" : "carol" })])),
      );
      renderPage("/cases/case-1/host-information?host_id=host-1");
      expect(await screen.findByTestId("user-row")).toHaveTextContent("alice");

      await userEvent.selectOptions(screen.getByTestId("host-selector"), "host-2");
      await waitFor(() => expect(screen.getByTestId("user-row")).toHaveTextContent("carol"));
      expect(screen.queryByText("alice")).not.toBeInTheDocument();
    });
  });

  describe("Network", () => {
    beforeEach(() => {
      useActiveCaseMock.mockReturnValue(activeCaseValue([host()]));
      getCaseHostFactsMock.mockResolvedValue(factsResponse([]));
    });

    it("shows the shared honest empty state when no reliable network addresses were observed", async () => {
      getCaseHostNetworkMock.mockResolvedValue(networkResponse([]));
      renderPage();
      const emptyState = await screen.findByTestId("network-empty-state");
      expect(emptyState).toHaveTextContent("No reliable host network addresses were observed in the collected evidence.");
      expect(screen.queryByTestId("network-address-row")).not.toBeInTheDocument();
    });

    it("renders observed addresses most-recently-seen first with classification and observation count", async () => {
      getCaseHostNetworkMock.mockResolvedValue(
        networkResponse([
          networkAddress({ ip: "192.168.20.99", last_seen: "2024-06-01T00:00:00Z", observation_count: 5, classification: "private" }),
          networkAddress({ ip: "192.168.20.41", last_seen: "2024-01-01T00:00:00Z", observation_count: 1611, classification: "private" }),
        ]),
      );
      renderPage();
      const rows = await screen.findAllByTestId("network-address-row");
      expect(rows.map((row) => row.dataset.ip)).toEqual(["192.168.20.99", "192.168.20.41"]);
      expect(rows[0]).toHaveTextContent("Private");
      expect(rows[0]).toHaveTextContent("5 observations");
    });

    it("labels IPv4 and IPv6 addresses distinctly", async () => {
      getCaseHostNetworkMock.mockResolvedValue(
        networkResponse([
          networkAddress({ ip: "192.168.20.41", ip_version: 4 }),
          networkAddress({ ip: "fe80::35fe:fb89:feab:10ae", ip_version: 6, classification: "link-local", is_private: false, is_link_local: true, last_seen: "2024-01-01T00:00:00Z" }),
        ]),
      );
      renderPage();
      const rows = await screen.findAllByTestId("network-address-row");
      expect(rows.some((row) => within(row).queryByText("IPv4"))).toBe(true);
      expect(rows.some((row) => within(row).queryByText("IPv6"))).toBe(true);
      expect(screen.getByText("Link-local")).toBeInTheDocument();
    });

    it("classifies loopback distinctly from private, never showing it as the primary address type", async () => {
      getCaseHostNetworkMock.mockResolvedValue(networkResponse([networkAddress({ ip: "127.0.0.1", classification: "loopback", is_private: false, is_loopback: true })]));
      renderPage();
      const row = await screen.findByTestId("network-address-row");
      expect(row).toHaveAttribute("data-classification", "loopback");
      expect(within(row).getByTestId("network-address-classification")).toHaveTextContent("Loopback");
    });

    it("expands provenance to show every contributing source with its own observation count and time range", async () => {
      getCaseHostNetworkMock.mockResolvedValue(
        networkResponse([
          networkAddress({
            ip: "192.168.20.41",
            observation_count: 1611 + 79,
            sources: [
              networkSource({ source_kind: "sysmon_network_connection", source_label: "Sysmon network connection (Event ID 3)", observation_count: 1611 }),
              networkSource({ source_kind: "memory_windows_netscan", source_label: "Memory analysis (Volatility3 windows.netscan)", observation_count: 79, evidence_id: "ev-mem-1" }),
            ],
          }),
        ]),
      );
      renderPage();
      await screen.findByTestId("network-address-row");
      await userEvent.click(screen.getByText("Show sources"));
      const sources = await screen.findAllByTestId("network-observation-source");
      expect(sources).toHaveLength(2);
      expect(sources[0]).toHaveTextContent("Sysmon network connection (Event ID 3)");
      expect(sources[0]).toHaveTextContent("1611 observations");
      expect(sources[1]).toHaveTextContent("Memory analysis (Volatility3 windows.netscan)");
      expect(sources[1]).toHaveTextContent("79 observations");
    });

    it("pivots to the evidence a source came from", async () => {
      getCaseHostNetworkMock.mockResolvedValue(networkResponse([networkAddress({ sources: [networkSource({ evidence_id: "ev-42" })] })]));
      renderPage();
      await screen.findByTestId("network-address-row");
      await userEvent.click(screen.getByText("Show sources"));
      const link = await screen.findByTestId("network-source-evidence-link");
      expect(link).toHaveAttribute("href", "/evidences/ev-42");
    });

    it("fetches network observations scoped to the selected host, never merging across hosts", async () => {
      useActiveCaseMock.mockReturnValue(activeCaseValue([host({ id: "host-1", display_name: "webserver-01" }), host({ id: "host-2", display_name: "db-02" })]));
      getCaseHostNetworkMock.mockImplementation((_caseId: string, params: { host_id: string }) =>
        Promise.resolve(networkResponse(params.host_id === "host-1" ? [networkAddress({ ip: "192.168.20.41" })] : [networkAddress({ ip: "10.0.0.5" })])),
      );
      renderPage("/cases/case-1/host-information?host_id=host-1");
      expect(await screen.findByTestId("network-address-row")).toHaveTextContent("192.168.20.41");

      await userEvent.selectOptions(screen.getByTestId("host-selector"), "host-2");
      await waitFor(() => expect(screen.getByTestId("network-address-row")).toHaveTextContent("10.0.0.5"));
      expect(screen.queryByText("192.168.20.41")).not.toBeInTheDocument();
      expect(getCaseHostNetworkMock).toHaveBeenCalledWith("case-1", { host_id: "host-1" });
      expect(getCaseHostNetworkMock).toHaveBeenCalledWith("case-1", { host_id: "host-2" });
    });
  });
});
