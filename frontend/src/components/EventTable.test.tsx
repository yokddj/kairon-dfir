import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import EventTable from "./EventTable";

vi.mock("../context/TimezoneContext", () => ({
  useTimezonePreference: () => ({
    effectiveTimezone: "UTC",
  }),
}));

vi.mock("../lib/time", async () => {
  const actual = await vi.importActual<typeof import("../lib/time")>("../lib/time");
  return {
    ...actual,
    copyToClipboard: vi.fn(),
  };
});

describe("EventTable PowerShell view", () => {
  const longPayload = `{"EventData":{"Data":"UserId=KAIRON-LAB01\\\\analyst\\nHostApplication=C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\\nCommandLine=${"Write-Host demo ".repeat(40)}","Binary":""}}`;
  const rawUserBlob = "Level = Informational, HostName = ConsoleHost, HostVersion = 5.1, EngineVersion = 5.1";
  const rawKeyBlob = "ContextInfo=UserId=KAIRON-LAB01\\analyst\nHostApplication=powershell.exe\nCommandLine=Write-Host demo";
  const item = {
    id: "event-1",
    "@timestamp": "2026-06-06T16:16:23Z",
    artifact: { type: "powershell", parser: "powershell_evtx" },
    event: { severity: "low", type: "pipeline_execution", message: longPayload },
    host: { name: "Kairon-Lab01" },
    user: { name: rawUserBlob },
    key_entity: rawKeyBlob,
    display_user: "KAIRON-LAB01\\analyst",
    display_key_entity: "C:\\Users\\analyst\\Downloads\\03_lab.ps1",
    display_command: "powershell.exe -ExecutionPolicy Bypass -File C:\\Users\\analyst\\Downloads\\03_lab.ps1",
    display_snippet: "pipeline_execution: C:\\Users\\analyst\\Downloads\\03_lab.ps1",
    powershell_event_normalized: {
      user: "KAIRON-LAB01\\analyst",
      key_entity: "C:\\Users\\analyst\\Downloads\\03_lab.ps1",
      command: "powershell.exe -ExecutionPolicy Bypass -File C:\\Users\\analyst\\Downloads\\03_lab.ps1",
      raw_payload: { message: longPayload, raw_user: rawUserBlob, raw_key: rawKeyBlob },
    },
    powershell: {
      artifact_type: "powershell_evtx",
      command: "powershell.exe -ExecutionPolicy Bypass -File C:\\Users\\analyst\\Downloads\\03_lab.ps1",
      command_preview: "powershell.exe -ExecutionPolicy Bypass -File C:\\Users\\analyst\\Downloads\\03_lab.ps1",
      raw_payload: longPayload,
    },
    process: { name: "powershell.exe", command_line: "powershell.exe -File C:\\Users\\analyst\\Downloads\\03_lab.ps1" },
    tags: ["powershell"],
  };

  it("renders normalized user and useful key entity instead of placeholder payloads", () => {
    render(<EventTable items={[item]} view="powershell" />);

    expect(screen.getByText("KAIRON-LAB01\\analyst")).toBeInTheDocument();
    expect(screen.getByText("C:\\Users\\analyst\\Downloads\\03_lab.ps1")).toBeInTheDocument();
    expect(screen.queryByText("0x0")).not.toBeInTheDocument();
    expect(screen.queryByText(rawUserBlob)).not.toBeInTheDocument();
    expect(screen.queryByText(rawKeyBlob)).not.toBeInTheDocument();
  });

  it("keeps full raw payload in expanded details", () => {
    render(<EventTable items={[item]} view="powershell" />);

    fireEvent.click(screen.getByText("C:\\Users\\analyst\\Downloads\\03_lab.ps1"));

    expect(screen.getByText("Copy PowerShell command")).toBeInTheDocument();
    expect(screen.getByText("Copy key entity")).toBeInTheDocument();
    expect(screen.getByText("Raw JSON")).toBeInTheDocument();
    expect(screen.getAllByText(/HostVersion = 5\.1/).length).toBeGreaterThan(0);
  });
});

describe("EventTable network service-log profiles", () => {
  const apacheAccess = {
    id: "apache-access-1",
    case_id: "case-1",
    evidence_id: "ev-1",
    artifact_id: "art-apache",
    "@timestamp": "2024-10-10T13:55:36Z",
    title: "GET /jabc/scripts/update.php?cmd=ls 200",
    source_file: "volume-1/linux/var/log/apache2/access.log",
    artifact: { type: "linux_apache", family: "linux_apache", parser: "linux_apache_raw", source_path: "volume-1/linux/var/log/apache2/access.log", original_source_path: "/var/log/apache2/access.log" },
    event: { type: "apache_access", action: "GET", outcome: "success", severity: "info", message: "GET /jabc/scripts/update.php?cmd=ls 200" },
    host: { name: "web01" },
    network: { source_ip: "192.168.210.131" },
    http: { request: { method: "GET" }, response: { status_code: 200 } },
    url: { path: "/jabc/scripts/update.php?cmd=ls" },
    user_agent: { original: "Mozilla/5.0" },
    linux: { line_number: 4498, bytes_sent: 2326 },
  };

  const apacheError = {
    id: "apache-error-1",
    "@timestamp": "2024-10-10T13:55:37Z",
    title: "AH00094: Command line: '/usr/sbin/apache2'",
    source_file: "volume-1/linux/var/log/apache2/error.log",
    artifact: { type: "linux_apache", family: "linux_apache", parser: "linux_apache_raw" },
    event: { type: "apache_error", action: "apache_error", severity: "info", message: "AH00094: Command line: '/usr/sbin/apache2'" },
    host: { name: "web01" },
    linux: { line_number: 195, http_severity: "notice" },
  };

  const exim = {
    id: "exim-1",
    case_id: "case-2",
    evidence_id: "ev-2",
    artifact_id: "art-exim",
    "@timestamp": "2011-02-06T15:07:13Z",
    title: "1Pm5GZ-0000X2-Dc rejected from <root@local.com>",
    source_file: "volume-0/linux/var/log/exim4/mainlog",
    artifact: { type: "linux_exim", family: "linux_exim", parser: "linux_exim_raw", original_source_path: "/var/log/exim4/mainlog" },
    event: { type: "exim_main", action: "message_rejected", outcome: "failure", severity: "medium", message: "1Pm5GZ-0000X2-Dc rejected from <root@local.com>" },
    host: { name: "victoria" },
    network: { source_ip: "192.168.56.101" },
    email: { from: { address: "root@local.com" }, to: ["user@example.test"], message_id: "msg-1@example.test" },
    linux: { queue_id: "1Pm5GZ-0000X2-Dc", helo: "(abcde.com)", smtp_status: 550, line_number: 40 },
  };

  const malformedExim = {
    id: "exim-malformed-1",
    title: "not a timestamped exim line but still forensic content",
    source_file: "volume-0/linux/var/log/exim4/rejectlog",
    artifact: { type: "linux_exim", family: "linux_exim", parser: "linux_exim_raw" },
    event: { type: "exim_reject", action: "message_rejected", outcome: "failure", severity: "medium", message: "not a timestamped exim line but still forensic content" },
    host: { name: "victoria" },
    linux: { line_number: 7 },
  };

  it("shows Apache access source IP and explicit HTTP columns without confusing request and source file", () => {
    render(<EventTable items={[apacheAccess]} view="network" />);

    expect(screen.getByRole("columnheader", { name: /Source IP/i })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: /Method/i })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: /Request/i })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: /HTTP Status/i })).toBeInTheDocument();
    expect(screen.queryByRole("columnheader", { name: /Source File/i })).not.toBeInTheDocument();
    expect(screen.getByText("192.168.210.131")).toBeInTheDocument();
    expect(screen.getByText("/jabc/scripts/update.php?cmd=ls")).toBeInTheDocument();
    expect(screen.queryByText("volume-1/linux/var/log/apache2/access.log")).not.toBeInTheDocument();
  });

  it("renders Apache error records with message-oriented defaults", () => {
    render(<EventTable items={[apacheError]} view="network" />);

    expect(screen.getByRole("columnheader", { name: /Message/i })).toBeInTheDocument();
    expect(screen.getByText("Error")).toBeInTheDocument();
    expect(screen.getByText("AH00094: Command line: '/usr/sbin/apache2'")).toBeInTheDocument();
    expect(screen.queryByRole("columnheader", { name: /Method/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("columnheader", { name: /HTTP Status/i })).not.toBeInTheDocument();
  });

  it("shows Exim source IP, sender, recipient, outcome/status, and queue ID", () => {
    render(<EventTable items={[exim]} view="network" />);

    expect(screen.getByRole("columnheader", { name: /Remote IP/i })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: /Sender/i })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: /Recipient/i })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: /Outcome \/ SMTP/i })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: /Queue ID/i })).toBeInTheDocument();
    expect(screen.getByText("192.168.56.101")).toBeInTheDocument();
    expect(screen.getByText("root@local.com")).toBeInTheDocument();
    expect(screen.getByText("user@example.test")).toBeInTheDocument();
    expect(screen.getByText("550")).toBeInTheDocument();
    expect(screen.getByText("1Pm5GZ-0000X2-Dc")).toBeInTheDocument();
  });

  it("renders malformed Exim records with summary and provenance instead of invented values", () => {
    render(<EventTable items={[malformedExim]} view="network" />);

    expect(screen.getByText("not a timestamped exim line but still forensic content")).toBeInTheDocument();
    expect(screen.getAllByText("-").length).toBeGreaterThan(0);
    fireEvent.click(screen.getByText("not a timestamped exim line but still forensic content"));
    expect(screen.getByText("Provenance")).toBeInTheDocument();
    expect(screen.getByText("volume-0/linux/var/log/exim4/rejectlog")).toBeInTheDocument();
    expect(screen.getByText("Line number")).toBeInTheDocument();
    expect(screen.getByText("7")).toBeInTheDocument();
  });

  it("separates semantic details from provenance and keeps raw JSON available", () => {
    render(<EventTable items={[apacheAccess]} view="network" />);

    fireEvent.click(screen.getByText("192.168.210.131"));

    expect(screen.getByText("Event")).toBeInTheDocument();
    expect(screen.getByText("Network")).toBeInTheDocument();
    expect(screen.getByText("HTTP")).toBeInTheDocument();
    expect(screen.getByText("Provenance")).toBeInTheDocument();
    expect(screen.getByText("Source file")).toBeInTheDocument();
    expect(screen.getByText("volume-1/linux/var/log/apache2/access.log")).toBeInTheDocument();
    expect(screen.getByText("Raw JSON")).toBeInTheDocument();
  });

  it("keeps optional provenance columns available in the column selector", () => {
    render(<EventTable items={[exim]} view="network" />);

    fireEvent.click(screen.getByRole("button", { name: /Columns/i }));
    expect(screen.getByText("Source File")).toBeInTheDocument();
    expect(screen.getByText("Line Number")).toBeInTheDocument();
    fireEvent.click(screen.getByLabelText(/Source File/i));
    expect(screen.getByRole("columnheader", { name: /Source File/i })).toBeInTheDocument();
  });

  it("supports timestamp sorting in semantic profiles", () => {
    const later = { ...apacheAccess, id: "apache-later", "@timestamp": "2024-10-10T13:57:00Z", title: "GET /later 200", url: { path: "/later" } };
    const earlier = { ...apacheAccess, id: "apache-earlier", "@timestamp": "2024-10-10T13:50:00Z", title: "GET /earlier 200", url: { path: "/earlier" } };
    render(<EventTable items={[later, earlier]} view="network" />);

    fireEvent.click(screen.getByRole("button", { name: /Timestamp/i }));
    const rows = screen.getAllByRole("row");
    expect(rows[1]).toHaveTextContent("/earlier");
    fireEvent.click(screen.getByRole("button", { name: /Timestamp/i }));
    expect(screen.getAllByRole("row")[1]).toHaveTextContent("/later");
  });

  it("uses the existing generic network fallback for unknown artifact families", () => {
    render(<EventTable items={[{ id: "dns-1", artifact: { type: "linux_network" }, event: { category: "network", type: "dns" }, dns: { name: "example.test" }, network: { source_ip: "10.0.0.5" } }]} view="network" />);

    expect(screen.getByRole("columnheader", { name: /URL \/ Domain \/ IP/i })).toBeInTheDocument();
    expect(screen.getByText("example.test")).toBeInTheDocument();
  });
});
