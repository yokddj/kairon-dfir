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
