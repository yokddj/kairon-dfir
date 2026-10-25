import { describe, expect, it } from "vitest";
import { buildMemoryFindingPrefill } from "./findingPrefill";

const context = { caseId: "case-1", evidenceId: "ev-1", hosts: [], sourceView: "memory", sourceRoute: "/cases/case-1/memory" };

describe("buildMemoryFindingPrefill", () => {
  it("names the indicator and process and takes Find Evil's priority", () => {
    const prefill = buildMemoryFindingPrefill("find_evil_indicator", {
      document_id: "doc-1", pid: 52, process_name: "WmiPrvSE.exe", indicator_type: "PROC_NOLINK", review_priority: "high",
      explanation: "Process missing from the kernel's active process list.", address: "0xffff988a4d6d60c0", sources: ["kairon.findevil"],
    }, context);
    expect(prefill.title).toBe("Memory: PROC_NOLINK in WmiPrvSE.exe (PID 52)");
    expect(prefill.severity).toBe("high");
    expect(prefill.linked_evidence_id).toBe("ev-1");
    expect(prefill.source_view).toBe("memory");
    expect(prefill.source_summary).toContain("Process missing");
    // A memory document is not an ingested artifact or a Search event.
    expect(prefill.linked_artifact_id).toBeNull();
    expect(prefill.linked_event_id).toBeNull();
    expect(prefill.event_ids).toEqual([]);
  });

  it("summarises a process's indicators", () => {
    const prefill = buildMemoryFindingPrefill("find_evil_process", {
      pid: 4012, process_name: "rundll32.exe", indicator_count: 3, top_priority: "medium",
      indicator_types: [{ value: "PE_INJECT", count: 2 }, { value: "PRIVATE_RWX", count: 1 }],
    }, context);
    expect(prefill.title).toBe("Memory: suspicious process rundll32.exe (PID 4012)");
    expect(prefill.severity).toBe("medium");
    expect(prefill.source_summary).toBe("3 Find Evil indicators: PE_INJECT, PRIVATE_RWX");
  });

  it("keeps the remote address of a connection", () => {
    const prefill = buildMemoryFindingPrefill("network", {
      pid: 900, process_name: "powershell.exe", protocol: "TCPv4", local_address: "10.0.0.5", local_port: 49712,
      remote_address: "203.0.113.7", remote_port: 443, state: "ESTABLISHED",
    }, context);
    expect(prefill.title).toBe("Memory: connection to 203.0.113.7:443 from powershell.exe (PID 900)");
    expect(prefill.related_ips).toEqual(["203.0.113.7"]);
  });
});
