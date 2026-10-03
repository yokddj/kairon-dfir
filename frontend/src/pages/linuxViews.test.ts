import { describe, expect, it } from "vitest";
import { addSyntaxTerm } from "./ArtifactExplorer";
import { summarizeResult } from "./Search";

describe("Explorer pivot: addSyntaxTerm", () => {
  it("starts a query when there is none, treating the wildcard placeholder as empty", () => {
    expect(addSyntaxTerm("", "verdict", "block", false)).toBe('verdict:"block"');
    expect(addSyntaxTerm("  ", "jail", "sshd", false)).toBe('jail:"sshd"');
    expect(addSyntaxTerm("*", "jail", "sshd", false)).toBe('jail:"sshd"');
  });

  it("narrows an existing query with AND, and excludes with NOT", () => {
    expect(addSyntaxTerm("ip:203.0.113.9", "verdict", "block", false)).toBe('ip:203.0.113.9 AND verdict:"block"');
    expect(addSyntaxTerm("ip:203.0.113.9", "verdict", "allow", true)).toBe('ip:203.0.113.9 AND NOT verdict:"allow"');
    expect(addSyntaxTerm("", "verdict", "allow", true)).toBe('NOT verdict:"allow"');
  });

  it("escapes quotes and backslashes so a value cannot break out of its term", () => {
    expect(addSyntaxTerm("", "exe", 'a"b', false)).toBe('exe:"a\\"b"');
    expect(addSyntaxTerm("", "exe", "C:\\tools\\x.exe", false)).toBe('exe:"C:\\\\tools\\\\x.exe"');
  });
});

type Result = Parameters<typeof summarizeResult>[0];
const result = (artifactType: string, raw: Record<string, unknown>, extra: Record<string, unknown> = {}): Result =>
  ({ id: "r1", artifact_type: artifactType, raw, title: "", summary: "", ...extra }) as unknown as Result;

describe("Search summary for Linux events", () => {
  it("uses the remote (source) address as the key entity on a Linux network event", () => {
    const summary = summarizeResult(result("linux_syslog", { network: { source_ip: "203.0.113.9", destination_ip: "192.0.2.10" }, event: { message: "[UFW BLOCK] ..." } }));
    expect(summary.primaryIp).toBe("203.0.113.9");
    expect(summary.keyEntity).toBe("203.0.113.9");
  });

  it("keeps preferring the destination for other artifacts", () => {
    const summary = summarizeResult(result("evtx", { network: { source_ip: "203.0.113.9", destination_ip: "192.0.2.10" }, event: { message: "connection" } }));
    expect(summary.primaryIp).toBe("192.0.2.10");
  });

  it("falls back to the destination when a Linux event has no source address", () => {
    expect(summarizeResult(result("linux_syslog", { network: { destination_ip: "192.0.2.10" } })).primaryIp).toBe("192.0.2.10");
  });

  it("keeps the original log line next to a label that replaced it", () => {
    const summary = summarizeResult(
      result(
        "linux_auth",
        { message: "Failed password for root from 203.0.113.9 port 51234 ssh2", event: { message: "SSH login failed" } },
        { summary: "SSH login failed" },
      ),
    );
    expect(summary.compactMessage).toBe("SSH login failed \u2014 Failed password for root from 203.0.113.9 port 51234 ssh2");
  });

  it("does not repeat a line the summary already contains", () => {
    const line = "[UFW BLOCK] IN=eth0 SRC=203.0.113.9 DST=192.0.2.10";
    expect(summarizeResult(result("linux_syslog", { message: line, event: { message: line } }, { summary: line })).compactMessage).toBe(line);
  });

  it("shows the original line when the summary is empty", () => {
    expect(summarizeResult(result("linux_generic_log", { message: "starting worker", event: {} })).compactMessage).toBe("starting worker");
  });

  it("leaves non-Linux summaries untouched", () => {
    const summary = summarizeResult(result("powershell", { message: "something else entirely", event: { message: "pipeline_execution" } }, { summary: "pipeline_execution" }));
    expect(summary.compactMessage).toBe("pipeline_execution");
  });
});
