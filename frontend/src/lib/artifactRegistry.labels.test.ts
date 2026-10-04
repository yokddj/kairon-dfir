import { describe, expect, it } from "vitest";

import { artifactLabel, artifactOptions } from "./artifactRegistry";

describe("artifact labels", () => {
  it("gives each artifact type of a Linux case its own name in the selector", () => {
    const types = ["network", "linux_network", "linux_ssh", "linux_auth", "linux_syslog", "linux_packages", "linux_identity", "linux_apache", "linux_database", "linux_generic_log", "linux_lastlog"];
    const labels = artifactOptions(types).map(artifactLabel);
    expect(new Set(labels).size).toBe(labels.length);
    expect(labels).toEqual(expect.arrayContaining(["Network", "Network Config", "SSH", "Auth Logs", "Syslog", "Packages", "Users & Groups"]));
  });

  it("does not repeat the platform in Linux labels", () => {
    for (const type of ["linux_auth", "linux_syslog", "linux_cron", "linux_journal", "linux_shell_history", "linux_packages"]) {
      expect(artifactLabel(type)).not.toMatch(/^Linux /);
    }
  });
});
