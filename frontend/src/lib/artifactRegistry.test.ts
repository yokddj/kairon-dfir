import { describe, expect, it } from "vitest";

import { artifactEventView, artifactLabel, artifactOptionsForPlatforms, canonicalArtifactView } from "./artifactRegistry";

describe("artifactRegistry", () => {
  it("resolves labels and aliases from the central registry", () => {
    expect(artifactLabel("windows_event")).toBe("Windows Events");
    expect(artifactLabel("registry_persistence")).toBe("Startup & Persistence");
    expect(canonicalArtifactView("appcompat")).toBe("shimcache");
  });

  it("resolves event views from the central registry", () => {
    expect(artifactEventView("linux_systemd")).toBe("persistence");
    expect(artifactEventView("linux_network")).toBe("network");
    expect(artifactEventView("mft")).toBe("filesystem");
  });

  it("returns linux platform shortcuts without unrelated families", () => {
    const linuxShortcuts = artifactOptionsForPlatforms(["linux"], { shortcutOnly: true });

    expect(linuxShortcuts).toContain("linux_journal");
    expect(linuxShortcuts).toContain("linux_systemd");
    expect(linuxShortcuts).not.toContain("browser");
  });
});
