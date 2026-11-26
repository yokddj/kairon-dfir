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
    expect(artifactEventView("linux_apache")).toBe("network");
    expect(artifactEventView("linux_exim")).toBe("network");
    expect(artifactEventView("mft")).toBe("mft");
    expect(artifactEventView("ntfs")).toBe("filesystem");
    expect(artifactEventView("usn")).toBe("filesystem");
  });

  it("returns linux platform shortcuts without unrelated families", () => {
    const linuxShortcuts = artifactOptionsForPlatforms(["linux"], { shortcutOnly: true });

    expect(linuxShortcuts).toContain("linux_journal");
    expect(linuxShortcuts).toContain("linux_apache");
    expect(linuxShortcuts).toContain("linux_exim");
    expect(linuxShortcuts).toContain("linux_systemd");
    expect(linuxShortcuts).not.toContain("browser");
  });

  it("returns macOS shortcuts: its own families and the Unix ones it shares with Linux", () => {
    const macosShortcuts = artifactOptionsForPlatforms(["macos"], { shortcutOnly: true });

    expect(macosShortcuts).toContain("macos_launchd");
    expect(macosShortcuts).toContain("macos_knowledgec");
    expect(macosShortcuts).toContain("linux_shell_history");
    expect(macosShortcuts).toContain("uac_live_response");
    expect(macosShortcuts).not.toContain("linux_journal");
    expect(artifactEventView("launch_daemon")).toBe("persistence");
    expect(artifactLabel("macos_tcc")).toBe("TCC privacy permissions");
  });
});
