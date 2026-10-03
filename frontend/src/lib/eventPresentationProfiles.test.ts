import { describe, expect, it } from "vitest";
import { firstPresent, presentationProfileForItems, renderPresentationValue } from "./eventPresentationProfiles";

type Item = Record<string, unknown>;

const base = (type: string, extra: Item = {}): Item => ({
  id: `${type}-1`,
  "@timestamp": "2024-03-01T10:20:30Z",
  artifact: { type },
  event: { severity: "info", type: "x", message: "the log text" },
  message: "the log text",
  host: { name: "web01" },
  linux: {},
  ...extra,
});

const LINUX_TYPES = ["linux_syslog", "linux_journal", "linux_auth", "linux_audit", "linux_fail2ban", "linux_generic_log", "linux_persistence", "linux_k8s_audit", "linux_container", "linux_apache", "linux_exim"];

describe("Linux presentation profiles: selection", () => {
  it.each(LINUX_TYPES)("has a profile for %s", (type) => {
    expect(presentationProfileForItems([base(type)])).not.toBeNull();
  });

  it("has none for artifact types without one, and none when types are mixed", () => {
    expect(presentationProfileForItems([base("evtx")])).toBeNull();
    expect(presentationProfileForItems([base("linux_auth"), base("linux_syslog")])).toBeNull();
    expect(presentationProfileForItems([])).toBeNull();
  });

  it("picks the firewall layout once at least 30% of the syslog rows are packet logs", () => {
    const packet = base("linux_syslog", { linux: { firewall_action: "block" } });
    const plain = base("linux_syslog");
    const rows = (packets: number, total: number) => Array.from({ length: total }, (_, index) => (index < packets ? packet : plain));
    expect(presentationProfileForItems(rows(3, 10))?.id).toBe("linux_syslog_firewall");
    expect(presentationProfileForItems(rows(10, 10))?.id).toBe("linux_syslog_firewall");
    expect(presentationProfileForItems(rows(1, 1))?.id).toBe("linux_syslog_firewall");
    expect(presentationProfileForItems(rows(2, 10))?.id).toBe("linux_syslog");
    expect(presentationProfileForItems(rows(0, 10))?.id).toBe("linux_syslog");
  });

  it("picks the Sysmon layout when Sysmon events dominate, and the larger group wins over firewall rows", () => {
    const sysmon = base("linux_syslog", { linux: { sysmon_event_id: 1 } });
    const packet = base("linux_syslog", { linux: { firewall_action: "block" } });
    const plain = base("linux_syslog");
    expect(presentationProfileForItems([sysmon, sysmon, plain, plain])?.id).toBe("linux_syslog_sysmon");
    expect(presentationProfileForItems([sysmon, packet, packet, plain])?.id).toBe("linux_syslog_firewall");
    expect(presentationProfileForItems([sysmon, packet, plain, plain, plain, plain, plain, plain, plain, plain])?.id).toBe("linux_syslog");
  });

  it("distinguishes web error logs from access logs", () => {
    const error = base("linux_apache", { event: { type: "apache_error", message: "boom" } });
    expect(presentationProfileForItems([error])?.id).toBe("linux_web_error");
    expect(presentationProfileForItems([base("linux_apache", { event: { type: "apache_access", message: "GET / 200" } })])?.id).toBe("linux_web_access");
  });
});

describe("Linux presentation profiles: the message is never lost", () => {
  // The invariant is that the log's own text is on screen: through a column named message/summary,
  // or through a column whose value *is* that text (persistence's "Entry / Command").
  it.each(LINUX_TYPES.filter((type) => type !== "linux_apache"))("%s shows the log text by default", (type) => {
    const profile = presentationProfileForItems([base(type)])!;
    const carriesText = profile.columns.filter(
      (column) => column.defaultVisible !== false && !column.visibleWhen && (column.key === "message" || column.key === "summary" || column.paths.includes("message") || column.paths.includes("event.message")),
    );
    expect(carriesText.length, `${type} shows no column carrying the log text`).toBeGreaterThan(0);
  });

  it("offers the message on web access logs without showing it by default (its content is in other columns)", () => {
    const profile = presentationProfileForItems([base("linux_apache", { event: { type: "apache_access", message: "GET / 200" } })])!;
    const message = profile.columns.find((column) => column.key === "message");
    expect(message).toBeDefined();
    expect(message!.defaultVisible).toBe(false);
  });

  it("reads the original log line first, so a label in event.message does not hide it", () => {
    const profile = presentationProfileForItems([base("linux_auth")])!;
    const message = profile.columns.find((column) => column.key === "message")!;
    const item = base("linux_auth", {
      message: "Failed password for root from 203.0.113.9 port 51234 ssh2",
      event: { type: "login_failure", message: "SSH login failed" },
      title: "SSH login failed",
    });
    expect(renderPresentationValue(item, message)).toBe("Failed password for root from 203.0.113.9 port 51234 ssh2");
  });

  it("falls back to the raw excerpt when a row has no message at all", () => {
    const profile = presentationProfileForItems([base("linux_generic_log")])!;
    const message = profile.columns.find((column) => column.key === "message")!;
    expect(renderPresentationValue({ raw_excerpt: "2024-03-01 something odd" }, message)).toBe("2024-03-01 something odd");
  });

  it("the generic text log leads with its message among the visible columns", () => {
    const profile = presentationProfileForItems([base("linux_generic_log")])!;
    const visible = profile.columns.filter((column) => column.defaultVisible !== false && !column.visibleWhen).map((column) => column.key);
    expect(visible).toContain("message");
    expect(visible.indexOf("message")).toBeGreaterThan(visible.indexOf("severity"));
  });
});

describe("Linux presentation profiles: data-driven columns", () => {
  const visible = (profile: ReturnType<typeof presentationProfileForItems>, key: string) => profile!.columns.find((column) => column.key === key)!.defaultVisible;

  it("shows Time Quality only when some time is not exact", () => {
    const exact = base("linux_generic_log", { linux: { timestamp_status: "ok" } });
    const assumed = base("linux_generic_log", { linux: { timestamp_status: "assumed_utc" } });
    expect(visible(presentationProfileForItems([exact, exact]), "time_quality")).toBe(false);
    expect(visible(presentationProfileForItems([exact, assumed]), "time_quality")).toBe(true);
    expect(visible(presentationProfileForItems([base("linux_generic_log")]), "time_quality")).toBe(false);
  });

  it("explains each time quality in words", () => {
    const column = presentationProfileForItems([base("linux_generic_log")])!.columns.find((c) => c.key === "time_quality")!;
    expect(renderPresentationValue({ linux: { timestamp_status: "assumed_utc" } }, column)).toMatch(/Assumed UTC/);
    expect(renderPresentationValue({ linux: { timestamp_status: "assumed_year_utc" } }, column)).toMatch(/year/);
    expect(renderPresentationValue({ linux: { timestamp_status: "missing" } }, column)).toBe("No time in the log");
  });

  it("shows the real client column only when a row carries X-Forwarded-For", () => {
    const access = (extra: Item) => base("linux_apache", { event: { type: "apache_access", message: "GET / 200" }, ...extra });
    expect(visible(presentationProfileForItems([access({})]), "xff")).toBe(false);
    expect(visible(presentationProfileForItems([access({ linux: { x_forwarded_for: "198.51.100.77" } })]), "xff")).toBe(true);
  });

  it("keeps the apache columns the web profile started from", () => {
    const keys = presentationProfileForItems([base("linux_apache", { event: { type: "apache_access", message: "x" } })])!.columns.map((column) => column.key);
    expect(keys).toEqual(expect.arrayContaining(["timestamp", "source_ip", "http_method", "request", "http_status", "user_agent", "xff", "web_server"]));
  });
});

describe("Linux presentation profiles: values", () => {
  const column = (item: Item, key: string) => {
    const profile = presentationProfileForItems([item])!;
    return renderPresentationValue(item, profile.columns.find((c) => c.key === key)!);
  };

  it("firewall rows", () => {
    const item = base("linux_syslog", {
      linux: { firewall_action: "block", network_protocol: "tcp", interface_in: "eth0" },
      network: { source_ip: "203.0.113.9", source_port: 51234, destination_ip: "192.0.2.10", destination_port: 22 },
    });
    expect(["verdict", "protocol", "source_ip", "destination_ip", "destination_port", "interface_in"].map((key) => column(item, key))).toEqual(["block", "tcp", "203.0.113.9", "192.0.2.10", "22", "eth0"]);
  });

  it("journal rows show the unit and a user id when there is no name", () => {
    const item = base("linux_journal", { linux: { unit: "ssh.service", process: "sshd" }, user: { id: "1000" } });
    expect(column(item, "unit")).toBe("ssh.service");
    expect(column(item, "user")).toBe("1000");
  });

  it("Sysmon rows show the event, image, command line and parent", () => {
    const item = base("linux_syslog", {
      event: { type: "sysmon_process_created", code: "1", severity: "info", message: "Process created: curl http://203.0.113.9/x" },
      user: { name: "root" },
      process: { path: "/usr/bin/curl", command_line: "curl http://203.0.113.9/x", parent_path: "/bin/bash" },
      linux: { sysmon_event_id: 1 },
    });
    expect(column(item, "sysmon_event")).toBe("Process created");
    expect(["user", "exe", "command", "parent_image"].map((key) => column(item, key))).toEqual(["root", "/usr/bin/curl", "curl http://203.0.113.9/x", "/bin/bash"]);
    expect(column(item, "message")).toBe("the log text");
  });

  it("process is the plain name, so a pivot filters on what the cell says", () => {
    expect(column(base("linux_syslog", { linux: { process: "sshd", pid: 411 } }), "process")).toBe("sshd");
  });

  it("fail2ban actions read as words", () => {
    expect(column(base("linux_fail2ban", { linux: { event_action: "restore_ban" } }), "fail2ban_action")).toBe("Restore ban");
    expect(column(base("linux_fail2ban", { linux: { event_action: "ban", jail: "sshd" } }), "jail")).toBe("sshd");
  });

  it("Kubernetes audit rows show who did what to which object, with raw values a pivot can use", () => {
    const item = base("linux_k8s_audit", {
      user: { name: "alice" },
      network: { source_ip: "203.0.113.9" },
      http: { response: { status_code: 101 } },
      linux: { k8s_verb: "create", k8s_resource: "pods", k8s_subresource: "exec", k8s_namespace: "default", k8s_object: "web", k8s_decision: "allow", suspicious_indicators: ["pod_exec"] },
    });
    expect(["user", "verb", "resource", "subresource", "namespace", "object", "source_ip", "http_status", "decision", "indicators"].map((key) => column(item, key)))
      .toEqual(["alice", "create", "pods", "exec", "default", "web", "203.0.113.9", "101", "allow", "pod_exec"]);
  });

  it("container rows use the log layout, or the configuration layout when every row is configuration", () => {
    const log = base("linux_container", { event: { type: "container_log", message: "m" } });
    const config = base("linux_container", { event: { type: "container_config", message: "m" } });
    const host = base("linux_container", { event: { type: "container_hostconfig", message: "m" } });
    expect(presentationProfileForItems([log])?.id).toBe("linux_container_log");
    expect(presentationProfileForItems([config, host])?.id).toBe("linux_container_config");
    expect(presentationProfileForItems([config, log])?.id).toBe("linux_container_log");
  });

  it("container configuration shows image, state, flags and a privileged yes/no", () => {
    const item = base("linux_container", {
      event: { type: "container_config", message: "Container web" },
      linux: { container_name: "web", container_image: "nginx:1.25", container_state: "running", container_privileged: true, network_mode: "host", suspicious_indicators: ["privileged_container", "host_network"] },
    });
    expect(["container", "image", "state", "indicators", "privileged", "network_mode", "kind"].map((key) => column(item, key)))
      .toEqual(["web", "nginx:1.25", "running", "privileged_container, host_network", "yes", "host", "Container"]);
    expect(column(base("linux_container", { event: { type: "container_config", message: "m" }, linux: { container_privileged: false } }), "privileged")).toBe("no");
  });

  it("pod and namespace columns appear only for Kubernetes logs", () => {
    const vis = (items: Item[], key: string) => presentationProfileForItems(items)!.columns.find((c) => c.key === key)!.defaultVisible;
    const docker = base("linux_container", { event: { type: "container_log", message: "m" }, linux: { container_id: "abc" } });
    const cri = base("linux_container", { event: { type: "container_log", message: "m" }, linux: { k8s_pod: "web-1", k8s_namespace: "shop", container_name: "nginx" } });
    expect([vis([docker], "pod"), vis([docker], "namespace"), vis([cri], "pod"), vis([cri], "namespace")]).toEqual([false, false, true, true]);
  });

  it("the subresource column appears only when some request has one", () => {
    const col = (items: Item[]) => presentationProfileForItems(items)!.columns.find((c) => c.key === "subresource")!.defaultVisible;
    expect(col([base("linux_k8s_audit", { linux: { k8s_verb: "get" } })])).toBe(false);
    expect(col([base("linux_k8s_audit", { linux: { k8s_subresource: "exec" } })])).toBe(true);
  });

  it("persistence rows show the entry, kind, PAM rule and flags", () => {
    const item = base("linux_persistence", {
      event: { type: "ld_so_preload", message: "/dev/shm/.hook.so" },
      linux: { library_path: "/dev/shm/.hook.so", suspicious_indicators: ["preload_library", "unusual_preload_path"] },
    });
    expect(column(item, "kind")).toBe("Preloaded library");
    expect(column(item, "item")).toBe("/dev/shm/.hook.so");
    expect(column(item, "indicators")).toBe("preload_library, unusual_preload_path");
    const pam = base("linux_persistence", { event: { type: "pam_config", message: "auth sufficient pam_permit.so" }, linux: { pam_type: "auth", pam_control: "sufficient", pam_module: "pam_permit.so" } });
    expect(column(pam, "pam")).toBe("auth sufficient pam_permit.so");
  });

  it("firstPresent skips blanks and placeholders", () => {
    expect(firstPresent({ a: "", b: "-", c: "x" }, ["a", "b", "c"])).toBe("x");
  });
});
