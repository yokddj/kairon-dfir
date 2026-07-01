import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { MemoryArtifactList, MemoryProcessEntityDetail } from "../../api/client";
import { ProcessDetailModal } from "./ProcessDetailModal";

const getMemoryEnvVariablesMock = vi.fn();
const getMemorySidsMock = vi.fn();
const getMemoryPrivilegesMock = vi.fn();
const getMemoryNetworkConnectionsMock = vi.fn();
const getMemoryProcessModulesMock = vi.fn();
const getMemoryHandlesMock = vi.fn();
const getMemorySuspiciousRegionsMock = vi.fn();
const getMemoryVadsMock = vi.fn();

vi.mock("../../api/client", () => ({
  api: {
    getMemoryEnvVariables: (...args: unknown[]) => getMemoryEnvVariablesMock(...args),
    getMemorySids: (...args: unknown[]) => getMemorySidsMock(...args),
    getMemoryPrivileges: (...args: unknown[]) => getMemoryPrivilegesMock(...args),
    getMemoryNetworkConnections: (...args: unknown[]) => getMemoryNetworkConnectionsMock(...args),
    getMemoryProcessModules: (...args: unknown[]) => getMemoryProcessModulesMock(...args),
    getMemoryHandles: (...args: unknown[]) => getMemoryHandlesMock(...args),
    getMemorySuspiciousRegions: (...args: unknown[]) => getMemorySuspiciousRegionsMock(...args),
    getMemoryVads: (...args: unknown[]) => getMemoryVadsMock(...args),
  },
}));

function detailFixture(overrides: Partial<MemoryProcessEntityDetail> = {}): MemoryProcessEntityDetail {
  return {
    entity: {
      process_entity_id: "ent-system",
      document_type: "memory_process_entity" as const,
      case_id: "case-1",
      evidence_id: "ev-memory",
      scan_run_id: "run-basic",
      host_id: null,
      process: {
        pid: 4,
        ppid: 0,
        name: "System",
        executable_name: null,
        command_line: null,
        create_time: null,
        exit_time: null,
        session_id: null,
        wow64: null,
      },
      sources: ["windows.pslist"],
      source_plugins: ["windows.pslist"],
      observation_count: 1,
      observation_summary: {},
      visibility: { listed: true },
      confidence: "high" as const,
      first_seen_run_id: "run-basic",
      latest_run_id: "run-basic",
      findings: [],
      findings_summary: [],
      normalization_version: "memory_process_canonical_v1",
      materialized_from_run_id: null,
      parent_entity_id: null,
      child_count: 0,
      tree: { is_root: true },
      indexed_at: null,
    },
    observations: [],
    parent: null,
    children: [],
    tree_path: ["System (4)"],
    alternate_command_lines: [],
    findings: [],
    source_record_refs: ["ref-1"],
    ...overrides,
  };
}

function artifactListFixture(items: Array<Record<string, unknown> & { document_id: string }> = [], total?: number): MemoryArtifactList {
  return {
    document_type: "memory_artifact",
    selected_run: "run-basic",
    total: total ?? items.length,
    page: 1,
    page_size: 30,
    items,
    facets: {},
    normalization_version: "v1",
  };
}

function renderModal(
  overrides: Partial<{
    open: boolean; detail: MemoryProcessEntityDetail | null; isLoading: boolean; error: Error | null;
    caseId: string; evidenceId: string; runId: string | null;
  }> = {},
) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <ProcessDetailModal
        open={overrides.open ?? true}
        detail={overrides.detail ?? detailFixture()}
        isLoading={overrides.isLoading ?? false}
        error={overrides.error ?? null}
        caseId={overrides.caseId ?? "case-1"}
        evidenceId={overrides.evidenceId ?? "ev-memory"}
        runId={overrides.runId ?? "run-basic"}
        onClose={vi.fn()}
      />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("ProcessDetailModal", () => {
  describe("modal and overview", () => {
    it("renders selected process identity", async () => {
      renderModal();
      expect(await screen.findByTestId("process-detail-modal")).toBeInTheDocument();
      expect(screen.getByTestId("process-detail-modal-title")).toHaveTextContent("PID");
    });

    it("renders PID, name and visibility", async () => {
      const detail = detailFixture();
      renderModal({ detail });
      await screen.findByTestId("process-detail-modal");
      expect(screen.getByTestId("modal-visibility")).toHaveTextContent("Listed");
    });

    it("does not render HTML injection in process name", async () => {
      const detail = detailFixture({
        entity: {
          ...detailFixture().entity,
          process: { ...detailFixture().entity.process, name: "<script>alert(1)</script>" },
        },
      });
      renderModal({ detail });
      await screen.findByTestId("process-detail-modal");
      expect(screen.queryByText("<script>")).toBeNull();
    });

    it("calls onClose when close button clicked", async () => {
      const onClose = vi.fn();
      const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
      render(
        <QueryClientProvider client={queryClient}>
          <ProcessDetailModal
            open={true} detail={detailFixture()} isLoading={false} error={null}
            caseId="case-1" evidenceId="ev-memory" runId="run-basic" onClose={onClose}
          />
        </QueryClientProvider>,
      );
      await screen.findByTestId("process-detail-modal");
      fireEvent.click(screen.getByTestId("process-detail-modal-close"));
      expect(onClose).toHaveBeenCalled();
    });
  });

  describe("tabs", () => {
    it("renders all 13 tab buttons", async () => {
      renderModal();
      await screen.findByTestId("process-detail-modal-tab-overview");
      expect(screen.getByTestId("process-detail-modal-tab-command_line")).toBeInTheDocument();
      expect(screen.getByTestId("process-detail-modal-tab-environment")).toBeInTheDocument();
      expect(screen.getByTestId("process-detail-modal-tab-sids")).toBeInTheDocument();
      expect(screen.getByTestId("process-detail-modal-tab-privileges")).toBeInTheDocument();
      expect(screen.getByTestId("process-detail-modal-tab-network")).toBeInTheDocument();
      expect(screen.getByTestId("process-detail-modal-tab-modules")).toBeInTheDocument();
      expect(screen.getByTestId("process-detail-modal-tab-handles")).toBeInTheDocument();
      expect(screen.getByTestId("process-detail-modal-tab-suspicious")).toBeInTheDocument();
      expect(screen.getByTestId("process-detail-modal-tab-vads")).toBeInTheDocument();
      expect(screen.getByTestId("process-detail-modal-tab-relationships")).toBeInTheDocument();
      expect(screen.getByTestId("process-detail-modal-tab-observations")).toBeInTheDocument();
      expect(screen.getByTestId("process-detail-modal-tab-raw")).toBeInTheDocument();
    });

    it("defaults to overview tab", async () => {
      renderModal();
      await screen.findByTestId("process-detail-modal-tabpanel-overview");
    });

    it("switches to command_line tab on click", async () => {
      renderModal();
      await screen.findByTestId("process-detail-modal");
      fireEvent.click(screen.getByTestId("process-detail-modal-tab-command_line"));
      await screen.findByTestId("process-detail-modal-tabpanel-command-line");
    });
  });

  describe("command line", () => {
    it("renders canonical command line when present", async () => {
      const detail = detailFixture({
        entity: { ...detailFixture().entity, process: { ...detailFixture().entity.process, command_line: "C:\\Windows\\System32\\cmd.exe /c dir" } },
      });
      renderModal({ detail });
      await screen.findByTestId("process-detail-modal");
      fireEvent.click(screen.getByTestId("process-detail-modal-tab-command_line"));
      await screen.findByTestId("process-detail-modal-tabpanel-command-line");
      expect(screen.getByText("C:\\Windows\\System32\\cmd.exe /c dir")).toBeInTheDocument();
    });

    it("shows precise empty state when command line is missing", async () => {
      renderModal();
      await screen.findByTestId("process-detail-modal");
      fireEvent.click(screen.getByTestId("process-detail-modal-tab-command_line"));
      await screen.findByTestId("process-detail-modal-tabpanel-command-line");
      expect(screen.getByText(/No command-line observation recorded/i)).toBeInTheDocument();
    });
  });

  describe("environment", () => {
    it("does not fetch environment before tab selection", async () => {
      renderModal();
      await screen.findByTestId("process-detail-modal");
      expect(getMemoryEnvVariablesMock).not.toHaveBeenCalled();
    });

    it("triggers PID-scoped environment request on tab select", async () => {
      getMemoryEnvVariablesMock.mockResolvedValue(artifactListFixture([]));
      renderModal();
      await screen.findByTestId("process-detail-modal");
      fireEvent.click(screen.getByTestId("process-detail-modal-tab-environment"));
      await waitFor(() => expect(getMemoryEnvVariablesMock).toHaveBeenCalled());
      const call = getMemoryEnvVariablesMock.mock.calls[0];
      expect(call[0]).toBe("case-1");
      expect(call[1]).toMatchObject({ evidence_id: "ev-memory", run_id: "run-basic", pid: 4 });
    });

    it("renders environment variables and values", async () => {
      getMemoryEnvVariablesMock.mockResolvedValue(artifactListFixture([
        { document_id: "e1", variable: "PATH", value: "C:\\Windows\\system32", source_plugin: "windows.envars" },
        { document_id: "e2", variable: "TEMP", value: "C:\\Temp", source_plugin: "windows.envars" },
      ]));
      renderModal();
      await screen.findByTestId("process-detail-modal");
      fireEvent.click(screen.getByTestId("process-detail-modal-tab-environment"));
      await screen.findByText("PATH");
      expect(screen.getByText("C:\\Windows\\system32")).toBeInTheDocument();
      expect(screen.getByText("C:\\Temp")).toBeInTheDocument();
    });

    it("shows loading state", async () => {
      let resolveFn!: (val: MemoryArtifactList) => void;
      getMemoryEnvVariablesMock.mockReturnValue(new Promise((resolve) => { resolveFn = resolve; }));
      renderModal();
      await screen.findByTestId("process-detail-modal");
      fireEvent.click(screen.getByTestId("process-detail-modal-tab-environment"));
      await screen.findByText("Loading…");
      resolveFn(artifactListFixture([]));
      await waitFor(() => expect(screen.queryByText("Loading…")).not.toBeInTheDocument());
    });

    it("shows completed-empty state", async () => {
      getMemoryEnvVariablesMock.mockResolvedValue(artifactListFixture([]));
      renderModal();
      await screen.findByTestId("process-detail-modal");
      fireEvent.click(screen.getByTestId("process-detail-modal-tab-environment"));
      await screen.findByText(/completed but returned no rows/i);
    });

    it("shows error state", async () => {
      getMemoryEnvVariablesMock.mockRejectedValue(new Error("API error"));
      renderModal();
      await screen.findByTestId("process-detail-modal");
      fireEvent.click(screen.getByTestId("process-detail-modal-tab-environment"));
      await screen.findByText(/Failed to load environment/i);
    });
  });

  describe("SIDs", () => {
    it("lazy-loads SIDs on tab select", async () => {
      getMemorySidsMock.mockResolvedValue(artifactListFixture([
        { document_id: "s1", sid: "S-1-5-18", resolved_name: "NT AUTHORITY\\SYSTEM" },
      ]));
      renderModal();
      await screen.findByTestId("process-detail-modal");
      fireEvent.click(screen.getByTestId("process-detail-modal-tab-sids"));
      await screen.findByText("S-1-5-18");
      expect(screen.getByText("NT AUTHORITY\\SYSTEM")).toBeInTheDocument();
    });

    it("does not invent missing resolved name", async () => {
      getMemorySidsMock.mockResolvedValue(artifactListFixture([
        { document_id: "s1", sid: "S-1-5-123", resolved_name: null },
      ]));
      renderModal();
      await screen.findByTestId("process-detail-modal");
      fireEvent.click(screen.getByTestId("process-detail-modal-tab-sids"));
      await screen.findByText("S-1-5-123");
      expect(screen.getByText("—")).toBeInTheDocument();
    });

    it("shows completed-empty for getsids", async () => {
      getMemorySidsMock.mockResolvedValue(artifactListFixture([]));
      renderModal();
      await screen.findByTestId("process-detail-modal");
      fireEvent.click(screen.getByTestId("process-detail-modal-tab-sids"));
      await screen.findByText(/completed but returned no rows/i);
    });
  });

  describe("privileges", () => {
    it("lazy-loads privileges with state", async () => {
      getMemoryPrivilegesMock.mockResolvedValue(artifactListFixture([
        { document_id: "p1", privilege: "SeDebugPrivilege", enabled: true, description: "Debug programs" },
        { document_id: "p2", privilege: "SeShutdownPrivilege", enabled: false, description: "Shut down" },
      ]));
      renderModal();
      await screen.findByTestId("process-detail-modal");
      fireEvent.click(screen.getByTestId("process-detail-modal-tab-privileges"));
      await screen.findByText("SeDebugPrivilege");
      expect(screen.getByText("Enabled")).toBeInTheDocument();
      expect(screen.getByText("Disabled")).toBeInTheDocument();
    });

    it("filters enabled privileges", async () => {
      getMemoryPrivilegesMock.mockResolvedValue(artifactListFixture([
        { document_id: "p1", privilege: "SeAuditPrivilege", enabled: true },
      ]));
      renderModal();
      await screen.findByTestId("process-detail-modal");
      fireEvent.click(screen.getByTestId("process-detail-modal-tab-privileges"));
      await screen.findByText("Enabled only");
      // Checkbox exists
      const cb = screen.getByRole("checkbox");
      expect(cb).toBeInTheDocument();
      fireEvent.click(cb);
      await waitFor(() => expect(getMemoryPrivilegesMock).toHaveBeenCalledTimes(2));
      expect(getMemoryPrivilegesMock.mock.calls[1][1]).toMatchObject({ enabled: true });
    });
  });

  describe("network", () => {
    it("is PID scoped", async () => {
      getMemoryNetworkConnectionsMock.mockResolvedValue(artifactListFixture([
        { document_id: "n1", protocol: "TCP", local_address: "0.0.0.0", local_port: 445, remote_address: "0.0.0.0", remote_port: 0, state: "LISTENING", source_plugin: "windows.netscan" },
      ]));
      renderModal();
      await screen.findByTestId("process-detail-modal");
      fireEvent.click(screen.getByTestId("process-detail-modal-tab-network"));
      await screen.findByText("LISTENING");
      const call = getMemoryNetworkConnectionsMock.mock.calls[0];
      expect(call[1]).toMatchObject({ pid: 4, evidence_id: "ev-memory" });
    });

    it("distinguishes netscan from netstat", async () => {
      getMemoryNetworkConnectionsMock.mockResolvedValue(artifactListFixture([
        { document_id: "n1", protocol: "TCP", local_address: "0.0.0.0", local_port: 135, remote_address: "0.0.0.0", remote_port: 0, state: "LISTENING", source_plugin: "windows.netscan" },
        { document_id: "n2", protocol: "TCP", local_address: "0.0.0.0", local_port: 445, remote_address: "0.0.0.0", remote_port: 0, state: "LISTENING", source_plugin: "windows.netstat" },
      ]));
      renderModal();
      await screen.findByTestId("process-detail-modal");
      fireEvent.click(screen.getByTestId("process-detail-modal-tab-network"));
      await screen.findByText("netscan");
      expect(screen.getByText("netstat")).toBeInTheDocument();
    });

    it("shows completed-zero distinct from profile-not-run", async () => {
      getMemoryNetworkConnectionsMock.mockResolvedValue(artifactListFixture([]));
      renderModal();
      await screen.findByTestId("process-detail-modal");
      fireEvent.click(screen.getByTestId("process-detail-modal-tab-network"));
      await screen.findByText(/No network connections found/i);
    });
  });

  describe("modules", () => {
    it("lazy-loads and shows module details", async () => {
      getMemoryProcessModulesMock.mockResolvedValue(artifactListFixture([
        { document_id: "m1", module_name: "kernel32.dll", path: "C:\\Windows\\System32\\kernel32.dll", base_address: "0x7ffe0000", size: "700000", load_state: "loaded", source_plugin: "windows.dlllist" },
      ]));
      renderModal();
      await screen.findByTestId("process-detail-modal");
      fireEvent.click(screen.getByTestId("process-detail-modal-tab-modules"));
      await screen.findByText("kernel32.dll");
      expect(screen.getByText("dlllist")).toBeInTheDocument();
    });

    it("distinguishes dlllist from ldrmodules", async () => {
      getMemoryProcessModulesMock.mockResolvedValue(artifactListFixture([
        { document_id: "m1", module_name: "ntdll.dll", load_state: "loaded", source_plugin: "windows.dlllist" },
        { document_id: "m2", module_name: "ntdll.dll", load_state: "in_load", source_plugin: "windows.ldrmodules" },
      ]));
      renderModal();
      await screen.findByTestId("process-detail-modal");
      fireEvent.click(screen.getByTestId("process-detail-modal-tab-modules"));
      await screen.findByText("dlllist");
      expect(screen.getByText("ldrmodules")).toBeInTheDocument();
    });
  });

  describe("handles", () => {
    it("lazy-loads on tab select", async () => {
      getMemoryHandlesMock.mockResolvedValue(artifactListFixture([
        { document_id: "h1", handle_value: "0x4", object_type: "File", object_name: "\\Device\\HarddiskVolume1", granted_access: "0x120089" },
      ]));
      renderModal();
      await screen.findByTestId("process-detail-modal");
      expect(getMemoryHandlesMock).not.toHaveBeenCalled();
      fireEvent.click(screen.getByTestId("process-detail-modal-tab-handles"));
      await waitFor(() => expect(getMemoryHandlesMock).toHaveBeenCalledTimes(1));
      await screen.findByText("File");
      expect(screen.getByText("0x4")).toBeInTheDocument();
      expect(screen.getByText("0x120089")).toBeInTheDocument();
    });

    it("shows error without breaking other tabs", async () => {
      getMemoryHandlesMock.mockRejectedValue(new Error("handle error"));
      renderModal();
      await screen.findByTestId("process-detail-modal");
      fireEvent.click(screen.getByTestId("process-detail-modal-tab-handles"));
      await screen.findByText(/Failed to load handles/i);
      // Switching to another tab should still work
      fireEvent.click(screen.getByTestId("process-detail-modal-tab-overview"));
      await screen.findByTestId("process-detail-modal-tabpanel-overview");
    });
  });

  describe("suspicious memory", () => {
    it("renders malfind results as suspicious memory candidates", async () => {
      getMemorySuspiciousRegionsMock.mockResolvedValue(artifactListFixture([
        { document_id: "s1", process_name: "cmd.exe", start_address: "0x400000", end_address: "0x4fffff", protection: "PAGE_EXECUTE_READWRITE", tag: "VadS", source_plugin: "windows.malfind", review_status: "needs_review" },
      ]));
      renderModal();
      await screen.findByTestId("process-detail-modal");
      fireEvent.click(screen.getByTestId("process-detail-modal-tab-suspicious"));
      await screen.findByText("PAGE_EXECUTE_READWRITE");
      expect(screen.getByText("malfind")).toBeInTheDocument();
    });

    it("does not label as confirmed malware", async () => {
      getMemorySuspiciousRegionsMock.mockResolvedValue(artifactListFixture([
        { document_id: "s1", protection: "PAGE_EXECUTE_READWRITE", source_plugin: "windows.malfind" },
      ]));
      renderModal();
      await screen.findByTestId("process-detail-modal");
      fireEvent.click(screen.getByTestId("process-detail-modal-tab-suspicious"));
      await screen.findByText("malfind");
      // Title says "Suspicious memory regions" not "Malware"
      expect(screen.queryByText(/malware/i)).toBeNull();
    });
  });

  describe("VADs", () => {
    it("renders memory_vad results with VAD-specific fields", async () => {
      getMemoryVadsMock.mockResolvedValue(artifactListFixture([
        { document_id: "v1", start_address: "0x7ffe0000", end_address: "0x7ffeffff", protection: "PAGE_READONLY", tag: "VadS", commit_charge: 1, private_memory: true, file_object: "\\Windows\\System32\\kernel32.dll" },
      ]));
      renderModal();
      await screen.findByTestId("process-detail-modal");
      fireEvent.click(screen.getByTestId("process-detail-modal-tab-vads"));
      await waitFor(() => expect(getMemoryVadsMock).toHaveBeenCalled());
      await screen.findByText("0x7ffe0000");
      expect(screen.getByText("VadS")).toBeInTheDocument();
    });

    it("shows missing file_object as null", async () => {
      getMemoryVadsMock.mockResolvedValue(artifactListFixture([
        { document_id: "v2", start_address: "0x10000", end_address: "0x1ffff", protection: "PAGE_EXECUTE_READ", tag: "Vad ", commit_charge: 2, private_memory: false, file_object: null },
      ]));
      renderModal();
      await screen.findByTestId("process-detail-modal");
      fireEvent.click(screen.getByTestId("process-detail-modal-tab-vads"));
      await waitFor(() => expect(getMemoryVadsMock).toHaveBeenCalled());
      await screen.findByText("PAGE_EXECUTE_READ");
      expect(screen.getByText("Shared")).toBeInTheDocument();
    });

    it("asks separate API from malfind", async () => {
      getMemorySuspiciousRegionsMock.mockResolvedValue(artifactListFixture([
        { document_id: "s1", protection: "PAGE_EXECUTE_READWRITE", source_plugin: "windows.malfind" },
      ]));
      getMemoryVadsMock.mockResolvedValue(artifactListFixture([
        { document_id: "v1", protection: "PAGE_READONLY", tag: "VadS" },
      ]));
      renderModal();
      await screen.findByTestId("process-detail-modal");
      fireEvent.click(screen.getByTestId("process-detail-modal-tab-suspicious"));
      await screen.findByText("malfind");
      fireEvent.click(screen.getByTestId("process-detail-modal-tab-vads"));
      await screen.findByText("VadS");
      expect(getMemorySuspiciousRegionsMock).toHaveBeenCalledTimes(1);
      expect(getMemoryVadsMock).toHaveBeenCalledTimes(1);
    });
  });

  describe("relationships and provenance", () => {
    it("renders parent and children when present", async () => {
      const parentEntity = {
        ...detailFixture().entity,
        process_entity_id: "ent-parent",
        process: { pid: 0, ppid: 0, name: "Idle", command_line: null, create_time: null, exit_time: null },
        sources: ["windows.pstree"], source_plugins: ["windows.pstree"],
        observation_count: 0, observation_summary: {},
        visibility: {}, confidence: "low" as const,
        findings: [], findings_summary: [], tree: {},
      };
      const childEntity = {
        ...detailFixture().entity,
        process_entity_id: "ent-child",
        process: { pid: 300, ppid: 4, name: "svchost.exe", command_line: null, create_time: null, exit_time: null },
        sources: ["windows.pslist"], source_plugins: ["windows.pslist"],
        observation_count: 0, observation_summary: {},
        visibility: { listed: true }, confidence: "medium" as const,
        findings: [], findings_summary: [], tree: {},
      };
      const detail = detailFixture({ parent: parentEntity, children: [childEntity] });
      renderModal({ detail });
      await screen.findByTestId("process-detail-modal");
      fireEvent.click(screen.getByTestId("process-detail-modal-tab-relationships"));
      await screen.findByTestId("process-detail-modal-tabpanel-relationships");
      expect(screen.getByText(/svchost.exe/)).toBeInTheDocument();
    });

    it("shows raw references", async () => {
      const detail = detailFixture({ source_record_refs: ["obs-1", "obs-2"] });
      renderModal({ detail });
      await screen.findByTestId("process-detail-modal");
      fireEvent.click(screen.getByTestId("process-detail-modal-tab-raw"));
      await screen.findByText("obs-1");
      expect(screen.getByText("obs-2")).toBeInTheDocument();
    });

    it("shows observations table", async () => {
      const detail = detailFixture({
        observations: [{
          document_type: "memory_process_observation" as const,
          case_id: "case-1", evidence_id: "ev-memory", scan_run_id: "run-basic",
          process_entity_id: "ent-system", plugin_name: "windows.pslist",
          source_record_id: "0",
          observed: { pid: 4, ppid: 0, name: "System" },
          raw_status: "reported_by_plugin", source_fields: {}, confidence: "high" as const,
        }],
      });
      renderModal({ detail });
      await screen.findByTestId("process-detail-modal");
      fireEvent.click(screen.getByTestId("process-detail-modal-tab-observations"));
      // Check the observations tabpanel renders
      await screen.findByTestId("process-detail-modal-tabpanel-observations");
      // Observations tab renders a table with plugin column
      expect(screen.getByTestId("modal-observations-table")).toBeInTheDocument();
    });
  });

  describe("run context", () => {
    it("uses effective run in child API requests", async () => {
      getMemoryEnvVariablesMock.mockResolvedValue(artifactListFixture([]));
      renderModal({ runId: "run-extended" });
      await screen.findByTestId("process-detail-modal");
      fireEvent.click(screen.getByTestId("process-detail-modal-tab-environment"));
      await waitFor(() => expect(getMemoryEnvVariablesMock).toHaveBeenCalled());
      expect(getMemoryEnvVariablesMock.mock.calls[0][1]).toMatchObject({ run_id: "run-extended" });
    });

    it("does not eagerly fetch all tabs on modal open", async () => {
      renderModal();
      await screen.findByTestId("process-detail-modal");
      await new Promise((resolve) => setTimeout(resolve, 100));
      expect(getMemoryEnvVariablesMock).not.toHaveBeenCalled();
      expect(getMemorySidsMock).not.toHaveBeenCalled();
      expect(getMemoryPrivilegesMock).not.toHaveBeenCalled();
      expect(getMemoryNetworkConnectionsMock).not.toHaveBeenCalled();
      expect(getMemoryProcessModulesMock).not.toHaveBeenCalled();
      expect(getMemoryHandlesMock).not.toHaveBeenCalled();
      expect(getMemorySuspiciousRegionsMock).not.toHaveBeenCalled();
      expect(getMemoryVadsMock).not.toHaveBeenCalled();
    });
  });

  describe("query isolation", () => {
    it("uses different query keys for different PIDs", async () => {
      getMemoryEnvVariablesMock.mockResolvedValue(artifactListFixture([]));
      renderModal({ detail: detailFixture({ entity: { ...detailFixture().entity, process: { ...detailFixture().entity.process, pid: 999 } } }) });
      await screen.findByTestId("process-detail-modal");
      fireEvent.click(screen.getByTestId("process-detail-modal-tab-environment"));
      await waitFor(() => expect(getMemoryEnvVariablesMock).toHaveBeenCalled());
      expect(getMemoryEnvVariablesMock.mock.calls[0][1]).toMatchObject({ pid: 999 });
    });

    it("one failed query does not break other sections", async () => {
      getMemoryEnvVariablesMock.mockRejectedValue(new Error("env error"));
      getMemorySidsMock.mockResolvedValue(artifactListFixture([
        { document_id: "s1", sid: "S-1-5-18", resolved_name: "SYSTEM" },
      ]));
      renderModal();
      await screen.findByTestId("process-detail-modal");
      fireEvent.click(screen.getByTestId("process-detail-modal-tab-environment"));
      await screen.findByText(/Failed to load environment/i);
      fireEvent.click(screen.getByTestId("process-detail-modal-tab-sids"));
      await screen.findByText("S-1-5-18");
    });
  });
});
