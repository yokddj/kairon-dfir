/* Test the MemoryExperimentalResultsPanel component.
 *
 * The panel is intentionally separate from the validated
 * artefacts panel.  It carries a permanent warning banner,
 * per-row trust labels, and a single "Acknowledgement" gate
 * that the analyst must pass before a canary may start.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    getExperimentalTrust: vi.fn(),
    listExperimentalCandidates: vi.fn(),
    listExperimentalRuns: vi.fn(),
    getExperimentalWarning: vi.fn(),
    getExperimentalProfileCatalogue: vi.fn(),
    getExperimentalRun: vi.fn(),
    getExperimentalRunArtifacts: vi.fn(),
    createExperimentalRun: vi.fn(),
    acknowledgeExperimentalRun: vi.fn(),
    startExperimentalCanary: vi.fn(),
    continueExperimentalRun: vi.fn(),
    cancelExperimentalRun: vi.fn(),
    deleteExperimentalRun: vi.fn(),
  },
}));

vi.mock("../../api/client", () => ({
  api: apiMock,
}));

import { MemoryExperimentalResultsPanel } from "./MemoryExperimentalResultsPanel";

function renderWithClient() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <MemoryExperimentalResultsPanel caseId="c1" evidenceId="e1" />
    </QueryClientProvider>,
  );
}

describe("MemoryExperimentalResultsPanel", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    apiMock.getExperimentalTrust.mockResolvedValue({
      enabled: true,
      has_active_candidate: true,
      has_active_run: false,
      run_id: null,
      run_status: null,
      canary_status: null,
      last_completed_at: null,
    });
    apiMock.listExperimentalCandidates.mockResolvedValue({ items: [{
      id: "c-1",
      case_id: "c1",
      evidence_id: "e1",
      requirement_id: "r1",
      cached_symbol_id: "s1",
      required_identity: { pdb_name: "ntkrnlmp.pdb", pdb_guid: "D801A9AFC0FB7761380800F708633DEA", pdb_age: 1, architecture: "x64" },
      observed_identity: { pdb_name: "ntkrnlmp.pdb", pdb_guid: "D801A9AFC0FB7761380800F708633DEA", pdb_age: 5, architecture: "x64" },
      symbol_match_type: "guid_only_age_mismatch",
      symbol_warning: "mismatch",
      provenance_source_type: "operator_cli_experimental_pdb",
      provenance_source_name: "Operator CLI experimental PDB import",
      provenance_actor: "operator_cli:test",
      pdb_sha256: "0".repeat(64),
      isf_sha256: "1".repeat(64),
      isf_validation_status: "usable",
      created_at: null,
      revoked_at: null,
      revoked_by: null,
      revocation_reason: null,
    }] });
    apiMock.listExperimentalRuns.mockResolvedValue({ items: [] });
    apiMock.getExperimentalWarning.mockResolvedValue({
      warning_version: "experimental-mismatch-ack-v1",
      warning_text: "EXPERIMENTAL",
      checkbox_text: "I understand",
      required_fields: [],
    });
    apiMock.getExperimentalProfileCatalogue.mockResolvedValue({
      canary_profile: "experimental_canary",
      canary_plugins: ["windows.info"],
      profiles: [
        {
          profile: "experimental_metadata",
          family: "system_info",
          title: "Experimental metadata",
          description: "d",
          cost_label: "Fast",
          est_duration_seconds: 30,
          requires_canary_pass: true,
          plugins: ["windows.info"],
          supported_os_families: ["windows"],
        },
      ],
    });
  });

  it("renders the permanent warning banner when the feature is enabled", async () => {
    renderWithClient();
    const banner = await screen.findByTestId("memory-experimental-banner");
    expect(banner).toBeTruthy();
    expect(banner.textContent).toMatch(/Experimental \/ Untrusted/);
  });

  it("renders a disabled message when the feature is off", async () => {
    apiMock.getExperimentalTrust.mockResolvedValue({
      enabled: false,
      has_active_candidate: false,
      has_active_run: false,
      run_id: null,
      run_status: null,
      canary_status: null,
      last_completed_at: null,
    });
    renderWithClient();
    const disabled = await screen.findByTestId(
      "memory-experimental-panel-disabled",
    );
    expect(disabled).toBeTruthy();
  });

  it("stays hidden when there is no active candidate", async () => {
    apiMock.getExperimentalTrust.mockResolvedValue({
      enabled: true,
      has_active_candidate: false,
      has_active_run: false,
      run_id: null,
      run_status: null,
      canary_status: null,
      last_completed_at: null,
    });
    apiMock.listExperimentalCandidates.mockResolvedValue({ items: [] });
    renderWithClient();
    await waitFor(() => {
      expect(screen.queryByTestId("memory-experimental-panel")).toBeNull();
    });
  });

  it("shows the per-row trust labels on the canary checks", async () => {
    apiMock.listExperimentalRuns.mockResolvedValue({
      items: [
        {
          id: "r-1",
          case_id: "c1",
          evidence_id: "e1",
          candidate_id: "x",
          requirement_id: "y",
          cached_symbol_id: "z",
          status: "canary_passed",
          acknowledgement: {
            actor: "ops@example.com",
            actor_trust: "unauthenticated_client_label",
            acknowledged_at: "2024-01-01T00:00:00",
            warning_version: "v1",
            required_identity: {
              pdb_name: "ntkrnlmp.pdb",
              pdb_guid: "D801A9AFC0FB7761380800F708633DEA",
              pdb_age: 1,
              architecture: "x64",
            },
            observed_identity: {
              pdb_name: "ntkrnlmp.pdb",
              pdb_guid: "D801A9AFC0FB7761380800F708633DEA",
              pdb_age: 5,
              architecture: "x64",
            },
          },
          canary: {
            status: "passed",
            score: 0.9,
            checks: [
              { name: "layer_construction", status: "passed", detail: "ok", value: 1 },
            ],
            summary: {},
            started_at: null,
            completed_at: null,
            override_required: false,
            override_at: null,
            override_actor: null,
            override_reason: null,
          },
          requested_profiles: ["experimental_metadata"],
          canary_profiles: ["experimental_canary"],
          allowed_profiles: ["experimental_metadata"],
          canary_profile: "experimental_canary",
          canary_plugins: ["windows.info"],
          profiles_queued: 0,
          profiles_completed: 0,
          profiles_failed: 0,
          profiles_cancelled: 0,
          started_at: null,
          completed_at: null,
          cancelled_at: null,
          cancelled_by: null,
          cancellation_reason: null,
          deleted_at: null,
          deleted_by: null,
          deletion_reason: null,
          created_at: null,
          updated_at: null,
        },
      ],
    });
    apiMock.getExperimentalRun.mockResolvedValue({
      id: "r-1",
      case_id: "c1",
      evidence_id: "e1",
      candidate_id: "x",
      requirement_id: "y",
      cached_symbol_id: "z",
      status: "canary_passed",
      acknowledgement: {
        actor: "ops@example.com",
        actor_trust: "unauthenticated_client_label",
        acknowledged_at: "2024-01-01T00:00:00",
        warning_version: "v1",
        required_identity: {
          pdb_name: "ntkrnlmp.pdb",
          pdb_guid: "D801A9AFC0FB7761380800F708633DEA",
          pdb_age: 1,
          architecture: "x64",
        },
        observed_identity: {
          pdb_name: "ntkrnlmp.pdb",
          pdb_guid: "D801A9AFC0FB7761380800F708633DEA",
          pdb_age: 5,
          architecture: "x64",
        },
      },
      canary: {
        status: "passed",
        score: 0.9,
        checks: [
          { name: "layer_construction", status: "passed", detail: "ok", value: 1 },
        ],
        summary: {},
        started_at: null,
        completed_at: null,
        override_required: false,
        override_at: null,
        override_actor: null,
        override_reason: null,
      },
      requested_profiles: ["experimental_metadata"],
      canary_profiles: ["experimental_canary"],
      allowed_profiles: ["experimental_metadata"],
      canary_profile: "experimental_canary",
      canary_plugins: ["windows.info"],
      profiles_queued: 0,
      profiles_completed: 0,
      profiles_failed: 0,
      profiles_cancelled: 0,
      started_at: null,
      completed_at: null,
      cancelled_at: null,
      cancelled_by: null,
      cancellation_reason: null,
      deleted_at: null,
      deleted_by: null,
      deletion_reason: null,
      created_at: null,
      updated_at: null,
    });
    apiMock.getExperimentalRunArtifacts.mockResolvedValue({
      items: [],
      total: 0,
      page: 1,
      page_size: 50,
    });
    renderWithClient();
    const runButton = await screen.findByTestId("memory-experimental-run-button");
    fireEvent.click(runButton);
    await waitFor(() => {
      const checks = screen.queryAllByTestId("memory-experimental-canary-check");
      expect(checks.length).toBeGreaterThan(0);
    });
    const checks = screen.getAllByTestId("memory-experimental-canary-check");
    expect(checks[0].textContent).toMatch(/passed/);
  });
});
