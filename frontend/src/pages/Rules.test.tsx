import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import Rules from "./Rules";

const listCasesMock = vi.fn();
const getRuleEngineStatusMock = vi.fn();
const listRulesMock = vi.fn();
const listRuleSetsMock = vi.fn();
const listCaseRuleRunsMock = vi.fn();
const listDetectionsMock = vi.fn();
const importRuleFileMock = vi.fn();
const importRuleArchiveMock = vi.fn();
const listRuleImportsMock = vi.fn();
const getRuleImportMock = vi.fn();
const cancelRuleImportMock = vi.fn();
const toggleRuleMock = vi.fn();
const toggleRuleSetMock = vi.fn();
const runRuleMock = vi.fn();
const runRuleSetMock = vi.fn();
const runRulesForCaseMock = vi.fn();
const getRuleMock = vi.fn();
const getRuleSetMock = vi.fn();
const getCaseRuleRunMock = vi.fn();
const deleteRuleMock = vi.fn();
const deleteRuleSetMock = vi.fn();
const bulkUpdateRulesMock = vi.fn();
const bulkDeleteRulesMock = vi.fn();
const bulkDeleteRuleSetsMock = vi.fn();
const cancelRuleRunMock = vi.fn();
const markRuleRunStaleMock = vi.fn();
const retryRuleRunMock = vi.fn();
const deleteRuleRunMock = vi.fn();
const bulkCancelRuleRunsMock = vi.fn();
const bulkMarkStaleRuleRunsMock = vi.fn();
const markAbandonedRuleRunsStaleMock = vi.fn();
const bulkRetryRuleRunsMock = vi.fn();
const bulkDeleteRuleRunsMock = vi.fn();

vi.mock("../api/client", () => ({
  api: {
    listCases: (...args: unknown[]) => listCasesMock(...args),
    getRuleEngineStatus: (...args: unknown[]) => getRuleEngineStatusMock(...args),
    listRules: (...args: unknown[]) => listRulesMock(...args),
    listRuleSets: (...args: unknown[]) => listRuleSetsMock(...args),
    listCaseRuleRuns: (...args: unknown[]) => listCaseRuleRunsMock(...args),
    listDetections: (...args: unknown[]) => listDetectionsMock(...args),
    importRuleFile: (...args: unknown[]) => importRuleFileMock(...args),
    importRuleArchive: (...args: unknown[]) => importRuleArchiveMock(...args),
    listRuleImports: (...args: unknown[]) => listRuleImportsMock(...args),
    getRuleImport: (...args: unknown[]) => getRuleImportMock(...args),
    cancelRuleImport: (...args: unknown[]) => cancelRuleImportMock(...args),
    toggleRule: (...args: unknown[]) => toggleRuleMock(...args),
    toggleRuleSet: (...args: unknown[]) => toggleRuleSetMock(...args),
    runRule: (...args: unknown[]) => runRuleMock(...args),
    runRuleSet: (...args: unknown[]) => runRuleSetMock(...args),
    runRulesForCase: (...args: unknown[]) => runRulesForCaseMock(...args),
    getRule: (...args: unknown[]) => getRuleMock(...args),
    getRuleSet: (...args: unknown[]) => getRuleSetMock(...args),
    getCaseRuleRun: (...args: unknown[]) => getCaseRuleRunMock(...args),
    deleteRule: (...args: unknown[]) => deleteRuleMock(...args),
    deleteRuleSet: (...args: unknown[]) => deleteRuleSetMock(...args),
    bulkUpdateRules: (...args: unknown[]) => bulkUpdateRulesMock(...args),
    bulkDeleteRules: (...args: unknown[]) => bulkDeleteRulesMock(...args),
    bulkDeleteRuleSets: (...args: unknown[]) => bulkDeleteRuleSetsMock(...args),
    cancelRuleRun: (...args: unknown[]) => cancelRuleRunMock(...args),
    markRuleRunStale: (...args: unknown[]) => markRuleRunStaleMock(...args),
    retryRuleRun: (...args: unknown[]) => retryRuleRunMock(...args),
    deleteRuleRun: (...args: unknown[]) => deleteRuleRunMock(...args),
    bulkCancelRuleRuns: (...args: unknown[]) => bulkCancelRuleRunsMock(...args),
    bulkMarkStaleRuleRuns: (...args: unknown[]) => bulkMarkStaleRuleRunsMock(...args),
    markAbandonedRuleRunsStale: (...args: unknown[]) => markAbandonedRuleRunsStaleMock(...args),
    bulkRetryRuleRuns: (...args: unknown[]) => bulkRetryRuleRunsMock(...args),
    bulkDeleteRuleRuns: (...args: unknown[]) => bulkDeleteRuleRunsMock(...args),
  },
}));

vi.mock("../context/ActiveCaseContext", () => ({
  useActiveCase: () => ({
    activeCaseId: "case-1",
    selectedHost: "HOST-01",
    selectedEvidenceId: "ev-1",
  }),
}));

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={queryClient}>
        <Rules />
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("Rules", () => {
  beforeEach(() => {
    window.localStorage.clear();
    vi.spyOn(window, "confirm").mockReturnValue(true);
    listCasesMock.mockResolvedValue([{ id: "case-1", name: "Synthetic Case" }]);
    getRuleEngineStatusMock.mockResolvedValue({
      sigma: { available: true, runs_on: "indexed_events", supported: "basic Sigma subset" },
      heuristic: { available: true, runs_on: "indexed_events" },
      yara: { available: true, runs_on: "preserved_files" },
    });
    const allRules = [
        {
          id: "sigma-1",
          case_id: "case-1",
          rule_set_id: null,
          name: "Encoded PowerShell",
          title: "Encoded PowerShell",
          engine: "sigma",
          namespace: "builtin",
          source: "builtin",
          description: "Detects -EncodedCommand",
          author: "DFIR",
          rule_version: "2026-05-18",
          level: "high",
          content: "title: Encoded PowerShell",
          content_hash: "abc",
          enabled: true,
          severity: "high",
          status: "valid",
          references: [],
          false_positives: [],
          tags: ["attack.execution"],
          mitre: ["attack.execution"],
          validation_errors: [],
          metadata_json: { import_run_id: "import-1", source_pack: "sigma_all_rules.zip", last_import_status: "updated" },
          created_at: "2026-05-18T18:00:00Z",
          updated_at: "2026-05-18T18:00:00Z",
        },
        {
          id: "sigma-2",
          case_id: "case-1",
          rule_set_id: null,
          name: "Suspicious Rundll32",
          title: "Suspicious Rundll32",
          engine: "sigma",
          namespace: "builtin",
          source: "builtin",
          description: "Detects suspicious rundll32 usage",
          author: "DFIR",
          rule_version: "2026-05-18",
          level: "medium",
          content: "title: Suspicious Rundll32",
          content_hash: "ab2",
          enabled: false,
          severity: "medium",
          status: "valid",
          references: [],
          false_positives: [],
          tags: ["attack.execution"],
          mitre: ["attack.execution"],
          validation_errors: [],
          metadata_json: { import_run_id: "import-1", source_pack: "sigma_all_rules.zip", last_import_status: "duplicate" },
          created_at: "2026-05-18T18:00:00Z",
          updated_at: "2026-05-18T18:00:00Z",
        },
        {
          id: "yara-1",
          case_id: "case-1",
          rule_set_id: null,
          name: "MarkerRule",
          title: "MarkerRule",
          engine: "yara",
          namespace: "lab",
          source: "uploaded",
          description: "Marker YARA rule",
          author: "DFIR",
          rule_version: "2026-05-18",
          level: null,
          content: "rule MarkerRule { condition: true }",
          content_hash: "def",
          enabled: true,
          severity: "medium",
          status: "valid",
          references: [],
          false_positives: [],
          tags: [],
          mitre: [],
          validation_errors: [],
          metadata_json: {},
          created_at: "2026-05-18T18:00:00Z",
          updated_at: "2026-05-18T18:00:00Z",
        },
        {
          id: "heur-1",
          case_id: "case-1",
          rule_set_id: null,
          name: "Suspicious Office Child",
          title: "Suspicious Office Child",
          engine: "heuristic",
          namespace: "builtin",
          source: "builtin",
          description: "Heuristic rule",
          author: "DFIR",
          rule_version: "2026-05-18",
          level: null,
          content: "{}",
          content_hash: "ghi",
          enabled: true,
          severity: "medium",
          status: "valid",
          references: [],
          false_positives: [],
          tags: [],
          mitre: [],
          validation_errors: [],
          metadata_json: {},
          created_at: "2026-05-18T18:00:00Z",
          updated_at: "2026-05-18T18:00:00Z",
        },
      ];
    listRulesMock.mockImplementation((params?: { engine?: string; enabled?: boolean; page_size?: number }) => {
      let items = allRules;
      if (params?.engine) items = items.filter((rule) => rule.engine === params.engine);
      if (typeof params?.enabled === "boolean") items = items.filter((rule) => rule.enabled === params.enabled);
      const pageSize = params?.page_size ?? 250;
      return Promise.resolve({
        total: items.length,
        page: 1,
        page_size: pageSize,
        total_pages: items.length ? Math.ceil(items.length / pageSize) : 0,
        items: items.slice(0, pageSize),
      });
    });
    const allRuleSets = [
        {
          id: "pack-1",
          case_id: "case-1",
          name: "YARA Pack",
          engine: "yara",
          namespace: "pack",
          description: "pack",
          source_filename: "pack.zip",
          content_path: null,
          rules_count: 12,
          enabled: true,
          severity: "high",
          tags: [],
          metadata_json: { first_rules: ["MarkerRule"], import_run_id: "import-1", source_pack: "sigma_all_rules.zip", last_import_status: "imported" },
          created_at: "2026-05-18T18:00:00Z",
          updated_at: "2026-05-18T18:00:00Z",
        },
      ];
    listRuleSetsMock.mockImplementation((params?: { engine?: string; page_size?: number }) => {
      let items = allRuleSets;
      if (params?.engine) items = items.filter((ruleSet) => ruleSet.engine === params.engine);
      const pageSize = params?.page_size ?? 250;
      return Promise.resolve({
        total: items.length,
        page: 1,
        page_size: pageSize,
        total_pages: items.length ? Math.ceil(items.length / pageSize) : 0,
        items: items.slice(0, pageSize),
      });
    });
    listCaseRuleRunsMock.mockResolvedValue([
      {
        id: "run-1",
        case_id: "case-1",
        evidence_id: null,
        rule_id: "sigma-1",
        rule_set_id: null,
        engine: "sigma",
        status: "completed",
        scope: "case",
        matched: 7,
        total_rules: 1,
        processed_rules: 1,
        total_events: 42,
        scanned_events: 42,
        total_files: 0,
        created_detections: 3,
        duplicates: 1,
        scanned_files: 0,
        skipped_files: 0,
        current_phase: "completed",
        heartbeat_at: "2026-05-18T19:00:45Z",
        last_error: null,
        elapsed_seconds: 60,
        percent_complete: 100,
        stale: false,
        warnings: [],
        errors: [],
        metadata_json: {},
        started_at: "2026-05-18T19:00:00Z",
        finished_at: "2026-05-18T19:01:00Z",
        created_at: "2026-05-18T19:00:00Z",
        updated_at: "2026-05-18T19:01:00Z",
      },
      {
        id: "run-2",
        case_id: "case-1",
        evidence_id: "ev-1",
        rule_id: null,
        rule_set_id: "pack-1",
        engine: "yara",
        status: "stale",
        scope: "evidence",
        matched: 0,
        total_rules: 12,
        processed_rules: 3,
        total_events: 0,
        scanned_events: 0,
        total_files: 40,
        created_detections: 2,
        duplicates: 0,
        scanned_files: 21,
        skipped_files: 0,
        current_phase: "scanning_files",
        heartbeat_at: "2026-05-18T19:05:30Z",
        last_error: null,
        elapsed_seconds: 120,
        percent_complete: 52.5,
        stale: true,
        warnings: [],
        errors: [],
        metadata_json: {},
        started_at: "2026-05-18T19:05:00Z",
        finished_at: "2026-05-18T19:07:00Z",
        created_at: "2026-05-18T19:05:00Z",
        updated_at: "2026-05-18T19:07:00Z",
      },
    ]);
    listDetectionsMock.mockImplementation((_caseId: string, options?: { source?: string }) =>
      Promise.resolve({
        total: options?.source === "sigma" ? 4 : options?.source === "yara" ? 2 : 1,
        page: 1,
        page_size: 1,
        total_pages: 1,
        items: [],
      }),
    );
    importRuleFileMock.mockResolvedValue({ imported_rules: 1, imported_rule_sets: 0, total_yara_rules_inside: 0, skipped_count: 0, errors: [], sample_imported: ["rule"], detected_engine_counts: { sigma: 1 }, rules: [], rule_sets: [], imported_count: 1 });
    importRuleArchiveMock.mockResolvedValue({ import_run_id: "import-2", status: "completed_with_warnings", engine: "sigma", source_name: "sigma_all_rules.zip", source_type: "archive", pack_name: "sigma_all_rules", total_files: 3283, processed_files: 3283, total_rules_found: 3283, imported_rules: 3, imported_rule_sets: 0, total_yara_rules_inside: 0, skipped_count: 0, warnings: ["Some files were ignored because they are macOS metadata."], errors: [], invalid_items: [], unsupported_items: [{ file: "linux.yml", rule: "Linux rule", reason: "unsupported_condition" }], detected_engine_counts: { sigma: 3 }, sigma_rules_by_product: { windows: 3 }, sigma_rules_by_category: { process_creation: 2 }, compiled_count: 2, unsupported_condition_count: 1, compile_error_count: 0, invalid_count: 0, unsupported_count: 1, warning_count: 1, error_count: 0, updated_count: 1, duplicate_count: 2, sample_imported: ["rule-1"], rules: [], rule_sets: [], imported_count: 3 });
    listRuleImportsMock.mockResolvedValue({
      total: 1,
      items: [
        {
          id: "import-1",
          case_id: "case-1",
          engine: "sigma",
          source_name: "sigma_all_rules.zip",
          source_type: "archive",
          uploaded_filename: "sigma_all_rules.zip",
          pack_name: "sigma_all_rules",
          status: "completed_with_warnings",
          started_at: "2026-05-22T20:00:00Z",
          finished_at: "2026-05-22T20:01:00Z",
          cancelled_at: null,
          elapsed_seconds: 60,
          total_files: 3283,
          processed_files: 3283,
          total_rules_found: 3283,
          processed_rules: 3283,
          imported_count: 2500,
          updated_count: 300,
          duplicate_count: 200,
          skipped_count: 25,
          invalid_count: 8,
          compiled_count: 2500,
          unsupported_count: 50,
          warning_count: 2,
          error_count: 0,
          current_phase: "completed",
          current_file: null,
          last_error: null,
          cancel_requested: false,
          warnings_summary: ["Some files were ignored because they are macOS metadata."],
          errors_summary: [],
          created_rule_ids: [],
          updated_rule_ids: [],
          duplicate_rule_ids: [],
          invalid_items: [{ file: "broken.yml", reason: "invalid yaml" }],
          unsupported_items: [{ file: "linux.yml", rule: "Linux rule", reason: "unsupported_condition" }],
          import_options: { engine: "sigma" },
          details_json: {
            detected_engine_counts: { sigma: 3283 },
            sigma_rules_by_product: { windows: 3000 },
            sigma_rules_by_category: { process_creation: 1000 },
            sigma_engine_coverage_report: {
              executable_by_current_engine: 3233,
              not_executable_by_current_engine: 50,
              newly_supported_condition_1_of: 600,
              newly_supported_condition_all_of: 420,
              unsupported_by_feature: { unsupported_condition: 50 },
              examples_by_feature: { unsupported_condition: ["Linux rule"] },
            },
            pysigma_evaluation: { available: false, reason: "pySigma is not installed in this deployment." },
          },
          created_at: "2026-05-22T20:00:00Z",
          updated_at: "2026-05-22T20:01:00Z",
        },
      ],
    });
    getRuleImportMock.mockResolvedValue({
      id: "import-1",
      case_id: "case-1",
      engine: "sigma",
      source_name: "sigma_all_rules.zip",
      source_type: "archive",
      uploaded_filename: "sigma_all_rules.zip",
      pack_name: "sigma_all_rules",
      status: "completed_with_warnings",
      started_at: "2026-05-22T20:00:00Z",
      finished_at: "2026-05-22T20:01:00Z",
      cancelled_at: null,
      elapsed_seconds: 60,
      total_files: 3283,
      processed_files: 3283,
      total_rules_found: 3283,
      processed_rules: 3283,
      imported_count: 2500,
      updated_count: 300,
      duplicate_count: 200,
      skipped_count: 25,
      invalid_count: 8,
      compiled_count: 2500,
      unsupported_count: 50,
      warning_count: 2,
      error_count: 0,
      current_phase: "completed",
      current_file: null,
      last_error: null,
      cancel_requested: false,
      warnings_summary: ["Some files were ignored because they are macOS metadata."],
      errors_summary: [],
      created_rule_ids: [],
      updated_rule_ids: [],
      duplicate_rule_ids: [],
      invalid_items: [{ file: "broken.yml", reason: "invalid yaml" }],
      unsupported_items: [{ file: "linux.yml", rule: "Linux rule", reason: "unsupported_condition" }],
      import_options: { engine: "sigma" },
      details_json: {
        detected_engine_counts: { sigma: 3283 },
        sigma_rules_by_product: { windows: 3000 },
        sigma_rules_by_category: { process_creation: 1000 },
        sigma_engine_coverage_report: {
          executable_by_current_engine: 3233,
          not_executable_by_current_engine: 50,
          newly_supported_condition_1_of: 600,
          newly_supported_condition_all_of: 420,
          unsupported_by_feature: { unsupported_condition: 50 },
          examples_by_feature: { unsupported_condition: ["Linux rule"] },
        },
        pysigma_evaluation: { available: false, reason: "pySigma is not installed in this deployment." },
      },
      created_at: "2026-05-22T20:00:00Z",
      updated_at: "2026-05-22T20:01:00Z",
    });
    cancelRuleImportMock.mockResolvedValue({
      id: "import-active-1",
      case_id: "case-1",
      engine: "sigma",
      source_name: "sigma_all_rules.zip",
      source_type: "archive",
      uploaded_filename: "sigma_all_rules.zip",
      pack_name: "sigma_all_rules",
      status: "compiling",
      started_at: "2026-05-22T20:00:00Z",
      finished_at: null,
      cancelled_at: null,
      elapsed_seconds: null,
      total_files: 100,
      processed_files: 25,
      total_rules_found: 40,
      processed_rules: 18,
      imported_count: 12,
      updated_count: 2,
      duplicate_count: 4,
      skipped_count: 0,
      invalid_count: 1,
      compiled_count: 8,
      unsupported_count: 3,
      warning_count: 0,
      error_count: 0,
      current_phase: "compiling",
      current_file: "windows/process_creation/test.yml",
      last_error: null,
      cancel_requested: true,
      warnings_summary: [],
      errors_summary: [],
      created_rule_ids: [],
      updated_rule_ids: [],
      duplicate_rule_ids: [],
      invalid_items: [],
      unsupported_items: [],
      import_options: { engine: "sigma" },
      details_json: { detected_engine_counts: { sigma: 40 } },
      created_at: "2026-05-22T20:00:00Z",
      updated_at: "2026-05-22T20:00:20Z",
    });
    toggleRuleMock.mockResolvedValue({});
    toggleRuleSetMock.mockResolvedValue({});
    runRuleMock.mockResolvedValue({ engine: "yara", case_id: "case-1", matched: 0, created_detections: 0, duplicates: 0, skipped: false, error: null, status: "queued", rule_id: "yara-1", run_id: "run-yara-1" });
    runRuleSetMock.mockResolvedValue({ engine: "yara", case_id: "case-1", matched: 0, created_detections: 0, duplicates: 0, skipped: false, error: null, status: "queued", rule_set_id: "pack-1", run_id: "run-yara-2" });
    runRulesForCaseMock.mockResolvedValue({ accepted: true, run_id: "run-sigma-new", status: "queued", queued_rules: 1, message: "Queued 1 rules." });
    getRuleMock.mockResolvedValue({
      id: "sigma-1",
      case_id: "case-1",
      rule_set_id: null,
      name: "Encoded PowerShell",
      title: "Encoded PowerShell",
      engine: "sigma",
      namespace: "builtin",
      source: "builtin",
      description: "Detects -EncodedCommand",
      author: "DFIR",
      rule_version: "2026-05-18",
      level: "high",
      content: "title: Encoded PowerShell",
      content_hash: "abc",
      enabled: true,
      severity: "high",
      status: "valid",
      references: [],
      false_positives: [],
      tags: [],
      mitre: [],
      validation_errors: [],
      metadata_json: {
        condition: "1 of selection*",
        compile_status: "compiled",
        compile_version: "rules_v3",
        sigma_compilation: {
          expanded_condition_summary: {
            original: "1 of selection*",
            expanded: "(selection_a or selection_b)",
          },
        },
      },
      created_at: "2026-05-18T18:00:00Z",
      updated_at: "2026-05-18T18:00:00Z",
    });
    getRuleSetMock.mockResolvedValue({
      id: "pack-1",
      case_id: "case-1",
      name: "YARA Pack",
      engine: "yara",
      namespace: "pack",
      description: "pack",
      source_filename: "pack.zip",
      content_path: null,
      content: "rule MarkerRule { condition: true }",
      rules_count: 12,
      enabled: true,
      severity: "high",
      tags: [],
      metadata_json: { first_rules: ["MarkerRule"], description: "pack" },
      created_at: "2026-05-18T18:00:00Z",
      updated_at: "2026-05-18T18:00:00Z",
    });
    getCaseRuleRunMock.mockResolvedValue({
      id: "run-2",
      case_id: "case-1",
      evidence_id: "ev-1",
      rule_id: null,
      rule_set_id: "pack-1",
      engine: "yara",
      status: "stale",
      scope: "evidence",
      matched: 0,
      total_rules: 12,
      processed_rules: 3,
      total_events: 0,
      scanned_events: 0,
      total_files: 40,
      created_detections: 2,
      duplicates: 0,
      scanned_files: 21,
      skipped_files: 0,
      current_phase: "scanning_files",
      heartbeat_at: "2026-05-18T19:05:30Z",
      last_error: null,
      elapsed_seconds: 120,
      percent_complete: 52.5,
      stale: true,
      warnings: [],
      errors: [],
      metadata_json: {
        display_status: "completed_with_warnings",
        total_rules_considered: 3283,
        total_rules_runnable: 412,
        total_rules_executed: 412,
        total_rules_skipped: 2871,
        events_in_scope: 42,
        candidate_event_evaluations: 144,
        matches_found: 2,
        rules_runtime_error: 8,
        query_time_ms_total: 1200,
        dedupe_time_ms_total: 220,
        write_time_ms_total: 410,
        noisy_rules_count: 3,
        capped_rules_count: 2,
        skipped_too_broad_count: 1,
        matches_capped_count: 2,
        detections_capped_count: 2,
        sigma_run_mode: "fast_triage",
        current_rule_title: "Suspicious PowerShell",
        current_rule_matches: 75,
        current_rule_created: 12,
        current_rule_duplicates: 63,
        current_rule_duration_ms: 950,
        top_noisy_rules: [
          { rule_id: "sigma-1", rule_name: "Suspicious PowerShell", matches_found: 75, reason: "candidate estimate 12000 exceeds per-rule limit 5000" },
        ],
        candidate_events_prefiltered: 144,
        case_compatibility: {
          applicable_to_case: 412,
          skipped_platform: 2100,
          skipped_logsource: 500,
          skipped_missing_fields_in_case: 271,
          skipped_too_broad: 1,
          runtime_error: 8,
        },
        skipped_by_reason: {
          unsupported_platform: 2100,
          unsupported_logsource: 500,
          missing_fields: 271,
        },
      },
      started_at: "2026-05-18T19:05:00Z",
      finished_at: null,
      created_at: "2026-05-18T19:05:00Z",
      updated_at: "2026-05-18T19:07:00Z",
    });
    deleteRuleMock.mockResolvedValue(undefined);
    deleteRuleSetMock.mockResolvedValue(undefined);
    bulkUpdateRulesMock.mockResolvedValue({ matched: 1, updated: 1, enabled: false, skipped: 0, skipped_reasons: {}, errors: [] });
    bulkDeleteRulesMock.mockResolvedValue({ matched: 1, deleted: 1, disabled: 0, skipped: 0, skipped_reasons: {}, affected_packs: [], errors: [] });
    bulkDeleteRuleSetsMock.mockResolvedValue({ matched: 1, deleted: 1, disabled: 0, skipped: 0, skipped_reasons: {}, affected_packs: ["YARA Pack"], errors: [] });
    cancelRuleRunMock.mockResolvedValue({ ok: true, message: "Cancel requested. The worker will stop at the next checkpoint.", run: { id: "run-2" } });
    markRuleRunStaleMock.mockResolvedValue({ ok: true, message: "Run marked stale.", run: { id: "run-2" } });
    retryRuleRunMock.mockResolvedValue({ ok: true, message: "Retry queued as a new run.", run: { id: "run-3" } });
    deleteRuleRunMock.mockResolvedValue(undefined);
    bulkCancelRuleRunsMock.mockResolvedValue({ matched: 1, updated: 1, deleted: 0, skipped: 0, skipped_reasons: {}, created_run_ids: [], errors: [] });
    bulkMarkStaleRuleRunsMock.mockResolvedValue({ matched: 2, updated: 2, deleted: 0, skipped: 0, skipped_reasons: {}, created_run_ids: [], errors: [] });
    markAbandonedRuleRunsStaleMock.mockResolvedValue({ matched: 2, updated: 2, deleted: 0, skipped: 0, skipped_reasons: {}, created_run_ids: [], errors: [], warnings: [] });
    bulkRetryRuleRunsMock.mockResolvedValue({ matched: 1, updated: 1, deleted: 0, skipped: 0, skipped_reasons: {}, created_run_ids: ["run-3"], errors: [] });
    bulkDeleteRuleRunsMock.mockResolvedValue({ matched: 1, updated: 0, deleted: 1, skipped: 0, skipped_reasons: {}, created_run_ids: [], errors: [] });
  });

  it("shows Sigma, YARA, Heuristics, Rule Runs and Rule Library tabs", async () => {
    renderPage();
    expect(await screen.findByRole("button", { name: "Sigma" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "YARA" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Heuristics" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Rule Runs" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Rule Library" })).toBeInTheDocument();
  });

  it("shows scoped Sigma inventory without false zero scope confusion", async () => {
    renderPage();
    expect(await screen.findByText("Available Sigma rules")).toBeInTheDocument();
    expect(screen.getByText("Global Sigma rules")).toBeInTheDocument();
    expect(screen.getByText("Case Sigma rules")).toBeInTheDocument();
    expect(screen.getByText("Enabled Sigma rules")).toBeInTheDocument();
    await waitFor(() =>
      expect(listRulesMock).toHaveBeenCalledWith(
        expect.objectContaining({ engine: "sigma", page_size: 1 }),
      ),
    );
    await waitFor(() =>
      expect(listRulesMock).toHaveBeenCalledWith(
        expect.objectContaining({ engine: "sigma", enabled: true, page_size: 1 }),
      ),
    );
  });

  it("explains Sigma runs over indexed events and not files", async () => {
    renderPage();
    expect(await screen.findByText(/Run behavior rules against indexed events/i)).toBeInTheDocument();
    expect(screen.getByText(/Sigma scans indexed events\. It does not scan raw files\./i)).toBeInTheDocument();
  });

  it("explains YARA runs over preserved files and not indexed event logs", async () => {
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "YARA" }));
    expect(await screen.findByText(/Scan preserved files, scripts and documents/i)).toBeInTheDocument();
    expect(screen.getByText(/YARA scans preserved files, not indexed event logs\./i)).toBeInTheDocument();
  });

  it("shows engine-specific import buttons and hides ambiguous primary labels", async () => {
    renderPage();
    expect((await screen.findAllByText("Import Sigma rule")).length).toBeGreaterThan(0);
    expect(screen.getAllByText("Import Sigma rule pack").length).toBeGreaterThan(0);
    expect(screen.queryByText(/^Import rule file$/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/^Import rules archive$/i)).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "YARA" }));
    expect((await screen.findAllByText("Import YARA rule")).length).toBeGreaterThan(0);
    expect(screen.getAllByText("Import YARA rule pack").length).toBeGreaterThan(0);
  });

  it("shows YARA scan options only in the YARA tab", async () => {
    renderPage();
    expect(await screen.findByText(/Sigma scans indexed events/i)).toBeInTheDocument();
    expect(screen.queryByText(/Include parsed CSV\/JSON outputs/i)).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "YARA" }));
    expect(await screen.findByText(/Include parsed CSV\/JSON outputs/i)).toBeInTheDocument();
    expect(screen.getByText(/Include archives/i)).toBeInTheDocument();
  });

  it("shows Sigma run summary CTAs and filtered detections link", async () => {
    renderPage();
    const runButton = await screen.findByRole("button", { name: /Run Sigma on selected scope/i });
    fireEvent.click(runButton);
    await waitFor(() => expect(runRulesForCaseMock).toHaveBeenCalledWith("case-1", expect.objectContaining({ engine: "sigma" })));
    expect(await screen.findByText(/Sigma run summary/i)).toBeInTheDocument();
    const detectionsLink = screen.getByRole("link", { name: "Open Detections" });
    expect(detectionsLink.getAttribute("href")).toContain("/cases/case-1/detections?");
    expect(detectionsLink.getAttribute("href")).toContain("source=sigma");
    expect(detectionsLink.getAttribute("href")).toContain("rule_run_id=run-sigma-new");
    const sigmaSearchLinks = screen.getAllByRole("link", { name: "Search Sigma hits" });
    expect(sigmaSearchLinks.at(-1)?.getAttribute("href")).toContain("detection.source%3Asigma");
  });

  it("shows Sigma run mode selector and descriptions", async () => {
    renderPage();
    expect(await screen.findByLabelText("Sigma run mode")).toBeInTheDocument();
    expect(screen.getByText(/Recommended\. Runs compatible rules with safety limits\./i)).toBeInTheDocument();
    await userEvent.selectOptions(screen.getByLabelText("Sigma run mode"), "fast_triage");
    expect(screen.getByText(/Quick first pass\. Caps noisy rules and prioritizes signal\./i)).toBeInTheDocument();
    await userEvent.selectOptions(screen.getByLabelText("Sigma run mode"), "exhaustive");
    expect(screen.getByText(/Runs more broadly\. May take longer and create many detections\./i)).toBeInTheDocument();
  });

  it("requires confirmation for exhaustive Sigma runs and passes run mode", async () => {
    renderPage();
    await userEvent.selectOptions(await screen.findByLabelText("Sigma run mode"), "exhaustive");
    fireEvent.click(screen.getByRole("button", { name: /Run Sigma on selected scope/i }));
    expect(window.confirm).toHaveBeenCalledWith("Run Sigma in Exhaustive mode? This may take a long time and create many detections.");
    await waitFor(() =>
      expect(runRulesForCaseMock).toHaveBeenCalledWith("case-1", expect.objectContaining({ engine: "sigma", run_mode: "exhaustive" })),
    );
  });

  it("shows import summary, history and details for Sigma imports", async () => {
    renderPage();
    const file = new File(["title: test"], "test.zip", { type: "application/zip" });
    const archiveInputs = await screen.findAllByLabelText("Import Sigma rule pack");
    await userEvent.upload(archiveInputs[0], file);

    expect(await screen.findByText("Latest Sigma import")).toBeInTheDocument();
    expect(screen.getByText("Rule Imports")).toBeInTheDocument();
    expect((await screen.findAllByText("sigma_all_rules.zip")).length).toBeGreaterThan(0);
    expect(screen.getByText("completed_with_warnings")).toBeInTheDocument();
    expect(screen.getByText("Unsupported items: Linux rule")).toBeInTheDocument();

    await userEvent.click(screen.getAllByRole("button", { name: "Open import details" })[0]);
    expect(await screen.findByText("Rule import details")).toBeInTheDocument();
    expect(screen.getByText("Engine compatibility")).toBeInTheDocument();
    expect(screen.getByText("Coverage report")).toBeInTheDocument();
    expect(screen.getByText(/Not executable by current engine:/i)).toBeInTheDocument();
    expect(screen.getByText(/Supported by condition expansion:/i)).toBeInTheDocument();
    expect(screen.getByText("Invalid items")).toBeInTheDocument();
    expect(screen.getByText("Unsupported items")).toBeInTheDocument();
    expect(screen.getByText(/broken.yml/i)).toBeInTheDocument();
    expect(screen.getAllByText(/Linux rule/i).length).toBeGreaterThan(0);
  });

  it("shows a persistent active import banner with progress", async () => {
    listRuleImportsMock.mockResolvedValue({
      total: 1,
      items: [
        {
          id: "import-active-1",
          case_id: "case-1",
          engine: "sigma",
          source_name: "sigma_all_rules.zip",
          source_type: "archive",
          uploaded_filename: "sigma_all_rules.zip",
          pack_name: "sigma_all_rules",
          status: "parsing",
          started_at: "2026-05-22T20:00:00Z",
          finished_at: null,
          cancelled_at: null,
          elapsed_seconds: null,
          total_files: 100,
          processed_files: 25,
          total_rules_found: 40,
          processed_rules: 18,
          imported_count: 12,
          updated_count: 2,
          duplicate_count: 4,
          skipped_count: 0,
          invalid_count: 1,
          compiled_count: 8,
          unsupported_count: 3,
          warning_count: 0,
          error_count: 0,
          current_phase: "parsing",
          current_file: "windows/process_creation/test.yml",
          last_error: null,
          cancel_requested: false,
          warnings_summary: [],
          errors_summary: [],
          created_rule_ids: [],
          updated_rule_ids: [],
          duplicate_rule_ids: [],
          invalid_items: [],
          unsupported_items: [],
          import_options: { engine: "sigma" },
          details_json: { detected_engine_counts: { sigma: 40 } },
          created_at: "2026-05-22T20:00:00Z",
          updated_at: "2026-05-22T20:00:20Z",
        },
      ],
    });

    renderPage();

    expect(await screen.findByText("Active import")).toBeInTheDocument();
    expect(screen.getByText("Importing Sigma rule pack")).toBeInTheDocument();
    expect(screen.getByText(/25% · 25\/100 files/i)).toBeInTheDocument();
    expect(screen.getByText(/Current file: windows\/process_creation\/test.yml/i)).toBeInTheDocument();
  });

  it("shows cancel import for active imports and requests cancellation", async () => {
    const confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(true);
    listRuleImportsMock.mockResolvedValue({
      total: 1,
      items: [
        {
          id: "import-active-1",
          case_id: "case-1",
          engine: "sigma",
          source_name: "sigma_all_rules.zip",
          source_type: "archive",
          uploaded_filename: "sigma_all_rules.zip",
          pack_name: "sigma_all_rules",
          status: "compiling",
          started_at: "2026-05-22T20:00:00Z",
          finished_at: null,
          cancelled_at: null,
          elapsed_seconds: null,
          total_files: 100,
          processed_files: 25,
          total_rules_found: 40,
          processed_rules: 18,
          imported_count: 12,
          updated_count: 2,
          duplicate_count: 4,
          skipped_count: 0,
          invalid_count: 1,
          compiled_count: 8,
          unsupported_count: 3,
          warning_count: 0,
          error_count: 0,
          current_phase: "compiling",
          current_file: "windows/process_creation/test.yml",
          last_error: null,
          cancel_requested: false,
          warnings_summary: [],
          errors_summary: [],
          created_rule_ids: [],
          updated_rule_ids: [],
          duplicate_rule_ids: [],
          invalid_items: [],
          unsupported_items: [],
          import_options: { engine: "sigma" },
          details_json: { detected_engine_counts: { sigma: 40 } },
          created_at: "2026-05-22T20:00:00Z",
          updated_at: "2026-05-22T20:00:20Z",
        },
      ],
    });
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "Cancel import" }));
    await waitFor(() => expect(cancelRuleImportMock).toHaveBeenCalledWith("import-active-1"));
    confirmSpy.mockRestore();
  });

  it("keeps the active import banner visible after switching tabs and remounting Rules", async () => {
    listRuleImportsMock.mockResolvedValue({
      total: 1,
      items: [
        {
          id: "import-active-2",
          case_id: "case-1",
          engine: "sigma",
          source_name: "sigma_all_rules.zip",
          source_type: "archive",
          uploaded_filename: "sigma_all_rules.zip",
          pack_name: "sigma_all_rules",
          status: "compiling",
          started_at: "2026-05-22T20:00:00Z",
          finished_at: null,
          cancelled_at: null,
          elapsed_seconds: null,
          total_files: 200,
          processed_files: 100,
          total_rules_found: 120,
          processed_rules: 80,
          imported_count: 60,
          updated_count: 5,
          duplicate_count: 10,
          skipped_count: 0,
          invalid_count: 2,
          compiled_count: 58,
          unsupported_count: 3,
          warning_count: 0,
          error_count: 0,
          current_phase: "compiling",
          current_file: "windows/registry_set/test.yml",
          last_error: null,
          cancel_requested: false,
          warnings_summary: [],
          errors_summary: [],
          created_rule_ids: [],
          updated_rule_ids: [],
          duplicate_rule_ids: [],
          invalid_items: [],
          unsupported_items: [],
          import_options: { engine: "sigma" },
          details_json: { detected_engine_counts: { sigma: 120 } },
          created_at: "2026-05-22T20:00:00Z",
          updated_at: "2026-05-22T20:00:20Z",
        },
      ],
    });

    const firstRender = renderPage();
    expect(await screen.findByText("Active import")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "YARA" }));
    expect(screen.getByText("Active import")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Rule Library" }));
    expect(screen.getByText("Active import")).toBeInTheDocument();

    firstRender.unmount();
    renderPage();
    expect(await screen.findByText("Active import")).toBeInTheDocument();
  });

  it("allows dismissing a completed import banner while keeping history visible", async () => {
    renderPage();
    expect(await screen.findByText("Latest import")).toBeInTheDocument();
    expect(screen.getAllByText(/completed with warnings/i).length).toBeGreaterThan(0);
    await userEvent.click(screen.getByRole("button", { name: "Dismiss" }));
    await waitFor(() => expect(screen.queryByText("Latest import")).not.toBeInTheDocument());
    expect(screen.getByText("Rule Imports")).toBeInTheDocument();
    expect(screen.getAllByText("sigma_all_rules.zip").length).toBeGreaterThan(0);
  });

  it("can jump from import history to Rule Library filtered by import run", async () => {
    renderPage();
    expect(await screen.findByText("Rule Imports")).toBeInTheDocument();
    await userEvent.click((await screen.findAllByRole("button", { name: "View imported rules" }))[0]);
    expect(await screen.findByRole("button", { name: "Rule Library" })).toBeInTheDocument();
    expect(await screen.findByDisplayValue("sigma_all_rules.zip")).toBeInTheDocument();
    expect(screen.getByDisplayValue("sigma_all_rules")).toBeInTheDocument();
  });

  it("shows run history in Rule Runs tab", async () => {
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "Rule Runs" }));
    expect(await screen.findByText("run-1")).toBeInTheDocument();
    expect(screen.getByText("run-2")).toBeInTheDocument();
    expect(screen.getAllByText("Progress").length).toBeGreaterThan(0);
    expect(screen.getByText(/21 \/ 40 files/i)).toBeInTheDocument();
    expect(screen.getByText(/52.5%/i)).toBeInTheDocument();
    expect(screen.getByText(/No heartbeat for/i)).toBeInTheDocument();
    expect(screen.getAllByText(/^stale$/i).length).toBeGreaterThan(0);
  });

  it("opens rule run details from the Rule Runs tab", async () => {
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "Rule Runs" }));
    const detailButtons = await screen.findAllByRole("button", { name: "View run details" });
    await userEvent.click(detailButtons[1]);
    expect(await screen.findByRole("dialog", { name: "Rule run details" })).toBeInTheDocument();
    expect(await screen.findByText(/Engine:/i)).toBeInTheDocument();
    expect(screen.getByText(/Run mode:/i)).toBeInTheDocument();
    expect(screen.getByText(/Fast triage/i)).toBeInTheDocument();
    expect(screen.getByText(/Case compatibility/i)).toBeInTheDocument();
    expect(screen.getByText(/Skipped platform:/i)).toBeInTheDocument();
    expect(screen.getByText(/Scanned files:/i)).toBeInTheDocument();
    expect(screen.getByText(/Skipped too broad \/ matches capped \/ detections capped:/i)).toBeInTheDocument();
    expect(screen.getByText(/candidate estimate 12000 exceeds per-rule limit 5000/i)).toBeInTheDocument();
  });

  it("lists library items in Rule Library tab", async () => {
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "Rule Library" }));
    expect(await screen.findByText("Encoded PowerShell")).toBeInTheDocument();
    expect(screen.getByText("YARA Pack")).toBeInTheDocument();
    expect(screen.getByText("Suspicious Office Child")).toBeInTheDocument();
    expect(screen.getAllByText(/Import run: import-1/i).length).toBeGreaterThan(0);
  });

  it("shows expanded condition summary in rule details", async () => {
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "Rule Library" }));
    await userEvent.click((await screen.findAllByRole("button", { name: "View rule" }))[0]);
    expect(await screen.findByText(/Expanded condition summary:/i)).toBeInTheDocument();
    expect(screen.getByText(/\(selection_a or selection_b\)/i)).toBeInTheDocument();
    expect(screen.getAllByText((_, node) => node?.textContent?.includes("Compiler version: rules_v3") ?? false).length).toBeGreaterThan(0);
  });

  it("shows checkboxes and bulk delete confirmation in Rule Library", async () => {
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "Rule Library" }));
    await userEvent.click(await screen.findByRole("checkbox", { name: /Select rule Encoded PowerShell/i }));
    expect(screen.getByRole("button", { name: "Delete selected" })).toBeEnabled();
    await userEvent.click(screen.getByRole("button", { name: "Delete selected" }));
    expect(await screen.findByText(/Delete 1 selected rules\/packs\?/i)).toBeInTheDocument();
  });

  it("requires stronger confirmation before deleting all imported rules", async () => {
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "Rule Library" }));
    await userEvent.click(await screen.findByRole("button", { name: "Delete all imported rules" }));
    expect(await screen.findByText(/DELETE GLOBAL RULE LIBRARY/i)).toBeInTheDocument();
    const confirm = screen.getByRole("button", { name: "Confirm" });
    expect(confirm).toBeDisabled();
    const inputs = screen.getAllByRole("textbox");
    await userEvent.type(inputs.at(-1) as HTMLInputElement, "DELETE GLOBAL RULE LIBRARY");
    expect(confirm).toBeEnabled();
  });

  it("shows live import progress in details without false zero summaries", async () => {
    const activeRun = {
      id: "import-active-1",
      case_id: "case-1",
      engine: "sigma",
      source_name: "sigma_all_rules.zip",
      source_type: "archive",
      uploaded_filename: "sigma_all_rules.zip",
      pack_name: "sigma_all_rules",
      status: "saving",
      started_at: "2026-05-22T20:00:00Z",
      finished_at: null,
      cancelled_at: null,
      elapsed_seconds: 120,
      total_files: 3284,
      processed_files: 170,
      total_rules_found: 3283,
      processed_rules: 170,
      imported_count: 170,
      updated_count: 0,
      duplicate_count: 0,
      skipped_count: 0,
      invalid_count: 0,
      compiled_count: 150,
      unsupported_count: 2,
      warning_count: 0,
      error_count: 0,
      current_phase: "saving_rules",
      current_file: "rules/windows/process_creation/test.yml",
      last_error: null,
      cancel_requested: false,
      warnings_summary: [],
      errors_summary: [],
      created_rule_ids: [],
      updated_rule_ids: [],
      duplicate_rule_ids: [],
      invalid_items: [],
      unsupported_items: [],
      import_options: { engine: "sigma" },
      details_json: { detected_engine_counts: { sigma: 3283 } },
      progress_pct: 5.2,
      is_terminal: false,
      files_per_sec: null,
      rules_per_sec: null,
      created_at: "2026-05-22T20:00:00Z",
      updated_at: "2026-05-22T20:02:00Z",
    };
    listRuleImportsMock.mockResolvedValue({ total: 1, items: [activeRun] });
    getRuleImportMock.mockResolvedValue(activeRun);

    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "View details" }));

    expect(await screen.findByText(/Import still running/i)).toBeInTheDocument();
    expect(screen.getByText(/Rules discovered: 3283/i)).toBeInTheDocument();
    expect(screen.getByText(/Processed files: 170 \/ 3284/i)).toBeInTheDocument();
    expect(screen.getByText(/Progress: 5\.2%/i)).toBeInTheDocument();
    expect(screen.getAllByText(/Current file: rules\/windows\/process_creation\/test\.yml/i).length).toBeGreaterThan(0);
    expect(screen.getByText("Imported so far")).toBeInTheDocument();
    expect(screen.getByText(/Performance: Calculating/i)).toBeInTheDocument();
    expect(screen.queryByText(/Rules found: 0/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Processed files: 0\/0/i)).not.toBeInTheDocument();
  });

  it("shows terminal import details with final counts", async () => {
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "View details" }));
    expect((await screen.findAllByText("Imported")).length).toBeGreaterThan(0);
    expect(screen.getAllByText("2500").length).toBeGreaterThan(0);
    expect(screen.getByText(/Rules discovered: 3283/i)).toBeInTheDocument();
    expect(screen.getByText(/Processed files: 3283 \/ 3283/i)).toBeInTheDocument();
  });

  it("shows select all matching and selected count in Rule Library", async () => {
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "Rule Library" }));
    await userEvent.click(await screen.findByRole("button", { name: "Select all matching" }));
    expect(await screen.findByText(/All .* matching rules\/packs selected\./i)).toBeInTheDocument();
  });

  it("keeps heuristic rules visible while warning that built-ins are protected", async () => {
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "Rule Library" }));
    expect(await screen.findByText(/Built-in heuristic rules are protected/i)).toBeInTheDocument();
    expect(screen.getByText("Suspicious Office Child")).toBeInTheDocument();
  });

  it("shows run control actions for stale and running runs", async () => {
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "Rule Runs" }));
    expect(await screen.findByRole("button", { name: "Cancel run" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Mark failed/stale" })).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Retry run" }).length).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: "Mark abandoned runs stale" })).toBeInTheDocument();
  });

  it("shows a worker warning for old queued runs", async () => {
    listCaseRuleRunsMock.mockResolvedValueOnce([
      {
        id: "run-queued",
        case_id: "case-1",
        evidence_id: null,
        rule_id: null,
        rule_set_id: null,
        engine: "multi",
        status: "queued",
        scope: "case",
        matched: 0,
        total_rules: 3283,
        processed_rules: 0,
        total_events: 0,
        scanned_events: 0,
        total_files: 0,
        created_detections: 0,
        duplicates: 0,
        scanned_files: 0,
        skipped_files: 0,
        current_phase: "queued",
        heartbeat_at: null,
        last_error: null,
        elapsed_seconds: 1380,
        percent_complete: 0,
        stale: false,
        warnings: [],
        errors: [],
        metadata_json: {},
        started_at: null,
        finished_at: null,
        created_at: "2026-05-18T19:00:00Z",
        updated_at: "2026-05-18T19:00:00Z",
      },
    ]);

    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "Rule Runs" }));
    expect(await screen.findByText(/Rules worker may not be processing jobs/i)).toBeInTheDocument();
  });

  it("shows a scope warning when a completed run scanned zero indexed events", async () => {
    listCaseRuleRunsMock.mockResolvedValueOnce([
      {
        id: "run-empty",
        case_id: "case-1",
        evidence_id: null,
        rule_id: "sigma-1",
        rule_set_id: null,
        engine: "sigma",
        status: "completed",
        scope: "case",
        matched: 0,
        total_rules: 1,
        processed_rules: 0,
        total_events: 0,
        scanned_events: 0,
        total_files: 0,
        created_detections: 0,
        duplicates: 0,
        scanned_files: 0,
        skipped_files: 0,
        current_phase: "completed",
        heartbeat_at: "2026-05-18T19:00:45Z",
        last_error: null,
        elapsed_seconds: 5,
        percent_complete: 100,
        stale: false,
        warnings: ["Selected scope contains 0 indexed events"],
        errors: [],
        metadata_json: {},
        started_at: "2026-05-18T19:00:00Z",
        finished_at: "2026-05-18T19:00:05Z",
        created_at: "2026-05-18T19:00:00Z",
        updated_at: "2026-05-18T19:00:05Z",
      },
    ]);

    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "Rule Runs" }));
    expect(await screen.findByText(/No indexed events matched the selected scope/i)).toBeInTheDocument();
  });

  it("supports bulk run actions and run details metadata", async () => {
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: "Rule Runs" }));
    await userEvent.click(await screen.findByRole("checkbox", { name: /Select run run-2/i }));
    await userEvent.click(screen.getByRole("button", { name: "Cancel selected" }));
    await waitFor(() => expect(bulkCancelRuleRunsMock).toHaveBeenCalled());
    await userEvent.click(screen.getAllByRole("button", { name: "View run details" })[1]);
    expect(await screen.findByText(/Cancel requested:/i)).toBeInTheDocument();
    expect(screen.getByText(/Stale reason:/i)).toBeInTheDocument();
    expect(screen.getByText(/Considered \/ runnable:/i)).toBeInTheDocument();
    expect(screen.getByText(/Executed \/ skipped:/i)).toBeInTheDocument();
    expect(screen.getByText(/Events in scope:/i)).toBeInTheDocument();
    expect(screen.getByText(/Candidate evaluations:/i)).toBeInTheDocument();
    expect(screen.getByText(/Matches found:/i)).toBeInTheDocument();
    expect(screen.getByText(/Runtime errors:/i)).toBeInTheDocument();
    expect(screen.getByText(/Query \/ dedupe \/ write:/i)).toBeInTheDocument();
    expect(screen.getByText(/Noisy \/ capped rules:/i)).toBeInTheDocument();
    expect(screen.getByText(/Current rule/i)).toBeInTheDocument();
    expect(screen.getByText(/Top noisy rules/i)).toBeInTheDocument();
    expect(screen.getByText(/Some rules produced too many matches and were capped/i)).toBeInTheDocument();
    expect(screen.getByText(/unsupported_platform:/i)).toBeInTheDocument();
  });
});
