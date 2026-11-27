import { describe, expect, it } from "vitest";

import type { Evidence, EvidenceRun, ProblematicArtifact } from "../api/client";
import { bucketProblems, deriveEvidenceView, liveProgress, processingStepForPhase } from "./evidenceStatus";

const NOW = Date.parse("2026-01-10T12:00:00Z");

function evidence(overrides: Partial<Evidence> = {}, metadata: Record<string, unknown> = {}): Evidence {
  return { id: "ev-1", case_id: "case-1", original_filename: "collection.zip", ingest_status: "completed", metadata_json: metadata, error_log: {}, ...overrides } as Evidence;
}

function run(overrides: Partial<EvidenceRun> = {}): EvidenceRun {
  return { run_id: "run-2", run_type: "reprocess", status: "running", ...overrides } as EvidenceRun;
}

function problem(status: string, overrides: Partial<ProblematicArtifact> = {}): ProblematicArtifact {
  return { artifact_id: `a-${status}`, name: `${status}.bin`, source_path: `/x/${status}`, artifact_type: "evtx_raw", parser: "evtx_raw", status, records_read: 0, records_indexed: 0, bulk_batches: 0, partial_data_indexed: false, data_loss_expected: false, retryable: false, importance: "normal", importance_reasons: [], ...overrides } as ProblematicArtifact;
}

describe("bucketProblems", () => {
  it("counts empty files as a note, never as warnings or failures", () => {
    const result = bucketProblems([problem("skipped_empty"), problem("completed_no_records"), problem("unsupported_no_records")]);
    expect(result).toEqual({ failures: [], warnings: [], emptyCount: 3 });
  });

  it("separates data loss from indexed-with-warning", () => {
    const failed = problem("failed", { data_loss_expected: true, retryable: true });
    const warned = problem("parsed_with_warning", { records_read: 10, records_indexed: 10 });
    const result = bucketProblems([failed, warned]);
    expect(result.failures).toEqual([failed]);
    expect(result.warnings).toEqual([warned]);
  });
});

describe("deriveEvidenceView", () => {
  it("is ready when indexed, whatever the backend display status says", () => {
    const view = deriveEvidenceView({ evidence: evidence({ display_status: "completed_with_warnings" }), runs: [], plan: undefined, indexedDocs: 5, nowMs: NOW });
    expect(view.state).toBe("ready");
  });

  it("ignores a run row stuck in running when nothing else is active", () => {
    const view = deriveEvidenceView({ evidence: evidence(), runs: [run()], plan: undefined, indexedDocs: 5, nowMs: NOW });
    expect(view.state).toBe("ready");
  });

  it("is processing while an on-demand job of the plan runs after ingest finished", () => {
    const view = deriveEvidenceView({ evidence: evidence(), runs: [], plan: { active: true } as never, indexedDocs: 5, nowMs: NOW });
    expect(view.state).toBe("processing");
  });

  it("is stalled when the worker has been silent past the watchdog limit", () => {
    const view = deriveEvidenceView({
      evidence: evidence({ ingest_status: "processing" }),
      runs: [run({ heartbeat_at: "2026-01-10T11:30:00Z" })],
      plan: undefined,
      indexedDocs: 0,
      nowMs: NOW,
    });
    expect(view.state).toBe("stalled");
  });

  it("asks for a selection when discovery found candidates and nothing runs", () => {
    const view = deriveEvidenceView({
      evidence: evidence({ ingest_status: "processing" }, { current_phase: "waiting_selection", velociraptor_discovery: { candidates: [{ id: "c1" }] } }),
      runs: [],
      plan: undefined,
      indexedDocs: 0,
      nowMs: NOW,
    });
    expect(view.state).toBe("needs_selection");
  });
});

describe("liveProgress", () => {
  it("never shows the previous run's elapsed time or totals", () => {
    const ev = evidence({ ingest_status: "processing" }, { current_ingest_run_id: "run-1", elapsed_seconds: 3720, started_at: "2026-01-10T10:00:00Z", artifacts_total: 300, artifacts_done: 300, progress_pct: 100 });
    const progress = liveProgress(ev, run({ started_at: "2026-01-10T11:59:00Z", artifacts_done: 129, artifacts_total: 0 }), NOW);
    expect(progress.elapsedSeconds).toBe(60);
    expect(progress.artifactsDone).toBe(129);
    expect(progress.artifactsTotal).toBeNull();
    expect(progress.percent).toBeNull();
  });

  it("reads zone-less backend timestamps as UTC", () => {
    const progress = liveProgress(evidence({ ingest_status: "processing" }), run({ started_at: "2026-01-10T11:58:00" }), NOW);
    expect(progress.elapsedSeconds).toBe(120);
  });

  it("shows a queued run without a percentage or elapsed time", () => {
    const progress = liveProgress(evidence({ ingest_status: "pending" }), run({ status: "queued", progress: 0 }), NOW);
    expect(progress).toMatchObject({ title: "Queued", percent: null, elapsedSeconds: null });
  });

  it("maps backend phases onto the four steps", () => {
    expect(processingStepForPhase("extracting_archive")).toBe("prepare");
    expect(processingStepForPhase("materializing_and_parsing")).toBe("parse");
    expect(processingStepForPhase("indexing_events")).toBe("index");
    expect(processingStepForPhase("matching_events")).toBe("finish");
  });
});
