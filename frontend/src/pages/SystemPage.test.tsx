import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import SystemPage from "./SystemPage";

const getAdminPerformanceMock = vi.fn();
const getAdminPerformanceRecommendationMock = vi.fn();
const updateAdminPerformanceMock = vi.fn();
const applyAdminPerformanceMock = vi.fn();
const applyAdminPerformanceProfileMock = vi.fn();
const applyAdminPerformanceRecommendedMock = vi.fn();
const getSystemVersionMock = vi.fn();

vi.mock("../api/client", () => ({
  API_BASE_URL: "http://127.0.0.1:8000/api",
  api: {
    getAdminPerformance: (...args: unknown[]) => getAdminPerformanceMock(...args),
    getAdminPerformanceRecommendation: (...args: unknown[]) => getAdminPerformanceRecommendationMock(...args),
    updateAdminPerformance: (...args: unknown[]) => updateAdminPerformanceMock(...args),
    applyAdminPerformance: (...args: unknown[]) => applyAdminPerformanceMock(...args),
    applyAdminPerformanceProfile: (...args: unknown[]) => applyAdminPerformanceProfileMock(...args),
    applyAdminPerformanceRecommended: (...args: unknown[]) => applyAdminPerformanceRecommendedMock(...args),
    getSystemVersion: (...args: unknown[]) => getSystemVersionMock(...args),
  },
}));

const basePerformanceState = {
  profile: "balanced",
  effective_settings: {
    ingest_batch_size: 1000,
    opensearch_bulk_docs: 1000,
    worker_concurrency: 1,
    opensearch_dashboards_public_url: "",
    report_brand_name: "Kairon DFIR",
  },
  pending_settings: {},
  requires_restart: [],
  restart_supported: false,
  restart_method: "manual",
  services_to_restart: ["worker"],
  restart_instructions: {
    title: "Manual restart required",
    description: "Run these commands on the server where Kairon DFIR is deployed.",
    commands: [
      { label: "Restart affected services", command: "docker compose restart worker" },
      { label: "Rebuild if environment or image settings changed", command: "docker compose up -d --build worker" },
    ],
    notes: [
      "Use restart for runtime service reloads.",
      "Use up -d --build when Docker image, environment variables or compose settings changed.",
      "The web UI cannot restart Docker services in this deployment.",
    ],
  },
  system: {
    cpu_count: 8,
    cpu_count_host: 8,
    cpu_count_container: 8,
    cpu_percent: 20,
    memory_total_bytes: 16 * 1024 * 1024 * 1024,
    memory_available_bytes: 8 * 1024 * 1024 * 1024,
    memory_container_limit_bytes: 12 * 1024 * 1024 * 1024,
    memory_used_percent: 50,
    disk_total_bytes: 100 * 1024 * 1024 * 1024,
    disk_free_bytes: 40 * 1024 * 1024 * 1024,
    disk_used_percent: 60,
    storage_used_bytes: 5 * 1024 * 1024 * 1024,
    warnings: [],
    allowed_roots: ["/mnt/evidence", "/data/evidence", "/cases"],
    allow_host_path_import: false,
  },
  evidence_storage: {
    allow_host_path_import: false,
    allowed_roots: ["/mnt/evidence", "/data/evidence", "/cases"],
    max_upload_size: 123,
    supports_mounted_path: true,
    can_edit_deployment_settings: false,
    restart_enabled: false,
    deployment_setting_scope: "backend+worker restart",
    restart_commands: ["docker compose up -d --build backend worker"],
    enable_instructions: {
      env: {
        DFIR_ALLOW_HOST_PATH_IMPORT: "true",
        DFIR_ALLOWED_EVIDENCE_ROOTS: "/mnt/evidence,/data/evidence,/cases",
      },
      commands: ["docker compose up -d --build backend worker"],
    },
    allowed_root_details: [
      { path: "/mnt/evidence", label: "Recommended mount point for large evidence", example_path: "/mnt/evidence/case001" },
      { path: "/data/evidence", label: "Alternative data volume", example_path: "/data/evidence/case001" },
      { path: "/cases", label: "Case storage mount", example_path: "/cases/case001" },
    ],
  },
  deployment: {
    restart_enabled: false,
    can_edit_deployment_settings: false,
    restart_commands: ["docker compose up -d --build backend worker"],
    restart_supported: false,
    restart_method: "manual",
    services_to_restart: ["worker"],
    restart_instructions: {
      title: "Manual restart required",
      description: "Run these commands on the server where Kairon DFIR is deployed.",
      commands: [
        { label: "Restart affected services", command: "docker compose restart worker" },
        { label: "Rebuild if environment or image settings changed", command: "docker compose up -d --build worker" },
      ],
      notes: [
        "Use restart for runtime service reloads.",
        "Use up -d --build when Docker image, environment variables or compose settings changed.",
        "The web UI cannot restart Docker services in this deployment.",
      ],
    },
    pending_changes: [
      {
        name: "worker_concurrency",
        key: "WORKER_SCALE",
        old_value: 1,
        new_value: 3,
        scope: "worker",
        status: "requires restart",
        requires_restart_services: ["worker"],
        diagnostic: {
          setting_key: "WORKER_SCALE",
          setting_name: "worker_concurrency",
          current_value: 1,
          expected_value: 3,
          affected_services: ["worker"],
          change_location: {
            type: "compose_scale",
            path: "docker compose runtime scale",
            variable: "WORKER_SCALE",
            compose_reference: "docker-compose.yml -> services.worker (scaled via docker compose up --scale)",
          },
          reason: "Worker scale is not changed by a plain restart. The compose service count is still at the old value.",
          steps: [
            "Scale the worker service to the expected count from the deployment directory.",
            "Use docker compose up with --scale so the extra worker containers are actually created.",
          ],
          commands: [
            "docker compose up -d --scale worker=3",
            "docker compose up -d --build worker --scale worker=3",
          ],
        },
      },
    ],
  },
  services: {
    backend: { status: "ok" },
    worker: { status: "ok", active: 2, known: ["worker-1"], queues: { "worker-1": ["dfir-ingest", "dfir-rules"] } },
    frontend: { status: "ok" },
    opensearch: { status: "ok", cluster_status: "green", heap_used_percent: 30, disk_watermark: { high: "90%" } },
    queues: {
      "dfir-ingest": { queued: 1, started: 0, failed: 0, finished: 5 },
    },
  },
  resources: {
    cpu_count_host: 8,
    cpu_count_container: 8,
    effective_cpu_count: 4,
    memory_total: 16 * 1024 * 1024 * 1024,
    memory_host_total: 32 * 1024 * 1024 * 1024,
    memory_visible_total: 16 * 1024 * 1024 * 1024,
    memory_available: 8 * 1024 * 1024 * 1024,
    memory_container_limit: 12 * 1024 * 1024 * 1024,
    memory_limit_source: "cgroup",
    memory_explanation: "The app can only use memory available to the container or VM. Your physical machine may have more RAM.",
    disk_free: 40 * 1024 * 1024 * 1024,
    opensearch_health: "green",
    opensearch_heap_percent: 30,
    opensearch_disk_watermark: { high: "90%" },
    redis_queue_status: {
      "dfir-ingest": { queued: 1, started: 0, failed: 0, finished: 5 },
    },
    active_workers: 2,
    worker_queues: { "worker-1": ["dfir-ingest", "dfir-rules"] },
    current_concurrency: { backend_workers: 1, worker_scale: 1, ingest_parallelism: 1, desired_ingest_parallelism: 8, effective_ingest_parallelism: 4, ingest_parallelism_reason: "container_cpu_limit", rules_parallelism: 1 },
    current_profile: "balanced",
    warnings: [],
  },
  queue_architecture: {
    current_worker_queues: { "worker-1": ["dfir-ingest", "dfir-rules"] },
    recommended_workers: ["worker-ingest", "worker-rules", "worker-heavy", "worker-maintenance"],
    recommended_queues: ["dfir-ingest", "dfir-rules", "dfir-heavy", "dfir-maintenance"],
    mode: "shared-workers",
  },
  settings: [
    {
      name: "ingest_batch_size",
      key: "INGEST_BATCH_SIZE",
      category: "runtime",
      group: "ingest",
      scope: "runtime",
      description: "Documents parsed per ingest chunk.",
      value_type: "int",
      min: 50,
      max: 10000,
      current_value: 1000,
      pending_value: null,
      effective_value: 1000,
      requires_restart: "none",
      requires_restart_services: [],
      editable: true,
      applies_immediately: true,
    },
    {
      name: "opensearch_dashboards_public_url",
      key: "OPENSEARCH_DASHBOARDS_PUBLIC_URL",
      category: "runtime",
      group: "opensearch",
      scope: "runtime",
      description: "Public OpenSearch Dashboards URL used in UI redirects.",
      value_type: "string",
      current_value: "",
      pending_value: null,
      effective_value: "",
      requires_restart: "none",
      requires_restart_services: [],
      editable: true,
      applies_immediately: true,
    },
    {
      name: "report_brand_name",
      key: "REPORT_BRAND_NAME",
      category: "runtime",
      group: "reports",
      scope: "runtime",
      description: "Brand name rendered in generated reports.",
      value_type: "string",
      current_value: "Kairon DFIR",
      pending_value: null,
      effective_value: "Kairon DFIR",
      requires_restart: "none",
      requires_restart_services: [],
      editable: true,
      applies_immediately: true,
    },
    {
      name: "worker_concurrency",
      key: "WORKER_SCALE",
      category: "deployment",
      group: "deployment",
      scope: "deployment",
      description: "Desired docker compose worker scale.",
      value_type: "int",
      min: 1,
      max: 16,
      current_value: 1,
      pending_value: 3,
      effective_value: 1,
      requires_restart: "worker",
      requires_restart_services: ["worker"],
      editable: true,
      applies_immediately: false,
    },
  ],
  profiles: {
    safe: { ingest_batch_size: 250, worker_concurrency: 1 },
    balanced: { ingest_batch_size: 1000, worker_concurrency: 1 },
    performance: { ingest_batch_size: 1500, worker_concurrency: 2 },
    max: { ingest_batch_size: 2000, worker_concurrency: 4 },
  },
  recommendation: {
    recommended_profile: "performance",
    reasons: ["8 CPU cores detected"],
    warnings: [],
    estimated_changes: { ingest_batch_size: 1500, worker_concurrency: 2 },
  },
};

function renderPage(initialEntries?: string[]) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <MemoryRouter initialEntries={initialEntries}>
      <QueryClientProvider client={queryClient}>
        <SystemPage />
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("SystemPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getAdminPerformanceMock.mockResolvedValue(basePerformanceState);
    getAdminPerformanceRecommendationMock.mockResolvedValue(basePerformanceState.recommendation);
    updateAdminPerformanceMock.mockResolvedValue({
      saved: true,
      profile: "max",
      updated: ["PERFORMANCE_PROFILE"],
      runtime_applied: ["INGEST_BATCH_SIZE"],
      requires_restart: ["worker"],
      restart_supported: false,
      restart_method: "manual",
      restart_instructions: basePerformanceState.restart_instructions,
      warnings: [],
      effective_after_restart: basePerformanceState,
    });
    applyAdminPerformanceMock.mockResolvedValue({
      saved: true,
      profile: "max",
      updated: ["PERFORMANCE_PROFILE"],
      runtime_applied: ["INGEST_BATCH_SIZE"],
      requires_restart: ["worker"],
      restart_supported: false,
      restart_method: "manual",
      restart_instructions: basePerformanceState.restart_instructions,
      warnings: [],
      effective_after_restart: basePerformanceState,
    });
    applyAdminPerformanceProfileMock.mockResolvedValue({
      saved: true,
      profile: "performance",
      updated: ["PERFORMANCE_PROFILE"],
      runtime_applied: ["INGEST_BATCH_SIZE"],
      requires_restart: ["worker"],
      warnings: [],
      effective_after_restart: basePerformanceState,
    });
    applyAdminPerformanceRecommendedMock.mockResolvedValue({
      saved: true,
      profile: "performance",
      updated: ["PERFORMANCE_PROFILE"],
      runtime_applied: ["INGEST_BATCH_SIZE"],
      requires_restart: ["worker"],
      restart_supported: false,
      restart_method: "manual",
      restart_instructions: basePerformanceState.restart_instructions,
      warnings: [],
      effective_after_restart: basePerformanceState,
    });
    getSystemVersionMock.mockResolvedValue({
      app_version: "0.1.0",
      vendor_id: "yokddj",
      build_channel: "evaluation",
      build_fingerprint: "kairon-dfir-evaluation",
      notice: "Internal evaluation build. Redistribution not authorized without permission.",
    });
  });

  it("renders system sections", async () => {
    renderPage();
    expect(await screen.findByText(/System settings and deployment guidance/i)).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /overview/i })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /performance/i })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /evidence storage/i })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /report branding/i })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /opensearch/i })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /deployment/i })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /advanced/i })).toBeInTheDocument();
    expect(screen.getByText(/container visible RAM/i)).toBeInTheDocument();
    expect(screen.getByText(/Ingest concurrency: desired 8 · effective 4/i)).toBeInTheDocument();
  });

  it("renders discrete build identity metadata", async () => {
    renderPage();
    expect(await screen.findByText(/Build identity/i)).toBeInTheDocument();
    expect(screen.getByText(/Channel:/i)).toBeInTheDocument();
    expect(screen.getByText(/^evaluation$/i)).toBeInTheDocument();
    expect(screen.getByText(/Vendor:/i)).toBeInTheDocument();
    expect(screen.getByText(/^yokddj$/i)).toBeInTheDocument();
    expect(screen.getByText(/kairon-dfir-evaluation/i)).toBeInTheDocument();
    expect(screen.getByText(/Internal evaluation build/i)).toBeInTheDocument();
  });

  it("defaults to overview and does not show advanced settings there", async () => {
    renderPage();
    expect(await screen.findByText(/System settings and deployment guidance/i)).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /overview/i })).toHaveAttribute("aria-selected", "true");
    expect(screen.queryByText("INGEST_BATCH_SIZE")).not.toBeInTheDocument();
    expect(screen.queryByPlaceholderText(/Filter advanced settings/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Advanced settings can affect ingest stability/i)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /open advanced settings/i })).toBeInTheDocument();
  });

  it("clears pending changes after apply succeeds", async () => {
    const confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(true);
    renderPage();
    expect(await screen.findByText(/System settings and deployment guidance/i)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("tab", { name: /performance/i }));
    await userEvent.click(screen.getByRole("button", { name: /^Max Max Max: uses more CPU\/RAM and may affect responsiveness$/i }));
    await userEvent.click(screen.getByRole("tab", { name: /overview/i }));
    await userEvent.click(screen.getByRole("button", { name: /apply now/i }));
    await waitFor(() => expect(applyAdminPerformanceProfileMock).toHaveBeenCalled());
    await waitFor(() => expect(screen.getByText(/Applied profile performance\./i)).toBeInTheDocument());
    expect(screen.getByText(/Changed settings:/i)).toBeInTheDocument();
    confirmSpy.mockRestore();
  });

  it("renders evidence storage disabled callout and enable instructions", async () => {
    renderPage(["/system/performance?tab=evidence-storage"]);
    await screen.findByText(/System settings and deployment guidance/i);

    expect(await screen.findByText(/Server-mounted path import is disabled/i)).toBeInTheDocument();
    expect(
      screen.getAllByText((_, element) => (element?.textContent ?? "").includes("DFIR_ALLOW_HOST_PATH_IMPORT=true")).length,
    ).toBeGreaterThan(0);
    expect(screen.getByText(/docker compose up -d --build backend worker/i)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Open Evidence & Ingest/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Copy enable instructions/i })).toBeInTheDocument();
  });

  it("renders allowed roots as cards", async () => {
    renderPage(["/system/performance?tab=evidence-storage"]);
    await screen.findByText(/System settings and deployment guidance/i);

    expect(await screen.findByText(/Recommended mount point for large evidence/i)).toBeInTheDocument();
    expect(screen.getByText("/mnt/evidence")).toBeInTheDocument();
    expect(screen.getByText("/data/evidence")).toBeInTheDocument();
    expect(screen.getByText("/cases")).toBeInTheDocument();
  });

  it("deployment settings are labeled as requiring restart and pending changes show old/new/scope", async () => {
    renderPage();
    await screen.findByText(/System settings and deployment guidance/i);

    await userEvent.click(screen.getByRole("tab", { name: /deployment/i }));
    expect(await screen.findByText(/Desired docker compose worker scale/i)).toBeInTheDocument();
    expect(screen.getAllByText(/Requires worker/i).length).toBeGreaterThan(0);

    await userEvent.click(screen.getByRole("tab", { name: /overview/i }));
    expect(screen.getAllByText(/Old value:/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/New value:/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Scope:/i).length).toBeGreaterThan(0);
  });

  it("shows manual restart required and not a fake restart button", async () => {
    renderPage();
    await screen.findByText(/System settings and deployment guidance/i);

    expect(screen.getByText(/Manual restart required/i)).toBeInTheDocument();
    expect(screen.getByText(/What you still need to change now/i)).toBeInTheDocument();
    expect(screen.getByText(/^docker compose restart$/i)).toBeInTheDocument();
    expect(screen.getByText(/is not enough for these settings/i)).toBeInTheDocument();
    expect(screen.getByText(/Scale worker from 1 to 3/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^Restart affected services$/i })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Copy restart command/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Copy rebuild command/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /I restarted services, check status/i })).toBeInTheDocument();
    expect(screen.getByText(/Current:/i)).toBeInTheDocument();
    expect(screen.getByText(/Expected:/i)).toBeInTheDocument();
    expect(screen.getByText(/docker compose runtime scale/i)).toBeInTheDocument();
  });

  it("refreshes status when checking manual restart", async () => {
    getAdminPerformanceMock
      .mockResolvedValueOnce(basePerformanceState)
      .mockResolvedValueOnce({
        ...basePerformanceState,
        requires_restart: [],
        services_to_restart: [],
        deployment: {
          ...basePerformanceState.deployment,
          pending_changes: [],
        },
      });
    renderPage();
    await screen.findByText(/System settings and deployment guidance/i);
    await userEvent.click(screen.getByRole("button", { name: /I restarted services, check status/i }));
    expect(await screen.findByText(/Restart detected. Settings are active./i)).toBeInTheDocument();
  });

  it("advanced settings are shown only in advanced tab", async () => {
    renderPage(["/system/performance?tab=advanced"]);
    await screen.findByText(/System settings and deployment guidance/i);
    expect(await screen.findByPlaceholderText(/Filter advanced settings/i)).toBeInTheDocument();
    expect(screen.getByText("INGEST_BATCH_SIZE")).toBeInTheDocument();
    expect(screen.getByText(/Documents parsed per ingest chunk/i)).toBeInTheDocument();
  });

  it("switching profile shows local pending change cards", async () => {
    renderPage();
    await screen.findByText(/System settings and deployment guidance/i);
    await userEvent.click(screen.getByRole("tab", { name: /performance/i }));
    await userEvent.click(screen.getByRole("button", { name: /^Max Max Max: uses more CPU\/RAM and may affect responsiveness$/i }));
    await userEvent.click(screen.getByRole("tab", { name: /overview/i }));

    expect(await screen.findByText(/Changed settings:/i)).toBeInTheDocument();
    expect(screen.getAllByText(/New value:/i).length).toBeGreaterThan(0);
  });

  it("shows performance profile and applies recommended profile", async () => {
    renderPage();
    await screen.findByText(/System settings and deployment guidance/i);
    await userEvent.click(screen.getByRole("tab", { name: /overview/i }));
    expect(screen.getAllByText(/^performance$/i).length).toBeGreaterThan(0);
    await userEvent.click(screen.getByRole("button", { name: /apply recommended/i }));
    await waitFor(() => expect(applyAdminPerformanceRecommendedMock).toHaveBeenCalled());
  });

  it("requires confirmation before applying max profile", async () => {
    const confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(false);
    renderPage();
    await screen.findByText(/System settings and deployment guidance/i);
    await userEvent.click(screen.getByRole("tab", { name: /performance/i }));
    await userEvent.click(screen.getByRole("button", { name: /^Max Max Max: uses more CPU\/RAM and may affect responsiveness$/i }));
    await userEvent.click(screen.getByRole("tab", { name: /overview/i }));
    await userEvent.click(screen.getByRole("button", { name: /apply now/i }));
    expect(confirmSpy).toHaveBeenCalled();
    expect(applyAdminPerformanceProfileMock).not.toHaveBeenCalled();
    confirmSpy.mockRestore();
  });

  it("invalid custom input shows validation error", async () => {
    renderPage();
    await screen.findByText(/System settings and deployment guidance/i);
    await userEvent.click(screen.getByRole("tab", { name: /deployment/i }));
    const workerField = screen.getByText(/Desired docker compose worker scale\./i).closest("label");
    expect(workerField).not.toBeNull();
    const workerInput = within(workerField as HTMLElement).getByRole("textbox");
    fireEvent.change(workerInput, { target: { value: "-1" } });
    await userEvent.click(screen.getByRole("tab", { name: /overview/i }));
    await userEvent.click(screen.getByRole("button", { name: /save settings/i }));

    expect(updateAdminPerformanceMock).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("tab", { name: /deployment/i }));
    expect(await screen.findByText(/Must be >= 1/i)).toBeInTheDocument();
  });

  it("renders configurable OpenSearch public URL setting", async () => {
    renderPage();
    await screen.findByText(/System settings and deployment guidance/i);
    await userEvent.click(screen.getByRole("tab", { name: /opensearch/i }));
    expect(await screen.findByText(/Public OpenSearch Dashboards URL used in UI redirects/i)).toBeInTheDocument();
  });
});
