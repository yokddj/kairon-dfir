import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import ArtifactExplorer from "./ArtifactExplorer";

const listCasesMock = vi.fn();
const searchFacetsMock = vi.fn();
const searchMock = vi.fn();
const siemExternalLinksMock = vi.fn();
const rebuildEvidenceCoreEzArtifactMock = vi.fn();
const getStartupPersistenceMock = vi.fn();
const getMotwMock = vi.fn();
const getEmailArtifactsMock = vi.fn();
const resolveIndicatorsMock = vi.fn();
const createTimelineKeyEventMock = vi.fn();

vi.mock("../api/client", () => ({
  api: {
    listCases: (...args: unknown[]) => listCasesMock(...args),
    searchFacets: (...args: unknown[]) => searchFacetsMock(...args),
    search: (...args: unknown[]) => searchMock(...args),
    siemExternalLinks: (...args: unknown[]) => siemExternalLinksMock(...args),
    rebuildEvidenceCoreEzArtifact: (...args: unknown[]) => rebuildEvidenceCoreEzArtifactMock(...args),
    getStartupPersistence: (...args: unknown[]) => getStartupPersistenceMock(...args),
    getMotw: (...args: unknown[]) => getMotwMock(...args),
    getEmailArtifacts: (...args: unknown[]) => getEmailArtifactsMock(...args),
    resolveIndicators: (...args: unknown[]) => resolveIndicatorsMock(...args),
    createTimelineKeyEvent: (...args: unknown[]) => createTimelineKeyEventMock(...args),
  },
}));

vi.mock("../context/ActiveCaseContext", () => ({
  useActiveCase: () => ({
    activeCaseId: "case-1",
    selectedEvidenceId: "ev-1",
    selectedHost: "HOST-01",
    setActiveCaseId: vi.fn(),
  }),
}));

vi.mock("../context/TimezoneContext", () => ({
  useTimezonePreference: () => ({
    effectiveTimezone: "UTC",
  }),
}));

vi.mock("../components/EventTable", () => ({
  default: () => <div data-testid="artifact-search-table">Artifact table</div>,
}));

vi.mock("../components/PaginationControls", () => ({
  default: () => <div>Pagination</div>,
}));

vi.mock("../components/CreateFindingDialog", () => ({
  default: () => null,
}));

vi.mock("../components/DebugExportDialog", () => ({
  default: () => null,
}));

function renderPage(path = "/cases/case-1/artifact-search") {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter initialEntries={[path]}>
      <QueryClientProvider client={queryClient}>
        <Routes>
          <Route path="/cases/:caseId/artifact-search" element={<ArtifactExplorer />} />
        </Routes>
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("ArtifactExplorer", () => {
  beforeEach(() => {
    listCasesMock.mockResolvedValue([{ id: "case-1", name: "Case Alpha" }]);
    searchFacetsMock.mockResolvedValue({
      "artifact.type": ["evtx", "prefetch"],
      "artifact.name": ["Security", "Prefetch"],
    });
    searchMock.mockResolvedValue({
      items: [],
      total: 0,
      total_pages: 0,
      total_relation: "eq",
    });
    siemExternalLinksMock.mockResolvedValue({
      discover_url: "http://opensearch.local/discover",
    });
    rebuildEvidenceCoreEzArtifactMock.mockResolvedValue({
      accepted: true,
      run_id: "run-1",
      evidence_id: "ev-1",
      status: "queued",
      artifact_type: "amcache",
      tool: "AmcacheParser",
      backend: "amcacheparser_csv",
      backend_variant: "advanced",
    });
    getStartupPersistenceMock.mockResolvedValue({
      case_id: "case-1",
      total: 1,
      page: 1,
      page_size: 50,
      total_pages: 1,
      summary: {
        total: 1,
        suspicious: 1,
        high_risk: 1,
        by_host: { "HOST-01": 1 },
        by_type: { scheduled_task: 1 },
        by_source: { scheduled_tasks: 1 },
      },
      warnings: [],
      wmi_status: "not_present",
      items: [
        {
          id: "persist-1",
          case_id: "case-1",
          evidence_id: "ev-1",
          host: "HOST-01",
          type: "scheduled_task",
          name: "OneDriveUpdateTask",
          command_or_target: "powershell.exe -ep bypass C:\\Users\\Public\\maintenance.ps1",
          path: "",
          user: "usera",
          enabled: true,
          start_type: "",
          trigger: "At logon",
          source_artifact: "scheduled_tasks",
          source_event_id: "event-1",
          first_seen: "2024-03-22T11:00:00Z",
          last_modified: "2024-03-22T11:00:00Z",
          risk_score: 85,
          risk_reasons: ["scheduled_task_mechanism", "suspicious_powershell_flags"],
          indicator_resolution: [{ indicator: "maintenance.ps1", type: "file", normalized: "maintenance.ps1" }],
          related_events: ["event-1"],
          confidence: "high",
          search_url: "/cases/case-1/search?q=maintenance.ps1",
          timeline_url: "/cases/case-1/search?view=timeline&q=maintenance.ps1",
        },
      ],
    });
    getMotwMock.mockResolvedValue({
      case_id: "case-1",
      total: 1,
      page: 1,
      page_size: 50,
      total_pages: 1,
      summary: {
        total: 1,
        suspicious: 1,
        high_risk: 1,
        by_host: { "HOST-01": 1 },
        by_zone: { "3": 1 },
        by_source: { sysmon_15: 1 },
        by_extension: { ".iso": 1 },
      },
      warnings: [],
      items: [
        {
          id: "motw-1",
          case_id: "case-1",
          evidence_id: "ev-1",
          host: "HOST-01",
          artifact_type: "motw",
          file_path: "C:\\Users\\usera\\Downloads\\sample.iso",
          file_name: "sample.iso",
          file_extension: ".iso",
          zone_identifier_path: "C:\\Users\\usera\\Downloads\\sample.iso:Zone.Identifier",
          zone_id: 3,
          zone_name: "Internet",
          host_url: "https://file.io/sample.iso",
          referrer_url: "",
          source_url: "https://file.io/sample.iso",
          timestamp: "2024-03-22T10:00:00Z",
          source_artifact: "sysmon_15",
          source_event_id: "event-motw-1",
          hashes: {},
          raw_content: "[ZoneTransfer]\nZoneId=3\nHostUrl=https://file.io/sample.iso\n",
          risk_score: 75,
          risk_reasons: ["internet_or_restricted_zone", "downloaded_executable_script_archive_or_iso"],
          linked: {
            base_file_search: "/cases/case-1/search?q=sample.iso",
            timeline_around: "/cases/case-1/search?view=timeline&q=sample.iso",
            browser_search: "/cases/case-1/search?q=file.io",
            user_activity_search: "/cases/case-1/search?artifact_type=recentdocs&q=sample.iso",
          },
          indicator_resolution: [{ indicator: "sample.iso", type: "file", normalized: "sample.iso" }],
        },
        {
          id: "motw-generic",
          case_id: "case-1",
          evidence_id: "ev-1",
          host: "HOST-01",
          artifact_type: "motw",
          file_path: "C:\\Users\\Administrator.EXAMPLECORP\\Downloads\\loupe-mono-dark.heic",
          file_name: "loupe-mono-dark.heic",
          file_extension: ".heic",
          zone_identifier_path: "C:\\Users\\Administrator.EXAMPLECORP\\Downloads\\loupe-mono-dark.heic:Zone.Identifier",
          zone_id: 3,
          zone_name: "Internet",
          host_url: "",
          referrer_url: "",
          source_url: "",
          timestamp: "2024-03-22T10:05:00Z",
          source_artifact: "mft_ads",
          source_event_id: "event-motw-generic",
          hashes: {},
          raw_content: "[ZoneTransfer]\nZoneId=3\n",
          risk_score: 35,
          risk_reasons: ["internet_or_restricted_zone"],
          linked: {
            base_file_search: "/cases/case-1/search?q=loupe-mono-dark.heic",
            timeline_around: "/cases/case-1/search?view=timeline&q=loupe-mono-dark.heic",
          },
          indicator_resolution: [{ indicator: "loupe-mono-dark.heic", type: "file", normalized: "loupe-mono-dark.heic" }],
        },
      ],
    });
    getEmailArtifactsMock.mockResolvedValue({
      case_id: "case-1",
      total: 4,
      page: 1,
      page_size: 50,
      total_pages: 1,
      summary: {
        total: 4,
        stores: 1,
        message_files: 0,
        attachment_cache: 0,
        webmail_activity: 1,
        related_email_downloads: 1,
        app_presence: 1,
        technical_traces: 0,
        advanced_technical_traces: 2,
        interesting: 3,
        by_host: { "HOST-01": 4 },
        by_type: { store: 1, webmail_activity: 1, related_email_download: 1, app_presence: 1 },
        by_client: { outlook: 2, unknown: 1, windows_mail: 1 },
        by_source: { mft: 2, browser: 1, motw: 1 },
      },
      warnings: [],
      limitations: [
        "Mail stores are detected, but OST/PST message content is not parsed in this version.",
        "Mail artifact presence does not prove malicious email content.",
      ],
      attachment_cache_status: "no_data",
      items: [
        {
          id: "email-1",
          case_id: "case-1",
          evidence_id: "ev-1",
          host: "HOST-01",
          artifact_type: "email",
          email_artifact_type: "store",
          client: "outlook",
          account_hint: "user.a@outlook.es",
          file_path: "C:\\Users\\usera\\AppData\\Local\\Microsoft\\Outlook\\user.a@outlook.es.ost",
          file_name: "user.a@outlook.es.ost",
          extension: ".ost",
          size: 2048,
          modified: "2024-03-22T09:55:00Z",
          timestamp: "2024-03-22T09:55:00Z",
          source_artifact: "mft",
          source_event_id: "event-email-1",
          confidence: "high",
          content_parsed: false,
          risk_score: 45,
          risk_reasons: ["mail_store_detected", "outlook_artifact"],
          related_indicators: [{ indicator: "user.a@outlook.es", type: "email", normalized: "user.a@outlook.es" }],
          related_downloads: [{ id: "download-1", label: "https://file.io/sample.iso", search_url: "/cases/case-1/search?q=file.io" }],
          related_motw: [{ id: "email-3", label: "invoice.pdf:Zone.Identifier", search_url: "/cases/case-1/search?q=invoice.pdf", relation_reason: "Zone.Identifier HostUrl or ReferrerUrl points to an explicit webmail/mail domain.", confidence: "high" }],
          related_user_activity: [{ id: "ua-1", label: "Sample.lnk", search_url: "/cases/case-1/search?q=Sample.lnk" }],
          search_url: "/cases/case-1/search?q=user.a%40outlook.es.ost",
          timeline_url: "/cases/case-1/search?view=timeline&q=user.a%40outlook.es.ost",
          raw: {},
        },
        {
          id: "email-2",
          case_id: "case-1",
          evidence_id: "ev-1",
          host: "HOST-01",
          artifact_type: "email",
          email_artifact_type: "webmail_activity",
          client: "unknown",
          account_hint: "",
          url: "https://file.io/sample.iso",
          source_artifact: "browser",
          source_event_id: "event-email-2",
          confidence: "medium",
          content_parsed: false,
          risk_score: 55,
          risk_reasons: ["file_sharing_activity", "download_or_attachment_extension_of_interest"],
          related_indicators: [{ indicator: "file.io", type: "domain", normalized: "file.io" }],
          related_downloads: [],
          related_motw: [{ id: "email-3", label: "invoice.pdf:Zone.Identifier", search_url: "/cases/case-1/search?q=invoice.pdf", relation_reason: "Zone.Identifier HostUrl or ReferrerUrl points to an explicit webmail/mail domain.", confidence: "high" }],
          related_user_activity: [],
          search_url: "/cases/case-1/search?q=file.io",
          timeline_url: "/cases/case-1/search?view=timeline&q=file.io",
          raw: {},
        },
        {
          id: "email-3",
          case_id: "case-1",
          evidence_id: "ev-1",
          host: "HOST-01",
          artifact_type: "email",
          email_artifact_type: "related_email_download",
          client: "outlook",
          account_hint: "",
          file_path: "C:\\Users\\usera\\Downloads\\invoice.pdf:Zone.Identifier",
          file_name: "invoice.pdf:Zone.Identifier",
          extension: ".identifier",
          url: "https://outlook.office.com/mail/attachment/invoice.pdf",
          source_artifact: "motw",
          source_event_id: "event-email-3",
          confidence: "high",
          relation_reason: "Zone.Identifier HostUrl or ReferrerUrl points to an explicit webmail/mail domain.",
          content_parsed: false,
          risk_score: 45,
          risk_reasons: ["related_email_download", "outlook_artifact"],
          related_indicators: [{ indicator: "outlook.office.com", type: "domain", normalized: "outlook.office.com" }],
          related_downloads: [],
          related_motw: [],
          related_user_activity: [],
          search_url: "/cases/case-1/search?q=invoice.pdf",
          timeline_url: "/cases/case-1/search?view=timeline&q=invoice.pdf",
          raw: {},
        },
        {
          id: "email-4",
          case_id: "case-1",
          evidence_id: "ev-1",
          host: "HOST-01",
          artifact_type: "email",
          email_artifact_type: "app_presence",
          client: "windows_mail",
          account_hint: "",
          file_path: "Windows Mail package presence (system-wide)",
          file_name: "microsoft.windowscommunicationsapps",
          extension: "",
          source_artifact: "mft",
          source_event_id: "event-email-4",
          confidence: "low",
          content_parsed: false,
          risk_score: 5,
          risk_reasons: ["windows_mail_app_presence_grouped"],
          related_indicators: [],
          related_downloads: [],
          related_motw: [],
          related_user_activity: [],
          search_url: "/cases/case-1/search?q=microsoft.windowscommunicationsapps",
          timeline_url: "/cases/case-1/search?view=timeline&q=microsoft.windowscommunicationsapps",
          raw: {},
        },
      ],
    });
    resolveIndicatorsMock.mockResolvedValue({
      case_id: "case-1",
      indicators: [{ indicator: "maintenance.ps1", type: "file", normalized: "maintenance.ps1" }],
      results: [
        {
          indicator: "maintenance.ps1",
          type: "file",
          status: "found",
          sources_found: ["mft"],
          counts_by_source: { mft: 1 },
          hosts: ["HOST-01"],
          evidence_ids: ["ev-1"],
          confidence: "medium",
          explanation: "maintenance.ps1 was found.",
          suggested_pivots: [{ label: "Find this file", url: "/cases/case-1/search?q=maintenance.ps1", type: "file" }],
        },
      ],
    });
    createTimelineKeyEventMock.mockResolvedValue({ id: "bookmark-1" });
  });

  it("shows Artifact Views as the main page title", async () => {
    renderPage();
    expect(await screen.findByRole("heading", { name: "Artifact Views" })).toBeInTheDocument();
    expect(screen.getByText(/Open focused views for parsed artifact families/i)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Open selected artifact in OpenSearch/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Export artifact debug pack/i })).toBeInTheDocument();
  });

  it("uses user-facing artifact view labels and hides registry_persistence from the main selector", async () => {
    searchFacetsMock.mockResolvedValueOnce({
      "artifact.type": {
        registry_persistence: 12,
        scheduled_task: 3,
        windows_event: 4,
        powershell: 2,
      },
      "artifact.name": {},
    });

    renderPage();

    expect(await screen.findByRole("heading", { name: "Artifact Views" })).toBeInTheDocument();
    const artifactSelector = screen.getByLabelText("Artifact view");
    expect(artifactSelector).toHaveTextContent("Startup & Persistence");
    expect(artifactSelector).toHaveTextContent("Scheduled Tasks");
    expect(artifactSelector).toHaveTextContent("Windows Events");
    expect(artifactSelector).not.toHaveTextContent("registry_persistence");
    expect(artifactSelector).not.toHaveTextContent("scheduled_task");
  });

  it("renders user activity tabs for RECmd artifacts", async () => {
    renderPage("/cases/case-1/artifact-search?artifact_type=shellbag");
    expect(await screen.findByText("User Activity")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Shellbags" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "UserAssist" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "RecentDocs" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "RunMRU" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "OpenSaveMRU" })).toBeInTheDocument();
  });

  it("shows advanced EZ rebuild controls for supported artifacts", async () => {
    renderPage("/cases/case-1/artifact-search?artifact_type=amcache&evidence_id=ev-1");
    expect(await screen.findByText(/EZ advanced: AmcacheParser/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Run AmcacheParser rebuild/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /View EZ results/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Compare/i })).toBeInTheDocument();
  });

  it("explains why PECmd rebuild is disabled for Prefetch", async () => {
    renderPage("/cases/case-1/artifact-search?artifact_type=prefetch&evidence_id=ev-1");
    expect(await screen.findByText(/Internal prefetch_raw is active/i)).toBeInTheDocument();
    expect(screen.getByText(/requires Windows decompression support/i)).toBeInTheDocument();
  });

  it("renders Startup & Persistence filters, risk reasons and actions", async () => {
    renderPage("/cases/case-1/artifact-search?artifact_type=startup_persistence&suspicious_only=true");
    expect(await screen.findByText("Startup & Persistence Items")).toBeInTheDocument();
    expect(screen.getByLabelText("Persistence category")).toHaveTextContent("Run keys");
    expect(screen.getByLabelText("Persistence source")).toHaveTextContent("Registry hive");
    expect(await screen.findByText("OneDriveUpdateTask")).toBeInTheDocument();
    expect(screen.getByText(/High 85/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Add to Finding/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Add to Incident Timeline/i })).toBeInTheDocument();
    fireEvent.click(screen.getAllByRole("button", { name: "Details" })[0]);
    expect(await screen.findByText("Persistence detail")).toBeInTheDocument();
    expect(screen.getByText("scheduled_task_mechanism")).toBeInTheDocument();
    expect(await screen.findByText("Evidence resolution")).toBeInTheDocument();
  });

  it("routes legacy registry_persistence view requests into Startup & Persistence", async () => {
    renderPage("/cases/case-1/artifact-search?artifact_type=registry_persistence");
    expect(await screen.findByText("Startup & Persistence Items")).toBeInTheDocument();
    expect(getStartupPersistenceMock).toHaveBeenCalledWith(
      "case-1",
      expect.objectContaining({ source: undefined, type: undefined }),
    );
  });

  it("renders MOTW downloaded file details and pivots", async () => {
    renderPage("/cases/case-1/artifact-search?artifact_type=motw&q=sample.iso");
    expect(await screen.findByRole("heading", { name: "MOTW / Downloaded Files" })).toBeInTheDocument();
    expect(await screen.findByText("sample.iso")).toBeInTheDocument();
    expect(screen.getAllByText(/3 Internet/i).length).toBeGreaterThan(0);
    expect(screen.getByText("https://file.io/sample.iso")).toBeInTheDocument();
    fireEvent.click(screen.getAllByRole("button", { name: "Details" })[0]);
    expect(await screen.findByText("MOTW detail")).toBeInTheDocument();
    expect(screen.getByText("downloaded_executable_script_archive_or_iso")).toBeInTheDocument();
    expect(screen.getAllByRole("link", { name: /Find this file/i }).length).toBeGreaterThan(0);
    expect(screen.getByRole("link", { name: /View activity around this time/i })).toBeInTheDocument();
    expect(await screen.findByText("Evidence resolution")).toBeInTheDocument();
  });

  it("keeps generic MOTW in MOTW view without showing it in Email Artifacts", async () => {
    const motwRender = renderPage("/cases/case-1/artifact-search?artifact_type=motw");
    expect(await screen.findByText("loupe-mono-dark.heic")).toBeInTheDocument();
    motwRender.unmount();

    renderPage("/cases/case-1/artifact-search?artifact_type=email");
    expect(await screen.findByRole("heading", { name: "Email Artifacts" })).toBeInTheDocument();
    expect(screen.queryByText(/loupe-mono-dark\.heic/i)).not.toBeInTheDocument();
  });

  it("renders Email Artifacts with mail-store caveat and related download context", async () => {
    renderPage("/cases/case-1/artifact-search?artifact_type=email");
    expect(await screen.findByRole("heading", { name: "Email Artifacts" })).toBeInTheDocument();
    expect(screen.getByText(/OST\/PST message content is not parsed/i)).toBeInTheDocument();
    expect(await screen.findByText("user.a@outlook.es")).toBeInTheDocument();
    expect(screen.getAllByText("Not parsed").length).toBeGreaterThan(0);
    expect(screen.getByText(/Advanced technical traces hidden: 2/i)).toBeInTheDocument();
    expect(screen.getByText("Windows Mail package presence (system-wide)")).toBeInTheDocument();
    expect(screen.getAllByText("downloads").length).toBeGreaterThan(0);
    expect(screen.getAllByText("MOTW").length).toBeGreaterThan(0);
    expect(screen.getByText(/Related downloads\/MOTW: 1/i)).toBeInTheDocument();
    fireEvent.click(screen.getAllByRole("button", { name: "Details" })[0]);
    expect(await screen.findByText("Email artifact detail")).toBeInTheDocument();
    expect(screen.getAllByText(/Message content is not parsed in this version/i).length).toBeGreaterThan(0);
    expect(screen.getByText("mail_store_detected")).toBeInTheDocument();
    expect(screen.getByText("Zone.Identifier HostUrl or ReferrerUrl points to an explicit webmail/mail domain.")).toBeInTheDocument();
    expect(screen.getByText(/Confidence: high/i)).toBeInTheDocument();
    expect(await screen.findByText("Evidence resolution")).toBeInTheDocument();
  });
});
