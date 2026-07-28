import { Suspense, lazy } from "react";
import { useQuery } from "@tanstack/react-query";
import { Navigate, Route, Routes, useLocation, useParams } from "react-router-dom";
import { api } from "./api/client";
import Layout from "./components/Layout";
import NoActiveCaseState from "./components/NoActiveCaseState";
import { ProtectedRoute } from "./components/ProtectedRoute";
import { MemoryWorkspace } from "./components/MemoryWorkspace";
import { ActiveCaseProvider } from "./context/ActiveCaseContext";
import { useActiveCase } from "./context/ActiveCaseContext";
import { AuthProvider } from "./context/AuthContext";
import { NotificationsProvider } from "./context/NotificationsContext";
import { TimezoneProvider } from "./context/TimezoneContext";

const LoginPage = lazy(() => import("./pages/LoginPage"));
const SetupWizardPage = lazy(() => import("./pages/SetupWizardPage"));
const AdminUsersPage = lazy(() => import("./pages/AdminUsersPage"));
const ChangePasswordPage = lazy(() => import("./pages/ChangePasswordPage"));
const Dashboard = lazy(() => import("./pages/Dashboard"));
const Cases = lazy(() => import("./pages/Cases"));
const CaseDetail = lazy(() => import("./pages/CaseDetail"));
const CaseOverviewPage = lazy(() => import("./pages/CaseOverviewPage"));
const CaseHostsPage = lazy(() => import("./pages/CaseHostsPage"));
const CaseProcessGraphPage = lazy(() => import("./pages/CaseProcessGraphPage"));
const CommandHistoryPage = lazy(() => import("./pages/CommandHistoryPage"));
const LinuxAuthenticationPage = lazy(() => import("./pages/LinuxAuthenticationPage"));
const IncidentTimelinePage = lazy(() => import("./pages/IncidentTimelinePage"));
const TimelinePage = lazy(() => import("./pages/TimelinePage"));
const ValidationMatrixPage = lazy(() => import("./pages/ValidationMatrixPage"));
const CaseReportsPage = lazy(() => import("./pages/CaseReportsPage"));
const EvidenceDetail = lazy(() => import("./pages/EvidenceDetail"));
const Search = lazy(() => import("./pages/Search"));
const ArtifactExplorer = lazy(() => import("./pages/ArtifactExplorer"));
const Siem = lazy(() => import("./pages/Siem"));
const ActivityPage = lazy(() => import("./pages/ActivityPage"));
const Findings = lazy(() => import("./pages/Findings"));
const Rules = lazy(() => import("./pages/Rules"));
const Detections = lazy(() => import("./pages/Detections"));
const SystemPage = lazy(() => import("./pages/SystemPage"));
const DocsPage = lazy(() => import("./pages/DocsPage"));
const ParserCoveragePage = lazy(() => import("./pages/ParserCoveragePage"));
const DebugExportPage = lazy(() => import("./pages/DebugExportPage"));
const MemoryEvidencePage = lazy(() => import("./pages/MemoryEvidencePage"));
const CaseMemoryLanding = lazy(() => import("./pages/CaseMemoryLanding"));

function WorkspaceLoadingFallback() {
  return (
    <div className="rounded-2xl border border-zinc-800 bg-zinc-950/70 px-4 py-6 text-sm text-zinc-300">
      Loading workspace...
    </div>
  );
}

function LegacyCaseRoute({ suffix }: { suffix: string }) {
  const { activeCaseId } = useActiveCase();
  if (activeCaseId) {
    return <Navigate to={`/cases/${activeCaseId}${suffix}`} replace />;
  }
  return <NoActiveCaseState />;
}

function appendSearch(path: string, search: string): string {
  if (!search) return path;
  const separator = path.includes("?") ? "&" : "?";
  return `${path}${separator}${search.replace(/^\?/, "")}`;
}

function NavigateToCaseTab({ tab }: { tab: string }) {
  const { caseId = "" } = useParams();
  if (!caseId) return <Navigate to="/cases" replace />;
  return <Navigate to={`/cases/${caseId}?tab=${tab}`} replace />;
}

function LegacyCaseParamRedirect({ suffix, fallback = "/cases", preserveQuery = true }: { suffix: string; fallback?: string; preserveQuery?: boolean }) {
  const { caseId = "" } = useParams();
  const location = useLocation();
  if (!caseId) return <Navigate to={fallback} replace />;
  return <Navigate to={preserveQuery ? appendSearch(`/cases/${caseId}${suffix}`, location.search) : `/cases/${caseId}${suffix}`} replace />;
}

function ActiveCaseCanonicalRedirect({ suffix }: { suffix: string }) {
  const { activeCaseId } = useActiveCase();
  const location = useLocation();
  if (!activeCaseId) {
    return <NoActiveCaseState description="Select or create a case first to open investigation views." />;
  }
  return <Navigate to={appendSearch(`/cases/${activeCaseId}${suffix}`, location.search)} replace />;
}

function memorySegmentFromLegacyTab(value: string | null): string {
  if (value === "graph") return "process-graph";
  if (value === "runs") return "runs";
  return value || "overview";
}

function LegacyMemoryRootRedirect() {
  const { caseId = "" } = useParams();
  const location = useLocation();
  const overviewQuery = useQuery({
    queryKey: ["memory-overview", caseId, "legacy-route"],
    queryFn: () => api.getMemoryOverview(caseId),
    enabled: Boolean(caseId),
    refetchOnWindowFocus: false,
  });
  if (!caseId) return <Navigate to="/cases" replace />;
  if (overviewQuery.isLoading) return <WorkspaceLoadingFallback />;
  const params = new URLSearchParams(location.search);
  const tab = memorySegmentFromLegacyTab(params.get("tab"));
  params.delete("tab");
  const query = params.toString();
  const evidences = overviewQuery.data?.evidences ?? [];
  if (tab === "runs") return <Navigate to={appendSearch(`/cases/${caseId}/m/runs`, query)} replace />;
  if (evidences.length === 1) return <Navigate to={appendSearch(`/cases/${caseId}/m/${evidences[0].id}/${tab}`, query)} replace />;
  return <Navigate to={appendSearch(`/cases/${caseId}/m`, query)} replace />;
}

function LegacyMemoryEvidenceRedirect() {
  const { caseId = "", evidenceId = "", memoryTab = "" } = useParams();
  const location = useLocation();
  if (!caseId) return <Navigate to="/cases" replace />;
  const params = new URLSearchParams(location.search);
  const tab = memorySegmentFromLegacyTab(memoryTab || params.get("tab") || "overview");
  params.delete("tab");
  const query = params.toString();
  if (!evidenceId) return <Navigate to={appendSearch(`/cases/${caseId}/m`, query)} replace />;
  return <Navigate to={appendSearch(`/cases/${caseId}/m/${evidenceId}/${tab}`, query)} replace />;
}

function MemoryRunsPage() {
  const { caseId = "" } = useParams();
  return <MemoryWorkspace caseId={caseId} activeTab="runs" />;
}

function AddEvidenceRedirect({ expectedKind }: { expectedKind?: string }) {
  const { caseId = "" } = useParams();
  if (!caseId) return <Navigate to="/cases" replace />;
  const params = new URLSearchParams({ tab: "evidences", add_evidence: "1" });
  if (expectedKind) params.set("expected_kind", expectedKind);
  return <Navigate to={`/cases/${caseId}?${params.toString()}`} replace />;
}

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<Suspense fallback={<WorkspaceLoadingFallback />}><LoginPage /></Suspense>} />
        <Route path="/setup" element={<Suspense fallback={<WorkspaceLoadingFallback />}><SetupWizardPage /></Suspense>} />
        <Route path="*" element={
          <ProtectedRoute>
            <ActiveCaseProvider>
              <TimezoneProvider>
                <NotificationsProvider>
                  <Layout>
                    <Suspense fallback={<WorkspaceLoadingFallback />}>
                      <Routes>
                        <Route path="/" element={<Dashboard />} />
                        <Route path="/cases" element={<Cases />} />
                        <Route path="/cases/:caseId/overview" element={<CaseOverviewPage />} />
                        <Route path="/cases/:caseId/hosts" element={<CaseHostsPage />} />
                        <Route path="/cases/:caseId/search" element={<Search />} />
                        <Route path="/cases/:caseId/findings" element={<Findings />} />
                        <Route path="/cases/:caseId/timeline" element={<TimelinePage />} />
                        <Route path="/cases/:caseId/l/access/authentication" element={<LinuxAuthenticationPage />} />
                        <Route path="/cases/:caseId/l/execution/command-history" element={<CommandHistoryPage />} />
                        <Route path="/cases/:caseId/w/execution/stories" element={<CaseProcessGraphPage />} />
                        <Route path="/cases/:caseId/w/execution/command-history" element={<CommandHistoryPage />} />
                        <Route path="/cases/:caseId/artifacts" element={<ArtifactExplorer />} />
                        <Route path="/cases/:caseId/incident-timeline" element={<IncidentTimelinePage />} />
                        <Route path="/cases/:caseId/validation-matrix" element={<ValidationMatrixPage />} />
                        <Route path="/cases/:caseId/evidence" element={<NavigateToCaseTab tab="evidences" />} />
                        <Route path="/cases/:caseId/ingest" element={<NavigateToCaseTab tab="processing" />} />
                        <Route path="/cases/:caseId/detections" element={<Detections />} />
                        <Route path="/cases/:caseId/reports" element={<CaseReportsPage />} />
                        <Route path="/cases/:caseId/debug-export" element={<DebugExportPage />} />
                        <Route path="/cases/:caseId/m" element={<CaseMemoryLanding />} />
                        <Route path="/cases/:caseId/m/runs" element={<MemoryRunsPage />} />
                        <Route path="/cases/:caseId/m/:evidenceId/processes" element={<MemoryEvidencePage />} />
                        <Route path="/cases/:caseId/m/:evidenceId/process-graph" element={<MemoryEvidencePage />} />
                        <Route path="/cases/:caseId/m/:evidenceId/network" element={<MemoryEvidencePage />} />
                        <Route path="/cases/:caseId/m/:evidenceId/modules" element={<MemoryEvidencePage />} />
                        <Route path="/cases/:caseId/m/:evidenceId/handles" element={<MemoryEvidencePage />} />
                        <Route path="/cases/:caseId/m/:evidenceId/vads" element={<MemoryEvidencePage />} />
                        <Route path="/cases/:caseId/m/:evidenceId/suspicious" element={<MemoryEvidencePage />} />
                        <Route path="/cases/:caseId/m/:evidenceId/system" element={<MemoryEvidencePage />} />
                        <Route path="/cases/:caseId/m/:evidenceId/overview" element={<MemoryEvidencePage />} />
                        <Route path="/cases/:caseId/m/:evidenceId/raw" element={<MemoryEvidencePage />} />
                        <Route path="/cases/:caseId/m/:evidenceId/artifacts" element={<MemoryEvidencePage />} />
                        <Route path="/cases/:caseId/linux-authentication" element={<LegacyCaseParamRedirect suffix="/l/access/authentication" />} />
                        <Route path="/cases/:caseId/command-history" element={<LegacyCaseParamRedirect suffix="/l/execution/command-history" />} />
                        <Route path="/cases/:caseId/process-graph" element={<LegacyCaseParamRedirect suffix="/w/execution/stories" />} />
                        <Route path="/cases/:caseId/process-tree" element={<LegacyCaseParamRedirect suffix="/w/execution/stories" />} />
                        <Route path="/cases/:caseId/artifact-search" element={<LegacyCaseParamRedirect suffix="/artifacts" />} />
                        <Route path="/cases/:caseId/memory" element={<LegacyMemoryRootRedirect />} />
                        <Route path="/cases/:caseId/memory/landing" element={<LegacyMemoryRootRedirect />} />
                        <Route path="/cases/:caseId/memory/upload" element={<AddEvidenceRedirect expectedKind="memory_dump" />} />
                        <Route path="/cases/:caseId/memory/:evidenceId/:memoryTab" element={<LegacyMemoryEvidenceRedirect />} />
                        <Route path="/cases/:caseId/memory/:evidenceId" element={<LegacyMemoryEvidenceRedirect />} />
                        <Route path="/cases/:caseId/dashboard" element={<LegacyCaseParamRedirect suffix="/overview" />} />
                        <Route path="/cases/:caseId" element={<CaseDetail />} />
                        <Route path="/evidences/:evidenceId" element={<EvidenceDetail />} />
                        <Route path="/search" element={<LegacyCaseRoute suffix="/search" />} />
                        <Route path="/artifacts/explorer" element={<LegacyCaseRoute suffix="/artifacts" />} />
                        <Route path="/activity" element={<ActivityPage />} />
                        <Route path="/siem" element={<Siem />} />
                        <Route path="/timeline" element={<ActiveCaseCanonicalRedirect suffix="/timeline" />} />
                        <Route path="/process-tree" element={<ActiveCaseCanonicalRedirect suffix="/w/execution/stories" />} />
                        <Route path="/command-history" element={<ActiveCaseCanonicalRedirect suffix="/l/execution/command-history" />} />
                        <Route path="/dashboard" element={<ActiveCaseCanonicalRedirect suffix="/overview" />} />
                        <Route path="/analysis/semi-auto" element={<ActiveCaseCanonicalRedirect suffix="/findings" />} />
                        <Route path="/semi-auto" element={<ActiveCaseCanonicalRedirect suffix="/findings" />} />
                        <Route path="/rules" element={<Rules />} />
                        <Route path="/detections" element={<LegacyCaseRoute suffix="/detections" />} />
                        <Route path="/findings" element={<LegacyCaseRoute suffix="/findings" />} />
                        <Route path="/docs" element={<DocsPage />} />
                        <Route path="/docs/:slug" element={<DocsPage />} />
                        <Route path="/parser-coverage" element={<ParserCoveragePage />} />
                        <Route path="/system" element={<SystemPage />} />
                        <Route path="/system/performance" element={<SystemPage />} />
                        <Route path="/admin/users" element={<AdminUsersPage />} />
                        <Route path="/account/change-password" element={<ChangePasswordPage />} />
                        <Route path="*" element={<Navigate to="/" replace />} />
                      </Routes>
                    </Suspense>
                  </Layout>
                </NotificationsProvider>
              </TimezoneProvider>
            </ActiveCaseProvider>
          </ProtectedRoute>
        } />
      </Routes>
    </AuthProvider>
  );
}
