import { Suspense, lazy } from "react";
import { Navigate, Route, Routes, useLocation, useParams } from "react-router-dom";
import Layout from "./components/Layout";
import NoActiveCaseState from "./components/NoActiveCaseState";
import { ActiveCaseProvider } from "./context/ActiveCaseContext";
import { useActiveCase } from "./context/ActiveCaseContext";
import { NotificationsProvider } from "./context/NotificationsContext";
import { TimezoneProvider } from "./context/TimezoneContext";

const Dashboard = lazy(() => import("./pages/Dashboard"));
const Cases = lazy(() => import("./pages/Cases"));
const CaseDetail = lazy(() => import("./pages/CaseDetail"));
const CaseOverviewPage = lazy(() => import("./pages/CaseOverviewPage"));
const CaseHostsPage = lazy(() => import("./pages/CaseHostsPage"));
const CaseProcessGraphPage = lazy(() => import("./pages/CaseProcessGraphPage"));
const CommandHistoryPage = lazy(() => import("./pages/CommandHistoryPage"));
const IncidentTimelinePage = lazy(() => import("./pages/IncidentTimelinePage"));
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
const DebugExportPage = lazy(() => import("./pages/DebugExportPage"));
const MemoryAnalysisPage = lazy(() => import("./pages/MemoryAnalysisPage"));
const MemoryEvidencePage = lazy(() => import("./pages/MemoryEvidencePage"));
const CaseMemoryLanding = lazy(() => import("./pages/CaseMemoryLanding"));
const MemoryUploadPage = lazy(() => import("./pages/MemoryUploadPage"));

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

function NavigateToCaseTab({ tab }: { tab: string }) {
  const { caseId = "" } = useParams();
  if (!caseId) return <Navigate to="/cases" replace />;
  return <Navigate to={`/cases/${caseId}?tab=${tab}`} replace />;
}

function LegacyActiveCaseRedirect({ suffix }: { suffix: string }) {
  const { activeCaseId } = useActiveCase();
  if (!activeCaseId) {
    return <NoActiveCaseState description="Select or create a case first to open timeline, graph and other investigation views." />;
  }
  return <Navigate to={`/cases/${activeCaseId}${suffix}`} replace />;
}

function LegacyCaseParamRedirect({ suffix, fallback = "/cases" }: { suffix: string; fallback?: string }) {
  const { caseId = "" } = useParams();
  if (!caseId) return <Navigate to={fallback} replace />;
  return <Navigate to={`/cases/${caseId}${suffix}`} replace />;
}

function CaseSearchViewRedirect({ view }: { view: "timeline" | "artifact_views" }) {
  const { caseId = "" } = useParams();
  const location = useLocation();
  if (!caseId) return <Navigate to="/cases" replace />;
  const params = new URLSearchParams(location.search);
  params.set("view", view);
  params.set("tab", view);
  if (view === "timeline" && !params.has("sort")) {
    params.set("sort", "@timestamp");
    params.set("order", "asc");
  }
  return <Navigate to={`/cases/${caseId}/search?${params.toString()}`} replace />;
}

function ActiveCaseSearchViewRedirect({ view }: { view: "timeline" | "artifact_views" }) {
  const { activeCaseId } = useActiveCase();
  const location = useLocation();
  if (!activeCaseId) {
    return <NoActiveCaseState description="Select or create a case first to open timeline and artifact views." />;
  }
  const params = new URLSearchParams(location.search);
  params.set("view", view);
  params.set("tab", view);
  if (view === "timeline" && !params.has("sort")) {
    params.set("sort", "@timestamp");
    params.set("order", "asc");
  }
  return <Navigate to={`/cases/${activeCaseId}/search?${params.toString()}`} replace />;
}

export default function App() {
  return (
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
                <Route path="/cases/:caseId/timeline" element={<CaseSearchViewRedirect view="timeline" />} />
                <Route path="/cases/:caseId/process-graph" element={<CaseProcessGraphPage />} />
                <Route path="/cases/:caseId/command-history" element={<CommandHistoryPage />} />
                <Route path="/cases/:caseId/artifact-search" element={<LegacyCaseParamRedirect suffix="/artifacts" />} />
                <Route path="/cases/:caseId/artifacts" element={<ArtifactExplorer />} />
                <Route path="/cases/:caseId/incident-timeline" element={<IncidentTimelinePage />} />
                <Route path="/cases/:caseId/validation-matrix" element={<ValidationMatrixPage />} />
                <Route path="/cases/:caseId/evidence" element={<NavigateToCaseTab tab="evidences" />} />
                <Route path="/cases/:caseId/detections" element={<Detections />} />
                <Route path="/cases/:caseId/reports" element={<CaseReportsPage />} />
                <Route path="/cases/:caseId/debug-export" element={<DebugExportPage />} />
                <Route path="/cases/:caseId/memory" element={<MemoryAnalysisPage />} />
                <Route path="/cases/:caseId/memory/landing" element={<CaseMemoryLanding />} />
                <Route path="/cases/:caseId/memory/upload" element={<MemoryUploadPage />} />
                <Route path="/cases/:caseId/memory/:evidenceId" element={<MemoryEvidencePage />} />
                <Route path="/cases/:caseId/process-tree" element={<LegacyCaseParamRedirect suffix="/process-graph" />} />
                <Route path="/cases/:caseId/dashboard" element={<LegacyCaseParamRedirect suffix="/overview" />} />
                <Route path="/cases/:caseId" element={<CaseDetail />} />
                <Route path="/evidences/:evidenceId" element={<EvidenceDetail />} />
                <Route path="/search" element={<LegacyCaseRoute suffix="/search" />} />
                <Route path="/artifacts/explorer" element={<LegacyCaseRoute suffix="/artifacts" />} />
                <Route path="/activity" element={<ActivityPage />} />
                <Route path="/siem" element={<Siem />} />
                <Route path="/timeline" element={<ActiveCaseSearchViewRedirect view="timeline" />} />
                <Route path="/process-tree" element={<LegacyActiveCaseRedirect suffix="/process-graph" />} />
                <Route path="/command-history" element={<LegacyActiveCaseRedirect suffix="/command-history" />} />
                <Route path="/dashboard" element={<LegacyActiveCaseRedirect suffix="/overview" />} />
                <Route path="/analysis/semi-auto" element={<LegacyActiveCaseRedirect suffix="/findings" />} />
                <Route path="/semi-auto" element={<LegacyActiveCaseRedirect suffix="/findings" />} />
                <Route path="/rules" element={<Rules />} />
                <Route path="/detections" element={<LegacyCaseRoute suffix="/detections" />} />
                <Route path="/findings" element={<LegacyCaseRoute suffix="/findings" />} />
                <Route path="/docs" element={<DocsPage />} />
                <Route path="/docs/:slug" element={<DocsPage />} />
                <Route path="/system" element={<SystemPage />} />
                <Route path="/system/performance" element={<SystemPage />} />
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            </Suspense>
          </Layout>
        </NotificationsProvider>
      </TimezoneProvider>
    </ActiveCaseProvider>
  );
}
