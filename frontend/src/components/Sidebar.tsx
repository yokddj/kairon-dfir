import {
  Activity,
  BookOpen,
  Database,
  FileArchive,
  FolderSearch2,
  Gauge,
  HardDrive,
  Home,
  KeyRound,
  ListChecks,
  LogOut,
  MemoryStick,
  Network,
  ScanSearch,
  Search,
  ShieldAlert,
  Terminal,
  UserCog,
  Waypoints,
} from "lucide-react";
import { NavLink, useLocation, useNavigate } from "react-router-dom";
import { useActiveCase } from "../context/ActiveCaseContext";
import { useAuth } from "../context/AuthContext";

// Investigation-stage tag for each destination -- preparation for the
// future stage-based navigation redesign (see the Phase-1 UX review), not
// yet wired into rendering. Two existing regression tests
// ("does not remove the Memory section when no memory evidence exists" in
// Sidebar.test.tsx, and the family/status-table coverage in
// MemoryAnalysisPage.test.tsx) document that collapsing or conditionally
// hiding this navigation was tried before and reverted, so this phase adds
// only this metadata layer and makes no rendering change.
type InvestigationStage = "overview" | "upload" | "prepare" | "analyze" | "investigate" | "report" | "tools";

type NavItem = {
  to: string;
  label: string;
  icon: typeof Home;
  requiresCase?: boolean;
  stage?: InvestigationStage;
};

const MEMORY_TAB_BY_LABEL: Record<string, string> = {
  "Memory Overview": "overview",
  Processes: "processes",
  "Process Graph": "graph",
  Network: "network",
  "Modules & DLLs": "modules",
  Handles: "handles",
  "Suspicious Memory": "suspicious",
  VADs: "vads",
  System: "system",
  Runs: "runs",
  "Raw Observations": "raw",
};

function activeMemoryEvidenceId(pathname: string, activeCaseId: string): string | null {
  const match = pathname.match(/^\/cases\/([^/]+)\/memory\/([^/]+)(?:\/[^/]+)?$/);
  if (!match || match[1] !== activeCaseId) return null;
  const evidenceId = match[2];
  if (evidenceId === "landing" || evidenceId === "upload") return null;
  return evidenceId;
}

type NavGroup = {
  title: string;
  items: NavItem[];
};

function SidebarLink({ item, activeCaseId }: { item: NavItem; activeCaseId: string }) {
  const location = useLocation();
  const memoryTab = MEMORY_TAB_BY_LABEL[item.label];
  const currentMemoryEvidenceId = activeMemoryEvidenceId(location.pathname, activeCaseId);
  const baseTarget = item.requiresCase && activeCaseId ? item.to.replace(":caseId", activeCaseId) : item.to;
  const target = memoryTab && activeCaseId && currentMemoryEvidenceId
    ? `/cases/${activeCaseId}/memory/${currentMemoryEvidenceId}/${memoryTab}`
    : baseTarget;
  const disabled = Boolean(item.requiresCase && !activeCaseId);
  const Icon = item.icon;

  const isActive = (() => {
    if (disabled) return false;
    const targetPath = target.split("?")[0];
    if (!location.pathname.includes("/memory") || !memoryTab) return location.pathname === targetPath;
    const parts = location.pathname.split("/").filter(Boolean);
    const currentTab = parts[4] || new URLSearchParams(location.search).get("tab") || "overview";
    return currentTab === memoryTab && location.pathname.startsWith(`/cases/${activeCaseId}/memory`);
  })();

  if (disabled) {
    return (
      <div
        aria-disabled="true"
        data-disabled="true"
        title="Select or create a case first."
        className="cursor-not-allowed rounded-2xl px-4 py-3 text-sm text-muted/45"
      >
        <div className="flex items-center gap-3">
          <Icon size={16} />
          <span>{item.label}</span>
        </div>
        <p className="mt-1 pl-7 text-[11px] text-muted/55">Select or create a case first.</p>
      </div>
    );
  }

  return (
    <NavLink
      to={target}
      className={`flex items-center gap-3 rounded-2xl px-4 py-3 text-sm transition ${
        isActive ? "bg-accent/10 text-accent shadow-panel" : "text-muted hover:bg-white/5 hover:text-ink"
      }`}
    >
      <Icon size={16} />
      {item.label}
    </NavLink>
  );
}

export default function Sidebar() {
  const { activeCaseId, caseContext } = useActiveCase();
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const showValidationMatrix = Boolean(caseContext?.summary?.validation_matrix?.show_validation_matrix);
  const groups: NavGroup[] = [
    {
      title: "Case Overview",
      items: [
        { to: activeCaseId ? "/cases/:caseId/overview" : "/", label: "Investigation Home", icon: Home, requiresCase: true, stage: "overview" },
      ],
    },
    {
      title: "Investigation",
      items: [
        { to: "/cases/:caseId/evidence", label: "Evidence & Ingest", icon: Database, requiresCase: true, stage: "upload" },
        { to: "/cases/:caseId/search", label: "Search", icon: Search, requiresCase: true, stage: "investigate" },
        { to: "/cases/:caseId/command-history", label: "Command History", icon: Terminal, requiresCase: true, stage: "investigate" },
        { to: "/cases/:caseId/process-graph", label: "Execution Stories", icon: Waypoints, requiresCase: true, stage: "analyze" },
        { to: "/cases/:caseId/artifacts", label: "Artifact Views", icon: FolderSearch2, requiresCase: true, stage: "analyze" },
        { to: "/cases/:caseId/incident-timeline", label: "Incident Timeline", icon: Waypoints, requiresCase: true, stage: "investigate" },
        ...(showValidationMatrix ? [{ to: "/cases/:caseId/validation-matrix", label: "Validation Matrix", icon: ListChecks, requiresCase: true, stage: "tools" as InvestigationStage }] : []),
      ],
    },
    {
      title: "Findings & Reports",
      items: [
        { to: "/cases/:caseId/findings", label: "Findings", icon: ShieldAlert, requiresCase: true, stage: "investigate" },
        { to: "/cases/:caseId/detections", label: "Detections", icon: ShieldAlert, requiresCase: true, stage: "investigate" },
        { to: "/cases/:caseId/reports", label: "Reports", icon: FileArchive, requiresCase: true, stage: "report" },
      ],
    },
    {
      title: "Memory",
      items: [
        { to: "/cases/:caseId/memory?tab=overview", label: "Memory Overview", icon: MemoryStick, requiresCase: true, stage: "analyze" },
        { to: "/cases/:caseId/memory?tab=processes", label: "Processes", icon: Terminal, requiresCase: true, stage: "analyze" },
        { to: "/cases/:caseId/memory?tab=graph", label: "Process Graph", icon: Waypoints, requiresCase: true, stage: "analyze" },
        { to: "/cases/:caseId/memory?tab=network", label: "Network", icon: Network, requiresCase: true, stage: "analyze" },
        { to: "/cases/:caseId/memory?tab=modules", label: "Modules & DLLs", icon: HardDrive, requiresCase: true, stage: "analyze" },
        { to: "/cases/:caseId/memory?tab=handles", label: "Handles", icon: HardDrive, requiresCase: true, stage: "analyze" },
        { to: "/cases/:caseId/memory?tab=suspicious", label: "Suspicious Memory", icon: ShieldAlert, requiresCase: true, stage: "analyze" },
        { to: "/cases/:caseId/memory?tab=vads", label: "VADs", icon: HardDrive, requiresCase: true, stage: "analyze" },
        { to: "/cases/:caseId/memory?tab=system", label: "System", icon: Gauge, requiresCase: true, stage: "analyze" },
        { to: "/cases/:caseId/memory?tab=runs", label: "Runs", icon: ListChecks, requiresCase: true, stage: "analyze" },
        { to: "/cases/:caseId/memory?tab=raw", label: "Raw Observations", icon: HardDrive, requiresCase: true, stage: "analyze" },
      ],
    },
    {
      title: "Advanced",
      items: [
        { to: "/rules", label: "Rules", icon: ScanSearch, stage: "tools" },
        { to: "/cases/:caseId/debug-export", label: "Debug Export", icon: FileArchive, requiresCase: true, stage: "tools" },
        { to: "/activity", label: "Activity Center", icon: Activity, stage: "tools" },
        { to: "/siem", label: "Diagnostics: OpenSearch Console", icon: ScanSearch, stage: "tools" },
        { to: "/system/performance", label: "System / Performance", icon: Gauge, stage: "tools" },
      ],
    },
    {
      title: "Help",
      items: [{ to: "/docs", label: "Docs", icon: BookOpen, stage: "tools" }],
    },
  ];

  return (
    <aside className="hidden min-h-screen w-64 shrink-0 overflow-y-auto border-r border-line/80 bg-panel/70 px-4 py-5 backdrop-blur lg:block">
      <div className="mb-8 flex items-center gap-3">
        <img src="/brand/kairon-dfir-mark.svg" alt="" className="h-11 w-11 rounded-2xl border border-accent/30 bg-accent/10 p-1.5" />
        <div>
          <p className="font-mono text-xs uppercase tracking-[0.22em] text-accent">Kairon DFIR</p>
          <p className="text-sm text-muted">Investigation workspace</p>
        </div>
      </div>

      <nav className="space-y-5">
        <NavLink
          to="/cases"
          className={({ isActive }) =>
            `flex items-center gap-3 rounded-2xl px-4 py-3 text-sm transition ${
              isActive ? "bg-accent/10 text-accent shadow-panel" : "text-muted hover:bg-white/5 hover:text-ink"
            }`
          }
        >
          <Database size={16} />
          Cases
        </NavLink>

        {groups.map((group) => (
          <section key={group.title} className="space-y-2">
            <p className="px-4 font-mono text-[11px] uppercase tracking-[0.18em] text-muted">{group.title}</p>
            <div className="space-y-1">
              {group.items.map((item) => (
                <SidebarLink key={`${group.title}-${item.to}`} item={item} activeCaseId={activeCaseId} />
              ))}
            </div>
          </section>
        ))}
      </nav>

      <div className="mt-auto border-t border-line/80 pt-5">
        <div className="mb-4 flex items-center gap-3 rounded-2xl px-4">
          <div className="flex h-8 w-8 items-center justify-center rounded-full bg-accent/10 text-xs font-bold text-accent">
            {user?.username?.[0]?.toUpperCase() || "?"}
          </div>
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm text-ink">{user?.display_name || user?.username || "User"}</p>
            <p className="truncate text-[11px] text-muted">{user?.is_admin ? "Admin" : "User"}</p>
          </div>
        </div>
        {user?.is_admin && (
          <NavLink
            to="/admin/users"
            className={({ isActive }) =>
              `flex items-center gap-3 rounded-2xl px-4 py-3 text-sm transition ${
                isActive ? "bg-accent/10 text-accent shadow-panel" : "text-muted hover:bg-white/5 hover:text-ink"
              }`
            }
          >
            <UserCog size={16} />
            Users
          </NavLink>
        )}
        <NavLink
          to="/account/change-password"
          className={({ isActive }) =>
            `flex items-center gap-3 rounded-2xl px-4 py-3 text-sm transition ${
              isActive ? "bg-accent/10 text-accent shadow-panel" : "text-muted hover:bg-white/5 hover:text-ink"
            }`
          }
        >
          <KeyRound size={16} />
          Change Password
        </NavLink>
        <button
          onClick={async () => {
            await logout();
            navigate("/login");
          }}
          className="flex w-full items-center gap-3 rounded-2xl px-4 py-3 text-sm text-muted transition hover:bg-white/5 hover:text-ink"
        >
          <LogOut size={16} />
          Sign Out
        </button>
      </div>
    </aside>
  );
}
