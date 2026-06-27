import {
  Activity,
  BookOpen,
  Database,
  FileArchive,
  FolderSearch2,
  Gauge,
  Home,
  ListChecks,
  MemoryStick,
  ScanSearch,
  Search,
  ShieldAlert,
  Terminal,
  Waypoints,
} from "lucide-react";
import { NavLink } from "react-router-dom";
import { useActiveCase } from "../context/ActiveCaseContext";

type NavItem = {
  to: string;
  label: string;
  icon: typeof Home;
  requiresCase?: boolean;
};

type NavGroup = {
  title: string;
  items: NavItem[];
};

function SidebarLink({ item, activeCaseId }: { item: NavItem; activeCaseId: string }) {
  const target = item.requiresCase && activeCaseId ? item.to.replace(":caseId", activeCaseId) : item.to;
  const disabled = Boolean(item.requiresCase && !activeCaseId);
  const Icon = item.icon;

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
      className={({ isActive }) =>
        `flex items-center gap-3 rounded-2xl px-4 py-3 text-sm transition ${
          isActive ? "bg-accent/10 text-accent shadow-panel" : "text-muted hover:bg-white/5 hover:text-ink"
        }`
      }
    >
      <Icon size={16} />
      {item.label}
    </NavLink>
  );
}

export default function Sidebar() {
  const { activeCaseId, caseContext } = useActiveCase();
  const showValidationMatrix = Boolean(caseContext?.summary?.validation_matrix?.show_validation_matrix);
  const groups: NavGroup[] = [
    {
      title: "Case Overview",
      items: [
        { to: activeCaseId ? "/cases/:caseId/overview" : "/", label: "Investigation Home", icon: Home, requiresCase: true },
      ],
    },
    {
      title: "Investigation",
      items: [
        { to: "/cases/:caseId/search", label: "Search", icon: Search, requiresCase: true },
        { to: "/cases/:caseId/command-history", label: "Command History", icon: Terminal, requiresCase: true },
        { to: "/cases/:caseId/process-graph", label: "Execution Stories", icon: Waypoints, requiresCase: true },
        { to: "/cases/:caseId/artifacts", label: "Artifact Views", icon: FolderSearch2, requiresCase: true },
        { to: "/cases/:caseId/incident-timeline", label: "Incident Timeline", icon: Waypoints, requiresCase: true },
        ...(showValidationMatrix ? [{ to: "/cases/:caseId/validation-matrix", label: "Validation Matrix", icon: ListChecks, requiresCase: true }] : []),
      ],
    },
    {
      title: "Findings & Reports",
      items: [
        { to: "/cases/:caseId/findings", label: "Findings", icon: ShieldAlert, requiresCase: true },
        { to: "/cases/:caseId/detections", label: "Detections", icon: ShieldAlert, requiresCase: true },
        { to: "/cases/:caseId/reports", label: "Reports", icon: FileArchive, requiresCase: true },
      ],
    },
    {
      title: "Evidence",
      items: [
        { to: "/cases/:caseId/evidence", label: "Evidence & Ingest", icon: Database, requiresCase: true },
      ],
    },
    {
      title: "Memory",
      items: [
        { to: "/cases/:caseId/memory", label: "Memory Analysis", icon: MemoryStick, requiresCase: true },
      ],
    },
    {
      title: "Advanced",
      items: [
        { to: "/rules", label: "Rules", icon: ScanSearch },
        { to: "/cases/:caseId/debug-export", label: "Debug Export", icon: FileArchive, requiresCase: true },
        { to: "/activity", label: "Jobs & Activity", icon: Activity },
        { to: "/siem", label: "Diagnostics: OpenSearch Console", icon: ScanSearch },
        { to: "/system/performance", label: "System / Performance", icon: Gauge },
      ],
    },
    {
      title: "Help",
      items: [{ to: "/docs", label: "Docs", icon: BookOpen }],
    },
  ];

  return (
    <aside className="hidden min-h-screen w-64 shrink-0 overflow-y-auto border-r border-line/80 bg-panel/70 px-4 py-5 backdrop-blur lg:block">
      <div className="mb-8 flex items-center gap-3">
        <img src="/brand/kairon-dfir-mark.svg" alt="" className="h-11 w-11 rounded-2xl border border-accent/30 bg-accent/10 p-1.5" />
        <div>
          <p className="font-mono text-xs uppercase tracking-[0.22em] text-accent">Kairon DFIR</p>
          <p className="text-sm text-muted">Analyst-centered workspace</p>
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
    </aside>
  );
}
