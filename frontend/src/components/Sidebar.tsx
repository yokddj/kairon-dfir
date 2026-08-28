import {
  BookOpen,
  Database,
  FileArchive,
  Fingerprint,
  FolderSearch2,
  GitCommitHorizontal,
  Home,
  KeyRound,
  LogOut,
  Search,
  ShieldAlert,
  UserCog,
  Waypoints,
} from "lucide-react";
import { NavLink, useLocation, useNavigate } from "react-router-dom";
import { api, type CaseCapabilitiesResponse } from "../api/client";
import { useActiveCase } from "../context/ActiveCaseContext";
import { useAuth } from "../context/AuthContext";
import { resolveSurfaceIcon } from "../lib/surfaceIcons";
import { useQuery } from "@tanstack/react-query";

type NavItem = {
  to: string;
  label: string;
  icon: typeof Home;
  requiresCase?: boolean;
  description?: string;
};

const INVESTIGATION_ITEMS: NavItem[] = [
  { to: "/cases/:caseId/overview", label: "Overview", icon: Home, requiresCase: true },
  { to: "/cases/:caseId/evidence", label: "Evidence", icon: Database, requiresCase: true },
  { to: "/cases/:caseId/host-information", label: "Host Information", icon: Fingerprint, requiresCase: true },
  { to: "/cases/:caseId/search", label: "Search", icon: Search, requiresCase: true },
  { to: "/cases/:caseId/artifacts", label: "Artifact Views", icon: FolderSearch2, requiresCase: true },
  {
    to: "/cases/:caseId/timeline",
    label: "Timeline",
    icon: Waypoints,
    requiresCase: true,
    description: "Raw, broad event timeline across every indexed artifact -- use this for open-ended exploration.",
  },
  {
    to: "/cases/:caseId/incident-timeline",
    label: "Incident Timeline",
    icon: GitCommitHorizontal,
    requiresCase: true,
    description: "Curated chronology for reporting: high-signal findings, marked events, command history and detections -- noisy raw artifacts excluded.",
  },
  { to: "/cases/:caseId/detections", label: "Detections", icon: ShieldAlert, requiresCase: true },
  { to: "/cases/:caseId/findings", label: "Findings", icon: ShieldAlert, requiresCase: true },
  { to: "/cases/:caseId/reports", label: "Reports", icon: FileArchive, requiresCase: true },
];

function activeMemoryEvidenceId(pathname: string, activeCaseId: string): string | null {
  const match = pathname.match(/^\/cases\/([^/]+)\/(?:memory|m)\/([^/]+)(?:\/[^/]+)?$/);
  if (!match || match[1] !== activeCaseId) return null;
  const evidenceId = match[2];
  if (evidenceId === "landing" || evidenceId === "upload") return null;
  return evidenceId;
}

function resolveTarget(to: string, activeCaseId: string, pathname: string): string {
  const baseTarget = activeCaseId ? to.replace(":caseId", activeCaseId) : to;
  const currentMemoryEvidenceId = activeMemoryEvidenceId(pathname, activeCaseId);
  if (baseTarget.includes(":evidenceId")) {
    return currentMemoryEvidenceId ? baseTarget.replace(":evidenceId", currentMemoryEvidenceId) : `/cases/${activeCaseId}/m`;
  }
  return baseTarget;
}

function SidebarLink({ item, activeCaseId }: { item: NavItem; activeCaseId: string }) {
  const location = useLocation();
  const disabled = Boolean(item.requiresCase && !activeCaseId);
  const target = disabled ? item.to : resolveTarget(item.to, activeCaseId, location.pathname);
  const Icon = item.icon;

  if (disabled) {
    return (
      <div aria-disabled="true" data-disabled="true" title="Select or create a case first." className="cursor-not-allowed rounded-2xl px-4 py-3 text-sm text-muted/45">
        <div className="flex items-center gap-3">
          <Icon size={16} />
          <span>{item.label}</span>
        </div>
      </div>
    );
  }

  return (
    <NavLink
      to={target}
      title={item.description}
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

// One row per Investigation Surface (Navigation RFC Tier 1 entry point).
// The row navigates straight to the surface's Surface Home
// (workbench.overview_route, already case-scoped by the backend) -- no
// domain/capability depth is rendered here; that lives inside the Surface
// Home page itself. Default (non-`end`) NavLink matching already marks this
// row active both on the Surface Home itself and on any deeper route that
// belongs to that surface (e.g. /w/execution/stories under /w), since
// overview_route is always a strict path-segment prefix of every route the
// registry declares for that surface.
function SurfaceRow({ workbench }: { workbench: CaseCapabilitiesResponse["workbenches"][number] }) {
  if (!workbench.overview_route) return null;
  const Icon = resolveSurfaceIcon(workbench.icon);
  return (
    <NavLink
      to={workbench.overview_route}
      data-testid={`surface-${workbench.id}`}
      className={({ isActive }) =>
        `flex items-center gap-3 rounded-2xl px-4 py-3 text-sm transition ${
          isActive ? "bg-accent/10 text-accent shadow-panel" : "text-muted hover:bg-white/5 hover:text-ink"
        }`
      }
    >
      <Icon size={16} />
      {workbench.label}
    </NavLink>
  );
}

function NavigationSection({ title, items, activeCaseId }: { title: string; items: NavItem[]; activeCaseId: string }) {
  return (
    <section className="space-y-2">
      <p className="px-4 font-mono text-[11px] uppercase tracking-[0.18em] text-muted">{title}</p>
      <div className="space-y-1">
        {items.map((item) => <SidebarLink key={`${title}-${item.to}`} item={item} activeCaseId={activeCaseId} />)}
      </div>
    </section>
  );
}

export default function Sidebar() {
  const { activeCaseId } = useActiveCase();
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const capabilitiesQuery = useQuery({
    queryKey: ["case-capabilities", activeCaseId],
    queryFn: () => api.getCaseCapabilities(activeCaseId),
    enabled: Boolean(activeCaseId),
    staleTime: 15_000,
    refetchOnWindowFocus: false,
  });
  const workbenches = capabilitiesQuery.data?.workbenches ?? [];

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

        <NavigationSection title="Investigation" items={INVESTIGATION_ITEMS} activeCaseId={activeCaseId} />

        {activeCaseId && capabilitiesQuery.isLoading ? <p className="px-4 text-xs text-muted" role="status">Loading workbenches...</p> : null}
        {activeCaseId && capabilitiesQuery.isError ? <p className="px-4 text-xs text-danger" role="alert">Capability registry unavailable.</p> : null}
        {activeCaseId && workbenches.length ? (
          <section className="space-y-2" aria-label="Investigation Surfaces">
            <p className="px-4 font-mono text-[11px] uppercase tracking-[0.18em] text-muted">Investigation Surfaces</p>
            <div className="space-y-1">
              {workbenches.map((workbench) => <SurfaceRow key={workbench.id} workbench={workbench} />)}
            </div>
          </section>
        ) : null}
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
          to="/docs"
          className={({ isActive }) =>
            `flex items-center gap-3 rounded-2xl px-4 py-3 text-sm transition ${
              isActive ? "bg-accent/10 text-accent shadow-panel" : "text-muted hover:bg-white/5 hover:text-ink"
            }`
          }
        >
          <BookOpen size={16} />
          Docs
        </NavLink>
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
