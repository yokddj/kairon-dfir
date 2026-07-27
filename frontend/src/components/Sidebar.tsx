import { useQuery } from "@tanstack/react-query";
import {
  AlertTriangle,
  Clock3,
  Database,
  FileArchive,
  FolderSearch2,
  Gauge,
  Home,
  KeyRound,
  ListChecks,
  LogOut,
  Search,
  ShieldAlert,
  UserCog,
  Waypoints,
} from "lucide-react";
import { NavLink, useLocation, useNavigate } from "react-router-dom";
import { api, type CaseCapabilitiesResponse, type CaseCapability } from "../api/client";
import { useActiveCase } from "../context/ActiveCaseContext";
import { useAuth } from "../context/AuthContext";

type NavItem = {
  to: string;
  label: string;
  icon: typeof Home;
  requiresCase?: boolean;
};

const INVESTIGATION_ITEMS: NavItem[] = [
  { to: "/cases/:caseId/overview", label: "Overview", icon: Home, requiresCase: true },
  { to: "/cases/:caseId/evidence", label: "Evidence", icon: Database, requiresCase: true },
  { to: "/cases/:caseId/search", label: "Search", icon: Search, requiresCase: true },
  { to: "/cases/:caseId/timeline", label: "Timeline", icon: Waypoints, requiresCase: true },
  { to: "/cases/:caseId/incident-timeline", label: "Incident Timeline", icon: Waypoints, requiresCase: true },
  { to: "/cases/:caseId/detections", label: "Detections", icon: ShieldAlert, requiresCase: true },
  { to: "/cases/:caseId/findings", label: "Findings", icon: ShieldAlert, requiresCase: true },
  { to: "/cases/:caseId/reports", label: "Reports", icon: FileArchive, requiresCase: true },
];

const CASE_TOOL_ITEMS: NavItem[] = [
  { to: "/cases/:caseId/artifacts", label: "Artifact Views", icon: FolderSearch2, requiresCase: true },
  { to: "/cases/:caseId/validation-matrix", label: "Validation Matrix", icon: ListChecks, requiresCase: true },
  { to: "/cases/:caseId/debug-export", label: "Debug Export", icon: FileArchive, requiresCase: true },
];

const READINESS_STYLES: Record<string, string> = {
  degraded: "border-amber-400/30 bg-amber-400/10 text-amber-200",
  processing: "border-sky-400/30 bg-sky-400/10 text-sky-200",
  failed: "border-rose-400/30 bg-rose-400/10 text-rose-200",
};

function activeMemoryEvidenceId(pathname: string, activeCaseId: string): string | null {
  const match = pathname.match(/^\/cases\/([^/]+)\/memory\/([^/]+)(?:\/[^/]+)?$/);
  if (!match || match[1] !== activeCaseId) return null;
  const evidenceId = match[2];
  if (evidenceId === "landing" || evidenceId === "upload") return null;
  return evidenceId;
}

function resolveTarget(to: string, activeCaseId: string, pathname: string): string {
  const baseTarget = activeCaseId ? to.replace(":caseId", activeCaseId) : to;
  const currentMemoryEvidenceId = activeMemoryEvidenceId(pathname, activeCaseId);
  if (!currentMemoryEvidenceId || !baseTarget.startsWith(`/cases/${activeCaseId}/memory?`)) return baseTarget;
  const tab = new URLSearchParams(baseTarget.split("?")[1] || "").get("tab") || "overview";
  return `/cases/${activeCaseId}/memory/${currentMemoryEvidenceId}/${tab}`;
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

function capabilityState(capability: CaseCapability): "processing" | "degraded" | "failed" | null {
  const readiness = String(capability.readiness || "").toLowerCase();
  if (readiness.includes("failed")) return "failed";
  if (readiness.includes("processing") || readiness.includes("running") || readiness.includes("pending")) return "processing";
  if (readiness.includes("degraded") || readiness.includes("error")) return "degraded";
  return null;
}

function CapabilityStatus({ capability }: { capability: CaseCapability }) {
  const state = capabilityState(capability);
  if (!state) return null;
  const Icon = state === "processing" ? Clock3 : AlertTriangle;
  return (
    <span aria-label={`${capability.title} ${state}`} className={`ml-auto inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] uppercase tracking-[0.12em] ${READINESS_STYLES[state]}`}>
      <Icon size={11} />
      {state}
    </span>
  );
}

function CapabilityItem({ capability, activeCaseId }: { capability: CaseCapability; activeCaseId: string }) {
  const location = useLocation();
  const target = resolveTarget(capability.route, activeCaseId, location.pathname);
  return (
    <NavLink
      to={target}
      className={({ isActive }) =>
        `flex items-center gap-3 rounded-2xl px-4 py-2.5 text-sm transition ${
          isActive ? "bg-accent/10 text-accent shadow-panel" : "text-muted hover:bg-white/5 hover:text-ink"
        }`
      }
    >
      <Gauge size={15} />
      <span className="min-w-0 flex-1 truncate">{capability.title}</span>
      <CapabilityStatus capability={capability} />
    </NavLink>
  );
}

function CapabilityGroup({ title, capabilities, activeCaseId }: { title: string; capabilities: CaseCapability[]; activeCaseId: string }) {
  const ordered = [...capabilities].sort((a, b) => (a.nav?.order ?? 999) - (b.nav?.order ?? 999) || a.title.localeCompare(b.title));
  return (
    <div className="space-y-1">
      <p className="px-4 text-[11px] font-semibold uppercase tracking-[0.12em] text-muted/70">{title}</p>
      {ordered.map((capability) => <CapabilityItem key={capability.id} capability={capability} activeCaseId={activeCaseId} />)}
    </div>
  );
}

function displayRegistryLabel(value: string) {
  return value.replace(/_/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function WorkbenchSection({ workbench, capabilities, activeCaseId }: { workbench: CaseCapabilitiesResponse["workbenches"][number]; capabilities: CaseCapability[]; activeCaseId: string }) {
  const visibleCapabilities = capabilities.filter((capability) => capability.visible && workbench.capability_ids.includes(capability.id));
  if (!visibleCapabilities.length) return null;
  const domains = [...workbench.domains]
    .map((domain) => ({ ...domain, capabilities: visibleCapabilities.filter((capability) => domain.capability_ids.includes(capability.id)) }))
    .filter((domain) => domain.capabilities.length > 0)
    .sort((a, b) => Math.min(...a.capabilities.map((capability) => capability.nav?.order ?? 999)) - Math.min(...b.capabilities.map((capability) => capability.nav?.order ?? 999)) || a.id.localeCompare(b.id));

  return (
    <section className="space-y-2" data-testid={`workbench-${workbench.id}`}>
      <p className="px-4 font-mono text-[11px] uppercase tracking-[0.18em] text-muted">{workbench.label}</p>
      <div className="space-y-3">
        {domains.map((domain) => <CapabilityGroup key={`${workbench.id}-${domain.id}`} title={displayRegistryLabel(domain.id)} capabilities={domain.capabilities} activeCaseId={activeCaseId} />)}
      </div>
    </section>
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
  const capabilities = capabilitiesQuery.data?.capabilities ?? [];

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
        {workbenches.map((workbench) => <WorkbenchSection key={workbench.id} workbench={workbench} capabilities={capabilities} activeCaseId={activeCaseId} />)}

        <NavigationSection title="Case Tools" items={CASE_TOOL_ITEMS} activeCaseId={activeCaseId} />
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
