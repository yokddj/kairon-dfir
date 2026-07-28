import { useEffect, useMemo, useRef, useState, type KeyboardEvent } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  AlertTriangle,
  ChevronDown,
  ChevronRight,
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

type DomainNode = CaseCapabilitiesResponse["workbenches"][number]["domains"][number] & {
  label: string;
  capabilities: CaseCapability[];
};

type WorkbenchNode = Omit<CaseCapabilitiesResponse["workbenches"][number], "domains"> & {
  domains: DomainNode[];
};

type PersistedNavigationState = {
  workbenches?: string[];
  domains?: string[];
  selectedCapability?: string;
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

const STORAGE_PREFIX = "kairon.navigation.workspace";

function storageKey(activeCaseId: string) {
  return `${STORAGE_PREFIX}.${activeCaseId || "no-case"}`;
}

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

function routePatternMatches(route: string, activeCaseId: string, pathname: string) {
  const pattern = route.split("?", 1)[0]
    .replace("/cases/:caseId", `/cases/${activeCaseId}`)
    .replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
    .replace(/:evidenceId/g, "[^/]+");
  return new RegExp(`^${pattern}(?:$|[/?#])`).test(pathname);
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

function treeItemFocusables(root: HTMLElement | null) {
  return Array.from(root?.querySelectorAll<HTMLElement>("[data-nav-treeitem='true']") ?? []).filter((item) => !item.hasAttribute("disabled"));
}

function CapabilityItem({ capability, activeCaseId, active, onSelect }: { capability: CaseCapability; activeCaseId: string; active: boolean; onSelect: (capabilityId: string) => void }) {
  const location = useLocation();
  const target = resolveTarget(capability.route, activeCaseId, location.pathname);
  return (
    <NavLink
      to={target}
      role="treeitem"
      aria-selected={active}
      data-nav-treeitem="true"
      data-capability-id={capability.id}
      onClick={() => onSelect(capability.id)}
      className={({ isActive }) =>
        `flex items-center gap-3 rounded-2xl px-4 py-2.5 text-sm transition ${
          isActive || active ? "bg-accent/10 text-accent shadow-panel" : "text-muted hover:bg-white/5 hover:text-ink"
        }`
      }
    >
      <Gauge size={15} />
      <span className="min-w-0 flex-1 truncate">{capability.title}</span>
      <CapabilityStatus capability={capability} />
    </NavLink>
  );
}

function DomainGroup({ node, activeCaseId, expanded, activeCapabilityId, onToggle, onSelect }: { node: DomainNode; activeCaseId: string; expanded: boolean; activeCapabilityId: string; onToggle: () => void; onSelect: (capabilityId: string) => void }) {
  return (
    <div className="space-y-1">
      <button
        type="button"
        role="treeitem"
        aria-expanded={expanded}
        data-nav-treeitem="true"
        onClick={onToggle}
        className="flex w-full items-center gap-2 rounded-xl px-4 py-1.5 text-left text-[11px] font-semibold uppercase tracking-[0.12em] text-muted/80 transition hover:bg-white/5 hover:text-ink"
      >
        {expanded ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
        <span className="min-w-0 flex-1 truncate">{node.label}</span>
        <span className="text-[10px] text-muted/60">{node.capabilities.length}</span>
      </button>
      <div role="group" className={`grid overflow-hidden transition-[grid-template-rows,opacity] duration-150 ease-out ${expanded ? "grid-rows-[1fr] opacity-100" : "grid-rows-[0fr] opacity-0"}`}>
        <div className="min-h-0 space-y-1 overflow-hidden">
          {expanded ? node.capabilities.map((capability) => <CapabilityItem key={capability.id} capability={capability} activeCaseId={activeCaseId} active={capability.id === activeCapabilityId} onSelect={onSelect} />) : null}
        </div>
      </div>
    </div>
  );
}

function displayRegistryLabel(value: string) {
  return value.replace(/_/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function WorkbenchSection({ node, activeCaseId, expanded, expandedDomains, activeCapabilityId, onToggleWorkbench, onToggleDomain, onSelectCapability }: { node: WorkbenchNode; activeCaseId: string; expanded: boolean; expandedDomains: Set<string>; activeCapabilityId: string; onToggleWorkbench: () => void; onToggleDomain: (domainKey: string) => void; onSelectCapability: (capabilityId: string) => void }) {
  return (
    <section className="space-y-2" data-testid={`workbench-${node.id}`}>
      <div className="flex items-center gap-1">
        <button
          type="button"
          role="treeitem"
          aria-expanded={expanded}
          data-nav-treeitem="true"
          onClick={onToggleWorkbench}
          className="flex min-w-0 flex-1 items-center gap-2 rounded-xl px-4 py-2 text-left font-mono text-[11px] uppercase tracking-[0.18em] text-muted transition hover:bg-white/5 hover:text-ink"
        >
          {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
          <span className="min-w-0 flex-1 truncate">{node.label}</span>
          <span className="font-sans text-[10px] tracking-normal text-muted/60">{node.domains.length}</span>
        </button>
        {node.overview_route ? (
          <NavLink to={node.overview_route} aria-label={`${node.label} overview`} className={({ isActive }) => `rounded-xl px-2 py-2 text-[11px] transition ${isActive ? "text-accent" : "text-muted hover:bg-white/5 hover:text-ink"}`}>
            Overview
          </NavLink>
        ) : null}
      </div>
      <div role="group" className={`grid overflow-hidden transition-[grid-template-rows,opacity] duration-150 ease-out ${expanded ? "grid-rows-[1fr] opacity-100" : "grid-rows-[0fr] opacity-0"}`}>
        <div className="min-h-0 space-y-3 overflow-hidden">
          {expanded ? node.domains.map((domain) => {
            const domainKey = `${node.id}/${domain.id}`;
            return <DomainGroup key={domainKey} node={domain} activeCaseId={activeCaseId} expanded={expandedDomains.has(domainKey)} activeCapabilityId={activeCapabilityId} onToggle={() => onToggleDomain(domainKey)} onSelect={onSelectCapability} />;
          }) : null}
        </div>
      </div>
    </section>
  );
}

function buildWorkbenchTree(workbenches: CaseCapabilitiesResponse["workbenches"], capabilities: CaseCapability[], searchQuery: string): WorkbenchNode[] {
  const query = searchQuery.trim().toLowerCase();
  return workbenches
    .map((workbench) => {
      const visibleCapabilities = capabilities.filter((capability) => capability.visible && workbench.capability_ids.includes(capability.id));
      const workbenchMatches = !query || workbench.label.toLowerCase().includes(query) || workbench.id.toLowerCase().includes(query);
      const domains = [...workbench.domains]
        .map((domain) => {
          const domainLabel = displayRegistryLabel(domain.id);
          const domainMatches = workbenchMatches || domain.id.toLowerCase().includes(query) || domainLabel.toLowerCase().includes(query);
          const domainCapabilities = visibleCapabilities
            .filter((capability) => domain.capability_ids.includes(capability.id))
            .filter((capability) => domainMatches || capability.title.toLowerCase().includes(query) || capability.id.toLowerCase().includes(query))
            .sort((a, b) => (a.nav?.order ?? 999) - (b.nav?.order ?? 999) || a.title.localeCompare(b.title));
          return { ...domain, label: domainLabel, capabilities: domainCapabilities };
        })
        .filter((domain) => domain.capabilities.length > 0)
        .sort((a, b) => Math.min(...a.capabilities.map((capability) => capability.nav?.order ?? 999)) - Math.min(...b.capabilities.map((capability) => capability.nav?.order ?? 999)) || a.id.localeCompare(b.id));
      return { ...workbench, domains };
    })
    .filter((workbench) => workbench.domains.length > 0);
}

function activeCapabilityInTree(nodes: WorkbenchNode[], activeCaseId: string, pathname: string) {
  for (const workbench of nodes) {
    for (const domain of workbench.domains) {
      for (const capability of domain.capabilities) {
        if (routePatternMatches(capability.route, activeCaseId, pathname)) return { capability, workbenchId: workbench.id, domainKey: `${workbench.id}/${domain.id}` };
      }
    }
  }
  return null;
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
  const location = useLocation();
  const treeRef = useRef<HTMLDivElement | null>(null);
  const searchRef = useRef<HTMLInputElement | null>(null);
  const [navigationSearch, setNavigationSearch] = useState("");
  const [expandedWorkbenches, setExpandedWorkbenches] = useState<Set<string>>(() => new Set());
  const [expandedDomains, setExpandedDomains] = useState<Set<string>>(() => new Set());
  const [selectedCapabilityId, setSelectedCapabilityId] = useState("");
  const capabilitiesQuery = useQuery({
    queryKey: ["case-capabilities", activeCaseId],
    queryFn: () => api.getCaseCapabilities(activeCaseId),
    enabled: Boolean(activeCaseId),
    staleTime: 15_000,
    refetchOnWindowFocus: false,
  });
  const workbenches = capabilitiesQuery.data?.workbenches ?? [];
  const capabilities = capabilitiesQuery.data?.capabilities ?? [];
  const tree = useMemo(() => buildWorkbenchTree(workbenches, capabilities, navigationSearch), [workbenches, capabilities, navigationSearch]);
  const activeCapability = useMemo(() => activeCapabilityInTree(buildWorkbenchTree(workbenches, capabilities, ""), activeCaseId, location.pathname), [activeCaseId, capabilities, location.pathname, workbenches]);
  const effectiveSelectedCapabilityId = activeCapability?.capability.id || selectedCapabilityId;

  useEffect(() => {
    if (!activeCaseId) return;
    try {
      const parsed = JSON.parse(localStorage.getItem(storageKey(activeCaseId)) || "{}") as PersistedNavigationState;
      setExpandedWorkbenches(new Set(parsed.workbenches ?? []));
      setExpandedDomains(new Set(parsed.domains ?? []));
      setSelectedCapabilityId(parsed.selectedCapability ?? "");
    } catch {
      setExpandedWorkbenches(new Set());
      setExpandedDomains(new Set());
      setSelectedCapabilityId("");
    }
  }, [activeCaseId]);

  useEffect(() => {
    if (!activeCaseId) return;
    const state: PersistedNavigationState = {
      workbenches: Array.from(expandedWorkbenches),
      domains: Array.from(expandedDomains),
      selectedCapability: selectedCapabilityId,
    };
    localStorage.setItem(storageKey(activeCaseId), JSON.stringify(state));
  }, [activeCaseId, expandedDomains, expandedWorkbenches, selectedCapabilityId]);

  useEffect(() => {
    if (!activeCapability) return;
    setExpandedWorkbenches((current) => new Set([...current, activeCapability.workbenchId]));
    setExpandedDomains((current) => new Set([...current, activeCapability.domainKey]));
    setSelectedCapabilityId(activeCapability.capability.id);
  }, [activeCapability]);

  useEffect(() => {
    if (!navigationSearch.trim()) return;
    setExpandedWorkbenches(new Set(tree.map((workbench) => workbench.id)));
    setExpandedDomains(new Set(tree.flatMap((workbench) => workbench.domains.map((domain) => `${workbench.id}/${domain.id}`))));
  }, [navigationSearch, tree]);

  function toggleWorkbench(workbenchId: string) {
    setExpandedWorkbenches((current) => {
      const next = new Set(current);
      next.has(workbenchId) ? next.delete(workbenchId) : next.add(workbenchId);
      return next;
    });
  }

  function toggleDomain(domainKey: string) {
    setExpandedDomains((current) => {
      const next = new Set(current);
      next.has(domainKey) ? next.delete(domainKey) : next.add(domainKey);
      return next;
    });
  }

  function handleTreeKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    const items = treeItemFocusables(treeRef.current);
    const currentIndex = items.indexOf(document.activeElement as HTMLElement);
    if (event.key === "ArrowDown") {
      event.preventDefault();
      items[Math.min(items.length - 1, currentIndex + 1)]?.focus();
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      items[Math.max(0, currentIndex - 1)]?.focus();
    } else if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      (document.activeElement as HTMLElement | null)?.click();
    } else if (event.key === "Escape") {
      event.preventDefault();
      setNavigationSearch("");
      searchRef.current?.focus();
    } else if (event.key === "ArrowRight") {
      const element = document.activeElement as HTMLElement | null;
      const expanded = element?.getAttribute("aria-expanded");
      if (expanded === "false") {
        event.preventDefault();
        element?.click();
      }
    } else if (event.key === "ArrowLeft") {
      const element = document.activeElement as HTMLElement | null;
      const expanded = element?.getAttribute("aria-expanded");
      if (expanded === "true") {
        event.preventDefault();
        element?.click();
      }
    }
  }

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
          <section className="space-y-3" aria-label="Capability workspaces">
            <label className="block px-1">
              <span className="sr-only">Search navigation</span>
              <input
                ref={searchRef}
                type="search"
                value={navigationSearch}
                onChange={(event) => setNavigationSearch(event.target.value)}
                placeholder="Search navigation"
                aria-label="Search navigation"
                className="w-full rounded-2xl border border-line bg-abyss/70 px-4 py-2.5 text-sm text-ink outline-none transition placeholder:text-muted focus:border-accent/50"
              />
            </label>
            <div ref={treeRef} role="tree" aria-label="Registry navigation" onKeyDown={handleTreeKeyDown} className="space-y-4">
              {tree.map((workbench) => (
                <WorkbenchSection
                  key={workbench.id}
                  node={workbench}
                  activeCaseId={activeCaseId}
                  expanded={expandedWorkbenches.has(workbench.id)}
                  expandedDomains={expandedDomains}
                  activeCapabilityId={effectiveSelectedCapabilityId}
                  onToggleWorkbench={() => toggleWorkbench(workbench.id)}
                  onToggleDomain={toggleDomain}
                  onSelectCapability={setSelectedCapabilityId}
                />
              ))}
            </div>
            {navigationSearch.trim() && !tree.length ? <p className="px-4 text-xs text-muted">No navigation matches.</p> : null}
          </section>
        ) : null}

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
