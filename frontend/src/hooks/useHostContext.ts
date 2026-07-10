import { useCallback, useEffect, useMemo } from "react";
import { useSearchParams } from "react-router-dom";
import type { CaseContextHostSummary } from "../api/client";
import { useActiveCase } from "../context/ActiveCaseContext";

export function normalizeHostName(value: string | null | undefined) {
  const normalized = String(value || "").trim().toLowerCase();
  if (!normalized) return "";
  return normalized.endsWith(".local") ? normalized.slice(0, -6) : normalized;
}

export function hostMatchesName(host: CaseContextHostSummary, value: string | null | undefined) {
  const target = normalizeHostName(value);
  if (!target) return false;
  const names = [host.id, host.canonical_name, host.display_name, ...(host.aliases || []), ...(host.all_names || [])];
  return names.some((name) => normalizeHostName(name) === target);
}

export function resolveHost(hosts: CaseContextHostSummary[], hostId?: string | null, hostName?: string | null) {
  if (hostId) {
    const byId = hosts.find((host) => host.id === hostId);
    if (byId) return byId;
  }
  if (hostName) {
    return hosts.find((host) => hostMatchesName(host, hostName)) ?? null;
  }
  return null;
}

export function useHostContext() {
  const [searchParams, setSearchParams] = useSearchParams();
  const {
    caseContext,
    selectedHost,
    selectedHostId,
    setSelectedHost,
    setSelectedHostId,
    clearSelectedHost,
  } = useActiveCase();
  const hosts = caseContext?.hosts ?? [];
  const urlHostId = searchParams.get("host_id") || "";
  const urlHost = searchParams.get("host") || "";
  const resolvedHost = useMemo(
    () => resolveHost(hosts, urlHostId || selectedHostId, urlHost || selectedHost),
    [hosts, selectedHost, selectedHostId, urlHost, urlHostId],
  );
  const activeHostId = resolvedHost?.id || urlHostId || selectedHostId || "";
  const activeHost = resolvedHost?.display_name || urlHost || selectedHost || "";

  useEffect(() => {
    if (resolvedHost) {
      if (selectedHostId !== resolvedHost.id) setSelectedHostId(resolvedHost.id);
      if (selectedHost !== resolvedHost.display_name) setSelectedHost(resolvedHost.display_name);
      return;
    }
    if (urlHostId && selectedHostId !== urlHostId) setSelectedHostId(urlHostId);
    if (urlHost && selectedHost !== urlHost) setSelectedHost(urlHost);
  }, [resolvedHost, selectedHost, selectedHostId, setSelectedHost, setSelectedHostId, urlHost, urlHostId]);

  useEffect(() => {
    if (!activeHostId && !activeHost) return;
    if (urlHostId || urlHost) return;
    setSearchParams((current) => {
      const next = new URLSearchParams(current);
      if (activeHostId) next.set("host_id", activeHostId);
      if (activeHost) next.set("host", activeHost);
      return next;
    }, { replace: true });
  }, [activeHost, activeHostId, setSearchParams, urlHost, urlHostId]);

  const setHostFilter = useCallback((hostId: string) => {
    const nextHost = hosts.find((host) => host.id === hostId) ?? null;
    setSearchParams((current) => {
      const next = new URLSearchParams(current);
      if (nextHost) {
        next.set("host_id", nextHost.id);
        next.set("host", nextHost.display_name || nextHost.canonical_name);
      } else {
        next.delete("host_id");
        next.delete("host");
      }
      next.delete("selected");
      next.set("page", "1");
      return next;
    }, { replace: false });
    if (nextHost) {
      setSelectedHostId(nextHost.id);
      setSelectedHost(nextHost.display_name || nextHost.canonical_name);
    } else {
      clearSelectedHost();
    }
  }, [clearSelectedHost, hosts, setSearchParams, setSelectedHost, setSelectedHostId]);

  const clearHostFilter = useCallback(() => {
    setSearchParams((current) => {
      const next = new URLSearchParams(current);
      next.delete("host_id");
      next.delete("host");
      next.delete("selected");
      next.set("page", "1");
      return next;
    }, { replace: false });
    clearSelectedHost();
  }, [clearSelectedHost, setSearchParams]);

  const scopedParams = useCallback((params?: URLSearchParams) => {
    const next = new URLSearchParams(params);
    if (activeHostId) next.set("host_id", activeHostId);
    if (activeHost) next.set("host", activeHost);
    return next;
  }, [activeHost, activeHostId]);

  const withHostScope = useCallback((to: string) => {
    if (!activeHostId && !activeHost) return to;
    const [path, query = ""] = to.split("?");
    const params = scopedParams(new URLSearchParams(query));
    const suffix = params.toString();
    return suffix ? `${path}?${suffix}` : path;
  }, [activeHost, activeHostId, scopedParams]);

  return {
    activeHost,
    activeHostId,
    activeHostSummary: resolvedHost,
    hasHostFilter: Boolean(activeHostId || activeHost),
    setHostFilter,
    clearHostFilter,
    scopedParams,
    withHostScope,
    hostMatchesName: (value: string | null | undefined) => resolvedHost ? hostMatchesName(resolvedHost, value) : normalizeHostName(value) === normalizeHostName(activeHost),
  };
}
