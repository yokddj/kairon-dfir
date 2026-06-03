import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, type CaseContextResponse, type DfirCase } from "../api/client";

type ActiveCaseContextValue = {
  activeCase: DfirCase | null;
  activeCaseId: string;
  selectedHost: string;
  selectedEvidenceId: string;
  caseContext: CaseContextResponse | null;
  isCaseContextLoading: boolean;
  setActiveCase: (item: DfirCase | null) => void;
  setActiveCaseId: (caseId: string) => void;
  clearActiveCase: () => void;
  setSelectedHost: (host: string) => void;
  clearSelectedHost: () => void;
  setSelectedEvidenceId: (evidenceId: string) => void;
  clearSelectedEvidenceId: () => void;
};

const STORAGE_KEYS = {
  caseId: "dfir.activeCaseId",
  host: "dfir.selectedHost",
  evidenceId: "dfir.selectedEvidenceId",
};

const ActiveCaseContext = createContext<ActiveCaseContextValue | null>(null);

export function ActiveCaseProvider({ children }: { children: ReactNode }) {
  const [activeCaseId, setActiveCaseIdState] = useState<string>(() => localStorage.getItem(STORAGE_KEYS.caseId) ?? "");
  const [selectedHost, setSelectedHostState] = useState<string>(() => localStorage.getItem(STORAGE_KEYS.host) ?? "");
  const [selectedEvidenceId, setSelectedEvidenceIdState] = useState<string>(() => localStorage.getItem(STORAGE_KEYS.evidenceId) ?? "");
  const casesQuery = useQuery({ queryKey: ["cases"], queryFn: api.listCases });
  const caseContextQuery = useQuery({
    queryKey: ["case-context", activeCaseId],
    queryFn: () => api.getCaseContext(activeCaseId),
    enabled: Boolean(activeCaseId),
    staleTime: 15_000,
    refetchOnWindowFocus: false,
  });

  useEffect(() => {
    if (activeCaseId) localStorage.setItem(STORAGE_KEYS.caseId, activeCaseId);
    else localStorage.removeItem(STORAGE_KEYS.caseId);
  }, [activeCaseId]);

  useEffect(() => {
    if (selectedHost) localStorage.setItem(STORAGE_KEYS.host, selectedHost);
    else localStorage.removeItem(STORAGE_KEYS.host);
  }, [selectedHost]);

  useEffect(() => {
    if (selectedEvidenceId) localStorage.setItem(STORAGE_KEYS.evidenceId, selectedEvidenceId);
    else localStorage.removeItem(STORAGE_KEYS.evidenceId);
  }, [selectedEvidenceId]);

  const activeCase = useMemo(
    () => (casesQuery.data ?? []).find((item) => item.id === activeCaseId) ?? null,
    [activeCaseId, casesQuery.data],
  );

  useEffect(() => {
    if (!caseContextQuery.data) return;
    if (selectedHost && selectedHost !== "unknown" && !caseContextQuery.data.hosts.some((item) => item.canonical_name === selectedHost)) {
      setSelectedHostState("");
    }
    if (selectedEvidenceId && !caseContextQuery.data.evidences.some((item) => item.id === selectedEvidenceId)) {
      setSelectedEvidenceIdState("");
    }
  }, [caseContextQuery.data, selectedEvidenceId, selectedHost]);

  const value = useMemo<ActiveCaseContextValue>(
    () => ({
      activeCase,
      activeCaseId,
      selectedHost,
      selectedEvidenceId,
      caseContext: caseContextQuery.data ?? null,
      isCaseContextLoading: caseContextQuery.isLoading,
      setActiveCase: (item) => setActiveCaseIdState(item?.id ?? ""),
      setActiveCaseId: (caseId) => setActiveCaseIdState(caseId.trim()),
      clearActiveCase: () => {
        setActiveCaseIdState("");
        setSelectedHostState("");
        setSelectedEvidenceIdState("");
      },
      setSelectedHost: (host) => setSelectedHostState(host.trim()),
      clearSelectedHost: () => setSelectedHostState(""),
      setSelectedEvidenceId: (evidenceId) => setSelectedEvidenceIdState(evidenceId.trim()),
      clearSelectedEvidenceId: () => setSelectedEvidenceIdState(""),
    }),
    [activeCase, activeCaseId, caseContextQuery.data, caseContextQuery.isLoading, selectedEvidenceId, selectedHost],
  );

  return <ActiveCaseContext.Provider value={value}>{children}</ActiveCaseContext.Provider>;
}

export function useActiveCase() {
  const context = useContext(ActiveCaseContext);
  if (!context) {
    throw new Error("useActiveCase must be used within ActiveCaseProvider");
  }
  return context;
}
