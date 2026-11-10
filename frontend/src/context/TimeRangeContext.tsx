import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { useActiveCase } from "./ActiveCaseContext";

/**
 * Case-wide investigation time window. Search, Timeline, Artifact Views,
 * Command History and the other event views read and write it, so a window
 * set on one screen still applies after moving to another. It is stored per
 * case (a window from one incident means nothing in another) and survives a
 * reload, like the host and evidence selectors. Values are UTC ISO instants;
 * an empty string means "open".
 */
export type TimeRange = { from: string; to: string };

type TimeRangeContextValue = {
  timeRange: TimeRange;
  setTimeRange: (range: TimeRange) => void;
  clearTimeRange: () => void;
};

const EMPTY: TimeRange = { from: "", to: "" };
const storageKey = (caseId: string) => `dfir.timeRange.${caseId}`;

function readStored(caseId: string): TimeRange {
  if (!caseId) return EMPTY;
  try {
    const parsed = JSON.parse(localStorage.getItem(storageKey(caseId)) || "null");
    if (parsed && typeof parsed === "object") {
      return { from: typeof parsed.from === "string" ? parsed.from : "", to: typeof parsed.to === "string" ? parsed.to : "" };
    }
  } catch {
    // Unreadable storage: start with an open window.
  }
  return EMPTY;
}

const TimeRangeContext = createContext<TimeRangeContextValue | null>(null);

export function TimeRangeProvider({ children }: { children: ReactNode }) {
  const { activeCaseId } = useActiveCase();
  const [state, setState] = useState<{ caseId: string; range: TimeRange }>(() => ({ caseId: activeCaseId, range: readStored(activeCaseId) }));
  // Switching case loads that case's own window.
  const range = state.caseId === activeCaseId ? state.range : readStored(activeCaseId);

  useEffect(() => {
    if (state.caseId !== activeCaseId) setState({ caseId: activeCaseId, range: readStored(activeCaseId) });
  }, [activeCaseId, state.caseId]);

  const setTimeRange = useCallback(
    (next: TimeRange) => {
      const normalized = { from: next.from || "", to: next.to || "" };
      setState({ caseId: activeCaseId, range: normalized });
      if (!activeCaseId) return;
      try {
        if (normalized.from || normalized.to) localStorage.setItem(storageKey(activeCaseId), JSON.stringify(normalized));
        else localStorage.removeItem(storageKey(activeCaseId));
      } catch {
        // Storage unavailable: the window still applies for this session.
      }
    },
    [activeCaseId],
  );

  const value = useMemo<TimeRangeContextValue>(
    () => ({ timeRange: range, setTimeRange, clearTimeRange: () => setTimeRange(EMPTY) }),
    [range, setTimeRange],
  );
  return <TimeRangeContext.Provider value={value}>{children}</TimeRangeContext.Provider>;
}

/** Null outside the provider so isolated component tests keep working. */
export function useOptionalTimeRangeContext() {
  return useContext(TimeRangeContext);
}
