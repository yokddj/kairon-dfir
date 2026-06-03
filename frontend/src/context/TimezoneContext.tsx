import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { useActiveCase } from "./ActiveCaseContext";

type TimezoneMode = "user" | "case" | "utc";

type TimezoneContextValue = {
  timezoneMode: TimezoneMode;
  setTimezoneMode: (mode: TimezoneMode) => void;
  userTimezone: string;
  effectiveTimezone: string;
};

const STORAGE_KEY = "dfir.timezoneMode";
const TimezoneContext = createContext<TimezoneContextValue | null>(null);

export function TimezoneProvider({ children }: { children: ReactNode }) {
  const { activeCase } = useActiveCase();
  const [timezoneMode, setTimezoneMode] = useState<TimezoneMode>(() => (localStorage.getItem(STORAGE_KEY) as TimezoneMode) || "user");
  const userTimezone = Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";

  useEffect(() => {
    localStorage.setItem(STORAGE_KEY, timezoneMode);
  }, [timezoneMode]);

  const effectiveTimezone = timezoneMode === "utc" ? "UTC" : timezoneMode === "case" ? activeCase?.timezone || userTimezone : userTimezone;

  const value = useMemo(
    () => ({
      timezoneMode,
      setTimezoneMode,
      userTimezone,
      effectiveTimezone,
    }),
    [effectiveTimezone, timezoneMode, userTimezone],
  );

  return <TimezoneContext.Provider value={value}>{children}</TimezoneContext.Provider>;
}

export function useTimezonePreference() {
  const context = useContext(TimezoneContext);
  if (!context) {
    throw new Error("useTimezonePreference must be used within TimezoneProvider");
  }
  return context;
}
