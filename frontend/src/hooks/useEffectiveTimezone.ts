import { useTimezonePreference } from "../context/TimezoneContext";

function browserTimezone() {
  return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
}

/**
 * Timezone the analyst reads timestamps in (top-bar TZ selector), or the
 * browser's when rendered outside the provider (isolated component tests).
 */
export function useEffectiveTimezone() {
  try {
    return useTimezonePreference().effectiveTimezone || browserTimezone();
  } catch {
    return browserTimezone();
  }
}
