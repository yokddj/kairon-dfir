import { useCallback, useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useOptionalTimeRangeContext, type TimeRange } from "../context/TimeRangeContext";

type Options = {
  /** Mirror the window into ?time_from=&time_to= (shareable URLs). Default true. */
  syncUrl?: boolean;
  /** Extra URL params to drop whenever the window changes (e.g. "page"). */
  resetParams?: string[];
};

/**
 * The case-wide time window as seen by one page.
 *
 * - Landing with ?time_from/?time_to (a deep link, "events around this one")
 *   adopts that window as the case window.
 * - Landing without them applies the case window that is already set.
 * - Changing it here, in another page or from the top-bar chip changes it
 *   everywhere; the URL follows so the page stays shareable.
 *
 * Outside the provider it degrades to URL/local state only.
 */
export function useGlobalTimeRange(options: Options = {}) {
  const { syncUrl = true, resetParams } = options;
  const context = useOptionalTimeRangeContext();
  const [searchParams, setSearchParams] = useSearchParams();
  const urlFrom = syncUrl ? searchParams.get("time_from") ?? "" : "";
  const urlTo = syncUrl ? searchParams.get("time_to") ?? "" : "";
  const [localRange, setLocalRange] = useState<TimeRange>({ from: urlFrom, to: urlTo });
  const contextRange = context?.timeRange ?? localRange;
  const setContextRange = context?.setTimeRange ?? setLocalRange;
  const resetKey = (resetParams ?? []).join(",");

  const writeUrl = useCallback(
    (range: TimeRange, reset = true) => {
      if (!syncUrl) return;
      setSearchParams(
        (current) => {
          const next = new URLSearchParams(current);
          if (range.from) next.set("time_from", range.from);
          else next.delete("time_from");
          if (range.to) next.set("time_to", range.to);
          else next.delete("time_to");
          if (reset) for (const key of resetKey ? resetKey.split(",") : []) next.delete(key);
          return next;
        },
        { replace: true },
      );
    },
    [resetKey, setSearchParams, syncUrl],
  );

  // URL -> case window. A window carried by the URL (deep link, "events
  // around this one", back/forward) becomes the case window. A URL without
  // one never clears it -- sidebar links and pages that rebuild their params
  // from scratch carry no window -- it is written back instead, so the page
  // stays shareable. Clearing is always explicit (setTimeRange / chip).
  const processedUrl = useRef<string | null>(null);
  useEffect(() => {
    if (!syncUrl) return;
    processedUrl.current = `${urlFrom}|${urlTo}`;
    if (!urlFrom && !urlTo) {
      if (contextRange.from || contextRange.to) writeUrl(contextRange, false);
      return;
    }
    if (urlFrom !== contextRange.from || urlTo !== contextRange.to) setContextRange({ from: urlFrom, to: urlTo });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [syncUrl, urlFrom, urlTo]);

  // Case window -> URL, when the case window changes elsewhere (another
  // view, the top-bar chip). Skipped on mount: the effect above owns landing.
  const lastRange = useRef<string | null>(null);
  useEffect(() => {
    const key = `${contextRange.from}|${contextRange.to}`;
    const first = lastRange.current === null;
    if (lastRange.current === key) return;
    lastRange.current = key;
    if (!syncUrl || first) return;
    if (urlFrom === contextRange.from && urlTo === contextRange.to) return;
    writeUrl(contextRange);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [syncUrl, contextRange.from, contextRange.to]);

  // Effective window for this render: a window carried by the URL that the
  // case window has not caught up with yet wins, so the first request after
  // a deep link is already filtered; otherwise the case window applies (also
  // on a landing without URL params, before the URL is filled in).
  const urlIsNew = syncUrl && Boolean(urlFrom || urlTo) && processedUrl.current !== `${urlFrom}|${urlTo}`;
  const timeRange: TimeRange = urlIsNew ? { from: urlFrom, to: urlTo } : contextRange;

  /**
   * Set (or clear, with empty values) the case window. Pass `{ url: false }`
   * when the caller writes time_from/time_to into the URL itself in the same
   * update -- two setSearchParams calls in one tick would overwrite each other.
   */
  const setTimeRange = useCallback(
    (range: TimeRange, opts: { url?: boolean } = {}) => {
      const normalized = { from: range.from || "", to: range.to || "" };
      lastRange.current = `${normalized.from}|${normalized.to}`;
      setContextRange(normalized);
      if (opts.url !== false) writeUrl(normalized);
    },
    [setContextRange, writeUrl],
  );

  const timeRangeInvalid = Boolean(
    timeRange.from && timeRange.to && !Number.isNaN(Date.parse(timeRange.from)) && !Number.isNaN(Date.parse(timeRange.to)) && Date.parse(timeRange.from) > Date.parse(timeRange.to),
  );

  return {
    timeFrom: timeRange.from,
    timeTo: timeRange.to,
    timeRange,
    timeRangeInvalid,
    setTimeRange,
    setTimeFrom: (from: string) => setTimeRange({ from, to: timeRange.to }),
    setTimeTo: (to: string) => setTimeRange({ from: timeRange.from, to }),
    clearTimeRange: () => setTimeRange({ from: "", to: "" }),
  };
}

/**
 * The case-wide time window without URL mirroring, for panels inside a page
 * that owns its own URL (memory tabs). Needs no router; outside the provider
 * it is local state.
 */
export function useCaseTimeWindow() {
  const context = useOptionalTimeRangeContext();
  const [localRange, setLocalRange] = useState<TimeRange>({ from: "", to: "" });
  const timeRange = context?.timeRange ?? localRange;
  const setTimeRange = useCallback((range: TimeRange) => (context?.setTimeRange ?? setLocalRange)({ from: range.from || "", to: range.to || "" }), [context]);
  return {
    timeFrom: timeRange.from,
    timeTo: timeRange.to,
    setTimeRange,
    setTimeFrom: (from: string) => setTimeRange({ from, to: timeRange.to }),
    setTimeTo: (to: string) => setTimeRange({ from: timeRange.from, to }),
  };
}
