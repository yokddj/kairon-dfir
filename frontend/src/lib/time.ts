export function formatTimestamp(value: unknown, timezone: string) {
  if (!value) return "No timestamp";
  const date = new Date(String(value));
  if (Number.isNaN(date.getTime())) return String(value);
  return new Intl.DateTimeFormat(undefined, {
    timeZone: timezone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(date);
}

function browserTimezone() {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  } catch {
    return "UTC";
  }
}

/** Milliseconds to add to a UTC instant to get the wall-clock time in `timezone`. */
function timezoneOffsetMs(instant: number, timezone: string) {
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone: timezone,
    hourCycle: "h23",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).formatToParts(new Date(instant));
  const get = (type: string) => Number(parts.find((part) => part.type === type)?.value ?? 0);
  const wall = Date.UTC(get("year"), get("month") - 1, get("day"), get("hour"), get("minute"), get("second"));
  return wall - Math.floor(instant / 1000) * 1000;
}

function safeTimezone(timezone?: string) {
  const candidate = timezone || browserTimezone();
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: candidate });
    return candidate;
  } catch {
    return "UTC";
  }
}

/**
 * ISO instant -> value for an <input type="datetime-local">, expressed in the
 * timezone the analyst reads timestamps in (user, case or UTC). Without a
 * timezone it falls back to the browser's, as before.
 */
export function toDateTimeLocalValue(value: string, timezone?: string) {
  if (!value) return "";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return "";
  const zone = safeTimezone(timezone);
  const wall = new Date(parsed.getTime() + timezoneOffsetMs(parsed.getTime(), zone));
  const iso = wall.toISOString();
  return parsed.getUTCSeconds() || parsed.getUTCMilliseconds() ? iso.slice(0, 19) : iso.slice(0, 16);
}

/**
 * Value of an <input type="datetime-local"> (wall-clock time in `timezone`)
 * -> UTC ISO instant for the API. A value that already carries an offset is
 * taken as is. Unparseable input is returned unchanged.
 */
export function fromDateTimeLocalValue(value: string, timezone?: string) {
  if (!value) return "";
  if (/([zZ]|[+-]\d{2}:?\d{2})$/.test(value.trim())) {
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? value : parsed.toISOString();
  }
  const match = /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,3}))?)?$/.exec(value.trim());
  if (!match) {
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? value : parsed.toISOString();
  }
  const [, y, mo, d, h, mi, sec = "0", ms = "0"] = match;
  const zone = safeTimezone(timezone);
  const wallAsUtc = Date.UTC(Number(y), Number(mo) - 1, Number(d), Number(h), Number(mi), Number(sec), Number(ms.padEnd(3, "0")));
  // Two passes so a wall time next to a DST change resolves to the offset in
  // force at the resulting instant, not at the naive guess.
  let instant = wallAsUtc - timezoneOffsetMs(wallAsUtc, zone);
  instant = wallAsUtc - timezoneOffsetMs(instant, zone);
  return new Date(instant).toISOString();
}

export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    // Fallback below.
  }

  try {
    const textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.setAttribute("readonly", "");
    textarea.style.position = "fixed";
    textarea.style.opacity = "0";
    textarea.style.pointerEvents = "none";
    document.body.appendChild(textarea);
    textarea.focus();
    textarea.select();
    textarea.setSelectionRange(0, textarea.value.length);
    const copied = document.execCommand("copy");
    document.body.removeChild(textarea);
    return copied;
  } catch {
    return false;
  }
}
