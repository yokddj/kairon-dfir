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

export function toUtcForApi(localValue: string, timezone: string) {
  if (!localValue) return null;
  const hasZone = /[zZ]|[+-]\d{2}:\d{2}$/.test(localValue);
  if (hasZone) return new Date(localValue).toISOString();
  const naive = `${localValue}:00`.slice(0, 19);
  const date = new Date(new Intl.DateTimeFormat("sv-SE", {
    timeZone: timezone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(new Date(`${naive}Z`)).replace(" ", "T"));
  if (Number.isNaN(date.getTime())) {
    return new Date(localValue).toISOString();
  }
  const localAsDate = new Date(localValue);
  return Number.isNaN(localAsDate.getTime()) ? null : localAsDate.toISOString();
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
