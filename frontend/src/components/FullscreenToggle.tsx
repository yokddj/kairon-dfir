import { Maximize2, Minimize2 } from "lucide-react";

export function FullscreenToggle({ fullscreen, onToggle, testId }: { fullscreen: boolean; onToggle: () => void; testId?: string }) {
  const label = fullscreen ? "Exit full screen" : "Full screen";
  return (
    <button
      type="button"
      onClick={onToggle}
      aria-label={label}
      aria-pressed={fullscreen}
      title={fullscreen ? "Exit full screen (Esc)" : "Full screen"}
      className="rounded-xl border border-line bg-abyss/70 px-2 py-1 text-xs"
      data-testid={testId}
    >
      {fullscreen ? <Minimize2 className="h-3.5 w-3.5" /> : <Maximize2 className="h-3.5 w-3.5" />}
    </button>
  );
}
