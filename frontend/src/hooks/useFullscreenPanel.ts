import { useCallback, useEffect, useState } from "react";

// A panel shown over the whole window (not the browser's fullscreen mode, so
// menus, dialogs and the detail panel inside it keep working). Esc leaves it.
export function useFullscreenPanel() {
  const [fullscreen, setFullscreen] = useState(false);
  useEffect(() => {
    if (!fullscreen) return undefined;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setFullscreen(false);
    };
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    window.addEventListener("keydown", onKeyDown);
    return () => {
      window.removeEventListener("keydown", onKeyDown);
      document.body.style.overflow = previousOverflow;
    };
  }, [fullscreen]);
  const toggle = useCallback(() => setFullscreen((value) => !value), []);
  return { fullscreen, toggle };
}
