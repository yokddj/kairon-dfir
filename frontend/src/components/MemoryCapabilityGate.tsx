import type { ReactNode } from "react";
import { useMemoryEnabled } from "../hooks/useMemoryEnabled";

// Wraps the memory routes: when the deployment has Memory disabled, its
// pages would only meet missing endpoints, so say so instead.
export function MemoryCapabilityGate({ children }: { children: ReactNode }) {
  const memoryEnabled = useMemoryEnabled();
  if (memoryEnabled) return <>{children}</>;
  return (
    <section className="rounded-[28px] border border-line bg-panel/70 p-8 shadow-panel">
      <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">Memory</p>
      <h2 className="mt-2 text-2xl font-semibold">Memory Analysis is not enabled</h2>
      <p className="mt-2 text-sm text-muted">This deployment runs without Memory Analysis (MEMORY_ENABLED=false). Memory images and their results are not available here.</p>
    </section>
  );
}
