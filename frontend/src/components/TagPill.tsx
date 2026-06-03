export default function TagPill({ tag }: { tag: string }) {
  return <span className="rounded-full border border-amber/30 bg-amber/10 px-2 py-1 font-mono text-[11px] text-amber">{tag}</span>;
}

