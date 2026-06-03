import { Binary, Clock3, FileJson, Globe, HardDriveDownload, ShieldQuestion } from "lucide-react";

const badgeMap: Record<string, { label: string; icon: JSX.Element }> = {
  execution: { label: "execution", icon: <Clock3 size={13} /> },
  evtx: { label: "evtx", icon: <Binary size={13} /> },
  registry: { label: "registry", icon: <Binary size={13} /> },
  browser: { label: "browser", icon: <Globe size={13} /> },
  network: { label: "network", icon: <Globe size={13} /> },
  file: { label: "file", icon: <HardDriveDownload size={13} /> },
  unknown: { label: "unknown", icon: <ShieldQuestion size={13} /> },
};

export default function ArtifactBadge({ type }: { type: string }) {
  const item = badgeMap[type] ?? { label: type, icon: <FileJson size={13} /> };
  return (
    <span className="inline-flex items-center gap-1 rounded-full border border-line bg-white/5 px-2.5 py-1 font-mono text-[11px] uppercase tracking-[0.16em] text-muted">
      {item.icon}
      {item.label}
    </span>
  );
}

