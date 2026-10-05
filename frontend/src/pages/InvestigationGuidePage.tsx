import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  Anchor,
  Clock,
  Compass,
  Download,
  ExternalLink,
  EyeOff,
  FileText,
  Globe,
  KeyRound,
  type LucideIcon,
  Package,
  Play,
  Search as SearchIcon,
  Server,
  Share2,
  Terminal,
  Trash2,
  Usb,
  UserCheck,
  Users,
} from "lucide-react";

import guide from "../../../docs/data/investigation-guide.json";
import { useActiveCase } from "../context/ActiveCaseContext";

type GuideView = { label: string; target: string; artifact_type?: string };
type GuideTopic = {
  id: string;
  platform: "windows" | "linux";
  category: string;
  icon: string;
  question: string;
  why: string;
  searches: { label: string; query: string }[];
  views: GuideView[];
  sources: { name: string; detail: string }[];
  look_for: string[];
};

const TOPICS = guide.topics as GuideTopic[];

const ICONS: Record<string, LucideIcon> = {
  play: Play,
  anchor: Anchor,
  "user-check": UserCheck,
  share: Share2,
  terminal: Terminal,
  file: FileText,
  download: Download,
  usb: Usb,
  trash: Trash2,
  "eye-off": EyeOff,
  globe: Globe,
  key: KeyRound,
  server: Server,
  package: Package,
  users: Users,
  clock: Clock,
};

const PLATFORMS = [
  { value: "all", label: "All" },
  { value: "windows", label: "Windows" },
  { value: "linux", label: "Linux" },
] as const;

/** Where a "view" of the guide lives for a case. */
export function guideViewHref(caseId: string, view: GuideView): string {
  if (view.target === "artifacts") return `/cases/${caseId}/artifact-search?artifact_type=${encodeURIComponent(view.artifact_type ?? "")}`;
  return `/cases/${caseId}/${view.target}`;
}

export function guideSearchHref(caseId: string, query: string): string {
  return `/cases/${caseId}/search?q=${encodeURIComponent(query)}`;
}

function matches(topic: GuideTopic, text: string): boolean {
  if (!text) return true;
  const haystack = [topic.question, topic.why, topic.category, ...topic.searches.flatMap((s) => [s.label, s.query]), ...topic.sources.flatMap((s) => [s.name, s.detail]), ...topic.look_for]
    .join(" ")
    .toLowerCase();
  return text
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean)
    .every((word) => haystack.includes(word));
}

function TopicCard({ topic, caseId }: { topic: GuideTopic; caseId: string | null }) {
  const Icon = ICONS[topic.icon] ?? Compass;
  return (
    <article id={topic.id} className="flex min-w-0 flex-col gap-5 rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
      <header className="flex items-start gap-4">
        <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl border border-accent/30 bg-accent/10 text-accent">
          <Icon size={20} />
        </span>
        <div className="min-w-0">
          <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted">
            {topic.category} · {topic.platform === "windows" ? "Windows" : "Linux"}
          </p>
          <h3 className="mt-1 text-lg font-semibold text-ink">{topic.question}</h3>
          <p className="mt-1 text-sm leading-6 text-muted">{topic.why}</p>
        </div>
      </header>

      <section aria-label="Searches">
        <p className="mb-2 font-mono text-[11px] uppercase tracking-[0.18em] text-accent">Search</p>
        <ul className="space-y-2">
          {topic.searches.map((search) => (
            <li key={search.query} className="flex items-center gap-3 rounded-2xl border border-line bg-abyss/60 px-3 py-2">
              <div className="min-w-0 flex-1">
                <p className="text-sm text-ink">{search.label}</p>
                <code className="mt-0.5 block truncate font-mono text-xs text-muted" title={search.query}>
                  {search.query}
                </code>
              </div>
              {caseId ? (
                <Link
                  to={guideSearchHref(caseId, search.query)}
                  aria-label={`Run: ${search.label}`}
                  className="flex shrink-0 items-center gap-1.5 rounded-xl border border-accent/40 bg-accent/10 px-3 py-1.5 text-xs text-accent hover:bg-accent/20"
                >
                  <SearchIcon size={13} /> Run
                </Link>
              ) : null}
            </li>
          ))}
        </ul>
      </section>

      {topic.views.length ? (
        <section aria-label="Open in Kairon">
          <p className="mb-2 font-mono text-[11px] uppercase tracking-[0.18em] text-accent">Open in Kairon</p>
          <div className="flex flex-wrap gap-2">
            {topic.views.map((view) =>
              caseId ? (
                <Link
                  key={view.label}
                  to={guideViewHref(caseId, view)}
                  className="flex items-center gap-1.5 rounded-full border border-line bg-abyss/70 px-3 py-1.5 text-xs text-ink hover:border-accent/40 hover:text-accent"
                >
                  {view.label} <ExternalLink size={11} />
                </Link>
              ) : (
                <span key={view.label} className="rounded-full border border-line bg-abyss/40 px-3 py-1.5 text-xs text-muted">
                  {view.label}
                </span>
              ),
            )}
          </div>
        </section>
      ) : null}

      <div className="grid gap-5 border-t border-line/60 pt-5 md:grid-cols-2">
        <section aria-label="Where it is recorded">
          <p className="mb-2 font-mono text-[11px] uppercase tracking-[0.18em] text-muted">Where it is recorded</p>
          <dl className="space-y-2">
            {topic.sources.map((source) => (
              <div key={source.name}>
                <dt className="text-sm font-medium text-ink">{source.name}</dt>
                <dd className="text-xs leading-5 text-muted">{source.detail}</dd>
              </div>
            ))}
          </dl>
        </section>
        <section aria-label="What stands out">
          <p className="mb-2 font-mono text-[11px] uppercase tracking-[0.18em] text-muted">What stands out</p>
          <ul className="space-y-1.5">
            {topic.look_for.map((item) => (
              <li key={item} className="flex gap-2 text-sm leading-6 text-muted">
                <span className="mt-2 h-1.5 w-1.5 shrink-0 rounded-full bg-warning/70" aria-hidden="true" />
                {item}
              </li>
            ))}
          </ul>
        </section>
      </div>
    </article>
  );
}

export default function InvestigationGuidePage() {
  const { activeCase } = useActiveCase();
  const [platform, setPlatform] = useState<(typeof PLATFORMS)[number]["value"]>("all");
  const [category, setCategory] = useState<string>("");
  const [text, setText] = useState("");

  const categories = useMemo(() => Array.from(new Set(TOPICS.filter((t) => platform === "all" || t.platform === platform).map((t) => t.category))), [platform]);
  const visible = TOPICS.filter((topic) => (platform === "all" || topic.platform === platform) && (!category || topic.category === category) && matches(topic, text));

  return (
    <div className="min-w-0 space-y-6">
      <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="max-w-3xl">
            <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">Investigation Guide</p>
            <h2 className="mt-2 text-2xl font-semibold text-ink">What to look for, and where</h2>
            <p className="mt-2 text-sm leading-6 text-muted">
              {guide.intro} Grouped like the{" "}
              <a href={guide.posters_url} target="_blank" rel="noreferrer" className="text-accent hover:underline">
                SANS DFIR posters
              </a>
              .
            </p>
          </div>
          <div className="rounded-2xl border border-line bg-abyss/60 px-4 py-3 text-xs text-muted">
            {activeCase ? (
              <>
                Searches run on <span className="text-ink">{activeCase.name}</span>
              </>
            ) : (
              <>Select a case to run the searches and open the views</>
            )}
          </div>
        </div>

        <div className="mt-5 flex flex-wrap items-center gap-3">
          <div className="flex rounded-2xl border border-line bg-abyss/60 p-1" role="group" aria-label="Platform">
            {PLATFORMS.map((option) => (
              <button
                key={option.value}
                type="button"
                aria-pressed={platform === option.value}
                onClick={() => {
                  setPlatform(option.value);
                  setCategory("");
                }}
                className={`rounded-xl px-4 py-1.5 text-sm ${platform === option.value ? "bg-accent/15 text-accent" : "text-muted hover:text-ink"}`}
              >
                {option.label}
              </button>
            ))}
          </div>
          <label className="flex min-w-[240px] flex-1 items-center gap-2 rounded-2xl border border-line bg-abyss/60 px-3 py-2">
            <SearchIcon size={14} className="text-muted" />
            <input
              value={text}
              onChange={(event) => setText(event.target.value)}
              placeholder="Filter: persistence, 4624, sudo, USB…"
              aria-label="Filter the guide"
              className="w-full bg-transparent text-sm text-ink outline-none placeholder:text-muted"
            />
          </label>
        </div>
        <div className="mt-3 flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() => setCategory("")}
            className={`rounded-full border px-3 py-1 text-xs ${!category ? "border-accent/40 bg-accent/10 text-accent" : "border-line text-muted hover:text-ink"}`}
          >
            All topics
          </button>
          {categories.map((name) => (
            <button
              key={name}
              type="button"
              onClick={() => setCategory(category === name ? "" : name)}
              className={`rounded-full border px-3 py-1 text-xs ${category === name ? "border-accent/40 bg-accent/10 text-accent" : "border-line text-muted hover:text-ink"}`}
            >
              {name}
            </button>
          ))}
        </div>
      </section>

      {visible.length ? (
        <div className="grid grid-cols-1 gap-5 xl:grid-cols-2">
          {visible.map((topic) => (
            <TopicCard key={topic.id} topic={topic} caseId={activeCase?.id ?? null} />
          ))}
        </div>
      ) : (
        <p className="rounded-[28px] border border-line bg-panel/70 p-6 text-sm text-muted">No topic matches this filter.</p>
      )}

      <p className="px-2 text-xs leading-5 text-muted">
        No result does not prove the activity did not happen: it may not have been logged, or the logs may not be in the evidence. Event IDs are
        reused across logs, so searches add <code className="font-mono">channel:</code> or <code className="font-mono">provider:</code> where an ID is
        ambiguous; do the same in your own searches.
      </p>
    </div>
  );
}
