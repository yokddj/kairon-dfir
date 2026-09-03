import { useEffect, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Bot,
  CalendarPlus,
  Clock,
  FileWarning,
  Loader2,
  Maximize2,
  Minimize2,
  Plus,
  Search,
  Send,
  Square,
  Trash2,
  X,
} from "lucide-react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { api, streamCaseAiChat, type AiChatMessage, type TimelineBookmark } from "../../api/client";
import CreateFindingDialog from "../CreateFindingDialog";
import type { FindingPrefill } from "../../lib/findingPrefill";
import { useActiveCase } from "../../context/ActiveCaseContext";
import { useNotifications } from "../../context/NotificationsContext";

/**
 * Event ids the assistant actually cited, pulled from its own citation links
 * rather than re-deriving them from tool calls: the model is instructed (see
 * the system prompt) to cite by relaying a tool-provided open_in_search URL
 * verbatim, so scraping that URL shape is the same information the analyst
 * already sees rendered as a link -- not a separate, potentially divergent
 * source of truth.
 */
const CITATION_EVENT_ID_PATTERN = /\/search\?q=event_id%3A([^&)\s]+)/g;
const CITATION_EVENT_ID_IN_URL = /\/search\?q=event_id%3A([^&)\s]+)/;
const MARKDOWN_LINK_PATTERN = /\[([^\]]+)\]\(([^)]+)\)/g;

type Citation = { id: string; label: string };

/** Every distinct cited event, paired with the link text the analyst sees. */
function citedEvents(markdown: string): Citation[] {
  const seen = new Map<string, string>();
  for (const [, label, url] of markdown.matchAll(MARKDOWN_LINK_PATTERN)) {
    const match = url.match(CITATION_EVENT_ID_IN_URL);
    if (!match) continue;
    try {
      const id = decodeURIComponent(match[1]);
      if (!seen.has(id)) seen.set(id, label);
    } catch {
      // A malformed percent-encoding here means a broken link, not a usable id.
    }
  }
  return [...seen.entries()].map(([id, label]) => ({ id, label }));
}

function citedEventIds(markdown: string): string[] {
  return citedEvents(markdown).map((citation) => citation.id);
}

/**
 * Panel sizes. The assistant quotes queries and event tables, which do not fit
 * a chat bubble, so the analyst picks how much room it gets. The choice is kept
 * per browser because it is a workspace preference, not case data.
 */
const SIZES = {
  compact: "h-[min(60vh,480px)] w-[min(92vw,380px)]",
  regular: "h-[min(78vh,620px)] w-[min(92vw,440px)]",
  large: "h-[min(88vh,900px)] w-[min(96vw,720px)]",
  full: "inset-4 h-auto w-auto",
} as const;

type PanelSize = keyof typeof SIZES;

const SIZE_ORDER: PanelSize[] = ["compact", "regular", "large", "full"];
const SIZE_STORAGE_KEY = "kairon.ai.panelSize";

function loadSize(): PanelSize {
  try {
    const stored = localStorage.getItem(SIZE_STORAGE_KEY);
    if (stored && stored in SIZES) return stored as PanelSize;
  } catch {
    // Private windows and blocked storage are fine; fall back to the default.
  }
  return "regular";
}

/** What the assistant looked up for one answer, shown above it. */
type Lookup = { tool: string; detail: string };

type Turn = AiChatMessage & { error?: boolean; notice?: string; lookups?: Lookup[] };

const SUGGESTIONS = [
  "Is there any suspicious persistence on this host?",
  "Were any files downloaded from the internet?",
  "Summarise what evidence is loaded and what is still missing.",
];

/** The lookups the assistant ran, so a claim can be traced back to a query. */
function Lookups({ items }: { items: Lookup[] }) {
  if (!items.length) return null;
  return (
    <ul className="mb-2 space-y-1 border-b border-line/50 pb-2">
      {items.map((item, index) => (
        <li key={index} className="flex items-start gap-1.5 text-[11px] text-muted">
          <Search size={11} className="mt-0.5 shrink-0 text-accent/70" />
          <span className="min-w-0">
            <span className="text-ink/80">{item.tool}</span>
            {item.detail ? <span className="break-words"> · {item.detail}</span> : null}
          </span>
        </li>
      ))}
    </ul>
  );
}

/** Answers arrive as markdown; render it compactly inside the bubble. */
function AnswerMarkdown({ content }: { content: string }) {
  return (
    <ReactMarkdown
      remarkPlugins={[remarkGfm]}
      components={{
        p: ({ children }) => <p className="mb-2 last:mb-0 leading-relaxed">{children}</p>,
        ul: ({ children }) => <ul className="mb-2 list-disc space-y-1 pl-4 last:mb-0">{children}</ul>,
        ol: ({ children }) => <ol className="mb-2 list-decimal space-y-1 pl-4 last:mb-0">{children}</ol>,
        strong: ({ children }) => <strong className="font-semibold text-ink">{children}</strong>,
        h1: ({ children }) => <p className="mb-1 font-semibold text-ink">{children}</p>,
        h2: ({ children }) => <p className="mb-1 font-semibold text-ink">{children}</p>,
        h3: ({ children }) => <p className="mb-1 font-semibold text-ink">{children}</p>,
        code: ({ inline, children }: any) =>
          inline ? (
            <code className="rounded bg-black/40 px-1 py-0.5 font-mono text-[0.85em] text-accent">{children}</code>
          ) : (
            <code className="my-2 block overflow-x-auto rounded-xl border border-line bg-black/40 p-2 font-mono text-[11px] text-ink">
              {children}
            </code>
          ),
        pre: ({ children }) => <>{children}</>,
        a: ({ href, children }) => (
          <a href={href} className="text-accent underline underline-offset-2" target="_blank" rel="noreferrer">
            {children}
          </a>
        ),
      }}
    >
      {content}
    </ReactMarkdown>
  );
}

/**
 * Add-to-timeline draft, kept minimal and matching the same category/
 * importance/note shape TimelinePage's own bookmark dialog already uses --
 * this is not a new feature, just a second door into the one that exists.
 * Deliberately no title/summary field: the backend always derives those from
 * the real event (see create_key_event), so the entry is never the model's
 * paraphrase, only the citation label shown while picking which one to add.
 */
type TimelineDraft = {
  eventId: string;
  label: string;
  category: TimelineBookmark["category"];
  importance: TimelineBookmark["importance"];
  note: string;
};

function AddKeyEventDialog({
  draft,
  onChange,
  onCancel,
  onConfirm,
  pending,
}: {
  draft: TimelineDraft;
  onChange: (next: TimelineDraft) => void;
  onCancel: () => void;
  onConfirm: () => void;
  pending: boolean;
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-abyss/70 p-4 backdrop-blur-sm">
      <div className="w-full max-w-md rounded-[28px] border border-line bg-panel p-6 shadow-panel" role="dialog" aria-modal="true" aria-label="Add to timeline">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Add to timeline</p>
            <h3 className="mt-2 truncate text-lg font-semibold" title={draft.label}>{draft.label}</h3>
          </div>
          <button type="button" onClick={onCancel} className="rounded-full border border-line bg-abyss/70 p-2 text-muted" aria-label="Cancel">
            <X size={16} />
          </button>
        </div>
        <div className="mt-4 grid gap-3 sm:grid-cols-2">
          <label className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm">
            <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Category</span>
            <select
              value={draft.category}
              onChange={(event) => onChange({ ...draft, category: event.target.value as TimelineBookmark["category"] })}
              className="w-full bg-transparent outline-none"
            >
              {(["execution", "download", "detection", "persistence", "network", "cleanup", "other"] as TimelineBookmark["category"][]).map((value) => (
                <option key={value} value={value}>{value}</option>
              ))}
            </select>
          </label>
          <label className="rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm">
            <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Importance</span>
            <select
              value={draft.importance}
              onChange={(event) => onChange({ ...draft, importance: event.target.value as TimelineBookmark["importance"] })}
              className="w-full bg-transparent outline-none"
            >
              {(["low", "medium", "high", "critical"] as TimelineBookmark["importance"][]).map((value) => (
                <option key={value} value={value}>{value}</option>
              ))}
            </select>
          </label>
        </div>
        <label className="mt-3 block rounded-2xl border border-line bg-abyss/80 px-4 py-3 text-sm">
          <span className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Note</span>
          <textarea
            value={draft.note}
            onChange={(event) => onChange({ ...draft, note: event.target.value })}
            rows={3}
            placeholder="Why this belongs on the timeline"
            className="w-full resize-none bg-transparent outline-none"
          />
        </label>
        <div className="mt-4 flex justify-end gap-2">
          <button type="button" onClick={onCancel} className="rounded-full border border-line bg-abyss/70 px-4 py-2 text-sm text-muted">
            Cancel
          </button>
          <button
            type="button"
            onClick={onConfirm}
            disabled={pending}
            className="rounded-full border border-accent/40 bg-accent/15 px-4 py-2 text-sm text-accent transition hover:bg-accent/25 disabled:opacity-50"
          >
            {pending ? "Adding..." : "Add to timeline"}
          </button>
        </div>
      </div>
    </div>
  );
}

export default function AiAssistantPanel() {
  // Read the selected host from context rather than useHostContext: that hook
  // writes host_id/host into the URL, and a panel mounted on every page must
  // not rewrite the address bar of screens that have nothing to do with hosts.
  const { activeCaseId, activeCase, selectedHost } = useActiveCase();
  const { notify } = useNotifications();
  const activeHost = selectedHost || "";
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [size, setSize] = useState<PanelSize>(loadSize);
  const [showHistory, setShowHistory] = useState(false);
  const [findingPrefill, setFindingPrefill] = useState<FindingPrefill | null>(null);
  const [timelineDraft, setTimelineDraft] = useState<TimelineDraft | null>(null);
  const [addingToTimeline, setAddingToTimeline] = useState(false);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const [turns, setTurns] = useState<Turn[]>([]);
  const [conversationId, setConversationId] = useState<string | null>(null);
  const [input, setInput] = useState("");
  const [streaming, setStreaming] = useState(false);
  const abortRef = useRef<AbortController | null>(null);
  const scrollRef = useRef<HTMLDivElement | null>(null);

  const statusQuery = useQuery({
    queryKey: ["ai-status"],
    queryFn: api.getAiStatus,
    staleTime: 60_000,
    refetchOnWindowFocus: false,
  });
  const status = statusQuery.data;

  const historyQuery = useQuery({
    queryKey: ["ai-conversations", activeCaseId],
    queryFn: () => api.listAiConversations(activeCaseId!),
    enabled: Boolean(activeCaseId) && open && showHistory,
    staleTime: 10_000,
  });

  useEffect(() => {
    const node = scrollRef.current;
    if (!node) return;
    // scrollTo is absent in jsdom, and smooth scrolling is a nicety here.
    if (typeof node.scrollTo === "function") node.scrollTo({ top: node.scrollHeight, behavior: "smooth" });
    else node.scrollTop = node.scrollHeight;
  }, [turns, open]);

  // A conversation is about one case; switching cases starts a new one.
  useEffect(() => {
    abortRef.current?.abort();
    setTurns([]);
    setConversationId(null);
    setShowHistory(false);
  }, [activeCaseId]);

  useEffect(() => () => abortRef.current?.abort(), []);

  if (!activeCaseId || !status?.enabled) return null;

  const ask = async (question: string) => {
    const trimmed = question.trim();
    if (!trimmed || streaming) return;

    const history: AiChatMessage[] = [
      ...turns.filter((turn) => !turn.error).map(({ role, content }) => ({ role, content })),
      { role: "user", content: trimmed },
    ];
    setTurns((current) => [...current, { role: "user", content: trimmed }, { role: "assistant", content: "" }]);
    setInput("");
    setStreaming(true);

    const controller = new AbortController();
    abortRef.current = controller;

    const patchLast = (update: (turn: Turn) => Turn) =>
      setTurns((current) => current.map((turn, index) => (index === current.length - 1 ? update(turn) : turn)));

    try {
      await streamCaseAiChat(
        activeCaseId,
        {
          messages: history,
          conversation_id: conversationId,
          // Without this the assistant has to ask which machine we mean.
          active_host: activeHost || null,
        },
        (event) => {
          if (event.type === "conversation" && event.conversation_id) {
            setConversationId(event.conversation_id);
          } else if (event.type === "text" && event.text) {
            patchLast((turn) => ({ ...turn, content: turn.content + event.text }));
          } else if (event.type === "notice" && event.tool) {
            // A lookup: keep every one, so the answer shows its working.
            const detail = String(
              (event.arguments?.query as string) ||
                (event.arguments?.host as string) ||
                "",
            );
            patchLast((turn) => ({
              ...turn,
              lookups: [...(turn.lookups ?? []), { tool: event.tool!, detail }],
            }));
          } else if (event.type === "notice" && event.text) {
            patchLast((turn) => ({ ...turn, notice: event.text }));
          } else if (event.type === "error" && event.text) {
            patchLast((turn) => ({ ...turn, content: turn.content || event.text!, error: !turn.content }));
          }
        },
        controller.signal,
      );
    } catch (error) {
      if (!controller.signal.aborted) {
        const message = error instanceof Error ? error.message : "The assistant failed to answer";
        patchLast((turn) => ({ ...turn, content: turn.content || message, error: !turn.content }));
      }
    } finally {
      setStreaming(false);
      abortRef.current = null;
      patchLast((turn) =>
        turn.role === "assistant" && !turn.content
          ? { ...turn, content: "The assistant returned nothing.", error: true }
          : turn,
      );
      queryClient.invalidateQueries({ queryKey: ["ai-conversations", activeCaseId] });
    }
  };

  const openFindingDialogFor = (turnIndex: number) => {
    const turn = turns[turnIndex];
    if (!turn?.content) return;
    const question = [...turns.slice(0, turnIndex)].reverse().find((item) => item.role === "user")?.content ?? "";
    const eventIds = citedEventIds(turn.content);
    setFindingPrefill({
      title: question ? `Investigate: ${question.slice(0, 150)}` : "Assistant finding",
      body: turn.content,
      severity: "medium",
      status: "draft",
      event_ids: eventIds,
      source_view: "ai_assistant",
      source_label: status?.label ?? status?.provider ?? "AI assistant",
      // The question, not the answer, goes here: source_summary is meant to
      // say what prompted the finding, while the answer is already the body.
      source_summary: question ? question.slice(0, 4000) : undefined,
      source_snapshot_json: {
        conversation_id: conversationId,
        provider: status?.provider ?? null,
        model: status?.model ?? null,
        question: question || null,
        answer: turn.content.slice(0, 4000),
        lookups: turn.lookups ?? [],
      },
    });
  };

  const confirmAddToTimeline = async () => {
    if (!timelineDraft || !activeCaseId) return;
    setAddingToTimeline(true);
    try {
      await api.createTimelineKeyEvent(activeCaseId, {
        event_id: timelineDraft.eventId,
        category: timelineDraft.category,
        importance: timelineDraft.importance,
        note: timelineDraft.note.trim() || undefined,
      });
      notify({ title: "Added to timeline", description: timelineDraft.label, tone: "success" });
      setTimelineDraft(null);
    } catch (error) {
      notify({
        title: "Could not add to timeline",
        description: error instanceof Error ? error.message : "The event could not be added.",
        tone: "error",
      });
    } finally {
      setAddingToTimeline(false);
    }
  };

  const startNewConversation = () => {
    abortRef.current?.abort();
    setTurns([]);
    setConversationId(null);
    setShowHistory(false);
  };

  const cycleSize = () => {
    const next = SIZE_ORDER[(SIZE_ORDER.indexOf(size) + 1) % SIZE_ORDER.length];
    setSize(next);
    try {
      localStorage.setItem(SIZE_STORAGE_KEY, next);
    } catch {
      // Not being able to remember the size is not worth failing over.
    }
  };

  const openConversation = async (id: string) => {
    abortRef.current?.abort();
    setHistoryError(null);
    try {
      const detail = await api.getAiConversation(activeCaseId, id);
      setTurns(
        detail.messages.map((message) => ({
          role: message.role === "assistant" ? "assistant" : "user",
          content: message.content,
          lookups: (message.lookups ?? []).map((lookup) => ({
            tool: lookup.tool,
            detail: String((lookup.arguments?.query as string) || (lookup.arguments?.host as string) || ""),
          })),
        })),
      );
      setConversationId(id);
      setShowHistory(false);
    } catch (error) {
      // Silence here reads as "the click did nothing", which is the worst
      // possible feedback. Say what failed and leave the list open to retry.
      setHistoryError(
        error instanceof Error ? error.message : "That conversation could not be opened.",
      );
    }
  };

  const removeConversation = async (id: string) => {
    setHistoryError(null);
    try {
      await api.deleteAiConversation(activeCaseId, id);
      if (id === conversationId) startNewConversation();
      queryClient.invalidateQueries({ queryKey: ["ai-conversations", activeCaseId] });
    } catch (error) {
      setHistoryError(
        error instanceof Error ? error.message : "That conversation could not be deleted.",
      );
    }
  };

  if (!open) {
    return (
      <button
        type="button"
        onClick={() => setOpen(true)}
        aria-label="Open the AI assistant"
        className="fixed bottom-6 right-6 z-40 flex items-center gap-2 rounded-full border border-accent/40 bg-panel px-4 py-3 text-sm text-accent shadow-panel transition hover:bg-accent/10"
      >
        <Bot size={16} /> Ask the assistant
      </button>
    );
  }

  return (
    <aside
      role="complementary"
      aria-label="AI assistant"
      className={`fixed z-40 flex flex-col rounded-2xl border border-line bg-panel/95 shadow-panel backdrop-blur ${
        size === "full" ? SIZES.full : `bottom-6 right-6 ${SIZES[size]}`
      }`}
    >
      <header className="flex items-start justify-between gap-2 border-b border-line/80 px-4 py-3">
        <div className="min-w-0">
          <p className="flex items-center gap-2 text-sm font-semibold text-ink">
            <Bot size={15} className="text-accent" /> Case assistant
          </p>
          <p className="truncate text-[11px] text-muted">
            {activeCase?.name ?? activeCaseId}
            {activeHost ? ` · ${activeHost}` : ""} · {status.label ?? status.provider} / {status.model}
          </p>
        </div>
        <div className="flex shrink-0 items-center gap-0.5">
          <button
            type="button"
            onClick={cycleSize}
            aria-label={`Resize the assistant (currently ${size})`}
            title={`Size: ${size} — click to change`}
            className="rounded-lg p-1 text-muted transition hover:text-ink"
          >
            {size === "full" ? <Minimize2 size={16} /> : <Maximize2 size={16} />}
          </button>
          <button
            type="button"
            onClick={startNewConversation}
            aria-label="New conversation"
            title="New conversation"
            className="rounded-lg p-1 text-muted transition hover:text-ink"
          >
            <Plus size={16} />
          </button>
          <button
            type="button"
            onClick={() => setShowHistory((value) => !value)}
            aria-label="Past conversations"
            title="Past conversations"
            aria-pressed={showHistory}
            className={`rounded-lg p-1 transition hover:text-ink ${showHistory ? "text-accent" : "text-muted"}`}
          >
            <Clock size={16} />
          </button>
          <button
            type="button"
            onClick={() => setOpen(false)}
            aria-label="Close the AI assistant"
            className="rounded-lg p-1 text-muted transition hover:text-ink"
          >
            <X size={16} />
          </button>
        </div>
      </header>

      {status.hosting === "cloud" ? (
        <p className="border-b border-line/80 bg-amber-500/5 px-4 py-2 text-[11px] text-amber-200">
          Questions and a summary of this case are sent to a third-party API.
        </p>
      ) : null}

      {showHistory ? (
        <div className="flex-1 overflow-y-auto px-3 py-3">
          <p className="px-1 pb-2 text-[11px] uppercase tracking-wide text-muted">Past conversations</p>
          {historyError ? (
            <p role="alert" className="mb-2 rounded-xl border border-danger/40 bg-danger/5 px-2 py-1.5 text-[11px] text-danger">
              {historyError}
            </p>
          ) : null}
          {historyQuery.isLoading ? (
            <p className="px-1 text-xs text-muted">Loading…</p>
          ) : (historyQuery.data?.conversations.length ?? 0) === 0 ? (
            <p className="px-1 text-xs text-muted">No conversations saved for this case yet.</p>
          ) : (
            <ul className="space-y-1">
              {historyQuery.data?.conversations.map((conversation) => (
                <li key={conversation.id} className="group flex items-center gap-1">
                  <button
                    type="button"
                    onClick={() => openConversation(conversation.id)}
                    className="min-w-0 flex-1 rounded-xl px-2 py-2 text-left transition hover:bg-accent/10"
                  >
                    <span className="block truncate text-xs text-ink">{conversation.title}</span>
                    <span className="block text-[10px] text-muted">
                      {conversation.message_count} messages
                      {conversation.updated_at
                        ? ` · ${new Date(conversation.updated_at).toLocaleString()}`
                        : ""}
                    </span>
                  </button>
                  <button
                    type="button"
                    onClick={() => removeConversation(conversation.id)}
                    aria-label={`Delete conversation: ${conversation.title}`}
                    className="rounded-lg p-1.5 text-muted opacity-0 transition hover:text-danger focus:opacity-100 group-hover:opacity-100"
                  >
                    <Trash2 size={13} />
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      ) : (
      <div
        ref={scrollRef}
        className={`flex-1 space-y-3 overflow-y-auto px-4 py-3 ${
          size === "large" || size === "full" ? "text-[13px]" : ""
        }`}
      >
        {turns.length === 0 ? (
          <div className="space-y-3">
            <p className="text-xs text-muted">
              The assistant can search this case&rsquo;s events, persistence entries, findings and
              timeline, and will show you the queries behind each answer.
              {activeHost ? ` Questions default to ${activeHost}.` : ""}
            </p>
            <div className="space-y-2">
              {SUGGESTIONS.map((suggestion) => (
                <button
                  key={suggestion}
                  type="button"
                  onClick={() => ask(suggestion)}
                  className="w-full rounded-xl border border-line/70 px-3 py-2 text-left text-xs text-muted transition hover:border-accent/40 hover:text-ink"
                >
                  {suggestion}
                </button>
              ))}
            </div>
          </div>
        ) : null}

        {turns.map((turn, index) => (
          <div
            key={index}
            className={
              turn.role === "user"
                ? "ml-6 rounded-2xl bg-accent/10 px-3 py-2 text-sm text-ink"
                : `mr-2 rounded-2xl border px-3 py-2 text-sm ${
                    turn.error ? "border-danger/40 bg-danger/5 text-danger" : "border-line/70 text-ink"
                  }`
            }
          >
            {turn.role === "assistant" && turn.lookups?.length ? (
              <Lookups items={turn.lookups} />
            ) : null}
            {turn.content ? (
              turn.role === "assistant" && !turn.error ? (
                <AnswerMarkdown content={turn.content} />
              ) : (
                turn.content
              )
            ) : streaming && index === turns.length - 1 ? (
              <Loader2 size={14} className="animate-spin text-muted" />
            ) : null}
            {turn.notice ? <span className="mt-1 block text-[11px] text-amber-300">{turn.notice}</span> : null}
            {turn.role === "assistant" && !turn.error && turn.content && !(streaming && index === turns.length - 1) ? (
              <div className="mt-2 flex flex-wrap items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => openFindingDialogFor(index)}
                  className="flex items-center gap-1.5 rounded-lg border border-line/60 px-2 py-1 text-[11px] text-muted transition hover:border-accent/40 hover:text-ink"
                >
                  <FileWarning size={12} /> Create finding from this answer
                </button>
                {citedEvents(turn.content).map((citation) => (
                  <button
                    key={citation.id}
                    type="button"
                    onClick={() =>
                      setTimelineDraft({ eventId: citation.id, label: citation.label, category: "other", importance: "medium", note: "" })
                    }
                    title={`Add "${citation.label}" to the case timeline`}
                    className="flex max-w-[220px] items-center gap-1.5 rounded-lg border border-line/60 px-2 py-1 text-[11px] text-muted transition hover:border-accent/40 hover:text-ink"
                  >
                    <CalendarPlus size={12} className="shrink-0" />
                    <span className="truncate">Timeline: {citation.label}</span>
                  </button>
                ))}
              </div>
            ) : null}
          </div>
        ))}
      </div>
      )}

      <form
        onSubmit={(event) => {
          event.preventDefault();
          ask(input);
        }}
        className="border-t border-line/80 p-3"
      >
        <div className="flex items-end gap-2">
          <textarea
            value={input}
            onChange={(event) => setInput(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter" && !event.shiftKey) {
                event.preventDefault();
                ask(input);
              }
            }}
            rows={2}
            placeholder="Ask about this case..."
            aria-label="Question for the assistant"
            className="min-w-0 flex-1 resize-none rounded-xl border border-line bg-black/30 px-3 py-2 text-sm text-ink outline-none focus:border-accent/60"
          />
          {streaming ? (
            <button
              type="button"
              onClick={() => abortRef.current?.abort()}
              aria-label="Stop generating"
              className="rounded-xl border border-line px-3 py-2 text-muted transition hover:text-ink"
            >
              <Square size={15} />
            </button>
          ) : (
            <button
              type="submit"
              disabled={!input.trim()}
              aria-label="Send"
              className="rounded-xl bg-accent/15 px-3 py-2 text-accent transition hover:bg-accent/25 disabled:opacity-40"
            >
              <Send size={15} />
            </button>
          )}
        </div>
        <p className="mt-2 text-[11px] text-muted">
          Analysis support, not evidence. Verify every claim against the artifacts.
        </p>
      </form>
      {activeCaseId ? (
        <CreateFindingDialog
          open={Boolean(findingPrefill)}
          onClose={() => setFindingPrefill(null)}
          caseId={activeCaseId}
          prefill={findingPrefill}
          onCreated={() => setFindingPrefill(null)}
        />
      ) : null}
      {timelineDraft ? (
        <AddKeyEventDialog
          draft={timelineDraft}
          onChange={setTimelineDraft}
          onCancel={() => setTimelineDraft(null)}
          onConfirm={confirmAddToTimeline}
          pending={addingToTimeline}
        />
      ) : null}
    </aside>
  );
}
