import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Sparkles } from "lucide-react";
import { api } from "../../api/client";

type Props = {
  caseId: string;
  /** Called with the translated query string; the caller applies it to its own search box. */
  onTranslated: (query: string) => void;
};

/**
 * A question in the analyst's own language, in any language -- Search's own query
 * syntax out. Deliberately does not search or show results itself -- it hands the
 * translated query to the normal search box, so the analyst ends up in the ordinary,
 * editable, rerunnable Search experience rather than a chat answer.
 */
export default function NaturalLanguageSearchToggle({ caseId, onTranslated }: Props) {
  const statusQuery = useQuery({ queryKey: ["ai-status"], queryFn: api.getAiStatus, staleTime: 60_000 });
  const [open, setOpen] = useState(false);
  const [question, setQuestion] = useState("");

  const translateMutation = useMutation({
    mutationFn: () => api.translateNaturalLanguageSearch(caseId, question.trim()),
    onSuccess: (result) => {
      if (result.query) {
        onTranslated(result.query);
        setOpen(false);
        setQuestion("");
      }
    },
  });

  // No AI configured: render nothing. The non-AI build of Search must look
  // and behave identically without this.
  if (!statusQuery.data?.enabled) return null;

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen((current) => !current)}
        className="inline-flex items-center gap-1.5 rounded-full border border-line px-3 py-1.5 text-xs text-muted hover:border-accent/40 hover:text-ink"
      >
        <Sparkles size={13} className="text-accent" />
        {open ? "Hide plain-language search" : "Ask in plain language"}
      </button>
      {open ? (
        <div className="mt-3 rounded-2xl border border-line bg-abyss/70 p-4" data-testid="nl-search-panel">
          <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-muted">Ask in plain language</p>
          <p className="mt-1 text-xs text-muted">Describe what you're looking for, in any language; it becomes an editable query in the search box above -- nothing runs automatically.</p>
          <div className="mt-3 flex flex-wrap gap-2">
            <input
              type="text"
              value={question}
              onChange={(event) => setQuestion(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter" && question.trim() && !translateMutation.isPending) translateMutation.mutate();
              }}
              placeholder="e.g. powershell downloads on WS01 last week / descargas de powershell en WS01"
              className="min-w-[16rem] flex-1 rounded-xl border border-line bg-abyss px-3 py-2 text-sm text-ink outline-none focus:border-accent/50"
            />
            <button
              type="button"
              disabled={!question.trim() || translateMutation.isPending}
              onClick={() => translateMutation.mutate()}
              className="rounded-xl bg-accent px-4 py-2 text-sm font-semibold text-abyss disabled:opacity-50"
            >
              {translateMutation.isPending ? "Translating…" : "Translate"}
            </button>
          </div>
          {translateMutation.isSuccess && !translateMutation.data.query ? (
            <p className="mt-2 text-xs text-amber-200">That didn't read like a search -- try describing what you want to find.</p>
          ) : null}
          {translateMutation.isError ? (
            <p className="mt-2 text-xs text-danger">{translateMutation.error instanceof Error ? translateMutation.error.message : "Translation failed."}</p>
          ) : null}
        </div>
      ) : null}
    </>
  );
}
