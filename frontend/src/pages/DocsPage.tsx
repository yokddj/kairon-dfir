import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { useParams } from "react-router-dom";

import { api, type DocEntry } from "../api/client";

const docSlugByHref: Record<string, string> = {
  "index.md": "index",
  "feature_map.md": "feature-map",
  "parser_backends.md": "parser-backends",
  "api_summary.md": "api-summary",
  "project_status.md": "project-status",
  "user_guide.md": "user-guide",
  "deployment.md": "deployment",
  "testing.md": "testing",
  "artifacts_matrix.md": "artifacts-matrix",
  "large_evidence.md": "large-evidence",
  "performance.md": "performance",
  "findings_correlation.md": "findings-correlation",
  "search.md": "search",
  "timeline_reports.md": "timeline-reports",
  "process_graph.md": "process-graph",
  "rules_sigma_yara.md": "rules-sigma-yara",
  "debug_export_pack.md": "debug-export-pack",
  "architecture.md": "architecture",
  "quickstart.md": "quickstart",
  "ingestion.md": "ingestion",
  "artifacts.md": "artifacts",
  "evtx.md": "evtx",
  "semi_automatic_analysis.md": "semi-automatic-analysis",
  "builtin_rules.md": "builtin-rules",
  "rule_authoring.md": "rule-authoring",
  "app_sections.md": "app-sections",
  "opensearch.md": "opensearch",
  "troubleshooting.md": "troubleshooting",
  "roadmap.md": "roadmap",
  "demo_mvp.md": "demo-mvp",
  "demo_checklist.md": "demo-checklist",
  "demo/README.md": "demo-readme",
  "demo/generic-demo-guide.md": "generic-demo-guide",
  "validation/README.md": "validation-readme",
  "validation/validation-matrix-format.md": "validation-matrix-format",
  "documentation_maintenance.md": "documentation-maintenance",
  "deployment/beta-vs-demo-mode.md": "beta-vs-demo-mode",
};

function MarkdownContent({ content, onNavigateDoc }: { content: string; onNavigateDoc: (slug: string) => void }) {
  return (
    <ReactMarkdown
      remarkPlugins={[remarkGfm]}
      components={{
        h1: ({ children }) => <h1 className="mt-2 text-3xl font-semibold text-ink">{children}</h1>,
        h2: ({ children }) => <h2 className="mt-8 border-t border-line/50 pt-6 text-2xl font-semibold text-ink">{children}</h2>,
        h3: ({ children }) => <h3 className="mt-6 text-lg font-semibold text-ink">{children}</h3>,
        p: ({ children }) => <p className="mt-3 leading-7 text-muted">{children}</p>,
        ul: ({ children }) => <ul className="mt-3 list-disc space-y-2 pl-6 text-muted">{children}</ul>,
        ol: ({ children }) => <ol className="mt-3 list-decimal space-y-2 pl-6 text-muted">{children}</ol>,
        li: ({ children }) => <li>{children}</li>,
        blockquote: ({ children }) => <blockquote className="mt-4 rounded-2xl border border-line bg-abyss/50 px-4 py-3 text-sm text-muted">{children}</blockquote>,
        code: ({ inline, children }: any) =>
          inline ? (
            <code className="rounded bg-abyss/80 px-1.5 py-0.5 font-mono text-[0.9em] text-accent">{children}</code>
          ) : (
            <code className="block overflow-x-auto rounded-2xl border border-line bg-abyss/80 p-4 font-mono text-sm text-ink">{children}</code>
          ),
        pre: ({ children }) => <pre className="mt-4">{children}</pre>,
        table: ({ children }) => (
          <div className="mt-4 overflow-x-auto">
            <table className="min-w-full border-collapse overflow-hidden rounded-2xl border border-line bg-abyss/50 text-sm">{children}</table>
          </div>
        ),
        thead: ({ children }) => <thead className="bg-panel/60 text-left">{children}</thead>,
        th: ({ children }) => <th className="border-b border-line px-3 py-2 font-mono text-[11px] uppercase tracking-[0.16em] text-accent">{children}</th>,
        td: ({ children }) => <td className="border-b border-line/50 px-3 py-2 align-top text-muted">{children}</td>,
        a: ({ href, children }) => {
          const docSlug = href ? docSlugByHref[href] : undefined;
          if (docSlug) {
            return (
              <button type="button" onClick={() => onNavigateDoc(docSlug)} className="text-accent underline underline-offset-4">
                {children}
              </button>
            );
          }
          return (
            <a href={href} className="text-accent underline underline-offset-4" target={href?.startsWith("http") ? "_blank" : undefined} rel="noreferrer">
              {children}
            </a>
          );
        },
        hr: () => <hr className="my-6 border-line/60" />,
      }}
    >
      {content}
    </ReactMarkdown>
  );
}

export default function DocsPage() {
  const { slug } = useParams();
  const [selectedSlug, setSelectedSlug] = useState(slug || "index");
  const docsQuery = useQuery({ queryKey: ["docs-catalog"], queryFn: api.listDocs, staleTime: 60_000, refetchOnWindowFocus: false });
  const docQuery = useQuery({
    queryKey: ["docs-page", selectedSlug],
    queryFn: () => api.getDoc(selectedSlug),
    enabled: Boolean(selectedSlug),
    staleTime: 60_000,
    refetchOnWindowFocus: false,
  });

  useEffect(() => {
    if (slug && slug !== selectedSlug) {
      setSelectedSlug(slug);
      return;
    }
    if (!selectedSlug && docsQuery.data?.length) {
      setSelectedSlug(docsQuery.data[0].slug);
    }
  }, [docsQuery.data, selectedSlug, slug]);

  const selectedMeta = useMemo<DocEntry | undefined>(
    () => docsQuery.data?.find((item) => item.slug === selectedSlug) ?? docsQuery.data?.[0],
    [docsQuery.data, selectedSlug],
  );

  return (
    <div className="grid gap-6 xl:grid-cols-[320px_minmax(0,1fr)]">
      <aside className="rounded-[28px] border border-line bg-panel/70 p-5 shadow-panel">
        <p className="font-mono text-xs uppercase tracking-[0.24em] text-accent">Docs</p>
        <h2 className="mt-2 text-2xl font-semibold">Manual práctico de Kairon DFIR</h2>
        <p className="mt-2 text-sm text-muted">
          Esta sección resume cómo está construida la herramienta hoy, qué soporta de verdad y cómo usar cada apartado en una investigación.
        </p>
        {docsQuery.isLoading ? <p className="mt-4 text-sm text-muted">Cargando índice de documentación…</p> : null}
        {docsQuery.error instanceof Error ? <p className="mt-4 text-sm text-danger">No se pudo cargar el índice: {docsQuery.error.message}</p> : null}
        <div className="mt-5 space-y-2">
          {(docsQuery.data ?? []).map((item) => (
            <button
              key={item.slug}
              onClick={() => setSelectedSlug(item.slug)}
              className={`w-full rounded-2xl border px-4 py-3 text-left transition ${
                item.slug === selectedSlug
                  ? "border-accent/40 bg-accent/10 text-ink"
                  : "border-line bg-abyss/60 text-muted hover:border-accent/20 hover:text-ink"
              }`}
            >
              <p className="font-medium">{item.title}</p>
              <p className="mt-1 text-xs leading-5 text-muted">{item.summary}</p>
            </button>
          ))}
        </div>
      </aside>

      <section className="rounded-[28px] border border-line bg-panel/70 p-6 shadow-panel">
        <div className="rounded-2xl border border-line bg-abyss/50 px-4 py-3">
          <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">Documento actual</p>
          <h3 className="mt-1 text-xl font-semibold">{docQuery.data?.title ?? selectedMeta?.title ?? "Documentación"}</h3>
          <p className="mt-1 text-sm text-muted">{docQuery.data?.summary ?? selectedMeta?.summary ?? "Cargando documento..."}</p>
        </div>

        {docQuery.isLoading ? <div className="mt-6 rounded-2xl border border-line bg-abyss/50 p-4 text-sm text-muted">Cargando documento…</div> : null}
        {docQuery.error instanceof Error ? <div className="mt-6 rounded-2xl border border-danger/30 bg-danger/10 p-4 text-sm text-danger">No se pudo cargar la documentación: {docQuery.error.message}</div> : null}

        {docQuery.data?.content ? (
          <article className="mt-6">
            <MarkdownContent content={docQuery.data.content} onNavigateDoc={setSelectedSlug} />
          </article>
        ) : null}
      </section>
    </div>
  );
}
