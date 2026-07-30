import type { ReactNode } from "react";

// Generic Entity Page shell: it only controls structure and composition
// (ordering sections, giving each an accessible heading, omitting sections
// with no data) -- it never interprets what a section's content means.
// MemoryProcessEntityPage supplies concrete sections (Overview, Parent and
// children, Command line, ...); a future entity page would supply its own
// sections through the same slots, not a new layout.
export type EntityPageSection = {
  id: string;
  title: string;
  content: ReactNode;
};

type Props = {
  breadcrumbs?: ReactNode;
  header: ReactNode;
  // Falsy entries are omitted entirely -- callers pass `hasData && {...}` for
  // a section backed by no real data instead of rendering an empty panel.
  sections: Array<EntityPageSection | null | false | undefined>;
  investigationContext?: ReactNode;
};

export function EntityPageLayout({ breadcrumbs, header, sections, investigationContext }: Props) {
  const visibleSections = sections.filter((section): section is EntityPageSection => Boolean(section));

  return (
    <div className="space-y-5" data-testid="entity-page-layout">
      {breadcrumbs}
      <header data-testid="entity-page-header">{header}</header>
      <div className="space-y-4" data-testid="entity-page-sections">
        {visibleSections.map((section) => (
          <section
            key={section.id}
            aria-labelledby={`entity-section-${section.id}-heading`}
            data-testid={`entity-section-${section.id}`}
            className="rounded-2xl border border-line bg-panel/60 p-4"
          >
            <h2
              id={`entity-section-${section.id}-heading`}
              className="text-[11px] uppercase tracking-[0.18em] text-muted"
            >
              {section.title}
            </h2>
            <div className="mt-3">{section.content}</div>
          </section>
        ))}
      </div>
      {investigationContext ? <div data-testid="entity-page-investigation-context">{investigationContext}</div> : null}
    </div>
  );
}
