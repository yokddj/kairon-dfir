import { useLayoutEffect, useRef, useState } from "react";

const URL_PATTERN = /(https?:\/\/[^\s<>"']+)/g;
// Punctuation that ends a sentence rather than the link.
const TRAILING = /[.,;:!?)\]]+$/;

function linkified(text: string) {
  return text.split(URL_PATTERN).map((part, index) => {
    if (index % 2 === 0) return part;
    const trailing = part.match(TRAILING)?.[0] ?? "";
    const url = trailing ? part.slice(0, -trailing.length) : part;
    return (
      <span key={index}>
        <a href={url} target="_blank" rel="noopener noreferrer" className="text-accent underline decoration-accent/40 hover:decoration-accent">
          {url}
        </a>
        {trailing}
      </span>
    );
  });
}

/**
 * A case's description: line breaks kept, long words and URLs wrapped inside its column, URLs as
 * links, and a long one folded to three lines with "Show more".
 */
export function CaseDescription({ text }: { text: string | null | undefined }) {
  const [expanded, setExpanded] = useState(false);
  const [overflowing, setOverflowing] = useState(false);
  const ref = useRef<HTMLParagraphElement>(null);

  useLayoutEffect(() => {
    const element = ref.current;
    if (!element || expanded) return;
    setOverflowing(element.scrollHeight > element.clientHeight + 1);
  }, [text, expanded]);

  if (!text) return null;
  return (
    <div className="mt-3 max-w-3xl" data-testid="case-description">
      <p ref={ref} className={`whitespace-pre-line text-sm text-muted [overflow-wrap:anywhere] ${expanded ? "" : "line-clamp-3"}`}>
        {linkified(text)}
      </p>
      {overflowing || expanded ? (
        <button type="button" onClick={() => setExpanded(!expanded)} className="mt-1 text-xs text-accent hover:underline" aria-expanded={expanded}>
          {expanded ? "Show less" : "Show more"}
        </button>
      ) : null}
    </div>
  );
}
