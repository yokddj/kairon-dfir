import type { ReactNode } from "react";

type MemoryPaginationControlsProps = {
  page: number;
  totalPages: number;
  onPage: (next: number) => void;
  prevTestId: string;
  nextTestId: string;
  className?: string;
  children?: ReactNode;
};

export function MemoryPaginationControls({
  page,
  totalPages,
  onPage,
  prevTestId,
  nextTestId,
  className = "flex gap-2",
  children,
}: MemoryPaginationControlsProps) {
  return (
    <div className={className}>
      <button
        type="button"
        onClick={() => onPage(Math.max(1, page - 1))}
        disabled={page <= 1}
        className="rounded-md border border-line bg-abyss/70 px-2 py-1 disabled:opacity-50"
        data-testid={prevTestId}
      >
        Previous
      </button>
      {children}
      <button
        type="button"
        onClick={() => onPage(Math.min(totalPages, page + 1))}
        disabled={page >= totalPages}
        className="rounded-md border border-line bg-abyss/70 px-2 py-1 disabled:opacity-50"
        data-testid={nextTestId}
      >
        Next
      </button>
    </div>
  );
}
