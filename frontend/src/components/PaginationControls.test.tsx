import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import PaginationControls from "./PaginationControls";

const base = { page: 1, totalPages: 200, total: 187_845, pageSize: 50, onPageChange: vi.fn(), onPageSizeChange: vi.fn() };

describe("PaginationControls", () => {
  it("says when more results match than can be paged through", () => {
    render(<PaginationControls {...base} beyondResultWindow />);
    expect(screen.getByText(/Only the first 10,000 can be paged/)).toBeInTheDocument();
    expect(screen.getByText(`${(187_845).toLocaleString()} results`)).toBeInTheDocument();
  });

  it("stays quiet when every result can be paged", () => {
    render(<PaginationControls {...base} total={120} totalPages={3} />);
    expect(screen.queryByText(/Only the first/)).not.toBeInTheDocument();
  });
});
