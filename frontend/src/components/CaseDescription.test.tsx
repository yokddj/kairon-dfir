import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CaseDescription } from "./CaseDescription";

const LONG = "Link one:\nhttps://docs.example.test/p/aGVsbG8tdGhpcy1pcy1hLXN5bnRoZXRpYy1sb29wLWxpbmstaWQtMDAwMDAwMDA?d=w00000&linkOpenTime=1000000000000.\nLink two: see https://docs.example.test/p/other";

describe("CaseDescription", () => {
  afterEach(() => vi.restoreAllMocks());

  it("keeps line breaks, wraps long words and turns URLs into links", () => {
    render(<CaseDescription text={LONG} />);
    const paragraph = screen.getByTestId("case-description").querySelector("p")!;
    expect(paragraph.className).toContain("whitespace-pre-line");
    expect(paragraph.className).toContain("[overflow-wrap:anywhere]");
    const links = screen.getAllByRole("link");
    expect(links.map((link) => link.getAttribute("href"))).toEqual([
      "https://docs.example.test/p/aGVsbG8tdGhpcy1pcy1hLXN5bnRoZXRpYy1sb29wLWxpbmstaWQtMDAwMDAwMDA?d=w00000&linkOpenTime=1000000000000",
      "https://docs.example.test/p/other",
    ]);
    expect(links[0]).toHaveAttribute("target", "_blank");
    expect(links[0]).toHaveAttribute("rel", "noopener noreferrer");
  });

  it("folds a long description and unfolds it on request", () => {
    vi.spyOn(HTMLElement.prototype, "scrollHeight", "get").mockReturnValue(200);
    vi.spyOn(HTMLElement.prototype, "clientHeight", "get").mockReturnValue(60);
    render(<CaseDescription text={LONG} />);
    const paragraph = screen.getByTestId("case-description").querySelector("p")!;
    expect(paragraph.className).toContain("line-clamp-3");
    fireEvent.click(screen.getByRole("button", { name: "Show more" }));
    expect(paragraph.className).not.toContain("line-clamp-3");
    fireEvent.click(screen.getByRole("button", { name: "Show less" }));
    expect(paragraph.className).toContain("line-clamp-3");
  });

  it("shows no toggle for a short description and nothing without one", () => {
    const { rerender, container } = render(<CaseDescription text="A short description" />);
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
    expect(screen.queryByRole("link")).not.toBeInTheDocument();
    rerender(<CaseDescription text="" />);
    expect(container.querySelector("[data-testid='case-description']")).toBeNull();
  });

  it("never links a javascript: or other non-web scheme", () => {
    render(<CaseDescription text="javascript:alert(1) and ftp://host/file" />);
    expect(screen.queryByRole("link")).not.toBeInTheDocument();
  });
});
