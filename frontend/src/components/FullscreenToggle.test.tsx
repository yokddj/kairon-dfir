import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { FullscreenToggle } from "./FullscreenToggle";
import { useFullscreenPanel } from "../hooks/useFullscreenPanel";

function Panel() {
  const { fullscreen, toggle } = useFullscreenPanel();
  return (
    <section data-testid="panel" className={fullscreen ? "fixed inset-0" : "rounded"}>
      <FullscreenToggle fullscreen={fullscreen} onToggle={toggle} />
    </section>
  );
}

describe("full screen panel", () => {
  it("enters and leaves full screen with the button", () => {
    render(<Panel />);
    fireEvent.click(screen.getByRole("button", { name: "Full screen" }));
    expect(screen.getByTestId("panel")).toHaveClass("fixed");
    expect(document.body.style.overflow).toBe("hidden");

    fireEvent.click(screen.getByRole("button", { name: "Exit full screen" }));
    expect(screen.getByTestId("panel")).not.toHaveClass("fixed");
    expect(document.body.style.overflow).toBe("");
  });

  it("leaves full screen with Esc", () => {
    render(<Panel />);
    fireEvent.click(screen.getByRole("button", { name: "Full screen" }));
    fireEvent.keyDown(window, { key: "Escape" });
    expect(screen.getByTestId("panel")).not.toHaveClass("fixed");
    expect(screen.getByRole("button", { name: "Full screen" })).toHaveAttribute("aria-pressed", "false");
  });
});
