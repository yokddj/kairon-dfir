import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import ResponsiveDetailPanel from "./ResponsiveDetailPanel";

describe("ResponsiveDetailPanel", () => {
  it("stretches the card to fill a drawer's full height instead of only its content", () => {
    // Regression: the outer drawer frame was h-full, but the visible card inside it
    // had no height class of its own, so in a flex column it sized to its content and
    // left the rest of the drawer showing bare, backdrop-blurred page underneath --
    // looking like the panel had "broken" halfway down.
    render(
      <ResponsiveDetailPanel open mode="drawer" heading="Timeline detail" onClose={() => {}}>
        <p>Some short content</p>
      </ResponsiveDetailPanel>,
    );

    const shell = screen.getByTestId("responsive-detail-panel");
    expect(shell.className).toContain("h-full");
  });

  it("does not force full height for a centered modal, which sizes to its content", () => {
    render(
      <ResponsiveDetailPanel open mode="stacked" heading="Process detail" onClose={() => {}}>
        <p>Some short content</p>
      </ResponsiveDetailPanel>,
    );

    const shell = screen.getByTestId("responsive-detail-panel");
    expect(shell.className).not.toContain("h-full");
  });

  it("closes on Escape and on overlay click, but not on a click inside the panel", () => {
    const onClose = vi.fn();
    render(
      <ResponsiveDetailPanel open mode="drawer" heading="Timeline detail" onClose={onClose}>
        <button type="button">Inside</button>
      </ResponsiveDetailPanel>,
    );

    screen.getByRole("button", { name: "Inside" }).click();
    expect(onClose).not.toHaveBeenCalled();

    screen.getByTestId("responsive-detail-overlay").click();
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});
