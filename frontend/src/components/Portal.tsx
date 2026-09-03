import type { ReactNode } from "react";
import { createPortal } from "react-dom";

/**
 * Renders its children into document.body instead of wherever this component
 * sits in the tree.
 *
 * A `position: fixed` modal only covers the viewport as long as none of its
 * ancestors establish a new containing block. `filter`, `backdrop-filter`,
 * `transform` and `will-change` on an ancestor all do this in modern
 * browsers -- so a modal that renders inline inside, say, a panel styled with
 * `backdrop-blur` gets clipped to that panel's box instead of the screen,
 * pushing its own footer (buttons included) outside the visible, clickable
 * area. A portal sidesteps the whole class of bug: the modal's DOM parent is
 * always <body>, so no ancestor's styling can ever contain it, today or after
 * a future style change to something that happens to render one.
 */
export default function Portal({ children }: { children: ReactNode }) {
  return createPortal(children, document.body);
}
