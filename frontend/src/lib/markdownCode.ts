import type { ReactNode } from "react";

/**
 * react-markdown 9 no longer tells a code component whether it is inline:
 * fenced blocks carry a language class or span several lines, inline code
 * (`factura.iso`) does neither.
 */
export function isCodeBlock(className: string | undefined, children: ReactNode): boolean {
  return /\blanguage-/.test(className ?? "") || String(children ?? "").includes("\n");
}
