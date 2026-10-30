import { render } from "@testing-library/react";
import ReactMarkdown from "react-markdown";
import { describe, expect, it } from "vitest";

import { isCodeBlock } from "./markdownCode";

function Rendered({ text }: { text: string }) {
  return (
    <ReactMarkdown
      components={{
        code: ({ className, children }) => <code data-block={isCodeBlock(className, children) ? "yes" : "no"}>{children}</code>,
      }}
    >
      {text}
    </ReactMarkdown>
  );
}

describe("isCodeBlock", () => {
  it("tells inline code from fenced blocks", () => {
    const { container } = render(<Rendered text={"Downloaded `factura.iso` by `mshutter`.\n\n```powershell\nGet-Process\n```\n\n```\nplain block\n```"} />);
    const codes = Array.from(container.querySelectorAll("code")).map((node) => [node.textContent?.trim(), node.getAttribute("data-block")]);
    expect(codes).toEqual([
      ["factura.iso", "no"],
      ["mshutter", "no"],
      ["Get-Process", "yes"],
      ["plain block", "yes"],
    ]);
  });
});
