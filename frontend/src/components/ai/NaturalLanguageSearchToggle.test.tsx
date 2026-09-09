import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import NaturalLanguageSearchToggle from "./NaturalLanguageSearchToggle";

const getAiStatusMock = vi.fn();
const translateNaturalLanguageSearchMock = vi.fn();

vi.mock("../../api/client", () => ({
  api: {
    getAiStatus: (...args: unknown[]) => getAiStatusMock(...args),
    translateNaturalLanguageSearch: (...args: unknown[]) => translateNaturalLanguageSearchMock(...args),
  },
}));

function renderToggle(onTranslated = vi.fn()) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return {
    onTranslated,
    ...render(
      <QueryClientProvider client={queryClient}>
        <NaturalLanguageSearchToggle caseId="case-1" onTranslated={onTranslated} />
      </QueryClientProvider>,
    ),
  };
}

describe("NaturalLanguageSearchToggle", () => {
  beforeEach(() => {
    getAiStatusMock.mockReset();
    translateNaturalLanguageSearchMock.mockReset();
  });

  it("renders nothing when no AI provider is configured", async () => {
    getAiStatusMock.mockResolvedValue({ enabled: false, provider: null, model: null, hosting: null });
    renderToggle();
    await waitFor(() => expect(getAiStatusMock).toHaveBeenCalled());
    expect(screen.queryByRole("button", { name: /Ask in plain language/i })).not.toBeInTheDocument();
  });

  it("translates a question and hands the query to the caller, not a results view of its own", async () => {
    getAiStatusMock.mockResolvedValue({ enabled: true, provider: "openai", model: "gpt-4", hosting: "cloud" });
    translateNaturalLanguageSearchMock.mockResolvedValue({ query: "process.name:powershell.exe host.name:WS01" });
    const user = userEvent.setup();
    const { onTranslated } = renderToggle();

    await user.click(await screen.findByRole("button", { name: /Ask in plain language/i }));
    await user.type(screen.getByPlaceholderText(/powershell downloads/i), "what did powershell do on WS01");
    await user.click(screen.getByRole("button", { name: /^Translate$/i }));

    await waitFor(() => expect(translateNaturalLanguageSearchMock).toHaveBeenCalledWith("case-1", "what did powershell do on WS01"));
    await waitFor(() => expect(onTranslated).toHaveBeenCalledWith("process.name:powershell.exe host.name:WS01"));
    // The panel closes itself once applied -- it never renders a results table.
    expect(screen.queryByTestId("nl-search-panel")).not.toBeInTheDocument();
  });

  it("says so when the question didn't read like a search, instead of applying an empty query", async () => {
    getAiStatusMock.mockResolvedValue({ enabled: true, provider: "openai", model: "gpt-4", hosting: "cloud" });
    translateNaturalLanguageSearchMock.mockResolvedValue({ query: "" });
    const user = userEvent.setup();
    const { onTranslated } = renderToggle();

    await user.click(await screen.findByRole("button", { name: /Ask in plain language/i }));
    await user.type(screen.getByPlaceholderText(/powershell downloads/i), "hello there");
    await user.click(screen.getByRole("button", { name: /^Translate$/i }));

    expect(await screen.findByText(/didn't read like a search/i)).toBeInTheDocument();
    expect(onTranslated).not.toHaveBeenCalled();
    expect(screen.getByTestId("nl-search-panel")).toBeInTheDocument();
  });

  it("surfaces a translation failure instead of failing silently", async () => {
    getAiStatusMock.mockResolvedValue({ enabled: true, provider: "openai", model: "gpt-4", hosting: "cloud" });
    translateNaturalLanguageSearchMock.mockRejectedValue(new Error("The provider rejected the request"));
    const user = userEvent.setup();
    renderToggle();

    await user.click(await screen.findByRole("button", { name: /Ask in plain language/i }));
    await user.type(screen.getByPlaceholderText(/powershell downloads/i), "anything");
    await user.click(screen.getByRole("button", { name: /^Translate$/i }));

    expect(await screen.findByText("The provider rejected the request")).toBeInTheDocument();
  });
});
