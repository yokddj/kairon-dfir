import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import AiAssistantPanel from "./AiAssistantPanel";
import type { AiStatusResponse, AiStreamEvent } from "../../api/client";

const getAiStatusMock = vi.fn();
const streamCaseAiChatMock = vi.fn();
const activeCase = { activeCaseId: "case-1", activeCase: { id: "case-1", name: "Ransomware IR" } };

vi.mock("../../api/client", () => ({
  api: { getAiStatus: () => getAiStatusMock() },
  streamCaseAiChat: (...args: unknown[]) => streamCaseAiChatMock(...args),
}));

vi.mock("../../context/ActiveCaseContext", () => ({
  useActiveCase: () => activeCase,
}));

const LOCAL_STATUS: AiStatusResponse = {
  enabled: true,
  provider: "ollama",
  label: "Ollama (local)",
  model: "llama-local",
  hosting: "local",
};

function renderPanel() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <AiAssistantPanel />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  getAiStatusMock.mockResolvedValue(LOCAL_STATUS);
  streamCaseAiChatMock.mockImplementation(
    async (_caseId: string, _payload: unknown, onEvent: (event: AiStreamEvent) => void) => {
      onEvent({ type: "meta", provider: "ollama", model: "llama-local" });
      onEvent({ type: "text", text: "Check **Run keys** " });
      onEvent({ type: "text", text: "and scheduled tasks." });
    },
  );
});

describe("AiAssistantPanel", () => {
  it("stays hidden while the assistant is disabled", async () => {
    getAiStatusMock.mockResolvedValue({ enabled: false, provider: null, model: null, hosting: null });
    renderPanel();
    await waitFor(() => expect(getAiStatusMock).toHaveBeenCalled());
    expect(screen.queryByRole("button", { name: /open the ai assistant/i })).not.toBeInTheDocument();
  });

  it("streams an answer and renders it as markdown", async () => {
    const user = userEvent.setup();
    renderPanel();

    await user.click(await screen.findByRole("button", { name: /open the ai assistant/i }));
    await user.type(screen.getByLabelText(/question for the assistant/i), "any persistence?");
    await user.click(screen.getByRole("button", { name: "Send" }));

    await waitFor(() => expect(screen.getByText(/scheduled tasks/)).toBeInTheDocument());
    expect(screen.getByText("Run keys").tagName).toBe("STRONG");

    const [caseId, payload] = streamCaseAiChatMock.mock.calls[0];
    expect(caseId).toBe("case-1");
    expect(payload).toEqual({ messages: [{ role: "user", content: "any persistence?" }] });
  });

  it("shows an error in the transcript when the request fails", async () => {
    const user = userEvent.setup();
    streamCaseAiChatMock.mockRejectedValue(new Error("The API key was rejected (401)"));
    renderPanel();

    await user.click(await screen.findByRole("button", { name: /open the ai assistant/i }));
    await user.type(screen.getByLabelText(/question for the assistant/i), "hello");
    await user.click(screen.getByRole("button", { name: "Send" }));

    await waitFor(() => expect(screen.getByText(/The API key was rejected/)).toBeInTheDocument());
  });

  it("warns the analyst when the active provider is a hosted API", async () => {
    getAiStatusMock.mockResolvedValue({ ...LOCAL_STATUS, provider: "openai", label: "OpenAI", hosting: "cloud" });
    const user = userEvent.setup();
    renderPanel();

    await user.click(await screen.findByRole("button", { name: /open the ai assistant/i }));
    expect(screen.getByText(/sent to a third-party API/i)).toBeInTheDocument();
  });

  it("carries the prior turns into the next question", async () => {
    const user = userEvent.setup();
    renderPanel();

    await user.click(await screen.findByRole("button", { name: /open the ai assistant/i }));
    const box = screen.getByLabelText(/question for the assistant/i);
    await user.type(box, "first");
    await user.click(screen.getByRole("button", { name: "Send" }));
    await waitFor(() => expect(screen.getByText(/scheduled tasks/)).toBeInTheDocument());

    await user.type(box, "second");
    await user.click(screen.getByRole("button", { name: "Send" }));

    await waitFor(() => expect(streamCaseAiChatMock).toHaveBeenCalledTimes(2));
    const [, payload] = streamCaseAiChatMock.mock.calls[1];
    expect((payload as { messages: unknown[] }).messages).toEqual([
      { role: "user", content: "first" },
      { role: "assistant", content: "Check **Run keys** and scheduled tasks." },
      { role: "user", content: "second" },
    ]);
  });
});
