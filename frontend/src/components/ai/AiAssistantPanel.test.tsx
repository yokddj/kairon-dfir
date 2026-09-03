import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import AiAssistantPanel from "./AiAssistantPanel";
import type { AiStatusResponse, AiStreamEvent } from "../../api/client";

const getAiStatusMock = vi.fn();
const streamCaseAiChatMock = vi.fn();
const listAiConversationsMock = vi.fn();
const getAiConversationMock = vi.fn();
const deleteAiConversationMock = vi.fn();
const createFindingMock = vi.fn();
const activeCase = {
  activeCaseId: "case-1",
  activeCase: { id: "case-1", name: "Ransomware IR" },
  selectedHost: "WS-01",
};

vi.mock("../../api/client", () => ({
  api: {
    getAiStatus: () => getAiStatusMock(),
    listAiConversations: (...args: unknown[]) => listAiConversationsMock(...args),
    getAiConversation: (...args: unknown[]) => getAiConversationMock(...args),
    deleteAiConversation: (...args: unknown[]) => deleteAiConversationMock(...args),
    createFinding: (...args: unknown[]) => createFindingMock(...args),
  },
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
      <MemoryRouter>
        <AiAssistantPanel />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  localStorage.clear();
  activeCase.selectedHost = "WS-01";
  getAiStatusMock.mockResolvedValue(LOCAL_STATUS);
  listAiConversationsMock.mockResolvedValue({ conversations: [] });
  deleteAiConversationMock.mockResolvedValue({ deleted: true });
  createFindingMock.mockResolvedValue({ id: "finding-1", title: "Investigate", status: "draft" });
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
    expect(payload).toEqual({
      messages: [{ role: "user", content: "any persistence?" }],
      conversation_id: null,
      // The host on screen travels with the question, so "this host" resolves.
      active_host: "WS-01",
    });
  });

  it("renders a citation as a real link back into the app", async () => {
    // Tools hand back a ready-made pivot URL (e.g. open_in_search); the model
    // is instructed to relay it verbatim as a markdown link. This locks in
    // that a relative in-app href survives react-markdown's link sanitising
    // and opens in a new tab, so a future dependency bump can't silently
    // strip it without a test noticing.
    const user = userEvent.setup();
    streamCaseAiChatMock.mockImplementation(
      async (_caseId: string, _payload: unknown, onEvent: (event: AiStreamEvent) => void) => {
        onEvent({
          type: "text",
          text: "Found [factura.iso](/cases/case-1/search?q=event_id%3Aevt-1&selected=evt-1) downloaded from file.io.",
        });
      },
    );
    renderPanel();

    await user.click(await screen.findByRole("button", { name: /open the ai assistant/i }));
    await user.type(screen.getByLabelText(/question for the assistant/i), "any downloads?");
    await user.click(screen.getByRole("button", { name: "Send" }));

    const link = await screen.findByRole("link", { name: "factura.iso" });
    expect(link).toHaveAttribute("href", "/cases/case-1/search?q=event_id%3Aevt-1&selected=evt-1");
    expect(link).toHaveAttribute("target", "_blank");
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

  it("shows the lookups the assistant ran, so a claim can be traced", async () => {
    const user = userEvent.setup();
    streamCaseAiChatMock.mockImplementation(
      async (_caseId: string, _payload: unknown, onEvent: (event: AiStreamEvent) => void) => {
        onEvent({ type: "notice", text: "Checking persistence mechanisms", tool: "list_persistence", arguments: { host: "WS-01" } });
        onEvent({ type: "notice", text: "Searching events: run key", tool: "search_events", arguments: { query: "run key" } });
        onEvent({ type: "text", text: "Three run keys found." });
      },
    );
    renderPanel();

    await user.click(await screen.findByRole("button", { name: /open the ai assistant/i }));
    await user.type(screen.getByLabelText(/question for the assistant/i), "persistence?");
    await user.click(screen.getByRole("button", { name: "Send" }));

    await waitFor(() => expect(screen.getByText(/Three run keys found/)).toBeInTheDocument());
    expect(screen.getByText("list_persistence")).toBeInTheDocument();
    expect(screen.getByText("search_events")).toBeInTheDocument();
    // The query itself is shown beside the tool name, not just the tool.
    expect(screen.getByText("· run key")).toBeInTheDocument();
  });

  it("keeps every lookup rather than overwriting with the last one", async () => {
    const user = userEvent.setup();
    streamCaseAiChatMock.mockImplementation(
      async (_caseId: string, _payload: unknown, onEvent: (event: AiStreamEvent) => void) => {
        onEvent({ type: "notice", text: "a", tool: "list_hosts", arguments: {} });
        onEvent({ type: "notice", text: "b", tool: "list_findings", arguments: {} });
        onEvent({ type: "text", text: "done" });
      },
    );
    renderPanel();

    await user.click(await screen.findByRole("button", { name: /open the ai assistant/i }));
    await user.type(screen.getByLabelText(/question for the assistant/i), "q");
    await user.click(screen.getByRole("button", { name: "Send" }));

    await waitFor(() => expect(screen.getByText("done")).toBeInTheDocument());
    expect(screen.getByText("list_hosts")).toBeInTheDocument();
    expect(screen.getByText("list_findings")).toBeInTheDocument();
  });

  it("names the host it will assume questions are about", async () => {
    const user = userEvent.setup();
    renderPanel();

    await user.click(await screen.findByRole("button", { name: /open the ai assistant/i }));

    expect(screen.getByText(/Questions default to WS-01/)).toBeInTheDocument();
  });

  it("continues the same thread on a follow-up question", async () => {
    const user = userEvent.setup();
    streamCaseAiChatMock.mockImplementation(
      async (_caseId: string, _payload: unknown, onEvent: (event: AiStreamEvent) => void) => {
        onEvent({ type: "conversation", conversation_id: "conv-9" });
        onEvent({ type: "text", text: "ok" });
      },
    );
    renderPanel();

    await user.click(await screen.findByRole("button", { name: /open the ai assistant/i }));
    await user.type(screen.getByLabelText(/question for the assistant/i), "first");
    await user.click(screen.getByRole("button", { name: "Send" }));
    await waitFor(() => expect(streamCaseAiChatMock).toHaveBeenCalledTimes(1));

    await user.type(screen.getByLabelText(/question for the assistant/i), "second");
    await user.click(screen.getByRole("button", { name: "Send" }));
    await waitFor(() => expect(streamCaseAiChatMock).toHaveBeenCalledTimes(2));

    expect(streamCaseAiChatMock.mock.calls[0][1].conversation_id).toBeNull();
    expect(streamCaseAiChatMock.mock.calls[1][1].conversation_id).toBe("conv-9");
  });

  it("lists past conversations and reopens one", async () => {
    const user = userEvent.setup();
    listAiConversationsMock.mockResolvedValue({
      conversations: [
        { id: "c1", title: "any persistence?", provider: "ollama", model: "m", message_count: 4, created_at: null, updated_at: null },
      ],
    });
    getAiConversationMock.mockResolvedValue({
      id: "c1",
      title: "any persistence?",
      provider: "ollama",
      model: "m",
      created_at: null,
      messages: [
        { id: "m1", role: "user", content: "any persistence?", lookups: [] },
        { id: "m2", role: "assistant", content: "Yes, three run keys.", lookups: [{ tool: "list_persistence", arguments: {} }] },
      ],
    });
    renderPanel();

    await user.click(await screen.findByRole("button", { name: /open the ai assistant/i }));
    await user.click(screen.getByRole("button", { name: /past conversations/i }));

    await user.click(await screen.findByText("any persistence?"));

    await waitFor(() => expect(screen.getByText(/Yes, three run keys/)).toBeInTheDocument());
    expect(screen.getByText("list_persistence")).toBeInTheDocument();
  });

  it("starting a new conversation clears the transcript", async () => {
    const user = userEvent.setup();
    renderPanel();

    await user.click(await screen.findByRole("button", { name: /open the ai assistant/i }));
    await user.type(screen.getByLabelText(/question for the assistant/i), "first");
    await user.click(screen.getByRole("button", { name: "Send" }));
    await waitFor(() => expect(screen.getByText(/scheduled tasks/)).toBeInTheDocument());

    await user.click(screen.getByRole("button", { name: /new conversation/i }));

    expect(screen.queryByText(/scheduled tasks/)).not.toBeInTheDocument();
  });

  it("deletes a conversation from the history list", async () => {
    const user = userEvent.setup();
    listAiConversationsMock.mockResolvedValue({
      conversations: [
        { id: "c1", title: "old thread", provider: null, model: null, message_count: 2, created_at: null, updated_at: null },
      ],
    });
    renderPanel();

    await user.click(await screen.findByRole("button", { name: /open the ai assistant/i }));
    await user.click(screen.getByRole("button", { name: /past conversations/i }));
    await user.click(await screen.findByRole("button", { name: /delete conversation: old thread/i }));

    await waitFor(() => expect(deleteAiConversationMock).toHaveBeenCalledWith("case-1", "c1"));
  });

  it("says so when a conversation cannot be opened", async () => {
    // Swallowing this made the click look like it did nothing at all.
    const user = userEvent.setup();
    listAiConversationsMock.mockResolvedValue({
      conversations: [
        { id: "c1", title: "broken thread", provider: null, model: null, message_count: 2, created_at: null, updated_at: null },
      ],
    });
    getAiConversationMock.mockRejectedValue(new Error("Conversation not found"));
    renderPanel();

    await user.click(await screen.findByRole("button", { name: /open the ai assistant/i }));
    await user.click(screen.getByRole("button", { name: /past conversations/i }));
    await user.click(await screen.findByText("broken thread"));

    expect(await screen.findByRole("alert")).toHaveTextContent("Conversation not found");
    // The list stays open so the analyst can try another one.
    expect(screen.getByText("broken thread")).toBeInTheDocument();
  });

  it("reports a failed delete instead of silently doing nothing", async () => {
    const user = userEvent.setup();
    listAiConversationsMock.mockResolvedValue({
      conversations: [
        { id: "c1", title: "stuck", provider: null, model: null, message_count: 1, created_at: null, updated_at: null },
      ],
    });
    deleteAiConversationMock.mockRejectedValue(new Error("Access denied"));
    renderPanel();

    await user.click(await screen.findByRole("button", { name: /open the ai assistant/i }));
    await user.click(screen.getByRole("button", { name: /past conversations/i }));
    await user.click(await screen.findByRole("button", { name: /delete conversation: stuck/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Access denied");
  });

  it("cycles through panel sizes and remembers the choice", async () => {
    const user = userEvent.setup();
    renderPanel();

    await user.click(await screen.findByRole("button", { name: /open the ai assistant/i }));
    expect(screen.getByRole("button", { name: /currently regular/i })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /resize the assistant/i }));
    expect(screen.getByRole("button", { name: /currently large/i })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /resize the assistant/i }));
    expect(screen.getByRole("button", { name: /currently full/i })).toBeInTheDocument();

    expect(localStorage.getItem("kairon.ai.panelSize")).toBe("full");
  });

  it("starts at the remembered size", async () => {
    localStorage.setItem("kairon.ai.panelSize", "large");
    const user = userEvent.setup();
    renderPanel();

    await user.click(await screen.findByRole("button", { name: /open the ai assistant/i }));

    expect(screen.getByRole("button", { name: /currently large/i })).toBeInTheDocument();
  });

  it("works when the analyst has no host selected", async () => {
    // The panel is mounted app-wide, including on screens with no host at all.
    activeCase.selectedHost = "";
    const user = userEvent.setup();
    renderPanel();

    await user.click(await screen.findByRole("button", { name: /open the ai assistant/i }));
    await user.type(screen.getByLabelText(/question for the assistant/i), "hello");
    await user.click(screen.getByRole("button", { name: "Send" }));

    await waitFor(() => expect(streamCaseAiChatMock).toHaveBeenCalled());
    expect(streamCaseAiChatMock.mock.calls[0][1].active_host).toBeNull();
    expect(screen.queryByText(/Questions default to/)).not.toBeInTheDocument();
  });

  describe("creating a finding from an answer", () => {
    it("prefills the dialog from the question, the answer, and its citations", async () => {
      const user = userEvent.setup();
      streamCaseAiChatMock.mockImplementation(
        async (_caseId: string, _payload: unknown, onEvent: (event: AiStreamEvent) => void) => {
          onEvent({
            type: "text",
            text: "Found [factura.iso](/cases/case-1/search?q=event_id%3Aevt-1&selected=evt-1) downloaded from file.io.",
          });
        },
      );
      renderPanel();

      await user.click(await screen.findByRole("button", { name: /open the ai assistant/i }));
      await user.type(screen.getByLabelText(/question for the assistant/i), "any suspicious downloads?");
      await user.click(screen.getByRole("button", { name: "Send" }));
      await screen.findByText(/downloaded from file.io/);

      await user.click(screen.getByRole("button", { name: /create finding from this answer/i }));

      const dialog = await screen.findByRole("dialog", { name: /create finding from source/i });
      expect(within(dialog).getByDisplayValue("Investigate: any suspicious downloads?")).toBeInTheDocument();
      expect(within(dialog).getByText(/downloaded from file.io/)).toBeInTheDocument();

      await user.click(within(dialog).getByRole("button", { name: "Create finding" }));

      await waitFor(() => expect(createFindingMock).toHaveBeenCalled());
      const [, payload] = createFindingMock.mock.calls[0];
      expect(payload.event_ids).toEqual(["evt-1"]);
      expect(payload.source_view).toBe("ai_assistant");
      expect(payload.source_summary).toMatch(/any suspicious downloads\?/i);
    });

    it("does not offer the action while the answer is still streaming", async () => {
      let resolveStream: () => void = () => {};
      streamCaseAiChatMock.mockImplementation(
        (_caseId: string, _payload: unknown, onEvent: (event: AiStreamEvent) => void) =>
          new Promise<void>((resolve) => {
            onEvent({ type: "text", text: "Looking..." });
            resolveStream = resolve;
          }),
      );
      const user = userEvent.setup();
      renderPanel();

      await user.click(await screen.findByRole("button", { name: /open the ai assistant/i }));
      await user.type(screen.getByLabelText(/question for the assistant/i), "q");
      await user.click(screen.getByRole("button", { name: "Send" }));

      await screen.findByText("Looking...");
      expect(screen.queryByRole("button", { name: /create finding from this answer/i })).not.toBeInTheDocument();

      await act(async () => {
        resolveStream();
        await Promise.resolve();
      });
    });

    it("does not offer the action on an error turn", async () => {
      streamCaseAiChatMock.mockRejectedValue(new Error("boom"));
      const user = userEvent.setup();
      renderPanel();

      await user.click(await screen.findByRole("button", { name: /open the ai assistant/i }));
      await user.type(screen.getByLabelText(/question for the assistant/i), "q");
      await user.click(screen.getByRole("button", { name: "Send" }));

      await screen.findByText("boom");
      expect(screen.queryByRole("button", { name: /create finding from this answer/i })).not.toBeInTheDocument();
    });

    it("falls back to a generic title when there is no preceding question", async () => {
      // Reachable defensively (e.g. a reopened conversation with only an
      // assistant turn); must not crash or leave the title blank.
      getAiConversationMock.mockResolvedValue({
        id: "c1",
        title: "old thread",
        provider: "ollama",
        model: "m",
        created_at: null,
        messages: [{ id: "m1", role: "assistant", content: "Some earlier answer.", lookups: [] }],
      });
      listAiConversationsMock.mockResolvedValue({
        conversations: [
          { id: "c1", title: "old thread", provider: null, model: null, message_count: 1, created_at: null, updated_at: null },
        ],
      });
      const user = userEvent.setup();
      renderPanel();

      await user.click(await screen.findByRole("button", { name: /open the ai assistant/i }));
      await user.click(screen.getByRole("button", { name: /past conversations/i }));
      await user.click(await screen.findByText("old thread"));
      await screen.findByText("Some earlier answer.");

      await user.click(screen.getByRole("button", { name: /create finding from this answer/i }));

      expect(await screen.findByDisplayValue("Assistant finding")).toBeInTheDocument();
    });
  });
});
