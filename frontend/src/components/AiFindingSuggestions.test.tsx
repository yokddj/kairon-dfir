import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import AiFindingSuggestions from "./AiFindingSuggestions";

const getAiStatusMock = vi.fn();
const startMock = vi.fn();
const getJobMock = vi.fn();
const createFindingMock = vi.fn();

vi.mock("../api/client", () => ({
  api: {
    getAiStatus: (...args: unknown[]) => getAiStatusMock(...args),
    startFindingSuggestions: (...args: unknown[]) => startMock(...args),
    getFindingSuggestions: (...args: unknown[]) => getJobMock(...args),
    createFinding: (...args: unknown[]) => createFindingMock(...args),
  },
}));

const RESULT = {
  suggestions: [
    {
      title: "Service account ticket theft",
      severity: "high",
      confidence: "medium",
      description: "tool.exe dumped a ticket [L1].",
      mitre: ["T1558.003"],
      phase: "credential_access",
      leads: [{ ref: "L1", kind: "command", time_utc: "2026-01-10T09:15:02Z", host: "ws-01", label: "Command (risk 90): tool.exe dump" }],
      issues: [{ kind: "unsupported_fact", value: "198.51.100.9" }],
      finding: { title: "Service account ticket theft", severity: "high", event_ids: ["ev-1"], source: "ai_suggestion" },
    },
    {
      title: "Routine noise",
      severity: "low",
      confidence: null,
      description: "Rule fired [L2].",
      mitre: [],
      phase: null,
      leads: [{ ref: "L2", kind: "detection", time_utc: null, host: null, label: "Rule X (1 match)" }],
      issues: [],
      finding: { title: "Routine noise" },
    },
  ],
  dropped: 1,
  lead_counts: { command: 1, detection: 1 },
  unavailable_sources: [],
  provenance: { provider: "Ollama (local)", model: "qwen", hosting: "local", generated_at: "", prompt_version: "v1" },
};

function job(status: string, result: unknown = null, extra: Record<string, unknown> = {}) {
  return { job: { id: "job-1", kind: "ai_finding_suggestions", status, created_at: null, started_at: "2026-01-10T09:00:00Z", finished_at: "2026-01-10T09:05:00Z", error: null, result, ...extra } };
}

function renderPanel() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <AiFindingSuggestions caseId="case-1" />
    </QueryClientProvider>,
  );
}

describe("AiFindingSuggestions", () => {
  beforeEach(() => {
    getAiStatusMock.mockReset();
    startMock.mockReset();
    getJobMock.mockReset();
    getJobMock.mockResolvedValue({ job: null });
    createFindingMock.mockReset();
  });

  it("renders nothing when AI is not configured", async () => {
    getAiStatusMock.mockResolvedValue({ enabled: false, provider: null, model: null, hosting: null });
    const { container } = renderPanel();
    await waitFor(() => expect(getAiStatusMock).toHaveBeenCalled());
    expect(container).toBeEmptyDOMElement();
  });

  it("asks before sending, then creates only the accepted suggestion", async () => {
    getAiStatusMock.mockResolvedValue({ enabled: true, provider: "openai", label: "OpenAI", model: "gpt", hosting: "cloud" });
    startMock.mockResolvedValue(job("completed", RESULT));
    createFindingMock.mockResolvedValue({ id: "finding-1" });
    const user = userEvent.setup();
    renderPanel();

    await user.click(await screen.findByRole("button", { name: "Suggest findings" }));
    const dialog = screen.getByRole("dialog", { name: "Suggest findings with AI" });
    expect(within(dialog).getByText(/not local/)).toBeInTheDocument();
    expect(startMock).not.toHaveBeenCalled();
    await user.click(within(dialog).getByRole("button", { name: "Send and suggest" }));

    expect(await screen.findAllByTestId("ai-suggestion")).toHaveLength(2);
    expect(screen.getByTestId("ai-suggestions-summary")).toHaveTextContent("2 suggestions from 1 suspicious commands, 1 rule detections");
    expect(screen.getByTestId("ai-suggestions-summary")).toHaveTextContent("1 left out");
    expect(screen.getByTestId("ai-suggestion-issues")).toHaveTextContent("198.51.100.9");

    const [first, second] = screen.getAllByTestId("ai-suggestion");
    await user.click(within(second).getByRole("button", { name: "Dismiss" }));
    expect(screen.getAllByTestId("ai-suggestion")).toHaveLength(1);
    await user.click(within(first).getByRole("button", { name: "Create finding" }));
    await waitFor(() => expect(createFindingMock).toHaveBeenCalledWith("case-1", RESULT.suggestions[0].finding));
    expect(await within(first).findByText("Finding created")).toBeInTheDocument();
    expect(createFindingMock).toHaveBeenCalledTimes(1);
  });

  it("shows the last result after a reload, with suggestions already created marked", async () => {
    getAiStatusMock.mockResolvedValue({ enabled: true, provider: "ollama", label: "Ollama", model: "qwen", hosting: "local" });
    const result = { ...RESULT, suggestions: [{ ...RESULT.suggestions[0], created_finding_id: "finding-9" }, RESULT.suggestions[1]] };
    getJobMock.mockResolvedValue(job("completed", result));
    renderPanel();
    const cards = await screen.findAllByTestId("ai-suggestion");
    expect(within(cards[0]).getByText("Finding created")).toBeInTheDocument();
    expect(within(cards[1]).getByRole("button", { name: "Create finding" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Suggest again" })).toBeInTheDocument();
  });

  it("shows a running job and a failed one", async () => {
    getAiStatusMock.mockResolvedValue({ enabled: true, provider: "ollama", label: "Ollama", model: "qwen", hosting: "local" });
    getJobMock.mockResolvedValueOnce(job("running"));
    const { unmount } = renderPanel();
    expect(await screen.findByTestId("ai-suggestions-progress")).toHaveTextContent(/leave this page/i);
    expect(screen.getByRole("button", { name: "Suggesting..." })).toBeDisabled();
    unmount();
    getJobMock.mockResolvedValue(job("failed", null, { error: "The model reached its token limit." }));
    renderPanel();
    expect(await screen.findByTestId("ai-suggestions-error")).toHaveTextContent(/token limit/);
  });
});
