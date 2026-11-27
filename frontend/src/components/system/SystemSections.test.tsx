import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import InstanceSettingsSection, { formatSettingValue } from "./InstanceSettingsSection";
import UpdatesSection from "./UpdatesSection";
import type { InstanceSettingEntry, InstanceSettingsResponse } from "../../api/client";

const getUpdateStatusMock = vi.fn();
const checkForUpdatesMock = vi.fn();
const getInstanceSettingsMock = vi.fn();
const updateInstanceSettingsMock = vi.fn();

vi.mock("../../api/client", () => ({
  api: {
    getUpdateStatus: () => getUpdateStatusMock(),
    checkForUpdates: () => checkForUpdatesMock(),
    getInstanceSettings: () => getInstanceSettingsMock(),
    updateInstanceSettings: (settings: unknown) => updateInstanceSettingsMock(settings),
  },
}));

function renderWithClient(node: React.ReactNode) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={queryClient}>{node}</QueryClientProvider>);
}

function entry(patch: Partial<InstanceSettingEntry>): InstanceSettingEntry {
  return {
    key: "MAX_ARCHIVE_DEPTH",
    group: "ingest",
    label: "Nested archive depth",
    description: "How many archives inside archives are extracted.",
    value_type: "int",
    unit: null,
    min: 1,
    max: 20,
    choices: [],
    env_value: 5,
    override: null,
    running_value: 5,
    applies: "restart",
    services: ["backend", "worker"],
    pending_restart: false,
    ...patch,
  };
}

function settingsResponse(settings: InstanceSettingEntry[], restart: string | null = null): InstanceSettingsResponse {
  return {
    settings,
    read_only: [{ key: "S3_SOURCE_ENABLED", value: false, reason: "Evidence from S3: the server downloads from outside the lab." }],
    restart_services: restart ? ["backend", "worker"] : [],
    restart_command: restart,
  };
}

describe("UpdatesSection", () => {
  beforeEach(() => {
    getUpdateStatusMock.mockReset();
    checkForUpdatesMock.mockReset();
  });

  it("lists the new commits and how to update", async () => {
    getUpdateStatusMock.mockResolvedValue({
      enabled: true,
      repository: "example/kairon",
      branch: "main",
      running_commit: "aaaaaaaaaaaa",
      interval_hours: 6,
      state: "update_available",
      checked_at: "2026-11-27T10:00:00Z",
      commits_behind: 2,
      commits: [
        { sha: "222222222222", title: "Second change" },
        { sha: "111111111111", title: "First change" },
      ],
      compare_url: "https://github.com/example/kairon/compare/aaaaaaaaaaaa...main",
    });
    renderWithClient(<UpdatesSection />);
    expect(await screen.findByTestId("update-summary")).toHaveTextContent("2 new commits on main");
    expect(within(screen.getByTestId("update-commits")).getAllByRole("listitem").map((item) => item.textContent)).toEqual(["22222222Second change", "11111111First change"]);
    expect(screen.getByText(/\.\/scripts\/upgrade\.sh/)).toBeInTheDocument();
  });

  it("says plainly when it is up to date, and checks again on request", async () => {
    const status = { enabled: true, repository: "example/kairon", branch: "main", running_commit: "aaaaaaaaaaaa", interval_hours: 6, state: "up_to_date" };
    getUpdateStatusMock.mockResolvedValue(status);
    checkForUpdatesMock.mockResolvedValue({ ...status, state: "update_available", commits_behind: 1, commits: [{ sha: "333333333333", title: "New" }] });
    renderWithClient(<UpdatesSection />);
    expect(await screen.findByTestId("update-summary")).toHaveTextContent("Up to date with main");
    expect(screen.queryByText(/How to update/i)).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Check now" }));
    expect(await screen.findByText("1 new commit on main")).toBeInTheDocument();
  });

  it("offers no check when the build does not know its commit", async () => {
    getUpdateStatusMock.mockResolvedValue({ enabled: true, repository: "example/kairon", branch: "main", running_commit: null, interval_hours: 6, state: "unknown_commit" });
    renderWithClient(<UpdatesSection />);
    expect(await screen.findByTestId("update-summary")).toHaveTextContent("does not record its commit");
    expect(screen.queryByRole("button", { name: "Check now" })).not.toBeInTheDocument();
  });
});

describe("InstanceSettingsSection", () => {
  beforeEach(() => {
    getInstanceSettingsMock.mockReset();
    updateInstanceSettingsMock.mockReset();
  });

  it("formats values with their unit", () => {
    expect(formatSettingValue({ value_type: "int", unit: "bytes" }, 10 * 1024 ** 3)).toBe("10 GiB");
    expect(formatSettingValue({ value_type: "int", unit: "seconds" }, 10800)).toBe("3 h");
    expect(formatSettingValue({ value_type: "bool", unit: null }, false)).toBe("off");
  });

  it("saves only what changed and shows the restart it needs", async () => {
    const depth = entry({});
    const level = entry({ key: "BACKEND_LOG_LEVEL", group: "general", label: "Log level", value_type: "choice", choices: ["DEBUG", "INFO"], env_value: "INFO", running_value: "INFO", min: null, max: null });
    getInstanceSettingsMock.mockResolvedValue(settingsResponse([depth, level]));
    updateInstanceSettingsMock.mockResolvedValue(settingsResponse([{ ...depth, override: 8, pending_restart: true }, level], "docker compose restart backend worker"));
    renderWithClient(<InstanceSettingsSection />);

    const input = await screen.findByLabelText("Nested archive depth");
    expect(screen.getByRole("button", { name: "Save changes" })).toBeDisabled();
    fireEvent.change(input, { target: { value: "8" } });
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() => expect(updateInstanceSettingsMock).toHaveBeenCalledWith({ MAX_ARCHIVE_DEPTH: 8 }));
    expect(await screen.findByTestId("instance-settings-restart")).toHaveTextContent("docker compose restart backend worker");
    expect(within(screen.getByTestId("instance-setting-MAX_ARCHIVE_DEPTH")).getByText("restart needed")).toBeInTheDocument();
    expect(screen.getByText("S3_SOURCE_ENABLED")).toBeInTheDocument();
  });

  it("blocks values out of range and sends null to go back to .env", async () => {
    getInstanceSettingsMock.mockResolvedValue(settingsResponse([entry({ override: 9, running_value: 9 })]));
    updateInstanceSettingsMock.mockResolvedValue(settingsResponse([entry({})]));
    renderWithClient(<InstanceSettingsSection />);

    const input = await screen.findByLabelText("Nested archive depth");
    fireEvent.change(input, { target: { value: "50" } });
    expect(screen.getByText("At most 20.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save changes" })).toBeDisabled();

    fireEvent.click(screen.getByRole("button", { name: "Use .env" }));
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() => expect(updateInstanceSettingsMock).toHaveBeenCalledWith({ MAX_ARCHIVE_DEPTH: null }));
  });
});
