import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import ServiceTokensPage from "./ServiceTokensPage";

const listTokens = vi.fn();
const createToken = vi.fn();
const revokeToken = vi.fn();
const copy = vi.fn();
let isAdmin = true;

vi.mock("../api/client", () => ({
  api: {
    listServiceTokens: (...args: unknown[]) => listTokens(...args),
    createServiceToken: (...args: unknown[]) => createToken(...args),
    revokeServiceToken: (...args: unknown[]) => revokeToken(...args),
  },
}));
vi.mock("../context/AuthContext", () => ({ useAuth: () => ({ user: { is_admin: isAdmin } }) }));
vi.mock("../lib/time", async (importOriginal) => ({ ...(await importOriginal<typeof import("../lib/time")>()), copyToClipboard: (...args: unknown[]) => copy(...args) }));

const base = { scope: "read_only_all_cases", created_by: "admin-1", created_at: "2026-11-01T10:00:00Z", last_used_at: null };
const active = { ...base, id: "t1", name: "mcp-server", token_prefix: "kairon_svc_ab12", expires_at: "2099-01-01T00:00:00Z", revoked_at: null };
const revoked = { ...base, id: "t2", name: "old-script", token_prefix: "kairon_svc_cd34", expires_at: null, revoked_at: "2026-11-02T10:00:00Z" };

function renderPage() {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter>
        <ServiceTokensPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("ServiceTokensPage", () => {
  beforeEach(() => {
    isAdmin = true;
    listTokens.mockReset().mockResolvedValue([active, revoked]);
    createToken.mockReset();
    revokeToken.mockReset();
    copy.mockReset().mockResolvedValue(true);
  });

  it("lists tokens with their state and never a secret", async () => {
    renderPage();
    const rows = await screen.findAllByTestId("service-token-row");
    expect(within(rows[0]).getByText("Active")).toBeInTheDocument();
    expect(within(rows[1]).getByText("Revoked")).toBeInTheDocument();
    expect(within(rows[1]).queryByRole("button", { name: "Revoke" })).not.toBeInTheDocument();
    expect(screen.getByText("kairon_svc_ab12…")).toBeInTheDocument();
  });

  it("shows a new token once, with copy, and sends the chosen expiry", async () => {
    createToken.mockResolvedValue({ ...active, id: "t3", name: "ci-script", token: "kairon_svc_SECRETVALUE" });
    renderPage();
    await screen.findAllByTestId("service-token-row");
    await userEvent.clear(screen.getByPlaceholderText("mcp-server"));
    await userEvent.type(screen.getByPlaceholderText("mcp-server"), "ci-script");
    await userEvent.selectOptions(screen.getByLabelText("Expires"), "never");
    await userEvent.click(screen.getByRole("button", { name: "Create" }));
    await waitFor(() => expect(createToken).toHaveBeenCalledWith({ name: "ci-script", expires_in_days: null }));
    expect(await screen.findByTestId("created-service-token-value")).toHaveTextContent("kairon_svc_SECRETVALUE");
    await userEvent.click(screen.getByRole("button", { name: /Copy/ }));
    expect(copy).toHaveBeenCalledWith("kairon_svc_SECRETVALUE");
    expect(await screen.findByRole("button", { name: /Copied/ })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /I have stored it/ }));
    expect(screen.queryByText("kairon_svc_SECRETVALUE")).not.toBeInTheDocument();
  });

  it("revokes only after an in-page confirmation", async () => {
    revokeToken.mockResolvedValue({ ...active, revoked_at: "2026-11-11T10:00:00Z" });
    renderPage();
    const rows = await screen.findAllByTestId("service-token-row");
    await userEvent.click(within(rows[0]).getByRole("button", { name: "Revoke" }));
    expect(revokeToken).not.toHaveBeenCalled();
    await userEvent.click(within(rows[0]).getByRole("button", { name: "Confirm revoke" }));
    await waitFor(() => expect(revokeToken).toHaveBeenCalledWith("t1"));
    expect(await screen.findByRole("status")).toHaveTextContent('Token "mcp-server" revoked');
  });

  it("is for administrators only", () => {
    isAdmin = false;
    renderPage();
    expect(screen.getByText(/managed by administrators/)).toBeInTheDocument();
    expect(listTokens).not.toHaveBeenCalled();
  });
});
