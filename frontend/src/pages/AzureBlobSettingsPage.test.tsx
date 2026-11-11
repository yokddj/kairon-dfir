import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";
import AzureBlobSettingsPage from "./AzureBlobSettingsPage";

const getConfig = vi.fn();
const updateConfig = vi.fn();
const testConfig = vi.fn();

vi.mock("../api/client", () => ({
  api: {
    getAzureBlobConfig: (...args: unknown[]) => getConfig(...args),
    updateAzureBlobConfig: (...args: unknown[]) => updateConfig(...args),
    testAzureBlobConfig: (...args: unknown[]) => testConfig(...args),
  },
}));
vi.mock("../context/AuthContext", () => ({ useAuth: () => ({ user: { is_admin: true } }) }));

const stored = {
  enabled: true,
  account_url: "https://irstorage.blob.core.windows.net",
  auth_method: "sas_token",
  account_name: "",
  tenant_id: "",
  client_id: "",
  default_container: "evidence",
  has_secret: true,
  secret_masked: "sv=****",
  configured: true,
};

function renderPage() {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <AzureBlobSettingsPage />
    </QueryClientProvider>,
  );
}

describe("AzureBlobSettingsPage", () => {
  beforeEach(() => {
    getConfig.mockReset().mockResolvedValue(stored);
    updateConfig.mockReset().mockResolvedValue(stored);
    testConfig.mockReset().mockResolvedValue({ ok: true, message: "Connected; container evidence can be listed." });
  });

  it("keeps the stored secret unless a new one is typed", async () => {
    renderPage();
    await screen.findByDisplayValue("https://irstorage.blob.core.windows.net");
    expect(screen.getByLabelText("SAS token")).toHaveAttribute("placeholder", expect.stringContaining("Stored"));
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(updateConfig).toHaveBeenCalled());
    expect(updateConfig.mock.calls[0][0]).not.toHaveProperty("secret");
  });

  it("asks for tenant and client id for a service principal, and a new secret for the new method", async () => {
    renderPage();
    await screen.findByDisplayValue("https://irstorage.blob.core.windows.net");
    await userEvent.selectOptions(screen.getByLabelText("Authentication"), "service_principal");
    expect(screen.getByPlaceholderText(/onmicrosoft/)).toBeInTheDocument();
    expect(screen.getByLabelText("Client secret")).toHaveAttribute("placeholder", "Not set");
    await userEvent.type(screen.getByLabelText("Client secret"), "s3cr3t");
    await userEvent.click(screen.getByRole("button", { name: "Test connection" }));
    await waitFor(() => expect(testConfig).toHaveBeenCalledWith(expect.objectContaining({ auth_method: "service_principal", secret: "s3cr3t" })));
    expect(await screen.findByRole("status")).toHaveTextContent("can be listed");
  });
});
