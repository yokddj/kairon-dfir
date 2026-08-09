/** @vitest-environment jsdom */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api, type LinuxSymbolValidationResult } from "../../api/client";
import { LinuxSymbolUploadPanel } from "./LinuxSymbolUploadPanel";

const getLinuxSymbolRequirementMock = vi.fn();
const validateLinuxEvidenceSymbolsMock = vi.fn();
const getLinuxSymbolValidationStatusMock = vi.fn();

vi.mock("../../api/client", () => ({
  api: {
    getLinuxSymbolRequirement: (...args: unknown[]) => getLinuxSymbolRequirementMock(...args),
    validateLinuxEvidenceSymbols: (...args: unknown[]) => validateLinuxEvidenceSymbolsMock(...args),
    getLinuxSymbolValidationStatus: (...args: unknown[]) => getLinuxSymbolValidationStatusMock(...args),
  },
}));

const CASE = "case-1";
const EVIDENCE = "ev-1";
const VALIDATION_ID = "validation-1";

function renderPanel(onValidated = vi.fn()) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } } });
  const result = render(
    <QueryClientProvider client={qc}>
      <LinuxSymbolUploadPanel caseId={CASE} evidenceId={EVIDENCE} architecture="X64" onValidated={onValidated} />
    </QueryClientProvider>,
  );
  return { ...result, onValidated };
}

function isf(): File {
  return new File(["{}"], "kernel.json", { type: "application/json" });
}

function statusResult(overrides: Partial<LinuxSymbolValidationResult> = {}): LinuxSymbolValidationResult {
  return {
    status: "queued",
    expected_identity: null,
    detected_identity: null,
    compatible: false,
    reason: "",
    cached: false,
    cache_key: null,
    ...overrides,
  };
}

function validResult(): LinuxSymbolValidationResult {
  return statusResult({
    status: "valid",
    expected_identity: { kernel_release: "6.8.0-test", architecture: "x64", banner: null, build_id: "build-a" },
    detected_identity: { kernel_release: "6.8.0-test", architecture: "x64", banner: null, build_id: "build-a" },
    compatible: true,
    cache_key: "abc123",
  });
}

async function selectAndSubmit() {
  await userEvent.upload(screen.getByTestId("linux-symbol-file-input"), isf());
  await userEvent.click(screen.getByTestId("linux-symbol-validate-button"));
}

describe("LinuxSymbolUploadPanel (Phase 3, async)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getLinuxSymbolRequirementMock.mockResolvedValue({ expected_identity: null });
    validateLinuxEvidenceSymbolsMock.mockResolvedValue({ validation_id: VALIDATION_ID, status: "queued" });
  });

  it("shows the required copy, expected kernel, architecture and accepted formats", async () => {
    renderPanel();
    expect(screen.getByText(/Kairon requires a compatible Volatility 3 ISF/)).toBeInTheDocument();
    await waitFor(() => expect(getLinuxSymbolRequirementMock).toHaveBeenCalledWith(CASE, EVIDENCE));
    expect(screen.getByText(/Expected kernel:/)).toBeInTheDocument();
    expect(screen.getByText("X64")).toBeInTheDocument();
    expect(screen.getByText(".json, .json.xz")).toBeInTheDocument();
  });

  it("does not render a Validate button until a file has been selected", () => {
    renderPanel();
    expect(screen.queryByTestId("linux-symbol-validate-button")).not.toBeInTheDocument();
  });

  it("selecting a file shows name and size but never calls the enqueue API", async () => {
    renderPanel();
    const input = screen.getByTestId("linux-symbol-file-input");
    await userEvent.upload(input, isf());

    expect(screen.getByTestId("linux-symbol-selected-file")).toHaveTextContent("kernel.json");
    expect(validateLinuxEvidenceSymbolsMock).not.toHaveBeenCalled();
  });

  it("clicking Validate symbols calls the enqueue API with the selected file", async () => {
    getLinuxSymbolValidationStatusMock.mockResolvedValue(statusResult());
    renderPanel();
    await selectAndSubmit();

    await waitFor(() => expect(validateLinuxEvidenceSymbolsMock).toHaveBeenCalledWith(CASE, EVIDENCE, expect.any(File)));
  });

  it("queued -> validating -> valid: polls status and shows 'Validating symbols...' while non-terminal", async () => {
    getLinuxSymbolValidationStatusMock
      .mockResolvedValueOnce(statusResult({ status: "queued" }))
      .mockResolvedValueOnce(statusResult({ status: "validating" }))
      .mockResolvedValue(validResult());
    renderPanel();
    await selectAndSubmit();

    expect(await screen.findByTestId("linux-symbol-validating")).toHaveTextContent("Validating symbols...");
    await waitFor(() => expect(screen.getByTestId("linux-symbol-result-valid")).toBeInTheDocument(), { timeout: 5000 });
    expect(getLinuxSymbolValidationStatusMock.mock.calls.length).toBeGreaterThanOrEqual(2);
  });

  it("queued -> invalid: polling stops as soon as the terminal state is reached", async () => {
    getLinuxSymbolValidationStatusMock
      .mockResolvedValueOnce(statusResult({ status: "queued" }))
      .mockResolvedValue(
        statusResult({
          status: "invalid",
          expected_identity: { kernel_release: "5.15.0-required", architecture: "x64", banner: null, build_id: null },
          detected_identity: { kernel_release: "6.8.0-wrong", architecture: "x64", banner: null, build_id: null },
          reason: "The uploaded ISF does not match this evidence's kernel_release.",
        }),
      );
    renderPanel();
    await selectAndSubmit();

    await screen.findByTestId("linux-symbol-result-invalid", {}, { timeout: 5000 });
    const callsAtTerminal = getLinuxSymbolValidationStatusMock.mock.calls.length;
    await new Promise((resolve) => setTimeout(resolve, 2500));
    expect(getLinuxSymbolValidationStatusMock.mock.calls.length).toBe(callsAtTerminal);
  });

  it("VALID: shows the exact required copy and calls onValidated exactly once", async () => {
    getLinuxSymbolValidationStatusMock.mockResolvedValue(validResult());
    const { onValidated } = renderPanel();
    await selectAndSubmit();

    const card = await screen.findByTestId("linux-symbol-result-valid");
    expect(card).toHaveTextContent("✓ Compatible symbols");
    expect(card).toHaveTextContent("Expected kernel:");
    expect(card).toHaveTextContent("Detected kernel:");
    expect(card).toHaveTextContent("Architecture:");
    expect(card).toHaveTextContent("Ready");
    await waitFor(() => expect(onValidated).toHaveBeenCalledTimes(1));

    // A subsequent re-render/poll of the same terminal state must not
    // re-fire onValidated.
    await new Promise((resolve) => setTimeout(resolve, 500));
    expect(onValidated).toHaveBeenCalledTimes(1);
  });

  it("VALID: hides the file selector and Validate button", async () => {
    getLinuxSymbolValidationStatusMock.mockResolvedValue(validResult());
    renderPanel();
    await selectAndSubmit();

    await screen.findByTestId("linux-symbol-result-valid");
    expect(screen.queryByTestId("linux-symbol-validate-button")).not.toBeInTheDocument();
    expect(screen.queryByTestId("linux-symbol-file-input")).not.toBeInTheDocument();
  });

  it("while queued/validating, the file input is hidden -- no second, concurrent submission of the same upload", async () => {
    getLinuxSymbolValidationStatusMock.mockResolvedValue(statusResult({ status: "validating" }));
    renderPanel();
    await selectAndSubmit();

    await screen.findByTestId("linux-symbol-validating");
    expect(screen.queryByTestId("linux-symbol-file-input")).not.toBeInTheDocument();
    expect(screen.queryByTestId("linux-symbol-validate-button")).not.toBeInTheDocument();
    expect(validateLinuxEvidenceSymbolsMock).toHaveBeenCalledTimes(1);
  });

  it("shows an indeterminate progress indicator, never a fabricated percentage, while validating", async () => {
    getLinuxSymbolValidationStatusMock.mockResolvedValue(statusResult({ status: "validating" }));
    renderPanel();
    await selectAndSubmit();

    const indicator = await screen.findByTestId("linux-symbol-validating-indeterminate");
    expect(indicator).toBeInTheDocument();
    expect(screen.getByTestId("linux-symbol-validating").textContent).not.toMatch(/%/);
  });

  it("INVALID: shows the exact required copy with expected/detected and a Choose another file button", async () => {
    getLinuxSymbolValidationStatusMock.mockResolvedValue(
      statusResult({
        status: "invalid",
        expected_identity: { kernel_release: "5.15.0-required", architecture: "x64", banner: null, build_id: null },
        detected_identity: { kernel_release: "6.8.0-wrong", architecture: "x64", banner: null, build_id: null },
        reason: "The uploaded ISF does not match this evidence's kernel_release.",
      }),
    );
    renderPanel();
    await selectAndSubmit();

    const card = await screen.findByTestId("linux-symbol-result-invalid");
    expect(card).toHaveTextContent("Symbols do not match this memory dump.");
    expect(card).toHaveTextContent("Expected:");
    expect(card).toHaveTextContent("5.15.0-required");
    expect(card).toHaveTextContent("Detected:");
    expect(card).toHaveTextContent("6.8.0-wrong");
    expect(screen.getByTestId("linux-symbol-choose-another")).toBeInTheDocument();
  });

  it("INVALID: Choose another file returns to the file selector and allows a fresh submission", async () => {
    getLinuxSymbolValidationStatusMock.mockResolvedValue(statusResult({ status: "invalid", reason: "mismatch" }));
    renderPanel();
    await selectAndSubmit();
    await screen.findByTestId("linux-symbol-result-invalid");

    await userEvent.click(screen.getByTestId("linux-symbol-choose-another"));

    expect(screen.getByTestId("linux-symbol-file-input")).toBeInTheDocument();
    expect(screen.queryByTestId("linux-symbol-selected-file")).not.toBeInTheDocument();
    expect(screen.queryByTestId("linux-symbol-result-invalid")).not.toBeInTheDocument();
  });

  it("UNSUPPORTED: shows the exact required copy and allows choosing another file", async () => {
    getLinuxSymbolValidationStatusMock.mockResolvedValue(
      statusResult({ status: "unsupported", reason: "Only .json or .json.xz Volatility 3 ISF files are accepted." }),
    );
    renderPanel();
    await selectAndSubmit();

    const card = await screen.findByTestId("linux-symbol-result-unsupported");
    expect(card).toHaveTextContent("Unsupported symbol file.");
    expect(screen.getByTestId("linux-symbol-choose-another")).toBeInTheDocument();
  });

  it("VALIDATION_FAILED (worker outcome): shows the exact required copy and allows choosing another file", async () => {
    getLinuxSymbolValidationStatusMock.mockResolvedValue(
      statusResult({ status: "validation_failed", reason: "Linux ISF could not be parsed." }),
    );
    renderPanel();
    await selectAndSubmit();

    const card = await screen.findByTestId("linux-symbol-result-validation-failed");
    expect(card).toHaveTextContent("Could not validate this symbol file.");
    expect(screen.getByTestId("linux-symbol-choose-another")).toBeInTheDocument();
  });

  it("VALIDATION_FAILED (submit itself rejected, e.g. 409/422/403): shows the failure and allows choosing another file", async () => {
    validateLinuxEvidenceSymbolsMock.mockRejectedValue(new Error("A Linux symbol validation is already queued for this evidence."));
    renderPanel();
    await selectAndSubmit();

    const card = await screen.findByTestId("linux-symbol-result-validation-failed");
    expect(card).toHaveTextContent("Could not validate this symbol file.");
    expect(card).toHaveTextContent("already queued");
    expect(screen.getByTestId("linux-symbol-choose-another")).toBeInTheDocument();
    expect(getLinuxSymbolValidationStatusMock).not.toHaveBeenCalled();
  });
});
