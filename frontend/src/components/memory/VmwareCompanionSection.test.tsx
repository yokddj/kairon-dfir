/** @vitest-environment jsdom */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { VmwareCompanionSection, type VmwareCompanionSectionProps } from "./VmwareCompanionSection";

const attachVmwareCompanionMock = vi.fn();
const deleteVmwareCompanionMock = vi.fn();

vi.mock("../../api/client", () => ({
  api: {
    attachVmwareCompanion: (...args: unknown[]) => attachVmwareCompanionMock(...args),
    deleteVmwareCompanion: (...args: unknown[]) => deleteVmwareCompanionMock(...args),
  },
}));

const CASE = "case-1";
const EVIDENCE = "ev-1";

function baseProps(overrides: Partial<VmwareCompanionSectionProps> = {}): VmwareCompanionSectionProps {
  return {
    caseId: CASE,
    evidenceId: EVIDENCE,
    hasCompanion: false,
    companionId: null,
    companionType: null,
    companionFilename: null,
    companionSha256: null,
    companionSizeBytes: null,
    recommended: true,
    warningText: "VMware memory can sometimes be analyzed without snapshot metadata. A matching .vmsn or .vmss file may be required for reliable analysis.",
    onChanged: vi.fn(),
    ...overrides,
  };
}

function companion(): File {
  return new File(["vmsn-bytes"], "Ubuntu.vmsn", { type: "application/octet-stream" });
}

function renderSection(props: VmwareCompanionSectionProps) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <VmwareCompanionSection {...props} />
    </QueryClientProvider>,
  );
}

async function selectFile(file: File = companion()) {
  await userEvent.click(screen.getByTestId("vmware-companion-add-button"));
  await userEvent.upload(screen.getByTestId("vmware-companion-file-input"), file);
}

describe("VmwareCompanionSection", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders nothing when neither a companion is attached nor recommended", () => {
    const { container } = renderSection(baseProps({ recommended: false, hasCompanion: false }));
    expect(container).toBeEmptyDOMElement();
  });

  it("renders when recommended even without an attached companion", () => {
    renderSection(baseProps({ recommended: true, hasCompanion: false }));
    expect(screen.getByTestId("vmware-companion-section")).toBeInTheDocument();
  });

  it("renders when a companion is attached even if no longer recommended", () => {
    renderSection(baseProps({ recommended: false, hasCompanion: true, companionId: "c1", companionType: "vmware_vmsn", companionFilename: "memory.vmsn", companionSha256: "a".repeat(64), companionSizeBytes: 5000 }));
    expect(screen.getByTestId("vmware-companion-section")).toBeInTheDocument();
  });

  describe("Not provided state", () => {
    it("shows the conservative copy and an Add VMware metadata button", () => {
      renderSection(baseProps());
      const panel = screen.getByTestId("vmware-companion-not-provided");
      expect(panel).toHaveTextContent("Not provided");
      expect(panel).toHaveTextContent("may be required");
      expect(panel).not.toHaveTextContent("is required");
      expect(screen.getByTestId("vmware-companion-add-button")).toBeInTheDocument();
    });

    it("selecting a file does NOT auto-upload -- only an explicit confirm click does", async () => {
      renderSection(baseProps());
      await userEvent.click(screen.getByTestId("vmware-companion-add-button"));
      await userEvent.upload(screen.getByTestId("vmware-companion-file-input"), companion());

      expect(screen.getByTestId("vmware-companion-selected-file")).toHaveTextContent("Ubuntu.vmsn");
      expect(attachVmwareCompanionMock).not.toHaveBeenCalled();
      expect(screen.getByTestId("vmware-companion-attach-button")).toBeInTheDocument();
    });

    it("only accepts .vmsn/.vmss in the file picker", async () => {
      renderSection(baseProps());
      await userEvent.click(screen.getByTestId("vmware-companion-add-button"));
      expect(screen.getByTestId("vmware-companion-file-input")).toHaveAttribute("accept", ".vmsn,.vmss");
    });

    it("clicking Attach metadata calls the API with the selected file and refetches on success", async () => {
      let resolveUpload: (value: unknown) => void = () => {};
      attachVmwareCompanionMock.mockReturnValue(new Promise((resolve) => { resolveUpload = resolve; }));
      const onChanged = vi.fn();
      renderSection(baseProps({ onChanged }));
      await selectFile();
      await userEvent.click(screen.getByTestId("vmware-companion-attach-button"));

      expect(await screen.findByText(/Uploading VMware metadata/)).toBeInTheDocument();
      resolveUpload({ id: "c1", companion_type: "vmware_vmsn" });
      await vi.waitFor(() => expect(onChanged).toHaveBeenCalledTimes(1));
      expect(attachVmwareCompanionMock).toHaveBeenCalledWith(CASE, EVIDENCE, expect.any(File));
    });

    it("shows an indeterminate progress indicator while uploading, never a fabricated percentage", async () => {
      let resolveUpload: (value: unknown) => void = () => {};
      attachVmwareCompanionMock.mockReturnValue(new Promise((resolve) => { resolveUpload = resolve; }));
      renderSection(baseProps());
      await selectFile();
      await userEvent.click(screen.getByTestId("vmware-companion-attach-button"));

      const indicator = await screen.findByTestId("vmware-companion-uploading-indeterminate");
      expect(indicator).toBeInTheDocument();
      expect(screen.getByTestId("vmware-companion-uploading").textContent).not.toMatch(/%/);
      resolveUpload({ id: "c1" });
      await screen.findByTestId("vmware-companion-not-provided");
    });

    it("blocks a second submit while an upload is in flight (no file input/button while uploading)", async () => {
      attachVmwareCompanionMock.mockReturnValue(new Promise(() => {}));
      renderSection(baseProps());
      await selectFile();
      await userEvent.click(screen.getByTestId("vmware-companion-attach-button"));

      await screen.findByTestId("vmware-companion-uploading");
      expect(screen.queryByTestId("vmware-companion-file-input")).not.toBeInTheDocument();
      expect(screen.queryByTestId("vmware-companion-attach-button")).not.toBeInTheDocument();
      expect(attachVmwareCompanionMock).toHaveBeenCalledTimes(1);
    });

    it("on failure, shows the reason and offers Retry and Choose another file", async () => {
      attachVmwareCompanionMock.mockRejectedValue(new Error("Only .vmsn and .vmss files are accepted as VMware companions."));
      renderSection(baseProps());
      await selectFile();
      await userEvent.click(screen.getByTestId("vmware-companion-attach-button"));

      const failed = await screen.findByTestId("vmware-companion-failed");
      expect(failed).toHaveTextContent("Could not attach VMware metadata.");
      expect(failed).toHaveTextContent("Only .vmsn and .vmss files are accepted");
      expect(screen.getByTestId("vmware-companion-retry-button")).toBeInTheDocument();
      expect(screen.getByTestId("vmware-companion-choose-another")).toBeInTheDocument();
    });

    it("Retry re-submits the same file without requiring re-selection", async () => {
      attachVmwareCompanionMock.mockRejectedValueOnce(new Error("network blip")).mockResolvedValueOnce({ id: "c1" });
      const onChanged = vi.fn();
      renderSection(baseProps({ onChanged }));
      await selectFile();
      await userEvent.click(screen.getByTestId("vmware-companion-attach-button"));
      await screen.findByTestId("vmware-companion-failed");

      await userEvent.click(screen.getByTestId("vmware-companion-retry-button"));

      await vi.waitFor(() => expect(onChanged).toHaveBeenCalledTimes(1));
      expect(attachVmwareCompanionMock).toHaveBeenCalledTimes(2);
    });

    it("Choose another file returns to the picker", async () => {
      attachVmwareCompanionMock.mockRejectedValue(new Error("rejected"));
      renderSection(baseProps());
      await selectFile();
      await userEvent.click(screen.getByTestId("vmware-companion-attach-button"));
      await screen.findByTestId("vmware-companion-failed");

      await userEvent.click(screen.getByTestId("vmware-companion-choose-another"));

      expect(screen.getByTestId("vmware-companion-file-input")).toBeInTheDocument();
      expect(screen.queryByTestId("vmware-companion-failed")).not.toBeInTheDocument();
    });
  });

  describe("Associated state", () => {
    function associatedProps(overrides: Partial<VmwareCompanionSectionProps> = {}): VmwareCompanionSectionProps {
      return baseProps({
        hasCompanion: true,
        recommended: false,
        companionId: "companion-1",
        companionType: "vmware_vmsn",
        companionFilename: "Ubuntu22.04-snapshot.vmsn",
        companionSha256: "abcdef0123456789".repeat(4),
        companionSizeBytes: 5567519,
        warningText: null,
        ...overrides,
      });
    }

    it("shows the original filename (never the server-internal filename), type, size and short hash", () => {
      renderSection(associatedProps());
      const panel = screen.getByTestId("vmware-companion-associated");
      expect(panel).toHaveTextContent("Associated");
      expect(screen.getByTestId("vmware-companion-filename")).toHaveTextContent("Ubuntu22.04-snapshot.vmsn");
      expect(panel).not.toHaveTextContent("memory-image.vmsn");
      expect(panel).toHaveTextContent(".vmsn");
      expect(panel).toHaveTextContent("5.3 MB");
      expect(screen.getByTestId("vmware-companion-sha256")).toHaveTextContent("abcdef0123456789".slice(0, 12));
    });

    it("Replace opens the same file picker as Attach", async () => {
      renderSection(associatedProps());
      await userEvent.click(screen.getByTestId("vmware-companion-replace-button"));
      expect(screen.getByTestId("vmware-companion-file-input")).toBeInTheDocument();
    });

    it("Replace uses the same POST endpoint (attachVmwareCompanion), never a delete-then-create", async () => {
      attachVmwareCompanionMock.mockResolvedValue({ id: "companion-1", companion_type: "vmware_vmss" });
      const onChanged = vi.fn();
      renderSection(associatedProps({ onChanged }));
      await userEvent.click(screen.getByTestId("vmware-companion-replace-button"));
      await userEvent.upload(screen.getByTestId("vmware-companion-file-input"), new File(["x"], "new.vmss"));
      await userEvent.click(screen.getByTestId("vmware-companion-attach-button"));

      await vi.waitFor(() => expect(onChanged).toHaveBeenCalledTimes(1));
      expect(attachVmwareCompanionMock).toHaveBeenCalledWith(CASE, EVIDENCE, expect.any(File));
      expect(deleteVmwareCompanionMock).not.toHaveBeenCalled();
    });

    it("Remove requires explicit confirmation and shows the reliability warning before deleting", async () => {
      renderSection(associatedProps());
      await userEvent.click(screen.getByTestId("vmware-companion-remove-button"));

      const confirm = screen.getByTestId("vmware-companion-confirm-remove");
      expect(confirm).toHaveTextContent("Removing snapshot metadata may reduce the reliability of VMware memory analysis.");
      expect(deleteVmwareCompanionMock).not.toHaveBeenCalled();
    });

    it("confirming Remove calls DELETE with the companion id and refetches on success", async () => {
      deleteVmwareCompanionMock.mockResolvedValue(undefined);
      const onChanged = vi.fn();
      renderSection(associatedProps({ onChanged }));
      await userEvent.click(screen.getByTestId("vmware-companion-remove-button"));
      await userEvent.click(screen.getByTestId("vmware-companion-confirm-remove-button"));

      await vi.waitFor(() => expect(onChanged).toHaveBeenCalledTimes(1));
      expect(deleteVmwareCompanionMock).toHaveBeenCalledWith(CASE, EVIDENCE, "companion-1");
    });

    it("Cancel on the remove confirmation returns to Associated without deleting", async () => {
      renderSection(associatedProps());
      await userEvent.click(screen.getByTestId("vmware-companion-remove-button"));
      await userEvent.click(screen.getByTestId("vmware-companion-cancel-remove-button"));

      expect(screen.getByTestId("vmware-companion-associated")).toBeInTheDocument();
      expect(deleteVmwareCompanionMock).not.toHaveBeenCalled();
    });
  });
});
