import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemorySymbolImportPanel } from "./MemorySymbolImportPanel";

vi.mock("../../api/client", () => ({
  api: {
    listRecoverySources: vi.fn().mockResolvedValue([]),
    importPdb: vi.fn(),
    importIsf: vi.fn(),
    importPackage: vi.fn(),
    createRecoverySource: vi.fn(),
  },
}));

import { api } from "../../api/client";

describe("MemorySymbolImportPanel", () => {
  it("opens a modal that lists the four recovery actions", async () => {
    render(
      <MemorySymbolImportPanel
        requirementId="req-1"
        caseId="case-1"
        evidenceId="ev-1"
        onCompleted={vi.fn()}
      />,
    );
    const opener = screen.getByTestId("memory-symbol-import-open");
    fireEvent.click(opener);
    await waitFor(() => {
      expect(screen.getByTestId("memory-symbol-import-panel")).toBeInTheDocument();
    });
    expect(screen.getByTestId("memory-symbol-import-tab-import-pdb")).toBeInTheDocument();
    expect(screen.getByTestId("memory-symbol-import-tab-import-isf")).toBeInTheDocument();
    expect(screen.getByTestId("memory-symbol-import-tab-import-package")).toBeInTheDocument();
    expect(screen.getByTestId("memory-symbol-import-tab-configure")).toBeInTheDocument();
  });

  it("imports a PDB and surfaces the result", async () => {
    const onCompleted = vi.fn();
    (api.importPdb as unknown as ReturnType<typeof vi.fn>).mockResolvedValue({
      status: "ready",
      cached_symbol_id: "cache-1",
    });
    render(
      <MemorySymbolImportPanel
        requirementId="req-1"
        caseId="case-1"
        evidenceId="ev-1"
        onCompleted={onCompleted}
      />,
    );
    fireEvent.click(screen.getByTestId("memory-symbol-import-open"));
    const file = new File(["fake-pdb"], "ntkrnlmp.pdb", { type: "application/octet-stream" });
    fireEvent.change(screen.getByTestId("memory-symbol-import-file-pdb"), {
      target: { files: [file] },
    });
    fireEvent.click(screen.getByTestId("memory-symbol-import-submit-pdb"));
    await waitFor(() => {
      expect(api.importPdb).toHaveBeenCalled();
    });
    await waitFor(() => {
      expect(onCompleted).toHaveBeenCalled();
    });
  });

  it("rejects an identity mismatch from the backend", async () => {
    (api.importPdb as unknown as ReturnType<typeof vi.fn>).mockResolvedValue({
      status: "identity_mismatch",
      error_code: "SYMBOL_PDB_IDENTITY_MISMATCH",
      sanitized_message: "PDB GUID/age does not match the requirement.",
    });
    render(
      <MemorySymbolImportPanel
        requirementId="req-1"
        caseId="case-1"
        evidenceId="ev-1"
        onCompleted={vi.fn()}
      />,
    );
    fireEvent.click(screen.getByTestId("memory-symbol-import-open"));
    const file = new File(["fake-pdb"], "ntkrnlmp.pdb", { type: "application/octet-stream" });
    fireEvent.change(screen.getByTestId("memory-symbol-import-file-pdb"), {
      target: { files: [file] },
    });
    fireEvent.click(screen.getByTestId("memory-symbol-import-submit-pdb"));
    await waitFor(() => {
      expect(screen.getByTestId("memory-symbol-import-result")).toBeInTheDocument();
    });
  });
});
