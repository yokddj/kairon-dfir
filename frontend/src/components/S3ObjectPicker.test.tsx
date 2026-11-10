import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { S3ObjectPicker } from "./S3ObjectPicker";

const listS3Objects = vi.fn();

vi.mock("../api/client", () => ({
  api: { listS3Objects: (...args: unknown[]) => listS3Objects(...args) },
}));

function renderPicker(onSelect = vi.fn()) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <S3ObjectPicker caseId="case-1" defaultBucket="evidence" selected={null} onSelect={onSelect} />
    </QueryClientProvider>,
  );
  return onSelect;
}

describe("S3ObjectPicker", () => {
  beforeEach(() => {
    listS3Objects.mockReset();
    listS3Objects.mockImplementation(async (_caseId: string, params: { prefix?: string }) =>
      params.prefix === "cases/"
        ? {
            bucket: "evidence",
            prefix: "cases/",
            prefixes: [],
            objects: [
              { key: "cases/ws01.zip", name: "ws01.zip", size: 3 * 1024 * 1024, last_modified: null, storage_class: "STANDARD" },
              { key: "cases/old.zip", name: "old.zip", size: 10, last_modified: null, storage_class: "GLACIER" },
            ],
            next_token: null,
          }
        : { bucket: "evidence", prefix: "", prefixes: ["cases/"], objects: [], next_token: null },
    );
  });

  it("browses into a folder and picks an object", async () => {
    const onSelect = renderPicker();
    fireEvent.click(await screen.findByText("cases/"));
    fireEvent.click(await screen.findByText("ws01.zip"));
    expect(listS3Objects).toHaveBeenLastCalledWith("case-1", { bucket: "evidence", prefix: "cases/", token: undefined });
    expect(onSelect).toHaveBeenCalledWith({ bucket: "evidence", object: expect.objectContaining({ key: "cases/ws01.zip" }) });
  });

  it("does not offer archived objects", async () => {
    renderPicker();
    fireEvent.click(await screen.findByText("cases/"));
    await waitFor(() => expect(screen.getByText("old.zip").closest("button")).toBeDisabled());
  });
});
