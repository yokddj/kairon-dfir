import { describe, expect, it, vi, beforeAll, afterAll, beforeEach } from "vitest";
import type { MemoryUploadStatus } from "./client";

const originalFetch = globalThis.fetch;

beforeAll(() => {
  globalThis.fetch = vi.fn();
});

beforeEach(() => {
  (globalThis.fetch as ReturnType<typeof vi.fn>).mockClear();
});

afterAll(() => {
  globalThis.fetch = originalFetch;
});

function mockResponse(
  body: unknown,
  status = 200,
  extraHeaders: Record<string, string> = {},
) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...extraHeaders },
  });
}

function mockNetworkError() {
  return Promise.reject(new TypeError("Failed to fetch"));
}

describe("apiFetch cache policy", () => {
  it("sends cache: no-store for GET requests", async () => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValue(
      new Response("[]", { status: 200, headers: { "content-type": "application/json" } }),
    );

    const { apiFetch } = await import("./client");
    await apiFetch("/cases");

    const [, init] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.lastCall!;
    expect(init).toHaveProperty("cache", "no-store");
  });

  it("preserves caller-provided options (method, headers, body)", async () => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValue(
      new Response(JSON.stringify({ id: "1" }), { status: 200, headers: { "content-type": "application/json" } }),
    );

    const { apiFetch } = await import("./client");
    await apiFetch("/cases", {
      method: "POST",
      headers: { "X-Custom": "value" },
      body: JSON.stringify({ name: "test" }),
    });

    const [, init] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.lastCall!;
    expect(init).toHaveProperty("cache", "no-store");
    expect(init).toHaveProperty("method", "POST");
    expect(init).toHaveProperty("body", JSON.stringify({ name: "test" }));
    expect((init as RequestInit).headers).toEqual({ "X-Custom": "value" });
  });

  it("caller-provided cache value cannot override required no-store policy", async () => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValue(
      new Response("[]", { status: 200, headers: { "content-type": "application/json" } }),
    );

    const { apiFetch } = await import("./client");
    await apiFetch("/cases", { cache: "force-cache" as RequestCache });

    const [, init] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.lastCall!;
    expect(init).toHaveProperty("cache", "no-store");
    expect(init.cache).toBe("no-store");
  });

  it("uses cache: no-store through api object endpoints (GET)", async () => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValue(
      new Response("[]", { status: 200, headers: { "content-type": "application/json" } }),
    );

    const { api } = await import("./client");
    await api.listCases();

    const [, init] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.lastCall!;
    expect(init).toHaveProperty("cache", "no-store");
  });

  it("uses cache: no-store through api object endpoints (POST)", async () => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValue(
      new Response(JSON.stringify({ id: "c-1", name: "test", description: null, status: "open", mode: "investigation", timezone: null, created_at: "", updated_at: "" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );

    const { api } = await import("./client");
    await api.createCase({ name: "test" });

    const [, init] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.lastCall!;
    expect(init).toHaveProperty("method", "POST");
    expect(init).toHaveProperty("cache", "no-store");
  });
});

describe("uploadBlob fetch transport", () => {
  it("uses PUT method", async () => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValue(mockResponse({ ok: true }));

    const { uploadBlob } = await import("./client");
    await uploadBlob("/upload", new Blob(["test"]));

    const [, init] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.lastCall!;
    expect(init).toHaveProperty("method", "PUT");
  });

  it("sends the exact Blob body", async () => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValue(mockResponse({ ok: true }));

    const { uploadBlob } = await import("./client");
    const blob = new Blob(["hello world"]);
    await uploadBlob("/upload", blob);

    const [, init] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.lastCall!;
    expect(init).toHaveProperty("body");
    expect(init.body).toBe(blob);
  });

  it("uses cache: no-store on the fetch call", async () => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValue(mockResponse({ ok: true }));

    const { uploadBlob } = await import("./client");
    await uploadBlob("/upload", new Blob(["test"]));

    const [, init] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.lastCall!;
    expect(init).toHaveProperty("cache", "no-store");
  });

  it("passes AbortSignal to fetch", async () => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValue(mockResponse({ ok: true }));

    const { uploadBlob } = await import("./client");
    const controller = new AbortController();
    await uploadBlob("/upload", new Blob(["test"]), { signal: controller.signal });

    const [, init] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.lastCall!;
    expect(init.signal).toBeInstanceOf(AbortSignal);
  });

  it("preserves Content-Type and custom headers", async () => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValue(mockResponse({ ok: true }));

    const { uploadBlob } = await import("./client");
    await uploadBlob("/upload", new Blob(["test"]), {
      contentType: "application/octet-stream",
      headers: { "X-Kairon-Chunk-SHA256": "abc123" },
    });

    const [, init] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.lastCall!;
    const headers = init.headers as Headers;
    expect(headers.get("content-type")).toBe("application/octet-stream");
    expect(headers.get("x-kairon-chunk-sha256")).toBe("abc123");
    expect(headers.get("accept")).toBe("application/json");
  });

  it("resolves parsed JSON on HTTP 200", async () => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValue(
      mockResponse({ upload_id: "u-1", status: "uploading" }),
    );

    const { uploadBlob } = await import("./client");
    const result = await uploadBlob<{ upload_id: string }>("/upload", new Blob(["test"]));

    expect(result).toEqual({ upload_id: "u-1", status: "uploading" });
  });

  it("resolves parsed JSON on HTTP 201", async () => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValue(
      mockResponse({ created: true }, 201),
    );

    const { uploadBlob } = await import("./client");
    const result = await uploadBlob<{ created: boolean }>("/upload", new Blob(["test"]));

    expect(result).toEqual({ created: true });
  });

  it("rejects structured 409 with error_code", async () => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValue(
      new Response(
        JSON.stringify({ detail: { error_code: "MEMORY_UPLOAD_CHUNK_CONFLICT", message: "Chunk already received." } }),
        { status: 409, headers: { "content-type": "application/json" } },
      ),
    );

    const { uploadBlob } = await import("./client");
    await expect(
      uploadBlob("/upload", new Blob(["test"])),
    ).rejects.toMatchObject({
      status: 409,
      errorCode: "MEMORY_UPLOAD_CHUNK_CONFLICT",
      message: "Chunk already received.",
    });
  });

  it("rejects 422 with structured error", async () => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValue(
      new Response(
        JSON.stringify({ detail: { error_code: "MEMORY_UPLOAD_INVALID_CHUNK_LENGTH", message: "Chunk length mismatch." } }),
        { status: 422, headers: { "content-type": "application/json" } },
      ),
    );

    const { uploadBlob } = await import("./client");
    await expect(
      uploadBlob("/upload", new Blob(["test"])),
    ).rejects.toMatchObject({
      status: 422,
      errorCode: "MEMORY_UPLOAD_INVALID_CHUNK_LENGTH",
      message: "Chunk length mismatch.",
    });
  });

  it("rejects 500 as API error", async () => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValue(
      new Response("Internal Server Error", { status: 500, headers: { "content-type": "text/plain" } }),
    );

    const { uploadBlob } = await import("./client");
    await expect(
      uploadBlob("/upload", new Blob(["test"])),
    ).rejects.toMatchObject({
      status: 500,
    });
  });

  it("retries on network failure across base URLs", async () => {
    // First call fails with network error, second succeeds
    (globalThis.fetch as ReturnType<typeof vi.fn>)
      .mockRejectedValueOnce(new TypeError("Failed to fetch"))
      .mockResolvedValueOnce(mockResponse({ ok: true }));

    const { uploadBlob } = await import("./client");
    const result = await uploadBlob<{ ok: boolean }>("/upload", new Blob(["test"]));

    expect(result).toEqual({ ok: true });
    expect(globalThis.fetch).toHaveBeenCalledTimes(2);
  });

  it("throws aborted error when parent signal is aborted", async () => {
    const abortError = new DOMException("The operation was aborted.", "AbortError");
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockRejectedValue(abortError);

    const { uploadBlob } = await import("./client");
    const controller = new AbortController();
    controller.abort();

    await expect(
      uploadBlob("/upload", new Blob(["test"]), { signal: controller.signal }),
    ).rejects.toThrow("Upload aborted");
  });

  it("does not create XMLHttpRequest", async () => {
    const xhrSpy = vi.spyOn(globalThis as unknown as { XMLHttpRequest: typeof XMLHttpRequest }, "XMLHttpRequest", "get");
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValue(mockResponse({ ok: true }));

    const { uploadBlob } = await import("./client");
    await uploadBlob("/upload", new Blob(["test"]));

    expect(xhrSpy).not.toHaveBeenCalled();
    xhrSpy.mockRestore();
  });

  it("timeout aborts fetch and cleans up", async () => {
    const fetchMock = globalThis.fetch as ReturnType<typeof vi.fn>;
    fetchMock.mockImplementation((_url: unknown, init?: RequestInit) => {
      return new Promise<Response>((resolve, reject) => {
        const id = setTimeout(() => resolve(mockResponse({ ok: true })), 5000);
        if (init?.signal) {
          init.signal.addEventListener("abort", () => {
            clearTimeout(id);
            reject(new DOMException("The operation was aborted.", "AbortError"));
          }, { once: true });
        }
      });
    });

    const { uploadBlob } = await import("./client");
    const promise = uploadBlob("/upload", new Blob(["test"]), { timeoutMs: 10 });

    await expect(promise).rejects.toThrow("Upload timed out");
  });
});

describe("uploadMemoryUploadChunk integration", () => {
  it("preserves chunk SHA-256 header through API", async () => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValue(
      mockResponse({ upload_id: "u-1", status: "uploading" } as MemoryUploadStatus),
    );

    const { api } = await import("./client");
    await api.uploadMemoryUploadChunk("case-1", "upload-1", 0, new Blob(["data"]), {
      chunkSha256: "deadbeef",
    });

    const [, init] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.lastCall!;
    const headers = init.headers as Headers;
    expect(headers.get("x-kairon-chunk-sha256")).toBe("deadbeef");
    expect(headers.get("accept")).toBe("application/json");
    expect(headers.get("content-type")).toBe("application/octet-stream");
  });

  it("returns MemoryUploadStatus on success", async () => {
    const status = { upload_id: "u-1", status: "uploading" } as MemoryUploadStatus;
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValue(mockResponse(status));

    const { api } = await import("./client");
    const result = await api.uploadMemoryUploadChunk("case-1", "u-1", 0, new Blob(["data"]));

    expect(result).toEqual(status);
  });
});
