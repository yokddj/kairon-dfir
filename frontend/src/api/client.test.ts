import { describe, expect, it, vi, beforeAll, afterAll, beforeEach, afterEach } from "vitest";
import type { MemoryUploadStatus } from "./client";

const originalFetch = globalThis.fetch;

beforeAll(() => {
  globalThis.fetch = vi.fn();
});

beforeEach(() => {
  (globalThis.fetch as ReturnType<typeof vi.fn>).mockClear();
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  globalThis.fetch = globalThis.fetch || originalFetch;
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

type XhrScenario = {
  status?: number;
  responseText?: string;
  contentType?: string;
  error?: boolean;
  timeout?: boolean;
};

function installMockXhr(scenarios: XhrScenario[]) {
  const instances: Array<{
    method?: string;
    url?: string;
    async?: boolean;
    headers: Record<string, string>;
    body?: XMLHttpRequestBodyInit | null;
    timeout: number;
    abort: () => void;
  }> = [];
  class MockXHR {
    method?: string;
    url?: string;
    async?: boolean;
    headers: Record<string, string> = {};
    body?: XMLHttpRequestBodyInit | null;
    status = 0;
    responseText = "";
    timeout = 0;
    onload: (() => void) | null = null;
    onerror: (() => void) | null = null;
    ontimeout: (() => void) | null = null;
    onabort: (() => void) | null = null;
    private contentType = "application/json";
    open(method: string, url: string, async: boolean) {
      this.method = method;
      this.url = url;
      this.async = async;
    }
    setRequestHeader(key: string, value: string) {
      this.headers[key.toLowerCase()] = value;
    }
    getResponseHeader(key: string) {
      return key.toLowerCase() === "content-type" ? this.contentType : null;
    }
    send(body?: XMLHttpRequestBodyInit | null) {
      this.body = body;
      instances.push(this);
      const scenario = scenarios.shift() ?? { status: 200, responseText: JSON.stringify({ ok: true }) };
      setTimeout(() => {
        if (scenario.error) {
          this.onerror?.();
          return;
        }
        if (scenario.timeout) {
          this.ontimeout?.();
          return;
        }
        this.status = scenario.status ?? 200;
        this.responseText = scenario.responseText ?? JSON.stringify({ ok: true });
        this.contentType = scenario.contentType ?? "application/json";
        this.onload?.();
      }, 0);
    }
    abort() {
      this.onabort?.();
    }
  }
  vi.stubGlobal("XMLHttpRequest", MockXHR);
  return instances;
}

function readBlobText(blob: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(reader.error ?? new Error("Failed to read blob"));
    reader.onload = () => resolve(String(reader.result ?? ""));
    reader.readAsText(blob);
  });
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

  it("posts Complete analysis to the evidence run-all endpoint", async () => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValue(
      new Response(JSON.stringify({ id: "batch-1", requested_profiles: ["processes_basic"], run_ids: ["run-1"] }), {
        status: 201,
        headers: { "content-type": "application/json" },
      }),
    );

    const { api } = await import("./client");
    await api.startMemoryRunAll("case-1", "ev-1", {
      mode: "missing_or_failed",
      authorization_acknowledged: true,
      continue_on_failure: true,
    });

    const [url, init] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.lastCall!;
    expect(String(url)).toContain("/cases/case-1/memory/evidences/ev-1/run-all");
    expect(init).toHaveProperty("method", "POST");
    expect(JSON.parse(String((init as RequestInit).body))).toEqual({
      mode: "missing_or_failed",
      authorization_acknowledged: true,
      continue_on_failure: true,
    });
  });
});

describe("uploadBlob XHR transport", () => {
  it("uses PUT method", async () => {
    const instances = installMockXhr([{ responseText: JSON.stringify({ ok: true }) }]);

    const { uploadBlob } = await import("./client");
    await uploadBlob("/upload", new Blob(["test"]));

    expect(instances[0].method).toBe("PUT");
  });

  it("sends the exact Blob body", async () => {
    const instances = installMockXhr([{ responseText: JSON.stringify({ ok: true }) }]);

    const { uploadBlob } = await import("./client");
    const blob = new Blob(["hello world"]);
    await uploadBlob("/upload", blob);

    expect(instances[0].body).toBe(blob);
  });

  it("sends no-store cache header", async () => {
    const instances = installMockXhr([{ responseText: JSON.stringify({ ok: true }) }]);

    const { uploadBlob } = await import("./client");
    await uploadBlob("/upload", new Blob(["test"]));

    expect(instances[0].headers["cache-control"]).toBe("no-store");
  });

  it("throws aborted error when parent signal is aborted", async () => {
    installMockXhr([{ responseText: JSON.stringify({ ok: true }) }]);
    const { uploadBlob } = await import("./client");
    const controller = new AbortController();
    controller.abort();

    await expect(uploadBlob("/upload", new Blob(["test"]), { signal: controller.signal })).rejects.toThrow("Upload aborted");
  });

  it("stops immediately when parent aborts an in-flight XHR", async () => {
    const instances = installMockXhr([{ responseText: JSON.stringify({ ok: true }) }, { responseText: JSON.stringify({ ok: true }) }]);
    const { uploadBlob } = await import("./client");
    const controller = new AbortController();

    const promise = uploadBlob("/upload", new Blob(["test"]), { signal: controller.signal });
    controller.abort();

    await expect(promise).rejects.toThrow("Upload aborted");
    expect(instances).toHaveLength(1);
  });

  it("preserves Content-Type and custom headers", async () => {
    const instances = installMockXhr([{ responseText: JSON.stringify({ ok: true }) }]);

    const { uploadBlob } = await import("./client");
    await uploadBlob("/upload", new Blob(["test"]), {
      contentType: "application/octet-stream",
      headers: { "X-Kairon-Chunk-SHA256": "abc123" },
    });

    expect(instances[0].headers["content-type"]).toBe("application/octet-stream");
    expect(instances[0].headers["x-kairon-chunk-sha256"]).toBe("abc123");
    expect(instances[0].headers.accept).toBe("application/json");
  });

  it("resolves parsed JSON on HTTP 200", async () => {
    installMockXhr([{ responseText: JSON.stringify({ upload_id: "u-1", status: "uploading" }) }]);

    const { uploadBlob } = await import("./client");
    const result = await uploadBlob<{ upload_id: string }>("/upload", new Blob(["test"]));

    expect(result).toEqual({ upload_id: "u-1", status: "uploading" });
  });

  it("resolves parsed JSON on HTTP 201", async () => {
    installMockXhr([{ status: 201, responseText: JSON.stringify({ created: true }) }]);

    const { uploadBlob } = await import("./client");
    const result = await uploadBlob<{ created: boolean }>("/upload", new Blob(["test"]));

    expect(result).toEqual({ created: true });
  });

  it("resolves undefined on HTTP 204", async () => {
    installMockXhr([{ status: 204, responseText: "", contentType: "" }]);

    const { uploadBlob } = await import("./client");
    await expect(uploadBlob("/upload", new Blob(["test"]))).resolves.toBeUndefined();
  });

  it("rejects structured 409 with error_code", async () => {
    installMockXhr([{ status: 409, responseText: JSON.stringify({ detail: { error_code: "MEMORY_UPLOAD_CHUNK_CONFLICT", message: "Chunk already received." } }) }]);

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
    installMockXhr([{ status: 422, responseText: JSON.stringify({ detail: { error_code: "MEMORY_UPLOAD_INVALID_CHUNK_LENGTH", message: "Chunk length mismatch." } }) }]);

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
    installMockXhr([{ status: 500, responseText: "Internal Server Error", contentType: "text/plain" }]);

    const { uploadBlob } = await import("./client");
    await expect(
      uploadBlob("/upload", new Blob(["test"])),
    ).rejects.toMatchObject({
      status: 500,
    });
  });

  it("rejects network failure when the same-origin API is unavailable", async () => {
    installMockXhr([{ error: true }, { responseText: JSON.stringify({ ok: true }) }]);

    const { uploadBlob } = await import("./client");

    await expect(uploadBlob<{ ok: boolean }>("/upload", new Blob(["test"]))).rejects.toThrow(
      "The backend could not be reached during upload. Tried the configured API endpoints.",
    );
  });

  it("timeout rejects without treating upload as success", async () => {
    installMockXhr([{ timeout: true }, { timeout: true }]);

    const { uploadBlob } = await import("./client");
    const promise = uploadBlob("/upload", new Blob(["test"]), { timeoutMs: 10 });

    await expect(promise).rejects.toThrow("Upload timed out");
  });

  it("reports malformed successful JSON as parsing failure", async () => {
    installMockXhr([{ responseText: "{", contentType: "application/json" }]);

    const { uploadBlob } = await import("./client");
    await expect(uploadBlob("/upload", new Blob(["test"]))).rejects.toThrow("Upload response parsing failed after successful HTTP 200");
  });
});

describe("uploadMemoryUploadChunk integration", () => {
  it("uses XMLHttpRequest POST multipart FormData for memory chunks", async () => {
    const instances = installMockXhr([{ status: 204, responseText: "", contentType: "" }]);
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValue(mockResponse({ upload_id: "u-1", status: "uploading" } as MemoryUploadStatus));

    const { api } = await import("./client");
    const blob = new Blob(["data"], { type: "application/octet-stream" });
    await api.uploadMemoryUploadChunk("case-1", "upload-1", 0, blob, {
      chunkSha256: "deadbeef",
    });

    expect(instances).toHaveLength(1);
    expect(instances[0].method).toBe("POST");
    expect(instances[0].body).toBeInstanceOf(FormData);
    expect(instances[0].url).toContain("/cases/case-1/memory/uploads/upload-1/chunks/0");
    expect(instances[0].headers.accept).toBe("application/json");
    expect(instances[0].headers["cache-control"]).toBe("no-store");
    expect(instances[0].headers["x-kairon-chunk-sha256"]).toBe("deadbeef");
    expect(instances[0].headers["content-type"]).toBeUndefined();

    const form = instances[0].body as FormData;
    const chunk = form.get("chunk") as File;
    expect(chunk).toBeInstanceOf(Blob);
    expect(chunk.name).toBe("chunk-0.bin");
    await expect(readBlobText(chunk)).resolves.toBe(await readBlobText(blob));
  });

  it("returns MemoryUploadStatus on success", async () => {
    const status = { upload_id: "u-1", status: "uploading" } as MemoryUploadStatus;
    installMockXhr([{ status: 204, responseText: "", contentType: "" }]);
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValue(mockResponse(status));

    const { api } = await import("./client");
    const result = await api.uploadMemoryUploadChunk("case-1", "u-1", 0, new Blob(["data"]));

    expect(result).toEqual(status);
  });

  it("accepts 204 successful POST response and fetches authoritative status", async () => {
    const status = { upload_id: "u-1", status: "uploading", bytes_received: 4, expected_bytes: 8 } as MemoryUploadStatus;
    installMockXhr([{ status: 204, responseText: "", contentType: "" }]);
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce(mockResponse(status));

    const { api } = await import("./client");
    const result = await api.uploadMemoryUploadChunk("case-1", "u-1", 0, new Blob(["data"]));

    expect(result).toEqual(status);
    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
    expect(String((globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0][0])).toContain("/cases/case-1/memory/uploads/u-1");
  });

  it("timeout rejects and never fetches status", async () => {
    installMockXhr([{ timeout: true }]);
    const { api } = await import("./client");

    await expect(api.uploadMemoryUploadChunk("case-1", "u-1", 0, new Blob(["data"]))).rejects.toThrow("Upload timed out");
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("network failure rejects and never fetches status", async () => {
    installMockXhr([{ error: true }]);
    const { api } = await import("./client");

    await expect(api.uploadMemoryUploadChunk("case-1", "u-1", 0, new Blob(["data"]))).rejects.toThrow("The backend could not be reached during upload");
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("user abort rejects immediately and never fetches status", async () => {
    installMockXhr([{ responseText: JSON.stringify({ ok: true }) }]);
    const { api } = await import("./client");
    const controller = new AbortController();

    const promise = api.uploadMemoryUploadChunk("case-1", "u-1", 0, new Blob(["data"]), { signal: controller.signal });
    controller.abort();

    await expect(promise).rejects.toThrow("Upload aborted");
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("uses XMLHttpRequest POST multipart FormData for direct memory uploads", async () => {
    const status = { upload_id: "direct-1", status: "completed", evidence_id: "ev-1" } as MemoryUploadStatus;
    const instances = installMockXhr([{ status: 201, responseText: JSON.stringify(status), contentType: "application/json" }]);

    const { api } = await import("./client");
    const file = new File(["small"], "small.dmp", { type: "application/octet-stream" });
    const result = await api.directMemoryUpload("case-1", file, {
      filename: file.name,
      expected_size_bytes: file.size,
      provided_host: "WS01",
      authorization_acknowledged: true,
      upload_mode: "direct",
    });

    expect(result).toEqual(status);
    expect(instances).toHaveLength(1);
    expect(instances[0].method).toBe("POST");
    expect(instances[0].url).toContain("/cases/case-1/memory/uploads/direct");
    expect(instances[0].headers["content-type"]).toBeUndefined();
    const form = instances[0].body as FormData;
    expect(form.get("filename")).toBe("small.dmp");
    expect(form.get("expected_size_bytes")).toBe(String(file.size));
    expect(form.get("provided_host")).toBe("WS01");
    expect(form.get("authorization_acknowledged")).toBe("true");
    expect(form.get("file")).toBeInstanceOf(Blob);
  });
});

describe("memory artifact observation endpoints", () => {
  it("hits the correct environment-variables URL", async () => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValue(
      new Response(JSON.stringify({ items: [], total: 0, page: 1, page_size: 30, document_type: "memory_environment_variable" }), { status: 200, headers: { "content-type": "application/json" } }),
    );
    const { api } = await import("./client");
    await api.getMemoryEnvVariables("case-1", { evidence_id: "ev-1", pid: 4, run_id: "run-a", page: 2, page_size: 30 });
    const [url] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.lastCall!;
    expect(String(url)).toContain("/cases/case-1/memory/environment-variables");
    expect(String(url)).toContain("evidence_id=ev-1");
    expect(String(url)).toContain("pid=4");
    expect(String(url)).toContain("run_id=run-a");
    expect(String(url)).toContain("page=2");
  });

  it("hits the correct sids URL with filter", async () => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValue(
      new Response(JSON.stringify({ items: [], total: 0, page: 1, page_size: 30 }), { status: 200, headers: { "content-type": "application/json" } }),
    );
    const { api } = await import("./client");
    await api.getMemorySids("case-1", { evidence_id: "ev-1", pid: 100, sid: "S-1-5-18" });
    const [url] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.lastCall!;
    expect(String(url)).toContain("/cases/case-1/memory/sids");
    expect(String(url)).toContain("sid=S-1-5-18");
  });

  it("hits the correct privileges URL with enabled filter", async () => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValue(
      new Response(JSON.stringify({ items: [], total: 0, page: 1, page_size: 30 }), { status: 200, headers: { "content-type": "application/json" } }),
    );
    const { api } = await import("./client");
    await api.getMemoryPrivileges("case-1", { evidence_id: "ev-1", pid: 4, enabled: true });
    const [url] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.lastCall!;
    expect(String(url)).toContain("/cases/case-1/memory/privileges");
    expect(String(url)).toContain("enabled=true");
  });

  it("hits the correct vads URL with protection filter", async () => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValue(
      new Response(JSON.stringify({ items: [], total: 0, page: 1, page_size: 30 }), { status: 200, headers: { "content-type": "application/json" } }),
    );
    const { api } = await import("./client");
    await api.getMemoryVads("case-1", { evidence_id: "ev-1", pid: 4, protection: "PAGE_EXECUTE_READWRITE", tag: "VadS" });
    const [url] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.lastCall!;
    expect(String(url)).toContain("/cases/case-1/memory/vads");
    expect(String(url)).toContain("protection=PAGE_EXECUTE_READWRITE");
    expect(String(url)).toContain("tag=VadS");
  });

  it("omits undefined params from URL", async () => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValue(
      new Response(JSON.stringify({ items: [], total: 0, page: 1, page_size: 30 }), { status: 200, headers: { "content-type": "application/json" } }),
    );
    const { api } = await import("./client");
    await api.getMemoryEnvVariables("case-2", { evidence_id: "ev-2" });
    const [url] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.lastCall!;
    expect(String(url)).not.toContain("pid=");
    expect(String(url)).not.toContain("run_id=");
    expect(String(url)).toContain("evidence_id=ev-2");
  });

  it("rejects with structured error from backend", async () => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValue(
      new Response(JSON.stringify({ detail: { error_code: "CASE_NOT_FOUND", message: "Case not found" } }), { status: 404, headers: { "content-type": "application/json" } }),
    );
    const { api, ApiError } = await import("./client");
    await expect(api.getMemoryEnvVariables("bad-case", { evidence_id: "ev-1" })).rejects.toThrow();
  });
});
