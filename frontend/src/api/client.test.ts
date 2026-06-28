import { describe, expect, it, vi, beforeAll, afterAll } from "vitest";

const originalFetch = globalThis.fetch;

beforeAll(() => {
  globalThis.fetch = vi.fn();
});

afterAll(() => {
  globalThis.fetch = originalFetch;
});

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
