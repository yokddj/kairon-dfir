import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";

import { hashFileWithProgress, IncrementalSha256 } from "./sha256";

describe("IncrementalSha256", () => {
  it("matches the known SHA-256 test vector for an empty input", () => {
    const hasher = new IncrementalSha256();
    expect(hasher.digestHex()).toBe(createHash("sha256").update(Buffer.alloc(0)).digest("hex"));
  });

  it("matches the known SHA-256 test vector for 'abc'", () => {
    const hasher = new IncrementalSha256();
    hasher.update(new TextEncoder().encode("abc"));
    expect(hasher.digestHex()).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  });

  it("matches Node's crypto for random data split across many chunk boundaries", () => {
    const bytes = new Uint8Array(500_000);
    for (let i = 0; i < bytes.length; i++) bytes[i] = (i * 37 + 11) % 256;

    const expected = createHash("sha256").update(bytes).digest("hex");

    const hasher = new IncrementalSha256();
    // Deliberately uneven chunk sizes to exercise the buffer boundary logic.
    const chunkSizes = [1, 63, 64, 65, 127, 4096, 999_999];
    let offset = 0;
    let chunkIndex = 0;
    while (offset < bytes.length) {
      const size = chunkSizes[chunkIndex % chunkSizes.length];
      hasher.update(bytes.subarray(offset, Math.min(offset + size, bytes.length)));
      offset += size;
      chunkIndex++;
    }
    expect(hasher.digestHex()).toBe(expected);
  });
});

describe("hashFileWithProgress", () => {
  it("hashes a File matching Node's crypto and reports monotonic progress ending at 1", async () => {
    const content = "x".repeat(5_000_000);
    const file = new File([content], "big.bin");
    const expected = createHash("sha256").update(content).digest("hex");

    const progressValues: number[] = [];
    const hash = await hashFileWithProgress(file, (fraction) => progressValues.push(fraction), 1024 * 1024);

    expect(hash).toBe(expected);
    expect(progressValues[0]).toBe(0);
    expect(progressValues[progressValues.length - 1]).toBe(1);
    for (let i = 1; i < progressValues.length; i++) {
      expect(progressValues[i]).toBeGreaterThanOrEqual(progressValues[i - 1]);
    }
  });

  it("hashes an empty file without error", async () => {
    const file = new File([], "empty.bin");
    const expected = createHash("sha256").update(Buffer.alloc(0)).digest("hex");
    const hash = await hashFileWithProgress(file);
    expect(hash).toBe(expected);
  });
});
