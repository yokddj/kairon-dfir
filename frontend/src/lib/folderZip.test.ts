import { describe, expect, it } from "vitest";

import { crc32Update, folderNameOf, zipFolder } from "./folderZip";

function folderFile(path: string, data: string) {
  const file = new File([data], path.split("/").pop() ?? path, { lastModified: Date.UTC(2025, 1, 15, 12, 0, 0) });
  Object.defineProperty(file, "webkitRelativePath", { value: path });
  return file;
}

async function bytesOf(file: File) {
  return new Uint8Array(await file.arrayBuffer());
}

function find(bytes: Uint8Array, signature: number, from = 0) {
  const view = new DataView(bytes.buffer);
  for (let i = from; i <= bytes.length - 4; i += 1) if (view.getUint32(i, true) === signature) return i;
  return -1;
}

describe("zipFolder", () => {
  it("computes the standard CRC-32", () => {
    expect(crc32Update(0, new TextEncoder().encode("hello"))).toBe(0x3610a686);
    expect(crc32Update(crc32Update(0, new TextEncoder().encode("hel")), new TextEncoder().encode("lo"))).toBe(0x3610a686);
  });

  it("stores every file under its folder path with its CRC", async () => {
    const files = [folderFile("challenge/C/Users/alice/notes.txt", "hello"), folderFile("challenge/empty.bin", "")];
    const progress: number[] = [];
    const zip = await zipFolder(files, { onProgress: (value) => progress.push(value) });
    const bytes = await bytesOf(zip);
    const view = new DataView(bytes.buffer);

    expect(zip.name).toBe("challenge.zip");
    expect(folderNameOf(files)).toBe("challenge");
    expect(progress.at(-1)).toBe(1);
    expect(view.getUint32(0, true)).toBe(0x04034b50);
    expect(view.getUint16(8, true)).toBe(0); // stored
    expect(view.getUint32(14, true)).toBe(0x3610a686);
    expect(new TextDecoder().decode(bytes.subarray(30, 30 + view.getUint16(26, true)))).toBe("challenge/C/Users/alice/notes.txt");
    expect(new TextDecoder().decode(bytes.subarray(30 + 33, 30 + 33 + 5))).toBe("hello");

    const end = find(bytes, 0x06054b50);
    expect(view.getUint16(end + 10, true)).toBe(2);
    const directoryOffset = view.getUint32(end + 16, true);
    expect(view.getUint32(directoryOffset, true)).toBe(0x02014b50);
    expect(end + 22).toBe(bytes.length);
  });

  it("writes the ZIP64 end records when asked or needed", async () => {
    const bytes = await bytesOf(await zipFolder([folderFile("f/a.txt", "a")], { forceZip64: true }));
    const view = new DataView(bytes.buffer);
    const zip64End = find(bytes, 0x06064b50);
    expect(zip64End).toBeGreaterThan(0);
    expect(Number(view.getBigUint64(zip64End + 32, true))).toBe(1);
    expect(find(bytes, 0x07064b50, zip64End)).toBe(zip64End + 56);
    const end = find(bytes, 0x06054b50, zip64End);
    expect(view.getUint16(end + 10, true)).toBe(0xffff);
  });

  it("names the file the browser could not read", async () => {
    const file = folderFile("challenge/locked.db", "data");
    Object.defineProperty(file, "slice", {
      value: () => ({ arrayBuffer: () => Promise.reject(new DOMException("could not be read", "NotReadableError")) }),
    });
    await expect(zipFolder([file])).rejects.toThrow(/could not read "challenge\/locked.db"/);
  });
});
