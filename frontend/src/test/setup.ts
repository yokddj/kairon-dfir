import "@testing-library/jest-dom/vitest";

// jsdom does not implement Blob/File.arrayBuffer() (real browsers do).
// Client-side per-chunk SHA-256 (runResumableUpload's chunk hashing, the
// Wizard's resume file-verification) relies on it, so without this
// polyfill those code paths silently degrade to "no hash" under test
// instead of exercising the real verification logic.
if (typeof Blob !== "undefined" && typeof Blob.prototype.arrayBuffer !== "function") {
  Blob.prototype.arrayBuffer = function arrayBuffer(this: Blob): Promise<ArrayBuffer> {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => {
        // jsdom's FileReader (and every constructor reachable from this
        // vitest "jsdom" test environment's globalThis, including
        // Uint8Array/ArrayBuffer) lives in jsdom's own VM realm. Node's
        // native SubtleCrypto does a realm-sensitive instanceof check and
        // rejects that ArrayBuffer with "2nd argument is not instance of
        // ArrayBuffer, Buffer, TypedArray, or DataView" even though the
        // bytes are fine -- constructing a fresh ArrayBuffer here doesn't
        // help, since `new` still resolves to jsdom's shadowed constructor.
        // Node's global Buffer is NOT shadowed by jsdom and is explicitly
        // one of the accepted BufferSource types, so route through it.
        const jsdomBuffer = reader.result as ArrayBuffer;
        resolve(Buffer.from(new Uint8Array(jsdomBuffer)) as unknown as ArrayBuffer);
      };
      reader.onerror = () => reject(reader.error ?? new Error("Blob.arrayBuffer() polyfill failed to read blob"));
      reader.readAsArrayBuffer(this);
    });
  };
}
