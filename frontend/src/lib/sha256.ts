// Incremental SHA-256 so large evidence files can be hashed client-side in
// chunks with progress feedback, without loading the whole file into memory
// at once (SubtleCrypto.digest() only accepts a single complete buffer).
const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function rotr(x: number, n: number): number {
  return (x >>> n) | (x << (32 - n));
}

export class IncrementalSha256 {
  private h = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
  private buffer = new Uint8Array(64);
  private bufferLength = 0;
  private totalLength = 0;
  private finalized = false;

  update(chunk: Uint8Array): void {
    if (this.finalized) throw new Error("Cannot update a finalized hash");
    this.totalLength += chunk.length;
    let offset = 0;
    if (this.bufferLength > 0) {
      const needed = 64 - this.bufferLength;
      const take = Math.min(needed, chunk.length);
      this.buffer.set(chunk.subarray(0, take), this.bufferLength);
      this.bufferLength += take;
      offset += take;
      if (this.bufferLength === 64) {
        this.processBlock(this.buffer);
        this.bufferLength = 0;
      }
    }
    while (offset + 64 <= chunk.length) {
      this.processBlock(chunk.subarray(offset, offset + 64));
      offset += 64;
    }
    if (offset < chunk.length) {
      this.buffer.set(chunk.subarray(offset), 0);
      this.bufferLength = chunk.length - offset;
    }
  }

  private processBlock(block: Uint8Array): void {
    const w = new Uint32Array(64);
    for (let i = 0; i < 16; i++) {
      w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | block[i * 4 + 3];
    }
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
    }
    let [a, b, c, d, e, f, g, hh] = this.h;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (hh + S1 + ch + K[i] + w[i]) | 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) | 0;
      hh = g;
      g = f;
      f = e;
      e = (d + temp1) | 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) | 0;
    }
    this.h[0] = (this.h[0] + a) | 0;
    this.h[1] = (this.h[1] + b) | 0;
    this.h[2] = (this.h[2] + c) | 0;
    this.h[3] = (this.h[3] + d) | 0;
    this.h[4] = (this.h[4] + e) | 0;
    this.h[5] = (this.h[5] + f) | 0;
    this.h[6] = (this.h[6] + g) | 0;
    this.h[7] = (this.h[7] + hh) | 0;
  }

  digestHex(): string {
    this.finalized = true;
    const totalBits = this.totalLength * 8;
    let paddedLength = this.bufferLength + 1;
    while (paddedLength % 64 !== 56) paddedLength++;
    const finalLength = paddedLength + 8;
    const padded = new Uint8Array(finalLength);
    padded.set(this.buffer.subarray(0, this.bufferLength), 0);
    padded[this.bufferLength] = 0x80;
    const view = new DataView(padded.buffer);
    const high = Math.floor(totalBits / 0x100000000);
    const low = totalBits >>> 0;
    view.setUint32(paddedLength, high, false);
    view.setUint32(paddedLength + 4, low, false);
    for (let offset = 0; offset < finalLength; offset += 64) {
      this.processBlock(padded.subarray(offset, offset + 64));
    }
    return Array.from(this.h)
      .map((word) => (word >>> 0).toString(16).padStart(8, "0"))
      .join("");
  }
}

const DEFAULT_CHUNK_SIZE = 8 * 1024 * 1024;

function readBlobAsArrayBuffer(blob: Blob): Promise<ArrayBuffer> {
  // Some Blob.slice() implementations (older jsdom in tests) don't expose
  // arrayBuffer() on the resulting slice, so FileReader is used for
  // portability - it works in every browser and in jsdom alike.
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result as ArrayBuffer);
    reader.onerror = () => reject(reader.error ?? new Error("Failed to read file chunk"));
    reader.readAsArrayBuffer(blob);
  });
}

/**
 * Hashes a single Blob/File in one shot (e.g. one upload chunk). Pure JS,
 * not SubtleCrypto -- unlike crypto.subtle.digest(), this works over plain
 * HTTP. Browsers restrict SubtleCrypto to secure contexts (HTTPS or
 * localhost), so a crypto.subtle-based hash silently becomes unavailable
 * the moment Kairon is served over HTTP, which is exactly the deployed
 * reality this needs to hold up under.
 */
export async function hashBlob(blob: Blob): Promise<string> {
  const hasher = new IncrementalSha256();
  const buffer = await readBlobAsArrayBuffer(blob);
  hasher.update(new Uint8Array(buffer));
  return hasher.digestHex();
}

/** Hashes a File in chunks, reporting fractional progress (0..1) as it goes. Never loads the whole file into memory at once. */
export async function hashFileWithProgress(file: File, onProgress?: (fraction: number) => void, chunkSize = DEFAULT_CHUNK_SIZE): Promise<string> {
  const hasher = new IncrementalSha256();
  const total = file.size || 1;
  let processed = 0;
  onProgress?.(0);
  for (let offset = 0; offset < file.size; offset += chunkSize) {
    const slice = file.slice(offset, Math.min(offset + chunkSize, file.size));
    const buffer = await readBlobAsArrayBuffer(slice);
    hasher.update(new Uint8Array(buffer));
    processed += buffer.byteLength;
    onProgress?.(Math.min(processed / total, 1));
  }
  onProgress?.(1);
  return hasher.digestHex();
}
