// Packs a selected folder into one uncompressed ZIP so it travels through the
// same resumable single-file upload as any archive (64 MB chunks, retries,
// preflight), with no per-request size or file-count limit.
//
// Nothing is copied: the returned File is a Blob made of small header buffers
// and the selected File objects themselves, which the browser reads lazily as
// each chunk is sliced and sent. Every file is read once here to compute its
// CRC-32, which ZIP readers verify.
//
// Members are stored (no compression). ZIP64 records are written when a size,
// an offset or the entry count passes the classic format's limits.

const CHUNK_BYTES = 16 * 1024 * 1024;
const UINT32_MAX = 0xffffffff;
const UINT16_MAX = 0xffff;
const UTF8_FLAG = 0x0800;

let crcTable: Uint32Array | null = null;

function table(): Uint32Array {
  if (crcTable) return crcTable;
  crcTable = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    crcTable[n] = c >>> 0;
  }
  return crcTable;
}

export function crc32Update(crc: number, bytes: Uint8Array): number {
  const t = table();
  let c = crc ^ UINT32_MAX;
  for (let i = 0; i < bytes.length; i += 1) c = t[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  return (c ^ UINT32_MAX) >>> 0;
}

function dosDateTime(ms: number): { time: number; date: number } {
  const d = new Date(ms || Date.now());
  const year = Math.min(Math.max(d.getFullYear(), 1980), 2107);
  return {
    time: (d.getHours() << 11) | (d.getMinutes() << 5) | Math.floor(d.getSeconds() / 2),
    date: ((year - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate(),
  };
}

class Writer {
  readonly view: DataView;
  readonly bytes: Uint8Array;
  private pos = 0;

  constructor(size: number) {
    this.bytes = new Uint8Array(size);
    this.view = new DataView(this.bytes.buffer);
  }

  u16(value: number) {
    this.view.setUint16(this.pos, value, true);
    this.pos += 2;
  }

  u32(value: number) {
    this.view.setUint32(this.pos, value >>> 0, true);
    this.pos += 4;
  }

  u64(value: number) {
    this.view.setBigUint64(this.pos, BigInt(value), true);
    this.pos += 8;
  }

  raw(data: Uint8Array) {
    this.bytes.set(data, this.pos);
    this.pos += data.length;
  }
}

type Entry = { name: Uint8Array; size: number; crc: number; offset: number; time: number; date: number };

function localHeader(entry: Entry, zip64: boolean): Uint8Array {
  const extraLength = zip64 ? 20 : 0;
  const w = new Writer(30 + entry.name.length + extraLength);
  w.u32(0x04034b50);
  w.u16(zip64 ? 45 : 20);
  w.u16(UTF8_FLAG);
  w.u16(0);
  w.u16(entry.time);
  w.u16(entry.date);
  w.u32(entry.crc);
  w.u32(zip64 ? UINT32_MAX : entry.size);
  w.u32(zip64 ? UINT32_MAX : entry.size);
  w.u16(entry.name.length);
  w.u16(extraLength);
  w.raw(entry.name);
  if (zip64) {
    w.u16(0x0001);
    w.u16(16);
    w.u64(entry.size);
    w.u64(entry.size);
  }
  return w.bytes;
}

function centralHeader(entry: Entry): Uint8Array {
  const bigSize = entry.size >= UINT32_MAX;
  const bigOffset = entry.offset >= UINT32_MAX;
  const extraLength = bigSize || bigOffset ? 4 + (bigSize ? 16 : 0) + (bigOffset ? 8 : 0) : 0;
  const w = new Writer(46 + entry.name.length + extraLength);
  w.u32(0x02014b50);
  w.u16(45);
  w.u16(extraLength ? 45 : 20);
  w.u16(UTF8_FLAG);
  w.u16(0);
  w.u16(entry.time);
  w.u16(entry.date);
  w.u32(entry.crc);
  w.u32(bigSize ? UINT32_MAX : entry.size);
  w.u32(bigSize ? UINT32_MAX : entry.size);
  w.u16(entry.name.length);
  w.u16(extraLength);
  w.u16(0);
  w.u16(0);
  w.u16(0);
  w.u32(0);
  w.u32(bigOffset ? UINT32_MAX : entry.offset);
  w.raw(entry.name);
  if (extraLength) {
    w.u16(0x0001);
    w.u16(extraLength - 4);
    if (bigSize) {
      w.u64(entry.size);
      w.u64(entry.size);
    }
    if (bigOffset) w.u64(entry.offset);
  }
  return w.bytes;
}

function endRecords(count: number, directorySize: number, directoryOffset: number, forceZip64: boolean): Uint8Array {
  const zip64 = forceZip64 || count >= UINT16_MAX || directorySize >= UINT32_MAX || directoryOffset >= UINT32_MAX;
  const w = new Writer((zip64 ? 56 + 20 : 0) + 22);
  if (zip64) {
    w.u32(0x06064b50);
    w.u64(44);
    w.u16(45);
    w.u16(45);
    w.u32(0);
    w.u32(0);
    w.u64(count);
    w.u64(count);
    w.u64(directorySize);
    w.u64(directoryOffset);
    w.u32(0x07064b50);
    w.u32(0);
    w.u64(directoryOffset + directorySize);
    w.u32(1);
  }
  w.u32(0x06054b50);
  w.u16(0);
  w.u16(0);
  w.u16(zip64 ? UINT16_MAX : count);
  w.u16(zip64 ? UINT16_MAX : count);
  w.u32(zip64 ? UINT32_MAX : directorySize);
  w.u32(zip64 ? UINT32_MAX : directoryOffset);
  w.u16(0);
  return w.bytes;
}

export function relativePathOf(file: File): string {
  return ((file as File & { webkitRelativePath?: string }).webkitRelativePath || file.name).replace(/\\/g, "/");
}

export function folderNameOf(files: File[]): string {
  const first = files.length ? relativePathOf(files[0]) : "";
  return first.includes("/") ? first.split("/")[0] : "folder";
}

async function fileCrc(file: File, onBytes: (count: number) => void): Promise<number> {
  let crc = 0;
  for (let offset = 0; offset < file.size; offset += CHUNK_BYTES) {
    let buffer: ArrayBuffer;
    try {
      buffer = await file.slice(offset, offset + CHUNK_BYTES).arrayBuffer();
    } catch (readError) {
      const detail = readError as { name?: string; message?: string } | null;
      throw new Error(`The browser could not read "${relativePathOf(file)}" from the selected folder${detail?.message ? ` (${detail.name || "Error"}: ${detail.message})` : ""}.`);
    }
    crc = crc32Update(crc, new Uint8Array(buffer));
    onBytes(buffer.byteLength);
  }
  return crc;
}

export async function zipFolder(
  files: File[],
  options?: { onProgress?: (fraction: number) => void; signal?: AbortSignal; forceZip64?: boolean },
): Promise<File> {
  const encoder = new TextEncoder();
  const total = files.reduce((sum, file) => sum + file.size, 0);
  const parts: BlobPart[] = [];
  const entries: Entry[] = [];
  let offset = 0;
  let read = 0;
  const report = () => options?.onProgress?.(total > 0 ? read / total : 1);
  for (const file of files) {
    if (options?.signal?.aborted) throw new Error("Folder packing cancelled");
    const crc = await fileCrc(file, (count) => {
      read += count;
      report();
    });
    const { time, date } = dosDateTime(file.lastModified);
    const entry: Entry = { name: encoder.encode(relativePathOf(file)), size: file.size, crc, offset, time, date };
    const header = localHeader(entry, file.size >= UINT32_MAX);
    parts.push(header as BlobPart, file);
    offset += header.length + file.size;
    entries.push(entry);
  }
  const directory = entries.map((entry) => centralHeader(entry));
  const directorySize = directory.reduce((sum, item) => sum + item.length, 0);
  parts.push(...(directory as BlobPart[]), endRecords(entries.length, directorySize, offset, Boolean(options?.forceZip64)) as BlobPart);
  report();
  return new File(parts, `${folderNameOf(files)}.zip`, { type: "application/zip", lastModified: Date.now() });
}
