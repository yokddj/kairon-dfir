import { describe, expect, it, vi } from "vitest";
import { ApiError, type MemoryUploadStatus } from "../../api/client";
import {
  runResumableUpload,
  CHUNK_UPLOAD_MAX_RETRIES,
  CHUNK_UPLOAD_RETRY_BASE_DELAY_MS,
} from "./runResumableUpload";

function makeStatus(
  overrides: Partial<MemoryUploadStatus> & { upload_id: string },
): MemoryUploadStatus {
  return {
    case_id: "case-1",
    evidence_id: null,
    status: "uploading",
    bytes_received: 0,
    expected_bytes: 20,
    chunk_size_bytes: 4,
    total_chunks: 5,
    received_chunk_count: 0,
    received_chunks: [],
    missing_chunks: [0, 1, 2, 3, 4],
    progress_percent: 0,
    filename: "authorized.mem",
    extension: ".mem",
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 3600_000).toISOString(),
    finalized_at: null,
    failure_code: null,
    message: "Upload session created. Ready to receive chunks.",
    retryable: false,
    ...overrides,
  };
}

function makeFile(size = 20, name = "authorized.mem"): File {
  const content = new Uint8Array(size).fill(0x41);
  return new File([content], name);
}

function chunkBytes(
  expectedBytes: number,
  chunkSize: number,
  chunkIndex: number,
) {
  const start = chunkIndex * chunkSize;
  const end = Math.min(expectedBytes, start + chunkSize);
  return Math.max(0, end - start);
}

function sleepImmediate() {
  return Promise.resolve();
}

describe("runResumableUpload", () => {
  it("uploads chunks 2, 3, and 4 in order with one call and finalizes once", async () => {
    const uploadId = "resume-1";
    const file = makeFile(20);
    const chunkSize = 4;

    const received: number[] = [0, 1];

    const buildStatus = (
      overrides: Partial<MemoryUploadStatus> = {},
    ): MemoryUploadStatus =>
      makeStatus({
        upload_id: uploadId,
        expected_bytes: file.size,
        chunk_size_bytes: chunkSize,
        total_chunks: 5,
        received_chunk_count: received.length,
        received_chunks: [...received],
        bytes_received: received.reduce(
          (total, index) => total + chunkBytes(file.size, chunkSize, index),
          0,
        ),
        missing_chunks: Array.from({ length: 5 }, (_, i) => i).filter(
          (i) => !received.includes(i),
        ),
        progress_percent: Math.round(
          (received.reduce(
            (total, index) => total + chunkBytes(file.size, chunkSize, index),
            0,
          ) /
            file.size) *
            100,
        ),
        ...overrides,
      });

    const getStatus = vi.fn(async () => buildStatus());

    const uploadChunk = vi.fn(
      async (
        _uploadId: string,
        chunkIndex: number,
        _blob: Blob,
        _signal: AbortSignal,
      ) => {
        if (!received.includes(chunkIndex)) {
          received.push(chunkIndex);
          received.sort((a, b) => a - b);
        }
        return buildStatus();
      },
    );

    const finalize = vi.fn(async () =>
      makeStatus({
        upload_id: uploadId,
        status: "completed",
        evidence_id: "evidence-123",
        bytes_received: file.size,
        expected_bytes: file.size,
        chunk_size_bytes: chunkSize,
        total_chunks: 5,
        received_chunk_count: 5,
        received_chunks: [0, 1, 2, 3, 4],
        missing_chunks: [],
        progress_percent: 100,
        message: "Memory image uploaded and registered.",
      }),
    );

    const onProgress = vi.fn();
    const signal = new AbortController().signal;

    const result = await runResumableUpload({
      uploadId,
      file,
      chunkSize,
      getStatus,
      uploadChunk,
      finalize,
      signal,
      onProgress,
      sleep: sleepImmediate,
    });

    expect(result.type).toBe("completed");
    if (result.type === "completed") {
      expect(result.status.status).toBe("completed");
      expect(result.status.evidence_id).toBe("evidence-123");
    }

    const chunkIndices = uploadChunk.mock.calls.map((call) => call[1]);
    expect(chunkIndices).toEqual([2, 3, 4]);

    const statusCallIds = getStatus.mock.calls.map((call) => call[0]);
    expect(statusCallIds.every((id) => id === uploadId)).toBe(true);

    const uploadCallIds = uploadChunk.mock.calls.map((call) => call[0]);
    expect(uploadCallIds.every((id) => id === uploadId)).toBe(true);

    expect(finalize).toHaveBeenCalledTimes(1);
    expect(finalize).toHaveBeenCalledWith(uploadId);

    expect(onProgress).toHaveBeenCalled();
  });

  it("returns terminal for already completed status with evidence_id", async () => {
    const uploadId = "done-1";
    const file = makeFile(20);
    const getStatus = vi.fn(async () =>
      makeStatus({
        upload_id: uploadId,
        status: "completed",
        evidence_id: "ev-already",
        bytes_received: file.size,
        expected_bytes: file.size,
        missing_chunks: [],
        received_chunks: [0, 1, 2, 3, 4],
        received_chunk_count: 5,
        progress_percent: 100,
      }),
    );

    const uploadChunk = vi.fn();
    const finalize = vi.fn();

    const result = await runResumableUpload({
      uploadId,
      file,
      getStatus,
      uploadChunk,
      finalize,
      signal: new AbortController().signal,
      sleep: sleepImmediate,
    });

    expect(result.type).toBe("terminal");
    if (result.type === "terminal") {
      expect(result.status.evidence_id).toBe("ev-already");
    }
    expect(uploadChunk).not.toHaveBeenCalled();
    expect(finalize).not.toHaveBeenCalled();
  });

  it("uploads one missing chunk and finalizes", async () => {
    const uploadId = "one-left";
    const file = makeFile(8);
    const chunkSize = 4;
    const received: number[] = [0];

    const buildStatus = (overrides: Partial<MemoryUploadStatus> = {}) =>
      makeStatus({
        upload_id: uploadId,
        expected_bytes: file.size,
        chunk_size_bytes: chunkSize,
        total_chunks: 2,
        received_chunk_count: received.length,
        received_chunks: [...received],
        bytes_received: received.reduce(
          (total, i) => total + chunkBytes(file.size, chunkSize, i),
          0,
        ),
        missing_chunks: Array.from({ length: 2 }, (_, i) => i).filter(
          (i) => !received.includes(i),
        ),
        ...overrides,
      });

    const getStatus = vi.fn(async () => buildStatus());
    const uploadChunk = vi.fn(async (_uid: string, chunkIndex: number) => {
      received.push(chunkIndex);
      return buildStatus();
    });
    const finalize = vi.fn(async () =>
      makeStatus({
        upload_id: uploadId,
        status: "completed",
        evidence_id: "ev-2",
        bytes_received: file.size,
        expected_bytes: file.size,
        missing_chunks: [],
        received_chunks: [0, 1],
        received_chunk_count: 2,
        progress_percent: 100,
      }),
    );

    const result = await runResumableUpload({
      uploadId,
      file,
      chunkSize,
      getStatus,
      uploadChunk,
      finalize,
      signal: new AbortController().signal,
      sleep: sleepImmediate,
    });

    expect(result.type).toBe("completed");
    expect(uploadChunk.mock.calls.map((c) => c[1])).toEqual([1]);
    expect(getStatus).toHaveBeenCalled();
    expect(finalize).toHaveBeenCalledTimes(1);
  });

  it("final chunk uses correct shorter byte range", async () => {
    const uploadId = "final-chunk";
    const fileSize = 10;
    const chunkSize = 4;
    const file = makeFile(fileSize);
    const received: number[] = [0, 1];

    const buildStatus = (overrides: Partial<MemoryUploadStatus> = {}) =>
      makeStatus({
        upload_id: uploadId,
        expected_bytes: fileSize,
        chunk_size_bytes: chunkSize,
        total_chunks: 3,
        received_chunk_count: received.length,
        received_chunks: [...received],
        bytes_received: received.reduce(
          (total, i) => total + chunkBytes(fileSize, chunkSize, i),
          0,
        ),
        missing_chunks: Array.from({ length: 3 }, (_, i) => i).filter(
          (i) => !received.includes(i),
        ),
        ...overrides,
      });

    const getStatus = vi.fn(async () => buildStatus());
    const uploadChunk = vi.fn(
      async (_uid: string, _chunkIndex: number, blob: Blob) => {
        received.push(2);
        return buildStatus();
      },
    );
    const finalize = vi.fn(async () =>
      makeStatus({
        upload_id: uploadId,
        status: "completed",
        evidence_id: "ev-final",
        bytes_received: fileSize,
        expected_bytes: fileSize,
        missing_chunks: [],
        received_chunks: [0, 1, 2],
        received_chunk_count: 3,
        progress_percent: 100,
      }),
    );

    await runResumableUpload({
      uploadId,
      file,
      chunkSize,
      getStatus,
      uploadChunk,
      finalize,
      signal: new AbortController().signal,
      sleep: sleepImmediate,
    });

    expect(uploadChunk).toHaveBeenCalledTimes(1);
    const blobArg = uploadChunk.mock.calls[0][2] as Blob;
    expect(blobArg.size).toBe(2);
  });

  it("non-advancing status throws MEMORY_UPLOAD_PROGRESS_STALLED", async () => {
    const uploadId = "stall-1";
    const file = makeFile(20);
    const chunkSize = 4;

    const statusTemplate = makeStatus({
      upload_id: uploadId,
      expected_bytes: file.size,
      chunk_size_bytes: chunkSize,
      total_chunks: 5,
      received_chunks: [0, 1],
      received_chunk_count: 2,
      bytes_received: 8,
      missing_chunks: [2, 3, 4],
    });

    const getStatus = vi.fn(async () => ({ ...statusTemplate }));
    const uploadChunk = vi.fn(async () => ({ ...statusTemplate }));
    const finalize = vi.fn();

    const result = await runResumableUpload({
      uploadId,
      file,
      chunkSize,
      getStatus,
      uploadChunk,
      finalize,
      signal: new AbortController().signal,
      sleep: sleepImmediate,
    });

    expect(result.type).toBe("stalled");
    if (result.type === "stalled") {
      expect(result.uploadId).toBe(uploadId);
      expect(result.attemptedChunk).toBe(2);
      expect(result.previousMissingCount).toBe(3);
      expect(result.nextMissingCount).toBe(3);
    }
    expect(finalize).not.toHaveBeenCalled();
  });

  it("retries transient failure on same chunk then continues", async () => {
    const uploadId = "retry-1";
    const file = makeFile(8);
    const chunkSize = 4;
    const received: number[] = [0];

    let callsForChunk1 = 0;

    const buildStatus = (overrides: Partial<MemoryUploadStatus> = {}) =>
      makeStatus({
        upload_id: uploadId,
        expected_bytes: file.size,
        chunk_size_bytes: chunkSize,
        total_chunks: 2,
        received_chunk_count: received.length,
        received_chunks: [...received],
        bytes_received: received.reduce(
          (total, i) => total + chunkBytes(file.size, chunkSize, i),
          0,
        ),
        missing_chunks: Array.from({ length: 2 }, (_, i) => i).filter(
          (i) => !received.includes(i),
        ),
        ...overrides,
      });

    const getStatus = vi.fn(async () => buildStatus());
    const uploadChunk = vi.fn(
      async (_uid: string, chunkIndex: number, _blob: Blob) => {
        callsForChunk1 += 1;
        if (chunkIndex === 1 && callsForChunk1 === 1) {
          throw new Error("Network error while uploading");
        }
        received.push(chunkIndex);
        return buildStatus();
      },
    );
    const finalize = vi.fn(async () =>
      makeStatus({
        upload_id: uploadId,
        status: "completed",
        evidence_id: "ev-retry",
        bytes_received: file.size,
        expected_bytes: file.size,
        missing_chunks: [],
        received_chunks: [0, 1],
        received_chunk_count: 2,
        progress_percent: 100,
      }),
    );

    const result = await runResumableUpload({
      uploadId,
      file,
      chunkSize,
      getStatus,
      uploadChunk,
      finalize,
      signal: new AbortController().signal,
      sleep: sleepImmediate,
    });

    expect(result.type).toBe("completed");
    const chunkIndices = uploadChunk.mock.calls.map((c) => c[1]);
    expect(chunkIndices).toEqual([1, 1]);
    expect(finalize).toHaveBeenCalledTimes(1);
  });

  it("retry limit exceeded stops safely without finalizing", async () => {
    const uploadId = "retry-limit";
    const file = makeFile(8);
    const chunkSize = 4;

    const statusTemplate = makeStatus({
      upload_id: uploadId,
      expected_bytes: file.size,
      chunk_size_bytes: chunkSize,
      total_chunks: 2,
      received_chunks: [0],
      received_chunk_count: 1,
      bytes_received: 4,
      missing_chunks: [1],
    });

    const getStatus = vi.fn(async () => ({ ...statusTemplate }));
    const uploadChunk = vi.fn(async () => {
      throw new Error("Network error while uploading");
    });
    const finalize = vi.fn();

    const result = await runResumableUpload({
      uploadId,
      file,
      chunkSize,
      getStatus,
      uploadChunk,
      finalize,
      signal: new AbortController().signal,
      sleep: sleepImmediate,
    });

    expect(result.type).toBe("failed");
    expect(uploadChunk).toHaveBeenCalledTimes(CHUNK_UPLOAD_MAX_RETRIES + 1);
    expect(finalize).not.toHaveBeenCalled();
  });

  it("does not retry HTTP 409 conflict", async () => {
    const uploadId = "conflict-1";
    const file = makeFile(8);
    const chunkSize = 4;

    const statusTemplate = makeStatus({
      upload_id: uploadId,
      expected_bytes: file.size,
      chunk_size_bytes: chunkSize,
      total_chunks: 2,
      received_chunks: [0],
      received_chunk_count: 1,
      bytes_received: 4,
      missing_chunks: [1],
    });

    const getStatus = vi.fn(async () => ({ ...statusTemplate }));
    const uploadChunk = vi.fn(async () => {
      throw new ApiError(409, "MEMORY_UPLOAD_CHUNK_CONFLICT", "Chunk conflict", null);
    });
    const finalize = vi.fn();

    const result = await runResumableUpload({
      uploadId,
      file,
      chunkSize,
      getStatus,
      uploadChunk,
      finalize,
      signal: new AbortController().signal,
      sleep: sleepImmediate,
    });

    expect(result.type).toBe("failed");
    expect(uploadChunk).toHaveBeenCalledTimes(1);
    expect(finalize).not.toHaveBeenCalled();
  });

  it("aborts before first chunk and does not start upload", async () => {
    const uploadId = "abort-early";
    const file = makeFile(20);
    const controller = new AbortController();

    const statusTemplate = makeStatus({
      upload_id: uploadId,
      expected_bytes: file.size,
      chunk_size_bytes: 4,
      total_chunks: 5,
      received_chunks: [0, 1],
      received_chunk_count: 2,
      bytes_received: 8,
      missing_chunks: [2, 3, 4],
    });

    const getStatus = vi.fn(async () => {
      controller.abort();
      return { ...statusTemplate };
    });

    const uploadChunk = vi.fn();
    const finalize = vi.fn();

    const result = await runResumableUpload({
      uploadId,
      file,
      chunkSize: 4,
      getStatus,
      uploadChunk,
      finalize,
      signal: controller.signal,
      sleep: sleepImmediate,
    });

    expect(result.type).toBe("aborted");
    expect(uploadChunk).not.toHaveBeenCalled();
    expect(finalize).not.toHaveBeenCalled();
  });

  it("aborts during chunk upload prevents finalize", async () => {
    const uploadId = "abort-during";
    const file = makeFile(20);
    const controller = new AbortController();

    const statusTemplate = makeStatus({
      upload_id: uploadId,
      expected_bytes: file.size,
      chunk_size_bytes: 4,
      total_chunks: 5,
      received_chunks: [0, 1],
      received_chunk_count: 2,
      bytes_received: 8,
      missing_chunks: [2, 3, 4],
    });

    const getStatus = vi.fn(async () => ({ ...statusTemplate }));
    const uploadChunk = vi.fn(async () => {
      controller.abort();
      throw new Error("Upload aborted");
    });
    const finalize = vi.fn();

    const result = await runResumableUpload({
      uploadId,
      file,
      chunkSize: 4,
      getStatus,
      uploadChunk,
      finalize,
      signal: controller.signal,
      sleep: sleepImmediate,
    });

    expect(result.type).toBe("aborted");
    expect(finalize).not.toHaveBeenCalled();
  });

  it("status refetched between every chunk", async () => {
    const uploadId = "refetch-check";
    const file = makeFile(12);
    const chunkSize = 4;
    const received: number[] = [0];

    const buildStatus = (overrides: Partial<MemoryUploadStatus> = {}) =>
      makeStatus({
        upload_id: uploadId,
        expected_bytes: file.size,
        chunk_size_bytes: chunkSize,
        total_chunks: 3,
        received_chunk_count: received.length,
        received_chunks: [...received],
        bytes_received: received.reduce(
          (total, i) => total + chunkBytes(file.size, chunkSize, i),
          0,
        ),
        missing_chunks: Array.from({ length: 3 }, (_, i) => i).filter(
          (i) => !received.includes(i),
        ),
        ...overrides,
      });

    const getStatus = vi.fn(async () => buildStatus());
    const uploadChunk = vi.fn(
      async (_uid: string, chunkIndex: number) => {
        received.push(chunkIndex);
        return buildStatus();
      },
    );
    const finalize = vi.fn(async () =>
      makeStatus({
        upload_id: uploadId,
        status: "completed",
        evidence_id: "ev-refetch",
        bytes_received: file.size,
        expected_bytes: file.size,
        missing_chunks: [],
        received_chunks: [0, 1, 2],
        received_chunk_count: 3,
        progress_percent: 100,
      }),
    );

    await runResumableUpload({
      uploadId,
      file,
      chunkSize,
      getStatus,
      uploadChunk,
      finalize,
      signal: new AbortController().signal,
      sleep: sleepImmediate,
    });

    expect(uploadChunk).toHaveBeenCalledTimes(2);

    const chunks = uploadChunk.mock.calls.map((c) => c[1]);
    expect(chunks).toEqual([1, 2]);

    const getStatusCalls = getStatus.mock.calls.length;

    expect(getStatusCalls).toBeGreaterThanOrEqual(2);
  });

  it("finalize called exactly once on full upload", async () => {
    const uploadId = "finalize-once";
    const file = makeFile(8);
    const chunkSize = 4;
    const received: number[] = [0];

    const buildStatus = (overrides: Partial<MemoryUploadStatus> = {}) =>
      makeStatus({
        upload_id: uploadId,
        expected_bytes: file.size,
        chunk_size_bytes: chunkSize,
        total_chunks: 2,
        received_chunk_count: received.length,
        received_chunks: [...received],
        bytes_received: received.reduce(
          (total, i) => total + chunkBytes(file.size, chunkSize, i),
          0,
        ),
        missing_chunks: Array.from({ length: 2 }, (_, i) => i).filter(
          (i) => !received.includes(i),
        ),
        ...overrides,
      });

    const getStatus = vi.fn(async () => buildStatus());
    const uploadChunk = vi.fn(async (_uid: string, chunkIndex: number) => {
      received.push(chunkIndex);
      return buildStatus();
    });
    let finalizeCalls = 0;
    const finalize = vi.fn(async () => {
      finalizeCalls += 1;
      return makeStatus({
        upload_id: uploadId,
        status: "completed",
        evidence_id: "ev-once",
        bytes_received: file.size,
        expected_bytes: file.size,
        missing_chunks: [],
        received_chunks: [0, 1],
        received_chunk_count: 2,
        progress_percent: 100,
      });
    });

    await runResumableUpload({
      uploadId,
      file,
      chunkSize,
      getStatus,
      uploadChunk,
      finalize,
      signal: new AbortController().signal,
      sleep: sleepImmediate,
    });

    expect(finalize).toHaveBeenCalledTimes(1);
  });

  it("same upload ID used throughout entire run", async () => {
    const uploadId = "same-id";
    const file = makeFile(12);
    const chunkSize = 4;
    const received: number[] = [0, 1];

    const buildStatus = (overrides: Partial<MemoryUploadStatus> = {}) =>
      makeStatus({
        upload_id: uploadId,
        expected_bytes: file.size,
        chunk_size_bytes: chunkSize,
        total_chunks: 3,
        received_chunk_count: received.length,
        received_chunks: [...received],
        bytes_received: received.reduce(
          (total, i) => total + chunkBytes(file.size, chunkSize, i),
          0,
        ),
        missing_chunks: Array.from({ length: 3 }, (_, i) => i).filter(
          (i) => !received.includes(i),
        ),
        ...overrides,
      });

    const getStatus = vi.fn(async (id: string) => {
      expect(id).toBe(uploadId);
      return buildStatus();
    });

    const uploadChunk = vi.fn(
      async (id: string, chunkIndex: number) => {
        expect(id).toBe(uploadId);
        received.push(chunkIndex);
        return buildStatus();
      },
    );

    const finalize = vi.fn(async (id: string) => {
      expect(id).toBe(uploadId);
      return makeStatus({
        upload_id: uploadId,
        status: "completed",
        evidence_id: "ev-same",
        missing_chunks: [],
        received_chunks: [0, 1, 2],
        received_chunk_count: 3,
        progress_percent: 100,
        bytes_received: file.size,
        expected_bytes: file.size,
      });
    });

    await runResumableUpload({
      uploadId,
      file,
      chunkSize,
      getStatus,
      uploadChunk,
      finalize,
      signal: new AbortController().signal,
      sleep: sleepImmediate,
    });

    expect(uploadChunk).toHaveBeenCalled();
  });

  it("progress callback fires after each acknowledged chunk", async () => {
    const uploadId = "progress-1";
    const file = makeFile(8);
    const chunkSize = 4;
    const received: number[] = [0];

    const buildStatus = (overrides: Partial<MemoryUploadStatus> = {}) =>
      makeStatus({
        upload_id: uploadId,
        expected_bytes: file.size,
        chunk_size_bytes: chunkSize,
        total_chunks: 2,
        received_chunk_count: received.length,
        received_chunks: [...received],
        bytes_received: received.reduce(
          (total, i) => total + chunkBytes(file.size, chunkSize, i),
          0,
        ),
        missing_chunks: Array.from({ length: 2 }, (_, i) => i).filter(
          (i) => !received.includes(i),
        ),
        ...overrides,
      });

    const getStatus = vi.fn(async () => buildStatus());
    const uploadChunk = vi.fn(async (_uid: string, chunkIndex: number) => {
      received.push(chunkIndex);
      return buildStatus();
    });
    const finalize = vi.fn(async () =>
      makeStatus({
        upload_id: uploadId,
        status: "completed",
        evidence_id: "ev-progress",
        bytes_received: file.size,
        expected_bytes: file.size,
        missing_chunks: [],
        received_chunks: [0, 1],
        received_chunk_count: 2,
        progress_percent: 100,
      }),
    );
    const onProgress = vi.fn();

    await runResumableUpload({
      uploadId,
      file,
      chunkSize,
      getStatus,
      uploadChunk,
      finalize,
      signal: new AbortController().signal,
      onProgress,
      sleep: sleepImmediate,
    });

    expect(onProgress).toHaveBeenCalled();
    const allCalls = onProgress.mock.calls;
    const lastProgress = allCalls[allCalls.length - 1][0];
    expect(lastProgress.loaded).toBe(file.size);
    expect(lastProgress.total).toBe(file.size);
  });
});
