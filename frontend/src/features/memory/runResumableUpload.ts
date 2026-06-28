import { ApiError, type MemoryUploadStatus } from "../../api/client";

export const CHUNK_UPLOAD_MAX_RETRIES = 3;
export const CHUNK_UPLOAD_RETRY_BASE_DELAY_MS = 500;
export const DEFAULT_CHUNK_SIZE = 64 * 1024 * 1024;

export type RunResumableUploadArgs = {
  uploadId: string;
  file: File;
  chunkSize?: number;
  getStatus: (uploadId: string) => Promise<MemoryUploadStatus>;
  uploadChunk: (
    uploadId: string,
    chunkIndex: number,
    blob: Blob,
    signal: AbortSignal,
  ) => Promise<MemoryUploadStatus>;
  finalize: (uploadId: string) => Promise<MemoryUploadStatus>;
  signal: AbortSignal;
  onProgress?: (info: { loaded: number; total: number }) => void;
  sleep?: (ms: number) => Promise<void>;
};

export type RunResumableUploadResult =
  | { type: "completed"; status: MemoryUploadStatus }
  | { type: "aborted" }
  | {
      type: "stalled";
      uploadId: string;
      attemptedChunk: number;
      previousMissingCount: number;
      nextMissingCount: number;
    }
  | { type: "failed"; message: string }
  | { type: "terminal"; status: MemoryUploadStatus };

type MissingChunksInfo = {
  chunkSize: number;
  totalChunks: number;
  missingChunks: number[];
};

function deriveMissingChunks(
  uploadStatus: MemoryUploadStatus,
  file: File,
  chunkSize: number,
): MissingChunksInfo {
  const effectiveChunkSize =
    uploadStatus.chunk_size_bytes || chunkSize;
  const totalChunks =
    uploadStatus.total_chunks ||
    Math.ceil(file.size / effectiveChunkSize);
  const missingChunks =
    uploadStatus.missing_chunks != null
      ? uploadStatus.missing_chunks
      : uploadStatus.received_chunks != null
        ? Array.from({ length: totalChunks }, (_, i) => i).filter(
            (i) => !new Set(uploadStatus.received_chunks).has(i),
          )
        : Array.from({ length: totalChunks }, (_, index) => index);
  return { chunkSize: effectiveChunkSize, totalChunks, missingChunks };
}

function sliceChunk(
  file: File,
  chunkIndex: number,
  chunkSize: number,
): Blob {
  if (chunkIndex < 0) {
    throw new Error(
      `Invalid chunk index ${chunkIndex}. Chunk index must be non-negative.`,
    );
  }
  const start = chunkIndex * chunkSize;
  if (start >= file.size) {
    throw new Error(
      `Chunk index ${chunkIndex} starts at byte ${start}, which exceeds file size ${file.size}.`,
    );
  }
  const end = Math.min(file.size, start + chunkSize);
  const blob = file.slice(start, end);
  if (blob.size !== end - start) {
    throw new Error(
      `Chunk ${chunkIndex} blob size ${blob.size} does not match expected size ${end - start}.`,
    );
  }
  return blob;
}

function shouldRetryChunkUpload(error: unknown): boolean {
  if (error instanceof ApiError) {
    if (error.status === 409) return false;
    if (error.status === 408 || error.status === 425 || error.status === 429)
      return true;
    return error.status >= 500;
  }
  if (error instanceof Error) {
    return (
      error.message.includes("Network error") ||
      error.message.includes("backend could not be reached")
    );
  }
  return false;
}

async function abortableSleep(
  ms: number,
  signal: AbortSignal,
  sleepImp: (ms: number) => Promise<void>,
): Promise<void> {
  if (signal.aborted) throw new Error("Upload aborted");
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => resolve(), ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(new Error("Upload aborted"));
    };
    signal.addEventListener("abort", onAbort, { once: true });
  });
  await sleepImp(0);
}

async function uploadChunkWithRetry(
  uploadId: string,
  file: File,
  chunkIndex: number,
  chunkSize: number,
  totalChunks: number,
  signal: AbortSignal,
  uploadChunk: RunResumableUploadArgs["uploadChunk"],
  onProgress: ((info: { loaded: number; total: number }) => void) | undefined,
  sleep: (ms: number) => Promise<void>,
): Promise<MemoryUploadStatus> {
  const blob = sliceChunk(file, chunkIndex, chunkSize);
  for (let attempt = 0; attempt <= CHUNK_UPLOAD_MAX_RETRIES; attempt += 1) {
    if (signal.aborted) throw new Error("Upload aborted");
    try {
      const status = await uploadChunk(uploadId, chunkIndex, blob, signal);
      if (onProgress) {
        onProgress({
          loaded: status.bytes_received,
          total: status.expected_bytes,
        });
      }
      return status;
    } catch (error) {
      if (!shouldRetryChunkUpload(error) || attempt >= CHUNK_UPLOAD_MAX_RETRIES) {
        throw error;
      }
      await abortableSleep(
        CHUNK_UPLOAD_RETRY_BASE_DELAY_MS * 2 ** attempt,
        signal,
        sleep,
      );
    }
  }
  throw new Error("Chunk upload retries exhausted.");
}

const TERMINAL_STATUSES: ReadonlySet<MemoryUploadStatus["status"]> = new Set([
  "failed",
  "cancelled",
  "expired",
  "inconsistent",
]);

export async function runResumableUpload(
  args: RunResumableUploadArgs,
): Promise<RunResumableUploadResult> {
  const {
    uploadId,
    file,
    chunkSize = DEFAULT_CHUNK_SIZE,
    getStatus,
    uploadChunk,
    finalize,
    signal,
    onProgress,
    sleep: injectedSleep,
  } = args;

  const sleep = injectedSleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));

  let currentStatus = await getStatus(uploadId);
  console.log("[KAIRON-DEBUG] INITIAL STATUS", {
    received_chunk_count: currentStatus.received_chunk_count,
    total_chunks: currentStatus.total_chunks,
    status: currentStatus.status,
    has_missing_chunks: currentStatus.missing_chunks !== null && currentStatus.missing_chunks !== undefined,
    missing_chunks_len: currentStatus.missing_chunks?.length,
    has_received_chunks: currentStatus.received_chunks !== null && currentStatus.received_chunks !== undefined,
    received_chunks_len: currentStatus.received_chunks?.length,
  });

  if (currentStatus.status === "completed" && currentStatus.evidence_id) {
    return { type: "terminal", status: currentStatus };
  }

  if (TERMINAL_STATUSES.has(currentStatus.status)) {
    return {
      type: "failed",
      message: currentStatus.message || "Memory image upload paused.",
    };
  }

  while (true) {
    if (signal.aborted) {
      return { type: "aborted" };
    }

    if (currentStatus.status === "completed" && currentStatus.evidence_id) {
      return { type: "terminal", status: currentStatus };
    }

    if (TERMINAL_STATUSES.has(currentStatus.status)) {
      return {
        type: "failed",
        message: currentStatus.message || "Memory image upload paused.",
      };
    }

    const { chunkSize: effectiveChunkSize, totalChunks, missingChunks } =
      deriveMissingChunks(currentStatus, file, chunkSize);

    console.log("[KAIRON-DEBUG] LOOP START", {
      status: currentStatus.status,
      received_chunk_count: currentStatus.received_chunk_count,
      missing_count: missingChunks.length,
      totalChunks,
      first_missing: missingChunks[0],
      last_missing: missingChunks[missingChunks.length - 1],
    });

    if (missingChunks.length === 0) {
      const authoritativeStatus = await getStatus(uploadId);
      currentStatus = authoritativeStatus;
      const refreshed = deriveMissingChunks(
        authoritativeStatus,
        file,
        chunkSize,
      );
      if (refreshed.missingChunks.length === 0) {
        break;
      }
      continue;
    }

    const chunkIndex = missingChunks[0];
    const previousMissingCount = missingChunks.length;

    try {
      currentStatus = await uploadChunkWithRetry(
        uploadId,
        file,
        chunkIndex,
        effectiveChunkSize,
        totalChunks,
        signal,
        uploadChunk,
        onProgress,
        sleep,
      );
    } catch (error) {
      if (error instanceof Error && error.message === "Upload aborted") {
        return { type: "aborted" };
      }
      if (error instanceof Error) {
        return { type: "failed", message: error.message };
      }
      return { type: "failed", message: "Chunk upload failed." };
    }

    const nextStatus = await getStatus(uploadId);
    if (onProgress) {
      onProgress({
        loaded: nextStatus.bytes_received,
        total: nextStatus.expected_bytes,
      });
    }
    const nextMissingInfo = deriveMissingChunks(
      nextStatus,
      file,
      chunkSize,
    );
    const nextMissingCount = nextMissingInfo.missingChunks.length;

    if (
      nextMissingCount >= previousMissingCount &&
      !TERMINAL_STATUSES.has(nextStatus.status) &&
      nextStatus.status !== "completed"
    ) {
      console.log("[KAIRON-DEBUG] STALL DETECTED", {
        uploadId,
        chunkIndex,
        previousMissingCount,
        nextMissingCount,
        nextStatus: {
          received_chunk_count: nextStatus.received_chunk_count,
          total_chunks: nextStatus.total_chunks,
          status: nextStatus.status,
          has_missing_chunks: nextStatus.missing_chunks !== null && nextStatus.missing_chunks !== undefined,
          missing_chunks_len: nextStatus.missing_chunks?.length,
          has_received_chunks: nextStatus.received_chunks !== null && nextStatus.received_chunks !== undefined,
          received_chunks_len: nextStatus.received_chunks?.length,
        },
      });
      return {
        type: "stalled",
        uploadId,
        attemptedChunk: chunkIndex,
        previousMissingCount,
        nextMissingCount,
      };
    }

    console.log("[KAIRON-DEBUG] CHUNK OK, continuing", {
      chunkIndex,
      previousMissingCount,
      nextMissingCount,
    });

    currentStatus = nextStatus;
  }

  const authoritativeStatus = await getStatus(uploadId);

  if (
    authoritativeStatus.status === "completed" &&
    authoritativeStatus.evidence_id
  ) {
    return { type: "terminal", status: authoritativeStatus };
  }

  const finalMissingInfo = deriveMissingChunks(
    authoritativeStatus,
    file,
    chunkSize,
  );
  if (finalMissingInfo.missingChunks.length > 0) {
    return {
      type: "failed",
      message:
        "Upload paused before all missing chunks were acknowledged. Resume upload to continue.",
    };
  }

  try {
    const finalized = await finalize(uploadId);
    return { type: "completed", status: finalized };
  } catch (error) {
    if (
      error instanceof Error &&
      (error.message.includes("abort") || error.message.includes("Abort"))
    ) {
      return { type: "aborted" };
    }
    return {
      type: "failed",
      message:
        error instanceof Error
          ? error.message
          : "Finalization failed.",
    };
  }
}
