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

type ChunkUploadResult = {
  status: MemoryUploadStatus;
  recovered: boolean;
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
      error.message.includes("backend could not be reached") ||
      error.message.includes("Upload timed out") ||
      error.message.includes("Upload response parsing failed") ||
      error.name === "TypeError"
    );
  }
  return false;
}

function shouldReconcileAmbiguousChunkUpload(error: unknown): boolean {
  if (error instanceof ApiError) {
    if ([400, 401, 403, 404, 409, 422].includes(error.status)) return false;
    return error.status === 408 || error.status === 425 || error.status === 429 || error.status >= 500;
  }
  return shouldRetryChunkUpload(error);
}

function statusAcknowledgesChunk(status: MemoryUploadStatus, chunkIndex: number): boolean {
  if (status.received_chunks?.includes(chunkIndex)) return true;
  if (status.missing_chunks?.includes(chunkIndex)) return false;
  return false;
}

async function abortableSleep(
  ms: number,
  signal: AbortSignal,
  sleepImp: (ms: number) => Promise<void>,
): Promise<void> {
  if (signal.aborted) throw new Error("Upload aborted");
  let onAbort: (() => void) | undefined;
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => resolve(), ms);
    onAbort = () => {
      clearTimeout(timer);
      reject(new Error("Upload aborted"));
    };
    signal.addEventListener("abort", onAbort, { once: true });
  }).finally(() => {
    if (onAbort) signal.removeEventListener("abort", onAbort);
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
  getStatus: RunResumableUploadArgs["getStatus"],
  uploadChunk: RunResumableUploadArgs["uploadChunk"],
  onProgress: ((info: { loaded: number; total: number }) => void) | undefined,
  sleep: (ms: number) => Promise<void>,
): Promise<ChunkUploadResult> {
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
      return { status, recovered: false };
    } catch (error) {
      if (signal.aborted) {
        throw new Error("Upload aborted");
      }
      if (shouldReconcileAmbiguousChunkUpload(error)) {
        const reconciledStatus = await getStatus(uploadId);
        if (statusAcknowledgesChunk(reconciledStatus, chunkIndex)) {
          if (onProgress) {
            onProgress({
              loaded: reconciledStatus.bytes_received,
              total: reconciledStatus.expected_bytes,
            });
          }
          return { status: reconciledStatus, recovered: true };
        }
      }
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
      const chunkResult = await uploadChunkWithRetry(
        uploadId,
        file,
        chunkIndex,
        effectiveChunkSize,
        totalChunks,
        signal,
        getStatus,
        uploadChunk,
        onProgress,
        sleep,
      );
      currentStatus = chunkResult.status;

      if (!chunkResult.recovered) {
        currentStatus = await getStatus(uploadId);
      }
    } catch (error) {
      if (error instanceof Error && error.message === "Upload aborted") {
        return { type: "aborted" };
      }
      if (error instanceof Error) {
        return { type: "failed", message: error.message };
      }
      return { type: "failed", message: "Chunk upload failed." };
    }

    if (onProgress) {
      onProgress({
        loaded: currentStatus.bytes_received,
        total: currentStatus.expected_bytes,
      });
    }
    const nextMissingInfo = deriveMissingChunks(
      currentStatus,
      file,
      chunkSize,
    );
    const nextMissingCount = nextMissingInfo.missingChunks.length;

    if (
      nextMissingCount >= previousMissingCount &&
      !TERMINAL_STATUSES.has(currentStatus.status) &&
      currentStatus.status !== "completed"
    ) {
      return {
        type: "stalled",
        uploadId,
        attemptedChunk: chunkIndex,
        previousMissingCount,
        nextMissingCount,
      };
    }

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
