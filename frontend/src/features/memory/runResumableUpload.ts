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
    onProgress?: (info: { loaded: number; total: number }) => void,
  ) => Promise<MemoryUploadStatus>;
  finalize: (uploadId: string) => Promise<MemoryUploadStatus>;
  signal: AbortSignal;
  onProgress?: (info: { loaded: number; total: number }) => void;
  concurrency?: number;
  maxConcurrency?: number;
  onSchedulerState?: (info: { concurrency: number; activeChunks: number[]; fallbackToSequential: boolean }) => void;
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
    if (error.status === 409) {
      // A distributed per-session lock (chunk write or finalize) was held
      // by a concurrent request for this same upload session. This is
      // transient - the lock holder releases within its own request - so
      // retrying with backoff is correct, unlike other 409s (offset
      // mismatches are reconciled separately below, not retried blindly).
      return error.errorCode === "session_busy" || error.errorCode === "session_lock_unavailable";
    }
    if (error.status === 408 || error.status === 425 || error.status === 429)
      return true;
    return error.status >= 500;
  }
  if (error instanceof Error) {
    return (
      error.message.includes("Network error") ||
      error.message.includes("backend could not be reached") ||
      error.message.includes("Upload timed out") ||
      error.name === "TypeError"
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
  uploadChunk: RunResumableUploadArgs["uploadChunk"],
  getStatus: RunResumableUploadArgs["getStatus"],
  onProgress: ((info: { loaded: number; total: number }) => void) | undefined,
  onChunkProgress: ((chunkIndex: number, loaded: number, chunkBytes: number) => void) | undefined,
  sleep: (ms: number) => Promise<void>,
): Promise<MemoryUploadStatus> {
  const blob = sliceChunk(file, chunkIndex, chunkSize);
  for (let attempt = 0; attempt <= CHUNK_UPLOAD_MAX_RETRIES; attempt += 1) {
    if (signal.aborted) throw new Error("Upload aborted");
    onChunkProgress?.(chunkIndex, 0, blob.size);
    try {
      const status = await uploadChunk(uploadId, chunkIndex, blob, signal, (info) => {
        const loaded = info.total > 0 ? Math.floor((Math.min(info.loaded, info.total) / info.total) * blob.size) : Math.min(info.loaded, blob.size);
        onChunkProgress?.(chunkIndex, Math.min(blob.size, loaded), blob.size);
      });
      onChunkProgress?.(chunkIndex, 0, blob.size);
      if (onProgress) {
        onProgress({
          loaded: status.bytes_received,
          total: status.expected_bytes,
        });
      }
      return status;
    } catch (error) {
      if (signal.aborted) {
        throw new Error("Upload aborted");
      }
      if (!shouldRetryChunkUpload(error)) {
        onChunkProgress?.(chunkIndex, 0, blob.size);
        throw error;
      }
      // The local request appeared to fail (timeout, network blip, 5xx),
      // but that doesn't mean the bytes never arrived - only that this
      // client never saw the response. Production logs have shown a real
      // browser resending (and getting a 409 offset_mismatch for) a chunk
      // the server had already committed minutes earlier. Reconcile
      // against the server's authoritative chunk bitmap before resending:
      // if this specific chunk is no longer missing, treat it as delivered
      // instead of paying for a full retry (and possible repeat stall).
      // Index-based (not a raw byte-count comparison) so this stays correct
      // under concurrency, where a sibling chunk landing first can advance
      // the cumulative byte count without this chunk being the one received.
      try {
        const reconciled = await getStatus(uploadId);
        const { missingChunks: reconciledMissing } = deriveMissingChunks(reconciled, file, chunkSize);
        if (!reconciledMissing.includes(chunkIndex)) {
          onChunkProgress?.(chunkIndex, 0, blob.size);
          if (onProgress) {
            onProgress({ loaded: reconciled.bytes_received, total: reconciled.expected_bytes });
          }
          return reconciled;
        }
      } catch {
        // Reconciliation read itself failed (e.g. offline) - fall through
        // to the normal retry/backoff below.
      }
      if (attempt >= CHUNK_UPLOAD_MAX_RETRIES) {
        onChunkProgress?.(chunkIndex, 0, blob.size);
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
    concurrency: requestedConcurrency = 1,
    maxConcurrency = 4,
    getStatus,
    uploadChunk,
    finalize,
    signal,
    onProgress,
    onSchedulerState,
    sleep: injectedSleep,
  } = args;

  const sleep = injectedSleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));

  let currentStatus = await getStatus(uploadId);
  let effectiveConcurrency = Math.max(1, Math.min(requestedConcurrency || 1, maxConcurrency || 1, 4));
  let fallbackToSequential = false;
  let confirmedBytes = currentStatus.bytes_received || 0;
  let offsetReconciliations = 0;
  const MAX_OFFSET_RECONCILIATIONS = 5;
  const activeProgress = new Map<number, number>();
  const emitAggregateProgress = () => {
    if (!onProgress) return;
    const transientBytes = Array.from(activeProgress.values()).reduce((sum, value) => sum + value, 0);
    onProgress({ loaded: Math.max(0, Math.min(file.size, confirmedBytes + transientBytes)), total: file.size });
  };
  const updateChunkProgress = (chunkIndex: number, loaded: number, _chunkBytes: number) => {
    if (loaded <= 0) {
      activeProgress.delete(chunkIndex);
    } else {
      activeProgress.set(chunkIndex, loaded);
    }
    emitAggregateProgress();
  };

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

    const selectedChunks = missingChunks.slice(0, effectiveConcurrency);
    const previousMissingCount = missingChunks.length;
    onSchedulerState?.({ concurrency: effectiveConcurrency, activeChunks: selectedChunks, fallbackToSequential });

    try {
      const results = await Promise.allSettled(
        selectedChunks.map((chunkIndex) =>
          uploadChunkWithRetry(
            uploadId,
            file,
            chunkIndex,
            effectiveChunkSize,
            totalChunks,
            signal,
            uploadChunk,
            getStatus,
            onProgress,
            updateChunkProgress,
            sleep,
          ),
        ),
      );
      const rejected = results.find((result): result is PromiseRejectedResult => result.status === "rejected");
      if (rejected) {
        activeProgress.clear();
        if (signal.aborted) {
          emitAggregateProgress();
          return { type: "aborted" };
        }
        if (!fallbackToSequential && effectiveConcurrency > 1) {
          fallbackToSequential = true;
          effectiveConcurrency = 1;
          currentStatus = await getStatus(uploadId);
          confirmedBytes = currentStatus.bytes_received || 0;
          emitAggregateProgress();
          continue;
        }
        const reason = rejected.reason;
        if (
          reason instanceof ApiError &&
          reason.status === 409 &&
          reason.errorCode === "offset_mismatch" &&
          offsetReconciliations < MAX_OFFSET_RECONCILIATIONS
        ) {
          // The server rejected the chunk because its offset no longer
          // matches the server-confirmed byte count. Our local view of
          // progress is stale (a prior chunk we thought was unconfirmed may
          // already be staged) - reconcile with the authoritative status
          // instead of failing outright, since this is a resumable uploader.
          offsetReconciliations += 1;
          currentStatus = await getStatus(uploadId);
          confirmedBytes = currentStatus.bytes_received || 0;
          emitAggregateProgress();
          continue;
        }
        if (reason instanceof Error) throw reason;
        throw new Error("Chunk upload failed.");
      }
      currentStatus = await getStatus(uploadId);
      confirmedBytes = currentStatus.bytes_received || confirmedBytes;
      activeProgress.clear();
    } catch (error) {
      activeProgress.clear();
      if (error instanceof Error && error.message === "Upload aborted") {
        emitAggregateProgress();
        return { type: "aborted" };
      }
      if (error instanceof Error) {
        return { type: "failed", message: error.message };
      }
      return { type: "failed", message: "Chunk upload failed." };
    } finally {
      onSchedulerState?.({ concurrency: effectiveConcurrency, activeChunks: [], fallbackToSequential });
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
        attemptedChunk: selectedChunks[0] ?? -1,
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
    // finalize reassembles and re-hashes the whole file server-side before
    // returning, so its duration scales with file size -- a proxy sitting in
    // front of the backend can give up (502/503/504) well before the backend
    // does, and the backend then finishes the registration anyway a short
    // while later. Re-check the authoritative status before declaring this a
    // failure, so a large file doesn't get reported as failed when it isn't.
    if (error instanceof ApiError && error.status >= 500) {
      try {
        const reconciled = await getStatus(uploadId);
        if (reconciled.status === "completed" && reconciled.evidence_id) {
          return { type: "completed", status: reconciled };
        }
        return {
          type: "failed",
          message:
            "The proxy in front of Kairon's server gave up waiting for this evidence file to finish registering (it can take a while for very large files), but the server may still be working on it in the background. Wait a moment and refresh -- if the evidence shows up as registered, this was not a real failure. If this keeps happening for large files, an administrator can raise proxy_read_timeout for the /finalize endpoint in frontend/nginx.conf (currently 1800s).",
        };
      } catch {
        // Status re-check itself failed (e.g. offline) -- fall through to
        // the original error below rather than hiding it.
      }
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
