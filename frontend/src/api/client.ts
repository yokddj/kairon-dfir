import { strToU8, zipSync, type Zippable } from "fflate";

// The frontend now uses a relative API base so the browser sees a
// same-origin request through the Vite dev server proxy.  The
// absolute fallback (window.location.hostname:8000) is retained
// for environments where the proxy is not in front of the API
// (e.g. some production deployments with a reverse proxy) — the
// browser will hit a CORS preflight in that case, which is the
// correct behaviour.
const configuredApiBase = import.meta.env.VITE_API_BASE_URL;
const fallbackApiBase = "/api";
const absoluteApiBase =
  typeof window !== "undefined"
    ? `${window.location.protocol}//${window.location.hostname}:8000/api`
    : null;
const preferredApiBases = [
  configuredApiBase,
  fallbackApiBase,
  absoluteApiBase,
];
const API_BASE_URLS = Array.from(
  new Set(
    preferredApiBases
      .map((value) => (value && value.trim() ? value.trim() : null))
      .filter((value): value is string => Boolean(value)),
  ),
);
export const API_BASE_URL = API_BASE_URLS[0] ?? fallbackApiBase;

async function apiFetch(path: string, init?: RequestInit): Promise<Response> {
  let lastError: unknown;
  const attemptedUrls: string[] = [];
  const failureDetails: string[] = [];
  for (const baseUrl of API_BASE_URLS) {
    attemptedUrls.push(`${baseUrl}${path}`);
    try {
      return await fetch(`${baseUrl}${path}`, init);
    } catch (error) {
      lastError = error;
      failureDetails.push(`${baseUrl}${path} => ${error instanceof Error && error.message ? error.message : String(error)}`);
    }
  }
  // Build a typed network error so the UI can render a friendly
  // "Kairon could not connect to the API" message instead of a
  // raw "Load failed" from the browser.
  const message =
    failureDetails.length
      ? failureDetails.join(" | ")
      : lastError instanceof Error && lastError.message
        ? lastError.message
        : "Network error";
  const error = new Error(`Kairon could not connect to the API. (${message})`);
  (error as Error & { kind?: string; isNetworkError?: boolean }).kind = "network";
  (error as Error & { kind?: string; isNetworkError?: boolean }).isNetworkError = true;
  throw error;
}

/**
 * Typed error for HTTP responses with a structured body.  The
 * backend returns ``{ detail: { error_code, message } }`` for
 * known error codes.  This wrapper exposes the error_code so the
 * UI can render a friendly message instead of the raw URL.
 */
export class ApiError extends Error {
  status: number;
  errorCode: string | null;
  detail: unknown;
  constructor(status: number, errorCode: string | null, message: string, detail: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.errorCode = errorCode;
    this.detail = detail;
  }
}

type UploadProgress = {
  loaded: number;
  total: number;
  lengthComputable: boolean;
};

type UploadAttemptError = Error & {
  nonRetryable?: boolean;
};

type UploadTransport = "xhr" | "fetch";
export type EvidenceIntent = "raw" | "parsed" | "mounted" | "auto";
export type EvidencePackaging = "single_file" | "archive" | "directory" | "mounted_path";
export type IngestMode = "full_forensic" | "usable_search";
export type EvtxProfile = "fast_high_value" | "full" | "custom";

type UploadFormDataOptions = {
  onProgress?: (progress: UploadProgress) => void;
  transport?: UploadTransport;
};

type UploadBlobOptions = {
  method?: "PUT" | "POST";
  contentType?: string;
  headers?: Record<string, string>;
  onProgress?: (progress: UploadProgress) => void;
};

async function buildZipFromFolder(files: File[], archiveName = "raw-folder.zip"): Promise<File> {
  const entries: Zippable = {};
  for (const file of files) {
    const relativePath = (file as File & { webkitRelativePath?: string }).webkitRelativePath || file.name;
    const normalizedPath = relativePath.replaceAll("\\", "/");
    const bytes = new Uint8Array(await file.arrayBuffer());
    entries[normalizedPath] = [bytes, { level: 0 as const }];
  }
  if (Object.keys(entries).length === 0) {
    entries["empty-folder.txt"] = strToU8("empty");
  }
  const zipped = zipSync(entries, { level: 0 });
  return new File([zipped], archiveName, { type: "application/zip" });
}

async function uploadFormData<T>(path: string, formData: FormData, options?: UploadFormDataOptions): Promise<T> {
  let lastError: UploadAttemptError | unknown;
  const attemptedUrls: string[] = [];
  const transport = options?.transport ?? "xhr";
  for (const baseUrl of API_BASE_URLS) {
    const url = `${baseUrl}${path}`;
    attemptedUrls.push(url);
    try {
      const payload =
        transport === "fetch"
          ? await (async () => {
              const response = await fetch(url, {
                method: "POST",
                headers: { Accept: "application/json" },
                body: formData,
              });
              const bodyText = await response.text();
              const contentType = response.headers.get("content-type") ?? "";
              if (!response.ok) {
                let detail: unknown = bodyText || `HTTP ${response.status}`;
                let errorCode: string | null = null;
                let humanMessage: string | null = null;
                try {
                  const parsed = JSON.parse(bodyText) as { detail?: string | { error_code?: string; message?: string } };
                  if (typeof parsed.detail === "string") {
                    detail = parsed.detail;
                    humanMessage = parsed.detail;
                  } else if (parsed.detail && typeof parsed.detail === "object") {
                    detail = parsed.detail;
                    errorCode = parsed.detail.error_code ?? null;
                    humanMessage = parsed.detail.message ?? null;
                  }
                } catch {
                  // Keep raw response text when JSON parsing fails.
                }
                const error = new ApiError(
                  response.status,
                  errorCode,
                  humanMessage || bodyText || `HTTP ${response.status}`,
                  detail,
                ) as ApiError & UploadAttemptError;
                error.nonRetryable = true;
                throw error;
              }
              if (!bodyText) {
                return undefined as T;
              }
              return contentType.includes("application/json") ? (JSON.parse(bodyText) as T) : (bodyText as T);
            })()
          : await new Promise<T>((resolve, reject) => {
              const xhr = new XMLHttpRequest();
              xhr.open("POST", url, true);
              xhr.setRequestHeader("Accept", "application/json");
              xhr.upload.onprogress = (event) => {
                options?.onProgress?.({
                  loaded: event.loaded,
                  total: event.total,
                  lengthComputable: event.lengthComputable,
                });
              };
              xhr.onerror = () => reject(new Error(`Network error while uploading to ${url}`));
              xhr.onabort = () => reject(new Error("Upload aborted"));
              xhr.onload = () => {
                const contentType = xhr.getResponseHeader("content-type") ?? "";
                 if (xhr.status < 200 || xhr.status >= 300) {
                   let detail: unknown = xhr.responseText || `HTTP ${xhr.status}`;
                   let errorCode: string | null = null;
                   let humanMessage: string | null = null;
                   try {
                     const parsed = JSON.parse(xhr.responseText) as { detail?: string | { error_code?: string; message?: string } };
                     if (typeof parsed.detail === "string") {
                       detail = parsed.detail;
                       humanMessage = parsed.detail;
                     } else if (parsed.detail && typeof parsed.detail === "object") {
                       detail = parsed.detail;
                       errorCode = parsed.detail.error_code ?? null;
                       humanMessage = parsed.detail.message ?? null;
                     }
                   } catch {
                     // Keep raw response text when JSON parsing fails.
                   }
                   const error = new ApiError(
                     xhr.status,
                     errorCode,
                     humanMessage || xhr.responseText || `HTTP ${xhr.status}`,
                     detail,
                   ) as ApiError & UploadAttemptError;
                   error.nonRetryable = true;
                   reject(error);
                   return;
                 }
                if (!xhr.responseText) {
                  resolve(undefined as T);
                  return;
                }
                if (contentType.includes("application/json")) {
                  resolve(JSON.parse(xhr.responseText) as T);
                  return;
                }
                resolve(xhr.responseText as T);
              };
              xhr.send(formData);
            });
      return payload;
    } catch (error) {
      lastError = error;
      if ((error as UploadAttemptError | undefined)?.nonRetryable) {
        throw error;
      }
    }
  }
  const detail = lastError instanceof Error && lastError.message ? ` ${lastError.message}` : "";
  throw new Error(`The backend could not be reached during upload. Tried: ${attemptedUrls.join(" | ")}.${detail}`);
}

async function uploadBlob<T>(path: string, blob: Blob, options?: UploadBlobOptions): Promise<T> {
  let lastError: UploadAttemptError | unknown;
  for (const baseUrl of API_BASE_URLS) {
    const url = `${baseUrl}${path}`;
    try {
      return await new Promise<T>((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.open(options?.method ?? "PUT", url, true);
        xhr.setRequestHeader("Accept", "application/json");
        if (options?.contentType) {
          xhr.setRequestHeader("Content-Type", options.contentType);
        }
        for (const [key, value] of Object.entries(options?.headers ?? {})) {
          xhr.setRequestHeader(key, value);
        }
        xhr.upload.onprogress = (event) => {
          options?.onProgress?.({
            loaded: event.loaded,
            total: event.total || blob.size,
            lengthComputable: event.lengthComputable,
          });
        };
        xhr.onerror = () => reject(new Error(`Network error while uploading to ${url}`));
        xhr.onabort = () => reject(new Error("Upload aborted"));
        xhr.onload = () => {
          const contentType = xhr.getResponseHeader("content-type") ?? "";
          if (xhr.status < 200 || xhr.status >= 300) {
            let detail: unknown = xhr.responseText || `HTTP ${xhr.status}`;
            let errorCode: string | null = null;
            let humanMessage: string | null = null;
            try {
              const parsed = JSON.parse(xhr.responseText) as { detail?: string | { error_code?: string; message?: string } };
              if (typeof parsed.detail === "string") {
                detail = parsed.detail;
                humanMessage = parsed.detail;
              } else if (parsed.detail && typeof parsed.detail === "object") {
                detail = parsed.detail;
                errorCode = parsed.detail.error_code ?? null;
                humanMessage = parsed.detail.message ?? null;
              }
            } catch {
              // Preserve raw text for non-JSON errors.
            }
            const error = new ApiError(
              xhr.status,
              errorCode,
              humanMessage || xhr.responseText || `HTTP ${xhr.status}`,
              detail,
            ) as ApiError & UploadAttemptError;
            error.nonRetryable = true;
            reject(error);
            return;
          }
          if (!xhr.responseText) {
            resolve(undefined as T);
            return;
          }
          if (contentType.includes("application/json")) {
            resolve(JSON.parse(xhr.responseText) as T);
            return;
          }
          resolve(xhr.responseText as T);
        };
        xhr.send(blob);
      });
    } catch (error) {
      lastError = error;
      if ((error as UploadAttemptError | undefined)?.nonRetryable) {
        throw error;
      }
    }
  }
  const detail = lastError instanceof Error && lastError.message ? ` ${lastError.message}` : "";
  throw new Error(`The backend could not be reached during upload. Tried the configured API endpoints.${detail}`);
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers ?? undefined);
  const hasBody = init?.body !== undefined && init?.body !== null;
  if (!headers.has("Accept")) {
    headers.set("Accept", "application/json");
  }
  if (hasBody && !(init?.body instanceof FormData) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  const response = await apiFetch(path, {
    headers,
    ...init,
  });
  if (!response.ok) {
    const body = await response.text();
    let detail: unknown = undefined;
    let errorCode: string | null = null;
    let humanMessage: string | null = null;
    try {
      const parsed = JSON.parse(body) as {
        detail?: string | { error_code?: string; message?: string };
      };
      if (typeof parsed.detail === "string") {
        detail = parsed.detail;
        humanMessage = parsed.detail;
      } else if (parsed.detail && typeof parsed.detail === "object") {
        detail = parsed.detail;
        errorCode = parsed.detail.error_code ?? null;
        humanMessage = parsed.detail.message ?? null;
      }
    } catch {
      detail = body || undefined;
    }
    if (response.status >= 500) {
      throw new ApiError(
        response.status, errorCode,
        "The analysis request failed on the server. Check the server logs and try again.",
        detail,
      );
    }
    throw new ApiError(
      response.status,
      errorCode,
      humanMessage || body || `HTTP ${response.status}`,
      detail,
    );
  }
  if (response.status === 204) return undefined as T;
  const contentType = response.headers.get("content-type") ?? "";
  return contentType.includes("application/json") ? ((await response.json()) as T) : ((await response.text()) as T);
}

function buildApiUrl(path: string): string {
  return `${API_BASE_URL}${path}`;
}

function extractDownloadFilename(contentDisposition: string | null, fallback: string): string {
  if (!contentDisposition) return fallback;
  const utf8Match = contentDisposition.match(/filename\*=UTF-8''([^;]+)/i);
  if (utf8Match?.[1]) {
    try {
      return decodeURIComponent(utf8Match[1]);
    } catch {
      return utf8Match[1];
    }
  }
  const basicMatch = contentDisposition.match(/filename="?([^"]+)"?/i);
  return basicMatch?.[1] ? basicMatch[1] : fallback;
}

export type DfirCase = {
  id: string;
  name: string;
  description: string | null;
  status: "open" | "closed" | "archived";
  mode: "investigation" | "demo" | "training" | "validation";
  timezone: string | null;
  detections_count: number;
  findings_count: number;
  created_at: string;
  updated_at: string;
};

export type Evidence = {
  id: string;
  case_id: string;
  original_filename: string;
  stored_path: string;
  original_path: string | null;
  storage_mode: "uploaded" | "mounted_path" | "shared_path" | "external_reference";
  is_external: boolean;
  copy_to_storage: boolean;
  evidence_type: string;
  sha256: string;
  size_bytes: number;
  file_count: number | null;
  ingest_status: string;
  display_status?: string | null;
  investigation_ready?: boolean;
  searchable_documents_count?: number;
  status_reason?: string | null;
  warning_count?: number;
  error_count?: number;
  provided_host?: string | null;
  detected_host: string | null;
  detected_user: string | null;
  source_tool: string | null;
  path_validation: Record<string, unknown>;
  ingest_source: Record<string, unknown>;
  metadata_json: Record<string, unknown>;
  error_log: Record<string, unknown>;
  created_at: string;
  processed_at: string | null;
};

export type MemoryEvidence = {
  id: string;
  case_id: string;
  original_filename: string;
  evidence_type: string;
  size_bytes: number;
  ingest_status: string;
  created_at: string;
};

export type MemoryEvidenceReadiness = {
  exists: boolean;
  regular_file: boolean;
  readable_by_memory_worker: boolean;
  size_matches: boolean;
  output_writable_by_memory_worker: boolean;
  worker_online: boolean;
  backend_ready: boolean;
  can_analyze: boolean;
  error_code: string | null;
  sanitized_message: string;
  symbols_required: boolean;
  symbol_identifier_present: boolean;
  acquisition_available: boolean;
  acquisition_status: string | null;
  can_analyze_offline: boolean;
  pending_request_id: string | null;
};

export type MemoryActiveRun = {
  id: string;
  profile: string;
  status: string;
  started_at: string | null;
  completed_at: string | null;
  duration_seconds: number;
  plugin_count: number | null;
  plugins_completed: number | null;
  plugins_failed: number | null;
  evidence_id: string;
  case_id: string;
};

export type MemoryImageProbeResult = {
  evidence_id: string;
  case_id: string;
  requested_type: string;
  detected_type: string;
  detected_format: string;
  status: string;
  confidence: string;
  reason: string;
  requires_confirmation: boolean;
  can_analyze: boolean;
  probe_version: string;
  file_size: number;
  extension: string;
  operator_override: boolean;
};

export type MemoryImageConfirmResult = {
  evidence_id: string;
  case_id: string;
  status: string;
  operator_override: boolean;
  operator_override_reason: string | null;
  can_analyze: boolean;
};

export type MemoryFamilyState =
  | "ready"
  | "not_analyzed"
  | "completed"
  | "running"
  | "latest_attempt_failed"
  | "unavailable"
  | "historical_override"
  | "unknown_family"
  | "evidence_scope_required"
  | "analyzed_with_results"
  | "analyzed_empty"
  | "partial"
  | "failed"
  | "historical_override_invalid";

export type MemoryActiveResult = {
  case_id: string;
  evidence_id: string;
  artifact_family: string;
  active_run: MemoryActiveRun | null;
  latest_attempt: MemoryActiveRun | null;
  selection_reason: string;
  using_fallback: boolean;
  historical_override: boolean;
  total: number;
  items: unknown[];
  page: number;
  page_size: number;
  count_source: string | null;
  analysis_state: MemoryFamilyState;
};

export type MemoryCatalogueGateType =
  | "available"
  | "blocked_symbol_probe_required"
  | "blocked_symbols_missing"
  | "blocked_acquisition_pending"
  | "unavailable";

export type MemoryAnalysisCatalogueItem = {
  profile: string;
  family: string;
  title: string;
  description: string;
  cost_label: string;
  est_duration_seconds: number;
  available: boolean;
  gate_type: MemoryCatalogueGateType;
  availability_reason: string | null;
  last_run: MemoryActiveRun | null;
  last_status: string | null;
  last_count: number;
  requires_windows_symbols?: boolean;
  can_run_without_symbols?: boolean;
  supported_os_families?: string[];
};

export type MemoryAnalysisCatalogue = {
  case_id: string;
  evidence_id: string;
  items: MemoryAnalysisCatalogueItem[];
};

export type MemoryRunAllMode = "missing_or_failed" | "rerun_all";

export type MemoryRunAllPlan = {
  case_id: string;
  evidence_id: string;
  mode: MemoryRunAllMode;
  selected_profiles: string[];
  skipped_profiles: Array<{ profile: string; reason: string }>;
  excluded_profiles: Array<{ profile: string; reason: string }>;
};

export type MemoryAnalysisBatch = {
  id: string;
  case_id: string;
  evidence_id: string;
  mode: MemoryRunAllMode;
  status: "queued" | "running" | "completed" | "completed_with_errors" | "failed" | "cancelled";
  requested_profiles: string[];
  skipped_profiles: Array<{ profile: string; reason: string }>;
  current_profile: string | null;
  completed_profiles: string[];
  failed_profiles: string[];
  continue_on_failure: boolean;
  cancellation_requested: boolean;
  authorization_acknowledged: boolean;
  created_at: string | null;
  started_at: string | null;
  completed_at: string | null;
  plan?: MemoryRunAllPlan;
  first_run_id?: string;
};

export type MemoryEvidenceLandingItem = {
  evidence_id: string;
  case_id: string;
  filename: string;
  detected_host: string | null;
  size_bytes: number;
  created_at: string | null;
  processed_at: string | null;
  ingest_status: string | null;
  metadata: Record<string, unknown>;
  families: Array<{
    family: string;
    title: string;
    state: MemoryFamilyState;
    active_run: MemoryActiveRun | null;
    latest_attempt: MemoryActiveRun | null;
    selection_reason: string;
    using_fallback: boolean;
    historical_override: boolean;
    availability_reason: string | null;
  }>;
  run_count: number;
  latest_run_id: string | null;
  latest_run_status: string | null;
  detection_status?: string | null;
  detected_format?: string | null;
  detection_confidence?: string | null;
  detection_reason?: string | null;
  operator_override?: boolean;
  operator_override_reason?: string | null;
  operator_override_at?: string | null;
  probe_version?: string | null;
  probed_at?: string | null;
  can_analyze?: boolean;
};

export type MemoryEvidenceLanding = {
  case_id: string;
  items: MemoryEvidenceLandingItem[];
};

export type MemorySymbolCacheStatus = {
  mode: "offline_only" | "managed_download";
  managed_download_enabled: boolean;
  acquisition_enabled: boolean;
  network_isolation_ready: boolean;
  administrator_authorization_available: boolean;
  local_approval_enabled: boolean;
  pending_requests: number;
  awaiting_operator_approval: number;
  approved_pending: number;
  fetcher_online: boolean;
  total_bytes: number;
  configured_max_bytes: number;
  max_bytes: number;
  available_bytes: number;
  symbol_count: number;
  pdb_count: number;
  isf_count: number;
  active_requests: number;
  failed_requests: number;
  last_success_at: string | null;
  error_code: string | null;
  message: string;
};

export type MemorySymbolRequestCreateResponse = {
  request_id: string;
  status: string;
  source_category: string;
  pending_request_id: string;
  requirement_fingerprint: string;
  error_code: string | null;
  message: string;
};

export type MemorySymbolRequestStatus = {
  request_id: string;
  requirement_id: string;
  case_id: string | null;
  evidence_id: string | null;
  status: string;
  source_category: string;
  requirement_fingerprint: string;
  downloaded_bytes: number;
  redirect_count: number;
  error_code: string | null;
  sanitized_message: string | null;
  created_at: string;
  updated_at: string;
  approved_at: string | null;
  approval_expires_at: string | null;
  approval_consumed_at: string | null;
  queued_at: string | null;
  started_at: string | null;
  completed_at: string | null;
  acquisition_id: string | null;
};

export type MemorySymbolRequirement = {
  pdb_name: string;
  pdb_guid: string;
  pdb_age: number;
  architecture: string;
};

export type MemorySymbolCacheMatch = {
  cache_status: "hit" | "miss";
  exact_match: boolean;
  required_identifier: string | null;
  cached_identifiers: string[];
  matched: {
    pdb_name: string;
    pdb_guid: string;
    pdb_age: number;
    architecture: string;
  } | null;
};

export type MemorySymbolReadiness = {
  evidence_id: string;
  state:
    | "unknown"
    | "probing"
    | "cached"
    | "missing"
    | "acquisition_required"
    | "acquisition_pending"
    | "acquiring"
    | "acquired"
    | "incompatible"
    | "unsupported"
    | "failed";
  requirement: MemorySymbolRequirement | null;
  cache: MemorySymbolCacheMatch | null;
  last_probe: string | null;
  last_acquisition: string | null;
  can_analyze_metadata: boolean;
  can_run_all: boolean;
  blocker: string | null;
  error_code: string | null;
  sanitized_message: string | null;
  acquisition_supported: boolean;
  pending_request_id: string | null;
  source: string | null;
  confidence: string | null;
  reconstructed_at: string | null;
};

export type MemorySymbolPreparationState =
  | "pending"
  | "queued"
  | "probing"
  | "acquiring"
  | "converting"
  | "verifying"
  | "ready"
  | "failed"
  | "cancelled"
  | "stale"
  | "blocked_symbols"
  // Legacy aliases kept for backwards compatibility with rows
  // written before the v1 reconciliation sprint.
  | "identified"
  | "cache_hit"
  | "acquisition_pending"
  | "isf_creation"
  | "requirement_unknown"
  | "acquisition_failed"
  | "unsupported"
  | "negative_cached";

export type MemorySymbolPreparationUIState = "ready" | "preparing" | "blocked" | "failed";

export type MemorySymbolAcquisitionSummary = {
  status: string | null;
  error_code: string | null;
  sanitized_message: string | null;
  identity_expected: {
    pdb_name: string;
    pdb_guid: string;
    pdb_age: number;
    architecture: string;
  } | null;
  identity_observed: {
    pdb_guid: string;
    pdb_age: number | null;
    architecture: string | null;
  } | null;
  started_at: string | null;
  completed_at: string | null;
};

export type MemorySymbolPreparation = {
  case_id: string;
  evidence_id: string;
  filename: string;
  ui_state: MemorySymbolPreparationUIState;
  preparation_state: MemorySymbolPreparationState;
  // v1 reconciliation: persisted_state is what is stored on disk;
  // effective_state is what the analyst should see (derived from
  // facts like a successful metadata_only run).
  persisted_state: MemorySymbolPreparationState | null;
  effective_state: MemorySymbolPreparationState | null;
  reconciled: boolean;
  source_of_truth: string | null;
  reconciled_at: string | null;
  preparation_id: string | null;
  stale: boolean;
  stale_reason: string | null;
  task_alive: boolean;
  requirement: MemorySymbolRequirement | null;
  cache_status: "hit" | "miss" | "negative" | "unknown";
  exact_match: boolean;
  pending_request_id: string | null;
  blocker: string | null;
  sanitized_message: string | null;
  can_analyze_metadata: boolean;
  can_run_all: boolean;
  progress_label: string;
  progress_percent: number;
  pending_intent_kind: "single_profile" | "run_all" | null;
  link_source: string | null;
  content_reused_by_hash: boolean;
  native_compatible?: boolean;
  native_compatibility_reason?: string | null;
  source_of_truth?: string | null;
  // Latest acquisition summary surfaced by the canonical preparation
  // endpoint.  The card uses the ``error_code`` to render the
  // structured failure panel and the ``identity_expected`` /
  // ``identity_observed`` payloads to show the analyst exactly
  // what the symbol server returned.
  acquisition?: MemorySymbolAcquisitionSummary;
  // Top-level error code propagated from the latest acquisition.
  // The card surfaces this to drive the identity-mismatch title.
  error_code?: string | null;
};

export type NativeProbeStatus = {
  probe_id: string | null;
  status: "never_run" | "queued" | "running" | "compatible" | "incompatible" | "failed" | "timeout";
  plugin?: string;
  vol_version?: string;
  exit_code?: number;
  output_row_count?: number;
  structural_validation?: Record<string, unknown>;
  sanitized_error?: string;
  started_at?: string;
  completed_at?: string;
  compatible?: boolean;
  compatibility_details?: Record<string, unknown>;
};

// Exact Symbol Recovery Sources v1 — types

export type MemoryRecoverySourceType =
  | "microsoft_public"
  | "corporate_symbol_server"
  | "manual_pdb_import"
  | "manual_isf_import"
  | "offline_symbol_package";

export type MemoryRecoverySourceRead = {
  id: string;
  source_type: MemoryRecoverySourceType;
  name: string;
  enabled: boolean;
  priority: number;
  host: string | null;
  port: number | null;
  path_prefix: string | null;
  tls_required: boolean;
  credential_secret_name: string | null;
  configured_by: string;
  note: string | null;
};

export type MemoryRecoverySourceCreate = {
  source_type: MemoryRecoverySourceType;
  name: string;
  enabled?: boolean;
  priority?: number;
  host?: string;
  port?: number;
  path_prefix?: string;
  tls_required?: boolean;
  credential_secret_name?: string;
  note?: string;
};

export type MemoryRecoverySourceUpdate = {
  enabled?: boolean;
  priority?: number;
  note?: string;
};

export type MemoryRecoveryAttempt = {
  id: string;
  source_type: string;
  source_label: string;
  status: string;
  error_code: string | null;
  sanitized_message: string | null;
  created_at: string;
};

export type MemoryRecoveryResult = {
  status:
    | "ready"
    | "exact_symbol_not_found"
    | "identity_mismatch"
    | "source_unavailable"
    | "validation_failed"
    | "import_rejected"
    | "configuration_required";
  requirement_id: string;
  attempts: Array<{
    source_type: string;
    source_label: string;
    status: string;
    error_code?: string;
    sanitized_message?: string;
  }>;
  cached_symbol_id: string | null;
  error_code: string | null;
  sanitized_message: string | null;
  identity_expected: Record<string, unknown> | null;
  identity_observed: Record<string, unknown> | null;
};

export type MemoryRunWhenReadyRequest = {
  kind: "single_profile" | "run_all";
  profile?: string;
  mode?: string;
  requested_profiles?: string[];
};

export type MemoryRunWhenReadyResponse = {
  case_id: string;
  evidence_id: string;
  pending_id: string;
  kind: string;
  profile: string | null;
  mode: string;
  requested_profiles: string[];
  status: string;
};

export type MemorySymbolProbeResult = {
  evidence_id: string;
  status: string;
  requirement: MemorySymbolRequirement | null;
  probable_os: string | null;
  layer: string | null;
  confidence: string;
  failure_reason: string | null;
  error_code: string | null;
  sanitized_message: string | null;
  duration_ms: number;
};

export type MemorySymbolAcquireResponse = {
  request_id: string | null;
  status: string;
  symbol_mode: string;
  source: string;
  error_code: string | null;
  message: string;
};

export type MemorySymbolBlockedAcquireResponse = {
  request_id: string | null;
  acquisition_id: string | null;
  requirement_id: string | null;
  cached_symbol_id: string | null;
  state: string;
  queue: string;
  task_id: string | null;
  task_alive: boolean;
  retryable: boolean;
  source_category: string;
  pdb_name: string | null;
  pdb_guid: string | null;
  pdb_age: number | null;
  architecture: string | null;
  symbol_key: string | null;
  message: string;
  error_code: string | null;
};

export type MemoryScanRun = {
  id: string;
  case_id: string;
  evidence_id: string;
  backend: string | null;
  profile: string;
  status: string;
  requested_plugin_count: number;
  plugin_count: number;
  plugins_completed: number;
  plugins_failed: number;
  plugins_skipped: number;
  started_at: string | null;
  completed_at: string | null;
  duration_ms: number | null;
  output_dir: string | null;
  metadata_json: Record<string, unknown>;
  error_log: Record<string, unknown>;
  backend_version: string | null;
  worker_task_id: string | null;
  cancellation_requested: boolean;
  created_at: string;
};

export type MemoryPluginRun = {
  id: string;
  memory_scan_run_id: string;
  case_id: string;
  evidence_id: string;
  plugin: string;
  status: string;
  started_at: string | null;
  completed_at: string | null;
  duration_ms: number | null;
  row_count: number;
  output_relative_path: string | null;
  output_sha256: string | null;
  output_size: number | null;
  error_code: string | null;
  error_message: string | null;
  metadata_json: Record<string, unknown>;
  created_at: string;
};

export type MemoryRunDetail = MemoryScanRun & {
  plugin_runs: MemoryPluginRun[];
};

export type MemorySystemInfo = {
  case_id: string;
  evidence_id: string;
  memory_run_id: string;
  memory_plugin_run_id: string;
  source_layer: "memory";
  memory_artifact_type: "memory_system_info";
  backend: string;
  plugin: string;
  host: Record<string, unknown>;
  os: Record<string, unknown>;
  memory: Record<string, unknown>;
  parsed_at: string;
  raw: Record<string, unknown>;
};

export type MemoryProcess = {
  document_id?: string | null;
  case_id: string;
  evidence_id: string;
  memory_run_id: string;
  source_layer: "memory";
  memory_artifact_type: "memory_process";
  backend: string;
  plugins: string[];
  process: Record<string, unknown>;
  memory: Record<string, unknown>;
  visibility: Record<string, unknown>;
  state: Record<string, unknown>;
  parsed_at: string;
  raw: Record<string, unknown>;
  warnings: string[];
};

export type MemoryProcessList = {
  items: MemoryProcess[];
  total: number;
  page: number;
  page_size: number;
};

export type MemoryProcessTree = {
  run_id: string;
  nodes: MemoryProcess[];
  edges: Array<Record<string, unknown>>;
  orphan_count: number;
  root_count: number;
  warnings: string[];
  source_plugins: string[];
  total_process_count: number;
};

export type MemoryProcessEntity = {
  document_id?: string | null;
  document_type: "memory_process_entity";
  case_id: string;
  evidence_id: string;
  scan_run_id: string;
  host_id?: string | null;
  process_entity_id: string;
  process: {
    pid: number;
    ppid?: number | null;
    name?: string | null;
    executable_name?: string | null;
    command_line?: string | null;
    create_time?: string | null;
    exit_time?: string | null;
    session_id?: number | null;
    wow64?: boolean | null;
  };
  visibility: {
    listed?: boolean;
    scan_only?: boolean;
    terminated?: boolean;
    unknown?: boolean;
    hidden_candidate?: boolean;
  };
  sources: string[];
  source_plugins: string[];
  observation_count: number;
  observation_summary: {
    has_pslist?: boolean;
    has_psscan?: boolean;
    has_pstree?: boolean;
    has_cmdline?: boolean;
  };
  confidence: "low" | "medium" | "high";
  first_seen_run_id?: string | null;
  latest_run_id?: string | null;
  findings: string[];
  findings_summary: string[];
  normalization_version: string;
  materialized_from_run_id?: string | null;
  parent_entity_id?: string | null;
  child_count: number;
  tree: {
    is_root?: boolean;
    is_orphan?: boolean;
    is_unknown_parent?: boolean;
    is_cycle?: boolean;
    is_self_parent?: boolean;
    is_pid_zero?: boolean;
  };
  indexed_at?: string | null;
};

export type MemoryProcessEntityList = {
  items: MemoryProcessEntity[];
  total: number;
  page: number;
  page_size: number;
  selected_run?: string | null;
  normalization_version: string;
  total_observations: number;
  facets: Record<string, unknown>;
};

export type MemoryProcessObservation = {
  document_id?: string | null;
  document_type: "memory_process_observation";
  case_id: string;
  evidence_id: string;
  scan_run_id: string;
  process_entity_id: string;
  plugin_run_id?: string | null;
  plugin_name: string;
  source_record_id?: string | null;
  observed: {
    pid: number;
    ppid?: number | null;
    name?: string | null;
    command_line?: string | null;
    create_time?: string | null;
    exit_time?: string | null;
  };
  raw_status: string;
  source_fields: Record<string, unknown>;
  confidence: "low" | "medium" | "high";
  indexed_at?: string | null;
};

export type MemoryProcessEntityDetail = {
  entity: MemoryProcessEntity;
  observations: MemoryProcessObservation[];
  parent: MemoryProcessEntity | null;
  children: MemoryProcessEntity[];
  tree_path: string[];
  alternate_command_lines: string[];
  findings: string[];
  source_record_refs: string[];
};

export type MemoryProcessTreeEntity = {
  run_id: string;
  roots: Array<{
    process_entity_id: string;
    pid: number;
    name?: string | null;
    command_line?: string | null;
    sources: string[];
    visibility: Record<string, boolean>;
    findings: string[];
    confidence?: string;
    create_time?: string | null;
    exit_time?: string | null;
    tree?: Record<string, boolean>;
  }>;
  orphans: Array<{
    process_entity_id: string;
    pid: number;
    name?: string | null;
    command_line?: string | null;
    sources: string[];
    visibility: Record<string, boolean>;
    findings: string[];
    confidence?: string;
    create_time?: string | null;
    exit_time?: string | null;
    tree?: Record<string, boolean>;
  }>;
  top_level_nodes: Array<Record<string, unknown>>;
  nodes: Array<{
    process_entity_id: string;
    pid: number;
    ppid?: number | null;
    name?: string | null;
    command_line?: string | null;
    sources: string[];
    visibility: Record<string, boolean>;
    findings: string[];
    child_count: number;
    confidence?: string;
    create_time?: string | null;
    exit_time?: string | null;
    tree?: Record<string, boolean>;
    truncated?: boolean;
    omitted_children?: number;
    children: Array<Record<string, unknown>>;
  }>;
  edges: Array<Record<string, unknown>>;
  metrics: {
    total_nodes: number;
    roots: number;
    orphans: number;
    unknown_parent: number;
    cycles: number;
    self_parent: number;
    hidden_candidates: number;
    scan_only: number;
    terminated: number;
    pid_zero_count: number;
    pid_4_count: number;
    case_roots?: number;
    current_view_roots?: number;
    visible_processes?: number;
    context_ancestors?: number;
    collapsed_branches?: number;
    processes_not_loaded?: number;
    visible_nodes?: number;
    search_results?: string[];
  };
  total_entities: number;
  omitted_count: number;
  truncation_reason: string | null;
  search_results?: string[];
};

export type MemoryRenormalizeSummary = {
  case_id: string;
  evidence_id: string;
  run_id: string;
  source_documents: number;
  candidate_entities: number;
  observation_count: number;
  duplicate_groups_collapsed: number;
  invalid_records: number;
  ambiguous_pid_groups: number;
  expected_edges: number;
  tree_metrics: {
    total_nodes: number;
    roots: number;
    orphans: number;
    unknown_parent: number;
    cycles: number;
    self_parent: number;
    hidden_candidates: number;
    scan_only: number;
    terminated: number;
    pid_zero_count: number;
    pid_4_count: number;
  };
  normalization_version: string;
  materialization_status: "pending" | "applied" | "dry_run";
};

export type MemoryRunOption = {
  run_id: string;
  profile: string;
  status: string;
  created_at: string;
  completed_at: string | null;
  plugin_count: number;
  plugins_completed: number;
  plugins_failed: number;
  selected: boolean;
};

export type MemoryRunSelector = {
  runs: MemoryRunOption[];
  default_run_id: string | null;
  combined_historical_available: boolean;
};

export type MemoryOverview = {
  case_id: string;
  memory_analysis_enabled: boolean;
  memory_process_profile_enabled: boolean;
  has_memory_evidence: boolean;
  has_memory_results: boolean;
  has_disk_events: boolean;
  mode: "empty" | "disk_only" | "memory_only" | "hybrid";
  evidences: MemoryEvidence[];
  runs: MemoryScanRun[];
  message: string;
};

export type MemoryStartScanResponse = {
  accepted: boolean;
  evidence_id: string;
  run_id: string | null;
  status: string;
  message: string;
  run: MemoryScanRun | null;
};

export type MemoryBackendStatus = {
  backend: string;
  display_name: string;
  configured: boolean;
  executable_found: boolean;
  execution_allowed: boolean;
  available: boolean;
  ready: boolean;
  execution_mode?: string | null;
  dedicated_worker_required?: boolean;
  dedicated_worker_online?: boolean;
  queue?: string | null;
  queue_reachable?: boolean;
  backend_available?: boolean | null;
  backend_version?: string | null;
  supported_profiles?: string[];
  supported_plugins?: string[];
  symbol_network_enabled?: boolean | null;
  version: string | null;
  command_display: string | null;
  status: "disabled" | "not_configured" | "blocked" | "not_found" | "available" | "check_failed";
  message: string;
  checked_at: string;
  error_code: string | null;
};

export type MemoryBackendOverview = {
  memory_analysis_enabled: boolean;
  external_execution_allowed: boolean;
  backends: MemoryBackendStatus[];
  preferred_backend: string | null;
  ready_backend_count: number;
  message: string;
};

export type MemoryUploadReadiness = {
  case_id: string;
  upload_enabled: boolean;
  max_upload_bytes: number;
  max_upload_display: string;
  recommended_chunk_size_bytes: number;
  resumable: boolean;
  max_parallel_chunks: number;
  case_quota_bytes: number;
  case_quota_remaining_bytes: number;
  allowed_extensions: string[];
  staging_available_bytes: number;
  canonical_storage_available_bytes: number;
  memory_output_available_bytes: number;
  recommended_max_upload_bytes: number;
  required_capacity_bytes: number;
  can_accept_selected_size: boolean;
  finalization_strategy: "atomic_move" | "staged_copy" | null;
  analysis_enabled: boolean;
  dedicated_worker_online: boolean;
  backend_ready: boolean;
  message: string;
};

export type MemoryUploadStatus = {
  upload_id: string;
  case_id?: string;
  evidence_id: string | null;
  status: "created" | "validating" | "uploading" | "verifying" | "finalizing" | "completed" | "failed" | "cancelled" | "expired" | "stale" | "inconsistent";
  stage?: string | null;
  registration_state?: string | null;
  registration_attempts?: number;
  canonical_preserved?: boolean;
  bytes_received: number;
  expected_bytes: number;
  expected_sha256?: string | null;
  chunk_size_bytes?: number;
  total_chunks?: number;
  received_chunk_count?: number;
  received_chunks?: number[];
  missing_chunks?: number[];
  progress_percent?: number;
  filename?: string;
  extension?: string;
  created_at?: string;
  updated_at: string;
  last_heartbeat?: string;
  expires_at?: string | null;
  finalized_at?: string | null;
  stale_after_seconds?: number;
  stale?: boolean;
  resumable?: boolean;
  cancellable?: boolean;
  is_active?: boolean;
  failure_code: string | null;
  failure_message?: string | null;
  duplicate?: { existing_evidence_id?: string; existing_filename?: string | null };
  last_registration_error_code?: string | null;
  last_registration_error_class?: string | null;
  message: string;
  retryable: boolean;
};

export type MemoryUploadSessionCreateRequest = {
  filename: string;
  expected_size_bytes: number;
  provided_host: string;
  authorization_acknowledged: boolean;
  expected_sha256?: string;
};

export type ProblematicArtifact = {
  artifact_id: string | null;
  name: string;
  source_path: string;
  artifact_type: string;
  parser: string;
  status: string;
  original_status?: string;
  effective_status?: string;
  effective_resolution?: string | null;
  records_read: number;
  records_indexed: number;
  effective_records_read?: number;
  effective_records_indexed?: number;
  bulk_batches: number;
  error_type?: string | null;
  error_message?: string | null;
  timeout_seconds?: number;
  partial_data_indexed: boolean;
  data_loss_expected: boolean;
  historical_data_loss_expected?: boolean;
  current_data_loss_expected?: boolean;
  retryable: boolean;
  suggested_retry_mode?: string | null;
  suggested_primary_action?: string | null;
  importance: string;
  importance_reasons: string[];
  retry_history?: Array<Record<string, unknown>>;
  latest_retry?: Record<string, unknown> | null;
  health_summary?: string;
  loss_summary?: string;
  deep_retry_history?: Array<Record<string, unknown>>;
  health_check?: Record<string, unknown> | null;
  latest_health_check?: Record<string, unknown> | null;
  recovered?: boolean;
  recovered_records?: number;
  accepted_warning?: boolean;
  accepted_at?: string | null;
  accepted_reason?: string | null;
};

export type EvtxHealthCheckResult = {
  artifact_id: string | null;
  artifact_key?: string | null;
  filename: string;
  exists: boolean;
  resolved_path?: string | null;
  size_bytes?: number | null;
  evtx_header_valid?: boolean;
  records_seen?: number;
  first_record_ok?: boolean;
  last_record_ok?: boolean;
  parse_errors?: number;
  timed_out?: boolean;
  corrupt_header?: boolean;
  truncated_file?: boolean;
  diagnosis: string;
  likely_corrupt: boolean;
  retry_recommended: boolean;
  suggested_retry_mode?: string | null;
  health_check_at?: string | null;
};

export type ProblematicArtifactsResponse = {
  evidence_id: string;
  summary: {
    problematic_count: number;
    parsed_with_warning: number;
    partially_parsed: number;
    failed: number;
    skipped_empty?: number;
    retryable: number;
    indexed_with_warning: number;
    recovered_count: number;
    unresolved_count: number;
    data_loss_expected_count: number;
    source_missing_but_indexed: number;
  };
  items: ProblematicArtifact[];
};

export type ProblematicRetryCandidatesResponse = {
  evidence_id: string;
  summary: ProblematicArtifactsResponse["summary"];
  retry_candidates: ProblematicArtifact[];
  retry_candidate_count: number;
  artifact_ids: string[];
  affected_families: Record<string, number>;
  excluded: {
    skipped_empty: number;
    warnings_fully_indexed: number;
    other_non_retryable: number;
  };
};

export type LongTailArtifact = {
  artifact_id: string | null;
  name?: string | null;
  artifact?: string | null;
  source_path?: string | null;
  artifact_type?: string | null;
  parser?: string | null;
  status: string;
  long_tail_state: string;
  importance: string;
  importance_reasons: string[];
  records_read: number;
  records_indexed: number;
  elapsed_seconds: number;
  no_progress_seconds: number;
  partial_coverage_warning: boolean;
  data_loss_expected: boolean;
  retryable: boolean;
  suggested_retry_mode?: string | null;
  defer_recommended?: boolean;
  hard_timeout_recommended?: boolean;
  defer_requested?: boolean;
  defer_request?: Record<string, unknown> | null;
};

export type LongTailArtifactsResponse = {
  evidence_id: string;
  run_id?: string | null;
  summary: {
    tail_artifacts_total: number;
    running_count: number;
    queued_count: number;
    deferred_count: number;
    stalled_count: number;
    high_value_count: number;
    partial_indexed_count: number;
    queued_artifacts: number;
  };
  items: LongTailArtifact[];
};

export type EvidenceRun = {
  run_id: string;
  run_type: string;
  mode?: string | null;
  status: string;
  phase?: string | null;
  progress?: number | null;
  current_artifact?: string | null;
  current_artifact_source?: string | null;
  artifact_progress?: string | null;
  artifacts_total?: number | null;
  artifacts_done?: number | null;
  artifacts_failed?: number | null;
  records_read?: number | null;
  records_indexed?: number | null;
  events_indexed?: number | null;
  records_per_sec?: number | null;
  tail_artifacts_total?: number | null;
  tail_artifacts_running?: number | null;
  tail_artifacts_queued?: number | null;
  tail_artifacts_completed?: number | null;
  tail_artifacts_failed?: number | null;
  tail_records_read?: number | null;
  tail_records_indexed?: number | null;
  tail_last_progress_at?: string | null;
  tail_records_per_sec?: number | null;
  tail_current_artifacts?: Array<Record<string, unknown>>;
  tail_slowest_artifacts?: Array<Record<string, unknown>>;
  tail_elapsed_seconds?: number | null;
  heartbeat_at?: string | null;
  started_at?: string | null;
  finished_at?: string | null;
  elapsed_seconds?: number | null;
  last_error?: string | null;
  warnings?: unknown[];
  selected_by_artifact_type?: Record<string, number>;
  selected_by_parser?: Record<string, number>;
  parsed_by_artifact_type?: Record<string, number>;
  failed_artifacts_count?: number | null;
  retry_candidates_count?: number | null;
  retry_of_artifact_ids?: string[];
  artifact_ids?: string[];
  recovered_count?: number | null;
  still_failed_count?: number | null;
  skipped_count?: number | null;
  final_message?: string | null;
  retry_profile?: Record<string, unknown>;
  items?: Array<Record<string, unknown>>;
};

export type EvidenceRunQueuedResponse = {
  accepted: boolean;
  evidence_id: string;
  run_id: string;
  status: string;
  mode: string;
};

export type EvidenceIndexingStep = {
  id: string;
  name: string;
  category: string;
  status: string;
  reason: string;
  heavy?: boolean;
  endpoint?: string | null;
  run_id?: string | null;
};

export type EvidenceIndexingPlan = {
  profile: "recommended" | "fast" | "advanced_custom";
  label: string;
  primary_cta: string;
  subcopy: string;
  steps: EvidenceIndexingStep[];
  excluded: Array<{ name: string; reason: string }>;
  runnable_steps: EvidenceIndexingStep[];
  active: boolean;
  active_job?: { step?: string; run_id?: string; status?: string } | null;
  state?: "planned_not_started" | "active" | "ready" | string;
  status_reason?: string;
  requires_user_action?: boolean;
  supported_candidate_count?: number;
  can_run: boolean;
};

export type EvidenceIndexingPlanRunResponse = {
  accepted: boolean;
  evidence_id: string;
  profile: string;
  run_id: string;
  status: string;
  queued_jobs: Array<{ step_id: string; run_id: string; status: string }>;
  plan: {
    run_id: string;
    profile: string;
    status: string;
    steps: EvidenceIndexingStep[];
    excluded: Array<{ name: string; reason: string }>;
    queued_jobs: Array<{ step_id: string; run_id: string; status: string }>;
  };
};

export type EvidenceBenchmark = {
  benchmark_id: string;
  evidence_id: string;
  case_id: string;
  run_id?: string | null;
  label?: string | null;
  notes?: string | null;
  mode: string;
  profile: string;
  status: string;
  requested_at?: string | null;
  started_at?: string | null;
  finished_at?: string | null;
  phase?: string | null;
  current_action?: string | null;
  current_selected_path?: string | null;
  last_progress_at?: string | null;
  last_progress_seconds_ago?: number | null;
  current_phase_stalled?: boolean | null;
  stalled_phase_warning?: string | null;
  effective_parallelism?: number | null;
  effective_cpu_count?: number | null;
  memory_limit_source?: string | null;
  source_evidence_name?: string | null;
  total_duration_seconds?: number | null;
  time_to_first_artifact_ready?: number | null;
  time_to_first_parse_start?: number | null;
  time_to_first_event_indexed?: number | null;
  records_read?: number | null;
  records_indexed?: number | null;
  events_indexed?: number | null;
  artifacts_total?: number | null;
  selected_total?: number | null;
  artifacts_completed?: number | null;
  artifacts_failed?: number | null;
  artifacts_created_for_run?: number | null;
  artifacts_processed_for_run?: number | null;
  artifacts_failed_for_run?: number | null;
  problematic_count?: number | null;
  records_per_sec?: number | null;
  events_per_sec?: number | null;
  artifacts_per_sec?: number | null;
  metadata_opensearch_delta?: number | null;
  phase_timings?: Array<Record<string, unknown>>;
  resource_samples?: Array<Record<string, unknown>>;
  by_parser?: Record<string, Record<string, unknown>>;
  bottleneck_report?: {
    bottleneck?: string;
    confidence?: string;
    reasons?: string[];
    recommendations?: string[];
  };
  benchmark_options?: Record<string, unknown>;
  autopilot_enabled?: boolean | null;
  attempts?: Array<Record<string, unknown>>;
  current_attempt?: number | null;
  watchdog_status?: string | null;
  last_watchdog_check_at?: string | null;
  watchdog_actions?: Array<Record<string, unknown>>;
  final_recommendation?: string | null;
};

export type EvidenceBenchmarkQueuedResponse = {
  accepted: boolean;
  benchmark_id: string;
  evidence_id: string;
  run_id: string;
  status: string;
  mode: string;
  profile: string;
};

export type OnDemandModule = {
  id: string;
  label: string;
  group: string;
  module_category?: "on_demand_stable" | "advanced" | "disabled" | "legacy" | string;
  status: "available" | "beta" | "advanced" | "disabled";
  badge?: string | null;
  disabled_reason?: string | null;
  requires: string[];
  risk_level?: "low" | "medium" | "high" | string;
  auto_runs?: boolean;
  visible_in_core?: boolean;
  visible_in_advanced?: boolean;
  route?: string | null;
  case_route?: string | null;
  evidence_route?: string | null;
  description?: string | null;
  warning?: string | null;
};

export type OnDemandModulesResponse = {
  evidence_id: string;
  case_id: string;
  core_flow: {
    recommended_ingest_mode: IngestMode;
    steps: string[];
  };
  modules: Record<string, OnDemandModule>;
};

export type CaseContextHostSummary = {
  id: string;
  canonical_name: string;
  display_name: string;
  confidence: string;
  source: string;
  event_count: number;
  evidence_count: number;
  findings_count: number;
  high_risk_count: number;
  aliases: string[];
  alias_rows: Array<{
    id: string;
    alias: string;
    normalized_alias: string;
    is_primary: boolean;
    event_count: number;
    first_seen?: string | null;
    last_seen?: string | null;
  }>;
  all_names: string[];
  alias_count: number;
  first_seen?: string | null;
  last_seen?: string | null;
};

export type CaseContextEvidenceSummary = {
  id: string;
  name: string;
  status: string;
  storage_mode: Evidence["storage_mode"];
  is_external: boolean;
  events_indexed: number;
  parser_errors: number;
  detected_host: string | null;
};

export type CaseNextAction = {
  id: string;
  label: string;
  href: string;
  priority: "primary" | "secondary" | string;
  enabled: boolean;
  reason?: string;
};

export type CaseContextResponse = {
  case: DfirCase;
  hosts: CaseContextHostSummary[];
  host_candidates?: Array<Record<string, unknown>>;
  rejected_host_candidates?: Array<Record<string, unknown>>;
  evidences: CaseContextEvidenceSummary[];
  summary: {
    events_indexed: number;
    findings_total: number;
    findings_high: number;
    parser_errors: number;
    warnings: string[];
    investigation_state?: {
      state: "empty_case" | "evidence_uploaded_not_indexed" | "indexing_in_progress" | "investigation_ready" | "investigation_in_progress" | "report_ready" | string;
      evidence_count: number;
      investigation_ready_evidence_count: number;
      indexed_docs: number;
      active_jobs: Array<Record<string, unknown>>;
      active_job_count: number;
      findings_count: number;
      official_timeline_count: number;
      candidate_timeline_count: number;
      marked_events_count: number;
      parser_errors: number;
      warnings: string[];
      reports_count?: number;
      timeline_needs_review_count?: number;
      timeline_dismissed_count?: number;
      defender_docs?: number;
      startup_persistence_docs?: number;
    };
    next_actions?: {
      primary: CaseNextAction[];
      secondary: CaseNextAction[];
      unavailable: CaseNextAction[];
    };
    validation_matrix?: {
      case_id: string;
      mode: "investigation" | "demo" | "training" | "validation";
      has_validation_matrix: boolean;
      show_validation_matrix: boolean;
      demo_cases_enabled?: boolean;
      validation_features_enabled?: boolean;
      label: string;
      reason: string;
    };
  };
};

export type CaseHostAuditEntry = {
  id: string;
  case_id: string;
  case_host_id?: string | null;
  action: string;
  old_value: Record<string, unknown>;
  new_value: Record<string, unknown>;
  reason?: string | null;
  analyst?: string | null;
  created_at?: string | null;
};

export type CaseHostsResponse = {
  case_id: string;
  hosts: CaseContextHostSummary[];
  host_candidates: Array<Record<string, unknown>>;
};

export type CaseHostAuditResponse = {
  case_id: string;
  items: CaseHostAuditEntry[];
};

export type StorageCapabilities = {
  allow_host_path_import: boolean;
  allowed_roots: string[];
  max_upload_size: number;
  memory_upload_enabled?: boolean;
  memory_upload_max_bytes?: number;
  memory_upload_allowed_extensions?: string[];
  supports_mounted_path: boolean;
  can_edit_deployment_settings?: boolean;
  restart_enabled?: boolean;
  deployment_setting_scope?: string;
  restart_commands?: string[];
  enable_instructions?: {
    env: Record<string, string>;
    commands: string[];
  };
  allowed_root_details?: Array<{
    path: string;
    label: string;
    example_path: string;
  }>;
};

export type PathValidationResult = {
  valid: boolean;
  exists: boolean;
  readable: boolean;
  is_directory: boolean;
  is_file: boolean;
  within_allowed_root: boolean;
  allowed_roots?: string[];
  looks_like_client_path?: boolean;
  path_style?: "windows" | "windows_unc" | "macos" | "linux_home" | "server_absolute" | "relative" | "unknown";
  suggested_action?: "upload_file" | "mount_folder" | "use_allowed_root" | "enable_host_path_import" | null;
  message?: string | null;
  resolved_path: string | null;
  size_bytes: number | null;
  file_count: number | null;
  warnings: string[];
  error?: string | null;
};

export type Artifact = {
  id: string;
  case_id: string;
  evidence_id: string;
  name: string;
  artifact_type: string;
  source_path: string;
  parser: string;
  record_count: number;
  status: string;
  created_at: string;
};

export type FindingSeverity = "info" | "low" | "medium" | "high" | "critical";
export type FindingConfidence = "low" | "medium" | "high";
export type FindingStatus = "new" | "reviewed" | "confirmed" | "dismissed" | "open" | "false_positive" | "closed";

export type FindingTimelineItem = {
  timestamp?: string | null;
  event_id?: string | null;
  artifact_type?: string | null;
  event_type?: string | null;
  summary?: string | null;
};

export type Finding = {
  id: string;
  case_id: string;
  evidence_id?: string | null;
  finding_type?: string | null;
  title: string;
  summary?: string | null;
  description?: string | null;
  severity: FindingSeverity;
  confidence?: FindingConfidence | null;
  status: FindingStatus;
  risk_score?: number | null;
  query?: string | null;
  event_ids?: string[];
  detection_ids?: string[];
  time_start?: string | null;
  time_end?: string | null;
  timeline?: FindingTimelineItem[];
  related_event_ids?: string[];
  related_artifact_ids?: string[];
  related_evidence_ids?: string[];
  related_process_node_ids?: string[];
  related_files?: string[];
  related_domains?: string[];
  related_ips?: string[];
  related_users?: string[];
  related_hosts?: string[];
  reasons?: string[];
  tags?: string[];
  mitre?: string[];
  recommended_triage?: string[];
  source?: string | null;
  correlation_version?: string | null;
  data_quality?: string[];
  fingerprint?: string | null;
  created_at: string;
  updated_at: string;
};

export type CorrelationRunResult = {
  case_id?: string;
  evidence_id?: string | null;
  findings_generated: number;
  findings_deduplicated: number;
  process_graph_available?: boolean;
  by_type?: Record<string, number>;
  by_severity?: Record<string, number>;
  by_status?: Record<string, number>;
  scope?: {
    case_id?: string;
    host?: string | null;
    canonical_host?: string | null;
    evidence_id?: string | null;
    all_hosts?: boolean;
    hosts?: string[];
    evidence_ids?: string[];
    time_range?: { from?: string | null; to?: string | null };
    query_terms?: string[];
    sources?: string[];
    scope_type?: string;
    scope_reason?: string;
  };
  effective_scope?: {
    case_id?: string;
    host?: string | null;
    canonical_host?: string | null;
    evidence_id?: string | null;
    all_hosts?: boolean;
  };
  request_scope?: { host?: string | null; evidence_id?: string | null };
  scope_reason?: string;
  correlation_run_id?: string;
  cache_key?: string;
  reused_previous_run?: boolean;
  counts?: {
    candidates_scanned?: number;
    matched?: number;
    returned?: number;
    deduplicated?: number;
    hidden_by_limit?: number;
    has_more?: boolean;
    event_limit_reached?: boolean;
  };
  limits?: {
    page?: number;
    page_size?: number;
    max_results?: number;
    max_candidates?: number;
    reason?: string;
  };
  source_breakdown?: Record<string, number>;
  host_breakdown?: Record<string, number>;
  result_source_breakdown?: Record<string, number>;
  result_host_breakdown?: Record<string, number>;
  pagination?: { page?: number; page_size?: number; has_more?: boolean; next_page?: number | null };
};

export type SearchV2FacetMap = Record<string, Record<string, number>>;

export type SearchV2Result = {
  kind: "event" | "finding";
  id: string;
  timestamp?: string | null;
  title: string;
  summary?: string | null;
  artifact_type?: string | null;
  parser?: string | null;
  event_type?: string | null;
  severity?: string | null;
  risk_score?: number | null;
  host?: string | null;
  user?: string | null;
  source_file?: string | null;
  matched_fields?: string[];
  highlights?: Record<string, string[]>;
  marking?: EventMarking | null;
  raw?: Record<string, unknown>;
};

export type EventMarkingStatus = "unreviewed" | "reviewed" | "suspicious" | "important" | "false_positive";

export type EventMarking = {
  id: string;
  case_id: string;
  evidence_id?: string | null;
  event_id: string;
  search_doc_id?: string | null;
  stable_event_id?: string | null;
  artifact_type?: string | null;
  timestamp?: string | null;
  host?: string | null;
  status: EventMarkingStatus;
  labels: string[];
  note?: string | null;
  finding_id?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
  created_by?: string | null;
};

export type SearchV2Response = {
  query: Record<string, unknown>;
  query_syntax?: {
    mode: "plain" | "advanced" | "mixed";
    parsed: boolean;
    errors: string[];
    warnings: string[];
    normalized_query: string;
    applied_filters: Array<{ field: string; operator: string; value: string }>;
  };
  total: number;
  page?: number;
  page_size: number;
  items_count?: number;
  has_next?: boolean;
  has_previous?: boolean;
  pagination_mode?: "offset" | "cursor";
  debug_pagination?: Record<string, unknown>;
  next_cursor?: string | null;
  results: SearchV2Result[];
  facets: SearchV2FacetMap;
  warnings: string[];
};

export type EventContextResponse = {
  event_id: string;
  case_id: string;
  evidence_id?: string | null;
  available_context: Record<string, string | number | boolean | null | undefined>;
  counts: {
    related_detections: number;
    related_findings: number;
  };
  related_detections: Array<{
    id: string;
    rule_name: string;
    rule_title?: string | null;
    severity?: string | null;
    status?: string | null;
    engine?: string | null;
    event_id?: string | null;
  }>;
  related_findings: Array<{
    id: string;
    title: string;
    severity?: string | null;
    status?: string | null;
    finding_type?: string | null;
    risk_score?: number | null;
  }>;
};

export type EvidenceSearchSummary = {
  evidence_id: string;
  case_id: string;
  ingest_status: string;
  display_status?: string | null;
  latest_ingest_run_id: string;
  total_indexed_docs: number;
  investigation_ready?: boolean;
  searchable_documents_count?: number;
  status_reason?: string | null;
  warning_count?: number;
  error_count?: number;
  last_successful_ingest_run_id?: string | null;
  artifact_type_counts: Record<string, number>;
  parser_counts: Record<string, number>;
  source_file_counts: Record<string, number>;
  host_counts: Record<string, number>;
  user_counts: Record<string, number>;
  mft_diagnostic?: MftDiagnostic;
  registry_diagnostic?: RegistryDiagnostic;
};

export type RegistryDiagnostic = {
  evidence_id: string;
  case_id: string;
  available: boolean;
  status: "not_present" | "available_on_demand" | "indexed" | "indexing" | "failed" | "tooling_missing" | string;
  hives_present: boolean;
  hive_count: number;
  hive_names: string[];
  hives_indexed: boolean;
  registry_docs: number;
  registry_persistence_docs: number;
  persistence_summary_status: string;
  registry_events_present: boolean;
  registry_events_indexed: boolean;
  registry_event_docs: number;
  sysmon_registry_events: number;
  sysmon_event_12_count?: number;
  sysmon_event_13_count?: number;
  sysmon_event_14_count?: number;
  security_4657_events: number;
  registry_command_evidence_count?: number;
  registry_modification_coverage?: {
    sysmon_registry_events_present: boolean;
    sysmon_event_12_count: number;
    sysmon_event_13_count: number;
    sysmon_event_14_count: number;
    security_4657_present: boolean;
    security_4657_count: number;
    registry_command_evidence_count: number;
    registry_event_docs_indexed: number;
    status: "not_present" | "indexed" | "available_from_event_logs" | "not_collected" | string;
  };
  derived_persistence_indexed: boolean;
  service_registry_docs: number;
  user_activity_docs: number;
  user_activity_status: string;
  tool_available: boolean;
  recommended_mode: string;
  actions: string[];
  registry_status?: {
    hives_present: boolean;
    hives: Array<{ hive?: string; name?: string; path?: string; source_path?: string; size_bytes?: number | null; size?: number | null; user_hint?: string | null; available?: boolean }>;
    persistence_summary_status: string;
    persistence_summary_docs: number;
    full_hive_status: string;
  };
  coverage_gaps: string[];
  detected_hives: Array<{ name: string; hive?: string; source_path: string; artifact_type: string; parser: string; status: string; reason: string; size?: number | null; size_bytes?: number | null; user_hint?: string | null }>;
};

export type MftDiagnostic = {
  evidence_id: string;
  case_id: string;
  mft_status?: {
    available: boolean;
    status: "not_present" | "available_on_demand" | "indexed" | "indexing" | "failed" | "tooling_missing" | string;
    raw_mft_found: boolean;
    raw_mft_size_bytes: number;
    usn_found: boolean;
    usn_size_bytes: number;
    mftecmd_output_found: boolean;
    indexed_docs: number;
    tool_available: boolean;
    recommended_mode: "summary" | "full" | "none" | string;
    actions: string[];
  };
  mft_present_in_evidence: boolean;
  mft_detected_by_inventory: boolean;
  mft_selected_for_indexing: boolean;
  mft_indexed_docs: number;
  mft_skipped_reason: string;
  mft_backend_available: boolean;
  mft_parser_backend?: string | null;
  mft_parser_backend_version?: string | null;
  mft_index_mode?: string | null;
  mft_coverage_status?: string | null;
  mft_records_total?: number;
  mft_records_indexed?: number;
  mft_records_skipped?: number;
  mft_elapsed_seconds?: number;
  mft_summary_status?: string | null;
  mft_summary_records_indexed?: number;
  mft_full_status?: string | null;
  mft_full_records_total?: number;
  mft_full_records_indexed?: number;
  mft_full_started_at?: string | null;
  mft_full_finished_at?: string | null;
  mft_full_elapsed_seconds?: number;
  mft_full_coverage_status?: string | null;
  mft_full_backend?: string | null;
  mft_full_limits?: Record<string, unknown>;
  recommended_action: string;
  detected_candidates: Array<{
    name: string;
    source_path: string;
    artifact_type: string;
    parser: string;
    status: string;
    reason: string;
    size?: number | null;
  }>;
};

export type SearchQuickFilter = {
  id: string;
  label: string;
  params: Record<string, unknown>;
};

export type SearchQuickFiltersResponse = {
  case_id: string;
  items: SearchQuickFilter[];
};

export type TimelineMode = "full" | "investigation";

export type TimelineBookmark = {
  id: string;
  case_id: string;
  event_id: string;
  finding_id?: string | null;
  timestamp?: string | null;
  title: string;
  summary?: string | null;
  note?: string | null;
  category: "execution" | "download" | "detection" | "persistence" | "network" | "cleanup" | "other";
  importance: "low" | "medium" | "high" | "critical";
  created_at?: string | null;
  updated_at?: string | null;
  created_by?: string | null;
  order_index: number;
  include_in_report: boolean;
};

export type TimelineItem = {
  id: string;
  kind: "event" | "finding" | "bookmark";
  timestamp?: string | null;
  time_bucket?: string | null;
  title: string;
  summary?: string | null;
  artifact_type?: string | null;
  parser?: string | null;
  event_type?: string | null;
  event_category?: string | null;
  risk_score?: number | null;
  severity?: string | null;
  host?: string | null;
  user?: string | null;
  evidence_id?: string | null;
  source_file?: string | null;
  key_entity?: string | null;
  related_finding_ids?: string[];
  related_process_node_ids?: string[];
  is_key_event?: boolean;
  bookmark?: TimelineBookmark | null;
  data_quality?: string[];
  raw?: Record<string, unknown>;
};

export type TimelineGroup = {
  key: string;
  label: string;
  count: number;
  high_risk_count: number;
};

export type TimelineResponse = {
  case_id: string;
  query: Record<string, unknown>;
  mode: TimelineMode;
  total: number;
  page_size: number;
  next_cursor?: string | null;
  items: TimelineItem[];
  groups: TimelineGroup[];
  facets: Record<string, Record<string, number>>;
  warnings: string[];
  finding?: SearchV2Result;
  related_events?: SearchV2Response;
};

export type IncidentTimelineItem = {
  id: string;
  timestamp?: string | null;
  host?: string | null;
  phase: string;
  phase_confidence?: string | null;
  confidence?: string | null;
  title: string;
  summary?: string | null;
  source: string;
  source_type?: string | null;
  status?: "candidate" | "accepted" | "dismissed" | "needs_review" | string;
  provenance_badge?: string | null;
  artifact_type?: string | null;
  severity?: string | null;
  risk_score?: number | null;
  event_id?: string | null;
  evidence_id?: string | null;
  finding_id?: string | null;
  command_id?: string | null;
  query?: string | null;
  notes?: string | null;
  included?: boolean;
  host_alias?: string | null;
  search_url?: string | null;
  execution_story_url?: string | null;
  story_target_type?: string | null;
  story_target_confidence?: string | null;
  story_target_reason?: string | null;
  story_primary_action?: string | null;
};

export type IncidentTimelineStoryBundle = {
  case_id: string;
  item: IncidentTimelineItem;
  target: {
    type: string;
    confidence?: string | null;
    reason?: string | null;
    primary_action?: string | null;
  };
  pivots: Record<string, string | null | undefined>;
  movement?: Record<string, unknown> | null;
  file_story?: Record<string, unknown> | null;
  indicator_resolution?: IndicatorResolutionResponse | null;
  linked_evidence: Record<string, unknown>;
};

export type ExtractedIndicator = {
  indicator: string;
  type: string;
  subtype?: string;
  source_field?: string;
  confidence?: string;
  normalized?: string;
  display?: string;
};

export type IndicatorResolutionResult = {
  indicator: string;
  type: string;
  status: string;
  sources_found: string[];
  counts_by_source: Record<string, number>;
  hosts: string[];
  first_seen?: string | null;
  last_seen?: string | null;
  evidence_ids: string[];
  confidence: string;
  explanation: string;
  suggested_pivots: Array<{ label: string; url: string; type: string }>;
};

export type IndicatorResolutionResponse = {
  case_id: string;
  indicators: ExtractedIndicator[];
  results: IndicatorResolutionResult[];
};

export type StartupPersistenceItem = {
  id: string;
  case_id: string;
  evidence_id?: string | null;
  host?: string | null;
  type: string;
  name: string;
  command_or_target?: string | null;
  path?: string | null;
  user?: string | null;
  enabled?: boolean | null;
  start_type?: string | null;
  trigger?: string | null;
  source_artifact?: string | null;
  source_event_id?: string | null;
  first_seen?: string | null;
  last_modified?: string | null;
  risk_score: number;
  risk_reasons: string[];
  indicator_resolution?: ExtractedIndicator[];
  related_events?: string[];
  confidence?: string | null;
  search_url?: string | null;
  timeline_url?: string | null;
  raw?: Record<string, unknown>;
};

export type StartupPersistenceResponse = {
  case_id: string;
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
  items: StartupPersistenceItem[];
  summary: {
    total: number;
    suspicious: number;
    high_risk: number;
    by_host: Record<string, number>;
    by_type: Record<string, number>;
    by_source: Record<string, number>;
  };
  warnings: string[];
  wmi_status?: "parsed" | "tooling_missing" | "not_present" | string;
};

export type MotwItem = {
  id: string;
  case_id: string;
  evidence_id?: string | null;
  host?: string | null;
  artifact_type: "motw" | string;
  file_path: string;
  file_name: string;
  file_extension?: string | null;
  zone_identifier_path: string;
  zone_id?: number | null;
  zone_name: string;
  host_url?: string | null;
  referrer_url?: string | null;
  source_url?: string | null;
  browser_download_id?: string | null;
  timestamp?: string | null;
  source_artifact: string;
  source_event_id?: string | null;
  hashes: Record<string, string>;
  raw_content?: string | null;
  risk_score: number;
  risk_reasons: string[];
  linked?: Record<string, string>;
  indicator_resolution?: ExtractedIndicator[];
  search_url?: string | null;
  timeline_url?: string | null;
  raw?: Record<string, unknown>;
};

export type MotwResponse = {
  case_id: string;
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
  items: MotwItem[];
  summary: {
    total: number;
    suspicious: number;
    high_risk: number;
    by_host: Record<string, number>;
    by_zone: Record<string, number>;
    by_source: Record<string, number>;
    by_extension: Record<string, number>;
  };
  warnings: string[];
};

export type EmailArtifactItem = {
  id: string;
  case_id: string;
  evidence_id?: string | null;
  host?: string | null;
  artifact_type: "email" | string;
  email_artifact_type: "store" | "message_file" | "profile" | "attachment_cache" | "webmail_activity" | "related_email_download" | "app_presence" | "technical_trace" | string;
  client: "outlook" | "thunderbird" | "windows_mail" | "browser_webmail" | "unknown" | string;
  account_hint?: string | null;
  file_path?: string | null;
  file_name?: string | null;
  url?: string | null;
  extension?: string | null;
  size?: number;
  created?: string | null;
  modified?: string | null;
  accessed?: string | null;
  timestamp?: string | null;
  source_artifact?: string | null;
  source_event_id?: string | null;
  confidence?: string | null;
  relation_reason?: string | null;
  content_parsed: boolean;
  risk_score: number;
  risk_reasons: string[];
  related_indicators?: ExtractedIndicator[];
  related_downloads?: Array<Record<string, unknown>>;
  related_motw?: Array<Record<string, unknown>>;
  related_user_activity?: Array<Record<string, unknown>>;
  search_url?: string | null;
  timeline_url?: string | null;
  raw?: Record<string, unknown>;
};

export type EmailArtifactsResponse = {
  case_id: string;
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
  items: EmailArtifactItem[];
  summary: {
    total: number;
    stores: number;
    message_files: number;
    attachment_cache: number;
    webmail_activity: number;
    related_email_downloads?: number;
    app_presence?: number;
    technical_traces?: number;
    advanced_technical_traces?: number;
    interesting: number;
    by_host: Record<string, number>;
    by_type: Record<string, number>;
    by_client: Record<string, number>;
    by_source: Record<string, number>;
  };
  warnings: string[];
  limitations: string[];
  attachment_cache_status: string;
};

export type IncidentTimelineDraftResponse = {
  case_id: string;
  timeline_id?: string;
  query: Record<string, unknown>;
  total: number;
  items: IncidentTimelineItem[];
  hosts: string[];
  phases: string[];
  groups: Record<string, { key: string; count: number }[]>;
  curation?: {
    official_count?: number;
    candidate_count?: number;
    needs_review_count?: number;
    dismissed_count?: number;
    by_status?: Record<string, number>;
    by_source_type?: Record<string, number>;
    by_confidence?: Record<string, number>;
  };
  warnings: string[];
  no_mft_flood_default: boolean;
  available_sources: string[];
  phase_options: string[];
  cache?: {
    hit?: boolean;
    memory?: boolean;
    persistent?: boolean;
    ttl_seconds?: number;
    status?: "fresh" | "stale" | "building" | "failed";
    stale?: boolean;
    reason?: string | null;
    draft_id?: string;
    timeline_id?: string;
    created_at?: string;
    updated_at?: string;
    generated_at?: string;
    generation_seconds?: number | null;
    builder_version?: string;
  };
};

export type ReportTemplate = {
  id: string;
  name: string;
  description: string;
  sections: string[];
};

export type CaseReport = {
  id: string;
  case_id: string;
  evidence_id?: string | null;
  title: string;
  status: "queued" | "running" | "completed" | "completed_with_warnings" | "completed_with_errors" | "failed" | "cancelled" | "draft" | "generated" | "archived";
  template: string;
  report_type?: string;
  format?: string;
  mode?: string | null;
  created_at: string | null;
  updated_at: string | null;
  generated_at: string | null;
  author?: string | null;
  source_ingest_run_id?: string | null;
  size_bytes?: number | null;
  time_range: Record<string, unknown>;
  filters: Record<string, unknown>;
  sections_enabled: Record<string, boolean>;
  analyst_notes: Record<string, string>;
  selected_finding_ids: string[];
  selected_key_event_ids: string[];
  selected_process_chain_ids: string[];
  include_raw_appendix: boolean;
  include_debug_metadata: boolean;
  metadata_json?: Record<string, unknown>;
};

export type CaseReportPreviewSection = {
  id: string;
  title: string;
  markdown: string;
  warnings: string[];
};

export type CaseReportPreview = {
  title: string;
  sections: CaseReportPreviewSection[];
  warnings: string[];
  stats: Record<string, number>;
  counts?: Record<string, number>;
  filters_applied?: Record<string, unknown>;
};

export type ValidationMatrixResult =
  | "found"
  | "partial"
  | "not_found"
  | "memory_only"
  | "not_present_in_evidence"
  | "parser_gap"
  | "ux_gap";

export type ValidationMatrixItem = {
  case_id: string;
  validation_id: string;
  source_name: string;
  source_urls: Record<string, string>;
  finding_id: string;
  title: string;
  description: string;
  phase: string;
  host: string;
  result: ValidationMatrixResult;
  confidence: string;
  expected_indicators: string[];
  expected_artifacts: string[];
  evidence_source_used: string[];
  supporting_event_ids: string[];
  related_timeline_items: string[];
  related_findings: string[];
  notes: string;
  source_part: string[];
  memory_required: boolean;
  search_url?: string | null;
  timeline_url?: string | null;
  docs_url?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
};

export type ValidationMatrixResponse = {
  case_id: string;
  validation_id: string | null;
  source_name: string | null;
  source_urls: Record<string, string>;
  source_parts: string[];
  items: ValidationMatrixItem[];
  summary: Record<string, number | Record<string, number>>;
  filtered_summary?: Record<string, number | Record<string, number>>;
  filters: {
    hosts: string[];
    phases: string[];
    results: ValidationMatrixResult[];
    source_parts: string[];
  };
  generated_at: string;
  warnings: string[];
  visibility?: {
    case_id: string;
    mode: "investigation" | "demo" | "training" | "validation";
    has_validation_matrix: boolean;
    show_validation_matrix: boolean;
    demo_cases_enabled?: boolean;
    validation_features_enabled?: boolean;
    label: string;
    reason: string;
  };
};

export type Rule = {
  id: string;
  case_id: string | null;
  rule_set_id: string | null;
  name: string;
  title: string | null;
  engine: "yara" | "sigma" | "heuristic";
  namespace: string | null;
  source: string | null;
  description: string | null;
  author: string | null;
  rule_version: string | null;
  level: string | null;
  content: string;
  content_hash: string | null;
  enabled: boolean;
  severity: string | null;
  status: string;
  references: string[];
  false_positives: string[];
  tags: string[];
  mitre: string[];
  validation_errors: string[];
  metadata_json: Record<string, unknown>;
  created_at: string;
  updated_at: string;
};

export type RuleSet = {
  id: string;
  case_id: string | null;
  name: string;
  engine: "yara" | "sigma" | "heuristic";
  namespace: string | null;
  description: string | null;
  source_filename: string | null;
  content_path: string | null;
  content?: string;
  rules_count: number;
  enabled: boolean;
  severity: string | null;
  tags: string[];
  metadata_json: Record<string, unknown>;
  created_at: string;
  updated_at: string;
};

export type RuleRun = {
  id: string;
  rule_id: string | null;
  rule_set_id: string | null;
  case_id: string;
  evidence_id: string | null;
  engine: string;
  status: "queued" | "running" | "completed" | "failed" | "cancelled" | "stale" | "skipped";
  scope: string;
  matched: number;
  total_rules: number;
  processed_rules: number;
  total_events: number;
  scanned_events: number;
  total_files: number;
  created_detections: number;
  duplicates: number;
  scanned_files: number;
  skipped_files: number;
  current_phase: string | null;
  heartbeat_at: string | null;
  last_error: string | null;
  cancel_requested?: boolean;
  retried_from_run_id?: string | null;
  stale_reason?: string | null;
  elapsed_seconds: number | null;
  percent_complete: number | null;
  stale: boolean;
  can_cancel?: boolean;
  can_retry?: boolean;
  warnings: string[];
  errors: unknown[];
  metadata_json: Record<string, unknown>;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
  updated_at: string;
};

export type RuleEngineStatus = Record<
  string,
  {
    available: boolean;
    runs_on: string;
    supported?: string | null;
    supports_rule_packs?: boolean | null;
    scan_extracted?: boolean | null;
    scan_originals?: boolean | null;
    max_file_size_mb?: number | null;
    error?: string | null;
  }
>;

export type Detection = {
  id: string;
  case_id: string;
  evidence_id: string | null;
  artifact_id: string | null;
  rule_id: string | null;
  rule_set_id: string | null;
  engine: string;
  source_engine: string | null;
  rule_name: string;
  rule_title: string | null;
  rule_version: string | null;
  rule_author: string | null;
  rule_level: string | null;
  severity: string | null;
  confidence: number | null;
  event_id: string | null;
  event_index: string | null;
  opensearch_id: string | null;
  target_type: string;
  target_path: string | null;
  matched_at: string | null;
  matched_file_hash: string | null;
  matched_process_node_id: string | null;
  host_name: string | null;
  message: string | null;
  status: string;
  analyst_note: string | null;
  matched_fields: Record<string, unknown>;
  matched_strings: Array<Record<string, unknown>>;
  condition_summary: string | null;
  description: string | null;
  false_positives: string[];
  references: string[];
  tags: string[];
  mitre: string[];
  related_event_ids: string[];
  related_finding_ids: string[];
  related_iocs: Record<string, unknown>;
  risk_score: number | null;
  dedup_fingerprint: string | null;
  engine_version: string | null;
  data_quality: string[];
  raw: Record<string, unknown>;
  rule_run_id?: string | null;
  rule_import_run_id?: string | null;
  rule_source_pack?: string | null;
  orphaned_rule?: boolean;
  created_at: string;
  deleted_at: string | null;
  archived_at: string | null;
};

export type ActivityEvent = {
  id: string;
  case_id: string | null;
  evidence_id: string | null;
  actor: string | null;
  activity_type: string;
  severity: "info" | "warning" | "error";
  title: string;
  message: string;
  metadata: Record<string, unknown>;
  created_at: string;
};

export type RuleImportResponse = {
  import_run_id: string | null;
  status: string;
  engine: string;
  summary: Record<string, unknown>;
  source_name: string | null;
  source_type: string | null;
  pack_name: string | null;
  total_files: number;
  processed_files: number;
  total_rules_found: number;
  imported_count: number;
  updated_count: number;
  duplicate_count: number;
  imported_rules: number;
  imported_rule_sets: number;
  total_yara_rules_inside: number;
  compiled_count: number;
  unsupported_condition_count: number;
  compile_error_count: number;
  invalid_count: number;
  unsupported_count: number;
  warning_count: number;
  error_count: number;
  sigma_rules_by_product: Record<string, number>;
  sigma_rules_by_category: Record<string, number>;
  skipped_count: number;
  warnings: string[];
  errors: string[];
  invalid_items: Array<Record<string, unknown>>;
  unsupported_items: Array<Record<string, unknown>>;
  detected_engine_counts: Record<string, number>;
  sample_imported: string[];
  rules: Rule[];
  rule_sets: RuleSet[];
};

export type RuleImportRun = {
  id: string;
  case_id: string | null;
  engine: string;
  source_name: string | null;
  source_type: string;
  uploaded_filename: string | null;
  pack_name: string | null;
  status: string;
  started_at: string | null;
  finished_at: string | null;
  cancelled_at: string | null;
  elapsed_seconds: number | null;
  total_files: number;
  processed_files: number;
  total_rules_found: number;
  processed_rules: number;
  imported_count: number;
  updated_count: number;
  duplicate_count: number;
  skipped_count: number;
  invalid_count: number;
  compiled_count: number;
  unsupported_count: number;
  warning_count: number;
  error_count: number;
  current_phase: string | null;
  current_file: string | null;
  last_error: string | null;
  cancel_requested: boolean;
  warnings_summary: string[];
  errors_summary: string[];
  created_rule_ids: string[];
  updated_rule_ids: string[];
  duplicate_rule_ids: string[];
  invalid_items: Array<Record<string, unknown>>;
  unsupported_items: Array<Record<string, unknown>>;
  import_options: Record<string, unknown>;
  details_json: Record<string, unknown>;
  progress_pct?: number | null;
  is_terminal?: boolean;
  files_per_sec?: number | null;
  rules_per_sec?: number | null;
  created_at: string;
  updated_at: string;
};

export type RuleImportRunListResponse = {
  total: number;
  items: RuleImportRun[];
};

export type DocEntry = {
  slug: string;
  title: string;
  summary: string;
};

export type DocPage = DocEntry & {
  content: string;
};

export type VelociraptorCandidate = {
  id: string;
  category: string;
  artifact_type: string;
  parser_status: string;
  parser?: string | null;
  display_name: string;
  original_path: string;
  local_path: string;
  normalized_windows_path: string | null;
  user: string | null;
  browser: string | null;
  profile: string | null;
  task_name?: string | null;
  task_path?: string | null;
  sid?: string | null;
  original_i_path?: string | null;
  original_r_path?: string | null;
  local_i_path?: string | null;
  local_r_path?: string | null;
  normalized_windows_i_path?: string | null;
  normalized_windows_r_path?: string | null;
  has_metadata_file?: boolean | null;
  has_content_file?: boolean | null;
  pair_id?: string | null;
  size: number | null;
  mtime: string | null;
  confidence: string;
  supported: boolean;
  reason: string | null;
  warnings: string[];
  companion_files: string[];
  container_type?: string | null;
  container_path?: string | null;
  local_staging_path?: string | null;
  extraction_status?: string | null;
};

export type VelociraptorDiscoveryResult = {
  collection_id: string;
  collection_root: string;
  hostname: string | null;
  candidates: VelociraptorCandidate[];
  summary: Record<string, number>;
  total_files_scanned: number;
  warnings: string[];
};

export type VelociraptorDiscoverResponse = {
  evidence: Evidence;
  discovery: VelociraptorDiscoveryResult;
  fallback_supported?: boolean;
  fallback_mode?: "generic_archive" | null;
  message?: string | null;
};

export type VelociraptorParseResponse = {
  evidence: Evidence;
  selected_candidate_ids: string[];
  selected_count: number;
  job: string;
};

export type UploadOptions = {
  onProgress?: (progress: UploadProgress) => void;
  ingestMode?: IngestMode;
  providedHost?: string;
  evtxProfile?: EvtxProfile;
};

export type RuleRunResult = {
  rule_id: string | null;
  rule_set_id?: string | null;
  engine: string;
  case_id: string;
  matched: number;
  created_detections: number;
  duplicates: number;
  skipped: boolean;
  error: string | null;
  status: string;
  run_id?: string | null;
};

export type SigmaSmokeRequest = {
  case_id: string;
  evidence_id?: string | null;
  host?: string | null;
  mode: "single_rule" | "subset" | "recommended";
  rule_id?: string | null;
  rule_ids?: string[];
  severity?: string | null;
  logsource?: string | null;
  tag?: string | null;
  keyword?: string | null;
  max_rules?: number;
  max_detections_per_rule?: number;
  max_events_per_rule?: number;
};

export type SigmaSmokeRuleResult = {
  rule_id: string;
  rule_name: string;
  title: string | null;
  severity: string | null;
  status: string;
  reason: string | null;
  matched: number;
  created_detections: number;
  duplicates: number;
  scanned_events: number;
  expected_logsource: Record<string, unknown>;
  field_mappings: Record<string, unknown>;
  required_fields: string[];
  missing_fields: string[];
  sample_detection_ids: string[];
  sample_event_ids: string[];
  warnings: string[];
  errors: string[];
};

export type SigmaSmokeResponse = {
  run_id: string | null;
  run_type: "smoke";
  case_id: string;
  evidence_id: string | null;
  host: string | null;
  mode: string;
  preflight_only: boolean;
  max_rules: number;
  max_detections_per_rule: number;
  rules_selected: number;
  matched: number;
  no_match: number;
  skipped: number;
  unsupported: number;
  errors: number;
  created_detections: number;
  field_mapping_explanation: boolean;
  rules: SigmaSmokeRuleResult[];
  warnings: string[];
};

export type RuleBulkDeleteResult = {
  matched: number;
  deleted: number;
  disabled: number;
  skipped: number;
  skipped_reasons: Record<string, number>;
  affected_packs: string[];
  errors: string[];
  warnings?: string[];
};

export type RuleBulkUpdateResult = {
  matched: number;
  updated: number;
  enabled: boolean;
  skipped: number;
  skipped_reasons: Record<string, number>;
  errors: string[];
  warnings?: string[];
};

export type RuleBulkPreviewResult = {
  matched: number;
  protected: number;
  affected_packs: string[];
  by_engine: Record<string, number>;
  by_source_pack: Record<string, number>;
};

export type SigmaCoverageReport = {
  scope: string;
  case_id: string | null;
  total: number;
  fully_supported: number;
  partially_supported?: number;
  partial: number;
  unsupported: number;
  by_support_status: Record<string, number>;
  by_product: Record<string, number>;
  by_category: Record<string, number>;
  by_service: Record<string, number>;
  by_compile_status: Record<string, number>;
  false_positive_risk_count: number;
  by_false_positive_risk_reason: Record<string, number>;
  missing_field_mappings?: Record<string, number>;
  top_missing_fields?: Array<Record<string, unknown>>;
  recommended_parser_followups?: Array<Record<string, unknown>>;
  false_positive_risk_examples: Array<Record<string, unknown>>;
  unsupported_examples: Array<Record<string, unknown>>;
  field_mapping: Record<string, unknown>;
  rules_scope: {
    global_sigma_rules: number;
    case_sigma_rules: number;
    available_for_case: number;
  };
  generated_at: string;
};

export type SigmaRuleLibrarySnapshot = {
  created: boolean;
  path: string;
  checksum: string;
  count: number;
  scope: string;
  case_id: string | null;
  created_at: string;
};

export type SigmaPromotionResult = {
  case_id: string;
  matched: number;
  promoted: number;
  skipped_duplicates: number;
  duplicate_rule_ids: string[];
  global_total_before: number;
  global_total_after: number;
  case_total_after: number;
  confirmation_required: string;
  mode?: string;
  before_snapshot: SigmaRuleLibrarySnapshot | null;
  after_snapshot: SigmaRuleLibrarySnapshot;
};

export type RuleRunActionResult = {
  ok: boolean;
  run: RuleRun;
  message: string;
};

export type RuleRunBulkActionResult = {
  matched: number;
  updated: number;
  deleted: number;
  skipped: number;
  skipped_reasons: Record<string, number>;
  created_run_ids: string[];
  errors: string[];
  warnings?: string[];
};

export type SearchResponse = {
  total: number;
  total_relation: string;
  has_more: boolean;
  page: number;
  page_size: number;
  total_pages: number;
  total_pages_visible: number;
  deep_pagination_supported: boolean;
  result_window_limit: number;
  has_more_beyond_window: boolean;
  result_profile: {
    is_homogeneous: boolean;
    artifact_types: string[];
    event_categories: string[];
    recommended_view: string;
  };
  items: Record<string, unknown>[];
};

export type ProcessTreeNode = {
  id: string;
  pid: number | null;
  name: string | null;
  path: string | null;
  command_line: string | null;
  user: string | null;
  sid: string | null;
  host: string | null;
  first_seen: string | null;
  last_seen: string | null;
  source_type?: string | null;
  source_event_id?: string | null;
  source_events: string[];
  risk_score: number;
  risk_reasons: string[];
  badges: string[];
  data_quality: string[];
  confidence: string;
  parent_entity_id?: string | null;
  parent_pid?: number | null;
  parent_name?: string | null;
  parent_link_status?: string | null;
  parent_link_reason?: string | null;
  parent_link_confidence?: string | null;
  parent_fields?: {
    parent_entity_id?: string | null;
    parent_pid?: number | null;
    parent_name?: string | null;
    host?: string | null;
    first_seen?: string | null;
  } | null;
};

export type ProcessTreeEdge = {
  id?: string;
  source: string;
  target: string;
  type: string;
  confidence: string;
  source_event_id?: string | null;
  timestamp?: string | null;
  reason: string;
  summary?: string | null;
  weight?: number | null;
  risk?: number | null;
};

export type ProcessTreeGraph = {
  case_id: string;
  evidence_id: string | null;
  scope: string;
  nodes: ProcessTreeNode[];
  edges: ProcessTreeEdge[];
  groups?: Array<Record<string, unknown>>;
  omitted_counts?: Record<string, number>;
  truncated?: boolean;
  summary: Record<string, unknown>;
};

export type ProcessTreeBundle = {
  graph: ProcessTreeGraph;
  report: Record<string, unknown>;
  sample_chains: Array<Record<string, unknown>>;
};

export type ProcessTreeExpansion = {
  base_node?: ProcessTreeNode | null;
  added_nodes: ProcessTreeNode[];
  added_edges: ProcessTreeEdge[];
  activity_groups?: Array<Record<string, unknown>>;
  omitted_counts?: Record<string, number>;
  warnings?: string[];
  summary?: Record<string, unknown>;
  command_history?: Record<string, unknown>;
};

export type ProcessTreeFocused = {
  focus_node?: ProcessTreeNode | null;
  parents: ProcessTreeNode[];
  children: ProcessTreeNode[];
  siblings: ProcessTreeNode[];
  activity_groups?: Array<Record<string, unknown>>;
  nodes: ProcessTreeNode[];
  edges: ProcessTreeEdge[];
  omitted_counts?: Record<string, number>;
  warnings?: string[];
  identity_resolution?: {
    method?: string | null;
    confidence?: string | null;
    ambiguous_candidates?: ProcessTreeNode[];
    parent_explanation?: string | null;
    target_identity_matches?: boolean | null;
    requested_source_event_id?: string | null;
    requested_process_guid?: string | null;
  };
};

export type ExecutionStory = {
  target?: ProcessTreeNode | null;
  target_node_id?: string | null;
  default_selected_node_id?: string | null;
  requested_target?: Record<string, unknown>;
  resolved_target?: Record<string, unknown> | null;
  auto_focus_reason?: "explicit_command_history_row" | "risk_based_fallback" | "candidate_child" | "manual" | string;
  story: {
    summary: string;
    parent_sentence: string;
    children_sentence: string;
    activity_sentence: string;
    risk_sentence: string;
  };
  parents: ProcessTreeNode[];
  children: ProcessTreeNode[];
  siblings: ProcessTreeNode[];
  activity_groups: {
    items: Array<Record<string, unknown>>;
    omitted_counts?: Record<string, number>;
  };
  commands: Array<Record<string, unknown>>;
  source_events: string[];
  visual_tree: {
    nodes: ProcessTreeNode[];
    edges: ProcessTreeEdge[];
  };
  event_summary?: Record<string, unknown>;
  candidate_processes?: ProcessTreeNode[];
  nearby?: Record<string, unknown>;
  recommended_action?: string;
  quality: {
    confidence: string;
    missing_parent: boolean;
    ambiguous_pid: boolean;
    warnings: string[];
    identity_resolution?: ProcessTreeFocused["identity_resolution"];
    exact_story?: boolean;
    origin?: "search_event" | "command_history" | "direct_search" | "advanced_graph" | string;
    filter_scope?: "exact_chain" | "extra_context" | "candidate_search" | "advanced_graph" | string;
    visual_tree_contains_target?: boolean;
    target_quality?: "exact" | "related" | "generic" | string;
    identity_method?: string | null;
    recommended_action?: string | null;
    recommendations?: string[];
    activity_lazy?: boolean;
    response_mode?: "full" | "lightweight" | string;
    cache?: { hit?: boolean; ttl_seconds?: number };
  };
};

export type CommandHistorySupportingEvent = {
  event_id?: string | null;
  stable_event_id?: string | null;
  source_type: string;
  windows_event_id?: number | string | null;
  timestamp?: string | null;
  source_file?: string | null;
  artifact_type?: string | null;
  parser?: string | null;
};

export type CommandHistoryItem = {
  id: string;
  case_id: string;
  evidence_id?: string | null;
  host?: string | null;
  timestamp?: string | null;
  timestamp_status: "forensic" | "derived" | "missing" | "suspicious";
  command: string;
  command_normalized?: string;
  shell: string;
  launcher?: string | null;
  launcher_path?: string | null;
  shell_family?: string | null;
  classification_confidence?: "high" | "medium" | "low" | string | null;
  parent_shell?: string | null;
  parent_context?: string | null;
  source_type: string;
  artifact_type?: string | null;
  source_event_id?: string | null;
  windows_event_id?: string | number | null;
  source_file?: string | null;
  user?: string | null;
  process: {
    name?: string | null;
    executable?: string | null;
    pid?: string | number | null;
    guid?: string | null;
    command_line?: string | null;
  };
  parent_process: {
    name?: string | null;
    executable?: string | null;
    pid?: string | number | null;
    guid?: string | null;
    command_line?: string | null;
  };
  working_directory?: string | null;
  risk_score: number;
  risk_reasons: string[];
  confidence: "high" | "medium" | "low";
  dedupe_key?: string;
  raw_payload?: string | null;
  registry_command?: {
    command_line?: string | null;
    registry_path?: string | null;
    operation?: string | null;
    confidence?: "command_evidence" | string | null;
    confirmed_by_registry_event?: boolean;
    linked_registry_event_ids?: string[];
    key_entity?: string | null;
    snippet?: string | null;
  } | null;
  supporting_events: CommandHistorySupportingEvent[];
  linked_search_url: string;
};

export type CommandHistoryResponse = {
  total: number;
  page: number;
  page_size: number;
  sort?: "timestamp_asc" | "timestamp_desc" | string;
  sort_by?: "timestamp" | string;
  sort_order?: "asc" | "desc" | string;
  items: CommandHistoryItem[];
  facets: {
    shell: Record<string, number>;
    family?: Record<string, number>;
    launcher?: Record<string, number>;
    confidence?: Record<string, number>;
    source_type: Record<string, number>;
    user: Record<string, number>;
    host: Record<string, number>;
    risk: Record<string, number>;
  };
  summary: {
    commands_total: number;
    suspicious_total: number;
    high_confidence: number;
    with_command_line: number;
    with_supporting_events: number;
  };
};

export type PaginatedDetections = {
  items: Detection[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
};

export type DetectionSummaryRuleGroup = {
  rule_id: string | null;
  rule_name: string;
  severity: string | null;
  count: number;
  new_count: number;
  reviewed_count: number;
  dismissed_count: number;
  confirmed_count: number;
  unique_hosts: number;
  unique_users: number;
  unique_artifact_types: number;
  unique_source_files: number;
  first_seen: string | null;
  last_seen: string | null;
  sample_entities: string[];
  sample_source_files: string[];
  sample_event_ids: string[];
  percentage?: number;
};

export type DetectionSummaryBucket = {
  key: string;
  count: number;
};

export type DetectionSummary = {
  total: number;
  state?: {
    active: number;
    soft_deleted: number;
    dismissed: number;
    reviewed: number;
    confirmed: number;
  };
  by_severity: Record<string, number>;
  by_status: Record<string, number>;
  by_rule: DetectionSummaryRuleGroup[];
  by_host: DetectionSummaryBucket[];
  by_user: DetectionSummaryBucket[];
  by_evidence: DetectionSummaryBucket[];
  by_artifact_type: DetectionSummaryBucket[];
  by_source_file: DetectionSummaryBucket[];
  by_rule_run: DetectionSummaryBucket[];
  top_noisy_rules: DetectionSummaryRuleGroup[];
  new_vs_reviewed: Record<string, number>;
};

export type SearchFacets = Record<string, Record<string, number>>;

export type DetectionFacets = {
  engines: Array<{ value: string; count: number }>;
  sources: Array<{ value: string; count: number }>;
  severities: Array<{ value: string; count: number }>;
  statuses: Array<{ value: string; count: number }>;
  rule_names: Array<{ value: string; count: number }>;
  hosts: Array<{ value: string; count: number }>;
  matched_object_types: Array<{ value: string; count: number }>;
  evidences: Array<{ id: string; name: string; count: number }>;
  artifacts: Array<{ value: string; count: number }>;
  has_linked_event: Array<{ value: boolean; count: number }>;
  has_file_target: Array<{ value: boolean; count: number }>;
};

export type DetectionBulkFilterSet = {
  case_id?: string;
  source?: string;
  engine?: string;
  rule_id?: string;
  rule_run_id?: string;
  import_run_id?: string;
  source_pack?: string;
  severity?: string;
  status?: string;
  rule_name?: string;
  evidence_id?: string;
  host?: string;
  user?: string;
  artifact_type?: string;
  source_file?: string;
  matched_object_type?: string;
  q?: string;
  has_linked_event?: boolean;
  has_file_target?: boolean;
  created_from?: string;
  created_to?: string;
  orphaned_only?: boolean;
  run_type?: string;
};

export type DetectionBulkPreviewResult = {
  matched: number;
  by_source: Record<string, number>;
  by_status: Record<string, number>;
  by_severity: Record<string, number>;
  by_rule: Array<{ rule_id: string | null; title: string; count: number }>;
  by_run: Array<{ rule_run_id: string; count: number }>;
  orphaned_rule_count: number;
  protected_count: number;
  warnings: string[];
};

export type DetectionBulkActionResult = {
  matched: number;
  updated: number;
  deleted: number;
  skipped: number;
  errors: string[];
  warnings: string[];
  activity_id?: string | null;
};

export type SiemFieldInfo = {
  name: string;
  type: string;
  searchable: boolean;
  aggregatable: boolean;
  count?: number;
  sample_values?: string[];
};

export type SiemFieldsResponse = {
  indexed_fields: SiemFieldInfo[];
  normalized_fields: SiemFieldInfo[];
  raw_fields_sample: Array<{ name: string; count: number; sample_values: string[]; searchable: boolean; aggregatable: boolean }>;
  unmapped_raw_fields: Array<{ name: string; count: number; sample_values: string[]; searchable: boolean; aggregatable: boolean }>;
  missing_common_fields: Array<{ field: string; missing_count: number }>;
  message?: string;
};

export type SiemFieldFilter = {
  field: string;
  operator: "eq" | "neq" | "contains" | "exists" | "not_exists" | "gte" | "lte";
  value?: string | number | boolean | null;
};

export type SiemExternalLinks = {
  dashboards_home: string;
  discover_url: string;
  index_pattern: string;
  case_filter: string;
  kql_or_lucene_query: string;
  copyable_filters: Record<string, string>;
};

export type SiemExternalStatus = {
  enabled: boolean;
  internal_url: string;
  public_url: string;
  index_pattern: string;
  time_field: string;
  available: boolean;
  error: string | null;
  case_filter: string;
};

export type SiemExternalSetup = {
  dashboards_available: boolean;
  opensearch_indices_found: boolean;
  indices: string[];
  data_view_created: boolean;
  data_view_exists: boolean;
  manual_steps_required: boolean;
  manual_steps: string[];
};

export type SiemExternalDiagnostics = {
  opensearch: {
    available: boolean;
    indices: string[];
    docs_count: number;
  };
  dashboards: {
    available: boolean;
    public_url: string;
    internal_url: string;
    data_view: {
      exists: boolean;
      title: string;
      time_field: string;
    };
    error?: string | null;
  };
  case: {
    case_id: string | null;
    events_count: number;
    filter: string;
  };
};

export type AdminOpenSearchDashboardsStatus = {
  opensearch: {
    available: boolean;
    events_index_pattern: string;
    events_count: number;
    indices: string[];
  };
  dashboards: {
    available: boolean;
    url: string;
    data_view_exists: boolean;
    data_view_id: string | null;
    data_view_title: string;
    time_field: string;
    warnings: string[];
    recommended_columns: string[];
  };
};

export type AdminOpenSearchDashboardsBootstrapResponse = {
  created: boolean;
  updated: boolean;
  data_view_id: string | null;
  data_view_title: string;
  time_field: string;
  message: string;
  warnings: string[];
  status: AdminOpenSearchDashboardsStatus;
};

export type EvidenceManifest = {
  evidence_id: string;
  case_id: string;
  original_filename: string;
  sha256: string;
  evidence_type: string;
  source_tool: string | null;
  created_at: string | null;
  processed_at: string | null;
  files: Array<{ path: string; size: number; sha256: string | null; extension: string; ignored: boolean; reason: string | null }>;
  artifacts: Array<{
    name: string;
    source_path: string;
    artifact_type: string;
    parser: string;
    profile: string | null;
    record_count: number;
    status: string;
    reason?: string | null;
    planned_parser?: string | null;
  }>;
  stats: Record<string, number>;
  errors: Array<Record<string, unknown>>;
};

export type IngestPlanCandidate = {
  candidate_id: string;
  source_path: string;
  relative_path: string;
  artifact_type: string;
  parser: string;
  enabled: boolean;
  reason: string;
  fingerprint: string;
  size: number | null;
  mtime: string | null;
  status: string;
  supported?: boolean;
  warnings?: string[];
  display_name?: string | null;
  category?: string | null;
  profile?: string | null;
  can_run_later?: boolean;
  suggested_action?: string | null;
  evtx_channel?: string | null;
};

export type EvidenceReprocessPreview = {
  evidence_id: string;
  previous_plan_available: boolean;
  mode: "previous_selection" | "choose_again" | "full_rediscovery" | "manual_selection";
  summary: {
    previous_selected: number;
    available_again: number;
    missing: number;
    changed: number;
    new_candidates: number;
    unsupported: number;
    selected_by_artifact_type?: Record<string, number>;
    selected_by_parser?: Record<string, number>;
  };
  selected_candidates: IngestPlanCandidate[];
  missing_candidates: IngestPlanCandidate[];
  new_candidates: IngestPlanCandidate[];
  changed_candidates: IngestPlanCandidate[];
  warnings: string[];
  previous_plan?: Record<string, unknown> | null;
};

export type RuleListResponse = {
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
  items: Rule[];
};

export type RuleSetListResponse = {
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
  items: RuleSet[];
};

export type SystemStatus = {
  cpu: { percent: number; count: number };
  memory: { total: number; used: number; percent: number };
  disk: {
    data_dir_total: number;
    data_dir_used: number;
    data_dir_free?: number;
    data_dir_percent: number;
    status?: "healthy" | "degraded" | "critical" | string;
    warning_threshold_percent?: number;
    critical_threshold_percent?: number;
  };
  queues: Record<string, { queued: number; started: number; failed: number; finished: number }>;
  opensearch: {
    available: boolean;
    cluster_status: string;
    heap_used_percent: number | null;
    indices: number;
    docs_count: number;
    write_blocked?: boolean | null;
    ingest_writable?: boolean | null;
    watermark_risk?: "low" | "medium" | "high" | "unknown" | string;
    blocking_reasons?: string[];
  };
  workers: { active: number; known: string[] };
  evtx_parser_backends?: {
    evtxecmd?: { available?: boolean; version?: string; path?: string; supports_csv?: boolean; supports_json?: boolean };
    evtx_raw_python?: { available?: boolean; role?: string };
  };
  settings: Record<string, unknown>;
  deployment: Record<string, unknown>;
};

export type SystemVersionInfo = {
  app_version: string;
  vendor_id: string;
  build_channel: string;
  build_fingerprint: string;
  notice: string;
};

export type PerformanceSettingEntry = {
  name: string;
  key: string;
  category: string;
  group?: string;
  scope?: "runtime" | "deployment" | "read_only";
  description: string;
  value_type?: string;
  min?: number;
  max?: number;
  current_value: unknown;
  pending_value: unknown;
  effective_value: unknown;
  requires_restart: string;
  requires_restart_services?: string[];
  editable?: boolean;
  applies_immediately: boolean;
};

export type PerformanceState = {
  profile: "safe" | "balanced" | "performance" | "max" | "custom";
  effective_settings: Record<string, unknown>;
  pending_settings: Record<string, unknown>;
  requires_restart: string[];
  restart_supported?: boolean;
  restart_method?: "manual" | string;
  services_to_restart?: string[];
  restart_instructions?: {
    title: string;
    description: string;
    commands: Array<{ label: string; command: string }>;
    notes: string[];
  };
  system: {
    cpu_count: number;
    cpu_count_host?: number | null;
    cpu_count_container?: number | null;
    cpu_percent: number;
    memory_total_bytes: number;
    memory_available_bytes: number;
    memory_container_limit_bytes?: number | null;
    memory_used_percent: number;
    disk_total_bytes: number;
    disk_free_bytes: number;
    disk_used_percent: number;
    disk_status?: "healthy" | "degraded" | "critical" | string;
    disk_warning_threshold_percent?: number;
    disk_critical_threshold_percent?: number;
    storage_used_bytes: number;
    warnings: string[];
    allowed_roots: string[];
    allow_host_path_import: boolean;
  };
  evidence_storage?: StorageCapabilities;
  deployment?: {
    restart_enabled: boolean;
    can_edit_deployment_settings: boolean;
    restart_commands: string[];
    restart_supported?: boolean;
    restart_method?: "manual" | string;
    services_to_restart?: string[];
    restart_instructions?: {
      title: string;
      description: string;
      commands: Array<{ label: string; command: string }>;
      notes: string[];
    };
    pending_changes: Array<{
      name: string;
      key: string;
      old_value: unknown;
      new_value: unknown;
      scope: string;
      status: string;
      requires_restart_services: string[];
      diagnostic?: {
        setting_key: string;
        setting_name: string;
        current_value: unknown;
        expected_value: unknown;
        affected_services: string[];
        change_location?: {
          type: string;
          path: string;
          variable?: string | null;
          compose_reference?: string | null;
        };
        reason?: string;
        steps?: string[];
        commands?: string[];
      };
    }>;
  };
  services: {
    backend: Record<string, unknown>;
    worker: Record<string, unknown>;
    frontend: Record<string, unknown>;
    opensearch: Record<string, unknown>;
    queues: Record<string, { queued: number; started: number; failed: number; finished: number }>;
  };
  resources?: {
    cpu_count_host: number | null;
    cpu_count_container: number | null;
    effective_cpu_count?: number | null;
    memory_total: number | null;
    memory_host_total?: number | null;
    memory_visible_total?: number | null;
    memory_available: number | null;
    memory_container_limit: number | null;
    memory_limit_source?: string | null;
    memory_explanation?: string | null;
    disk_free: number | null;
    disk_status?: "healthy" | "degraded" | "critical" | string;
    disk_used_percent?: number | null;
    opensearch_health: string | null;
    opensearch_heap_percent: number | null;
    opensearch_disk_watermark: Record<string, unknown> | null;
    opensearch_write_blocked?: boolean | null;
    opensearch_ingest_writable?: boolean | null;
    opensearch_watermark_risk?: "low" | "medium" | "high" | "unknown" | string;
    redis_queue_status: Record<string, { queued: number; started: number; failed: number; finished: number }>;
    active_workers: number | null;
    worker_queues: Record<string, string[]>;
    current_concurrency: Record<string, unknown> & {
      desired_ingest_parallelism?: number | null;
      effective_ingest_parallelism?: number | null;
      ingest_parallelism_reason?: string | null;
      ingest_parallelism?: number | null;
    };
    current_profile: string;
    warnings: string[];
  };
  queue_architecture?: {
    current_worker_queues: Record<string, string[]>;
    recommended_workers: string[];
    recommended_queues: string[];
    mode: string;
  };
  settings: PerformanceSettingEntry[];
  profiles: Record<string, Record<string, unknown>>;
  recommendation: {
    recommended_profile: "safe" | "balanced" | "performance" | "max";
    reasons: string[];
    warnings: string[];
    estimated_changes?: Record<string, unknown>;
  };
};

export type PerformancePatchResponse = {
  saved: boolean;
  profile: "safe" | "balanced" | "performance" | "max" | "custom";
  updated: string[];
  runtime_applied: string[];
  requires_restart: string[];
  applied_now?: string[];
  pending_restart?: string[];
  services_to_restart?: string[];
  restart_supported?: boolean;
  restart_method?: "manual" | string;
  restart_instructions?: {
    title: string;
    description: string;
    commands: Array<{ label: string; command: string }>;
    notes: string[];
  };
  warnings: string[];
  effective_after_restart: PerformanceState;
};

export type PerformanceRestartResponse = {
  accepted: boolean;
  services: string[];
  restart_enabled: boolean;
  message: string;
  restart_supported?: boolean;
  restart_method?: "manual" | string;
  services_to_restart?: string[];
  restart_instructions?: {
    title: string;
    description: string;
    commands: Array<{ label: string; command: string }>;
    notes: string[];
  };
};

export type SystemSettingsResponse = {
  runtime: Record<string, unknown>;
  deployment: Record<string, unknown>;
  meta: Record<string, { category: string; description: string; requires_restart: boolean }>;
};

export type SystemSettingsPatchResponse = {
  updated: string[];
  requires_restart: string[];
  runtime_applied: string[];
  warnings: string[];
  settings: Record<string, unknown>;
};

export type InvestigationSummary = {
  total_events: number;
  event_count_info?: {
    count: number;
    relation: string;
    source: string;
  };
  counts: {
    detections: number;
    findings: number;
  };
  events_by_category: Record<string, number>;
  events_by_severity: Record<string, number>;
  top_hosts: Array<{ key: string; count: number }>;
  top_users: Array<{ key: string; count: number }>;
  top_processes: Array<{ key: string; count: number }>;
  top_executables: Array<{ key: string; count: number }>;
  top_powershell_commands: number;
  top_domains: Array<{ key: string; count: number }>;
  top_source_ips: Array<{ key: string; count: number }>;
  top_destination_ips: Array<{ key: string; count: number }>;
  service_install_events: number;
  scheduled_task_events: number;
  failed_logons: number;
  successful_logons: number;
  rdp_events: number;
  deleted_files: number;
  suspicious_events: number;
  detections_count: number;
  findings_count: number;
  recent_high_severity_events: Record<string, unknown>[];
  suspicious_process_events: Record<string, unknown>[];
  persistence_events: Record<string, unknown>[];
  deleted_file_events: Record<string, unknown>[];
  powershell_events: Record<string, unknown>[];
};

export type SemiAutoActivity = {
  id: string;
  activity_type: string;
  title: string;
  timestamp: string | null;
  host: string | null;
  user: string | null;
  summary: string;
  severity: string;
  confidence: number;
  tags: string[];
  key_fields: Record<string, unknown>;
  evidence_refs: string[];
  related_events: string[];
  suspicious_reasons: string[];
};

export type SemiAutoAnalysis = {
  case_id: string;
  generated_at: string;
  time_range?: {
    from: string | null;
    to: string | null;
  };
  summary: {
    [key: string]: number | undefined;
    total_events: number;
    total_activities: number;
    program_executions: number;
    powershell_executions: number;
    downloads: number;
    deleted_files: number;
    services_created: number;
    scheduled_tasks_created: number;
    logons: number;
    rdp_sessions: number;
    defender_detections: number;
    detected_downloads?: number;
    detected_executions?: number;
    quarantined_items?: number;
    remediation_failures?: number;
    suspicious_findings: number;
    account_changes?: number;
    anti_forensics?: number;
    usb_devices?: number;
    user_activity?: number;
  };
  sections: Record<string, SemiAutoActivity[]>;
};

export type SemiAutoAnalysisStatus = {
  id?: string;
  status: "idle" | "queued" | "running" | "completed" | "failed" | "cancelled";
  progress_pct: number;
  current_phase: string | null;
  phases: string[];
  parameters: {
    time_from?: string | null;
    time_to?: string | null;
  };
  metrics: Record<string, unknown>;
  result: SemiAutoAnalysis | null;
  error_message: string | null;
  cancel_requested: boolean;
  job_id: string | null;
  started_at: string | null;
  finished_at: string | null;
  created_at: string | null;
  updated_at: string | null;
};

export type DebugExportRequest = {
  scope: "case" | "evidence" | "selected_events" | "search" | "artifact_type" | "semiauto";
  evidence_id?: string | null;
  event_ids?: string[];
  artifact_types?: string[];
  include_raw_samples?: boolean;
  include_raw_xml?: boolean;
  include_source_paths?: boolean;
  include_full_raw?: boolean;
  max_events_per_type?: number;
  max_field_length?: number;
  redact_secrets?: boolean;
  include_cached_semiauto?: boolean;
  rebuild_semiauto_for_export?: boolean;
  ui_context?: Record<string, unknown>;
  search_request?: Record<string, unknown>;
};

export type MemoryArtifactList = {
  document_type: string;
  selected_run: string | null;
  total: number;
  page: number;
  page_size: number;
  items: Array<Record<string, unknown> & { document_id: string }>;
  facets: Record<string, unknown>;
  normalization_version: string;
};

export type MemoryArtifactOverview = {
  case_id: string;
  selected_run: string | null;
  run_status: string | null;
  profile: string | null;
  evidence_id: string | null;
  network_connections: {
    count: number;
    active_run: MemoryActiveRun | null;
    analysis_state: MemoryFamilyState;
  };
  process_modules: {
    count: number;
    active_run: MemoryActiveRun | null;
    analysis_state: MemoryFamilyState;
  };
  module_discrepancies: number;
  kernel_modules: {
    count: number;
    active_run: MemoryActiveRun | null;
    analysis_state: MemoryFamilyState;
  };
  drivers: {
    count: number;
    active_run: MemoryActiveRun | null;
    analysis_state: MemoryFamilyState;
  };
  handles: {
    count: number;
    active_run: MemoryActiveRun | null;
    analysis_state: MemoryFamilyState;
  };
  suspicious_regions: {
    count: number;
    active_run: MemoryActiveRun | null;
    analysis_state: MemoryFamilyState;
  };
  facets: Record<string, unknown>;
  normalization_version: string;
};

export type MemoryArtifactDetail = {
  document_type: string;
  document_id: string;
  fields: Record<string, unknown>;
  provenance: Record<string, unknown>;
};

// ---------------------------------------------------------------------------
// Experimental Mismatched-Symbol Analysis v1 — types
// ---------------------------------------------------------------------------

export type ExperimentalIdentity = {
  pdb_name: string;
  pdb_guid: string;
  pdb_age: number;
  architecture: string;
};

export type ExperimentalTrustState = {
  enabled: boolean;
  has_active_candidate: boolean;
  has_active_run: boolean;
  run_id: string | null;
  run_status: string | null;
  canary_status: string | null;
  last_completed_at: string | null;
};

export type ExperimentalWarning = {
  warning_version: string;
  warning_text: string;
  checkbox_text: string;
  required_fields: string[];
};

export type ExperimentalCandidate = {
  id: string;
  case_id: string;
  evidence_id: string;
  requirement_id: string;
  cached_symbol_id: string;
  required_identity: ExperimentalIdentity;
  observed_identity: ExperimentalIdentity;
  symbol_match_type: string;
  symbol_warning: string;
  provenance_source_type: string;
  provenance_source_name: string;
  provenance_actor: string;
  pdb_sha256: string;
  isf_sha256: string;
  isf_validation_status: string;
  created_at: string | null;
  revoked_at: string | null;
  revoked_by: string | null;
  revocation_reason: string | null;
};

export type ExperimentalRun = {
  id: string;
  case_id: string;
  evidence_id: string;
  candidate_id: string;
  requirement_id: string;
  cached_symbol_id: string;
  status: string;
  acknowledgement: {
    actor: string | null;
    actor_trust?: string | null;
    acknowledged_at: string | null;
    warning_version: string | null;
    required_identity: ExperimentalIdentity | null;
    observed_identity: ExperimentalIdentity | null;
  };
  canary: {
    status: string;
    score: number | null;
    checks: Array<{ name: string; status: string; detail: string; value?: unknown }>;
    summary: Record<string, unknown>;
    started_at: string | null;
    completed_at: string | null;
    override_required: boolean;
    override_at: string | null;
    override_actor: string | null;
    override_reason: string | null;
  };
  requested_profiles: string[];
  canary_profiles: string[];
  allowed_profiles: string[];
  canary_profile: string;
  canary_plugins: string[];
  profiles_queued: number;
  profiles_completed: number;
  profiles_failed: number;
  profiles_cancelled: number;
  started_at: string | null;
  completed_at: string | null;
  cancelled_at: string | null;
  cancelled_by: string | null;
  cancellation_reason: string | null;
  deleted_at: string | null;
  deleted_by: string | null;
  deletion_reason: string | null;
  created_at: string | null;
  updated_at: string | null;
};

export type ExperimentalRunArtifacts = {
  items: Array<Record<string, unknown>>;
  total: number;
  page: number;
  page_size: number;
  run_status?: string;
  trust_level?: string;
  error?: string;
};

export type ExperimentalExportPayload = {
  warning: string;
  warning_full_text: string;
  trust_level: string;
  run_id: string;
  case_id: string;
  evidence_id: string;
  required_identity: ExperimentalIdentity | null;
  observed_identity: ExperimentalIdentity | null;
  canary: ExperimentalRun["canary"];
  status: string;
  items: Array<Record<string, unknown>>;
  total: number;
};

function buildArtifactQuery(path: string, params: Record<string, unknown> | undefined): string {
  const query = new URLSearchParams();
  if (!params) return path;
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") continue;
    query.set(key, String(value));
  }
  return query.size ? `${path}?${query.toString()}` : path;
}

export const api = {
  listCases: () => request<DfirCase[]>("/cases"),
  createCase: (payload: Partial<DfirCase>) => request<DfirCase>("/cases", { method: "POST", body: JSON.stringify(payload) }),
  getCase: (caseId: string) => request<DfirCase>(`/cases/${caseId}`),
  getCaseContext: (caseId: string) => request<CaseContextResponse>(`/cases/${caseId}/context`),
  getValidationMatrix: (
    caseId: string,
    params?: { host?: string; phase?: string; result?: string; source_part?: string; memory_required?: boolean | null },
  ) => {
    const query = new URLSearchParams();
    if (params?.host) query.set("host", params.host);
    if (params?.phase) query.set("phase", params.phase);
    if (params?.result) query.set("result", params.result);
    if (params?.source_part) query.set("source_part", params.source_part);
    if (params?.memory_required !== undefined && params.memory_required !== null) query.set("memory_required", String(params.memory_required));
    return request<ValidationMatrixResponse>(`/cases/${caseId}/validation-matrix${query.size ? `?${query.toString()}` : ""}`);
  },
  exportValidationMatrixMarkdown: async (caseId: string) => {
    const response = await apiFetch(`/cases/${caseId}/validation-matrix/export`);
    if (!response.ok) {
      const body = await response.text();
      throw new Error(body || `HTTP ${response.status}`);
    }
    return {
      blob: await response.blob(),
      filename: extractDownloadFilename(response.headers.get("content-disposition"), `validation-matrix-${caseId}.md`),
    };
  },
  getCaseHosts: (caseId: string) => request<CaseHostsResponse>(`/cases/${caseId}/hosts`),
  mergeCaseHosts: (caseId: string, payload: { canonical_host_id: string; aliases: string[]; reason?: string | null; analyst?: string | null }) =>
    request<{ case_id: string; host: CaseContextHostSummary }>(`/cases/${caseId}/hosts/merge`, { method: "POST", body: JSON.stringify(payload) }),
  renameCaseHost: (caseId: string, hostId: string, payload: { display_name?: string | null; canonical_name?: string | null; reason?: string | null; analyst?: string | null }) =>
    request<{ case_id: string; host: CaseContextHostSummary }>(`/cases/${caseId}/hosts/${hostId}`, { method: "PATCH", body: JSON.stringify(payload) }),
  splitCaseHostAlias: (caseId: string, hostId: string, aliasId: string, params?: { reason?: string; analyst?: string }) => {
    const search = new URLSearchParams();
    if (params?.reason) search.set("reason", params.reason);
    if (params?.analyst) search.set("analyst", params.analyst);
    const suffix = search.toString() ? `?${search.toString()}` : "";
    return request<{ case_id: string; detached_host: CaseContextHostSummary; source_host_id: string }>(`/cases/${caseId}/hosts/${hostId}/aliases/${aliasId}${suffix}`, { method: "DELETE" });
  },
  getCaseHostAudit: (caseId: string) => request<CaseHostAuditResponse>(`/cases/${caseId}/hosts/audit`),
  updateCase: (caseId: string, payload: Partial<DfirCase>) => request<DfirCase>(`/cases/${caseId}`, { method: "PATCH", body: JSON.stringify(payload) }),
  deleteCase: (caseId: string) => request<void>(`/cases/${caseId}`, { method: "DELETE" }),
  getInvestigationSummary: (caseId: string) => request<InvestigationSummary>(`/cases/${caseId}/investigation-summary`),
  getSemiAutoAnalysis: (caseId: string, options?: { time_from?: string; time_to?: string }) => {
    const query = new URLSearchParams();
    if (options?.time_from) query.append("time_from", options.time_from);
    if (options?.time_to) query.append("time_to", options.time_to);
    return request<SemiAutoAnalysis>(`/cases/${caseId}/analysis/semi-auto${query.size ? `?${query.toString()}` : ""}`);
  },
  getSemiAutoAnalysisStatus: (caseId: string, options?: { time_from?: string; time_to?: string }) => {
    const query = new URLSearchParams();
    if (options?.time_from) query.append("time_from", options.time_from);
    if (options?.time_to) query.append("time_to", options.time_to);
    return request<SemiAutoAnalysisStatus>(`/cases/${caseId}/analysis/semi-auto/status${query.size ? `?${query.toString()}` : ""}`);
  },
  startSemiAutoAnalysis: (caseId: string, options?: { time_from?: string; time_to?: string }) => {
    const query = new URLSearchParams();
    if (options?.time_from) query.append("time_from", options.time_from);
    if (options?.time_to) query.append("time_to", options.time_to);
    return request<SemiAutoAnalysisStatus>(`/cases/${caseId}/analysis/semi-auto/start${query.size ? `?${query.toString()}` : ""}`, { method: "POST" });
  },
  stopSemiAutoAnalysis: (caseId: string, options?: { time_from?: string; time_to?: string }) => {
    const query = new URLSearchParams();
    if (options?.time_from) query.append("time_from", options.time_from);
    if (options?.time_to) query.append("time_to", options.time_to);
    return request<SemiAutoAnalysisStatus>(`/cases/${caseId}/analysis/semi-auto/stop${query.size ? `?${query.toString()}` : ""}`, { method: "POST" });
  },
  exportSemiAutoAnalysisMarkdown: async (caseId: string, options?: { time_from?: string; time_to?: string }) => {
    const query = new URLSearchParams();
    if (options?.time_from) query.append("time_from", options.time_from);
    if (options?.time_to) query.append("time_to", options.time_to);
    const response = await apiFetch(`/cases/${caseId}/analysis/semi-auto/export-markdown${query.size ? `?${query.toString()}` : ""}`);
    if (!response.ok) {
      const body = await response.text();
      throw new Error(body || `HTTP ${response.status}`);
    }
    return { blob: await response.blob(), filename: response.headers.get("content-disposition") ?? "" };
  },
  exportSemiAutoAnalysisPdf: async (caseId: string, options?: { time_from?: string; time_to?: string }) => {
    const query = new URLSearchParams();
    if (options?.time_from) query.append("time_from", options.time_from);
    if (options?.time_to) query.append("time_to", options.time_to);
    const response = await apiFetch(`/cases/${caseId}/analysis/semi-auto/export-pdf${query.size ? `?${query.toString()}` : ""}`);
    if (!response.ok) {
      const body = await response.text();
      throw new Error(body || `HTTP ${response.status}`);
    }
    return { blob: await response.blob(), filename: response.headers.get("content-disposition") ?? "" };
  },
  exportDebugPack: async (caseId: string, payload: DebugExportRequest) => {
    const response = await apiFetch(`/cases/${caseId}/debug-export`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      const body = await response.text();
      throw new Error(body || `HTTP ${response.status}`);
    }
    return { blob: await response.blob(), filename: response.headers.get("content-disposition") ?? "" };
  },
  buildDebugPackDownloadUrl: (caseId: string, payload: DebugExportRequest) => {
    const query = new URLSearchParams();
    query.set("scope", payload.scope);
    if (payload.evidence_id) query.set("evidence_id", payload.evidence_id);
    if (payload.artifact_types?.length) query.set("artifact_types", payload.artifact_types.join(","));
    query.set("include_raw_samples", String(payload.include_raw_samples ?? false));
    query.set("include_raw_xml", String(payload.include_raw_xml ?? false));
    query.set("include_source_paths", String(payload.include_source_paths ?? true));
    query.set("include_full_raw", String(payload.include_full_raw ?? false));
    query.set("max_events_per_type", String(payload.max_events_per_type ?? 25));
    query.set("max_field_length", String(payload.max_field_length ?? 2000));
    query.set("redact_secrets", String(payload.redact_secrets ?? true));
    query.set("include_cached_semiauto", String(payload.include_cached_semiauto ?? true));
    query.set("rebuild_semiauto_for_export", String(payload.rebuild_semiauto_for_export ?? false));
    if (payload.ui_context && Object.keys(payload.ui_context).length) {
      query.set("ui_context_json", JSON.stringify(payload.ui_context));
    }
    return buildApiUrl(`/cases/${caseId}/debug-export/download?${query.toString()}`);
  },
  listDocs: () => request<DocEntry[]>("/docs"),
  getDoc: (slug: string) => request<DocPage>(`/docs/${slug}`),
  listEvidences: (caseId: string) => request<Evidence[]>(`/cases/${caseId}/evidences`),
  getMemoryBackendOverview: () => request<MemoryBackendOverview>("/memory/backends"),
  getMemoryOverview: (caseId: string) => request<MemoryOverview>(`/cases/${caseId}/memory`),
  getMemoryUploadReadiness: (caseId: string, selectedSizeBytes?: number) => {
    const query = selectedSizeBytes && selectedSizeBytes > 0 ? `?selected_size_bytes=${encodeURIComponent(String(selectedSizeBytes))}` : "";
    return request<MemoryUploadReadiness>(`/cases/${caseId}/memory/upload-readiness${query}`);
  },
  getMemoryUploadStatus: (caseId: string, uploadId: string) => request<MemoryUploadStatus>(`/cases/${caseId}/memory/uploads/${uploadId}`),
  createMemoryUploadSession: (caseId: string, payload: MemoryUploadSessionCreateRequest) =>
    request<MemoryUploadStatus>(`/cases/${caseId}/memory/uploads`, { method: "POST", body: JSON.stringify(payload) }),
  uploadMemoryUploadChunk: (
    caseId: string,
    uploadId: string,
    chunkIndex: number,
    blob: Blob,
    options?: { chunkSha256?: string; onProgress?: (progress: UploadProgress) => void; signal?: AbortSignal },
  ) =>
    uploadBlob<MemoryUploadStatus>(`/cases/${caseId}/memory/uploads/${uploadId}/chunks/${chunkIndex}`, blob, {
      method: "PUT",
      contentType: "application/octet-stream",
      headers: options?.chunkSha256 ? { "X-Kairon-Chunk-SHA256": options.chunkSha256 } : undefined,
      onProgress: options?.onProgress,
      signal: options?.signal,
    }),
  finalizeMemoryUpload: (caseId: string, uploadId: string, payload?: { expected_sha256?: string }) =>
    request<MemoryUploadStatus>(`/cases/${caseId}/memory/uploads/${uploadId}/finalize`, { method: "POST", body: JSON.stringify(payload ?? {}) }),
  reconcileMemoryUpload: (caseId: string, uploadId: string) => request<MemoryUploadStatus>(`/cases/${caseId}/memory/uploads/${uploadId}/reconcile`, { method: "POST" }),
  retryMemoryUploadRegistration: (caseId: string, uploadId: string) =>
    request<MemoryUploadStatus>(`/cases/${caseId}/memory/uploads/${uploadId}/retry-registration`, { method: "POST" }),
  reconcileCaseMemoryUploads: (caseId: string) =>
    request<{ case_id: string; scanned: number; requeued: number; skipped_terminal: number; skipped_inconsistent: number }>(
      `/cases/${caseId}/memory/uploads/reconcile`,
      { method: "POST" },
    ),
  cancelMemoryUpload: (caseId: string, uploadId: string, reason: string) =>
    request<MemoryUploadStatus>(`/cases/${caseId}/memory/uploads/${uploadId}/cancel`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    }),
  getActiveMemoryUpload: (caseId: string) =>
    request<MemoryUploadStatus | null>(`/cases/${caseId}/memory/uploads/active`),
  listMemoryEvidences: (caseId: string) => request<MemoryEvidence[]>(`/cases/${caseId}/memory/evidences`),
  getMemoryEvidenceReadiness: (caseId: string, evidenceId: string) => request<MemoryEvidenceReadiness>(`/cases/${caseId}/memory/evidences/${evidenceId}/readiness`),
  getMemoryEvidenceDiagnostics: (caseId: string, evidenceId: string) =>
    request<{
      case_id: string;
      evidence_id: string;
      file_present: boolean;
      file_size: number;
      expected_size: number;
      size_match: boolean;
      hash_recorded: boolean;
      evidence_registered: boolean;
      worker_ready: boolean;
      worker_online: boolean;
      volatility_executable: boolean;
      volatility_version: string | null;
      cache_readable: boolean;
      last_run_status: string | null;
      last_error_stage: string | null;
      auto_preparation: boolean;
      auto_symbol_probe: boolean;
      auto_symbol_acquire: boolean;
      run_all_enabled: boolean;
    }>(`/cases/${caseId}/memory/evidences/${evidenceId}/diagnostics`),
  repairPreservedMemoryUploads: (caseId: string, dryRun: boolean) =>
    request<Array<Record<string, unknown>>>(`/cases/${caseId}/memory/uploads/repair`, {
      method: "POST",
      body: JSON.stringify({ dry_run: dryRun }),
    }),
  getMemorySymbolCacheStatus: () => request<MemorySymbolCacheStatus>("/memory/symbols/cache"),
  requestMemorySymbolAcquisition: (caseId: string, evidenceId: string, authorizationAcknowledged = false) =>
    request<MemorySymbolRequestCreateResponse>(`/cases/${caseId}/memory/evidences/${evidenceId}/symbols/request`, {
      method: "POST",
      body: JSON.stringify({ authorization_acknowledged: authorizationAcknowledged }),
    }),
  getMemorySymbolRequest: (requestId: string) => request<MemorySymbolRequestStatus>(`/memory/symbols/requests/${requestId}`),
  getMemorySymbolReadiness: (caseId: string, evidenceId: string) =>
    request<MemorySymbolReadiness>(`/cases/${caseId}/memory/evidences/${evidenceId}/symbol-readiness`),
  getMemorySymbolPreparation: (caseId: string, evidenceId: string) =>
    request<MemorySymbolPreparation>(`/cases/${caseId}/memory/evidences/${evidenceId}/symbol-preparation`),
  startNativeProbe: (caseId: string, evidenceId: string) =>
    request<{ probe_id: string; status: string; plugin: string; requirement_id: string }>(
      `/cases/${caseId}/memory/evidences/${evidenceId}/native-probe`,
      { method: "POST", body: JSON.stringify({}) },
    ),
  getNativeProbeStatus: (caseId: string, evidenceId: string) =>
    request<Record<string, unknown>>(
      `/cases/${caseId}/memory/evidences/${evidenceId}/native-probe`,
    ),
  retryMemorySymbolPreparation: (caseId: string, evidenceId: string) =>
    request<MemorySymbolPreparation>(
      `/cases/${caseId}/memory/evidences/${evidenceId}/symbol-preparation/retry`,
      { method: "POST" },
    ),
  // Sprint 6: OS-agnostic preparation.
  getMemoryPreparationDiagnostics: (caseId: string, evidenceId: string) =>
    request<Record<string, unknown>>(
      `/cases/${caseId}/memory/evidences/${evidenceId}/preparation/diagnostics`,
    ),
  retryMemoryPreparation: (caseId: string, evidenceId: string) =>
    request<Record<string, unknown>>(
      `/cases/${caseId}/memory/evidences/${evidenceId}/preparation/retry`,
      { method: "POST" },
    ),
  directMemoryProbe: (caseId: string, evidenceId: string) =>
    request<{ accepted: boolean; scan_run_id: string; task_id: string }>(
      `/cases/${caseId}/memory/evidences/${evidenceId}/direct-probe`,
      { method: "POST" },
    ),
  reconcileMemorySymbols: (caseId: string) =>
    request<{ stats: Record<string, number> }>(`/cases/${caseId}/memory/symbol-reconcile`, {
      method: "POST",
    }),
  runMemoryAnalysisWhenReady: (caseId: string, evidenceId: string, payload: MemoryRunWhenReadyRequest) =>
    request<MemoryRunWhenReadyResponse>(`/cases/${caseId}/memory/evidences/${evidenceId}/run-when-ready`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  cancelMemoryRunWhenReady: (caseId: string, evidenceId: string) =>
    request<{ cancelled: number }>(`/cases/${caseId}/memory/evidences/${evidenceId}/run-when-ready/cancel`, {
      method: "POST",
    }),
  probeMemorySymbolRequirement: (caseId: string, evidenceId: string) =>
    request<MemorySymbolProbeResult>(`/cases/${caseId}/memory/evidences/${evidenceId}/symbol-probe`, {
      method: "POST",
    }),
  acquireMemorySymbols: (caseId: string, evidenceId: string) =>
    request<MemorySymbolAcquireResponse>(`/cases/${caseId}/memory/evidences/${evidenceId}/symbols/acquire`, {
      method: "POST",
      body: JSON.stringify({ authorization_acknowledged: true }),
    }),
  acquireExactMemorySymbols: (caseId: string, evidenceId: string) =>
    request<MemorySymbolBlockedAcquireResponse>(
      `/cases/${caseId}/memory/evidences/${evidenceId}/symbols/acquire-managed`,
      { method: "POST", body: JSON.stringify({ authorization_acknowledged: true }) },
    ),
  getMemorySymbolAcquisition: (caseId: string, evidenceId: string) =>
    request<MemorySymbolBlockedAcquireResponse>(
      `/cases/${caseId}/memory/evidences/${evidenceId}/symbols/acquisition`,
    ),
  // Experimental Mismatched-Symbol Analysis v1
  getExperimentalTrust: (caseId: string, evidenceId: string) =>
    request<ExperimentalTrustState>(
      `/cases/${caseId}/memory/evidences/${evidenceId}/experimental-trust`,
    ),
  getExperimentalWarning: (caseId: string, evidenceId: string) =>
    request<ExperimentalWarning>(
      `/cases/${caseId}/memory/evidences/${evidenceId}/experimental-warning`,
    ),
  getExperimentalProfileCatalogue: (caseId: string, evidenceId: string) =>
    request<{
      canary_profile: string;
      canary_plugins: string[];
      profiles: Array<{
        profile: string;
        family: string;
        title: string;
        description: string;
        cost_label: string;
        est_duration_seconds: number;
        requires_canary_pass: boolean;
        plugins: string[];
        supported_os_families: string[];
      }>;
    }>(`/cases/${caseId}/memory/evidences/${evidenceId}/experimental-profile-catalogue`),
  listExperimentalCandidates: (caseId: string, evidenceId: string) =>
    request<{ items: ExperimentalCandidate[] }>(
      `/cases/${caseId}/memory/evidences/${evidenceId}/experimental-symbol-candidates`,
    ),
  registerExperimentalCandidate: (
    caseId: string,
    evidenceId: string,
      payload: {
        cached_symbol_id: string;
        source_host_path?: string;
        actor: string;
      },
  ) =>
    request<ExperimentalCandidate>(
      `/cases/${caseId}/memory/evidences/${evidenceId}/experimental-symbol-candidates`,
      { method: "POST", body: JSON.stringify(payload) },
    ),
  revokeExperimentalCandidate: (
    caseId: string,
    evidenceId: string,
    candidateId: string,
    payload: { client_actor_label?: string; reason: string },
  ) =>
    request<ExperimentalCandidate>(
      `/cases/${caseId}/memory/evidences/${evidenceId}/experimental-symbol-candidates/${candidateId}/revoke`,
      { method: "POST", body: JSON.stringify(payload) },
    ),
  listExperimentalRuns: (
    caseId: string,
    evidenceId: string,
    includeDeleted = false,
  ) =>
    request<{ items: ExperimentalRun[] }>(
      `/cases/${caseId}/memory/evidences/${evidenceId}/experimental-runs${
        includeDeleted ? "?include_deleted=true" : ""
      }`,
    ),
  createExperimentalRun: (
    caseId: string,
    evidenceId: string,
    payload: { requested_profiles?: string[] },
  ) =>
    request<ExperimentalRun>(
      `/cases/${caseId}/memory/evidences/${evidenceId}/experimental-runs`,
      { method: "POST", body: JSON.stringify(payload) },
    ),
  getExperimentalRun: (caseId: string, evidenceId: string, runId: string) =>
    request<ExperimentalRun>(
      `/cases/${caseId}/memory/evidences/${evidenceId}/experimental-runs/${runId}`,
    ),
  acknowledgeExperimentalRun: (
    caseId: string,
    evidenceId: string,
    runId: string,
    payload: Record<string, unknown>,
  ) =>
    request<ExperimentalRun>(
      `/cases/${caseId}/memory/evidences/${evidenceId}/experimental-runs/${runId}/acknowledge`,
      { method: "POST", body: JSON.stringify(payload) },
    ),
  startExperimentalCanary: (caseId: string, evidenceId: string, runId: string) =>
    request<ExperimentalRun>(
      `/cases/${caseId}/memory/evidences/${evidenceId}/experimental-runs/${runId}/start-canary`,
      { method: "POST", body: JSON.stringify({}) },
    ),
  overrideExperimentalCanary: (
    caseId: string,
    evidenceId: string,
    runId: string,
    payload: { client_actor_label?: string; reason: string },
  ) =>
    request<ExperimentalRun>(
      `/cases/${caseId}/memory/evidences/${evidenceId}/experimental-runs/${runId}/canary-override`,
      { method: "POST", body: JSON.stringify(payload) },
    ),
  continueExperimentalRun: (caseId: string, evidenceId: string, runId: string) =>
    request<ExperimentalRun>(
      `/cases/${caseId}/memory/evidences/${evidenceId}/experimental-runs/${runId}/continue`,
      { method: "POST", body: JSON.stringify({}) },
    ),
  cancelExperimentalRun: (
    caseId: string,
    evidenceId: string,
    runId: string,
    payload: { client_actor_label?: string; reason: string },
  ) =>
    request<ExperimentalRun>(
      `/cases/${caseId}/memory/evidences/${evidenceId}/experimental-runs/${runId}/cancel`,
      { method: "POST", body: JSON.stringify(payload) },
    ),
  finalizeExperimentalRun: (
    caseId: string,
    evidenceId: string,
    runId: string,
    outcome: string,
  ) =>
    request<ExperimentalRun>(
      `/cases/${caseId}/memory/evidences/${evidenceId}/experimental-runs/${runId}/finalize`,
      {
        method: "POST",
        body: JSON.stringify({ outcome }),
      },
    ),
  deleteExperimentalRun: (
    caseId: string,
    evidenceId: string,
    runId: string,
    payload: { client_actor_label?: string; reason: string },
  ) =>
    request<ExperimentalRun>(
      `/cases/${caseId}/memory/evidences/${evidenceId}/experimental-runs/${runId}`,
      { method: "DELETE", body: JSON.stringify(payload) },
    ),
  getExperimentalRunArtifacts: (
    caseId: string,
    evidenceId: string,
    runId: string,
    params: { document_type?: string; page?: number; page_size?: number } = {},
  ) => {
    const search = new URLSearchParams();
    if (params.document_type) search.set("document_type", params.document_type);
    if (params.page) search.set("page", String(params.page));
    if (params.page_size) search.set("page_size", String(params.page_size));
    const qs = search.toString();
    return request<ExperimentalRunArtifacts>(
      `/cases/${caseId}/memory/evidences/${evidenceId}/experimental-runs/${runId}/artifacts${
        qs ? `?${qs}` : ""
      }`,
    );
  },
  exportExperimentalRun: (
    caseId: string,
    evidenceId: string,
    runId: string,
  ) =>
    request<ExperimentalExportPayload>(
      `/cases/${caseId}/memory/evidences/${evidenceId}/experimental-runs/${runId}/export`,
    ),
  // Exact Symbol Recovery Sources v1
  listRecoverySources: () =>
    request<MemoryRecoverySourceRead[]>(
      "/admin/memory/symbols/recovery-sources",
    ),
  createRecoverySource: (payload: MemoryRecoverySourceCreate) =>
    request<MemoryRecoverySourceRead>(
      "/admin/memory/symbols/recovery-sources",
      {
        method: "POST",
        body: JSON.stringify(payload),
      },
    ),
  updateRecoverySource: (
    id: string,
    payload: MemoryRecoverySourceUpdate,
  ) =>
    request<MemoryRecoverySourceRead>(
      `/admin/memory/symbols/recovery-sources/${id}`,
      {
        method: "PATCH",
        body: JSON.stringify(payload),
      },
    ),
  deleteRecoverySource: (id: string) =>
    request<{ status: string }>(
      `/admin/memory/symbols/recovery-sources/${id}`,
      { method: "DELETE" },
    ),
  importPdb: (requirementId: string, file: File) => {
    const form = new FormData();
    form.append("file", file);
    return fetch(
      `/api/admin/memory/symbols/import-pdb?requirement_id=${encodeURIComponent(requirementId)}`,
      {
        method: "POST",
        body: form,
      },
    ).then((res) => res.json() as Promise<MemoryRecoveryResult>);
  },
  importIsf: (requirementId: string, file: File) => {
    const form = new FormData();
    form.append("file", file);
    return fetch(
      `/api/admin/memory/symbols/import-isf?requirement_id=${encodeURIComponent(requirementId)}`,
      {
        method: "POST",
        body: form,
      },
    ).then((res) => res.json() as Promise<MemoryRecoveryResult>);
  },
  importPackage: (file: File) => {
    const form = new FormData();
    form.append("file", file);
    return fetch(
      "/api/admin/memory/symbols/import-package",
      { method: "POST", body: form },
    ).then((res) => res.json() as Promise<MemoryRecoveryResult>);
  },
  recoverSymbol: (requirementId: string) =>
    request<MemoryRecoveryResult>(
      `/admin/memory/symbols/recover/${requirementId}`,
      { method: "POST" },
    ),
  listRecoveryAttempts: (requirementId: string) =>
    request<MemoryRecoveryAttempt[]>(
      `/admin/memory/symbols/attempts/${requirementId}`,
    ),
  listMemoryRuns: (caseId: string, evidenceId?: string) => {
    const query = evidenceId ? `?evidence_id=${encodeURIComponent(evidenceId)}` : "";
    return request<MemoryScanRun[]>(`/cases/${caseId}/memory/runs${query}`);
  },
  getMemoryEvidenceLanding: (caseId: string) => request<MemoryEvidenceLanding>(`/cases/${caseId}/memory/landing`),
  getMemoryActiveResult: (
    caseId: string,
    evidenceId: string,
    family: string,
    runId?: string,
    filters?: {
      protocol?: string;
      local_address?: string;
      local_port?: number;
      remote_address?: string;
      remote_port?: number;
      state?: string;
      pid?: number;
      process_name?: string;
      module_name?: string;
      path?: string;
      load_state?: string;
      object_type?: string;
      object_name?: string;
      page?: number;
      page_size?: number;
    },
  ) => {
    const query = new URLSearchParams();
    query.set("family", family);
    if (runId) query.set("run_id", runId);
    if (filters) {
      for (const [key, value] of Object.entries(filters)) {
        if (value !== undefined && value !== null && value !== "") {
          query.set(key, String(value));
        }
      }
    }
    return request<MemoryActiveResult>(`/cases/${caseId}/memory/evidences/${evidenceId}/active-result?${query.toString()}`);
  },
  getMemoryAnalysisCatalogue: (caseId: string, evidenceId: string) =>
    request<MemoryAnalysisCatalogue>(`/cases/${caseId}/memory/evidences/${evidenceId}/catalogue`),
  previewMemoryRunAll: (caseId: string, evidenceId: string, mode: MemoryRunAllMode) =>
    request<MemoryRunAllPlan>(`/cases/${caseId}/memory/evidences/${evidenceId}/run-all/preview?mode=${mode}`),
  startMemoryRunAll: (caseId: string, evidenceId: string, payload: { mode: MemoryRunAllMode; authorization_acknowledged: boolean; continue_on_failure?: boolean }) =>
    request<MemoryAnalysisBatch>(`/cases/${caseId}/memory/evidences/${evidenceId}/run-all`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  getMemoryAnalysisBatch: (caseId: string, evidenceId: string, batchId: string) =>
    request<MemoryAnalysisBatch>(`/cases/${caseId}/memory/evidences/${evidenceId}/analysis-batches/${batchId}`),
  getActiveMemoryAnalysisBatch: (caseId: string, evidenceId: string) =>
    request<MemoryAnalysisBatch>(`/cases/${caseId}/memory/evidences/${evidenceId}/analysis-batches/active`),
  cancelMemoryAnalysisBatch: (caseId: string, evidenceId: string, batchId: string) =>
    request<MemoryAnalysisBatch>(`/cases/${caseId}/memory/evidences/${evidenceId}/analysis-batches/${batchId}/cancel`, {
      method: "POST",
    }),
  startMemoryScan: (caseId: string, evidenceId: string, profile: "metadata_only" | "processes_basic" | "processes_extended" = "metadata_only", authorizationAcknowledged = false) =>
    request<MemoryStartScanResponse>(`/evidences/${evidenceId}/memory/scan?case_id=${encodeURIComponent(caseId)}`, { method: "POST", body: JSON.stringify({ profile, authorization_acknowledged: authorizationAcknowledged }) }),
  getMemoryRun: (runId: string) => request<MemoryRunDetail>(`/memory/runs/${runId}`),
  getMemoryRunSystemInfo: (runId: string) => request<MemorySystemInfo>(`/memory/runs/${runId}/system-info`),
  getCaseMemorySystemInfo: (caseId: string) => request<MemorySystemInfo[]>(`/cases/${caseId}/memory/system-info`),
  getEvidenceMemorySystemInfo: (caseId: string, evidenceId: string) => request<MemorySystemInfo[]>(`/cases/${caseId}/memory/evidences/${evidenceId}/system-info`),
  getCaseMemoryProcesses: (caseId: string, params?: { run_id?: string; pid?: number; process_name?: string; source_plugin?: string; page?: number; page_size?: number }) => {
    const query = new URLSearchParams();
    if (params?.run_id) query.set("run_id", params.run_id);
    if (params?.pid !== undefined) query.set("pid", String(params.pid));
    if (params?.process_name) query.set("process_name", params.process_name);
    if (params?.source_plugin) query.set("source_plugin", params.source_plugin);
    if (params?.page) query.set("page", String(params.page));
    if (params?.page_size) query.set("page_size", String(params.page_size));
    return request<MemoryProcessList>(`/cases/${caseId}/memory/processes${query.size ? `?${query.toString()}` : ""}`);
  },
  getMemoryProcessTree: (runId: string) => request<MemoryProcessTree>(`/memory/runs/${runId}/process-tree`),
  getMemoryRunOptions: (caseId: string) => request<MemoryRunSelector>(`/cases/${caseId}/memory/runs/options`),
  getEvidenceMemoryRunOptions: (caseId: string, evidenceId: string) => request<MemoryRunSelector>(`/cases/${caseId}/memory/evidences/${evidenceId}/runs/options`),
  probeMemoryImage: (caseId: string, evidenceId: string) =>
    request<MemoryImageProbeResult>(
      `/cases/${caseId}/evidences/probe-memory-image?evidence_id=${encodeURIComponent(evidenceId)}`,
      { method: "POST" },
    ),
  confirmMemoryType: (caseId: string, evidenceId: string, reason: string) =>
    request<MemoryImageConfirmResult>(
      `/cases/${caseId}/evidences/${encodeURIComponent(evidenceId)}/confirm-memory-type`,
      { method: "POST", body: JSON.stringify({ reason, authorization_acknowledged: true }) },
    ),
  getCanonicalProcessEntities: (
    caseId: string,
    params?: {
      run_id?: string;
      evidence_id?: string;
      profile?: "processes_basic" | "processes_extended";
      visibility?: "listed" | "scan_only" | "terminated" | "unknown" | "hidden_candidate";
      source_plugin?: "windows.pslist" | "windows.psscan" | "windows.pstree" | "windows.cmdline";
      process_name?: string;
      pid?: number;
      ppid?: number;
      has_command_line?: boolean;
      interesting_only?: boolean;
      page?: number;
      page_size?: number;
    },
  ) => {
    const query = new URLSearchParams();
    if (params?.run_id) query.set("run_id", params.run_id);
    if (params?.evidence_id) query.set("evidence_id", params.evidence_id);
    if (params?.profile) query.set("profile", params.profile);
    if (params?.visibility) query.set("visibility", params.visibility);
    if (params?.source_plugin) query.set("source_plugin", params.source_plugin);
    if (params?.process_name) query.set("process_name", params.process_name);
    if (params?.pid !== undefined) query.set("pid", String(params.pid));
    if (params?.ppid !== undefined) query.set("ppid", String(params.ppid));
    if (params?.has_command_line !== undefined) query.set("has_command_line", String(params.has_command_line));
    if (params?.interesting_only !== undefined) query.set("interesting_only", String(params.interesting_only));
    if (params?.page) query.set("page", String(params.page));
    if (params?.page_size) query.set("page_size", String(params.page_size));
    return request<MemoryProcessEntityList>(`/cases/${caseId}/memory/process-entities${query.size ? `?${query.toString()}` : ""}`);
  },
  getCanonicalProcessEntityDetail: (caseId: string, entityId: string, runId?: string) => {
    const query = new URLSearchParams();
    if (runId) query.set("run_id", runId);
    return request<MemoryProcessEntityDetail>(`/cases/${caseId}/memory/process-entities/${entityId}${query.size ? `?${query.toString()}` : ""}`);
  },
  getCanonicalProcessSummary: (caseId: string, params?: { run_id?: string; profile?: "processes_basic" | "processes_extended" }) => {
    const query = new URLSearchParams();
    if (params?.run_id) query.set("run_id", params.run_id);
    if (params?.profile) query.set("profile", params.profile);
    return request<MemoryRenormalizeSummary>(`/cases/${caseId}/memory/process-entities/summary${query.size ? `?${query.toString()}` : ""}`);
  },
  getCanonicalProcessTree: (
    caseId: string,
    params?: {
      run_id?: string;
      profile?: "processes_basic" | "processes_extended";
      root_pid?: number;
      root_entity_id?: string;
      depth?: number;
      max_nodes?: number;
      visibility?: "listed" | "scan_only" | "terminated" | "unknown" | "hidden_candidate";
      interesting_only?: boolean;
      include_ancestors?: boolean;
      orphans_only?: boolean;
      search?: string;
    },
  ) => {
    const query = new URLSearchParams();
    if (params?.run_id) query.set("run_id", params.run_id);
    if (params?.profile) query.set("profile", params.profile);
    if (params?.root_pid !== undefined) query.set("root_pid", String(params.root_pid));
    if (params?.root_entity_id) query.set("root_entity_id", params.root_entity_id);
    if (params?.depth) query.set("depth", String(params.depth));
    if (params?.max_nodes) query.set("max_nodes", String(params.max_nodes));
    if (params?.visibility) query.set("visibility", params.visibility);
    if (params?.interesting_only !== undefined) query.set("interesting_only", String(params.interesting_only));
    if (params?.include_ancestors !== undefined) query.set("include_ancestors", String(params.include_ancestors));
    if (params?.orphans_only !== undefined) query.set("orphans_only", String(params.orphans_only));
    if (params?.search) query.set("search", params.search);
    return request<MemoryProcessTreeEntity>(`/cases/${caseId}/memory/process-tree-canonical${query.size ? `?${query.toString()}` : ""}`);
  },
  renormalizeProcessEntities: (caseId: string, evidenceId: string, runId: string, dryRun = true) =>
    request<MemoryRenormalizeSummary>(`/cases/${caseId}/memory/evidences/${evidenceId}/process-entities/renormalize`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ run_id: runId, dry_run: dryRun }),
    }),
  // Core memory artifact endpoints
  getMemoryArtifactOverview: (caseId: string, params?: { run_id?: string | null; evidence_id?: string }) => {
    const query = new URLSearchParams();
    if (params?.run_id) query.set("run_id", params.run_id);
    if (params?.evidence_id) query.set("evidence_id", params.evidence_id);
    return request<MemoryArtifactOverview>(`/cases/${caseId}/memory/artifacts/overview${query.size ? `?${query.toString()}` : ""}`);
  },
  getMemoryNetworkConnections: (
    caseId: string,
    params?: {
      evidence_id: string;
      run_id?: string;
      protocol?: string;
      local_address?: string;
      local_port?: number;
      remote_address?: string;
      remote_port?: number;
      state?: string;
      pid?: number;
      process_name?: string;
      page?: number;
      page_size?: number;
    },
  ) => request<MemoryArtifactList>(buildArtifactQuery(`/cases/${caseId}/memory/network`, params)),
  getMemoryProcessModules: (
    caseId: string,
    params?: {
      evidence_id: string;
      run_id?: string;
      pid?: number;
      process_name?: string;
      module_name?: string;
      path?: string;
      load_state?: string;
      discrepancy_only?: boolean;
      page?: number;
      page_size?: number;
    },
  ) => request<MemoryArtifactList>(buildArtifactQuery(`/cases/${caseId}/memory/modules`, params)),
  getMemoryHandles: (
    caseId: string,
    params?: {
      evidence_id: string;
      run_id?: string;
      pid?: number;
      process_name?: string;
      object_type?: string;
      object_name?: string;
      page?: number;
      page_size?: number;
    },
  ) => request<MemoryArtifactList>(buildArtifactQuery(`/cases/${caseId}/memory/handles`, params)),
  getMemoryKernelModules: (
    caseId: string,
    params: { evidence_id: string; run_id?: string; page?: number; page_size?: number },
  ) => request<MemoryArtifactList>(buildArtifactQuery(`/cases/${caseId}/memory/kernel-modules`, params)),
  getMemoryDrivers: (
    caseId: string,
    params: { evidence_id: string; run_id?: string; page?: number; page_size?: number },
  ) => request<MemoryArtifactList>(buildArtifactQuery(`/cases/${caseId}/memory/drivers`, params)),
  getMemorySuspiciousRegions: (
    caseId: string,
    params?: {
      evidence_id: string;
      run_id?: string;
      pid?: number;
      process_name?: string;
      protection?: string;
      review_status?: string;
      page?: number;
      page_size?: number;
    },
  ) => request<MemoryArtifactList>(buildArtifactQuery(`/cases/${caseId}/memory/suspicious-regions`, params)),
  getMemoryArtifactDetail: (caseId: string, documentType: string, documentId: string) =>
    request<MemoryArtifactDetail>(`/cases/${caseId}/memory/artifacts/${documentType}/${documentId}`),
  getEvidence: (evidenceId: string) => request<Evidence>(`/evidences/${evidenceId}`),
  getEvidenceManifest: (evidenceId: string) => request<EvidenceManifest>(`/evidences/${evidenceId}/manifest`),
  getEvidenceOnDemandModules: (evidenceId: string) => request<OnDemandModulesResponse>(`/evidences/${evidenceId}/on-demand-modules`),
  getEvidenceSearchSummary: (evidenceId: string) => request<EvidenceSearchSummary>(`/evidences/${evidenceId}/search-summary`),
  getEvidenceMftDiagnostic: (evidenceId: string) => request<MftDiagnostic>(`/evidences/${evidenceId}/mft-diagnostic`),
  getEvidenceRegistryDiagnostic: (evidenceId: string) => request<RegistryDiagnostic>(`/evidences/${evidenceId}/registry-diagnostic`),
  getEvidenceIndexingPlan: (evidenceId: string, profile: "recommended" | "fast" | "advanced_custom" = "recommended") => request<EvidenceIndexingPlan>(`/evidences/${evidenceId}/indexing-plan?profile=${encodeURIComponent(profile)}`),
  runEvidenceIndexingPlan: (evidenceId: string, payload: { profile?: "recommended" | "fast" | "advanced_custom"; force?: boolean } = {}) => request<EvidenceIndexingPlanRunResponse>(`/evidences/${evidenceId}/indexing-plan/run`, { method: "POST", body: JSON.stringify(payload) }),
  cancelEvidenceIndexing: (evidenceId: string, payload: { reason?: string } = {}) => request<{ accepted: boolean; evidence_id: string; status: string; previous_status?: string; previous_phase?: string; lock_released?: boolean; retry_allowed?: boolean }>(`/evidences/${evidenceId}/indexing/cancel`, { method: "POST", body: JSON.stringify(payload) }),
  indexEvidenceMftSummary: (evidenceId: string, payload: { max_records?: number | null; force?: boolean } = {}) => request<{ accepted: boolean; run_id: string; evidence_id: string; status: string; backend: string; mode: string }>(`/evidences/${evidenceId}/mft-summary-index`, { method: "POST", body: JSON.stringify(payload) }),
  indexEvidenceMftFull: (evidenceId: string, payload: { max_records?: number | null; force?: boolean } = {}) => request<{ accepted: boolean; run_id: string; evidence_id: string; status: string; backend: string; mode: string }>(`/evidences/${evidenceId}/mft-full-index`, { method: "POST", body: JSON.stringify(payload) }),
  indexEvidenceRecmdUserActivity: (evidenceId: string, payload: { force?: boolean } = {}) => request<{ accepted: boolean; run_id: string; evidence_id: string; status: string; backend: string; mode: string }>(`/evidences/${evidenceId}/recmd-user-activity-index`, { method: "POST", body: JSON.stringify(payload) }),
  indexEvidenceRegistryPersistenceSummary: (evidenceId: string, payload: { force?: boolean } = {}) => request<{ accepted: boolean; run_id: string; evidence_id: string; status: string; backend: string; mode: string }>(`/evidences/${evidenceId}/registry-persistence-summary-index`, { method: "POST", body: JSON.stringify(payload) }),
  indexEvidenceDefenderEvtx: (evidenceId: string, payload: { force?: boolean } = {}) => request<{ accepted: boolean; run_id: string; evidence_id: string; status: string; parser: string; mode: string }>(`/evidences/${evidenceId}/defender-evtx-index`, { method: "POST", body: JSON.stringify(payload) }),
  indexEvidenceSrum: (evidenceId: string, payload: { force?: boolean } = {}) => request<{ accepted: boolean; run_id: string; evidence_id: string; status: string; backend: string; mode: string }>(`/evidences/${evidenceId}/srum-index`, { method: "POST", body: JSON.stringify(payload) }),
  rebuildEvidenceCoreEzArtifact: (evidenceId: string, artifactType: string, payload: { force?: boolean } = {}) => request<{ accepted: boolean; run_id: string; evidence_id: string; status: string; artifact_type: string; tool: string; backend: string; backend_variant: string }>(`/evidences/${evidenceId}/core-ez-rebuild/${artifactType}`, { method: "POST", body: JSON.stringify(payload) }),
  getProblematicArtifacts: (evidenceId: string) => request<ProblematicArtifactsResponse>(`/evidences/${evidenceId}/problematic-artifacts`),
  getProblematicRetryCandidates: (evidenceId: string) => request<ProblematicRetryCandidatesResponse>(`/evidences/${evidenceId}/problematic-artifacts/retry-candidates`),
  getLongTailArtifacts: (evidenceId: string) => request<LongTailArtifactsResponse>(`/evidences/${evidenceId}/long-tail-artifacts`),
  getEvidenceRuns: (evidenceId: string) => request<EvidenceRun[]>(`/evidences/${evidenceId}/runs`),
  getEvidenceRun: (evidenceId: string, runId: string) => request<EvidenceRun>(`/evidences/${evidenceId}/runs/${runId}`),
  generateEvidenceReport: (
    evidenceId: string,
    payload: {
      scope?: "evidence";
      report_type?: "summary";
      format?: "json" | "markdown" | "html";
      mode?: "on_demand";
      include_detections?: boolean;
      include_problematic_artifacts?: boolean;
      include_search_summary?: boolean;
      include_parser_contract?: boolean;
      force?: boolean;
    },
  ) => request<CaseReport>(`/evidences/${evidenceId}/reports/generate`, { method: "POST", body: JSON.stringify(payload) }),
  listEvidenceReports: (evidenceId: string) => request<CaseReport[]>(`/evidences/${evidenceId}/reports`),
  getReport: (reportId: string) => request<CaseReport>(`/reports/${reportId}`),
  downloadReport: async (reportId: string, format?: "json" | "markdown" | "html") => {
    const suffix = format ? `?format=${encodeURIComponent(format)}` : "";
    const response = await apiFetch(`/reports/${reportId}/download${suffix}`);
    if (!response.ok) {
      const body = await response.text();
      let detail = body || `HTTP ${response.status}`;
      try {
        const parsed = JSON.parse(body) as { detail?: string | Record<string, unknown> };
        detail =
          typeof parsed.detail === "string"
            ? parsed.detail
            : parsed.detail
              ? JSON.stringify(parsed.detail)
              : detail;
      } catch {
        // Keep raw body.
      }
      throw new Error(detail);
    }
    const fallbackExtension = format === "json" ? "json" : format === "html" ? "html" : "md";
    return {
      blob: await response.blob(),
      filename: extractDownloadFilename(response.headers.get("content-disposition"), `evidence-report-${reportId}.${fallbackExtension}`),
    };
  },
  runRulesForEvidence: (
    evidenceId: string,
    payload: {
  mode?: string;
      rule_types?: string[];
      engines?: string[];
      rule_ids?: string[];
      enabled_only?: boolean;
      engine?: string;
      severity?: string;
      namespace?: string;
      scope?: string;
      force?: boolean;
      search?: string;
      include_disabled?: boolean;
      enabled?: boolean;
      include_parsed_outputs?: boolean | null;
      include_archives?: boolean | null;
      include_text_outputs?: boolean | null;
      max_file_size_mb?: number | null;
      run_mode?: "fast_triage" | "balanced" | "exhaustive";
    },
  ) => request<{ accepted: boolean; run_id?: string; status: string; queued_rules?: number; message?: string }>(`/evidences/${evidenceId}/rules/run`, { method: "POST", body: JSON.stringify(payload) }),
  listEvidenceRuleRuns: (evidenceId: string) => request<RuleRun[]>(`/evidences/${evidenceId}/rules/runs`),
  listEvidenceDetections: (evidenceId: string) => request<Detection[]>(`/evidences/${evidenceId}/detections`),
  getEvidenceBenchmarks: (evidenceId: string) => request<EvidenceBenchmark[]>(`/evidences/${evidenceId}/benchmarks`),
  getEvidenceBenchmark: (evidenceId: string, benchmarkId: string) => request<EvidenceBenchmark>(`/evidences/${evidenceId}/benchmarks/${benchmarkId}`),
  runEvidenceBenchmark: (
    evidenceId: string,
    payload: {
      mode: "ingest" | "reprocess_previous_selection" | "reprocess_full" | "current";
      profile: "current" | "safe" | "balanced" | "performance" | "max";
      label?: string;
      notes?: string;
      stop_after_overlap_observed?: boolean;
      max_duration_seconds?: number;
      skip_detections?: boolean;
      skip_rules?: boolean;
      autopilot?: boolean;
      max_attempts?: number;
      max_wall_time_seconds?: number;
      no_progress_timeout_seconds?: number;
      heartbeat_timeout_seconds?: number;
    },
  ) => request<EvidenceBenchmarkQueuedResponse>(`/evidences/${evidenceId}/benchmarks`, { method: "POST", body: JSON.stringify(payload) }),
  runEvidenceBenchmarkWatchdog: (evidenceId: string, benchmarkId: string) =>
    request<EvidenceBenchmark>(`/evidences/${evidenceId}/benchmarks/${benchmarkId}/watchdog/run`, { method: "POST" }),
  compareEvidenceBenchmarks: (evidenceId: string, payload: { benchmark_ids: string[] }) =>
    request<Record<string, unknown>>(`/evidences/${evidenceId}/benchmarks/compare`, { method: "POST", body: JSON.stringify(payload) }),
  getStorageCapabilities: () => request<StorageCapabilities>("/storage/allowed-roots"),
  validateEvidencePath: (payload: { path: string; copy_to_storage: boolean; evidence_intent?: EvidenceIntent; packaging?: EvidencePackaging }) =>
    request<PathValidationResult>("/evidence/validate-path", { method: "POST", body: JSON.stringify(payload) }),
  registerEvidencePath: (
    caseId: string,
    payload: { path: string; name?: string; copy_to_storage: boolean; start_ingest: boolean; storage_mode?: string; evidence_intent?: EvidenceIntent; packaging?: EvidencePackaging; ingest_mode?: IngestMode; provided_host?: string; evtx_profile?: EvtxProfile },
  ) =>
    request<Evidence>(`/cases/${caseId}/evidences/register-path`, { method: "POST", body: JSON.stringify(payload) }),
  uploadEvidence: async (
    caseId: string,
    file: File,
    options?: UploadOptions & { evidenceIntent?: EvidenceIntent; packaging?: EvidencePackaging; folderName?: string; folderUpload?: boolean; ingestMode?: IngestMode; providedHost?: string; evtxProfile?: EvtxProfile; memoryAuthorizationAcknowledged?: boolean; memoryUploadId?: string },
  ) => {
    const formData = new FormData();
    formData.append("file", file);
    if (options?.evidenceIntent) formData.append("evidence_intent", options.evidenceIntent);
    if (options?.packaging) formData.append("packaging", options.packaging);
    if (options?.ingestMode) formData.append("ingest_mode", options.ingestMode);
    if (options?.providedHost) formData.append("provided_host", options.providedHost);
    if (options?.evtxProfile) formData.append("evtx_profile", options.evtxProfile);
    if (options?.memoryAuthorizationAcknowledged) formData.append("memory_authorization_acknowledged", "true");
    if (options?.memoryUploadId) formData.append("memory_upload_id", options.memoryUploadId);
    if (options?.folderUpload) formData.append("folder_upload", "true");
    if (options?.folderName) formData.append("folder_name", options.folderName);
    return uploadFormData<Evidence>(`/cases/${caseId}/evidences/upload`, formData, { onProgress: options?.onProgress, transport: "xhr" });
  },
  uploadEvidenceFolder: async (caseId: string, files: File[], options?: UploadOptions & { evidenceIntent?: EvidenceIntent; ingestMode?: IngestMode; providedHost?: string; evtxProfile?: EvtxProfile }) => {
    const folderName = ((files[0] as File & { webkitRelativePath?: string } | undefined)?.webkitRelativePath || files[0]?.name || "uploaded-folder")
      .split("/")[0]
      .trim() || "uploaded-folder";
    const archive = await buildZipFromFolder(files, `${folderName}.zip`);
    return api.uploadEvidence(caseId, archive, {
      onProgress: options?.onProgress,
      evidenceIntent: options?.evidenceIntent ?? "raw",
      ingestMode: options?.ingestMode,
      providedHost: options?.providedHost,
      evtxProfile: options?.evtxProfile,
      packaging: "directory",
      folderUpload: true,
      folderName,
    });
  },
  discoverVelociraptorZip: async (caseId: string, file: File, options?: UploadOptions) => {
    const formData = new FormData();
    formData.append("file", file);
    if (options?.ingestMode) formData.append("ingest_mode", options.ingestMode);
    if (options?.providedHost) formData.append("provided_host", options.providedHost);
    if (options?.evtxProfile) formData.append("evtx_profile", options.evtxProfile);
    return uploadFormData<VelociraptorDiscoverResponse>(`/cases/${caseId}/velociraptor/discover-zip`, formData, { onProgress: options?.onProgress, transport: "xhr" });
  },
  discoverVelociraptorFolder: async (caseId: string, files: File[], options?: UploadOptions) => {
    const folderName = ((files[0] as File & { webkitRelativePath?: string } | undefined)?.webkitRelativePath || files[0]?.name || "raw-folder")
      .split("/")[0]
      .trim() || "raw-folder";
    const archive = await buildZipFromFolder(files, `${folderName}.zip`);
    const formData = new FormData();
    formData.append("file", archive);
    if (options?.ingestMode) formData.append("ingest_mode", options.ingestMode);
    if (options?.providedHost) formData.append("provided_host", options.providedHost);
    if (options?.evtxProfile) formData.append("evtx_profile", options.evtxProfile);
    return uploadFormData<VelociraptorDiscoverResponse>(`/cases/${caseId}/velociraptor/discover-zip`, formData, { onProgress: options?.onProgress, transport: "xhr" });
  },
  parseVelociraptorSelection: (payload: { evidence_id: string; selected_candidate_ids?: string[]; categories?: string[]; parse_all?: boolean; ingest_mode?: IngestMode; provided_host?: string; evtx_profile?: EvtxProfile }) =>
    request<VelociraptorParseResponse>("/velociraptor/parse", { method: "POST", body: JSON.stringify(payload) }),
  previewReprocessEvidence: (evidenceId: string, payload: { mode: "previous_selection" | "choose_again" | "full_rediscovery" | "manual_selection" }) =>
    request<EvidenceReprocessPreview>(`/evidences/${evidenceId}/reprocess/preview`, { method: "POST", body: JSON.stringify(payload) }),
  reprocessEvidence: (
    evidenceId: string,
    payload: {
      mode: "previous_selection" | "choose_again" | "full_rediscovery" | "manual_selection";
      selected_candidate_ids?: string[];
      parser_options?: Record<string, unknown>;
      preserve_analyst_state?: boolean;
      explicit_confirm?: boolean;
      ingest_mode?: IngestMode;
      provided_host?: string;
      evtx_profile?: EvtxProfile;
    },
  ) => request<EvidenceRunQueuedResponse>(`/evidences/${evidenceId}/reprocess`, { method: "POST", body: JSON.stringify(payload) }),
  retryProblematicArtifact: (
    evidenceId: string,
    artifactId: string,
    payload: {
      mode?: string;
      timeout_seconds?: number | null;
      preserve_existing_events?: boolean;
      replace_existing_events_for_artifact?: boolean;
    },
  ) => request<{ accepted: boolean; run_id?: string; artifact_ids?: string[]; mode?: string }>(`/evidences/${evidenceId}/artifacts/${artifactId}/retry`, { method: "POST", body: JSON.stringify(payload) }),
  retryProblematicArtifacts: (
    evidenceId: string,
    payload: {
      artifact_ids?: string[];
      mode?: string;
      timeout_seconds?: number | null;
      preserve_existing_events?: boolean;
      replace_existing_events_for_artifact?: boolean;
    },
  ) => request<{ accepted: boolean; run_id?: string; artifact_ids?: string[]; mode?: string }>(`/evidences/${evidenceId}/problematic-artifacts/retry`, { method: "POST", body: JSON.stringify(payload) }),
  checkEvtxHealth: (
    evidenceId: string,
    artifactId: string,
    payload?: {
      record_timeout_seconds?: number | null;
      max_records?: number | null;
    },
  ) => request<EvtxHealthCheckResult>(`/evidences/${evidenceId}/artifacts/${artifactId}/evtx-health-check`, { method: "POST", body: JSON.stringify(payload ?? {}) }),
  acceptProblematicArtifactWarning: (evidenceId: string, artifactId: string, payload?: { accepted_reason?: string | null }) =>
    request<ProblematicArtifact>(`/evidences/${evidenceId}/problematic-artifacts/${artifactId}/accept-warning`, { method: "POST", body: JSON.stringify(payload ?? {}) }),
  deferLongTailArtifact: (evidenceId: string, artifactId: string, payload?: { reason?: string | null }) =>
    request<{ accepted: boolean; artifact_ids: string[]; reason?: string | null; status: string }>(
      `/evidences/${evidenceId}/artifacts/${artifactId}/defer-long-tail`,
      { method: "POST", body: JSON.stringify(payload ?? {}) },
    ),
  deferLongTailArtifacts: (evidenceId: string, payload?: { artifact_ids?: string[]; reason?: string | null }) =>
    request<{ accepted: boolean; artifact_ids: string[]; reason?: string | null; status: string }>(
      `/evidences/${evidenceId}/long-tail/defer`,
      { method: "POST", body: JSON.stringify(payload ?? {}) },
    ),
  deleteEvidence: (evidenceId: string) => request<void>(`/evidences/${evidenceId}`, { method: "DELETE" }),
  listArtifacts: (caseId: string) => request<Artifact[]>(`/cases/${caseId}/artifacts`),
  getProcessTree: (caseId: string, params?: { scope?: "case" | "evidence"; evidence_id?: string; host?: string; pid?: number; process_name?: string; entity_id?: string; include_activity?: boolean; aggregate_activity?: boolean; edge_types?: string; max_nodes?: number; max_activity_per_process?: number; only_suspicious?: boolean; only_marked?: boolean }) => {
    const query = new URLSearchParams();
    query.set("scope", params?.scope ?? "case");
    if (params?.evidence_id) query.set("evidence_id", params.evidence_id);
    if (params?.host) query.set("host", params.host);
    if (params?.pid !== undefined) query.set("pid", String(params.pid));
    if (params?.process_name) query.set("process_name", params.process_name);
    if (params?.entity_id) query.set("entity_id", params.entity_id);
    if (params?.include_activity !== undefined) query.set("include_activity", String(params.include_activity));
    if (params?.aggregate_activity !== undefined) query.set("aggregate_activity", String(params.aggregate_activity));
    if (params?.edge_types) query.set("edge_types", params.edge_types);
    if (params?.max_nodes) query.set("max_nodes", String(params.max_nodes));
    if (params?.max_activity_per_process) query.set("max_activity_per_process", String(params.max_activity_per_process));
    if (params?.only_suspicious !== undefined) query.set("only_suspicious", String(params.only_suspicious));
    if (params?.only_marked !== undefined) query.set("only_marked", String(params.only_marked));
    return request<ProcessTreeBundle>(`/cases/${caseId}/process-tree?${query.toString()}`);
  },
  expandProcessTree: (
    caseId: string,
    params: {
      scope?: "case" | "evidence";
      evidence_id?: string;
      host?: string;
      node_id?: string;
      process_guid?: string;
      process_pid?: number | null;
      process_name?: string | null;
      timestamp?: string | null;
      expansion_type: "children" | "parents" | "siblings" | "activity" | "commands";
      depth?: number;
      time_window_before?: number;
      time_window_after?: number;
      max_nodes?: number;
      max_activity?: number;
      edge_types?: string;
    },
  ) => {
    const query = new URLSearchParams();
    query.set("scope", params.scope ?? "case");
    if (params.evidence_id) query.set("evidence_id", params.evidence_id);
    if (params.host) query.set("host", params.host);
    if (params.node_id) query.set("node_id", params.node_id);
    if (params.process_guid) query.set("process_guid", params.process_guid);
    if (params.process_pid !== undefined && params.process_pid !== null) query.set("process_pid", String(params.process_pid));
    if (params.process_name) query.set("process_name", params.process_name);
    if (params.timestamp) query.set("timestamp", params.timestamp);
    query.set("expansion_type", params.expansion_type);
    if (params.depth) query.set("depth", String(params.depth));
    if (params.time_window_before !== undefined) query.set("time_window_before", String(params.time_window_before));
    if (params.time_window_after !== undefined) query.set("time_window_after", String(params.time_window_after));
    if (params.max_nodes) query.set("max_nodes", String(params.max_nodes));
    if (params.max_activity) query.set("max_activity", String(params.max_activity));
    if (params.edge_types) query.set("edge_types", params.edge_types);
    return request<ProcessTreeExpansion>(`/cases/${caseId}/process-tree/expand?${query.toString()}`);
  },
  getFocusedProcessTree: (
    caseId: string,
    params: {
      scope?: "case" | "evidence";
      evidence_id?: string;
      host?: string;
      pid?: number | null;
      process_guid?: string | null;
      source_event_id?: string | null;
      process_name?: string | null;
      timestamp?: string | null;
      parent_depth?: number;
      child_depth?: number;
      include_siblings?: boolean;
      include_activity?: boolean;
      time_window_before?: number;
      time_window_after?: number;
      max_nodes?: number;
      max_activity?: number;
    },
  ) => {
    const query = new URLSearchParams();
    query.set("scope", params.scope ?? "case");
    if (params.evidence_id) query.set("evidence_id", params.evidence_id);
    if (params.host) query.set("host", params.host);
    if (params.pid !== undefined && params.pid !== null) query.set("pid", String(params.pid));
    if (params.process_guid) query.set("process_guid", params.process_guid);
    if (params.source_event_id) query.set("source_event_id", params.source_event_id);
    if (params.process_name) query.set("process_name", params.process_name);
    if (params.timestamp) query.set("timestamp", params.timestamp);
    if (params.parent_depth !== undefined) query.set("parent_depth", String(params.parent_depth));
    if (params.child_depth !== undefined) query.set("child_depth", String(params.child_depth));
    if (params.include_siblings !== undefined) query.set("include_siblings", String(params.include_siblings));
    if (params.include_activity !== undefined) query.set("include_activity", String(params.include_activity));
    if (params.time_window_before !== undefined) query.set("time_window_before", String(params.time_window_before));
    if (params.time_window_after !== undefined) query.set("time_window_after", String(params.time_window_after));
    if (params.max_nodes) query.set("max_nodes", String(params.max_nodes));
    if (params.max_activity) query.set("max_activity", String(params.max_activity));
    return request<ProcessTreeFocused>(`/cases/${caseId}/process-tree/focused?${query.toString()}`);
  },
  getExecutionStory: (
    caseId: string,
    params: {
      scope?: "case" | "evidence";
      evidence_id?: string;
      host?: string;
      pid?: number | null;
      process_guid?: string | null;
      source_event_id?: string | null;
      command_history_row_id?: string | null;
      origin?: string | null;
      q?: string | null;
      timestamp?: string | null;
      parent_depth?: number;
      child_depth?: number;
      include_activity?: boolean;
      time_window_before?: number;
      time_window_after?: number;
      max_nodes?: number;
    },
  ) => {
    const query = new URLSearchParams();
    query.set("scope", params.scope ?? "case");
    if (params.evidence_id) query.set("evidence_id", params.evidence_id);
    if (params.host) query.set("host", params.host);
    if (params.pid !== undefined && params.pid !== null) query.set("pid", String(params.pid));
    if (params.process_guid) query.set("process_guid", params.process_guid);
    if (params.source_event_id) query.set("source_event_id", params.source_event_id);
    if (params.command_history_row_id) query.set("command_history_row_id", params.command_history_row_id);
    if (params.origin) query.set("origin", params.origin);
    if (params.q) query.set("q", params.q);
    if (params.timestamp) query.set("timestamp", params.timestamp);
    if (params.parent_depth !== undefined) query.set("parent_depth", String(params.parent_depth));
    if (params.child_depth !== undefined) query.set("child_depth", String(params.child_depth));
    if (params.include_activity !== undefined) query.set("include_activity", String(params.include_activity));
    if (params.time_window_before !== undefined) query.set("time_window_before", String(params.time_window_before));
    if (params.time_window_after !== undefined) query.set("time_window_after", String(params.time_window_after));
    if (params.max_nodes) query.set("max_nodes", String(params.max_nodes));
    return request<ExecutionStory>(`/cases/${caseId}/execution-story?${query.toString()}`);
  },
  getCommandHistory: (
    caseId: string,
    params?: {
      evidence_id?: string;
      host?: string;
      user?: string;
      shell?: string;
      family?: string;
      launcher?: string;
      classification_confidence?: string;
      source_type?: string;
      q?: string;
      time_from?: string;
      time_to?: string;
      risk_min?: number;
      risk_max?: number;
      only_suspicious?: boolean;
      has_supporting_sources?: boolean;
      page?: number;
      page_size?: number;
      sort?: "timestamp_asc" | "timestamp_desc";
      sort_by?: "timestamp";
      sort_order?: "asc" | "desc";
    },
  ) => {
    const query = new URLSearchParams();
    for (const [key, value] of Object.entries(params ?? {})) {
      if (value === undefined || value === null) continue;
      query.set(key, String(value));
    }
    return request<CommandHistoryResponse>(`/cases/${caseId}/command-history${query.size ? `?${query.toString()}` : ""}`);
  },
  extractIndicators: (caseId: string, payload: Record<string, unknown>) =>
    request<{ case_id: string; indicators: ExtractedIndicator[] }>(`/cases/${caseId}/indicators/extract`, { method: "POST", body: JSON.stringify(payload) }),
  resolveIndicators: (caseId: string, payload: Record<string, unknown>) =>
    request<IndicatorResolutionResponse>(`/cases/${caseId}/indicators/resolve`, { method: "POST", body: JSON.stringify(payload) }),
  extractAndResolveIndicators: (caseId: string, payload: Record<string, unknown>) =>
    request<IndicatorResolutionResponse>(`/cases/${caseId}/indicators/extract-resolve`, { method: "POST", body: JSON.stringify(payload) }),
  getStartupPersistence: (
    caseId: string,
    params?: {
      host?: string[];
      type?: string[];
      source?: string[];
      q?: string;
      suspicious_only?: boolean;
      risk_min?: number;
      enabled?: boolean;
      page?: number;
      page_size?: number;
    },
  ) => {
    const query = new URLSearchParams();
    for (const [key, value] of Object.entries(params ?? {})) {
      if (value === undefined || value === null || value === "") continue;
      if (Array.isArray(value)) {
        for (const item of value) {
          if (item !== undefined && item !== null && item !== "") query.append(key, String(item));
        }
        continue;
      }
      query.set(key, String(value));
    }
    return request<StartupPersistenceResponse>(`/cases/${caseId}/startup-persistence${query.size ? `?${query.toString()}` : ""}`);
  },
  getMotw: (
    caseId: string,
    params?: {
      host?: string[];
      q?: string;
      zone_id?: number[];
      extension?: string[];
      source?: string[];
      risk_min?: number;
      page?: number;
      page_size?: number;
    },
  ) => {
    const query = new URLSearchParams();
    for (const [key, value] of Object.entries(params ?? {})) {
      if (value === undefined || value === null || value === "") continue;
      if (Array.isArray(value)) {
        for (const item of value) {
          if (item !== undefined && item !== null && item !== "") query.append(key, String(item));
        }
        continue;
      }
      query.set(key, String(value));
    }
    return request<MotwResponse>(`/cases/${caseId}/motw${query.size ? `?${query.toString()}` : ""}`);
  },
  getEmailArtifacts: (
    caseId: string,
    params?: {
      host?: string[];
      artifact_type?: string[];
      client?: string[];
      q?: string;
      interesting_only?: boolean;
      risk_min?: number;
      page?: number;
      page_size?: number;
    },
  ) => {
    const query = new URLSearchParams();
    for (const [key, value] of Object.entries(params ?? {})) {
      if (value === undefined || value === null || value === "") continue;
      if (Array.isArray(value)) {
        for (const item of value) {
          if (item !== undefined && item !== null && item !== "") query.append(key, String(item));
        }
        continue;
      }
      query.set(key, String(value));
    }
    return request<EmailArtifactsResponse>(`/cases/${caseId}/email-artifacts${query.size ? `?${query.toString()}` : ""}`);
  },
  search: (payload: Record<string, unknown>) => request<SearchResponse>("/search", { method: "POST", body: JSON.stringify(payload) }),
  searchCase: (
    caseId: string,
    params?: {
      q?: string;
      exclude_q?: string;
      filters?: string;
      scope?: "events" | "findings" | "all";
      evidence_id?: string;
      artifact_type?: string[];
      parser?: string[];
      backend_variant?: string[];
      parser_backend?: string[];
      exclude_artifact_type?: string[];
      exclude_parser?: string[];
      event_type?: string[];
      event_category?: string[];
      severity?: string[];
      risk_min?: number;
      risk_max?: number;
      status?: string[];
      confidence?: string[];
      finding_type?: string[];
      host?: string;
      user?: string;
      exclude_host?: string;
      exclude_user?: string;
      process_name?: string;
      source_file?: string;
      exclude_source_file?: string;
      file_name?: string;
      file_path?: string;
      domain?: string;
      ip?: string;
      hash?: string;
      url?: string;
      suspicious_reason?: string;
      tag?: string;
      marked_only?: boolean;
      marking_status?: string;
      marked_has_note?: boolean;
      marked_in_finding?: boolean;
      time_from?: string;
      time_to?: string;
      sort?: "timestamp_desc" | "timestamp_asc" | "risk_desc" | "risk_asc" | "relevance";
      page?: number;
      page_size?: number;
      cursor?: string;
      include_highlights?: boolean;
      include_facets?: boolean;
      include_filesystem_timeline?: boolean;
    },
  ) => {
    const query = new URLSearchParams();
    for (const [key, value] of Object.entries(params ?? {})) {
      if (value === undefined || value === null) continue;
      if (Array.isArray(value)) {
        for (const item of value) {
          if (item !== undefined && item !== null && item !== "") query.append(key, String(item));
        }
        continue;
      }
      query.set(key, String(value));
    }
    return request<SearchV2Response>(`/cases/${caseId}/search${query.size ? `?${query.toString()}` : ""}`);
  },
  getSearchQuickFilters: (caseId: string) => request<SearchQuickFiltersResponse>(`/cases/${caseId}/search/quick-filters`),
  searchAroundEvent: (caseId: string, eventId: string, params?: { window?: string; page_size?: number }) => {
    const query = new URLSearchParams();
    if (params?.window) query.set("window", params.window);
    if (params?.page_size) query.set("page_size", String(params.page_size));
    return request<SearchV2Response>(`/cases/${caseId}/search/around-event/${eventId}${query.size ? `?${query.toString()}` : ""}`);
  },
  searchRelatedToFinding: (caseId: string, findingId: string, params?: { page_size?: number }) => {
    const query = new URLSearchParams();
    if (params?.page_size) query.set("page_size", String(params.page_size));
    return request<SearchV2Response>(`/cases/${caseId}/search/related-to-finding/${findingId}${query.size ? `?${query.toString()}` : ""}`);
  },
  getEventContext: (caseId: string, eventId: string) => request<EventContextResponse>(`/cases/${caseId}/events/${eventId}/context`),
  markEvent: (
    eventId: string,
    payload: {
      case_id: string;
      evidence_id?: string | null;
      search_doc_id?: string | null;
      stable_event_id?: string | null;
      artifact_type?: string | null;
      timestamp?: string | null;
      host?: string | null;
      status: EventMarkingStatus;
      labels?: string[];
      note?: string | null;
      finding_id?: string | null;
      created_by?: string;
    },
  ) => request<EventMarking>(`/events/${eventId}/mark`, { method: "POST", body: JSON.stringify(payload) }),
  updateEventMarking: (markingId: string, payload: Partial<Pick<EventMarking, "status" | "labels" | "note" | "finding_id">>) =>
    request<EventMarking>(`/event-markings/${markingId}`, { method: "PATCH", body: JSON.stringify(payload) }),
  deleteEventMarking: (markingId: string) => request<void>(`/event-markings/${markingId}`, { method: "DELETE" }),
  listEventMarkings: (caseId: string, params?: { status?: string; has_note?: boolean; finding_id?: string }) => {
    const query = new URLSearchParams();
    if (params?.status) query.set("status", params.status);
    if (params?.has_note !== undefined) query.set("has_note", String(params.has_note));
    if (params?.finding_id) query.set("finding_id", params.finding_id);
    return request<EventMarking[]>(`/cases/${caseId}/event-markings${query.size ? `?${query.toString()}` : ""}`);
  },
  searchByEntity: (caseId: string, params: { type: string; value: string; page_size?: number }) => {
    const query = new URLSearchParams();
    query.set("type", params.type);
    query.set("value", params.value);
    if (params.page_size) query.set("page_size", String(params.page_size));
    return request<SearchV2Response>(`/cases/${caseId}/search/entity?${query.toString()}`);
  },
  getTimeline: (
    caseId: string,
    params?: {
      host?: string;
      evidence_id?: string;
      mode?: TimelineMode;
      q?: string;
      artifact_type?: string[];
      event_type?: string[];
      event_category?: string[];
      kind?: string;
      risk_min?: number;
      risk_max?: number;
      severity?: string[];
      finding_id?: string;
      process_node_id?: string;
      file_path?: string;
      process_name?: string;
      domain?: string;
      ip?: string;
      user?: string;
      time_from?: string;
      time_to?: string;
      sort?: "timestamp_desc" | "timestamp_asc" | "risk_desc" | "risk_asc";
      page?: number;
      page_size?: number;
      cursor?: string;
      include_findings?: boolean;
      include_bookmarks?: boolean;
      include_facets?: boolean;
      lightweight?: boolean;
      group_by?: "none" | "hour" | "day" | "finding" | "process" | "artifact";
      key_events_only?: boolean;
    },
  ) => {
    const query = new URLSearchParams();
    for (const [key, value] of Object.entries(params ?? {})) {
      if (value === undefined || value === null || value === "") continue;
      if (Array.isArray(value)) {
        for (const item of value) {
          if (item !== undefined && item !== null && item !== "") query.append(key, String(item));
        }
        continue;
      }
      query.set(key, String(value));
    }
    return request<TimelineResponse>(`/cases/${caseId}/timeline${query.size ? `?${query.toString()}` : ""}`);
  },
  getTimelineQuickFilters: (caseId: string) => request<SearchQuickFiltersResponse>(`/cases/${caseId}/timeline/quick-filters`),
  getTimelineAroundEvent: (caseId: string, eventId: string, params?: { window?: string; page_size?: number }) => {
    const query = new URLSearchParams();
    if (params?.window) query.set("window", params.window);
    if (params?.page_size) query.set("page_size", String(params.page_size));
    return request<TimelineResponse>(`/cases/${caseId}/timeline/around-event/${eventId}${query.size ? `?${query.toString()}` : ""}`);
  },
  getTimelineAroundFinding: (caseId: string, findingId: string, params?: { window?: string; page_size?: number }) => {
    const query = new URLSearchParams();
    if (params?.window) query.set("window", params.window);
    if (params?.page_size) query.set("page_size", String(params.page_size));
    return request<TimelineResponse>(`/cases/${caseId}/timeline/around-finding/${findingId}${query.size ? `?${query.toString()}` : ""}`);
  },
  listTimelineKeyEvents: (caseId: string) => request<TimelineBookmark[]>(`/cases/${caseId}/timeline/key-events`),
  createTimelineKeyEvent: (
    caseId: string,
    payload: {
      event_id: string;
      finding_id?: string | null;
      note?: string;
      category?: TimelineBookmark["category"];
      importance?: TimelineBookmark["importance"];
      created_by?: string;
      include_in_report?: boolean;
    },
  ) => request<TimelineBookmark>(`/cases/${caseId}/timeline/key-events`, { method: "POST", body: JSON.stringify(payload) }),
  updateTimelineKeyEvent: (caseId: string, bookmarkId: string, payload: Partial<TimelineBookmark>) =>
    request<TimelineBookmark>(`/cases/${caseId}/timeline/key-events/${bookmarkId}`, { method: "PATCH", body: JSON.stringify(payload) }),
  deleteTimelineKeyEvent: (caseId: string, bookmarkId: string) => request<void>(`/cases/${caseId}/timeline/key-events/${bookmarkId}`, { method: "DELETE" }),
  exportTimelineKeyEventsMarkdown: (caseId: string, params?: { host?: string; evidence_id?: string }) => {
    const query = new URLSearchParams({ format: "markdown" });
    if (params?.host) query.set("host", params.host);
    if (params?.evidence_id) query.set("evidence_id", params.evidence_id);
    return request<string>(`/cases/${caseId}/timeline/key-events/export?${query.toString()}`);
  },
  getIncidentTimelineDraft: (
    caseId: string,
    params?: {
      sources?: string[];
      host?: string[];
      phase?: string[];
      include_low_signal?: boolean;
      max_items?: number;
      regenerate?: boolean;
    },
  ) => {
    const query = new URLSearchParams();
    for (const [key, value] of Object.entries(params ?? {})) {
      if (value === undefined || value === null) continue;
      if (Array.isArray(value)) {
        for (const item of value) {
          if (item !== undefined && item !== null && item !== "") query.append(key, String(item));
        }
        continue;
      }
      query.set(key, String(value));
    }
    return request<IncidentTimelineDraftResponse>(`/cases/${caseId}/incident-timeline/draft${query.size ? `?${query.toString()}` : ""}`);
  },
  regenerateIncidentTimelineDraft: (
    caseId: string,
    payload: {
      sources?: string[];
      host?: string[];
      phase?: string[];
      include_low_signal?: boolean;
      max_items?: number;
    },
  ) => request<IncidentTimelineDraftResponse>(`/cases/${caseId}/incident-timeline/draft`, { method: "POST", body: JSON.stringify(payload) }),
  updateIncidentTimelineItemStatus: (caseId: string, timelineId: string, itemId: string, payload: { status: string; note?: string }) =>
    request<{ timeline_id: string; item: IncidentTimelineItem; curation?: IncidentTimelineDraftResponse["curation"] }>(
      `/cases/${caseId}/incident-timeline/draft/${timelineId}/items`,
      { method: "PATCH", body: JSON.stringify({ ...payload, item_id: itemId }) },
    ),
  getIncidentTimelineStoryBundle: (caseId: string, itemId: string) =>
    request<IncidentTimelineStoryBundle>(`/cases/${caseId}/incident-timeline/story-bundle?item_id=${encodeURIComponent(itemId)}`),
  exportIncidentTimelineMarkdown: (caseId: string, payload: { items: IncidentTimelineItem[]; title?: string; group_by?: string; include_candidates?: boolean }) =>
    request<string>(`/cases/${caseId}/incident-timeline/export`, { method: "POST", body: JSON.stringify(payload) }),
  listReportTemplates: (caseId: string) => request<{ case_id: string; items: ReportTemplate[] }>(`/cases/${caseId}/reports/templates`),
  listCaseReports: (caseId: string) => request<CaseReport[]>(`/cases/${caseId}/reports`),
  createCaseReportDraft: (
    caseId: string,
    payload: {
      title?: string;
      template?: string;
      filters?: Record<string, unknown>;
      time_range?: Record<string, unknown>;
      sections_enabled?: Record<string, boolean>;
      analyst_notes?: Record<string, string>;
      selected_finding_ids?: string[];
      selected_key_event_ids?: string[];
      selected_process_chain_ids?: string[];
      auto_select?: boolean;
      include_raw_appendix?: boolean;
      include_debug_metadata?: boolean;
    },
  ) => request<CaseReport>(`/cases/${caseId}/reports/draft`, { method: "POST", body: JSON.stringify(payload) }),
  getCaseReport: (caseId: string, reportId: string) => request<CaseReport>(`/cases/${caseId}/reports/${reportId}`),
  updateCaseReport: (caseId: string, reportId: string, payload: Partial<CaseReport>) =>
    request<CaseReport>(`/cases/${caseId}/reports/${reportId}`, { method: "PATCH", body: JSON.stringify(payload) }),
  getCaseReportPreview: (caseId: string, reportId: string) => request<CaseReportPreview>(`/cases/${caseId}/reports/${reportId}/preview`),
  exportCaseReport: async (caseId: string, reportId: string, format: "markdown" | "pdf" = "markdown") => {
    const path = format === "markdown" ? `/reports/${reportId}/download?format=markdown` : `/cases/${caseId}/reports/${reportId}/export?format=${format}`;
    const response = await apiFetch(path);
    if (!response.ok) {
      const body = await response.text();
      let detail = body || `HTTP ${response.status}`;
      try {
        const parsed = JSON.parse(body) as { detail?: string | Record<string, unknown> };
        detail =
          typeof parsed.detail === "string"
            ? parsed.detail
            : parsed.detail
              ? JSON.stringify(parsed.detail)
              : detail;
      } catch {
        // Keep raw body.
      }
      throw new Error(detail);
    }
    return {
      blob: await response.blob(),
      filename: extractDownloadFilename(response.headers.get("content-disposition"), `case-report-${caseId}.${format === "pdf" ? "pdf" : "md"}`),
    };
  },
  searchFacets: (params?: { caseId?: string; evidenceId?: string }) => {
    const query = new URLSearchParams();
    if (params?.caseId) query.append("case_id", params.caseId);
    if (params?.evidenceId) query.append("evidence_id", params.evidenceId);
    return request<SearchFacets>(`/search/facets${query.size ? `?${query.toString()}` : ""}`);
  },
  siem: (payload: Record<string, unknown>) => request<SearchResponse>("/siem", { method: "POST", body: JSON.stringify(payload) }),
  siemFields: (caseId?: string) => request<SiemFieldsResponse>(`/siem/fields${caseId ? `?case_id=${caseId}` : ""}`),
  siemExternalStatus: (caseId?: string) => request<SiemExternalStatus>(`/siem/external/status${caseId ? `?case_id=${caseId}` : ""}`),
  siemExternalSetup: () => request<SiemExternalSetup>("/siem/external/setup", { method: "POST" }),
  siemExternalDiagnostics: (caseId?: string) => request<SiemExternalDiagnostics>(`/siem/external/diagnostics${caseId ? `?case_id=${caseId}` : ""}`),
  getAdminOpenSearchDashboardsStatus: () => request<AdminOpenSearchDashboardsStatus>("/admin/opensearch-dashboards/status"),
  bootstrapAdminOpenSearchDashboards: (payload?: { repair?: boolean }) =>
    request<AdminOpenSearchDashboardsBootstrapResponse>("/admin/opensearch-dashboards/bootstrap", { method: "POST", body: JSON.stringify(payload ?? {}) }),
  siemExternalLinks: (params?: { case_id?: string; query?: string; artifact_type?: string; event_id?: string; detection_id?: string }) => {
    const query = new URLSearchParams();
    if (params?.case_id) query.append("case_id", params.case_id);
    if (params?.query) query.append("query", params.query);
    if (params?.artifact_type) query.append("artifact_type", params.artifact_type);
    if (params?.event_id) query.append("event_id", params.event_id);
    if (params?.detection_id) query.append("detection_id", params.detection_id);
    return request<SiemExternalLinks>(`/siem/external/links${query.size ? `?${query.toString()}` : ""}`);
  },
  listSiemQueryHistory: () => request<Array<Record<string, unknown>>>("/siem/query-history"),
  saveSiemQueryHistory: (payload: Record<string, unknown>) => request<Array<Record<string, unknown>>>("/siem/query-history", { method: "POST", body: JSON.stringify(payload) }),
  listSiemSavedSearches: () => request<Array<Record<string, unknown>>>("/siem/saved-searches"),
  createSiemSavedSearch: (payload: Record<string, unknown>) => request<Record<string, unknown>>("/siem/saved-searches", { method: "POST", body: JSON.stringify(payload) }),
  deleteSiemSavedSearch: (searchId: string) => request<{ status: string }>(`/siem/saved-searches/${searchId}`, { method: "DELETE" }),
  timeline: (payload: Record<string, unknown>) => request<SearchResponse>("/timeline", { method: "POST", body: JSON.stringify(payload) }),
  listActivity: () => request<ActivityEvent[]>("/activity"),
  listCaseActivity: (caseId: string) => request<ActivityEvent[]>(`/cases/${caseId}/activity`),
  listFindings: (
    caseId: string,
    params?: {
      severity?: string;
      confidence?: string;
      status?: string;
      finding_type?: string;
      evidence_id?: string;
      host?: string;
    },
  ) => {
    const query = new URLSearchParams();
    if (params?.severity) query.set("severity", params.severity);
    if (params?.confidence) query.set("confidence", params.confidence);
    if (params?.status) query.set("status", params.status);
    if (params?.finding_type) query.set("finding_type", params.finding_type);
    if (params?.evidence_id) query.set("evidence_id", params.evidence_id);
    if (params?.host) query.set("host", params.host);
    return request<Finding[]>(`/cases/${caseId}/findings${query.size ? `?${query.toString()}` : ""}`);
  },
  getFinding: (caseId: string, findingId: string) => request<Finding>(`/cases/${caseId}/findings/${findingId}`),
  createFinding: (caseId: string, payload: Partial<Finding>) => request<Finding>(`/cases/${caseId}/findings`, { method: "POST", body: JSON.stringify(payload) }),
  updateFinding: (caseId: string, findingId: string, payload: Partial<Finding>) => request<Finding>(`/cases/${caseId}/findings/${findingId}`, { method: "PATCH", body: JSON.stringify(payload) }),
  runCorrelation: (
    caseId: string,
    payload?: {
      evidence_id?: string | null;
      host?: string | null;
      canonical_host?: string | null;
      host_alias_mode?: string | null;
      finding_types?: string[];
      force?: boolean;
      force_reset_status?: boolean;
      page?: number;
      page_size?: number;
    },
  ) => request<{ report: CorrelationRunResult; findings: Finding[] }>(`/cases/${caseId}/correlate`, { method: "POST", body: JSON.stringify(payload ?? {}) }),
  exportFindingMarkdown: (findingId: string) => request<string>(`/findings/${findingId}/export-markdown`, { method: "POST" }),
  listRules: (params?: Record<string, string | number | boolean | undefined>) => {
    const query = new URLSearchParams();
    for (const [key, value] of Object.entries(params ?? {})) {
      if (value !== undefined && value !== "") query.append(key, String(value));
    }
    return request<RuleListResponse>(`/rules${query.size ? `?${query.toString()}` : ""}`);
  },
  getSigmaCoverage: (params?: { case_id?: string; scope?: "global" | "case" | "all" }) => {
    const query = new URLSearchParams();
    if (params?.case_id) query.set("case_id", params.case_id);
    if (params?.scope) query.set("scope", params.scope);
    return request<SigmaCoverageReport>(`/rules/sigma/coverage${query.size ? `?${query.toString()}` : ""}`);
  },
  createSigmaSnapshot: (payload: { case_id?: string; scope?: "global" | "case" | "all"; label?: string }) =>
    request<SigmaRuleLibrarySnapshot>("/rules/sigma/snapshot", { method: "POST", body: JSON.stringify(payload) }),
  getRuleCoverageSummary: (params?: { case_id?: string; scope?: "global" | "case" | "all" }) => {
    const query = new URLSearchParams();
    if (params?.case_id) query.set("case_id", params.case_id);
    if (params?.scope) query.set("scope", params.scope);
    return request<SigmaCoverageReport>(`/rules/coverage/summary${query.size ? `?${query.toString()}` : ""}`);
  },
  listRuleCoverage: (params?: { case_id?: string; scope?: "global" | "case" | "all"; status?: string; logsource?: string; missing_field?: string; severity?: string; page?: number; page_size?: number }) => {
    const query = new URLSearchParams();
    for (const [key, value] of Object.entries(params ?? {})) {
      if (value !== undefined && value !== "") query.set(key, String(value));
    }
    return request<{ total: number; page: number; page_size: number; total_pages: number; items: Array<Record<string, unknown>> }>(`/rules/coverage${query.size ? `?${query.toString()}` : ""}`);
  },
  promoteCaseSigmaRulesToGlobal: (payload: { case_id: string; confirm: string; mode?: "copy_keep_case" | "convert_to_global" }) =>
    request<SigmaPromotionResult>("/rules/sigma/promote-case-to-global", { method: "POST", body: JSON.stringify(payload) }),
  getRule: (ruleId: string) => request<Rule>(`/rules/${ruleId}`),
  createRule: (payload: Partial<Rule>) => request<Rule>("/rules", { method: "POST", body: JSON.stringify(payload) }),
  validateRule: (payload: { engine: string; content: string }) => request<Record<string, unknown>>("/rules/validate", { method: "POST", body: JSON.stringify(payload) }),
  uploadRule: (file: File, options?: { engine?: string; import_mode?: string; case_id?: string; namespace?: string; enabled?: boolean }) => {
    const formData = new FormData();
    formData.append("file", file);
    if (options?.engine) formData.append("engine", options.engine);
    if (options?.import_mode) formData.append("import_mode", options.import_mode);
    if (options?.case_id) formData.append("case_id", options.case_id);
    if (options?.namespace) formData.append("namespace", options.namespace);
    if (typeof options?.enabled === "boolean") formData.append("enabled", String(options.enabled));
    return uploadFormData<RuleImportResponse>("/rules/upload", formData);
  },
  updateRule: (ruleId: string, payload: Partial<Rule>) => request<Rule>(`/rules/${ruleId}`, { method: "PATCH", body: JSON.stringify(payload) }),
  toggleRule: (ruleId: string) => request<Rule>(`/rules/${ruleId}/toggle`, { method: "PATCH" }),
  deleteRule: (ruleId: string) => request<void>(`/rules/${ruleId}`, { method: "DELETE" }),
  bulkUpdateRules: (payload: {
    rule_ids?: string[];
    mode: "selected" | "matching" | "all_imported";
    engine?: string;
    namespace?: string;
    severity?: string;
    import_run_id?: string;
    source_pack?: string;
    enabled?: boolean | null;
    scope?: string;
    case_id?: string;
    search?: string;
    confirm?: string;
  }) => request<RuleBulkUpdateResult>("/rules/bulk", { method: "PATCH", body: JSON.stringify(payload) }),
  previewBulkRules: (payload: {
    rule_ids?: string[];
    mode: "selected" | "matching" | "all_imported";
    engine?: string;
    namespace?: string;
    severity?: string;
    import_run_id?: string;
    source_pack?: string;
    enabled?: boolean | null;
    scope?: string;
    case_id?: string;
    search?: string;
  }) => request<RuleBulkPreviewResult>("/rules/bulk/preview", { method: "POST", body: JSON.stringify(payload) }),
  bulkDeleteRules: (payload: {
    rule_ids?: string[];
    mode: "selected" | "matching" | "all_imported";
    engine?: string;
    namespace?: string;
    severity?: string;
    import_run_id?: string;
    source_pack?: string;
    enabled?: boolean | null;
    scope?: string;
    case_id?: string;
    search?: string;
    confirm?: string;
  }) => request<RuleBulkDeleteResult>("/rules/bulk", { method: "DELETE", body: JSON.stringify(payload) }),
  importRuleFile: async (file: File, options?: { engine?: string; import_mode?: string; case_id?: string; namespace?: string; enabled?: boolean }) => {
    const formData = new FormData();
    formData.append("file", file);
    formData.append("engine", options?.engine ?? "auto");
    formData.append("import_mode", options?.import_mode ?? "auto");
    if (options?.case_id) formData.append("case_id", options.case_id);
    if (options?.namespace) formData.append("namespace", options.namespace);
    formData.append("enabled", String(options?.enabled ?? true));
    const response = await apiFetch(`/rules/import-file`, { method: "POST", body: formData });
    if (!response.ok) throw new Error(await response.text());
    return (await response.json()) as RuleImportResponse;
  },
  importRuleArchive: async (file: File, options?: { engine?: string; import_mode?: string; case_id?: string; namespace?: string; enabled?: boolean }) => {
    const formData = new FormData();
    formData.append("file", file);
    formData.append("engine", options?.engine ?? "auto");
    formData.append("import_mode", options?.import_mode ?? "auto");
    if (options?.case_id) formData.append("case_id", options.case_id);
    if (options?.namespace) formData.append("namespace", options.namespace);
    formData.append("enabled", String(options?.enabled ?? true));
    const response = await apiFetch(`/rules/import-archive`, { method: "POST", body: formData });
    if (!response.ok) throw new Error(await response.text());
    return (await response.json()) as RuleImportResponse;
  },
  listRuleImports: (options?: { case_id?: string; engine?: string; limit?: number }) => {
    const query = new URLSearchParams();
    if (options?.case_id) query.append("case_id", options.case_id);
    if (options?.engine) query.append("engine", options.engine);
    if (typeof options?.limit === "number") query.append("limit", String(options.limit));
    return request<RuleImportRunListResponse>(`/rules/imports${query.size ? `?${query.toString()}` : ""}`);
  },
  getRuleImport: (importRunId: string) => request<RuleImportRun>(`/rules/imports/${importRunId}`),
  cancelRuleImport: (importRunId: string) => request<RuleImportRun>(`/rules/imports/${importRunId}/cancel`, { method: "POST" }),
  getRuleEngineStatus: () => request<RuleEngineStatus>("/rules/engines/status"),
  listRuleSets: (params?: Record<string, string | number | boolean | undefined>) => {
    const query = new URLSearchParams();
    for (const [key, value] of Object.entries(params ?? {})) {
      if (value !== undefined && value !== "") query.append(key, String(value));
    }
    return request<RuleSetListResponse>(`/rule-sets${query.size ? `?${query.toString()}` : ""}`);
  },
  getRuleSet: (ruleSetId: string) => request<RuleSet>(`/rule-sets/${ruleSetId}`),
  toggleRuleSet: (ruleSetId: string) => request<RuleSet>(`/rule-sets/${ruleSetId}/toggle`, { method: "PATCH" }),
  deleteRuleSet: (ruleSetId: string) => request<void>(`/rule-sets/${ruleSetId}`, { method: "DELETE" }),
  bulkDeleteRuleSets: (payload: {
    pack_ids?: string[];
    mode: "selected" | "matching";
    engine?: string;
    namespace?: string;
    enabled?: boolean | null;
    scope?: string;
    case_id?: string;
    search?: string;
    confirm?: string;
  }) => request<RuleBulkDeleteResult>("/rule-sets/bulk", { method: "DELETE", body: JSON.stringify(payload) }),
  runRule: (ruleId: string, payload: { case_id: string; evidence_id?: string | null; mode?: string; dry_run?: boolean; include_parsed_outputs?: boolean | null; include_archives?: boolean | null; include_text_outputs?: boolean | null; max_file_size_mb?: number | null }) =>
    request<RuleRunResult>(`/rules/${ruleId}/run`, { method: "POST", body: JSON.stringify(payload) }),
  runRuleSet: (ruleSetId: string, payload: { case_id: string; evidence_id?: string | null; mode?: string; dry_run?: boolean; include_parsed_outputs?: boolean | null; include_archives?: boolean | null; include_text_outputs?: boolean | null; max_file_size_mb?: number | null }) =>
    request<RuleRunResult>(`/rule-sets/${ruleSetId}/run`, { method: "POST", body: JSON.stringify(payload) }),
  preflightSigmaSmoke: (payload: SigmaSmokeRequest) =>
    request<SigmaSmokeResponse>("/rules/sigma/smoke/preflight", { method: "POST", body: JSON.stringify(payload) }),
  runSigmaSmoke: (payload: SigmaSmokeRequest) =>
    request<SigmaSmokeResponse>("/rules/sigma/smoke/run", { method: "POST", body: JSON.stringify(payload) }),
  listRuleRuns: (ruleId: string) => request<RuleRun[]>(`/rules/${ruleId}/runs`),
  getRuleRun: (runId: string) => request<RuleRun>(`/rule-runs/${runId}`),
  getCaseRuleRun: (caseId: string, runId: string) => request<RuleRun>(`/cases/${caseId}/rules/runs/${runId}`),
  listCaseRuleRuns: (caseId: string) => request<RuleRun[]>(`/cases/${caseId}/rule-runs`),
  cancelRuleRun: (runId: string) => request<RuleRunActionResult>(`/rule-runs/${runId}/cancel`, { method: "POST" }),
  markRuleRunStale: (runId: string) => request<RuleRunActionResult>(`/rule-runs/${runId}/mark-stale`, { method: "POST" }),
  retryRuleRun: (runId: string) => request<RuleRunActionResult>(`/rule-runs/${runId}/retry`, { method: "POST" }),
  deleteRuleRun: (runId: string) => request<void>(`/rule-runs/${runId}`, { method: "DELETE" }),
  bulkCancelRuleRuns: (payload: { run_ids?: string[]; statuses?: string[]; engine?: string; case_id?: string; older_than_minutes?: number | null; mode: "selected" | "matching" }) =>
    request<RuleRunBulkActionResult>("/rule-runs/bulk/cancel", { method: "POST", body: JSON.stringify(payload) }),
  bulkMarkStaleRuleRuns: (payload: { run_ids?: string[]; statuses?: string[]; engine?: string; case_id?: string; older_than_minutes?: number | null; mode: "selected" | "matching" }) =>
    request<RuleRunBulkActionResult>("/rule-runs/mark-stale", { method: "POST", body: JSON.stringify(payload) }),
  markAbandonedRuleRunsStale: (params?: { case_id?: string; older_than_minutes?: number | null }) => {
    const query = new URLSearchParams();
    if (params?.case_id) query.set("case_id", params.case_id);
    if (typeof params?.older_than_minutes === "number") query.set("older_than_minutes", String(params.older_than_minutes));
    return request<RuleRunBulkActionResult>(`/rule-runs/mark-stale-abandoned${query.size ? `?${query.toString()}` : ""}`, { method: "POST" });
  },
  bulkRetryRuleRuns: (payload: { run_ids?: string[]; statuses?: string[]; engine?: string; case_id?: string; older_than_minutes?: number | null; mode: "selected" | "matching" }) =>
    request<RuleRunBulkActionResult>("/rule-runs/bulk/retry", { method: "POST", body: JSON.stringify(payload) }),
  bulkDeleteRuleRuns: (payload: { run_ids?: string[]; statuses?: string[]; engine?: string; case_id?: string; older_than_minutes?: number | null; mode: "selected" | "matching" }) =>
    request<RuleRunBulkActionResult>("/rule-runs/bulk", { method: "DELETE", body: JSON.stringify(payload) }),
  runRulesForCase: (
    caseId: string,
    payload: {
      rule_types?: string[];
      engines?: string[];
      rule_ids?: string[];
      enabled_only?: boolean;
      engine?: string;
      severity?: string;
      namespace?: string;
      scope?: string;
      evidence_id?: string | null;
      host?: string;
      time_from?: string | null;
      time_to?: string | null;
      selected_paths?: string[];
      force?: boolean;
      search?: string;
      include_disabled?: boolean;
      enabled?: boolean;
      include_parsed_outputs?: boolean | null;
      include_archives?: boolean | null;
      include_text_outputs?: boolean | null;
      max_file_size_mb?: number | null;
      run_mode?: "fast_triage" | "balanced" | "exhaustive";
    },
  ) => request<{ accepted: boolean; run_id?: string; status: string; queued_rules?: number; message?: string }>(`/cases/${caseId}/rules/run`, { method: "POST", body: JSON.stringify(payload) }),
  listDetections: (
    caseId: string,
    options?: {
      include_deleted?: boolean;
      include_stale?: boolean;
      include_event_preview?: boolean;
      source?: string;
      engine?: string;
      rule_id?: string;
      rule_run_id?: string;
      import_run_id?: string;
      source_pack?: string;
      severity?: string;
      status?: string;
      rule_name?: string;
      evidence_id?: string;
      host?: string;
      user?: string;
      artifact_type?: string;
      source_file?: string;
      matched_object_type?: string;
      q?: string;
      has_linked_event?: boolean;
      has_file_target?: boolean;
      created_from?: string;
      created_to?: string;
      orphaned_only?: boolean;
      run_type?: string;
      page?: number;
      page_size?: number;
      sort_field?: string;
      sort_direction?: string;
    },
  ) => {
    const query = new URLSearchParams();
    if (options?.include_deleted) query.append("include_deleted", "true");
    if (options?.include_stale) query.append("include_stale", "true");
    if (options?.include_event_preview) query.append("include_event_preview", "true");
    if (options?.source) query.append("source", options.source);
    if (options?.engine) query.append("engine", options.engine);
    if (options?.rule_id) query.append("rule_id", options.rule_id);
    if (options?.rule_run_id) query.append("rule_run_id", options.rule_run_id);
    if (options?.import_run_id) query.append("import_run_id", options.import_run_id);
    if (options?.source_pack) query.append("source_pack", options.source_pack);
    if (options?.severity) query.append("severity", options.severity);
    if (options?.status) query.append("status", options.status);
    if (options?.rule_name) query.append("rule_name", options.rule_name);
    if (options?.evidence_id) query.append("evidence_id", options.evidence_id);
    if (options?.host) query.append("host", options.host);
    if (options?.user) query.append("user", options.user);
    if (options?.artifact_type) query.append("artifact_type", options.artifact_type);
    if (options?.source_file) query.append("source_file", options.source_file);
    if (options?.matched_object_type) query.append("matched_object_type", options.matched_object_type);
    if (options?.q) query.append("q", options.q);
    if (typeof options?.has_linked_event === "boolean") query.append("has_linked_event", String(options.has_linked_event));
    if (typeof options?.has_file_target === "boolean") query.append("has_file_target", String(options.has_file_target));
    if (options?.created_from) query.append("created_from", options.created_from);
    if (options?.created_to) query.append("created_to", options.created_to);
    if (options?.orphaned_only) query.append("orphaned_only", "true");
    if (options?.run_type) query.append("run_type", options.run_type);
    if (options?.page) query.append("page", String(options.page));
    if (options?.page_size) query.append("page_size", String(options.page_size));
    if (options?.sort_field) query.append("sort_field", options.sort_field);
    if (options?.sort_direction) query.append("sort_direction", options.sort_direction);
    return request<PaginatedDetections>(`/cases/${caseId}/detections${query.size ? `?${query.toString()}` : ""}`);
  },
  listAllDetections: (
    options?: {
      case_id?: string;
      include_deleted?: boolean;
      include_stale?: boolean;
      include_event_preview?: boolean;
      source?: string;
      engine?: string;
      rule_id?: string;
      rule_run_id?: string;
      import_run_id?: string;
      source_pack?: string;
      severity?: string;
      status?: string;
      rule_name?: string;
      evidence_id?: string;
      host?: string;
      user?: string;
      artifact_type?: string;
      source_file?: string;
      matched_object_type?: string;
      q?: string;
      has_linked_event?: boolean;
      has_file_target?: boolean;
      created_from?: string;
      created_to?: string;
      orphaned_only?: boolean;
      run_type?: string;
      page?: number;
      page_size?: number;
      sort_field?: string;
      sort_direction?: string;
    },
  ) => {
    const query = new URLSearchParams();
    if (options?.case_id) query.append("case_id", options.case_id);
    if (options?.include_deleted) query.append("include_deleted", "true");
    if (options?.include_stale) query.append("include_stale", "true");
    if (options?.include_event_preview) query.append("include_event_preview", "true");
    if (options?.source) query.append("source", options.source);
    if (options?.engine) query.append("engine", options.engine);
    if (options?.rule_id) query.append("rule_id", options.rule_id);
    if (options?.rule_run_id) query.append("rule_run_id", options.rule_run_id);
    if (options?.import_run_id) query.append("import_run_id", options.import_run_id);
    if (options?.source_pack) query.append("source_pack", options.source_pack);
    if (options?.severity) query.append("severity", options.severity);
    if (options?.status) query.append("status", options.status);
    if (options?.rule_name) query.append("rule_name", options.rule_name);
    if (options?.evidence_id) query.append("evidence_id", options.evidence_id);
    if (options?.host) query.append("host", options.host);
    if (options?.user) query.append("user", options.user);
    if (options?.artifact_type) query.append("artifact_type", options.artifact_type);
    if (options?.source_file) query.append("source_file", options.source_file);
    if (options?.matched_object_type) query.append("matched_object_type", options.matched_object_type);
    if (options?.q) query.append("q", options.q);
    if (typeof options?.has_linked_event === "boolean") query.append("has_linked_event", String(options.has_linked_event));
    if (typeof options?.has_file_target === "boolean") query.append("has_file_target", String(options.has_file_target));
    if (options?.created_from) query.append("created_from", options.created_from);
    if (options?.created_to) query.append("created_to", options.created_to);
    if (options?.orphaned_only) query.append("orphaned_only", "true");
    if (options?.run_type) query.append("run_type", options.run_type);
    if (options?.page) query.append("page", String(options.page));
    if (options?.page_size) query.append("page_size", String(options.page_size));
    if (options?.sort_field) query.append("sort_field", options.sort_field);
    if (options?.sort_direction) query.append("sort_direction", options.sort_direction);
    return request<PaginatedDetections>(`/detections${query.size ? `?${query.toString()}` : ""}`);
  },
  getDetectionFacets: (caseId?: string) => request<DetectionFacets>(`/detections/facets${caseId ? `?case_id=${caseId}` : ""}`),
  getDetectionSummary: (options?: {
    case_id?: string;
    source?: string;
    engine?: string;
    rule_id?: string;
    rule_run_id?: string;
    import_run_id?: string;
    source_pack?: string;
    severity?: string;
    status?: string;
    rule_name?: string;
    evidence_id?: string;
    host?: string;
    user?: string;
    artifact_type?: string;
    source_file?: string;
    q?: string;
    run_type?: string;
    limit?: number;
  }) => {
    const query = new URLSearchParams();
    for (const [key, value] of Object.entries(options ?? {})) {
      if (value !== undefined && value !== null && value !== "") query.append(key, String(value));
    }
    return request<DetectionSummary>(`/detections/summary${query.size ? `?${query.toString()}` : ""}`);
  },
  getEvidenceDetectionSummary: (evidenceId: string, options?: {
    case_id?: string;
    source?: string;
    engine?: string;
    rule_id?: string;
    rule_run_id?: string;
    import_run_id?: string;
    source_pack?: string;
    severity?: string;
    status?: string;
    rule_name?: string;
    host?: string;
    user?: string;
    artifact_type?: string;
    source_file?: string;
    q?: string;
    run_type?: string;
    limit?: number;
  }) => {
    const query = new URLSearchParams();
    for (const [key, value] of Object.entries(options ?? {})) {
      if (value !== undefined && value !== null && value !== "") query.append(key, String(value));
    }
    return request<DetectionSummary>(`/evidences/${evidenceId}/detections/summary${query.size ? `?${query.toString()}` : ""}`);
  },
  getDetection: (detectionId: string) => request<Detection>(`/detections/${detectionId}`),
  getCaseDetection: (caseId: string, detectionId: string) => request<Detection>(`/cases/${caseId}/detections/${detectionId}`),
  updateDetection: (detectionId: string, payload: { status?: string; confidence?: number | null; analyst_note?: string | null }) =>
    request<Detection>(`/detections/${detectionId}`, { method: "PATCH", body: JSON.stringify(payload) }),
  deleteDetection: (detectionId: string) => request<void>(`/detections/${detectionId}`, { method: "DELETE" }),
  previewBulkDetections: (payload: {
    mode: "selected" | "matching" | "rule_run" | "rule" | "import_run" | "source_pack" | "orphaned_rules";
    detection_ids?: string[];
    filters?: DetectionBulkFilterSet;
    case_id?: string;
    rule_run_id?: string;
    rule_id?: string;
    import_run_id?: string;
    source_pack?: string;
  }) => request<DetectionBulkPreviewResult>("/detections/bulk/preview", { method: "POST", body: JSON.stringify(payload) }),
  updateBulkDetections: (payload: {
    action: "mark_reviewed" | "mark_dismissed" | "mark_new";
    mode: "selected" | "matching" | "rule_run" | "rule" | "import_run" | "source_pack" | "orphaned_rules";
    detection_ids?: string[];
    filters?: DetectionBulkFilterSet;
    case_id?: string;
    rule_run_id?: string;
    rule_id?: string;
    import_run_id?: string;
    source_pack?: string;
    confirm?: string | null;
  }) => request<DetectionBulkActionResult>("/detections/bulk", { method: "PATCH", body: JSON.stringify(payload) }),
  deleteBulkDetections: (payload: {
    mode: "selected" | "matching" | "rule_run" | "rule" | "import_run" | "source_pack" | "orphaned_rules";
    detection_ids?: string[];
    filters?: DetectionBulkFilterSet;
    case_id?: string;
    rule_run_id?: string;
    rule_id?: string;
    import_run_id?: string;
    source_pack?: string;
    confirm?: string | null;
  }) => request<DetectionBulkActionResult>("/detections/bulk", { method: "DELETE", body: JSON.stringify(payload) }),
  bulkDetections: (payload: {
    detection_ids: string[];
    action: "delete" | "archive" | "mark_reviewed" | "mark_false_positive";
    case_id?: string;
    engine?: string;
    severity?: string;
    status?: string;
    rule_name?: string;
    evidence_id?: string;
    has_linked_event?: boolean;
    has_file_target?: boolean;
  }) =>
    request<{ updated: number }>("/detections/bulk", { method: "POST", body: JSON.stringify(payload) }),
  getDetectionEvent: (detectionId: string) => request<Record<string, unknown>>(`/detections/${detectionId}/event`),
  promoteDetectionToFinding: (detectionId: string) => request<Finding>(`/detections/${detectionId}/promote-to-finding`, { method: "POST" }),
  getSystemStatus: () => request<SystemStatus>("/system/status"),
  getSystemVersion: () => request<SystemVersionInfo>("/system/version"),
  getSystemSettings: () => request<SystemSettingsResponse>("/system/settings"),
  updateSystemSettings: (settings: Record<string, unknown>) =>
    request<SystemSettingsPatchResponse>("/system/settings", { method: "PATCH", body: JSON.stringify({ settings }) }),
  resetSystemSettings: () => request<SystemSettingsPatchResponse>("/system/settings/reset", { method: "POST" }),
  getAdminPerformance: () => request<PerformanceState>("/admin/performance"),
  getAdminPerformanceResources: () => request<PerformanceState["resources"]>("/admin/performance/resources"),
  updateAdminPerformance: (payload: { profile: string; settings?: Record<string, unknown>; confirm_max?: boolean }) =>
    request<PerformancePatchResponse>("/admin/performance", { method: "PATCH", body: JSON.stringify(payload) }),
  applyAdminPerformance: (payload: { profile: string; settings?: Record<string, unknown>; confirm_max?: boolean }) =>
    request<PerformancePatchResponse>("/admin/performance/apply", { method: "POST", body: JSON.stringify(payload) }),
  applyAdminPerformanceProfile: (payload: { profile: string; settings?: Record<string, unknown>; confirm_max?: boolean }) =>
    request<PerformancePatchResponse>("/admin/performance/apply-profile", { method: "POST", body: JSON.stringify(payload) }),
  applyAdminPerformanceRecommended: (payload?: { confirm_max?: boolean }) =>
    request<PerformancePatchResponse>("/admin/performance/apply-recommended", { method: "POST", body: JSON.stringify(payload ?? {}) }),
  restartAdminPerformance: (services: string[]) =>
    request<PerformanceRestartResponse>("/admin/performance/restart", { method: "POST", body: JSON.stringify({ services }) }),
  getAdminPerformanceRestartInstructions: () =>
    request<{
      restart_supported: boolean;
      restart_method: string;
      services_to_restart: string[];
      restart_instructions: NonNullable<PerformanceState["restart_instructions"]>;
    }>("/admin/performance/restart-instructions"),
  getAdminPerformanceRecommendation: () => request<PerformanceState["recommendation"]>("/admin/performance/recommendation"),
};
