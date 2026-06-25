import { useState } from "react";
import { api } from "../../api/client";
import type {
  MemoryRecoveryResult,
  MemoryRecoverySourceCreate,
  MemoryRecoverySourceRead,
} from "../../api/client";

type Tab = "import-pdb" | "import-isf" | "import-package" | "configure";

type Props = {
  requirementId: string;
  caseId: string;
  evidenceId: string;
  onCompleted: (result: MemoryRecoveryResult) => void;
};

/**
 * Administrator-only symbol import panel.  The button is rendered
 * by the parent blocked-symbols card; this component owns the
 * modal flow.
 *
 * Security: every upload is sent as a multipart/form-data
 * request.  The backend enforces:
 * - file size cap (configured server-side)
 * - exact identity match (no client-supplied GUID/age accepted)
 * - quarantine + atomic promotion
 */
export function MemorySymbolImportPanel({
  requirementId,
  onCompleted,
}: Props) {
  const [open, setOpen] = useState(false);
  const [tab, setTab] = useState<Tab>("import-pdb");
  const [file, setFile] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<MemoryRecoveryResult | null>(null);
  const [sources, setSources] = useState<MemoryRecoverySourceRead[] | null>(
    null,
  );

  async function loadSources() {
    try {
      const rows = await api.listRecoverySources();
      setSources(rows);
    } catch (err) {
      // Non-admin users will get a 4xx; the tab is hidden for them
      // in production by the parent component.  We silently fail.
      setSources([]);
    }
  }

  if (!open) {
    return (
      <button
        type="button"
        onClick={() => {
          setOpen(true);
          void loadSources();
        }}
        data-testid="memory-symbol-import-open"
        className="rounded border border-slate-300 px-3 py-1 text-xs"
      >
        Import exact symbol
      </button>
    );
  }

  async function submitPdb() {
    if (!file) {
      setError("Select a PDB file first.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const r = await api.importPdb(requirementId, file);
      setResult(r);
      onCompleted(r);
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(false);
    }
  }

  async function submitIsf() {
    if (!file) {
      setError("Select an ISF file first.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const r = await api.importIsf(requirementId, file);
      setResult(r);
      onCompleted(r);
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(false);
    }
  }

  async function submitPackage() {
    if (!file) {
      setError("Select a package file first.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const r = await api.importPackage(file);
      // The package import returns a slightly different shape; we
      // adapt it to the standard MemoryRecoveryResult.
      setResult({
        status: r.status as MemoryRecoveryResult["status"],
        requirement_id: requirementId,
        attempts: [],
        cached_symbol_id: null,
        error_code: r.error_code ?? null,
        sanitized_message: r.sanitized_message ?? null,
        identity_expected: null,
        identity_observed: null,
      });
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(false);
    }
  }

  async function submitNewSource(payload: MemoryRecoverySourceCreate) {
    setBusy(true);
    setError(null);
    try {
      await api.createRecoverySource(payload);
      await loadSources();
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div
      className="fixed inset-0 z-40 flex items-center justify-center bg-slate-900/50 p-4"
      data-testid="memory-symbol-import-panel"
    >
      <div className="w-full max-w-2xl rounded-md bg-white p-6 shadow-lg">
        <header className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold">Exact symbol recovery</h2>
          <button
            type="button"
            onClick={() => {
              setOpen(false);
              setFile(null);
              setError(null);
              setResult(null);
            }}
            className="text-slate-500 hover:text-slate-900"
            aria-label="Close"
          >
            ×
          </button>
        </header>
        <nav className="mb-4 flex gap-2 border-b border-slate-200">
          {(
            [
              ["import-pdb", "Import PDB"],
              ["import-isf", "Import ISF"],
              ["import-package", "Offline package"],
              ["configure", "Corporate source"],
            ] as Array<[Tab, string]>
          ).map(([key, label]) => (
            <button
              key={key}
              type="button"
              onClick={() => setTab(key)}
              className={`px-3 py-2 text-sm ${
                tab === key
                  ? "border-b-2 border-sky-600 font-medium text-sky-700"
                  : "text-slate-600"
              }`}
              data-testid={`memory-symbol-import-tab-${key}`}
            >
              {label}
            </button>
          ))}
        </nav>

        {error && (
          <p
            className="mb-3 rounded bg-rose-50 px-3 py-2 text-sm text-rose-700"
            data-testid="memory-symbol-import-error"
          >
            {error}
          </p>
        )}

        {result && (
          <p
            className={`mb-3 rounded px-3 py-2 text-sm ${
              result.status === "ready"
                ? "bg-emerald-50 text-emerald-700"
                : "bg-amber-50 text-amber-700"
            }`}
            data-testid="memory-symbol-import-result"
          >
            {result.status === "ready"
              ? "Exact match accepted. Preparation is now ready."
              : `Rejected (${result.error_code ?? "?"}): ${result.sanitized_message ?? ""}`}
          </p>
        )}

        {tab === "import-pdb" && (
          <div>
            <p className="mb-2 text-sm text-slate-600">
              Upload the PDB for the exact required symbol.  The file's
              name, GUID, age, and architecture are parsed and compared
              to the requirement — a mismatch is rejected.
            </p>
            <input
              type="file"
              accept=".pdb"
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              data-testid="memory-symbol-import-file-pdb"
            />
            <button
              type="button"
              onClick={submitPdb}
              disabled={busy || !file}
              className="ml-2 rounded bg-sky-600 px-3 py-1 text-sm text-white disabled:opacity-50"
              data-testid="memory-symbol-import-submit-pdb"
            >
              {busy ? "Uploading..." : "Import PDB"}
            </button>
          </div>
        )}

        {tab === "import-isf" && (
          <div>
            <p className="mb-2 text-sm text-slate-600">
              Upload an ISF (JSON or JSON.xz) that already contains
              the required PDB identity.
            </p>
            <input
              type="file"
              accept=".isf,.json,.xz"
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              data-testid="memory-symbol-import-file-isf"
            />
            <button
              type="button"
              onClick={submitIsf}
              disabled={busy || !file}
              className="ml-2 rounded bg-sky-600 px-3 py-1 text-sm text-white disabled:opacity-50"
              data-testid="memory-symbol-import-submit-isf"
            >
              {busy ? "Uploading..." : "Import ISF"}
            </button>
          </div>
        )}

        {tab === "import-package" && (
          <div>
            <p className="mb-2 text-sm text-slate-600">
              Upload a controlled offline zip package of PDBs and
              ISFs.  The package is validated for traversal and
              decompression-bomb protections.
            </p>
            <input
              type="file"
              accept=".zip"
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              data-testid="memory-symbol-import-file-package"
            />
            <button
              type="button"
              onClick={submitPackage}
              disabled={busy || !file}
              className="ml-2 rounded bg-sky-600 px-3 py-1 text-sm text-white disabled:opacity-50"
              data-testid="memory-symbol-import-submit-package"
            >
              {busy ? "Uploading..." : "Import package"}
            </button>
          </div>
        )}

        {tab === "configure" && (
          <ConfigureCorporateSource
            sources={sources}
            onCreate={submitNewSource}
            busy={busy}
          />
        )}
      </div>
    </div>
  );
}

function ConfigureCorporateSource({
  sources,
  onCreate,
  busy,
}: {
  sources: MemoryRecoverySourceRead[] | null;
  onCreate: (payload: MemoryRecoverySourceCreate) => void;
  busy: boolean;
}) {
  const [host, setHost] = useState("");
  const [pathPrefix, setPathPrefix] = useState("/symbols");
  const [name, setName] = useState("");
  const [priority, setPriority] = useState(100);

  return (
    <div data-testid="memory-symbol-configure-source">
      <p className="mb-2 text-sm text-slate-600">
        Configure a corporate or SymProxy symbol server.  The host and
        path prefix are frozen at creation time and used by the
        recovery orchestrator exactly as configured.
      </p>
      <ul className="mb-3 max-h-32 overflow-y-auto rounded border border-slate-200 bg-slate-50 p-2 text-xs">
        {(sources ?? []).map((s) => (
          <li key={s.id}>
            <strong>{s.name}</strong> · {s.host} {s.path_prefix} · priority {s.priority}
          </li>
        ))}
        {sources !== null && sources.length === 0 && (
          <li className="italic text-slate-500">No corporate sources configured.</li>
        )}
      </ul>
      <div className="grid grid-cols-2 gap-2 text-sm">
        <label className="flex flex-col">
          <span className="text-xs text-slate-500">Name</span>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="rounded border border-slate-300 px-2 py-1"
            data-testid="memory-symbol-source-name"
          />
        </label>
        <label className="flex flex-col">
          <span className="text-xs text-slate-500">Priority</span>
          <input
            type="number"
            value={priority}
            onChange={(e) => setPriority(Number(e.target.value))}
            className="rounded border border-slate-300 px-2 py-1"
            data-testid="memory-symbol-source-priority"
          />
        </label>
        <label className="flex flex-col">
          <span className="text-xs text-slate-500">Host</span>
          <input
            value={host}
            onChange={(e) => setHost(e.target.value)}
            placeholder="symproxy.example.com"
            className="rounded border border-slate-300 px-2 py-1"
            data-testid="memory-symbol-source-host"
          />
        </label>
        <label className="flex flex-col">
          <span className="text-xs text-slate-500">Path prefix</span>
          <input
            value={pathPrefix}
            onChange={(e) => setPathPrefix(e.target.value)}
            className="rounded border border-slate-300 px-2 py-1"
            data-testid="memory-symbol-source-path"
          />
        </label>
      </div>
      <button
        type="button"
        disabled={busy || !host || !name || !pathPrefix.startsWith("/")}
        onClick={() =>
          onCreate({
            source_type: "corporate_symbol_server",
            name,
            host,
            path_prefix: pathPrefix,
            priority,
            port: 443,
            tls_required: true,
          })
        }
        className="mt-2 rounded bg-sky-600 px-3 py-1 text-sm text-white disabled:opacity-50"
        data-testid="memory-symbol-source-submit"
      >
        {busy ? "Saving..." : "Add corporate source"}
      </button>
    </div>
  );
}
