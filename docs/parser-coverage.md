# Parser Coverage

This page is a human-readable summary of Kairon's structured parser
coverage data. The authoritative, machine-readable source is
[`docs/data/parser-coverage.json`](data/parser-coverage.json), which the
in-app Parser Coverage page (`/parsers`) renders directly — this document
and the app UI describe the same data, never a separate claim.

Each entry in the JSON records, per artifact family: status
(`stable` / `partial` / `experimental` / `planned` / `unsupported` /
`deprecated`), the input formats and filenames it recognizes, which views
it feeds (Artifact Explorer, Search, Timeline, Command History, Memory
views, etc.), its normalized fields, and its known limitations. Statuses
are kept honest on purpose — `partial` and `experimental` mean exactly
that, not "coming soon."

## Collector Compatibility

Kairon parses the *output* of third-party forensic collection tools; it does not run them and does not redistribute third-party collector binaries. Supported collector output includes:

- **KAPE** — Windows triage collections and individual KAPE module output
  (EZ Tools CSVs, raw artifact files).
- **Velociraptor** — ZIP collection containers, including nested
  `uploads/` trees, CSV/JSON artifact results, and EVTX exports.
- Manually assembled ZIP/TAR collections following a conventional
  filesystem layout (e.g. Linux triage folders with `var/log/`,
  `etc/`, and user home directories).

An operator brings their own collector run (KAPE, Velociraptor, or a
manual triage script); Kairon ingests and normalizes what that collector
already produced.

## Where to look for detail

- `docs/data/parser-coverage.json` — the full per-family record, kept in
  sync with the in-app Parser Coverage page.
- `docs/linux-support.md` — Linux-specific ingestion and memory coverage.
- `docs/KNOWN_LIMITATIONS.md` — cross-cutting limitations not tied to a
  single parser family.
