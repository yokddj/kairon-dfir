"""Host Facts derived from Windows memory analysis (Volatility windows.info).

Consumes the already-normalized output of
app.services.memory.normalizers.normalize_windows_info() -- this module
never touches raw Volatility payloads itself, so it stays correct
regardless of how that normalizer's field extraction evolves.

Deliberately NOT read from windows.info for Host Facts:

- ``host.name`` in the normalized document. It is fed by
  _host_name()'s fallback chain, whose only key that is ever actually
  present in a real windows.info payload is ``NtProductType`` -- a Windows
  product-type enum string (e.g. "NtProductWinNt"), not a computer name.
  Treating it as a hostname would be exactly the kind of invented fact
  this producer must not create; app.ingest.windows.host_facts (EVTX) and
  app.ingest.raw_parsers.system_hive_identity_parser (SYSTEM hive) are the
  real hostname/FQDN sources.
- ``memory.system_time``. That is the instant the memory image was
  acquired, not the machine's configured timezone -- windows.info exposes
  no genuine timezone field at all, so this producer never emits
  host.timezone.
- host.kernel. For Windows the NT kernel version and the OS version are
  the same number (unlike Linux, where the kernel release and the distro
  version are genuinely different axes) -- os.kernel_version already
  becomes host.distribution_version below, so populating host.kernel with
  the identical string would be a duplicate label, not new information.

What IS treated as reliable enough to observe:

- os.family ("windows") -> host.distribution = "Windows". Not an
  inference: normalize_windows_info() only ever runs on a successfully
  parsed windows.info result, which cannot exist over a non-Windows
  kernel image -- the field is a structural fact about which plugin
  produced this document, not a name Volatility read out of memory.
- os.kernel_version (NT major.minor.build, e.g. "10.0.22621", already
  computed by the normalizer from NtMajorVersion/NtMinorVersion/the
  Major/Minor build field) -> host.distribution_version. This is a
  version/build string, never a marketing edition name ("Windows 11 Pro")
  -- that would require SOFTWARE hive ProductName/EditionID, which memory
  analysis does not expose.
- os.machine_type ("x64"/"x86"/"ARM64"/...), already decoded by the
  normalizer from the PE/KUSER_SHARED_DATA MachineType code -> host
  .architecture. This is the OS's own reported architecture, not a
  per-process PE32/PE64 guess.
"""
from __future__ import annotations

from app.ingest.linux.os_info import FACT_ARCHITECTURE, FACT_DISTRIBUTION, FACT_DISTRIBUTION_VERSION

SOURCE_KIND_MEMORY_WINDOWS_INFO = "memory_windows_info"


def _fact(*, fact_type: str, raw_value: str, normalized_value: str, run_id: str, plugin_run_id: str, plugin: str) -> dict:
    return {
        "fact_type": fact_type,
        "artifact_family": "memory_windows_info",
        "artifact_type": SOURCE_KIND_MEMORY_WINDOWS_INFO,
        "source_file": f"memory:{plugin}",
        "raw_value": raw_value,
        "normalized_value": normalized_value,
        # windows.info reads kernel-internal structures directly (KDBG /
        # KUSER_SHARED_DATA) rather than a persisted configuration file --
        # a genuine observation, but of a single point-in-time snapshot,
        # not the machine's own record of itself the way a registry hive
        # is. See _SOURCE_PRIORITY in app.services.host_facts: this ranks
        # below both the EVTX Computer field and the SYSTEM hive for the
        # facts they share.
        "confidence": "medium",
        "parse_status": "valid",
        "reason": "",
        "extra_provenance": {
            "memory_run_id": run_id,
            "memory_plugin_run_id": plugin_run_id,
            "plugin": plugin,
        },
    }


def extract_memory_windows_host_facts(system_info: dict) -> list[dict]:
    """Derive Host Fact observations from one normalize_windows_info() result.

    Returns inline-tagged synthetic documents (doc["host_fact"] set
    directly) in the same shape app.ingest.host_facts_extraction expects
    from any inline producer -- the caller passes these through
    extract_host_fact_documents() exactly like every other platform's
    documents, so this module needs no registration of its own and
    app.ingest.host_facts_extraction never changes for it.
    """
    os_info = system_info.get("os") or {}
    plugin = str(system_info.get("plugin") or "windows.info")
    run_id = str(system_info.get("memory_run_id") or "")
    plugin_run_id = str(system_info.get("memory_plugin_run_id") or "")

    facts: list[dict] = []

    family = str(os_info.get("family") or "").strip().lower()
    if family == "windows":
        facts.append(
            _fact(
                fact_type=FACT_DISTRIBUTION,
                raw_value="Windows",
                normalized_value="Windows",
                run_id=run_id,
                plugin_run_id=plugin_run_id,
                plugin=plugin,
            )
        )

    kernel_version = str(os_info.get("kernel_version") or "").strip()
    if kernel_version:
        facts.append(
            _fact(
                fact_type=FACT_DISTRIBUTION_VERSION,
                raw_value=kernel_version,
                normalized_value=kernel_version,
                run_id=run_id,
                plugin_run_id=plugin_run_id,
                plugin=plugin,
            )
        )

    machine_type = str(os_info.get("machine_type") or "").strip()
    if machine_type:
        facts.append(
            _fact(
                fact_type=FACT_ARCHITECTURE,
                raw_value=machine_type,
                normalized_value=machine_type,
                run_id=run_id,
                plugin_run_id=plugin_run_id,
                plugin=plugin,
            )
        )

    documents = []
    for fact in facts:
        documents.append({"host_fact": fact, "event_id": None, "source_file": fact["source_file"]})
    return documents
