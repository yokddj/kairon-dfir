# Evidence Platform Selection

Kairon records three platform fields for evidence uploads:

| Field | Meaning |
| --- | --- |
| `provided_platform` | Analyst selection at upload or path registration time. Defaults to `auto`. |
| `detected_platform` | Lightweight inference from filename and container paths. |
| `effective_platform` | Platform used for routing and display. This is never `auto`. |

## Options

| Option | Status |
| --- | --- |
| Auto-detect | Default. Uses path and filename markers to infer Windows, Linux, macOS or unknown. |
| Windows | Supported for current Windows artifact parsers. |
| Linux | Accepted, but Linux parser coverage is limited. Unsupported artifacts may be preserved without parsed events. |
| macOS | Planned. The UI shows it as disabled, and direct API selection is rejected with `400`. |
| Unknown / Other | Accepted for unclear or non-OS-specific evidence. |

## Detection Scope

Platform detection is intentionally lightweight. It looks for common path and filename markers such as Windows event logs, registry hives, Linux `/var/log` or `/etc/passwd`, and macOS plist or Library paths. It does not mount disk images, execute uploaded binaries, or run full OS-specific parsers.

If the analyst selects a concrete platform, that selection becomes the effective platform. If the analyst leaves Auto-detect selected, the detected platform becomes effective, or `unknown` when detection has no confident signal.

## Parser Coverage

Platform selection does not imply full parser coverage. Windows has the broadest support today. Linux support is limited to accepted ingestion and future parser expansion. macOS support is planned but not enabled.
