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
| macOS (UAC) | Experimental: UAC collections of a Mac, parsed from a closed list of macOS artifacts. With Auto-detect, a UAC collection whose `uac.log` says `macos` is detected as macOS; see [macOS Support](../macos/macos-support.md). |
| Unknown / Other | Accepted for unclear or non-OS-specific evidence. |

## Detection Scope

Platform detection is intentionally lightweight. It looks for common path and filename markers such as Windows event logs, registry hives, Linux `/var/log` or `/etc/passwd`, and macOS plist or Library paths. It does not mount disk images, execute uploaded binaries, or run full OS-specific parsers.

If the analyst selects a concrete platform, that selection becomes the effective platform. If the analyst leaves Auto-detect selected, the detected platform becomes effective, or `unknown` when detection has no confident signal.

## Parser Coverage

Platform selection does not imply full parser coverage. Windows has the broadest support today; Linux is covered in [Linux Support](../linux/linux-support.md); macOS is limited to UAC collections and the artifacts listed in [macOS Support](../macos/macos-support.md).

A UAC collection is recognised by its own `uac.log`, and the operating system UAC recorded there (`macos` or `linux`) decides the detected platform, ahead of path markers.
