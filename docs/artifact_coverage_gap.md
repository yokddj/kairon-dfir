# Artifact Coverage Gap

The canonical artifact status is now maintained in:

- [artifacts_matrix.md](artifacts_matrix.md)
- [feature_map.md](feature_map.md)
- [parser_backends.md](parser_backends.md)

## Current priority gaps

| Priority | Artifact / area | Current state | Reason | Next action |
| --- | --- | --- | --- | --- |
| P1 | SRUM | detected, not parsed | SrumECmd requires Windows ESE libraries on this deployment | SRUM Windows Worker Parser v1 |
| P1 | Shellbags | raw hives detected, not parsed as Shellbags | backend not active | Shellbags Parser v1 |
| P2 | USN Journal | not stable by default | no active UsnJrnl2Csv backend | Decide backend/selection strategy |
| P2 | EZ Tool defaults | advanced only for LNK/Jumplist/Amcache/Shimcache | richer fields but default activation not decided | EZ Backend Default Activation Decision |
| P3 | Prefetch PECmd | disabled for raw `.pf` on Linux | Windows decompression dependency | Keep internal parser or move to Windows worker |

