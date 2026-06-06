# Kairon Lab 01 - Suspicious PowerShell Activity

Kairon Lab 01 is a public Windows DFIR demonstration case for Kairon DFIR. It is based on a controlled Velociraptor collection from a laboratory host and is designed to help analysts test the platform with realistic forensic artifacts.

This is not a real malware case and should not be described as one. The activity is benign, reproducible and intentionally crafted to leave evidence that can be ingested, searched, pivoted and validated inside Kairon DFIR.

## What You Can Test

Use this case to evaluate how Kairon DFIR helps reduce investigation friction:

- ingest a Velociraptor ZIP collection into a case;
- centralize parsed and raw artifacts from one Windows host;
- search across host, user, command, path and marker strings;
- reconstruct activity in a timeline;
- pivot between Search, Artifact Explorer, Command History, Detections and raw artifacts;
- validate findings using multiple artifact sources where available.

The goal is not automatic attribution or perfect detection. The goal is to show how Kairon DFIR gives analysts a structured workspace for asking questions, finding evidence and documenting conclusions.

## Evidence

Load the Velociraptor ZIP collection for the lab host:

- expected host: `KAIRON-LAB01`
- expected user: `analyst`
- main lab directory: `C:\Users\analyst\Documents\KaironLab01`

Depending on the collection profile and parser support, some artifact sources listed in this case may not be visible. If an expected artifact is not visible, check parser support, collection scope and indexing logs before treating it as absent from the system.

## Start The Investigation

1. Create a new case in Kairon DFIR.
2. Upload the Velociraptor ZIP evidence.
3. Set or confirm the expected host as `KAIRON-LAB01` if the workflow asks for canonical host identity.
4. Run the recommended indexing action for investigation.
5. Review the evidence processing summary and parser warnings.
6. Begin with Search queries for `KAIRON-LAB01`, `analyst`, `KaironLab01`, `KAIRON-LAB01-MARKER` and `KAIRON-LAB01-RUNKEY-MARKER`.

## Useful Kairon DFIR Views

- Case ingest: upload evidence, monitor processing and review parser errors.
- Artifact Explorer: inspect artifact families and locate created files, registry entries, scheduled tasks and execution traces.
- Investigation Timeline: order events and build a narrative from isolated observations.
- Search: pivot quickly across normalized artifacts.
- Detections: review PowerShell, scheduled task or Run Key signals if matching rules exist and have been run.
- Command History: review observed command lines and process launch context if available.
- Raw artifacts: validate parser output against collected source files when needed.

## Case Documents

- [Scenario](scenario.md)
- [Investigation guide](investigation-guide.md)
- [Questions](questions.md)
- [Expected findings](expected-findings.md)
- [Validation checklist](validation-checklist.md)
- [Lab indicators](iocs.md)
- [Artifact map](artifact-map.md)
