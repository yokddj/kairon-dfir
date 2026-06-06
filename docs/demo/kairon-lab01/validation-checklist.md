# Validation Checklist

Use this checklist to confirm that Kairon DFIR handles the lab evidence in a useful way.

- [ ] The Velociraptor ZIP ingests without critical errors.
- [ ] Processing creates searchable events or artifacts.
- [ ] Search finds `KAIRON-LAB01`.
- [ ] Search finds `analyst`.
- [ ] Search finds `KaironLab01`.
- [ ] Search finds `EncodedCommand`.
- [ ] Search finds `KaironLab01Updater`.
- [ ] Search finds `KaironLab01Run`.
- [ ] Search finds `KAIRON-LAB01-MARKER`.
- [ ] Search finds `KAIRON-LAB01-RUNKEY-MARKER`.
- [ ] Timeline views allow the activity to be ordered chronologically.
- [ ] Artifact Explorer helps locate created files where filesystem artifacts were collected.
- [ ] Command History shows relevant PowerShell or `cmd.exe` activity if supported by the collected artifacts.
- [ ] Detections show signals related to PowerShell, scheduled tasks or Run Keys if matching rules exist and have been run.
- [ ] Raw artifacts can be used to validate parser output where applicable.
- [ ] The user can reconstruct a coherent investigation narrative from the interface.
- [ ] This documentation is sufficient to complete the case without external explanation.

If a check fails, review collection scope, parser support, indexing logs and feature flags before treating the lab evidence as incorrect.
