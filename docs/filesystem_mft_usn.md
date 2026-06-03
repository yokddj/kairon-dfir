# MFT / Filesystem

`$MFT` is the NTFS master file table. It records file and directory metadata: names, paths, sizes, flags and timestamps.

## Current support

- Raw `$MFT` detection: stable.
- MFTECmd backend: stable.
- MFT summary indexing: stable, capped/high-value selection.
- MFT full indexing: stable advanced action.
- Search over MFT: stable.
- Artifact Views MFT / Filesystem: stable.
- Timeline: opt-in for MFT/filesystem to avoid flooding.
- USN Journal raw parsing: not stable in this deployment; no active UsnJrnl2Csv backend.

## Summary versus full

Summary mode indexes a high-value subset for fast triage:

- known case indicators
- suspicious extensions
- user-writable paths
- deleted/not-in-use entries
- incident-window rows where known
- representative samples

Full mode indexes all MFTECmd rows for the evidence. It is explicit/advanced because it can add hundreds of thousands of filesystem records.

## Normalized fields

Common fields:

- `artifact.type = mft`
- `artifact.parser = mftecmd_csv`
- `source_file`
- `file.path`
- `file.name`
- `file.extension`
- `file.directory`
- `file.size`
- `file.is_directory`
- `file.deleted`
- `file.profile_user`
- `mft.record_number`
- `mft.sequence_number`
- `mft.parent_record_number`
- `mft.flags`
- `mft.in_use`
- `mft.created_time`
- `mft.modified_time`
- `mft.mft_modified_time`
- `mft.accessed_time`
- `mft.fn_created_time`
- `mft.fn_modified_time`
- `mft.fn_mft_modified_time`
- `mft.fn_accessed_time`
- `mft.summary_score`
- `mft.summary_reasons`

Raw row fields are preserved in controlled raw structures where available.

## Search behavior

Search supports:

- `artifact_type=mft`
- filename/path query, such as `sample.iso`
- `file.extension=iso`
- `file.deleted`
- profile user
- path fragments like `Users\Public` or `Temp`
- MFT record number where exposed

If full MFT is indexed, global Search can find filenames and paths present in MFT. If a file does not appear, verify whether it exists in the MFTECmd source before treating it as a selection bug.

## Timeline behavior

MFT is excluded from default Timeline. Use one of:

- `artifact_type=mft`
- `include_filesystem_timeline=true`
- `Open timeline` from MFT Artifact View

## Interpretation

MFT proves metadata was present in the filesystem table. It does not always prove:

- execution
- user interaction
- recent deletion
- attacker action

Correlate with:

- Security 4688 / Sysmon 1
- Command History
- Prefetch
- LNK/Jumplist
- Defender
- User Activity
- Browser downloads

## Limitations

- `InUse=false` is a deleted/not-in-use candidate, not guaranteed recent deletion.
- `$SI` versus `$FN` timestamp differences require manual interpretation.
- Full MFT volume can be large.
- USN Journal support is not a stable default feature in this deployment.

