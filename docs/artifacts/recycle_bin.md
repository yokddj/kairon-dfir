# Recycle Bin

## What the app supports

- `RBCmd_Output.csv` and compatible variants
- raw Velociraptor artifacts:
  - `$Recycle.Bin\<SID>\$I*`
  - `$Recycle.Bin\<SID>\$R*`

## What `$I` and `$R` are

- `$I*` stores metadata about the recycled item:
  - original size
  - deletion date/time
  - original path
- in modern Windows versions it usually includes:
  - `version`
  - `original file size`
  - `deletion FILETIME`
  - path length or related metadata
  - original path in `UTF-16LE`
- `$R*` is the recycled content.
- If `$I` and `$R` share a suffix, the app pairs them as the same logical candidate.

## What RBCmd provides

RBCmd already delivers most of the useful Recycle Bin metadata in CSV form and is the most convenient path when parsed output already exists.

## What is parsed directly from Velociraptor

The app already parses directly:

- raw `$I`
- `$I/$R` pairing
- orphan `$R` as partial evidence

If the original path cannot be resolved from the main offset, the app attempts a fallback by searching for a `UTF-16LE` string that looks like a real Windows path within the blob.

## What fields are extracted

- `recycle.original_path`
- `recycle.original_file_name`
- `recycle.original_size`
- `recycle.deleted_time`
- `recycle.sid`
- `recycle.i_file_path`
- `recycle.r_file_path`
- `recycle.has_i_file`
- `recycle.has_r_file`
- `recycle.pair_id`
- `recycle.version`
- `recycle.drive_letter`
- `recycle.content_status`

The following are also filled:

- `file.path`
- `file.name`
- `file.extension`
- `file.size`
- `file.deleted_time`
- `user.sid`
- `user.name` when it can be inferred

## How to interpret `deleted_time`

The main event time is the recycle date/time observed in `$I` or in the RBCmd output.

This means:

- evidence of being sent to the Recycle Bin
- does not prove permanent deletion
- does not by itself guarantee when the file was executed

## What `content_missing` means

- `content_missing_confirmed`: `$I` was found, but the corresponding `$R` does not exist in the collection
- `present`: the corresponding `$R` exists

The absence of `$R` does not by itself imply malicious activity. It can be due to prior cleanup or an incomplete collection.

## What `original_path_extracted_by_utf16_fallback` means

This is a parsing warning indicating that:

- the main offset of `$I` did not produce a valid path
- the app found a plausible Windows path by scanning the `UTF-16LE` blob
- the resulting path is useful for investigation, but should be validated against other artifacts

## What `invalid_recycle_original_path` means

This is set when:

- the parser obtains a value that does not look like a valid Windows path
- or it fails to extract a useful path even with the fallback

In that case the app:

- does not index garbage values like `5`, `^`, or a single letter as `file.path`
- keeps the rest of the useful metadata (`SID`, size, deleted_time, source file)
- shows the event as observed metadata, not as a fully recycled item with a reliable path

## How to interpret SID and user

- the SID usually comes from the `$Recycle.Bin\<SID>\...` path
- if resolution with other artifacts exists, the app can enrich `user.name`
- otherwise, it keeps `user.sid` and marks the data quality as unresolved

## Correlations the app makes

- `Recycle Bin -> MFT/USN`
- `Recycle Bin -> Browser downloads`
- `Recycle Bin -> LNK / Jump Lists`
- `Recycle Bin -> Defender`
- `Recycle Bin -> PowerShell`
- `Recycle Bin -> Prefetch / Amcache`
- `Recycle Bin -> Scheduled Tasks`

Derived activities:

- `file_recycled`
- `deleted_download`
- `deleted_detected_file`
- `deleted_executable`
- `deleted_script`
- `cleanup_candidate`

## Common false positives

- legitimate downloads discarded by the user
- temporary administration or development scripts
- legitimate software deleted manually
- partial collections missing `$R`

## Limitations

- Recycle Bin does not equal permanent deletion
- `$R` may be missing due to partial collection or prior cleanup
- SID may not resolve to a name
- some deletions never go through the Recycle Bin
- the app does not compute large hashes of `$R` content by default
- some `$I` files may require `UTF-16LE` fallback if the specific variant does not match the expected layout

## Investigation examples

- download sent to the Recycle Bin after execution
- payload detected by Defender and then recycled
- script used from PowerShell and then deleted
- `$I` metadata present without `$R`, possible partial evidence cleanup
