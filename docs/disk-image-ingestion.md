# Disk Image Ingestion

## Scope in this phase

Implemented now:

- RAW disk images: `.dd`, `.img`, `.raw`
- RAW detection by content where possible
- EWF uploads: `.E01`, `.Ex01`, segmented `E01/E02/E03/...`
- MBR partition discovery
- GPT partition discovery
- Filesystem-image without partition table
- Multiple volume discovery
- Windows and Linux installation detection
- Reuse of existing Windows/Linux artifact discovery, parsers, normalizers, indexing, search and timeline

Prepared but not supported yet:

- VMDK
- VHD/VHDX
- QCOW/QCOW2
- VDI
- AFF/AFF4
- L01
- AD1
- RAID
- APFS/HFS+
- BitLocker unlock
- LUKS unlock

## Architecture

High-level flow:

Upload
-> Image format detection
-> Hash original evidence
-> Read-only image inspection
-> Partition and volume discovery
-> Filesystem exposure
-> Operating system detection
-> Existing Windows/Linux discovery
-> Existing parsers
-> Existing normalization
-> Existing indexing

The new layer does not add alternate artifact parsers. It converts disk images into traceable filesystem sources.

## Core Components

### Domain models

- `DiskImage`
- `DiskVolume`
- `OSInstallation`

Artifacts now carry provenance fields linking back to:

- disk image
- disk volume
- OS installation
- original path inside the filesystem
- logical materialized path
- acquisition method

### Format registry

`backend/app/disk_images/registry.py`

Defines a central `ImageFormatRegistry` and adapters:

- `RawImageAdapter`
- `EwfImageAdapter`

Unsupported future formats are registered explicitly as unsupported, not silently ignored.

### Read-only access

Current implementation:

- RAW: direct read-only access through `pytsk3`
- EWF: validated segment set, then controlled `ewfexport` to a temporary RAW file, then read-only access through `pytsk3`

This EWF export is a current limitation, not the final long-term architecture.

## Security Model

- original evidence is treated as immutable
- no write mount
- no automount
- no content execution
- no `shell=True`
- subprocess arguments are passed as lists
- temporary workspaces are unique per evidence
- cleanup runs in `finally`
- nested/temporary export files are removed after use
- path materialization uses sanitization and destination-root checks
- segment grouping rejects inconsistent or incomplete sets

## States

The ingest flow reports detailed disk-image actions through progress metadata, including:

- `hashing`
- `detecting_format`
- `validating_segments`
- `inspecting_image`
- `discovering_volumes`
- `detecting_operating_systems`
- `discovering_artifacts`

The persisted disk image row also records its own status.

## Errors

The first phase distinguishes at least:

- `unknown_format`
- `unsupported_format`
- `missing_dependency`
- `missing_segment`
- `duplicate_segment`
- `invalid_segment_set`
- `unsupported_filesystem`
- `encrypted_volume`
- `unreadable_volume`
- `corrupt_image`

## RAW

RAW detection combines:

- MBR signature
- GPT signature
- filesystem signatures such as FAT/NTFS/ext
- extension fallback

RAW can be either:

- full disk image with partition table
- filesystem image without partition table

## EWF

Current EWF behavior:

- detect EWF by signature and extension
- group sibling segments in the same directory
- validate contiguous numbering
- reject duplicates and missing segments
- use `ewfexport` to a temporary RAW representation
- process the exported RAW through the common RAW pipeline

## Filesystem and OS discovery

The current volume layer supports:

- MBR
- GPT
- filesystem image without partition table
- multiple readable or unreadable volumes
- encrypted volume detection by recognizable signatures

OS detection is content-based:

Windows markers:

- `/Windows/System32`
- `/Windows/System32/config/SYSTEM`
- `/Windows/System32/config/SOFTWARE`
- `/Users`
- `/ProgramData`

Linux markers:

- `/etc/os-release`
- `/etc/passwd`
- `/var/log`
- `/var/lib/systemd`
- `/home`
- `/boot`

## Reuse of existing pipelines

Once files are materialized from a detected installation, the following are reused unchanged:

- Windows discovery
- Linux discovery
- artifact registry
- parsers
- normalizers
- indexing
- Search
- Timeline

## Readiness

`/api/system/status` now reports disk image adapter readiness and tool visibility.

Examples:

- RAW adapter ready when `pytsk3` is available
- EWF adapter ready when `ewfinfo` and `ewfexport` are available

Optional dependencies do not mark the whole system unhealthy.

## Creating test fixtures

The test suite generates minimal deterministic fixtures on the fly using small FAT filesystem images and partitioned disk images.

Tools used for fixture generation in tests:

- `mkfs.vfat`
- `mtools`
- `parted`
- `ewfacquire`

This avoids storing large binary fixtures in Git.

## Troubleshooting

If a disk image returns zero artifacts, check:

1. format detection result
2. adapter readiness in `/api/system/status`
3. segment validation for EWF
4. discovered volumes and whether they are readable
5. OS installations detected
6. per-volume warnings/errors

If EWF is recognized but not processed, verify that:

- `ewfinfo` exists
- `ewfexport` exists
- the segment set is complete and in one directory

## Known limitations

- EWF currently uses controlled temporary export to RAW instead of direct filesystem access.
- Linux and Windows installation detection is content-driven and currently assumes the installation root is the filesystem root.
- Encrypted volumes are detected and marked, but not unlocked.
- VMDK/VHD/VHDX/QCOW/VDI are registry-prepared only, not supported in this phase.
- The UI exposes disk image inspection in Evidence Detail, but deeper artifact provenance rendering is still minimal.
