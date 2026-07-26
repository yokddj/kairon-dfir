"""Layer 2: a thin pytsk3.Img_Info adapter over LogicalVolumeReader.

This is the only module in app.disk_images.lvm that imports pytsk3.
Everything it does is forward pytsk3's own calls to an already-constructed
LogicalVolumeReader (Layer 1) -- no offset translation, no segment
lookup, no validation logic lives here at all. This mirrors the existing
_PytskFileReader pattern already used elsewhere in Kairon's disk-image
pipeline (app.disk_images.service), which does the same thing for a plain
file instead of a Logical Volume.

Not referenced anywhere in Kairon's production pipeline yet -- see PR3.
"""

from __future__ import annotations

import pytsk3

from app.disk_images.lvm.reader import LogicalVolumeReader


class LogicalVolumeImgInfo(pytsk3.Img_Info):
    """Presents a LogicalVolumeReader as a pytsk3.Img_Info, so it can be
    passed to pytsk3.FS_Info exactly as a physical partition's own reader
    already is (see app.disk_images.service._PytskFileReader). Every
    method here is a one-line forward to `reader`; nothing about how
    logical offsets map to physical ones is decided in this class."""

    def __init__(self, reader: LogicalVolumeReader, *, url: str = "") -> None:
        self._reader = reader
        super().__init__(url=url)

    def close(self) -> None:
        # LogicalVolumeReader owns no closable resource of its own (it
        # only calls a caller-supplied read_physical callable); closing
        # whatever backs that callable, if anything needs to be closed,
        # is the caller's responsibility, not this adapter's.
        pass

    def read(self, offset: int, size: int) -> bytes:
        return self._reader.read(offset, size)

    def get_size(self) -> int:
        return self._reader.size_bytes
