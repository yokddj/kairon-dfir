"""EwfImgInfo: a pytsk3.Img_Info backed directly by pyewf, with no
intermediate flat RAW file.

This is the only module in app.disk_images that imports pyewf -- keeping
every pyewf call confined here mirrors the existing isolation pattern
already used for _PytskFileReader (app.disk_images.service, a plain file)
and LogicalVolumeImgInfo (app.disk_images.lvm.img_info, an LVM logical
volume): each is a thin pytsk3.Img_Info adapter over a different byte
source, with no format-specific logic leaking into callers.

Before this module existed, EwfImageAdapter.expose_readonly() ran the
`ewfexport` CLI tool to fully decompress an EWF (E01) image into a
temporary flat RAW file sized to the *logical* disk, before pytsk3 ever
read a byte of it -- see the architecture investigation this sprint
implements. pyewf (the libewf project's own Python bindings) exposes the
same random-access read(offset, size) pytsk3.Img_Info already requires,
directly against the compressed EWF segments, so no such file is needed
at all.
"""

from __future__ import annotations

from pathlib import Path

import pyewf
import pytsk3


class EwfOpenError(Exception):
    """pyewf could not open this EWF segment set (corrupt image, an EWF
    variant pyewf does not support, or an inconsistent segment set that
    slipped past EwfImageAdapter.validate_segments). Raised explicitly --
    callers must not catch this and silently fall back to any other
    access method (e.g. ewfexport); see EwfImageAdapter.expose_readonly."""


class EwfImgInfo(pytsk3.Img_Info):
    """Presents an EWF (E01/Ex01, single- or multi-segment) image as a
    pytsk3.Img_Info. Every method here is a one-line forward to the
    underlying pyewf handle; pyewf itself already handles EWF's internal
    chunking, compression, and segment-spanning -- nothing about that
    format is reimplemented in this class."""

    def __init__(self, segment_paths: list[Path], *, url: str = "") -> None:
        self._handle = pyewf.handle()
        try:
            self._handle.open([str(path) for path in segment_paths])
        except Exception as exc:
            raise EwfOpenError(str(exc)) from exc
        self._size = self._handle.get_media_size()
        super().__init__(url=url)

    def close(self) -> None:
        try:
            self._handle.close()
        except Exception:
            pass

    def read(self, offset: int, size: int) -> bytes:
        self._handle.seek(offset)
        return self._handle.read(size)

    def get_size(self) -> int:
        return self._size


def pyewf_available() -> bool:
    """Whether the pyewf Python binding itself can be imported -- distinct
    from the ewfinfo/ewfexport CLI tools this format used to depend on,
    which EwfImgInfo does not use at all."""
    try:
        import pyewf as _pyewf  # noqa: F401
    except ImportError:
        return False
    return True


def pyewf_version() -> str | None:
    getter = getattr(pyewf, "get_version", None)
    if getter is None:
        return None
    try:
        return str(getter())
    except Exception:
        return None
