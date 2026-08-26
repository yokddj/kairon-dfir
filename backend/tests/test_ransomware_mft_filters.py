from __future__ import annotations

from app.api.routes_search import (
    BENIGN_TRAILING_EXTENSIONS,
    KNOWN_RANSOMWARE_EXTENSIONS,
    RANSOM_TARGET_EXTENSIONS,
)
from app.schemas.event import SearchFilters


def test_filters_accept_the_ransomware_toggles() -> None:
    filters = SearchFilters(double_extension_only=True, ransomware_extension_only=True)
    assert filters.double_extension_only is True
    assert filters.ransomware_extension_only is True


def test_benign_trailing_extensions_cover_the_observed_false_positives() -> None:
    """Validated against a real case: without these exclusions the double
    extension heuristic flags Windows components and shortcuts such as
    "Windows.Data.Pdf.dll" and "users.txt.lnk", which buries the real signal."""
    for extension in (".dll", ".lnk", ".exe", ".cdxml"):
        assert extension in BENIGN_TRAILING_EXTENSIONS


def test_ransomware_extensions_do_not_overlap_benign_ones() -> None:
    """An extension in both lists would make the two filters contradict:
    ransomware_extension_only would select it while double_extension_only
    would discard it."""
    assert not set(KNOWN_RANSOMWARE_EXTENSIONS) & set(BENIGN_TRAILING_EXTENSIONS)


def test_target_extensions_are_documents_not_executables() -> None:
    """The heuristic looks for a *document* extension left in the middle of the
    name. Including executables would match ordinary installer naming."""
    targets = set(RANSOM_TARGET_EXTENSIONS.split("|"))
    assert {"docx", "xlsx", "pdf", "kdbx"} <= targets
    assert not ({"exe", "dll", "sys"} & targets)


def test_double_extension_pattern_matches_ransomware_and_spares_lookalikes() -> None:
    """Positive + negative control for the regexp used against OpenSearch.

    Verified end to end against a live index; mirrored here with Python's re so
    the pattern cannot rot silently. Lucene anchors regexp queries, hence
    fullmatch. A filter that quietly matches nothing looks exactly like "this
    case has no ransomware", which is the failure mode worth guarding.
    """
    import re

    pattern = re.compile(rf".*\.({RANSOM_TARGET_EXTENSIONS})\.[-a-z0-9_]{{2,12}}", re.IGNORECASE)

    encrypted = {
        "informe.docx.locked": ".locked",
        "nomina.xlsx.lockbit": ".lockbit",
        "passwords.kdbx.encrypted": ".encrypted",
        "REPORT.PDF.CRYPT": ".crypt",
    }
    for name, trailing in encrypted.items():
        assert pattern.fullmatch(name), name
        assert trailing not in BENIGN_TRAILING_EXTENSIONS, name

    # Real false positives observed on a live case before the exclusion list.
    lookalikes = {"Windows.Data.Pdf.dll": ".dll", "users.txt.lnk": ".lnk"}
    for name, trailing in lookalikes.items():
        assert pattern.fullmatch(name), f"{name} still matches the regexp..."
        assert trailing in BENIGN_TRAILING_EXTENSIONS, f"...so {trailing} must be excluded"

    # Single-extension files must not match the pattern at all.
    for name in ("informe.docx", "backup.gz", "notes.txt"):
        assert not pattern.fullmatch(name), name
