"""Turn the zone-less, year-less times of Linux logs into real UTC times.

Most Linux logs write the host's *local* time with no zone (``2016-04-03 18:15:13``), and syslog-style
lines write no year either (``Apr  3 18:15:13``). Parsers stamp such lines provisionally as UTC and
mark them ``assumed_utc`` or ``assumed_year_utc``. This module then corrects them, per host:

* **Time zone.** The host's zone comes from ``/etc/timezone`` or the ``/etc/localtime`` TZif file of
  the same evidence. Local times are converted with it, daylight saving included.
* **Year.** Every line was written while the machine was running. ``wtmp`` records each boot and
  shutdown with an exact UTC time, so the year chosen is the one in which the line falls inside a
  boot-to-shutdown interval. Without ``wtmp``, or when no candidate fits, the year comes from the
  file itself, the way plaso does it: the last line belongs to the year of the file's modification
  time, and walking back up the file, a jump forward in the calendar means the previous year.

What was applied is recorded in ``timestamp_status``: ``host_timezone`` (local time converted with the
host's zone), ``inferred_year`` (year inferred, zone still unknown so read as UTC) or
``inferred_year_host_timezone`` (both). Lines nothing could be learned for keep the earlier status.
"""
from __future__ import annotations

import bisect
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone, tzinfo
from functools import lru_cache
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

ASSUMED_YEAR = "assumed_year_utc"
ASSUMED_ZONE = "assumed_utc"
_OUT_OF_ORDER_TOLERANCE = timedelta(days=7)
_UPTIME_SLACK = timedelta(minutes=10)
_MIN_YEAR = 1990
_MAX_ROOT_DEPTH = 8


@dataclass(frozen=True)
class HostClock:
    zone: tzinfo | None = None
    zone_name: str | None = None
    # (boot, end) in UTC, sorted by boot; end is None while the last boot never ended.
    uptime: tuple[tuple[datetime, datetime | None], ...] = field(default_factory=tuple)

    @property
    def boot_years(self) -> frozenset[int]:
        years: set[int] = set()
        for start, end in self.uptime:
            years.update(range(start.year, (end or start).year + 1))
        return frozenset(years)

    def running_at(self, moment: datetime) -> bool:
        if not self.uptime:
            return False
        starts = [start for start, _ in self.uptime]
        index = bisect.bisect_right(starts, moment + _UPTIME_SLACK) - 1
        if index < 0:
            return False
        start, end = self.uptime[index]
        return end is None or moment <= end + _UPTIME_SLACK


def _is_outside_evidence(candidate: Path) -> bool:
    """The machine Kairon runs on, not the evidence: its root, or a directory holding Kairon's data."""
    try:
        resolved = candidate.resolve()
        if resolved == Path(resolved.anchor):
            return True
        from app.core.config import get_settings

        data_dir = Path(get_settings().backend_data_dir).resolve()
        return data_dir == resolved or resolved in data_dir.parents
    except (OSError, RuntimeError, ValueError):
        return True


def _evidence_root(path: Path) -> Path | None:
    """The directory holding this file's ``etc`` and ``var`` (the root of the collected filesystem).

    The walk stops before it leaves the evidence: the host Kairon runs on has an /etc too, and its
    timezone must never be applied to a collection that did not include one.
    """
    try:
        for candidate in list(path.parents)[:_MAX_ROOT_DEPTH]:
            if _is_outside_evidence(candidate):
                return None
            if (candidate / "etc").is_dir() and (candidate / "var").is_dir():
                return candidate
    except OSError:
        return None
    return None


def _read_zone(root: Path) -> tuple[tzinfo | None, str | None]:
    try:
        named = root / "etc" / "timezone"
        if named.is_file():
            name = named.read_text(encoding="utf-8", errors="replace").strip().splitlines()[0].strip()
            if name:
                return ZoneInfo(name), name
    except (OSError, IndexError, ValueError, ZoneInfoNotFoundError):
        pass
    try:
        binary = root / "etc" / "localtime"
        if binary.is_file() and binary.stat().st_size < 1_000_000:
            with binary.open("rb") as handle:
                if handle.read(4) == b"TZif":
                    handle.seek(0)
                    return ZoneInfo.from_file(handle, key="host /etc/localtime"), "host /etc/localtime"
    except (OSError, ValueError):
        pass
    return None, None


def _read_uptime(root: Path) -> tuple[tuple[datetime, datetime | None], ...]:
    from app.ingest.linux.auth import parse_wtmp_btmp

    events: list[tuple[datetime, str]] = []
    last_seen: datetime | None = None
    log_dir = root / "var" / "log"
    try:
        files = sorted([*log_dir.glob("wtmp*"), *log_dir.glob("btmp*")])
    except OSError:
        return ()
    fresh = datetime.now(tz=timezone.utc) - timedelta(days=1)
    for record_file in files:
        try:
            if record_file.suffix == ".gz" or record_file.stat().st_size > 64 * 1024 * 1024:
                continue
            modified = datetime.fromtimestamp(record_file.stat().st_mtime, tz=timezone.utc)
            if modified < fresh:  # a modification time kept from the evidence, not the extraction time
                last_seen = max(last_seen, modified) if last_seen else modified
            for row in parse_wtmp_btmp(record_file.read_bytes(), source_path=str(record_file)):
                if not row.get("timestamp"):
                    continue
                moment = datetime.fromisoformat(row["timestamp"])
                last_seen = max(last_seen, moment) if last_seen else moment
                if record_file.name.startswith("wtmp") and row.get("event_action") in {"system_boot", "system_shutdown"}:
                    events.append((moment, row["event_action"]))
        except (OSError, ValueError, OverflowError):
            continue
    events.sort()
    intervals: list[tuple[datetime, datetime | None]] = []
    for moment, action in events:
        if action == "system_boot":
            if intervals and intervals[-1][1] is None:
                intervals[-1] = (intervals[-1][0], moment)  # booted again without a shutdown record
            intervals.append((moment, None))
        elif intervals and intervals[-1][1] is None:
            intervals[-1] = (intervals[-1][0], moment)
    if intervals and intervals[-1][1] is None and last_seen:
        # The last boot never ended in the records: it ran at least until the last thing they saw.
        intervals[-1] = (intervals[-1][0], max(last_seen, intervals[-1][0]) + timedelta(days=1))
    return tuple(intervals)


@lru_cache(maxsize=64)
def _host_clock_for_root(root: str) -> HostClock:
    base = Path(root)
    zone, name = _read_zone(base)
    return HostClock(zone=zone, zone_name=name, uptime=_read_uptime(base))


def host_clock_for(path: Path) -> HostClock:
    root = _evidence_root(path)
    return _host_clock_for_root(str(root)) if root else HostClock()


def file_reference_time(path: Path) -> datetime:
    try:
        stamp = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    except (OSError, OverflowError, ValueError):
        return datetime.now(tz=timezone.utc)
    return stamp if stamp.year >= _MIN_YEAR else datetime.now(tz=timezone.utc)


def _with_year(value: datetime, year: int) -> datetime | None:
    try:
        return value.replace(year=year)
    except ValueError:  # 29 February in a non-leap year
        return None


def _to_utc(local: datetime, zone: tzinfo | None) -> datetime:
    naive = local.replace(tzinfo=None)
    return naive.replace(tzinfo=zone).astimezone(timezone.utc) if zone else naive.replace(tzinfo=timezone.utc)


def _years_by_file_order(locals_: list[datetime], reference_local: datetime) -> list[int]:
    """The plaso walk: last line in the reference year (or before), one year back per calendar jump."""
    years = [0] * len(locals_)
    year = reference_local.year
    newer: datetime | None = None
    for index in range(len(locals_) - 1, -1, -1):
        candidate = _with_year(locals_[index], year)
        limit = (newer + _OUT_OF_ORDER_TOLERANCE) if newer else (reference_local + timedelta(days=1))
        while (candidate is None or candidate > limit) and year > _MIN_YEAR:
            year -= 1
            candidate = _with_year(locals_[index], year)
        years[index] = year
        if candidate is not None:
            newer = candidate
    return years


def resolve_local_times(rows: list[dict[str, Any]], *, reference: datetime, clock: HostClock) -> int:
    """Correct the zone and year of provisional rows in place. Returns the number of rows changed."""
    year_rows = [row for row in rows if row.get("timestamp_status") == ASSUMED_YEAR and row.get("timestamp")]
    zone_rows = [row for row in rows if row.get("timestamp_status") == ASSUMED_ZONE and row.get("timestamp")] if clock.zone else []
    changed = 0
    for row in zone_rows:
        try:
            local = datetime.fromisoformat(str(row["timestamp"]))
        except ValueError:
            continue
        row["timestamp"] = _to_utc(local, clock.zone).isoformat()
        row["timestamp_status"] = "host_timezone"
        changed += 1
    if not year_rows:
        return changed
    parsed: list[tuple[dict[str, Any], datetime]] = []
    for row in year_rows:
        try:
            parsed.append((row, datetime.fromisoformat(str(row["timestamp"])).replace(tzinfo=None)))
        except ValueError:
            continue
    reference_local = reference.astimezone(clock.zone).replace(tzinfo=None) if clock.zone else reference.replace(tzinfo=None)
    default_years = _years_by_file_order([local for _, local in parsed], reference_local)
    boot_years = clock.boot_years
    for (row, local), default_year in zip(parsed, default_years):
        chosen = default_year
        if boot_years:
            fitting = []
            for year in sorted(boot_years | {default_year}):
                candidate = _with_year(local, year)
                if candidate is not None and clock.running_at(_to_utc(candidate, clock.zone)):
                    fitting.append(year)
            if len(fitting) == 1 or (fitting and default_year not in fitting):
                chosen = fitting[-1] if default_year not in fitting else default_year
            elif default_year in fitting:
                chosen = default_year
        with_year = _with_year(local, chosen)
        if with_year is None:
            continue
        row["timestamp"] = _to_utc(with_year, clock.zone).isoformat()
        row["timestamp_status"] = "inferred_year_host_timezone" if clock.zone else "inferred_year"
        changed += 1
    return changed
