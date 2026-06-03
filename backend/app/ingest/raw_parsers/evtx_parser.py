from collections import Counter
from contextlib import contextmanager
from datetime import UTC, datetime
from hashlib import sha1
import signal
from pathlib import Path
import threading
import time
from xml.etree import ElementTree as ET

from app.ingest.raw_parsers.audit import build_raw_parser_audit
from app.ingest.raw_parsers.base import BaseRawParser
from app.ingest.raw_parsers.errors import RawParserDependencyError
from app.ingest.raw_parsers.models import RawParserResult


def _strip_ns(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag


def _safe_text(value: object | None, *, limit: int = 2048) -> str | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    if not text:
        return None
    return text[:limit]


def _coerce_iso_timestamp(value: str | None) -> str | None:
    if not value:
        return None
    try:
        normalized = value.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.isoformat()
    except Exception:  # noqa: BLE001
        return None


def _summarize_event_data(payload: dict[str, str]) -> str | None:
    if not payload:
        return None
    parts: list[str] = []
    for key in sorted(payload.keys())[:12]:
        value = _safe_text(payload.get(key), limit=120)
        if value:
            parts.append(f"{key}={value}")
    if not parts:
        return None
    return " | ".join(parts)[:1024]


def _extract_payload(root: ET.Element) -> tuple[dict[str, str], dict[str, str]]:
    event_data: dict[str, str] = {}
    user_data: dict[str, str] = {}
    for child in root:
        name = _strip_ns(child.tag)
        if name == "EventData":
            for data in child:
                if _strip_ns(data.tag) != "Data":
                    continue
                key = data.attrib.get("Name") or f"Data{len(event_data) + 1}"
                value = _safe_text(data.text)
                if value is not None:
                    event_data[key] = value
        elif name == "UserData":
            for data in child.iter():
                if data is child:
                    continue
                key = _strip_ns(data.tag)
                value = _safe_text(data.text)
                if value is not None and key not in user_data:
                    user_data[key] = value
    return event_data, user_data


def parse_evtx_xml_record(xml_text: str) -> dict:
    root = ET.fromstring(xml_text)
    system = next((child for child in root if _strip_ns(child.tag) == "System"), None)
    payload, user_data = _extract_payload(root)
    result: dict[str, object] = {
        "RawXml": xml_text,
        "Payload": payload,
        "UserData": user_data,
    }
    if system is None:
        result["EventDataSummary"] = _summarize_event_data(payload | user_data)
        return result
    for child in system:
        name = _strip_ns(child.tag)
        if name == "Provider":
            result["Provider"] = child.attrib.get("Name")
        elif name == "EventID":
            result["EventID"] = _safe_text(child.text)
        elif name == "Channel":
            result["Channel"] = _safe_text(child.text)
        elif name == "Computer":
            result["Computer"] = _safe_text(child.text)
        elif name == "EventRecordID":
            result["RecordID"] = _safe_text(child.text)
        elif name == "Level":
            result["Level"] = _safe_text(child.text)
        elif name == "Task":
            result["Task"] = _safe_text(child.text)
        elif name == "Opcode":
            result["Opcode"] = _safe_text(child.text)
        elif name == "Keywords":
            result["Keywords"] = _safe_text(child.text)
        elif name == "TimeCreated":
            result["TimeCreated"] = _coerce_iso_timestamp(child.attrib.get("SystemTime"))
        elif name == "Execution":
            result["ProcessId"] = _safe_text(child.attrib.get("ProcessID"))
            result["ThreadId"] = _safe_text(child.attrib.get("ThreadID"))
        elif name == "Security":
            result["UserId"] = _safe_text(child.attrib.get("UserID"))
    for key, value in user_data.items():
        result.setdefault(key, value)
    for key, value in payload.items():
        result.setdefault(key, value)
    result["EventDataSummary"] = _summarize_event_data(payload | user_data)
    result["Message"] = _safe_text(result.get("EventDataSummary"), limit=512)
    return result


def iter_evtx_xml_records(path: Path):
    try:
        from Evtx.Evtx import Evtx
    except Exception as exc:  # noqa: BLE001
        raise RawParserDependencyError("python-evtx dependency is required for native EVTX parsing") from exc
    with Evtx(str(path)) as log:
        for record in log.records():
            yield record.xml()


@contextmanager
def _evtx_record_timeout(seconds: int | None):
    timeout_seconds = max(int(seconds or 0), 0)
    if timeout_seconds <= 0 or threading.current_thread() is not threading.main_thread() or not hasattr(signal, "setitimer"):
        yield
        return

    previous_handler = signal.getsignal(signal.SIGALRM)

    def _handle_timeout(signum, frame):  # noqa: ARG001
        raise TimeoutError(f"EVTX record timed out after {timeout_seconds}s")

    signal.signal(signal.SIGALRM, _handle_timeout)
    signal.setitimer(signal.ITIMER_REAL, timeout_seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)


def iter_evtx_xml_record_results(path: Path, *, record_timeout_seconds: int | None = None):
    try:
        from Evtx.Evtx import Evtx
    except Exception as exc:  # noqa: BLE001
        raise RawParserDependencyError("python-evtx dependency is required for native EVTX parsing") from exc
    with Evtx(str(path)) as log:
        for index, record in enumerate(log.records(), start=1):
            try:
                with _evtx_record_timeout(record_timeout_seconds):
                    yield index, record.xml(), None
            except Exception as exc:  # noqa: BLE001
                yield index, None, exc


def evtx_native_available() -> bool:
    try:
        from Evtx.Evtx import Evtx  # noqa: F401
        return True
    except Exception:  # noqa: BLE001
        return False


class EvtxRawParser(BaseRawParser):
    parser_name = "evtx_raw"
    artifact_type = "evtx_raw"

    def can_parse(self, candidate_or_path: object) -> bool:
        path = getattr(candidate_or_path, "original_path", candidate_or_path)
        return str(path or "").lower().endswith(".evtx")

    def parse(
        self,
        path: Path,
        *,
        case_id: str,
        evidence_id: str,
        artifact_id: str,
        artifact_meta: dict,
        progress_cb=None,
    ) -> RawParserResult:
        batch_results = list(
            self.iter_batches(
                path,
                case_id=case_id,
                evidence_id=evidence_id,
                artifact_id=artifact_id,
                artifact_meta=artifact_meta,
                batch_size=50_000,
                progress_cb=progress_cb,
            )
        )
        if not batch_results:
            return RawParserResult(
                parser_name=self.parser_name,
                artifact_type="windows_event",
                source_path=str(artifact_meta.get("source_path") or path),
                parser_status="parsed_empty",
                metadata={"audit": build_raw_parser_audit(RawParserResult(parser_name=self.parser_name, artifact_type="windows_event", source_path=str(artifact_meta.get("source_path") or path), parser_status="parsed_empty"))},
            )
        events: list[dict] = []
        final_result = batch_results[-1]
        for batch in batch_results:
            events.extend(batch.events)
        return RawParserResult(
            parser_name=self.parser_name,
            artifact_type=final_result.artifact_type,
            source_path=final_result.source_path,
            records_read=final_result.records_read,
            events=events,
            warnings=list(final_result.warnings),
            errors=list(final_result.errors),
            parser_status=final_result.parser_status,
            metadata=dict(final_result.metadata),
        )

    def iter_batches(
        self,
        path: Path,
        *,
        case_id: str,
        evidence_id: str,
        artifact_id: str,
        artifact_meta: dict,
        batch_size: int = 2_000,
        progress_cb=None,
        record_timeout_seconds: int | None = None,
        max_records: int | None = None,
        max_seconds: int | None = None,
        limit_checker=None,
    ):
        from app.ingest.normalizer import normalize_row

        start = time.perf_counter()
        warnings: list[str] = []
        errors: list[str] = []
        records_read = 0
        events: list[dict] = []
        channels = Counter()
        event_ids = Counter()
        source_path = str(artifact_meta.get("source_path") or path)
        limit_reason: str | None = None

        def _build_result(*, batch_events: list[dict], parser_status: str, completed: bool) -> RawParserResult:
            metadata = {
                "parse_duration_ms": int((time.perf_counter() - start) * 1000),
                "evtx_files_seen": 1,
                "evtx_files_parsed": 1 if batch_events else 0,
                "evtx_records_read": records_read,
                "evtx_records_indexed": len(batch_events),
                "evtx_records_failed": len(errors),
                "channels_seen": list(channels.keys()),
                "event_ids_seen": list(event_ids.keys()),
                "classification_counts": dict(Counter(str(event.get("event", {}).get("type") or "unknown") for event in batch_events)),
                "completed": completed,
            }
            if limit_reason:
                metadata.update(
                    {
                        "partial": True,
                        "limit_reason": limit_reason,
                        "evtx_partial": True,
                        "records_remaining_unknown": True,
                    }
                )
            result = RawParserResult(
                parser_name=self.parser_name,
                artifact_type="windows_event",
                source_path=source_path,
                records_read=records_read,
                events=batch_events,
                warnings=list(warnings),
                errors=list(errors),
                parser_status=parser_status,
                metadata=metadata,
            )
            result.metadata["audit"] = build_raw_parser_audit(result)
            return result

        for record_index, xml_text, record_error in iter_evtx_xml_record_results(path, record_timeout_seconds=record_timeout_seconds):
            records_read += 1
            if progress_cb and records_read % 250 == 0:
                progress_cb(
                    {
                        "records_read": records_read,
                        "events_buffered": len(events),
                        "errors_count": len(errors),
                    }
                )
            if record_error is not None:
                errors.append(f"record {record_index}: {record_error}")
                continue
            try:
                row = parse_evtx_xml_record(str(xml_text))
                document = normalize_row(
                    case_id,
                    evidence_id,
                    artifact_id,
                    row,
                    {
                        **artifact_meta,
                        "artifact_type": "windows_event",
                        "parser": "evtx_raw",
                        "source_tool": "native_evtx",
                        "source_format": "evtx",
                        "source_path": str(artifact_meta.get("source_path") or path),
                    },
                )
                events.append(document)
                if document.get("windows", {}).get("channel"):
                    channels[str(document["windows"]["channel"])] += 1
                if document.get("windows", {}).get("event_id") is not None:
                    event_ids[str(document["windows"]["event_id"])] += 1
                if len(events) >= max(int(batch_size or 0), 1):
                    yield _build_result(batch_events=events, parser_status="parsed_native", completed=False)
                    events = []
            except Exception as exc:  # noqa: BLE001
                errors.append(f"record {record_index}: {exc}")
            if max_records and records_read >= int(max_records):
                limit_reason = "max_records_per_file"
            elif max_seconds and (time.perf_counter() - start) >= int(max_seconds):
                limit_reason = "max_seconds_per_file"
            elif limit_checker:
                checked_reason = limit_checker(records_read=records_read, events_indexed=len(events), elapsed_seconds=time.perf_counter() - start)
                if checked_reason:
                    limit_reason = str(checked_reason)
            if limit_reason:
                warnings.append(f"evtx_fast_limit_reached:{limit_reason}")
                break
        if progress_cb:
            progress_cb(
                {
                    "records_read": records_read,
                    "events_buffered": len(events),
                    "errors_count": len(errors),
                    "completed": True,
                }
            )
        parser_status = "partial" if limit_reason else "parsed_native"
        if not errors and records_read == 0 and not events:
            warnings.append("evtx_file_empty")
            parser_status = "parsed_empty"
        elif errors and not events:
            parser_status = "failed"
        yield _build_result(batch_events=events, parser_status=parser_status, completed=True)
