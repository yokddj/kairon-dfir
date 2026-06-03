import hashlib
from collections import Counter
from pathlib import Path

from app.core.config import get_settings
from app.core.storage import build_evidence_root
from app.models.evidence import Evidence
from app.models.rule import Rule
from app.models.rule_set import RuleSet


settings = get_settings()

try:  # pragma: no cover - optional dependency path
    import yara  # type: ignore
except Exception:  # noqa: BLE001
    yara = None


def yara_available() -> bool:
    return yara is not None


def compile_yara_source(source: str):
    if yara is None:
        raise RuntimeError("YARA engine unavailable in this build.")
    return yara.compile(source=source)


def compile_yara_rule(rule: Rule):
    return compile_yara_source(rule.content)


def compile_yara_rule_set(rule_set: RuleSet):
    return compile_yara_source(rule_set.content)


def validate_yara_content(content: str) -> dict:
    if yara is None:
        return {"valid": False, "available": False, "errors": ["YARA engine unavailable in this build."]}
    try:
        compiled = compile_yara_source(content)
    except Exception as exc:  # noqa: BLE001
        return {"valid": False, "available": True, "errors": [str(exc)]}
    names = []
    try:
        names = [str(item.identifier) for item in getattr(compiled, "rules", []) if getattr(item, "identifier", None)]
    except Exception:  # noqa: BLE001
        names = detect_rule_names_from_content(content)
    return {"valid": True, "available": True, "rules_count": len(names) or len(detect_rule_names_from_content(content)), "rule_names": names}


def detect_rule_names_from_content(content: str) -> list[str]:
    import re

    return re.findall(r"\brule\s+([A-Za-z0-9_]+)\s*[:{]", content)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


EXECUTABLE_EXTENSIONS = {".exe", ".sys"}
SCRIPT_EXTENSIONS = {".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta"}
DOCUMENT_EXTENSIONS = {".doc", ".docx", ".xls", ".xlsx", ".pdf"}
ARCHIVE_EXTENSIONS = {".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2"}
PARSED_OUTPUT_EXTENSIONS = {".csv", ".json", ".jsonl"}
TEXT_OUTPUT_EXTENSIONS = {".txt", ".log"}
MEMORY_DUMP_EXTENSIONS = {".dmp", ".raw", ".mem"}
PARSER_OUTPUT_NAMES = {
    "mftecmd",
    "evtxecmd",
    "pecmd",
    "recmd",
    "amcacheparser",
    "appcompatcacheparser",
    "jlecmd",
    "lecmd",
    "srumecmd",
    "hayabusa",
}
PARSER_OUTPUT_PATH_TOKENS = {"parsed", "parseado", "results"}
MANIFEST_INTERNAL_NAMES = {"manifest.json", "tree.json", ".ds_store"}


def _looks_like_parser_output(path: Path) -> bool:
    parts = {part.lower() for part in path.parts}
    if parts & PARSER_OUTPUT_PATH_TOKENS:
        return True
    lower_name = path.name.lower()
    return any(token in lower_name for token in PARSER_OUTPUT_NAMES)


def classify_yara_target(path: Path) -> dict:
    lower_name = path.name.lower()
    suffix = path.suffix.lower()
    if lower_name in MANIFEST_INTERNAL_NAMES or lower_name.startswith("manifest"):
        return {"candidate_type": "manifest_or_internal", "scan": False, "skip_reason": "manifest_or_internal"}
    if suffix in ARCHIVE_EXTENSIONS:
        return {"candidate_type": "archive", "scan": settings.yara_scan_archives, "skip_reason": None if settings.yara_scan_archives else "archive"}
    if _looks_like_parser_output(path) or suffix in PARSED_OUTPUT_EXTENSIONS:
        return {"candidate_type": "parsed_output", "scan": settings.yara_scan_parsed_outputs, "skip_reason": None if settings.yara_scan_parsed_outputs else "parsed_output"}
    if suffix in TEXT_OUTPUT_EXTENSIONS:
        return {"candidate_type": "parsed_output" if _looks_like_parser_output(path) else "unknown", "scan": settings.yara_scan_text_outputs, "skip_reason": None if settings.yara_scan_text_outputs else "text_output"}
    if suffix in EXECUTABLE_EXTENSIONS:
        return {"candidate_type": "executable", "scan": True, "skip_reason": None}
    if suffix == ".dll":
        return {"candidate_type": "dll", "scan": True, "skip_reason": None}
    if suffix in SCRIPT_EXTENSIONS:
        return {"candidate_type": "script", "scan": True, "skip_reason": None}
    if suffix in DOCUMENT_EXTENSIONS:
        return {"candidate_type": "document", "scan": True, "skip_reason": None}
    if suffix in MEMORY_DUMP_EXTENSIONS:
        return {"candidate_type": "memory_dump", "scan": True, "skip_reason": None}
    if suffix in {".bin"}:
        return {"candidate_type": "raw_candidate", "scan": True, "skip_reason": None}
    if suffix == ".dat":
        return {"candidate_type": "raw_candidate", "scan": not _looks_like_parser_output(path), "skip_reason": None if not _looks_like_parser_output(path) else "parsed_output"}
    return {"candidate_type": "unknown", "scan": False, "skip_reason": "unsupported_extension"}


def _iter_candidate_files(case_id: str, evidence: Evidence) -> list[Path]:
    root = build_evidence_root(case_id, evidence.id)
    candidates: list[Path] = []
    if settings.yara_scan_extracted:
        extracted = root / "extracted"
        if extracted.exists():
            candidates.extend(path for path in extracted.rglob("*") if path.is_file())
    if settings.yara_scan_originals or settings.yara_scan_raw_evidence:
        original = root / "original"
        if original.exists():
            candidates.extend(path for path in original.rglob("*") if path.is_file())
        original_folder = root / "original_folder"
        if original_folder.exists():
            candidates.extend(path for path in original_folder.rglob("*") if path.is_file())
    return candidates


def _resolve_selected_targets(case_id: str, evidence: Evidence, selected_paths: list[str] | None) -> list[Path]:
    if not selected_paths:
        return _iter_candidate_files(case_id, evidence)
    root = build_evidence_root(case_id, evidence.id).resolve()
    resolved: list[Path] = []
    for raw_path in selected_paths:
        candidate = Path(str(raw_path))
        if not candidate.is_absolute():
            candidate = (root / candidate).resolve()
        else:
            candidate = candidate.resolve()
        try:
            candidate.relative_to(root)
        except Exception:
            continue
        if candidate.is_dir():
            resolved.extend(path for path in candidate.rglob("*") if path.is_file() or path.is_symlink())
        elif candidate.is_file() or candidate.is_symlink():
            resolved.append(candidate)
    return list(dict.fromkeys(resolved))


def _run_compiled_yara_on_evidence(compiled, evidence: Evidence, scan_options: dict | None = None) -> dict:
    if yara is None:
        return {"available": False, "scanned_files": 0, "matched_files": 0, "skipped_files": 0, "errors": ["YARA engine unavailable in this build."], "matches": []}
    scan_options = scan_options or {}
    files = _resolve_selected_targets(evidence.case_id, evidence, scan_options.get("selected_paths"))
    matches = []
    skipped_files = 0
    errors = []
    skipped_by_reason: Counter[str] = Counter()
    candidate_breakdown: Counter[str] = Counter()
    warnings: list[str] = []
    scan_parsed_outputs = scan_options.get("scan_parsed_outputs", settings.yara_scan_parsed_outputs)
    scan_archives = scan_options.get("scan_archives", settings.yara_scan_archives)
    scan_text_outputs = scan_options.get("scan_text_outputs", settings.yara_scan_text_outputs)
    max_bytes = int(scan_options.get("max_file_size_mb", settings.yara_max_file_size_mb)) * 1024 * 1024
    max_files = int(scan_options.get("max_files", 5000) or 5000)
    timeout_seconds = int(scan_options.get("timeout_seconds", 10) or 10)
    evidence_root = build_evidence_root(evidence.case_id, evidence.id).resolve()
    scanned_candidates = 0
    for path in files:
        if scanned_candidates >= max_files:
            warnings.append(f"YARA scan stopped after {max_files} files due to max_files limit.")
            break
        try:
            if path.is_symlink():
                skipped_files += 1
                skipped_by_reason["symlink"] += 1
                continue
            resolved_path = path.resolve()
            resolved_path.relative_to(evidence_root)
            size = path.stat().st_size
        except Exception as exc:  # noqa: BLE001
            skipped_files += 1
            skipped_by_reason["stat_error"] += 1
            errors.append(f"{path}: {exc}")
            continue
        candidate = classify_yara_target(path)
        candidate_type = str(candidate["candidate_type"])
        candidate_breakdown[candidate_type] += 1
        skip_reason = candidate.get("skip_reason")
        should_scan = bool(candidate.get("scan"))
        if candidate_type == "parsed_output" and scan_parsed_outputs:
            should_scan = True
            skip_reason = None
        elif candidate_type == "archive" and scan_archives:
            should_scan = True
            skip_reason = None
        elif skip_reason == "text_output" and scan_text_outputs:
            should_scan = True
            skip_reason = None
        if size > max_bytes:
            skipped_files += 1
            skipped_by_reason["too_large"] += 1
            continue
        if not should_scan:
            skipped_files += 1
            skipped_by_reason[str(skip_reason or "unsupported_extension")] += 1
            continue
        scanned_candidates += 1
        try:
            results = compiled.match(str(path), timeout=timeout_seconds)
            if not results:
                continue
            match_names = [result.rule for result in results]
            matched_strings = []
            for result in results:
                for string_match in getattr(result, "strings", []) or []:
                    try:
                        identifier = getattr(string_match, "identifier", None)
                        instances = getattr(string_match, "instances", []) or []
                        for instance in instances[:10]:
                            matched_data = bytes(instance.matched_data[:64]).hex() if getattr(instance, "matched_data", None) else None
                            matched_strings.append(
                                {
                                    "identifier": identifier,
                                    "offset": int(getattr(instance, "offset", 0)),
                                    "matched_data_hex": matched_data,
                                }
                            )
                    except Exception:  # noqa: BLE001
                        continue
            matches.append(
                {
                    "path": str(path),
                    "match_names": match_names,
                    "file_size": size,
                    "file_sha256": _sha256_file(path),
                    "file_type": candidate_type,
                    "matched_strings": matched_strings,
                }
            )
        except Exception as exc:  # noqa: BLE001
            skipped_files += 1
            errors.append(f"{path}: {exc}")
            skipped_by_reason["scan_error"] += 1
    if candidate_breakdown.get("parsed_output", 0) and scanned_candidates <= 1 and candidate_breakdown.get("parsed_output", 0) >= scanned_candidates:
        warnings.append("This evidence mostly contains parsed CSV/JSON outputs. YARA is designed for raw files; use Sigma/heuristics/Search for parsed artifacts.")
    return {
        "available": True,
        "scanned_files": scanned_candidates,
        "matched_files": len(matches),
        "skipped_files": skipped_files,
        "skipped_by_reason": dict(skipped_by_reason),
        "candidate_breakdown": dict(candidate_breakdown),
        "warnings": warnings,
        "errors": errors,
        "matches": matches,
    }


def run_yara_rule_on_evidence(rule: Rule, evidence: Evidence, scan_options: dict | None = None) -> dict:
    return _run_compiled_yara_on_evidence(compile_yara_rule(rule), evidence, scan_options=scan_options)


def run_yara_rule_set_on_evidence(rule_set: RuleSet, evidence: Evidence, scan_options: dict | None = None) -> dict:
    return _run_compiled_yara_on_evidence(compile_yara_rule_set(rule_set), evidence, scan_options=scan_options)
