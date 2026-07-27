from __future__ import annotations
from app.parsers.base import ParserPlugin
from app.parsers.registry import register_parser
from app.ingest.linux.helpers import looks_like_linux_artifact


@register_parser
class LinuxTriageParser(ParserPlugin):
    name = "linux_triage"
    supported_evidence_types = ["linux_triage", "parsed_folder", "unknown"]

    def detect(self, root):
        candidates = []
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            try:
                if path.stat().st_size > 50_000_000:
                    continue
            except OSError:
                continue
            result = looks_like_linux_artifact(str(path.relative_to(root)))
            if result:
                family, artifact_type, parser = result
                candidates.append({
                    "name": path.name,
                    "artifact_type": artifact_type,
                    "artifact_family": family,
                    "parser": parser,
                    "source_path": str(path.relative_to(root)),
                })
        return candidates

    def parse(self, artifact):
        import importlib
        family = artifact.get("artifact_family", "")
        source_path = artifact.get("source_path", "")
        parser_module_name = family.replace("linux_", "")

        try:
            module = importlib.import_module(f"app.ingest.linux.{parser_module_name}")
            parse_func = getattr(module, f"parse_{parser_module_name}", None)
            if not parse_func:
                return []
            with open(artifact.get("full_path", source_path), "rb") as fh:
                content = fh.read()
                if family == "linux_auth" and artifact.get("artifact_type") in {"wtmp", "btmp", "lastlog"}:
                    return parse_func(content, source_path=source_path)
                try:
                    content = content.decode("utf-8")
                except UnicodeDecodeError:
                    content = content.decode("latin-1", errors="replace")
            return parse_func(content, source_path=source_path)
        except Exception:
            return []
