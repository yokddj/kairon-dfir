from __future__ import annotations
from pathlib import Path

from app.parsers.base import ParserPlugin
from app.parsers.registry import register_parser
from app.ingest.linux.dispatch import parse_linux_artifact_file
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
        family = artifact.get("artifact_family", "")
        source_path = artifact.get("source_path", "")
        return parse_linux_artifact_file(
            Path(artifact.get("full_path", source_path)),
            parser=artifact.get("parser"),
            artifact_type=artifact.get("artifact_type"),
            source_path=source_path,
        )
