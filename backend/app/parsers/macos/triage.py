from app.parsers.base import ParserPlugin
from app.parsers.registry import register_parser


@register_parser
class MacOSTriageParser(ParserPlugin):
    name = "macos_triage"
    supported_evidence_types = ["macos_triage"]

