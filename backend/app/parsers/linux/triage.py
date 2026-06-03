from app.parsers.base import ParserPlugin
from app.parsers.registry import register_parser


@register_parser
class LinuxTriageParser(ParserPlugin):
    name = "linux_triage"
    supported_evidence_types = ["linux_triage"]

