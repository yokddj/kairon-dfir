from app.parsers.base import ParserPlugin
from app.parsers.registry import register_parser


@register_parser
class MemProcFSParser(ParserPlugin):
    name = "memprocfs"
    supported_evidence_types = ["memory_dump"]

