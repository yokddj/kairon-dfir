from app.parsers.base import ParserPlugin
from app.parsers.registry import register_parser


@register_parser
class EvtxParser(ParserPlugin):
    name = "evtx"
    supported_evidence_types = ["evtx"]

