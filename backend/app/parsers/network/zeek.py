from app.parsers.base import ParserPlugin
from app.parsers.registry import register_parser


@register_parser
class ZeekParser(ParserPlugin):
    name = "zeek"
    supported_evidence_types = ["pcap"]

