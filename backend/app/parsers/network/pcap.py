from app.parsers.base import ParserPlugin
from app.parsers.registry import register_parser


@register_parser
class PcapParser(ParserPlugin):
    name = "pcap"
    supported_evidence_types = ["pcap"]

