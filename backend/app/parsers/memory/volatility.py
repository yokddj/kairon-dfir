from app.parsers.base import ParserPlugin
from app.parsers.registry import register_parser


@register_parser
class VolatilityParser(ParserPlugin):
    name = "volatility"
    supported_evidence_types = ["memory_dump"]

