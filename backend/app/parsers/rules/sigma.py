from app.parsers.base import ParserPlugin
from app.parsers.registry import register_parser


@register_parser
class SigmaParser(ParserPlugin):
    name = "sigma"
    supported_evidence_types = ["sigma_rules"]

