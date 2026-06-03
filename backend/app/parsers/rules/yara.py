from app.parsers.base import ParserPlugin
from app.parsers.registry import register_parser


@register_parser
class YaraParser(ParserPlugin):
    name = "yara"
    supported_evidence_types = ["yara_rules"]

