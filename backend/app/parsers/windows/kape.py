from app.parsers.base import ParserPlugin
from app.parsers.registry import register_parser


@register_parser
class KapeParser(ParserPlugin):
    name = "kape"
    supported_evidence_types = ["kape_archive", "parsed_folder"]

