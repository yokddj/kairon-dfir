from app.parsers.base import ParserPlugin
from app.parsers.registry import register_parser


@register_parser
class VelociraptorParser(ParserPlugin):
    name = "velociraptor"
    supported_evidence_types = ["velociraptor_zip"]

