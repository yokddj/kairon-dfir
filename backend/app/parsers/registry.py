from app.parsers.base import ParserPlugin


PARSER_PLUGINS: list[type[ParserPlugin]] = []


def register_parser(plugin: type[ParserPlugin]) -> type[ParserPlugin]:
    PARSER_PLUGINS.append(plugin)
    return plugin


def get_registered_parsers() -> list[type[ParserPlugin]]:
    return list(PARSER_PLUGINS)

