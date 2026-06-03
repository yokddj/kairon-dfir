class RawParserError(Exception):
    """Base exception for native raw parsers."""


class RawParserDependencyError(RawParserError):
    """Raised when a native raw parser dependency is missing."""


class RawParserUnsupportedError(RawParserError):
    """Raised when no native parser supports the given artifact."""

