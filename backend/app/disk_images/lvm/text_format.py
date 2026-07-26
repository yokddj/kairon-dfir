"""Parser for LVM2's human-readable metadata text format (the same simple
config-file grammar used by lvm.conf and vgcfgbackup output): nested named
sections, integer/string/array values, '#' comments to end of line.

This module's output (a plain dict-based tree) is intentionally *not*
part of app.disk_images.lvm's public API -- it is a private intermediate
representation that parser.py immediately walks to build the typed
dataclasses in models.py. Nothing here is exported from the lvm package's
__init__.py.

Grammar (informal):

    document  := statement*
    statement := IDENT '=' value | IDENT section
    section   := '{' statement* '}'
    value     := INTEGER | STRING | array
    array     := '[' (value (',' value)*)? ']'

Whitespace and comments ('#' to end of line) are insignificant between
tokens. This is deliberately a small, purpose-built grammar for exactly
what LVM2 writes -- not a general-purpose config-language parser.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.disk_images.lvm.exceptions import MalformedMetadataTextError

ConfigValue = "int | str | list[int | str] | ConfigSection"
ConfigSection = dict  # dict[str, ConfigValue] -- private tree node, never exported

# '-' is included because real Volume Group and Logical Volume names
# routinely contain it (e.g. "kali-vg"); see _next_token for how this is
# disambiguated from a leading '-' on a negative integer.
_IDENT_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-")


@dataclass(frozen=True)
class _Token:
    kind: str  # "ident" | "int" | "string" | "{" | "}" | "[" | "]" | "=" | ","
    value: object
    position: int


class _Tokenizer:
    def __init__(self, text: str) -> None:
        self._text = text
        self._length = len(text)
        self._pos = 0

    def tokens(self) -> list[_Token]:
        result: list[_Token] = []
        while True:
            self._skip_insignificant()
            if self._pos >= self._length:
                break
            result.append(self._next_token())
        return result

    def _skip_insignificant(self) -> None:
        while self._pos < self._length:
            ch = self._text[self._pos]
            if ch.isspace():
                self._pos += 1
                continue
            if ch == "#":
                newline = self._text.find("\n", self._pos)
                self._pos = self._length if newline == -1 else newline + 1
                continue
            break

    def _next_token(self) -> _Token:
        start = self._pos
        ch = self._text[self._pos]
        if ch in "{}[]=,":
            self._pos += 1
            return _Token(kind=ch, value=ch, position=start)
        if ch == '"':
            return self._read_string(start)
        if ch.isdigit():
            return self._read_integer(start)
        if ch == "-" and self._pos + 1 < self._length and self._text[self._pos + 1].isdigit():
            return self._read_integer(start)
        if ch in _IDENT_CHARS:
            return self._read_ident(start)
        raise MalformedMetadataTextError(f"Unexpected character {ch!r} at position {start} while tokenizing LVM2 metadata text.")

    def _read_string(self, start: int) -> _Token:
        self._pos += 1  # opening quote
        chars: list[str] = []
        while True:
            if self._pos >= self._length:
                raise MalformedMetadataTextError(f"Unterminated string starting at position {start}.")
            ch = self._text[self._pos]
            if ch == "\\":
                if self._pos + 1 >= self._length:
                    raise MalformedMetadataTextError(f"Unterminated escape sequence at position {self._pos}.")
                chars.append(self._text[self._pos + 1])
                self._pos += 2
                continue
            if ch == '"':
                self._pos += 1
                return _Token(kind="string", value="".join(chars), position=start)
            chars.append(ch)
            self._pos += 1

    def _read_integer(self, start: int) -> _Token:
        end = self._pos
        if self._text[end] == "-":
            end += 1
        while end < self._length and self._text[end].isdigit():
            end += 1
        raw = self._text[self._pos : end]
        if raw in ("", "-"):
            raise MalformedMetadataTextError(f"Malformed number at position {start}.")
        self._pos = end
        return _Token(kind="int", value=int(raw), position=start)

    def _read_ident(self, start: int) -> _Token:
        end = self._pos
        while end < self._length and self._text[end] in _IDENT_CHARS:
            end += 1
        raw = self._text[self._pos : end]
        self._pos = end
        return _Token(kind="ident", value=raw, position=start)


class _Parser:
    def __init__(self, tokens: list[_Token]) -> None:
        self._tokens = tokens
        self._index = 0

    def parse_document(self) -> dict:
        section = self._parse_statements()
        if self._index != len(self._tokens):
            leftover = self._tokens[self._index]
            raise MalformedMetadataTextError(f"Unexpected token {leftover.kind!r} at position {leftover.position} after the top-level document.")
        return section

    def _peek(self) -> _Token | None:
        return self._tokens[self._index] if self._index < len(self._tokens) else None

    def _advance(self) -> _Token:
        token = self._peek()
        if token is None:
            raise MalformedMetadataTextError("Unexpected end of metadata text.")
        self._index += 1
        return token

    def _expect(self, kind: str) -> _Token:
        token = self._advance()
        if token.kind != kind:
            raise MalformedMetadataTextError(f"Expected {kind!r} but found {token.kind!r} at position {token.position}.")
        return token

    def _parse_statements(self) -> dict:
        section: dict = {}
        while True:
            token = self._peek()
            if token is None or token.kind == "}":
                return section
            name_token = self._expect("ident")
            name = name_token.value
            next_token = self._peek()
            if next_token is None:
                raise MalformedMetadataTextError(f"Statement {name!r} at position {name_token.position} has no value or body.")
            if next_token.kind == "=":
                self._advance()
                section[name] = self._parse_value()
            elif next_token.kind == "{":
                self._advance()
                nested = self._parse_statements()
                self._expect("}")
                section[name] = nested
            else:
                raise MalformedMetadataTextError(f"Expected '=' or '{{' after {name!r} at position {next_token.position}, found {next_token.kind!r}.")

    def _parse_value(self):
        token = self._advance()
        if token.kind == "int":
            return token.value
        if token.kind == "string":
            return token.value
        if token.kind == "[":
            return self._parse_array()
        raise MalformedMetadataTextError(f"Expected a value at position {token.position}, found {token.kind!r}.")

    def _parse_array(self) -> list:
        items: list = []
        first = self._peek()
        if first is not None and first.kind == "]":
            self._advance()
            return items
        while True:
            token = self._advance()
            if token.kind not in ("int", "string"):
                raise MalformedMetadataTextError(f"Array elements must be integers or strings; found {token.kind!r} at position {token.position}.")
            items.append(token.value)
            separator = self._advance()
            if separator.kind == "]":
                return items
            if separator.kind != ",":
                raise MalformedMetadataTextError(f"Expected ',' or ']' in array at position {separator.position}, found {separator.kind!r}.")


def parse_config_text(text: str) -> dict:
    """Parse LVM2 metadata text into a private, dict-based tree. Never
    returned from any public function in this package -- see the module
    docstring."""
    tokens = _Tokenizer(text).tokens()
    return _Parser(tokens).parse_document()
