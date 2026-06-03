from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import re
from typing import Any

from dateutil import parser as date_parser


SEARCH_SYNTAX_EXAMPLES = [
    'artifact.type:ntfs risk_score>=70',
    'process.name:powershell.exe EncodedCommand',
    'file.name:"invoice.docm"',
    'host.name:"TEST-WIN10-01"',
    'email.from.domain:suspicious.example',
    'detection.source:sigma',
]
MAX_TOKENS = 128
MAX_OR_TERMS = 20
MAX_WILDCARD_CLAUSES = 10
MAX_QUERY_TERMS = 64
_WILDCARD_RE = re.compile(r"[*?]")


class QuerySyntaxError(ValueError):
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


@dataclass(frozen=True)
class Token:
    kind: str
    value: str
    position: int


@dataclass(frozen=True)
class FieldSpec:
    path: str
    kind: str = "keyword"
    wildcard: bool = True
    leading_wildcard: bool = False


@dataclass
class ParsedField:
    name: str
    specs: list[FieldSpec]


class Node:
    pass


@dataclass
class TextNode(Node):
    value: str


@dataclass
class PredicateNode(Node):
    field: ParsedField
    operator: str
    value: str


@dataclass
class ExistsNode(Node):
    field: ParsedField


@dataclass
class NotNode(Node):
    child: Node


@dataclass
class BoolNode(Node):
    operator: str
    children: list[Node]


FIELD_SPECS: dict[str, FieldSpec] = {
    "@timestamp": FieldSpec("@timestamp", kind="date", wildcard=False),
    "case_id": FieldSpec("case_id"),
    "evidence_id": FieldSpec("evidence_id"),
    "stable_event_id": FieldSpec("stable_event_id"),
    "event_fingerprint": FieldSpec("event_fingerprint"),
    "host.name": FieldSpec("host.name"),
    "user.name": FieldSpec("user.name"),
    "user.sid": FieldSpec("user.sid"),
    "artifact.type": FieldSpec("artifact.type"),
    "artifact.parser": FieldSpec("artifact.parser"),
    "event.type": FieldSpec("event.type"),
    "event.action": FieldSpec("event.action"),
    "risk_score": FieldSpec("risk_score", kind="numeric", wildcard=False),
    "severity": FieldSpec("severity"),
    "status": FieldSpec("status"),
    "process.name": FieldSpec("process.name"),
    "process.path": FieldSpec("process.path", kind="text", leading_wildcard=True),
    "process.command_line": FieldSpec("process.command_line", kind="text", leading_wildcard=True),
    "process.parent.name": FieldSpec("process.parent.name"),
    "process.parent.path": FieldSpec("process.parent.path", kind="text", leading_wildcard=True),
    "file.name": FieldSpec("file.name", leading_wildcard=True),
    "file.path": FieldSpec("file.path", kind="text", leading_wildcard=True),
    "file.extension": FieldSpec("file.extension", leading_wildcard=True),
    "file.size": FieldSpec("file.size", kind="numeric", wildcard=False),
    "folder.path": FieldSpec("folder.path", kind="text", leading_wildcard=True),
    "registry.key_path": FieldSpec("registry.key_path", kind="text", leading_wildcard=True),
    "registry.value_name": FieldSpec("registry.value_name"),
    "registry.value_data": FieldSpec("registry.value_data", kind="text", leading_wildcard=True),
    "dns.domain": FieldSpec("dns.domain", leading_wildcard=True),
    "url.full": FieldSpec("url.full", kind="text", leading_wildcard=True),
    "url.domain": FieldSpec("url.domain", leading_wildcard=True),
    "source.ip": FieldSpec("source.ip", wildcard=False),
    "destination.ip": FieldSpec("destination.ip", wildcard=False),
    "network.direction": FieldSpec("network.direction"),
    "email.message_id": FieldSpec("email.message_id", kind="text", leading_wildcard=True),
    "email.subject": FieldSpec("email.subject", kind="text", leading_wildcard=True),
    "email.from.address": FieldSpec("email.from.address", leading_wildcard=True),
    "email.from.domain": FieldSpec("email.from.domain", leading_wildcard=True),
    "email.to.addresses": FieldSpec("email.to.addresses", leading_wildcard=True),
    "email.attachments.file_name": FieldSpec("email.attachments.file_name", leading_wildcard=True),
    "ntfs.reason": FieldSpec("ntfs.reason", kind="text", leading_wildcard=True),
    "ntfs.zone_id": FieldSpec("ntfs.zone_id", kind="numeric", wildcard=False),
    "ntfs.host_url": FieldSpec("ntfs.host_url", kind="text", leading_wildcard=True),
    "ntfs.referrer_url": FieldSpec("ntfs.referrer_url", kind="text", leading_wildcard=True),
    "windows_search.indexed_path": FieldSpec("windows_search.indexed_path", kind="text", leading_wildcard=True),
    "notification.title": FieldSpec("notification.title", kind="text", leading_wildcard=True),
    "notification.body_preview": FieldSpec("notification.body_preview", kind="text", leading_wildcard=True),
    "office.alert_text": FieldSpec("office.alert_text", kind="text", leading_wildcard=True),
    "office.document_path": FieldSpec("office.document_path", kind="text", leading_wildcard=True),
    "rule.id": FieldSpec("rule.id"),
    "rule.name": FieldSpec("rule.name", kind="text", leading_wildcard=True),
    "rule.title": FieldSpec("rule.title", kind="text", leading_wildcard=True),
    "detection.source": FieldSpec("detection.source"),
    "finding.type": FieldSpec("finding.type"),
    "finding.status": FieldSpec("finding.status"),
    "finding.severity": FieldSpec("finding.severity"),
}

FIELD_ALIASES: dict[str, list[str]] = {
    "host": ["host.name"],
    "user": ["user.name"],
    "artifact": ["artifact.type"],
    "type": ["event.type"],
    "event": ["event.type"],
    "process": ["process.name"],
    "command": ["process.command_line"],
    "file": ["file.path", "file.name"],
    "path": ["file.path", "folder.path", "process.path"],
    "domain": ["dns.domain", "url.domain", "email.from.domain"],
    "ip": ["source.ip", "destination.ip"],
    "url": ["url.full"],
    "hash": ["file.sha256", "file.sha1", "file.md5"],
    "rule": ["rule.name", "rule.title", "rule.id"],
    "source": ["detection.source", "artifact.parser"],
    "parser": ["artifact.parser"],
    "risk": ["risk_score"],
    "severity": ["severity", "finding.severity"],
    "status": ["status", "finding.status"],
    "stable": ["stable_event_id"],
}

# Non-spec alias-only actuals for evaluator/querying.
FIELD_SPECS.update(
    {
        "file.sha256": FieldSpec("file.sha256", wildcard=False),
        "file.sha1": FieldSpec("file.sha1", wildcard=False),
        "file.md5": FieldSpec("file.md5", wildcard=False),
    }
)


def query_has_advanced_syntax(query: str | None) -> bool:
    text = str(query or "").strip()
    if not text:
        return False
    for match in re.finditer(r"([@A-Za-z_][\w.@-]*)\s*(>=|<=|:|>|<)", text):
        field_name = match.group(1)
        if field_name in FIELD_SPECS or field_name in FIELD_ALIASES or "." in field_name or field_name.startswith("@"):
            return True
    return bool(
        re.search(r"(^|\s)(AND|OR|NOT)(\s|$)", text, flags=re.IGNORECASE)
        or re.search(r"\bhas\s*:\s*[@A-Za-z_]", text, flags=re.IGNORECASE)
        or "(" in text
        or ")" in text
    )


def _tokenize(query: str) -> list[Token]:
    tokens: list[Token] = []
    i = 0
    while i < len(query):
        char = query[i]
        if char.isspace():
            i += 1
            continue
        if char in "()":
            tokens.append(Token(char, char, i))
            i += 1
            continue
        if query.startswith(">=", i) or query.startswith("<=", i):
            tokens.append(Token("OP", query[i : i + 2], i))
            i += 2
            continue
        if char in ":<>":
            tokens.append(Token("OP", char, i))
            i += 1
            continue
        if char == '"':
            start = i
            i += 1
            buffer: list[str] = []
            while i < len(query):
                if query[i] == "\\" and i + 1 < len(query):
                    buffer.append(query[i + 1])
                    i += 2
                    continue
                if query[i] == '"':
                    i += 1
                    break
                buffer.append(query[i])
                i += 1
            else:
                raise QuerySyntaxError(f'Invalid search query: unclosed quote near position {start + 1}.')
            tokens.append(Token("STRING", "".join(buffer), start))
            continue
        start = i
        while i < len(query) and (not query[i].isspace()) and query[i] not in '()<>:"':
            i += 1
        value = query[start:i]
        upper = value.upper()
        if upper in {"AND", "OR", "NOT"}:
            tokens.append(Token(upper, upper, start))
        else:
            tokens.append(Token("WORD", value, start))
    if len(tokens) > MAX_TOKENS:
        raise QuerySyntaxError(f"Invalid search query: too many tokens ({len(tokens)}). Limit is {MAX_TOKENS}.")
    return tokens


def _resolve_field(name: str) -> ParsedField:
    normalized = name.strip()
    actuals = FIELD_ALIASES.get(normalized, [normalized])
    specs = [FIELD_SPECS.get(item) for item in actuals]
    if any(spec is None for spec in specs):
        raise QuerySyntaxError(f"Invalid search query: field '{name}' is not supported.")
    return ParsedField(name=normalized, specs=[spec for spec in specs if spec is not None])


class _Parser:
    def __init__(self, tokens: list[Token]):
        self.tokens = tokens
        self.index = 0
        self.wildcard_clauses = 0
        self.or_terms = 0

    def parse(self) -> Node:
        node = self._parse_or()
        if self._peek() is not None:
            token = self._peek()
            raise QuerySyntaxError(f"Invalid search query near '{token.value}' at position {token.position + 1}.")
        if self.or_terms > MAX_OR_TERMS:
            raise QuerySyntaxError(f"Invalid search query: too many OR clauses ({self.or_terms}). Limit is {MAX_OR_TERMS}.")
        if self.wildcard_clauses > MAX_WILDCARD_CLAUSES:
            raise QuerySyntaxError(f"Invalid search query: too many wildcard clauses ({self.wildcard_clauses}). Limit is {MAX_WILDCARD_CLAUSES}.")
        return node

    def _peek(self) -> Token | None:
        return self.tokens[self.index] if self.index < len(self.tokens) else None

    def _consume(self) -> Token:
        token = self._peek()
        if token is None:
            raise QuerySyntaxError("Invalid search query: unexpected end of query.")
        self.index += 1
        return token

    def _accept(self, kind: str, value: str | None = None) -> Token | None:
        token = self._peek()
        if token is None or token.kind != kind:
            return None
        if value is not None and token.value != value:
            return None
        self.index += 1
        return token

    def _parse_or(self) -> Node:
        nodes = [self._parse_and()]
        while self._accept("OR"):
            self.or_terms += 1
            nodes.append(self._parse_and())
        if len(nodes) == 1:
            return nodes[0]
        return BoolNode("OR", nodes)

    def _parse_and(self) -> Node:
        nodes = [self._parse_unary()]
        while True:
            if self._accept("AND"):
                nodes.append(self._parse_unary())
                continue
            next_token = self._peek()
            if next_token and next_token.kind in {"WORD", "STRING", "NOT", "("}:
                nodes.append(self._parse_unary())
                continue
            break
        if len(nodes) == 1:
            return nodes[0]
        if len(nodes) > MAX_QUERY_TERMS:
            raise QuerySyntaxError(f"Invalid search query: too many clauses ({len(nodes)}). Limit is {MAX_QUERY_TERMS}.")
        return BoolNode("AND", nodes)

    def _parse_unary(self) -> Node:
        if self._accept("NOT"):
            return NotNode(self._parse_unary())
        return self._parse_primary()

    def _parse_primary(self) -> Node:
        if self._accept("("):
            node = self._parse_or()
            if not self._accept(")"):
                raise QuerySyntaxError("Invalid search query: unclosed parenthesis.")
            return node
        return self._parse_atom()

    def _parse_atom(self) -> Node:
        token = self._peek()
        if token is None:
            raise QuerySyntaxError("Invalid search query: missing expression.")
        if token.kind == "WORD" and token.value.lower() == "has":
            self._consume()
            if not self._accept("OP", ":"):
                raise QuerySyntaxError("Invalid search query: expected ':' after has.")
            field_token = self._consume()
            if field_token.kind != "WORD":
                raise QuerySyntaxError("Invalid search query: expected field name after has:.")
            return ExistsNode(_resolve_field(field_token.value))
        if token.kind == "WORD":
            next_token = self.tokens[self.index + 1] if self.index + 1 < len(self.tokens) else None
            if next_token and next_token.kind == "OP":
                field = _resolve_field(self._consume().value)
                operator = self._consume().value
                value_token = self._consume()
                if value_token.kind not in {"WORD", "STRING"}:
                    raise QuerySyntaxError(f"Invalid search query near '{value_token.value}' at position {value_token.position + 1}.")
                value = value_token.value
                if _WILDCARD_RE.search(value):
                    self.wildcard_clauses += 1
                return PredicateNode(field, operator, value)
        if token.kind in {"WORD", "STRING"}:
            return TextNode(self._consume().value)
        raise QuerySyntaxError(f"Invalid search query near '{token.value}' at position {token.position + 1}.")


def _normalize_string(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


def _coerce_value(spec: FieldSpec, value: str) -> Any:
    if spec.kind == "numeric":
        try:
            return float(value) if "." in value else int(value)
        except ValueError as exc:
            raise QuerySyntaxError(f"Invalid search query: '{value}' is not a valid numeric value for {spec.path}.") from exc
    if spec.kind == "date":
        try:
            parsed = date_parser.parse(value)
        except Exception as exc:  # noqa: BLE001
            raise QuerySyntaxError(f"Invalid search query: '{value}' is not a valid timestamp for {spec.path}.") from exc
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC).isoformat()
    return value


def _query_for_spec(spec: FieldSpec, operator: str, value: str) -> dict[str, Any]:
    coerced = _coerce_value(spec, value)
    if operator in {">", ">=", "<", "<="}:
        if spec.kind not in {"numeric", "date"}:
            raise QuerySyntaxError(f"Invalid search query: operator '{operator}' is not supported for field {spec.path}.")
        mapping = {">": "gt", ">=": "gte", "<": "lt", "<=": "lte"}
        return {"range": {spec.path: {mapping[operator]: coerced}}}
    if operator != ":":
        raise QuerySyntaxError(f"Invalid search query: operator '{operator}' is not supported.")
    if spec.kind in {"numeric", "date"}:
        return {"term": {spec.path: coerced}}
    if _WILDCARD_RE.search(value):
        if not spec.wildcard:
            raise QuerySyntaxError(f"Invalid search query: wildcards are not supported for field {spec.path}.")
        if value.startswith("*") and not spec.leading_wildcard:
            raise QuerySyntaxError(f"Invalid search query: leading wildcards are not supported for field {spec.path}.")
        return {"wildcard": {spec.path: {"value": value, "case_insensitive": True}}}
    if spec.kind == "text":
        return {"match_phrase": {spec.path: value}}
    return {"term": {spec.path: value}}


def _collect_filters(node: Node) -> list[dict[str, str]]:
    filters: list[dict[str, str]] = []
    if isinstance(node, PredicateNode):
        filters.append({"field": node.field.name, "operator": node.operator, "value": node.value})
    elif isinstance(node, ExistsNode):
        filters.append({"field": node.field.name, "operator": "has", "value": ""})
    elif isinstance(node, NotNode):
        filters.extend(_collect_filters(node.child))
    elif isinstance(node, BoolNode):
        for child in node.children:
            filters.extend(_collect_filters(child))
    return filters


def _has_text_terms(node: Node | None) -> bool:
    if node is None:
        return False
    if isinstance(node, TextNode):
        return True
    if isinstance(node, NotNode):
        return _has_text_terms(node.child)
    if isinstance(node, BoolNode):
        return any(_has_text_terms(child) for child in node.children)
    return False


def _build_query(node: Node, text_query_builder) -> dict[str, Any]:  # noqa: ANN001
    if isinstance(node, TextNode):
        return text_query_builder(node.value)
    if isinstance(node, ExistsNode):
        if len(node.field.specs) == 1:
            return {"exists": {"field": node.field.specs[0].path}}
        return {
            "bool": {
                "should": [{"exists": {"field": spec.path}} for spec in node.field.specs],
                "minimum_should_match": 1,
            }
        }
    if isinstance(node, PredicateNode):
        clauses = [_query_for_spec(spec, node.operator, node.value) for spec in node.field.specs]
        if len(clauses) == 1:
            return clauses[0]
        return {"bool": {"should": clauses, "minimum_should_match": 1}}
    if isinstance(node, NotNode):
        return {"bool": {"must_not": [_build_query(node.child, text_query_builder)]}}
    if isinstance(node, BoolNode):
        if node.operator == "OR":
            return {"bool": {"should": [_build_query(child, text_query_builder) for child in node.children], "minimum_should_match": 1}}
        return {"bool": {"must": [_build_query(child, text_query_builder) for child in node.children]}}
    raise QuerySyntaxError("Invalid search query: unsupported expression.")


def _iter_values(payload: dict[str, Any], path: str) -> list[Any]:
    current: list[Any] = [payload]
    for part in path.split("."):
        next_values: list[Any] = []
        for item in current:
            if isinstance(item, dict):
                value = item.get(part)
                if isinstance(value, list):
                    next_values.extend(value)
                elif value is not None:
                    next_values.append(value)
            elif isinstance(item, list):
                next_values.extend(item)
        current = next_values
    flattened: list[Any] = []
    for item in current:
        if isinstance(item, list):
            flattened.extend(item)
        else:
            flattened.append(item)
    return flattened


def _match_string(value: str, expected: str) -> bool:
    regex = "^" + re.escape(expected).replace(r"\*", ".*").replace(r"\?", ".") + "$"
    return bool(re.search(regex, value, flags=re.IGNORECASE))


def _evaluate_spec(spec: FieldSpec, operator: str, expected: str, candidate: Any) -> bool:
    if candidate is None:
        return False
    if operator in {">", ">=", "<", "<="}:
        expected_value = _coerce_value(spec, expected)
        if spec.kind == "date":
            try:
                candidate_value = date_parser.parse(_normalize_string(candidate))
            except Exception:  # noqa: BLE001
                return False
            if candidate_value.tzinfo is None:
                candidate_value = candidate_value.replace(tzinfo=UTC)
            candidate_value = candidate_value.astimezone(UTC).isoformat()
        else:
            try:
                candidate_value = float(candidate) if "." in _normalize_string(candidate) else int(candidate)
            except Exception:  # noqa: BLE001
                return False
        mapping = {
            ">": candidate_value > expected_value,
            ">=": candidate_value >= expected_value,
            "<": candidate_value < expected_value,
            "<=": candidate_value <= expected_value,
        }
        return bool(mapping[operator])
    candidate_text = _normalize_string(candidate)
    if _WILDCARD_RE.search(expected):
        return _match_string(candidate_text, expected)
    return candidate_text.lower() == expected.lower() if spec.kind != "numeric" else candidate_text == expected


def _evaluate(node: Node, payload: dict[str, Any], text_haystack: str) -> bool:
    if isinstance(node, TextNode):
        return node.value.lower() in text_haystack
    if isinstance(node, ExistsNode):
        return any(_iter_values(payload, spec.path) for spec in node.field.specs)
    if isinstance(node, PredicateNode):
        for spec in node.field.specs:
            for candidate in _iter_values(payload, spec.path):
                if _evaluate_spec(spec, node.operator, node.value, candidate):
                    return True
        return False
    if isinstance(node, NotNode):
        return not _evaluate(node.child, payload, text_haystack)
    if isinstance(node, BoolNode):
        if node.operator == "OR":
            return any(_evaluate(child, payload, text_haystack) for child in node.children)
        return all(_evaluate(child, payload, text_haystack) for child in node.children)
    return False


def analyze_query_syntax(query: str, text_query_builder) -> dict[str, Any]:  # noqa: ANN001
    text = str(query or "").strip()
    if not text:
        return {
            "mode": "plain",
            "parsed": True,
            "errors": [],
            "warnings": [],
            "normalized_query": "",
            "applied_filters": [],
            "ast": None,
            "query": text_query_builder(""),
        }
    if not query_has_advanced_syntax(text):
        return {
            "mode": "plain",
            "parsed": True,
            "errors": [],
            "warnings": [],
            "normalized_query": text,
            "applied_filters": [],
            "ast": None,
            "query": text_query_builder(text),
        }
    tokens = _tokenize(text)
    ast = _Parser(tokens).parse()
    filters = _collect_filters(ast)
    has_text_terms = _has_text_terms(ast)
    has_field_filters = bool(filters)
    mode = "mixed" if has_text_terms and has_field_filters else "advanced"
    return {
        "mode": mode,
        "parsed": True,
        "errors": [],
        "warnings": [],
        "normalized_query": text,
        "applied_filters": filters,
        "ast": ast,
        "query": _build_query(ast, text_query_builder),
    }


def evaluate_query_syntax(query_info: dict[str, Any], payload: dict[str, Any], text_haystack: str) -> bool:
    ast = query_info.get("ast")
    if ast is None:
        query_text = str(query_info.get("normalized_query") or "").strip().lower()
        return not query_text or query_text in text_haystack
    return _evaluate(ast, payload, text_haystack)
