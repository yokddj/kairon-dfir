from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import lzma
import os
import re
import socket
import ssl
import struct
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, urljoin, urlsplit


PDB_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,120}\.pdb$", re.IGNORECASE)
PDB_GUID = re.compile(r"^[0-9A-F]{32}$")
MSF7_SIGNATURE = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"


class SymbolFetchError(RuntimeError):
    def __init__(self, code: str, message: str, *, retryable: bool = False):
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable


@dataclass(frozen=True)
class SymbolIdentity:
    pdb_name: str
    guid: str
    age: int
    architecture: str

    @property
    def key(self) -> str:
        return f"{self.pdb_name.lower()}/{self.guid}-{self.age}"

    def validate(self) -> None:
        if not PDB_NAME.fullmatch(self.pdb_name) or any(token in self.pdb_name for token in ("/", "\\", "%")):
            raise SymbolFetchError("SYMBOL_IDENTITY_INVALID", "The recorded PDB name is invalid.")
        if not PDB_GUID.fullmatch(self.guid.upper()):
            raise SymbolFetchError("SYMBOL_IDENTITY_INVALID", "The recorded PDB GUID is invalid.")
        if not 0 <= int(self.age) <= 0xFFFFFFFF:
            raise SymbolFetchError("SYMBOL_IDENTITY_INVALID", "The recorded PDB age is invalid.")
        if self.architecture not in {"x64", "x86", "arm64"}:
            raise SymbolFetchError("SYMBOL_IDENTITY_INVALID", "The recorded symbol architecture is invalid.")


def official_symbol_url(identity: SymbolIdentity, initial_host: str = "msdl.microsoft.com", path_prefix: str = "/download/symbols") -> str:
    identity.validate()
    name = quote(identity.pdb_name, safe="._-")
    key = quote(f"{identity.guid.upper()}{identity.age}", safe="")
    return f"https://{initial_host}{path_prefix}/{name}/{key}/{name}"


def _public_addresses(host: str, port: int = 443) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SymbolFetchError("SYMBOL_DOWNLOAD_FAILED", "Official symbol destination could not be resolved.", retryable=True) from exc
    addresses = sorted({item[4][0] for item in infos})
    if not addresses:
        raise SymbolFetchError("SYMBOL_DOWNLOAD_FAILED", "Official symbol destination returned no addresses.", retryable=True)
    for raw in addresses:
        address = ipaddress.ip_address(raw)
        if not address.is_global or address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified:
            raise SymbolFetchError("SYMBOL_SOURCE_NOT_ALLOWED", "Official symbol destination resolved to a disallowed address.")
    return addresses


def validate_destination(url: str, *, initial: bool, initial_host: str, redirect_suffixes: list[str]) -> tuple[str, str, int]:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.username or parsed.password or parsed.fragment:
        raise SymbolFetchError("SYMBOL_SOURCE_NOT_ALLOWED", "Symbol destination is not an approved HTTPS endpoint.")
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host or parsed.port not in (None, 443):
        raise SymbolFetchError("SYMBOL_SOURCE_NOT_ALLOWED", "Symbol destination host or port is not approved.")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise SymbolFetchError("SYMBOL_SOURCE_NOT_ALLOWED", "IP-literal symbol destinations are not allowed.")
    if initial:
        allowed = host == initial_host.lower().rstrip(".")
    else:
        allowed = host == initial_host.lower().rstrip(".") or any(host.endswith(suffix) and host != suffix.lstrip(".") for suffix in redirect_suffixes)
    if not allowed:
        raise SymbolFetchError("SYMBOL_SOURCE_NOT_ALLOWED", "Symbol destination is outside approved official infrastructure.")
    path = parsed.path or "/"
    if any(ord(char) < 32 for char in path) or "\\" in path:
        raise SymbolFetchError("SYMBOL_SOURCE_NOT_ALLOWED", "Symbol destination path is invalid.")
    return host, path + (f"?{parsed.query}" if parsed.query else ""), 443


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, address: str, *, timeout: float):
        super().__init__(host, port=443, timeout=timeout, context=ssl.create_default_context())
        self._address = address

    def connect(self) -> None:
        sock = socket.create_connection((self._address, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def download_official_pdb(
    identity: SymbolIdentity,
    partial_path: Path,
    *,
    initial_host: str,
    redirect_suffixes: list[str],
    connect_timeout: int,
    total_timeout: int,
    max_redirects: int,
    max_bytes: int,
) -> dict[str, object]:
    url = official_symbol_url(identity, initial_host)
    started = time.monotonic()
    redirects = 0
    partial_path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    if partial_path.exists() or partial_path.is_symlink():
        raise SymbolFetchError("SYMBOL_CACHE_WRITE_FAILED", "A symbol partial already exists.")
    while True:
        host, target, _ = validate_destination(url, initial=redirects == 0, initial_host=initial_host, redirect_suffixes=redirect_suffixes)
        if time.monotonic() - started > total_timeout:
            raise SymbolFetchError("SYMBOL_DOWNLOAD_TIMEOUT", "Official symbol download timed out.", retryable=True)
        addresses = _public_addresses(host)
        connection = _PinnedHTTPSConnection(host, addresses[0], timeout=max(1, connect_timeout))
        try:
            connection.request("GET", target, headers={"Accept": "application/octet-stream", "User-Agent": "Kairon-Symbol-Fetcher/1"})
            response = connection.getresponse()
            if response.status in {301, 302, 303, 307, 308}:
                location = response.getheader("Location")
                response.read(4096)
                if not location or redirects >= max_redirects:
                    raise SymbolFetchError("SYMBOL_DOWNLOAD_FAILED", "Official symbol redirect limit was exceeded.", retryable=True)
                next_url = urljoin(url, location)
                validate_destination(next_url, initial=False, initial_host=initial_host, redirect_suffixes=redirect_suffixes)
                url = next_url
                redirects += 1
                continue
            if response.status != 200:
                raise SymbolFetchError("SYMBOL_DOWNLOAD_FAILED", "Official symbol source did not return the requested symbol.", retryable=response.status >= 500)
            declared = response.getheader("Content-Length")
            if declared:
                try:
                    declared_size = int(declared)
                except ValueError as exc:
                    raise SymbolFetchError("SYMBOL_DOWNLOAD_FAILED", "Official symbol source returned an invalid size.") from exc
                if declared_size < 0 or declared_size > max_bytes:
                    raise SymbolFetchError("SYMBOL_DOWNLOAD_TOO_LARGE", "Official symbol exceeds the configured download limit.")
            digest = hashlib.sha256()
            written = 0
            descriptor = os.open(partial_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o640)
            try:
                with os.fdopen(descriptor, "wb") as output:
                    while True:
                        if time.monotonic() - started > total_timeout:
                            raise SymbolFetchError("SYMBOL_DOWNLOAD_TIMEOUT", "Official symbol download timed out.", retryable=True)
                        chunk = response.read(min(1024 * 1024, max_bytes - written + 1))
                        if not chunk:
                            break
                        written += len(chunk)
                        if written > max_bytes:
                            raise SymbolFetchError("SYMBOL_DOWNLOAD_TOO_LARGE", "Official symbol exceeds the configured download limit.")
                        digest.update(chunk)
                        output.write(chunk)
                    output.flush()
                    os.fsync(output.fileno())
            except Exception:
                partial_path.unlink(missing_ok=True)
                raise
            return {"bytes": written, "sha256": digest.hexdigest(), "redirects": redirects, "duration_ms": int((time.monotonic() - started) * 1000)}
        except (TimeoutError, socket.timeout) as exc:
            partial_path.unlink(missing_ok=True)
            raise SymbolFetchError("SYMBOL_DOWNLOAD_TIMEOUT", "Official symbol download timed out.", retryable=True) from exc
        except ssl.SSLError as exc:
            partial_path.unlink(missing_ok=True)
            raise SymbolFetchError("SYMBOL_DOWNLOAD_FAILED", "Official symbol TLS validation failed.") from exc
        except (OSError, http.client.HTTPException) as exc:
            partial_path.unlink(missing_ok=True)
            raise SymbolFetchError("SYMBOL_DOWNLOAD_FAILED", "Official symbol download failed.", retryable=True) from exc
        finally:
            connection.close()


def _read_stream(handle, block_size: int, blocks: list[int], size: int) -> bytes:
    result = bytearray()
    for block in blocks:
        handle.seek(block * block_size)
        result.extend(handle.read(min(block_size, size - len(result))))
        if len(result) >= size:
            break
    return bytes(result[:size])


def read_pdb_identity(path: Path) -> tuple[str, int]:
    with path.open("rb") as handle:
        superblock = handle.read(56)
        if len(superblock) != 56 or superblock[:32] != MSF7_SIGNATURE:
            raise SymbolFetchError("SYMBOL_PDB_INVALID", "Downloaded symbol is not a supported PDB file.")
        block_size, _, num_blocks, directory_size, _, block_map = struct.unpack_from("<6I", superblock, 32)
        if block_size not in {512, 1024, 2048, 4096} or num_blocks <= 0 or directory_size <= 0 or directory_size > 64 * 1024 * 1024:
            raise SymbolFetchError("SYMBOL_PDB_INVALID", "Downloaded PDB structure is invalid.")
        directory_blocks = (directory_size + block_size - 1) // block_size
        handle.seek(block_map * block_size)
        block_numbers = list(struct.unpack(f"<{directory_blocks}I", handle.read(directory_blocks * 4)))
        directory = _read_stream(handle, block_size, block_numbers, directory_size)
        stream_count = struct.unpack_from("<I", directory, 0)[0]
        if stream_count < 2 or stream_count > 100000:
            raise SymbolFetchError("SYMBOL_PDB_INVALID", "Downloaded PDB stream table is invalid.")
        sizes = list(struct.unpack_from(f"<{stream_count}I", directory, 4))
        cursor = 4 + stream_count * 4
        streams: list[list[int]] = []
        for size in sizes:
            count = 0 if size == 0xFFFFFFFF else (size + block_size - 1) // block_size
            blocks = list(struct.unpack_from(f"<{count}I", directory, cursor)) if count else []
            cursor += count * 4
            streams.append(blocks)
        pdb_stream = _read_stream(handle, block_size, streams[1], sizes[1])
        if len(pdb_stream) < 28:
            raise SymbolFetchError("SYMBOL_PDB_INVALID", "Downloaded PDB identity stream is incomplete.")
        _, _, age = struct.unpack_from("<III", pdb_stream, 0)
        guid = uuid.UUID(bytes_le=pdb_stream[12:28]).hex.upper()
        return guid, age


def validate_pdb(path: Path, identity: SymbolIdentity) -> dict[str, int | str]:
    """Validate the downloaded PDB identity against the requirement.

    The check is strict: both the GUID and the age must match the
    authoritative identity recorded in the requirement.  Microsoft
    re-publishes PDB files at the same URL with a different internal
    age when the file is updated; the kernel PE's CodeView RSDS
    record is the authoritative source for the age the kernel was
    built against.  A discrepancy is surfaced as
    ``SYMBOL_PDB_IDENTITY_MISMATCH`` with the expected and observed
    values so the operator can investigate; the caller must not
    silently rewrite the requirement.

    Returns a dict with ``guid``, ``age`` and ``architecture`` on
    success.  Raises :class:`SymbolFetchError` with code
    ``SYMBOL_PDB_IDENTITY_MISMATCH`` on any identity discrepancy.
    """
    guid, age = read_pdb_identity(path)
    expected_guid = identity.guid.upper()
    expected_age = int(identity.age)
    if guid != expected_guid or age != expected_age:
        raise SymbolFetchError(
            "SYMBOL_PDB_IDENTITY_MISMATCH",
            (
                "Downloaded PDB identity does not match the required symbol: "
                f"expected GUID={expected_guid} age={expected_age}, "
                f"observed GUID={guid} age={age}."
            ),
            retryable=False,
        )
    return {
        "guid": guid,
        "expected_guid": expected_guid,
        "age": int(age),
        "expected_age": expected_age,
        "architecture": identity.architecture,
    }


def generate_isf(pdb_path: Path, output_path: Path, identity: SymbolIdentity, *, max_bytes: int) -> dict[str, object]:
    """Generate the Volatility ISF from a downloaded PDB.

    The validation is split into four distinct layers, each with its
    own :class:`SymbolFetchError` code so the caller can tell which
    stage disagreed:

    1. ``SYMBOL_ISF_PARSE_FAILED`` — Volatility could not parse the
       PDB into a usable ISF (missing sections, schema failure).
    2. ``SYMBOL_ISF_IDENTITY_MISSING`` — the ISF was generated but
       the ``metadata.windows.pdb`` identity block is absent.
    3. ``SYMBOL_ISF_IDENTITY_MISMATCH`` — the ISF identity disagrees
       with the authoritative requirement (GUID or age differs).
    4. ``SYMBOL_ISF_VOLATILITY_VALIDATION_FAILED`` — the ISF could
       not be re-loaded from disk (corrupt compression / truncated).

    All four are permanent failures: the operator must intervene.
    """
    from volatility3.framework import contexts
    from volatility3.framework.symbols.windows import pdbconv

    location = pdb_path.resolve().as_uri()
    try:
        payload = pdbconv.PdbReader(contexts.Context(), location, identity.pdb_name).get_json()
    except Exception as exc:  # noqa: BLE001
        raise SymbolFetchError(
            "SYMBOL_ISF_PARSE_FAILED",
            f"Volatility could not parse the PDB into an ISF: {type(exc).__name__}.",
        ) from exc
    if not isinstance(payload, dict):
        raise SymbolFetchError("SYMBOL_ISF_PARSE_FAILED", "Generated Volatility ISF payload is not a dictionary.")
    if not isinstance(payload.get("metadata"), dict):
        raise SymbolFetchError("SYMBOL_ISF_PARSE_FAILED", "Generated Volatility ISF has no metadata section.")
    if not isinstance(payload.get("symbols"), dict):
        raise SymbolFetchError("SYMBOL_ISF_PARSE_FAILED", "Generated Volatility ISF has no symbols section.")
    if not isinstance(payload.get("user_types"), dict):
        raise SymbolFetchError("SYMBOL_ISF_PARSE_FAILED", "Generated Volatility ISF has no user_types section.")
    metadata = payload.get("metadata") or {}
    if not isinstance(metadata.get("windows"), dict):
        raise SymbolFetchError("SYMBOL_ISF_IDENTITY_MISSING", "Generated Volatility ISF has no windows metadata block.")
    pdb_metadata = metadata.get("windows", {}).get("pdb")
    if not isinstance(pdb_metadata, dict):
        raise SymbolFetchError("SYMBOL_ISF_IDENTITY_MISSING", "Generated Volatility ISF has no PDB identity block.")
    generated_guid = str(pdb_metadata.get("GUID") or "").replace("-", "").replace("{", "").replace("}", "").upper()
    generated_age = pdb_metadata.get("age")
    try:
        generated_age_value = int(generated_age)
    except (TypeError, ValueError):
        generated_age_value = -1
    expected_guid = identity.guid.upper()
    expected_age = int(identity.age)
    if generated_guid != expected_guid or generated_age_value != expected_age:
        raise SymbolFetchError(
            "SYMBOL_ISF_IDENTITY_MISMATCH",
            (
                "Generated Volatility ISF identity does not match the required symbol: "
                f"expected GUID={expected_guid} age={expected_age}, "
                f"observed GUID={generated_guid or '<missing>'} age={generated_age_value}."
            ),
        )
    output_path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    temporary = output_path.with_suffix(output_path.suffix + ".partial")
    digest = hashlib.sha256()
    encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if len(encoded) > max_bytes:
        raise SymbolFetchError("SYMBOL_ISF_GENERATION_FAILED", "Generated Volatility ISF exceeds the configured limit.")
    compressed = lzma.compress(encoded)
    if len(compressed) > max_bytes:
        raise SymbolFetchError("SYMBOL_ISF_GENERATION_FAILED", "Generated Volatility ISF exceeds the configured limit.")
    digest.update(compressed)
    with temporary.open("xb") as handle:
        os.chmod(temporary, 0o640)
        handle.write(compressed)
        handle.flush()
        os.fsync(handle.fileno())
    with lzma.open(temporary, "rb") as handle:
        checked = json.load(handle)
    if not isinstance(checked, dict) or not isinstance(checked.get("metadata"), dict):
        temporary.unlink(missing_ok=True)
        raise SymbolFetchError("SYMBOL_ISF_VOLATILITY_VALIDATION_FAILED", "Generated Volatility ISF could not be re-loaded from disk.")
    os.replace(temporary, output_path)
    return {"bytes": len(compressed), "sha256": digest.hexdigest(), "isf_guid": expected_guid, "isf_age": expected_age}
