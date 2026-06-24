"""Static checks for the Docker network topology of the symbol subsystem.

These tests inspect the compose source for the symbol-fetcher and
symbol-egress-gateway services.  They are the application-side mirror of
the runtime proof: the fetcher must NOT be on a network with a default
route, and the gateway must be the only one connected to such a network.
"""
from __future__ import annotations

import re
from pathlib import Path


COMPOSE_PATH = Path(__file__).parents[2] / "docker-compose.yml"


def _service_block(compose: str, name: str) -> str:
    lines = compose.splitlines()
    inside = False
    collected: list[str] = []
    for line in lines:
        if line.startswith(f"  {name}:"):
            inside = True
            continue
        if inside and line.startswith("  ") and not line.startswith("    ") and line.rstrip().endswith(":"):
            break
        if inside:
            collected.append(line)
    return "\n".join(collected)


def _networks_for_service(service_block: str) -> list[str]:
    match = re.search(r"^    networks:\s*$", service_block, re.MULTILINE)
    if not match:
        return []
    block = service_block[match.end():]
    out: list[str] = []
    for line in block.splitlines():
        if not line.strip():
            continue
        if not line.startswith("      - "):
            break
        out.append(line.split("- ", 1)[1].strip())
    return out


def test_compose_source_available() -> None:
    if not COMPOSE_PATH.exists():
        import pytest
        pytest.skip("Compose source is not copied into the backend test image; runtime inspection covers this assertion.")
    assert COMPOSE_PATH.read_text().strip()


def test_symbol_fetcher_is_on_internal_only_networks() -> None:
    if not COMPOSE_PATH.exists():
        import pytest
        pytest.skip("Compose source is not copied into the backend test image; runtime inspection covers this assertion.")
    compose = COMPOSE_PATH.read_text()
    service = _service_block(compose, "symbol-fetcher")
    networks = sorted(_networks_for_service(service))
    assert networks == sorted(["symbol-internal", "symbol-fetcher-channel"]), f"symbol-fetcher must only be on internal networks; got {networks}"


def test_symbol_egress_gateway_on_channel_and_egress_only() -> None:
    if not COMPOSE_PATH.exists():
        import pytest
        pytest.skip("Compose source is not copied into the backend test image; runtime inspection covers this assertion.")
    compose = COMPOSE_PATH.read_text()
    service = _service_block(compose, "symbol-egress-gateway")
    networks = sorted(_networks_for_service(service))
    assert networks == sorted(["symbol-fetcher-channel", "symbol-egress"]), f"gateway must be on fetcher-channel+egress only; got {networks}"


def test_symbol_egress_gateway_is_not_on_symbol_internal() -> None:
    """The gateway must not have a path to postgres/redis via the
    internal network.  It only shares the dedicated fetcher-channel
    with the symbol-fetcher.
    """
    if not COMPOSE_PATH.exists():
        import pytest
        pytest.skip("Compose source is not copied into the backend test image; runtime inspection covers this assertion.")
    compose = COMPOSE_PATH.read_text()
    service = _service_block(compose, "symbol-egress-gateway")
    networks = _networks_for_service(service)
    assert "symbol-internal" not in networks, f"gateway must not be on symbol-internal; got {networks}"


def test_internal_network_marks_internal_true() -> None:
    if not COMPOSE_PATH.exists():
        import pytest
        pytest.skip("Compose source is not copied into the backend test image; runtime inspection covers this assertion.")
    compose = COMPOSE_PATH.read_text()
    networks_section = compose.split("networks:", 1)[1]
    internal_block = networks_section.split("symbol-internal:", 1)[1].split("symbol-fetcher-channel:", 1)[0]
    assert "internal: true" in internal_block


def test_fetcher_channel_marks_internal_true() -> None:
    if not COMPOSE_PATH.exists():
        import pytest
        pytest.skip("Compose source is not copied into the backend test image; runtime inspection covers this assertion.")
    compose = COMPOSE_PATH.read_text()
    networks_section = compose.split("networks:", 1)[1]
    channel_block = networks_section.split("symbol-fetcher-channel:", 1)[1].split("symbol-egress:", 1)[0]
    assert "internal: true" in channel_block


def test_egress_network_has_no_internal_flag() -> None:
    if not COMPOSE_PATH.exists():
        import pytest
        pytest.skip("Compose source is not copied into the backend test image; runtime inspection covers this assertion.")
    compose = COMPOSE_PATH.read_text()
    networks_section = compose.split("networks:", 1)[1]
    egress_block = networks_section.split("symbol-egress:", 1)[1]
    assert "internal: true" not in egress_block


def test_symbol_fetcher_has_no_public_ports() -> None:
    if not COMPOSE_PATH.exists():
        import pytest
        pytest.skip("Compose source is not copied into the backend test image; runtime inspection covers this assertion.")
    compose = COMPOSE_PATH.read_text()
    service = _service_block(compose, "symbol-fetcher")
    assert "ports:" not in service


def test_symbol_egress_gateway_has_no_public_ports() -> None:
    if not COMPOSE_PATH.exists():
        import pytest
        pytest.skip("Compose source is not copied into the backend test image; runtime inspection covers this assertion.")
    compose = COMPOSE_PATH.read_text()
    service = _service_block(compose, "symbol-egress-gateway")
    assert "ports:" not in service


def test_symbol_egress_gateway_does_not_mount_evidence() -> None:
    if not COMPOSE_PATH.exists():
        import pytest
        pytest.skip("Compose source is not copied into the backend test image; runtime inspection covers this assertion.")
    compose = COMPOSE_PATH.read_text()
    service = _service_block(compose, "symbol-egress-gateway")
    assert "data/evidence" not in service
    assert "memory-output" not in service


def test_symbol_egress_gateway_has_no_symbol_cache_write_mount() -> None:
    if not COMPOSE_PATH.exists():
        import pytest
        pytest.skip("Compose source is not copied into the backend test image; runtime inspection covers this assertion.")
    compose = COMPOSE_PATH.read_text()
    service = _service_block(compose, "symbol-egress-gateway")
    assert "memory-symbol-cache" not in service


def test_no_other_service_uses_internal_network() -> None:
    """The symbol-internal network is reserved for the symbol-fetcher and
    the core database/queue services.  No application tier (backend,
    frontend, worker, opensearch) may attach to it.
    """
    if not COMPOSE_PATH.exists():
        import pytest
        pytest.skip("Compose source is not copied into the backend test image; runtime inspection covers this assertion.")
    compose = COMPOSE_PATH.read_text()
    forbidden = ["backend", "frontend", "memory-worker", "worker", "opensearch", "opensearch-dashboards"]
    for service in forbidden:
        block = _service_block(compose, service)
        if "networks:" in block:
            nets = _networks_for_service(block)
            assert "symbol-internal" not in nets, f"{service} must not be on symbol-internal; got {nets}"


def test_symbol_internal_does_not_expose_database_to_gateway() -> None:
    """Regression: the gateway must not be on the same network as
    postgres/redis.  This is enforced by topology, not just by
    application policy.
    """
    if not COMPOSE_PATH.exists():
        import pytest
        pytest.skip("Compose source is not copied into the backend test image; runtime inspection covers this assertion.")
    compose = COMPOSE_PATH.read_text()
    gateway_nets = set(_networks_for_service(_service_block(compose, "symbol-egress-gateway")))
    for db_service in ("postgres", "redis"):
        db_nets = set(_networks_for_service(_service_block(compose, db_service)))
        shared = gateway_nets & db_nets
        assert not shared, f"gateway and {db_service} share networks: {shared}"


def test_fetcher_channel_does_not_expose_database() -> None:
    """The symbol-fetcher-channel must not contain the database either.
    Only the fetcher and the gateway should be on it.
    """
    if not COMPOSE_PATH.exists():
        import pytest
        pytest.skip("Compose source is not copied into the backend test image; runtime inspection covers this assertion.")
    compose = COMPOSE_PATH.read_text()
    channel_section = compose.split("symbol-fetcher-channel:", 1)[1]
    # The networks block ends at the next top-level key.
    for line in channel_section.splitlines():
        if line.startswith("  ") and not line.startswith("    ") and line.rstrip().endswith(":"):
            break
    assert "postgres" not in channel_section
    assert "redis" not in channel_section


def test_memory_worker_has_no_external_egress() -> None:
    """memory-worker must NOT be on any of the symbol-* networks.
    It is on the default bridge only; its only symbol-related work is
    running Volatility in --offline mode.
    """
    if not COMPOSE_PATH.exists():
        import pytest
        pytest.skip("Compose source is not copied into the backend test image; runtime inspection covers this assertion.")
    compose = COMPOSE_PATH.read_text()
    service = _service_block(compose, "memory-worker")
    if "networks:" in service:
        nets = _networks_for_service(service)
        for forbidden in ("symbol-internal", "symbol-fetcher-channel", "symbol-egress"):
            assert forbidden not in nets, f"memory-worker must not be on {forbidden}; got {nets}"
    # memory-worker must not reference the egress gateway URL either.
    assert "MEMORY_SYMBOL_EGRESS_GATEWAY_URL" not in service
    assert "symbol-egress-gateway" not in service


def test_backend_does_not_download_symbols() -> None:
    """The backend service is NOT a symbol-fetcher.  It must not reference
    the egress gateway URL or any symbol-egress service.  Only the
    symbol-fetcher service talks to the gateway.
    """
    if not COMPOSE_PATH.exists():
        import pytest
        pytest.skip("Compose source is not copied into the backend test image; runtime inspection covers this assertion.")
    compose = COMPOSE_PATH.read_text()
    service = _service_block(compose, "backend")
    assert "MEMORY_SYMBOL_EGRESS_GATEWAY_URL" not in service
    assert "symbol-egress-gateway" not in service


def test_only_symbol_fetcher_uses_egress_gateway() -> None:
    """The only service that may reference the egress gateway is
    symbol-fetcher.  No other tier may reach it.
    """
    if not COMPOSE_PATH.exists():
        import pytest
        pytest.skip("Compose source is not copied into the backend test image; runtime inspection covers this assertion.")
    compose = COMPOSE_PATH.read_text()
    services = ("backend", "frontend", "memory-worker", "worker", "opensearch", "opensearch-dashboards")
    for service in services:
        block = _service_block(compose, service)
        assert "symbol-egress-gateway" not in block, f"{service} must not reference the symbol egress gateway"
        assert "MEMORY_SYMBOL_EGRESS_GATEWAY_URL" not in block, f"{service} must not carry the egress gateway URL"
