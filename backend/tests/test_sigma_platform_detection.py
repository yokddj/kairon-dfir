from __future__ import annotations

from app.rules_engine.sigma import build_sigma_case_profile


def _windows_event() -> dict:
    return {"windows": {"event_id": 4688, "channel": "Security"}, "artifact": {"type": "windows_event"}, "host": {"os": "Windows"}}


def _linux_event() -> dict:
    return {
        "windows": {"event_id": None, "channel": None, "provider": None},
        "linux": {"artifact_family": "linux_auth", "process": "sshd", "command": "sudo su -"},
        "artifact": {"type": "linux_auth"},
        "host": {"os": "Linux"},
    }


def test_a_linux_case_is_recognised_as_linux() -> None:
    """No code path ever added "linux".

    A Sigma rule with logsource product: linux was therefore skipped as
    unsupported_platform on every case that has ever run, including Linux ones:
    195 rules refused to evaluate against 89788 Linux events while the run
    reported success.
    """
    profile = build_sigma_case_profile([_linux_event()])
    assert "linux" in profile["source_products"]


def test_an_empty_windows_block_does_not_make_a_case_windows() -> None:
    """Every document carries a windows block, populated or not.

    Testing it for truthiness marked Linux-only cases as Windows, which is what
    let the platform gate reject their own rules.
    """
    profile = build_sigma_case_profile([_linux_event()])
    assert "windows" not in profile["source_products"]


def test_a_windows_case_is_still_recognised() -> None:
    profile = build_sigma_case_profile([_windows_event()])
    assert "windows" in profile["source_products"]


def test_a_mixed_case_reports_both() -> None:
    profile = build_sigma_case_profile([_windows_event(), _linux_event()])
    assert {"windows", "linux"} <= set(profile["source_products"])


def test_host_os_alone_is_enough_to_identify_the_platform() -> None:
    """Some artifacts carry no platform block of their own."""
    profile = build_sigma_case_profile([{"host": {"os": "Linux"}, "artifact": {"type": "network"}}])
    assert "linux" in profile["source_products"]
