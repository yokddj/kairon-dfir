from app.disk_images.service import _should_materialize
from app.ingest.linux.os_detection import detect_linux_release


def test_ubuntu_os_release_wins_over_debian_version() -> None:
    detection = detect_linux_release(
        {
            "/etc/os-release": 'NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="24.04"\nID_LIKE=debian\n',
            "/etc/debian_version": "bookworm/sid\n",
        }
    )

    assert detection.distribution == "Ubuntu"
    assert detection.version == "24.04"
    assert detection.confidence == "high"
    assert "/etc/os-release:ID=ubuntu" in detection.reasons
    assert "/etc/os-release:ID_LIKE=debian" in detection.reasons


def test_debian_os_release_still_resolves_to_debian() -> None:
    detection = detect_linux_release({"/etc/os-release": 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nID=debian\nVERSION_ID="12"\n'})

    assert detection.distribution == "Debian GNU/Linux 12 (bookworm)"
    assert detection.confidence == "high"


def test_missing_os_release_allows_debian_version_weak_fallback() -> None:
    detection = detect_linux_release({"/etc/debian_version": "12.5\n"})

    assert detection.distribution == "Debian"
    assert detection.version == "12.5"
    assert detection.confidence == "low"


def test_conflicting_lsb_release_does_not_override_os_release() -> None:
    detection = detect_linux_release(
        {
            "/etc/os-release": 'NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="22.04"\n',
            "/etc/lsb-release": 'DISTRIB_ID=Debian\nDISTRIB_RELEASE=12\n',
        }
    )

    assert detection.distribution == "Ubuntu"
    assert detection.version == "22.04"


def test_linux_disk_materialization_uses_supported_linux_sources() -> None:
    supported_paths = [
        "/etc/os-release",
        "/usr/lib/os-release",
        "/etc/lsb-release",
        "/etc/hostname",
        "/var/log/apt/history.log",
        "/var/log/apt/term.log.1",
        "/var/lib/dpkg/status",
        "/etc/netplan/01-netcfg.yaml",
        "/etc/systemd/system/example.service",
        "/lib/systemd/system/example.timer",
        "/etc/cron.d/example",
        "/var/spool/cron/crontabs/root",
        "/etc/ssh/sshd_config",
        "/home/alice/.ssh/authorized_keys",
    ]

    for path in supported_paths:
        assert _should_materialize(path), path


def test_linux_disk_materialization_does_not_extract_unrelated_files() -> None:
    assert not _should_materialize("/tmp/random.bin")
    assert not _should_materialize("/var/cache/apt/pkgcache.bin")
