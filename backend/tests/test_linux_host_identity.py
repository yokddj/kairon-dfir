"""Generic Linux host-identity facts: hostname, fqdn, distribution,
distribution_version, kernel, architecture -- the second Host Facts
consumer (see app.services.host_facts), added without any change to the
Host Facts model or aggregation service itself.
"""
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api import routes_host_facts
from app.core.database import Base, get_db
from app.ingest.linux.helpers import looks_like_linux_artifact
from app.ingest.linux.os_info import parse_os_info
from app.ingest.normalizer import normalize_row
from app.models.case import Case
from app.models.case_host import CaseHost
from app.models.evidence import Evidence, EvidenceStorageMode, EvidenceType, IngestStatus
from app.services.host_facts import create_host_fact_observations, resolve_host_facts

CASE_ID = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"
HOST_ID = "dddddddd-1111-4111-8111-dddddddddddd"
EVIDENCE_ID = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb"
ART1_ID = "11111111-1111-4111-8111-1111111111af"
ART2_ID = "22222222-2222-4222-8222-2222222222bf"


class TestHostnameDiscovery:
    def test_etc_hostname_routes_to_os_info(self):
        assert looks_like_linux_artifact("etc/hostname") == ("linux_os_info", "hostname", "linux_os_info_raw")

    def test_byobu_hostname_script_is_not_dispatched(self):
        # Confirmed against real disk-image evidence: byobu ships a real
        # shell script at this exact path, basename "hostname".
        assert looks_like_linux_artifact("usr/lib/byobu/hostname") is None

    def test_perl_sys_hostname_module_is_not_dispatched(self):
        assert looks_like_linux_artifact("usr/lib/perl/5.18.2/auto/Sys/Hostname") is None


class TestDistributionFileDiscovery:
    def test_dpkg_own_metadata_for_lsb_release_package_is_not_dispatched(self):
        # Confirmed against real disk-image evidence: dpkg tracks the
        # lsb-release *package*'s own files under var/lib/dpkg/info/ with
        # names like "lsb-release.list" -- package-manager bookkeeping,
        # not the file's content, but a bare "lsb-release" marker matched
        # it anyway (5 of 18 linux_os_info documents on real evidence were
        # this kind of noise before this fix).
        for suffix in ("list", "md5sums", "postinst", "postrm", "prerm"):
            assert looks_like_linux_artifact(f"var/lib/dpkg/info/lsb-release.{suffix}") is None

    def test_bug_report_template_lsb_release_is_not_dispatched(self):
        assert looks_like_linux_artifact("usr/share/bug/lsb-release") is None

    def test_installer_snapshot_lsb_release_is_dispatched(self):
        assert looks_like_linux_artifact("var/log/installer/lsb-release") == ("linux_os_info", "lsb_release", "linux_os_info_raw")

    def test_man_page_for_issue_is_not_dispatched(self):
        assert looks_like_linux_artifact("usr/share/man/man5/issue.5.gz") is None


class TestHostname:
    def test_static_hostname(self):
        rows = parse_os_info("VulnOSv2\n", source_path="etc/hostname")
        assert len(rows) == 1
        assert rows[0]["fact_type"] == "host.hostname"
        assert rows[0]["normalized_value"] == "VulnOSv2"
        assert rows[0]["confidence"] == "high"

    def test_fqdn_detected_when_dotted(self):
        rows = parse_os_info("server01.example.com\n", source_path="etc/hostname")
        fact_types = {row["fact_type"] for row in rows}
        assert fact_types == {"host.hostname", "host.fqdn"}
        for row in rows:
            assert row["normalized_value"] == "server01.example.com"

    def test_bare_hostname_never_produces_fqdn(self):
        rows = parse_os_info("victoria\n", source_path="etc/hostname")
        assert {row["fact_type"] for row in rows} == {"host.hostname"}

    def test_empty_hostname_is_invalid(self):
        rows = parse_os_info("\n", source_path="etc/hostname")
        assert rows[0]["parse_status"] == "invalid"
        assert rows[0]["normalized_value"] is None


class TestHostnamectl:
    _FULL = (
        "   Static hostname: server01\n"
        " Operating System: Ubuntu 20.04.3 LTS\n"
        "           Kernel: Linux 5.4.0-90-generic\n"
        "     Architecture: x86-64\n"
        "        Time zone: Europe/Madrid (CEST, +0200)\n"
    )

    def test_dispatches_to_os_info_not_timezone(self):
        assert looks_like_linux_artifact("hostnamectl.txt") == ("linux_os_info", "hostnamectl", "linux_os_info_raw")

    def test_binary_under_bin_is_not_dispatched(self):
        assert looks_like_linux_artifact("usr/bin/hostnamectl") is None

    def test_extracts_all_facts_from_one_capture(self):
        rows = parse_os_info(self._FULL, source_path="hostnamectl.txt")
        by_type = {row["fact_type"]: row for row in rows}
        assert by_type["host.hostname"]["normalized_value"] == "server01"
        assert by_type["host.kernel"]["normalized_value"] == "5.4.0-90-generic"
        assert by_type["host.architecture"]["normalized_value"] == "x86_64"  # hyphenated "x86-64" normalized
        assert by_type["host.timezone"]["normalized_value"] == "Europe/Madrid"
        assert "CEST" not in by_type["host.timezone"]["normalized_value"]

    def test_distribution_has_no_machine_readable_id(self):
        rows = parse_os_info(self._FULL, source_path="hostnamectl.txt")
        dist = next(row for row in rows if row["fact_type"] == "host.distribution")
        assert dist["normalized_value"] is None
        assert dist["raw_value"] == "Ubuntu 20.04.3 LTS"
        assert dist["reason"] == "hostnamectl_pretty_name_only_no_machine_readable_id"

    def test_partial_capture_only_emits_present_fields(self):
        rows = parse_os_info("Static hostname: db01\n", source_path="hostnamectl.txt")
        assert {row["fact_type"] for row in rows} == {"host.hostname"}


class TestOsRelease:
    _UBUNTU = (
        'NAME="Ubuntu"\n'
        'VERSION="14.04.4 LTS, Trusty Tahr"\n'
        "ID=ubuntu\n"
        "ID_LIKE=debian\n"
        'PRETTY_NAME="Ubuntu 14.04.4 LTS"\n'
        'VERSION_ID="14.04"\n'
    )

    def test_distribution_and_version_split(self):
        rows = parse_os_info(self._UBUNTU, source_path="etc/os-release")
        by_type = {row["fact_type"]: row for row in rows}
        assert by_type["host.distribution"]["normalized_value"] == "ubuntu"
        assert by_type["host.distribution"]["raw_value"] == "Ubuntu 14.04.4 LTS"
        assert by_type["host.distribution_version"]["normalized_value"] == "14.04"

    def test_usr_lib_os_release_also_recognized(self):
        assert looks_like_linux_artifact("usr/lib/os-release") is not None

    def test_missing_fields_yields_invalid(self):
        rows = parse_os_info("SOME_OTHER_KEY=1\n", source_path="etc/os-release")
        assert rows[0]["parse_status"] == "invalid"


class TestLsbRelease:
    def test_distrib_fields_mapped(self):
        content = 'DISTRIB_ID=Ubuntu\nDISTRIB_RELEASE=14.04\nDISTRIB_CODENAME=trusty\nDISTRIB_DESCRIPTION="Ubuntu 14.04.4 LTS"\n'
        rows = parse_os_info(content, source_path="etc/lsb-release")
        by_type = {row["fact_type"]: row for row in rows}
        assert by_type["host.distribution"]["normalized_value"] == "ubuntu"
        assert by_type["host.distribution_version"]["normalized_value"] == "14.04"
        assert by_type["host.distribution"]["confidence"] == "medium"


class TestDebianVersion:
    def test_old_debian_with_no_os_release(self):
        # Debian 5 predates the os-release spec entirely -- debian_version
        # is the only distribution signal available on such a system.
        rows = parse_os_info("5.0.7\n", source_path="etc/debian_version")
        by_type = {row["fact_type"]: row for row in rows}
        assert by_type["host.distribution"]["normalized_value"] == "debian"
        assert by_type["host.distribution"]["confidence"] == "medium"
        assert by_type["host.distribution"]["reason"] == "distribution_inferred_from_debian_version_file_identity"
        assert by_type["host.distribution_version"]["normalized_value"] == "5.0.7"
        assert by_type["host.distribution_version"]["confidence"] == "high"

    def test_does_not_collide_with_proc_version_routing(self):
        # Regression: parse_os_info's kernel branch used to match on the
        # substring "version" anywhere in the path, which "debian_version"
        # also contains -- misreading a distro release number as a kernel
        # version. Confirmed against real (Debian 5) evidence.
        rows = parse_os_info("5.0.7\n", source_path="etc/debian_version")
        assert not any(row["fact_type"] == "host.kernel" for row in rows)


class TestProcVersion:
    _CONTENT = (
        "Linux version 5.10.0-9-amd64 (debian-kernel@lists.debian.org) "
        "(gcc-10 (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU Binutils for Debian) 2.35.2) "
        "#1 SMP Debian 5.10.70-1 (2021-09-30)\n"
    )

    def test_kernel_and_architecture(self):
        rows = parse_os_info(self._CONTENT, source_path="proc/version")
        by_type = {row["fact_type"]: row for row in rows}
        assert by_type["host.kernel"]["normalized_value"] == "5.10.0-9-amd64"
        assert "#1 SMP" in by_type["host.kernel"]["raw_value"]
        assert by_type["host.architecture"]["normalized_value"] == "x86_64"

    def test_no_kernel_line_is_invalid(self):
        rows = parse_os_info("nothing relevant here\n", source_path="proc/version")
        assert rows[0]["parse_status"] == "invalid"


class TestUname:
    def test_standard_uname_a_format(self):
        content = "Linux hostname 5.10.0-9-amd64 #1 SMP Debian 5.10.70-1 (2021-09-30) x86_64 GNU/Linux\n"
        rows = parse_os_info(content, source_path="uname.txt")
        by_type = {row["fact_type"]: row for row in rows}
        assert by_type["host.kernel"]["normalized_value"] == "5.10.0-9-amd64"
        assert by_type["host.architecture"]["normalized_value"] == "x86_64"

    def test_unrecognized_format_is_invalid_not_silently_dropped(self):
        rows = parse_os_info("not a uname line\n", source_path="uname.txt")
        assert rows[0]["parse_status"] == "invalid"
        assert rows[0]["reason"] == "unrecognized_uname_format"

    def test_uname_binary_under_bin_is_not_dispatched(self):
        assert looks_like_linux_artifact("usr/bin/uname") is None

    def test_uname_capture_file_is_dispatched(self):
        assert looks_like_linux_artifact("uname.txt") == ("linux_os_info", "uname", "linux_os_info_raw")


class TestArchitectureNormalization:
    def test_amd64_normalizes_to_x86_64(self):
        rows = parse_os_info("Linux h 1.0 #1 amd64 GNU/Linux\n", source_path="uname.txt")
        arch = next(row for row in rows if row["fact_type"] == "host.architecture")
        assert arch["normalized_value"] == "x86_64"
        assert arch["raw_value"] == "amd64"  # original value preserved

    def test_i686_normalizes_to_x86(self):
        rows = parse_os_info("Linux h 1.0 #1 i686 GNU/Linux\n", source_path="uname.txt")
        arch = next(row for row in rows if row["fact_type"] == "host.architecture")
        assert arch["normalized_value"] == "x86"

    def test_arm64_normalizes_to_aarch64(self):
        rows = parse_os_info("Linux h 1.0 #1 arm64 GNU/Linux\n", source_path="uname.txt")
        arch = next(row for row in rows if row["fact_type"] == "host.architecture")
        assert arch["normalized_value"] == "aarch64"

    def test_ppc64le_and_s390x_preserved(self):
        for token in ("ppc64le", "s390x"):
            rows = parse_os_info(f"Linux h 1.0 #1 {token} GNU/Linux\n", source_path="uname.txt")
            arch = next(row for row in rows if row["fact_type"] == "host.architecture")
            assert arch["normalized_value"] == token


class TestNormalization:
    def test_event_semantics_generic_over_fact_type(self):
        rows = parse_os_info("VulnOSv2\n", source_path="etc/hostname")
        doc = normalize_row("case-1", "ev-1", "art-1", rows[0], {
            "artifact_family": "linux_os_info", "artifact_type": "hostname",
            "parser": "linux_os_info_raw", "name": "hostname", "source_path": "etc/hostname",
        })
        assert doc["event"]["category"] == "config"
        assert doc["event"]["type"] == "host.hostname"
        assert doc["event"]["action"] == "host_identity_detected"
        assert doc["event"]["severity"] == "info"
        assert doc["linux"]["fact_normalized_value"] == "VulnOSv2"
        assert "VulnOSv2" in doc["search_text"]

    def test_host_document_hostname_populated(self):
        rows = parse_os_info("VulnOSv2\n", source_path="etc/hostname")
        doc = normalize_row("case-1", "ev-1", "art-1", rows[0], {
            "artifact_family": "linux_os_info", "artifact_type": "hostname",
            "parser": "linux_os_info_raw", "name": "hostname", "source_path": "etc/hostname",
        })
        assert doc["host"]["hostname"] == "vulnosv2"


def _db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, future=True)()


def _client(db):
    app = FastAPI()
    app.include_router(routes_host_facts.router)
    app.dependency_overrides[get_db] = lambda: db
    return TestClient(app)


def _case(db):
    db.add(Case(id=CASE_ID, name="Case", description=None))
    db.commit()


def _evidence(db, evidence_id=EVIDENCE_ID, *, host_id=None, filename="disk.E01"):
    item = Evidence(
        id=evidence_id, case_id=CASE_ID, original_filename=filename, stored_path=f"/tmp/{filename}",
        original_path=f"/tmp/{filename}", storage_mode=EvidenceStorageMode.uploaded, is_external=False,
        copy_to_storage=True, evidence_type=EvidenceType.disk_image, sha256="0" * 64, size_bytes=128,
        ingest_status=IngestStatus.completed, detected_host=None, host_id=host_id,
        path_validation={}, ingest_source={}, metadata_json={}, error_log={},
    )
    db.add(item)
    db.commit()
    return item


def _doc(raw: str, source_path: str) -> dict:
    rows = parse_os_info(raw, source_path=source_path)
    return [
        normalize_row("case-1", "ev-1", "art-1", row, {
            "artifact_family": "linux_os_info", "artifact_type": row["artifact_type"],
            "parser": "linux_os_info_raw", "name": source_path.rsplit("/", 1)[-1], "source_path": source_path,
        })
        for row in rows
    ]


class TestHostFactsAggregation:
    def test_agreement_across_os_release_and_lsb_release_is_confirmed(self):
        db = _db()
        _case(db)
        _evidence(db)
        create_host_fact_observations(
            db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART1_ID, host_id=None, observed_at=None,
            documents=_doc('NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="14.04"\nPRETTY_NAME="Ubuntu 14.04.4 LTS"\n', "etc/os-release"),
        )
        create_host_fact_observations(
            db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART2_ID, host_id=None, observed_at=None,
            documents=_doc('DISTRIB_ID=Ubuntu\nDISTRIB_RELEASE=14.04\nDISTRIB_DESCRIPTION="Ubuntu 14.04.4 LTS"\n', "etc/lsb-release"),
        )
        resolved = resolve_host_facts(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, fact_type="host.distribution")
        assert resolved[0]["status"] == "confirmed"
        assert resolved[0]["preferred_value"] == "ubuntu"
        assert len(resolved[0]["supporting"]) == 2

    def test_hostnamectl_vs_etc_hostname_conflict_is_visible(self):
        """The exact example from the sprint brief: hostnamectl says
        server01, /etc/hostname says server02 -- both must be surfaced,
        and /etc/hostname (the persisted config) wins the tie-break.
        """
        db = _db()
        _case(db)
        _evidence(db)
        create_host_fact_observations(
            db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART1_ID, host_id=None, observed_at=None,
            documents=_doc("Static hostname: server01\n", "hostnamectl.txt"),
        )
        create_host_fact_observations(
            db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART2_ID, host_id=None, observed_at=None,
            documents=_doc("server02\n", "etc/hostname"),
        )
        resolved = resolve_host_facts(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, fact_type="host.hostname")
        assert resolved[0]["status"] == "conflicting"
        assert resolved[0]["preferred_value"] == "server02"  # etc_hostname outranks hostnamectl
        values = {obs["normalized_value"] for obs in resolved[0]["observations"]}
        assert values == {"server01", "server02"}
        conflicting_values = {obs["normalized_value"] for obs in resolved[0]["conflicting"]}
        assert conflicting_values == {"server01"}

    def test_hostname_casing_variants_resolve_as_one_identity(self):
        # Same case-insensitive contract as Windows (app.services.host_facts
        # .normalize_host_fact_value) -- the resolver is shared, so this
        # must hold for Linux hostnames too, not just EVTX-derived ones.
        db = _db()
        _case(db)
        _evidence(db)
        create_host_fact_observations(
            db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART1_ID, host_id=None, observed_at=None,
            documents=_doc("VulnOSv2\n", "etc/hostname"),
        )
        create_host_fact_observations(
            db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART2_ID, host_id=None, observed_at=None,
            documents=_doc("Static hostname: vulnosv2\n", "hostnamectl.txt"),
        )
        resolved = resolve_host_facts(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, fact_type="host.hostname")
        assert resolved[0]["status"] == "confirmed"
        assert resolved[0]["conflicting"] == []
        assert len(resolved[0]["supporting"]) == 2
        observed_values = {row["normalized_value"] for row in resolved[0]["observations"]}
        assert observed_values == {"VulnOSv2", "vulnosv2"}

    def test_fqdn_casing_variants_resolve_as_one_identity(self):
        db = _db()
        _case(db)
        _evidence(db)
        create_host_fact_observations(
            db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART1_ID, host_id=None, observed_at=None,
            documents=_doc("server01.example.com\n", "etc/hostname"),
        )
        create_host_fact_observations(
            db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART2_ID, host_id=None, observed_at=None,
            documents=_doc("Static hostname: SERVER01.EXAMPLE.COM\n", "hostnamectl.txt"),
        )
        resolved = resolve_host_facts(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, fact_type="host.fqdn")
        assert resolved[0]["status"] == "confirmed"
        assert resolved[0]["conflicting"] == []

    def test_provenance_preserved_for_debian_version_inference(self):
        db = _db()
        _case(db)
        _evidence(db)
        create_host_fact_observations(
            db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART1_ID, host_id=None, observed_at=None,
            documents=_doc("5.0.7\n", "etc/debian_version"),
        )
        resolved = resolve_host_facts(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, fact_type="host.distribution")
        obs = resolved[0]["supporting"][0]
        assert obs["provenance"]["reason"] == "distribution_inferred_from_debian_version_file_identity"
        assert obs["source_path"] == "etc/debian_version"
        assert obs["parser"] == "linux_os_info_raw"

    def test_multiple_fact_types_coexist_independently(self):
        db = _db()
        _case(db)
        _evidence(db)
        create_host_fact_observations(
            db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART1_ID, host_id=None, observed_at=None,
            documents=_doc("VulnOSv2\n", "etc/hostname"),
        )
        create_host_fact_observations(
            db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART2_ID, host_id=None, observed_at=None,
            documents=_doc("5.0.7\n", "etc/debian_version"),
        )
        resolved = resolve_host_facts(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID)
        fact_types = {item["fact_type"] for item in resolved}
        assert fact_types == {"host.hostname", "host.distribution", "host.distribution_version"}
        for item in resolved:
            assert item["status"] in {"observed", "confirmed"}  # no cross-fact-type bleeding into conflicts

    def test_no_duplicate_fingerprints_on_repeat_call(self):
        db = _db()
        _case(db)
        _evidence(db)
        docs = _doc("VulnOSv2\n", "etc/hostname")
        create_host_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART1_ID, host_id=None, observed_at=None, documents=docs)
        create_host_fact_observations(db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART1_ID, host_id=None, observed_at=None, documents=docs)
        from app.models.host_fact import HostFact
        assert db.query(HostFact).count() == 1


class TestApiExtension:
    def test_existing_endpoint_returns_new_fact_types(self):
        from app.ingest.linux.timezone import parse_timezone

        db = _db()
        _case(db)
        _evidence(db)
        timezone_docs = [
            normalize_row("case-1", "ev-1", "art-1", row, {
                "artifact_family": "linux_timezone", "artifact_type": row["artifact_type"],
                "parser": "linux_timezone_raw", "name": "timezone", "source_path": "etc/timezone",
            })
            for row in parse_timezone("Europe/Madrid\n", source_path="etc/timezone")
        ]
        create_host_fact_observations(
            db, case_id=CASE_ID, evidence_id=EVIDENCE_ID, artifact_id=ART1_ID, host_id=None, observed_at=None,
            documents=_doc("VulnOSv2\n", "etc/hostname") + _doc("5.0.7\n", "etc/debian_version") + timezone_docs,
        )
        client = _client(db)
        response = client.get(f"/api/cases/{CASE_ID}/host-facts", params={"evidence_id": EVIDENCE_ID})
        assert response.status_code == 200
        fact_types = {item["fact_type"] for item in response.json()["facts"]}
        assert fact_types == {"host.hostname", "host.distribution", "host.distribution_version", "host.timezone"}

    def test_no_new_endpoint_was_added(self):
        # Same router, same path prefix as Sprint 1 -- this sprint must not
        # introduce a second API surface.
        paths = {route.path for route in routes_host_facts.router.routes}
        assert paths == {"/api/cases/{case_id}/host-facts"}
