from app.services.windows_accounts import accounts_from_events, canonical_accounts, service_account

SID = "S-1-5-21-1111111111-2222222222-3333333333-1103"


def test_service_accounts_have_one_spelling() -> None:
    for value in ("S-1-5-18", "SYSTEM", "Local System", "NT AUTHORITY\\SYSTEM", "nt authority\\system"):
        assert service_account(value) == "NT AUTHORITY\\SYSTEM", value
    for value in ("LOCAL SERVICE", "NT AUTHORITY\\LocalService", "S-1-5-19"):
        assert service_account(value) == "NT AUTHORITY\\LOCAL SERVICE", value
    assert service_account("LAB\\SYSTEM") is None
    assert service_account("alice") is None


def test_sid_and_bare_name_join_the_qualified_account() -> None:
    events = [{"windows": {"event_data": {"SubjectUserSid": SID, "SubjectDomainName": "LAB", "SubjectUserName": "alice"}}}]
    names = canonical_accounts([SID, "alice", "LAB\\alice", "S-1-5-18", "WS01$"], accounts_from_events(events))

    assert names[SID] == "LAB\\alice"
    assert names["alice"] == "LAB\\alice"
    assert names["LAB\\alice"] == "LAB\\alice"
    assert names["S-1-5-18"] == "NT AUTHORITY\\SYSTEM"
    assert names["WS01$"] == "WS01$"


def test_a_bare_name_shared_by_two_accounts_is_left_alone() -> None:
    names = canonical_accounts(["admin", "LAB\\admin", "WS01\\admin"], {})

    assert names["admin"] == "admin"


def test_an_unknown_sid_stays_a_sid() -> None:
    assert canonical_accounts([SID], {})[SID] == SID


def test_session_accounts_and_placeholder() -> None:
    assert service_account("S-1-5-90-0-2") == "Window Manager\\DWM-2"
    assert service_account("S-1-5-96-0-0") == "Font Driver Host\\UMFD-0"
    assert canonical_accounts(["-"], {})["-"] == ""


def test_getsids_envars_privileges_documents_carry_their_evidence_and_run() -> None:
    from app.services.memory.artifact_normalizers import normalize_windows_envars, normalize_windows_getsids, normalize_windows_privileges

    common = {"case_id": "case-1", "evidence_id": "ev-1", "scan_run_id": "run-1", "plugin_run_id": "plugin-1"}
    documents = [
        *normalize_windows_getsids([{"PID": 4, "Process": "System", "SID": "S-1-5-18", "Name": "Local System"}], **common)["items"],
        *normalize_windows_envars([{"PID": 4, "Process": "System", "Variable": "Path", "Value": "C:\\Windows"}], **common)["items"],
        *normalize_windows_privileges([{"PID": 4, "Process": "System", "Privilege": "SeDebugPrivilege"}], **common)["items"],
    ]

    assert len(documents) == 3
    for document in documents:
        assert {key: document[key] for key in common} == common
