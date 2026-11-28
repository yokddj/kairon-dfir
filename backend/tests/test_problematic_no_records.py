from app.services.problematic_artifacts import _no_records_message


def test_only_evtx_parsers_mention_channels():
    assert "EVTX channel" in _no_records_message("evtx_raw")
    assert "EVTX" not in _no_records_message("macos_recent_items_raw")
    assert "EVTX" not in _no_records_message("")
