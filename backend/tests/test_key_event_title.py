"""A key event's title comes from the event's message, which can exceed the column."""

from __future__ import annotations

from app.models.timeline_bookmark import TimelineBookmark


def test_a_long_event_message_is_trimmed_to_the_title_column() -> None:
    message = "Defender detected: C:\\Users\\analyst\\Downloads\\tool.exe; " + "x" * 400
    bookmark = TimelineBookmark(case_id="c", event_id="e", title=message)
    assert len(bookmark.title) == 255
    assert bookmark.title.endswith("\u2026")
    assert TimelineBookmark(case_id="c", event_id="e", title="short").title == "short"
