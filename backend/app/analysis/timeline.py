from app.models.forensic_activity import ForensicActivity


def build_global_timeline(activities: list[ForensicActivity]) -> list[dict]:
    return [activity.model_dump() for activity in sorted(activities, key=lambda item: item.timestamp or "")]
