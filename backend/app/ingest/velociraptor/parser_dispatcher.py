from app.ingest.velociraptor.discovery import list_velociraptor_artifacts


def build_selected_velociraptor_artifacts(root, candidates: list[dict]) -> list[dict]:
    return list_velociraptor_artifacts(root, candidates)
