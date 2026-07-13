from datetime import datetime

from pydantic import BaseModel


class OSInstallationRead(BaseModel):
    id: str
    disk_volume_id: str
    platform: str
    hostname: str | None = None
    version: str | None = None
    distro: str | None = None
    root_path: str
    confidence: str
    detection_reasons: list = []
    metadata_json: dict = {}
    created_at: datetime | None = None
    updated_at: datetime | None = None

    model_config = {"from_attributes": True}


class DiskVolumeRead(BaseModel):
    id: str
    disk_image_id: str
    partition_index: int
    offset_bytes: int
    length_bytes: int
    partition_type: str | None = None
    filesystem_type: str | None = None
    label: str | None = None
    uuid: str | None = None
    encrypted: bool
    readable: bool
    status: str
    warnings_json: list = []
    error_json: dict = {}
    metadata_json: dict = {}
    installations: list[OSInstallationRead] = []
    created_at: datetime | None = None
    updated_at: datetime | None = None

    model_config = {"from_attributes": True}


class DiskImageRead(BaseModel):
    id: str
    evidence_id: str
    original_filename: str
    format: str
    size_bytes: int
    sha256: str | None = None
    segment_count: int
    status: str
    metadata_json: dict = {}
    tool_metadata: dict = {}
    warnings_json: list = []
    error_json: dict = {}
    volumes: list[DiskVolumeRead] = []
    created_at: datetime | None = None
    updated_at: datetime | None = None

    model_config = {"from_attributes": True}
