from pydantic import BaseModel, Field


class NormalizedEvent(BaseModel):
    id: str
    case_id: str | None = None
    source_file: str
    source_tool: str
    source_format: str
    artifact_type: str
    timestamp: str | None = None
    timestamp_type: str = "unknown"
    host: str | None = None
    user: str | None = None
    event_category: str = "unknown"
    event_type: str = "unknown"
    severity: str = "info"
    message: str = ""
    tags: list[str] = Field(default_factory=list)
    raw: dict = Field(default_factory=dict)
    event: dict = Field(default_factory=dict)
    windows: dict = Field(default_factory=dict)
    source: dict = Field(default_factory=dict)
    destination: dict = Field(default_factory=dict)
    process: dict = Field(default_factory=dict)
    file: dict = Field(default_factory=dict)
    execution: dict = Field(default_factory=dict)
    prefetch: dict = Field(default_factory=dict)
    browser: dict = Field(default_factory=dict)
    url: dict = Field(default_factory=dict)
    download: dict = Field(default_factory=dict)
    registry: dict = Field(default_factory=dict)
    filesystem: dict = Field(default_factory=dict)
    network: dict = Field(default_factory=dict)
    lnk: dict = Field(default_factory=dict)
    jumplist: dict = Field(default_factory=dict)
    volume: dict = Field(default_factory=dict)
    usb: dict = Field(default_factory=dict)
    shellbag: dict = Field(default_factory=dict)
    velociraptor: dict = Field(default_factory=dict)
    mft: dict = Field(default_factory=dict)
    usn: dict = Field(default_factory=dict)
    detection: dict = Field(default_factory=dict)
    task: dict = Field(default_factory=dict)
    service: dict = Field(default_factory=dict)
    suspicious_reasons: list[str] = Field(default_factory=list)
