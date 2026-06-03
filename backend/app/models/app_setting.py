from datetime import datetime

from sqlalchemy import Boolean, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base, JSONVariant, utc_now_naive


class AppSetting(Base):
    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[dict | int | str | bool | list | None] = mapped_column(JSONVariant, nullable=True)
    category: Mapped[str] = mapped_column(String(64), nullable=False, default="runtime")
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    requires_restart: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(default=utc_now_naive, onupdate=utc_now_naive, nullable=False)
