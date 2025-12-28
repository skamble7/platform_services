from __future__ import annotations

from typing import List

from pydantic import Field, Json
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SENTINEL_", env_file=".env", extra="ignore")

    # API
    PORT: int = 8030
    LOG_LEVEL: str = "INFO"
    CORS_ALLOW_ORIGINS: Json[List[str]] = Field(default_factory=list)

    # MongoDB
    MONGO_URI: str = "mongodb+srv://sandeepk:sandeep@cluster0.tnbpi.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
    MONGO_DB: str = "sentinel"

    # Collections
    COL_PERMISSIONS: str = "permissions"
    COL_ROLES: str = "roles"
    COL_GROUPS: str = "groups"
    COL_USERS: str = "users"
    COL_POLICIES: str = "policies"


settings = Settings()