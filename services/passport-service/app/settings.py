from __future__ import annotations

from typing import List, Optional

from pydantic import AnyUrl, Field, Json
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PASSPORT_", env_file=".env", extra="ignore")

    PUBLIC_ISSUER_URL: AnyUrl = Field(default="http://localhost:8080/realms/astra")
    INTERNAL_ISSUER_URL: AnyUrl = Field(default="http://keycloak:8080/realms/astra")

    CLIENT_ID: str = Field(default="passport")
    CLIENT_SECRET: Optional[str] = Field(default=None)
    SCOPES: str = Field(default="openid profile email")

    BASE_URL: AnyUrl = Field(default="http://localhost:8020")
    CALLBACK_PATH: str = Field(default="/auth/callback")

    SESSION_COOKIE_NAME: str = Field(default="passport_session")
    COOKIE_DOMAIN: Optional[str] = Field(default=None)
    COOKIE_SECURE: bool = Field(default=False)
    COOKIE_SAMESITE: str = Field(default="lax")
    SESSION_TTL_SECONDS: int = Field(default=3600)

    CORS_ALLOW_ORIGINS: Json[List[str]] = Field(default_factory=list)
    SESSION_SIGNING_SECRET: str = Field(...)

    # 🔐 Sentinel
    SENTINEL_BASE_URL: AnyUrl = Field(default="http://sentinel-service:8030")
    SENTINEL_RESOLVE_PATH: str = Field(default="/resolve")
    SENTINEL_TIMEOUT_SECONDS: int = Field(default=5)

    LOG_LEVEL: str = Field(default="INFO")

    @property
    def callback_url(self) -> str:
        return f"{str(self.BASE_URL).rstrip('/')}{self.CALLBACK_PATH}"

    @property
    def sentinel_resolve_url(self) -> str:
        return f"{str(self.SENTINEL_BASE_URL).rstrip('/')}{self.SENTINEL_RESOLVE_PATH}"


settings = Settings()