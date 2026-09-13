from typing import List, Optional
import json
from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "SentinelAI API"
    app_version: str = "0.5.0"
    environment: str = Field(default="development", alias="SENTINEL_ENV")
    api_host: str = Field(default="0.0.0.0", alias="API_HOST")
    api_port: int = Field(default=8000, alias="API_PORT")
    cors_origins: List[str] = ["http://localhost:5173", "http://localhost:3000"]
    trusted_hosts: List[str] = ["*"]
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    # Database configuration
    database_url: str = Field(
        default="sqlite:///./sentinel.db",
        alias="DATABASE_URL",
        description="SQLAlchemy database connection URI",
    )
    postgres_password: Optional[str] = Field(default=None, alias="POSTGRES_PASSWORD")
    postgres_user: Optional[str] = Field(default=None, alias="POSTGRES_USER")
    postgres_host: Optional[str] = Field(default=None, alias="POSTGRES_HOST")
    postgres_port: int = Field(default=5432, alias="POSTGRES_PORT")
    postgres_db: Optional[str] = Field(default=None, alias="POSTGRES_DB")
    db_pool_size: int = Field(default=10, alias="DB_POOL_SIZE")
    db_max_overflow: int = Field(default=20, alias="DB_MAX_OVERFLOW")
    db_pool_recycle: int = Field(default=1800, alias="DB_POOL_RECYCLE")
    db_echo: bool = Field(default=False, alias="DB_ECHO")

    # Pagination limits
    default_page_limit: int = Field(default=50, alias="DEFAULT_PAGE_LIMIT")
    max_page_limit: int = Field(default=500, alias="MAX_PAGE_LIMIT")

    # AI Analyst configuration
    ai_provider: str = Field(default="mock", alias="SENTINEL_AI_PROVIDER")
    ai_model: str = Field(default="mock-analyst-v1", alias="SENTINEL_AI_MODEL")
    ai_api_key: Optional[str] = Field(default=None, alias="SENTINEL_AI_API_KEY")
    ai_base_url: Optional[str] = Field(default=None, alias="SENTINEL_AI_BASE_URL")
    ai_temperature: float = Field(default=0.0, alias="SENTINEL_AI_TEMPERATURE")
    ai_timeout_seconds: float = Field(default=15.0, alias="SENTINEL_AI_TIMEOUT_SECONDS")
    ai_rate_limit_rpm: int = Field(default=20, alias="SENTINEL_AI_RATE_LIMIT_RPM")
    ai_cache_ttl_seconds: int = Field(default=3600, alias="SENTINEL_AI_CACHE_TTL_SECONDS")
    ai_cache_max_entries: int = Field(default=1000, alias="SENTINEL_AI_CACHE_MAX_ENTRIES")

    @field_validator("cors_origins", "trusted_hosts", mode="before")
    @classmethod
    def parse_comma_separated_list(cls, v):
        if isinstance(v, str):
            v = v.strip()
            if v.startswith("[") and v.endswith("]"):
                try:
                    return json.loads(v)
                except Exception:
                    pass
            return [item.strip() for item in v.split(",") if item.strip()]
        return v

    @model_validator(mode="after")
    def validate_production_settings(self):
        # Assemble DATABASE_URL from discrete RDS parameters if host is provided
        if (self.database_url.startswith("sqlite") or not self.database_url) and self.postgres_host:
            user = self.postgres_user or "sentinel"
            pwd = self.postgres_password or ""
            host = self.postgres_host
            port = self.postgres_port or 5432
            db = self.postgres_db or "sentinel_db"
            self.database_url = f"postgresql://{user}:{pwd}@{host}:{port}/{db}"

        if self.environment.lower() == "production":
            # 1. POSTGRES_PASSWORD check
            if not self.postgres_password:
                raise ValueError("POSTGRES_PASSWORD must be explicitly provided in production mode.")
            if self.postgres_password == "sentinel_dev_password":
                raise ValueError(
                    "Default development password 'sentinel_dev_password' is strictly forbidden in production mode."
                )

            # 2. DATABASE_URL check
            if self.database_url.startswith("sqlite"):
                raise ValueError("SQLite database is not permitted in production mode. Use PostgreSQL.")
            if "sentinel_dev_password" in self.database_url:
                raise ValueError(
                    "Default development password 'sentinel_dev_password' detected in DATABASE_URL in production mode."
                )

            # 3. trusted_hosts check
            if not self.trusted_hosts or "*" in self.trusted_hosts:
                raise ValueError(
                    "trusted_hosts must be explicitly configured and cannot contain '*' in production mode."
                )

            # 4. cors_origins check
            if not self.cors_origins or "*" in self.cors_origins:
                raise ValueError(
                    "cors_origins must be explicitly configured and cannot contain '*' in production mode."
                )

            # 5. AI provider api_key check if non-mock
            if self.ai_provider != "mock" and not self.ai_api_key:
                raise ValueError(
                    f"SENTINEL_AI_API_KEY must be provided for AI provider '{self.ai_provider}' in production mode."
                )

        return self

settings = Settings()
