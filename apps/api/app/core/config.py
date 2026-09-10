from typing import List, Optional
from pydantic import Field, model_validator
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

    @model_validator(mode="after")
    def validate_production_settings(self):
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
