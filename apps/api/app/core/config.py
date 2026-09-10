from typing import List, Optional
from pydantic import Field
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
    db_pool_size: int = Field(default=10, alias="DB_POOL_SIZE")
    db_max_overflow: int = Field(default=20, alias="DB_MAX_OVERFLOW")
    db_pool_recycle: int = Field(default=1800, alias="DB_POOL_RECYCLE")
    db_echo: bool = Field(default=False, alias="DB_ECHO")

    # Pagination limits
    default_page_limit: int = Field(default=50, alias="DEFAULT_PAGE_LIMIT")
    max_page_limit: int = Field(default=500, alias="MAX_PAGE_LIMIT")


settings = Settings()
