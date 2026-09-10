"""API configuration settings."""

from typing import List
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "SentinelAI API"
    app_version: str = "0.1.0"
    api_host: str = Field(default="0.0.0.0", alias="API_HOST")
    api_port: int = Field(default=8000, alias="API_PORT")
    cors_origins: List[str] = ["http://localhost:5173", "http://localhost:3000"]
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")


settings = Settings()
