"""Application configuration loaded from environment variables."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables and .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    AWS_PROFILE: str | None = None
    AWS_REGION: str = "ap-southeast-2"
    POSTURE_RESULTS_BUCKET: str = "cloud-posture-scanner-results"
    APP_ENV: str = "development"
    DEBUG: bool = False
    CORS_ORIGINS: list[str] = ["http://localhost:5173"]


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance."""
    return Settings()
