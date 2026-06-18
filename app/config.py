from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Added settings model config to load from .env
# Added SECRET_KEY validation (min_length=32)
# Created a shared singleton: settings = Settings()

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    SECRET_KEY: str = Field(min_length=32)
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    DATABASE_URL: str = "sqlite:///./test.db"


settings = Settings()