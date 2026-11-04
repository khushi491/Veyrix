from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    database_url: str = "postgresql+psycopg://veyrix:veyrix_local@localhost:58439/veyrix"
    redis_url: str = "redis://localhost:6379/0"
    veyrix_dev_mode: bool = False


settings = Settings()
