from pydantic_settings import BaseSettings, SettingsConfigDict
class Settings(BaseSettings):
    DATABASE_URL:str
    JWT_ALGORITHM:str
    JWT_SECRET:str
    REDIS_HOST : str 
    REDIS_PORT: int 
    REDIS_USERNAME: str
    REDIS_PASSWORD: str

    model_config = SettingsConfigDict(
        env_file=".env",
        extra='ignore'
    )

Config = Settings()