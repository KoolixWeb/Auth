from pydantic_settings import BaseSettings
from dotenv import load_dotenv

load_dotenv() 

class Settings(BaseSettings):
    # MongoDB
    mongodb_uri: str

    # JWT
    secret_key: str
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_minutes: int = 10080
    
    # OAuth - Google
    google_client_id: str
    google_client_secret: str
    google_discovery_url: str
    google_redirect_uri: str
    google_scopes: str

    # App
    app_name: str = "AuthSystem"
    debug: bool = True

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()