from dotenv import load_dotenv
from pydantic_settings import BaseSettings
import os

# Load variables from .env
load_dotenv()


class Settings(BaseSettings):
    DATABASE_URL: str
    SECRET_KEY: str

    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # Threat Intelligence API Keys
    VIRUSTOTAL_API_KEY: str
    ABUSEIPDB_API_KEY: str
    OTX_API_KEY: str

    class Config:
        env_file = ".env"


# Create settings instance
settings = Settings()


# Optional: Direct environment variable access
DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY")

ALGORITHM = os.getenv("ALGORITHM", "HS256")

ACCESS_TOKEN_EXPIRE_MINUTES = int(
    os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 60)
)

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")