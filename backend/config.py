import os
from pathlib import Path
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql+psycopg2:///intrusion_db"
    MODEL_PATH: str = "../ML-Based-Network-Intrusion-Detection-System/intrusion_model.pkl"
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    class Config:
        env_file = Path(__file__).parent / ".env"
        env_file_encoding = "utf-8"


settings = Settings()

# Resolve model path relative to this file's directory
MODEL_ABS_PATH = (Path(__file__).parent / settings.MODEL_PATH).resolve()
