"""
SecureAPI Configuration
Central place for all settings – easy to tweak.
"""

from pydantic_settings import BaseSettings
from typing import List, ClassVar, Dict, Any


class Settings(BaseSettings):
    # JWT
    SECRET_KEY: str = "SecureAPI-College-Project-Change-This-In-Real-Use-2024!"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # Rate Limiting (requests per minute)
    RATE_LIMIT: str = "30/minute"

    # Suspicious patterns (simple keyword detection)
    SUSPICIOUS_KEYWORDS: List[str] = [
        "union select", "drop table", "';'", "or 1=1",
        "<script>", "javascript:", "../", "..\\",
        "eval(", "exec(", "system(", "cmd.exe"
    ]

    # Logging
    LOG_FILE: str = "logs/api_activity.log"

    # Demo users (username: password, role)
    # Passwords are hashed at startup
    DEMO_USERS: ClassVar[Dict[str, Dict[str, Any]]] = {
        "admin": {"password": "admin123", "role": "admin", "full_name": "System Admin"},
        "alice": {"password": "alice123", "role": "user", "full_name": "Alice User"},
        "bob":   {"password": "bob123",   "role": "user", "full_name": "Bob User"},
    }

    class Config:
        env_file = ".env"


settings = Settings()
