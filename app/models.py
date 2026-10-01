"""
Pydantic models for request/response validation.
This is the heart of Input Validation & Parameter Validation.
"""

from pydantic import BaseModel, Field, EmailStr, field_validator
from typing import Optional, List
from datetime import datetime
from enum import Enum


class Role(str, Enum):
    USER = "user"
    ADMIN = "admin"


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    username: str


class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None


class UserLogin(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, examples=["alice"])
    password: str = Field(..., min_length=6, max_length=100, examples=["alice123"])


class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6, max_length=100)
    full_name: str = Field(..., min_length=2, max_length=100)
    role: Role = Role.USER

    @field_validator("username")
    @classmethod
    def username_alphanumeric(cls, v: str) -> str:
        if not v.replace("_", "").isalnum():
            raise ValueError("Username must be alphanumeric (underscore allowed)")
        return v.lower()


class UserOut(BaseModel):
    username: str
    full_name: str
    role: str
    created_at: datetime


class ProtectedDataRequest(BaseModel):
    """Example of strict parameter validation"""
    query: str = Field(..., min_length=1, max_length=200, description="Search query")
    limit: int = Field(10, ge=1, le=50, description="Max results (1-50)")
    include_sensitive: bool = False

    @field_validator("query")
    @classmethod
    def no_sql_injection(cls, v: str) -> str:
        lowered = v.lower()
        bad = ["union", "select", "drop", "insert", "delete", "--", ";"]
        for word in bad:
            if word in lowered:
                raise ValueError(f"Potentially dangerous content detected: '{word}'")
        return v


class AdminAction(BaseModel):
    action: str = Field(..., min_length=3, max_length=50)
    target_user: Optional[str] = None
    reason: Optional[str] = Field(None, max_length=200)


class ActivityLogEntry(BaseModel):
    timestamp: str
    method: str
    path: str
    client_ip: str
    username: Optional[str]
    status_code: int
    message: str
    threat_score: int = 0


class HealthResponse(BaseModel):
    status: str
    version: str
    features: List[str]
