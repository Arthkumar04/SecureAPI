"""
Authentication & Authorization (JWT + RBAC)
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from app.config import settings
from app.models import TokenData, Role

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme (Swagger will show the Authorize button)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# In-memory user store (for demo – easy, no DB needed)
# In real projects use a proper database
users_db: Dict[str, Dict[str, Any]] = {}


def init_demo_users():
    """Create demo users with hashed passwords"""
    for username, data in settings.DEMO_USERS.items():
        users_db[username] = {
            "username": username,
            "full_name": data["full_name"],
            "hashed_password": pwd_context.hash(data["password"]),
            "role": data["role"],
            "created_at": datetime.now(timezone.utc),
            "is_active": True,
        }


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def authenticate_user(username: str, password: str) -> Optional[dict]:
    user = users_db.get(username.lower())
    if not user or not verify_password(password, user["hashed_password"]):
        return None
    if not user.get("is_active", True):
        return None
    return user


async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username, role=role)
    except JWTError:
        raise credentials_exception

    user = users_db.get(token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(current_user: dict = Depends(get_current_user)) -> dict:
    if not current_user.get("is_active", True):
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


def require_role(required_role: Role):
    """RBAC dependency factory"""
    async def role_checker(current_user: dict = Depends(get_current_active_user)):
        if current_user.get("role") != required_role.value and current_user.get("role") != "admin":
            # Admin can do everything, otherwise exact role match
            if required_role == Role.ADMIN and current_user.get("role") != "admin":
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Requires '{required_role.value}' role"
                )
            if current_user.get("role") != required_role.value:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Requires '{required_role.value}' role"
                )
        return current_user
    return role_checker


# Convenience
require_admin = require_role(Role.ADMIN)
require_user = require_role(Role.USER)
