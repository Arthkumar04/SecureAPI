"""
SecureAPI – Intelligent API Security Gateway
============================================
A complete working demo for college project.

Features demonstrated:
✅ Authentication (JWT)
✅ Authorization + RBAC
✅ Input & Parameter Validation (Pydantic)
✅ Rate Limiting
✅ Suspicious Request Detection
✅ API Activity Logging
✅ Secure Error Handling
✅ Security Headers
"""

from fastapi import FastAPI, Depends, HTTPException, status, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from datetime import datetime, timezone
from typing import List
import os

from app.config import settings
from app.models import (
    Token, UserLogin, UserRegister, UserOut, ProtectedDataRequest,
    AdminAction, HealthResponse, Role
)
from app.auth import (
    init_demo_users, authenticate_user, create_access_token,
    get_current_active_user, require_admin, users_db, get_password_hash
)
from app.security import (
    limiter, SecurityMiddleware, rate_limit_exceeded_handler, log_activity
)

# -------------------------------------------------
# App setup
# -------------------------------------------------
app = FastAPI(
    title="SecureAPI – Intelligent API Security Gateway",
    description="""
## College Project Demo

This is a **live working security gateway** that sits in front of APIs and protects them.

### How to test (easy steps)
1. Click **Authorize** (top right) after logging in
2. Use the endpoints below
3. Watch the terminal / `logs/api_activity.log` for live security events

### Demo Accounts
| Username | Password  | Role  |
|----------|-----------|-------|
| admin    | admin123  | admin |
| alice    | alice123  | user  |
| bob      | bob123    | user  |
    """,
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Rate limiter state
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)

# Security middleware (threat detection + logging + headers)
app.add_middleware(SecurityMiddleware)

# CORS (open for demo – tighten in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup():
    init_demo_users()
    os.makedirs("logs", exist_ok=True)
    print("\n" + "=" * 60)
    print("  SecureAPI Gateway is LIVE!")
    print("  Open → http://127.0.0.1:8000/docs")
    print("  Demo users: admin/admin123 | alice/alice123 | bob/bob123")
    print("=" * 60 + "\n")


# -------------------------------------------------
# Public endpoints
# -------------------------------------------------

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def home():
    """Simple landing page"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>SecureAPI Gateway</title>
        <style>
            body { font-family: system-ui, sans-serif; max-width: 800px; margin: 40px auto; padding: 20px; background: #0f172a; color: #e2e8f0; }
            h1 { color: #38bdf8; }
            a { color: #7dd3fc; }
            .card { background: #1e293b; padding: 20px; border-radius: 12px; margin: 16px 0; }
            code { background: #334155; padding: 2px 6px; border-radius: 4px; }
            table { width: 100%; border-collapse: collapse; }
            td, th { padding: 8px; border-bottom: 1px solid #334155; text-align: left; }
        </style>
    </head>
    <body>
        <h1>🛡️ SecureAPI – Intelligent API Security Gateway</h1>
        <p>College Project Demo • Live Working Model</p>

        <div class="card">
            <h3>🚀 Quick Start</h3>
            <ol>
                <li>Open the interactive docs: <a href="/docs" target="_blank"><b>/docs</b></a></li>
                <li>Login with a demo account (see table below)</li>
                <li>Click <b>Authorize</b> and paste the token</li>
                <li>Try protected endpoints and watch the security features</li>
            </ol>
        </div>

        <div class="card">
            <h3>👤 Demo Accounts</h3>
            <table>
                <tr><th>Username</th><th>Password</th><th>Role</th></tr>
                <tr><td>admin</td><td>admin123</td><td>admin</td></tr>
                <tr><td>alice</td><td>alice123</td><td>user</td></tr>
                <tr><td>bob</td><td>bob123</td><td>user</td></tr>
            </table>
        </div>

        <div class="card">
            <h3>✅ Features Implemented</h3>
            <ul>
                <li>JWT Authentication</li>
                <li>Role-Based Access Control (RBAC)</li>
                <li>Input & Parameter Validation</li>
                <li>Rate Limiting (30 req/min)</li>
                <li>Suspicious Request Detection (threat score)</li>
                <li>API Activity Logging</li>
                <li>Secure Error Handling</li>
                <li>Security Headers</li>
            </ul>
        </div>

        <p style="text-align:center; opacity:0.6;">Made for college project • Easy to understand & demo</p>
    </body>
    </html>
    """


@app.get("/health", response_model=HealthResponse, tags=["Public"])
@limiter.limit("60/minute")
async def health(request: Request):
    """Health check – public"""
    return {
        "status": "healthy",
        "version": "1.0.0",
        "features": [
            "Authentication (JWT)",
            "Authorization + RBAC",
            "Input Validation",
            "Parameter Validation",
            "Rate Limiting",
            "Suspicious Request Detection",
            "Activity Logging",
            "Secure Error Handling"
        ]
    }


# -------------------------------------------------
# Authentication
# -------------------------------------------------

@app.post("/auth/login", response_model=Token, tags=["Authentication"])
@limiter.limit("10/minute")
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Login to get JWT token.
    Use the token in the **Authorize** button in Swagger.
    """
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        log_activity(request, 401, "Login failed – invalid credentials", form_data.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(
        data={"sub": user["username"], "role": user["role"]}
    )
    log_activity(request, 200, "Login successful", user["username"])
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "role": user["role"],
        "username": user["username"]
    }


@app.post("/auth/register", response_model=UserOut, tags=["Authentication"])
@limiter.limit("5/minute")
async def register(request: Request, user_in: UserRegister):
    """
    Register a new user (role defaults to 'user').
    Only admin can create another admin (enforced by validation).
    """
    username = user_in.username.lower()
    if username in users_db:
        raise HTTPException(status_code=400, detail="Username already registered")

    # Prevent creating admin via public register
    role = user_in.role.value
    if role == "admin":
        role = "user"  # force user role for public registration

    users_db[username] = {
        "username": username,
        "full_name": user_in.full_name,
        "hashed_password": get_password_hash(user_in.password),
        "role": role,
        "created_at": datetime.now(timezone.utc),
        "is_active": True,
    }
    log_activity(request, 201, f"New user registered: {username}", username)
    return {
        "username": username,
        "full_name": user_in.full_name,
        "role": role,
        "created_at": users_db[username]["created_at"]
    }


# -------------------------------------------------
# Protected endpoints (need JWT)
# -------------------------------------------------

@app.get("/api/me", response_model=UserOut, tags=["Protected – Any User"])
@limiter.limit("30/minute")
async def get_me(request: Request, current_user: dict = Depends(get_current_active_user)):
    """Get current logged-in user profile"""
    log_activity(request, 200, "Profile accessed", current_user["username"])
    return {
        "username": current_user["username"],
        "full_name": current_user["full_name"],
        "role": current_user["role"],
        "created_at": current_user["created_at"]
    }


@app.post("/api/search", tags=["Protected – Any User"])
@limiter.limit("20/minute")
async def search_data(
    request: Request,
    payload: ProtectedDataRequest,
    current_user: dict = Depends(get_current_active_user)
):
    """
    Example protected endpoint with **strict input validation**.
    Try sending dangerous input – it will be rejected by Pydantic + threat engine.
    """
    log_activity(
        request, 200,
        f"Search performed: query='{payload.query[:50]}'",
        current_user["username"]
    )
    return {
        "message": "Search completed successfully",
        "query": payload.query,
        "limit": payload.limit,
        "include_sensitive": payload.include_sensitive,
        "results": [
            {"id": 1, "title": f"Result for '{payload.query}'", "safe": True},
            {"id": 2, "title": "Another safe result", "safe": True},
        ],
        "user": current_user["username"]
    }


@app.get("/api/data", tags=["Protected – Any User"])
@limiter.limit("30/minute")
async def get_public_data(request: Request, current_user: dict = Depends(get_current_active_user)):
    """Simple protected data endpoint"""
    log_activity(request, 200, "Data list accessed", current_user["username"])
    return {
        "data": [
            {"id": 1, "name": "Public Item A", "owner": "system"},
            {"id": 2, "name": "Public Item B", "owner": "system"},
        ],
        "accessed_by": current_user["username"]
    }


# -------------------------------------------------
# Admin-only endpoints (RBAC)
# -------------------------------------------------

@app.get("/api/admin/users", response_model=List[UserOut], tags=["Admin Only – RBAC"])
@limiter.limit("20/minute")
async def list_all_users(
    request: Request,
    current_user: dict = Depends(require_admin)
):
    """List all users – **Admin only**"""
    log_activity(request, 200, "Admin listed all users", current_user["username"])
    return [
        {
            "username": u["username"],
            "full_name": u["full_name"],
            "role": u["role"],
            "created_at": u["created_at"]
        }
        for u in users_db.values()
    ]


@app.post("/api/admin/action", tags=["Admin Only – RBAC"])
@limiter.limit("10/minute")
async def admin_action(
    request: Request,
    action: AdminAction,
    current_user: dict = Depends(require_admin)
):
    """Perform an admin action – **Admin only**"""
    log_activity(
        request, 200,
        f"Admin action: {action.action} on {action.target_user}",
        current_user["username"]
    )
    return {
        "status": "success",
        "action": action.action,
        "target": action.target_user,
        "performed_by": current_user["username"],
        "reason": action.reason or "No reason provided"
    }


@app.get("/api/admin/logs", tags=["Admin Only – RBAC"])
@limiter.limit("10/minute")
async def view_recent_logs(
    request: Request,
    current_user: dict = Depends(require_admin)
):
    """View recent activity logs – **Admin only**"""
    log_file = settings.LOG_FILE
    lines = []
    if os.path.exists(log_file):
        with open(log_file, "r", encoding="utf-8") as f:
            lines = f.readlines()[-30:]  # last 30 entries
    log_activity(request, 200, "Admin viewed logs", current_user["username"])
    return {
        "total_shown": len(lines),
        "logs": [line.strip() for line in lines]
    }


# -------------------------------------------------
# Intentionally vulnerable-looking endpoint for demo
# (still protected by our gateway)
# -------------------------------------------------

@app.get("/api/echo", tags=["Demo – Threat Detection"])
@limiter.limit("15/minute")
async def echo_query(request: Request, q: str = ""):
    """
    Public echo endpoint used to **demonstrate threat detection**.
    Try these in the browser or Swagger:
    - ?q=hello          → allowed
    - ?q=union select   → blocked by threat engine
    - ?q=../../../etc   → blocked
    """
    # Even though this is public, the middleware already scanned it
    return {
        "echo": q,
        "note": "If you see this, the request was considered safe enough",
        "tip": "Try malicious values to see the gateway block them"
    }


# -------------------------------------------------
# Run with: uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
# -------------------------------------------------
