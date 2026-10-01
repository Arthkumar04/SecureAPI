"""
Security helpers: Rate limiting, Suspicious request detection,
Activity logging, Secure error handling.
"""

import time
import re
from datetime import datetime, timezone
from typing import Optional, Callable
from fastapi import Request, Response, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from app.config import settings
import logging
import os

# Ensure logs directory exists
os.makedirs("logs", exist_ok=True)

# Configure activity logger
activity_logger = logging.getLogger("secureapi.activity")
activity_logger.setLevel(logging.INFO)
if not activity_logger.handlers:
    fh = logging.FileHandler(settings.LOG_FILE, encoding="utf-8")
    fh.setFormatter(logging.Formatter(
        "%(asctime)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    ))
    activity_logger.addHandler(fh)
    # Also print to console for live demo
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s | %(message)s", datefmt="%H:%M:%S"))
    activity_logger.addHandler(ch)


# Rate limiter (IP based)
limiter = Limiter(key_func=get_remote_address, default_limits=[settings.RATE_LIMIT])


def calculate_threat_score(request: Request, body: str = "") -> int:
    """
    Simple threat scoring engine.
    Higher score = more suspicious.
    """
    score = 0
    path = request.url.path.lower()
    query = str(request.url.query).lower()
    headers = {k.lower(): v.lower() for k, v in request.headers.items()}
    combined = f"{path} {query} {body}".lower()

    # 1. Known attack keywords
    for keyword in settings.SUSPICIOUS_KEYWORDS:
        if keyword in combined:
            score += 30

    # 2. SQL injection style patterns
    sql_patterns = [
        r"(\bunion\b.*\bselect\b)",
        r"(\bor\b\s+\d+\s*=\s*\d+)",
        r"(--\s*$)",
        r"(;\s*drop\b)",
        r"(/\*.*\*/)",
    ]
    for pattern in sql_patterns:
        if re.search(pattern, combined, re.IGNORECASE):
            score += 40

    # 3. Path traversal
    if ".." in path or "%2e%2e" in path:
        score += 50

    # 4. Suspicious User-Agent
    ua = headers.get("user-agent", "")
    if not ua or "curl" in ua or "python-requests" in ua or "sqlmap" in ua:
        score += 10  # mild – many legitimate tools use these

    # 5. Missing common headers (very basic)
    if "accept" not in headers:
        score += 5

    # 6. Extremely long query / body
    if len(query) > 500 or len(body) > 2000:
        score += 20

    return min(score, 100)  # cap at 100


def log_activity(
    request: Request,
    status_code: int,
    message: str,
    username: Optional[str] = None,
    threat_score: int = 0,
):
    """Write structured activity log"""
    client_ip = request.client.host if request.client else "unknown"
    entry = (
        f"IP={client_ip} | {request.method} {request.url.path} | "
        f"User={username or 'anonymous'} | Status={status_code} | "
        f"Threat={threat_score} | {message}"
    )
    activity_logger.info(entry)


class SecurityMiddleware(BaseHTTPMiddleware):
    """
    Custom middleware that runs on EVERY request:
    - Calculates threat score
    - Blocks high-threat requests
    - Logs everything
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start = time.time()
        body_bytes = b""
        threat_score = 0
        username = None

        # Read body for inspection (careful with large bodies)
        if request.method in ("POST", "PUT", "PATCH"):
            body_bytes = await request.body()
            # Recreate receive so FastAPI can still read the body
            async def receive():
                return {"type": "http.request", "body": body_bytes}
            request._receive = receive

        body_str = body_bytes.decode("utf-8", errors="ignore")[:2000]

        # Calculate threat
        threat_score = calculate_threat_score(request, body_str)

        # Block if threat is very high
        if threat_score >= 70:
            log_activity(
                request, 403,
                f"BLOCKED – High threat score ({threat_score})",
                threat_score=threat_score
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "Request blocked by security gateway",
                    "reason": "Suspicious patterns detected",
                    "threat_score": threat_score,
                    "hint": "This looks like an attack attempt. Please use normal requests."
                }
            )

        # Process request
        try:
            response = await call_next(request)
        except Exception as e:
            # Secure error handling – never leak stack traces
            log_activity(
                request, 500,
                f"Internal error (sanitized): {type(e).__name__}",
                threat_score=threat_score
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "error": "Internal server error",
                    "message": "Something went wrong. The incident has been logged.",
                    "request_id": str(int(time.time() * 1000))
                }
            )

        # Try to extract username from response headers if set by auth
        # (we also log in endpoints for better accuracy)

        duration = round((time.time() - start) * 1000, 1)
        log_activity(
            request,
            response.status_code,
            f"OK – {duration}ms",
            threat_score=threat_score
        )

        # Add security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["X-Threat-Score"] = str(threat_score)
        response.headers["X-SecureAPI"] = "v1.0"

        return response


def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded):
    """Custom friendly message when rate limit is hit"""
    log_activity(request, 429, "Rate limit exceeded")
    raise HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail={
            "error": "Too many requests",
            "message": f"Rate limit exceeded. Please wait a moment.",
            "limit": settings.RATE_LIMIT
        }
    )
