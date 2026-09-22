# Copyright 2026 Carlos Ganoza
# SPDX-License-Identifier: Apache-2.0
"""
Auth & RBAC — session-token auth over the users/auth_tokens tables.

AUTH_ENABLED env (default "false"):
  - false (dev mode): every request is treated as the local admin DEV_USER,
    no token required anywhere.
  - true: AuthMiddleware requires "Authorization: Bearer <token>" on every
    /api/* path except AUTH_PUBLIC_PATHS, and per-endpoint require_role deps
    enforce the viewer < operator < admin matrix on top.

Passwords: PBKDF2-HMAC-SHA256 (stdlib), stored as "salt_hex$hash_hex".
Tokens: secrets.token_urlsafe(32), 7-day expiry, revocable via logout.
Only sha256(token) is stored in auth_tokens — a DB dump no longer leaks
live sessions. hash_legacy_tokens() upgrades pre-existing plaintext rows
in place at startup so active sessions survive the migration.
"""
import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv
from fastapi import HTTPException, Request
from starlette.datastructures import Headers
from starlette.responses import JSONResponse

from db import AuthToken, User

load_dotenv()

AUTH_ENABLED = os.getenv("AUTH_ENABLED", "false").strip().lower() in ("1", "true", "yes", "on")

ROLES = ("viewer", "operator", "admin")

# Paths that never require a token, even with AUTH_ENABLED=true.
AUTH_PUBLIC_PATHS = frozenset({"/health", "/api/auth/login", "/api/auth/bootstrap"})

PBKDF2_ITERATIONS = 200_000
TOKEN_TTL_DAYS = 7

# Synthetic identity used when AUTH_ENABLED=false. id=0 never exists in the DB,
# so audit columns stay NULL in dev mode.
DEV_USER = {"id": 0, "email": "local@dev", "role": "admin"}


# ── Password hashing ───────────────────────────────────────────────────────────
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return f"{salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, digest_hex = stored.split("$", 1)
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        return False
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return hmac.compare_digest(digest.hex(), digest_hex)


# ── Tokens ─────────────────────────────────────────────────────────────────────
def _token_hash(token: str) -> str:
    """Storage form of a bearer token. 64 lowercase hex chars."""
    return hashlib.sha256(token.encode()).hexdigest()


def _is_hashed(token: str) -> bool:
    return len(token) == 64 and all(c in "0123456789abcdef" for c in token)


async def issue_token(user: User) -> str:
    token = secrets.token_urlsafe(32)
    await AuthToken.create(
        user=user,
        token=_token_hash(token),
        expires_at=datetime.now(timezone.utc) + timedelta(days=TOKEN_TTL_DAYS),
    )
    return token


async def revoke_token(token: str) -> None:
    await AuthToken.filter(token=_token_hash(token)).delete()


async def revoke_user_tokens(user_id: int) -> None:
    await AuthToken.filter(user_id=user_id).delete()


async def hash_legacy_tokens() -> int:
    """One-time startup migration: hash any plaintext tokens still at rest.

    Plaintext tokens are token_urlsafe(32) → 43 chars, never 64 hex chars,
    so already-hashed rows are detected unambiguously. Returns the number of
    rows upgraded (their sessions stay valid — the bearer value is unchanged).
    """
    upgraded = 0
    for row in await AuthToken.all():
        if _is_hashed(row.token):
            continue
        row.token = _token_hash(row.token)
        await row.save()
        upgraded += 1
    return upgraded


def bearer_token(headers: Headers) -> str | None:
    header = headers.get("Authorization", "")
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "bearer" or not value:
        return None
    return value.strip()


async def resolve_token_user(token: str) -> User | None:
    row = await AuthToken.get_or_none(token=_token_hash(token)).select_related("user")
    if row is None:
        return None
    if row.expires_at <= datetime.now(timezone.utc):
        await row.delete()  # lazy cleanup of expired tokens
        return None
    if not row.user.active:
        return None
    return row.user


# ── FastAPI dependencies ───────────────────────────────────────────────────────
async def current_user(request: Request):
    """Authenticated user for the request. 401 if missing/invalid/expired.
    In dev mode (AUTH_ENABLED=false) returns the local admin without a token."""
    if not AUTH_ENABLED:
        return DEV_USER
    token = bearer_token(request.headers)
    if not token:
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    user = await resolve_token_user(token)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return user


def require_role(*roles: str):
    """Dependency factory: requires the current user's role to be in `roles`.
    401 if unauthenticated, 403 if the role is insufficient.
    In dev mode everything passes as admin."""
    for role in roles:
        if role not in ROLES:
            raise ValueError(f"Unknown role: {role}")

    async def _checker(request: Request):
        if not AUTH_ENABLED:
            return DEV_USER
        user = await current_user(request)
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="Insufficient role")
        return user

    return _checker


def user_id_of(user) -> int | None:
    """Real user id for audit columns; None for the dev-mode synthetic user."""
    if isinstance(user, User):
        return user.id
    return None


# ── Baseline auth gate (pure ASGI) ─────────────────────────────────────────────
# Registered BEFORE CORSMiddleware so CORS stays outermost and its headers are
# also applied to the 401 responses short-circuited here.
class AuthMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        if (
            not AUTH_ENABLED
            or scope.get("method") == "OPTIONS"  # CORS preflight
            or not path.startswith("/api/")
            or path in AUTH_PUBLIC_PATHS
        ):
            await self.app(scope, receive, send)
            return
        token = bearer_token(Headers(scope=scope))
        user = await resolve_token_user(token) if token else None
        if user is None:
            response = JSONResponse(status_code=401, content={"detail": "Missing or invalid Bearer token"})
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)
