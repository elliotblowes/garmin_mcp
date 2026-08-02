"""
Per-user Garmin token storage, encrypted at rest in Upstash Redis.
Each user is identified by their own auth token (the one they'll put
into the iOS app / connector URL). We never store that auth token
itself unencrypted anywhere except as the lookup key.
"""

import os
import json
import hashlib
from datetime import datetime, timezone
from upstash_redis import Redis
from cryptography.fernet import Fernet

_redis = None
_fernet = None


def _get_redis() -> Redis:
    global _redis
    if _redis is None:
        _redis = Redis(
            url=os.environ["UPSTASH_REDIS_REST_URL"],
            token=os.environ["UPSTASH_REDIS_REST_TOKEN"],
        )
    return _redis


def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        key = os.environ["GARMIN_MCP_ENCRYPTION_KEY"]
        _fernet = Fernet(key.encode())
    return _fernet


def _email_hash(email: str) -> str:
    """One-way hash of an email, used only to detect repeat signups —
    never stores or exposes the real email address."""
    return hashlib.sha256(email.strip().lower().encode()).hexdigest()


def find_token_for_email(email: str) -> str | None:
    """Return an existing user token for this email, if they've signed up before."""
    return _get_redis().get(f"email_index:{_email_hash(email)}")


def _record_email_token(email: str, user_auth_token: str) -> None:
    _get_redis().set(f"email_index:{_email_hash(email)}", user_auth_token)


def save_user_tokens(user_auth_token: str, garmin_token_json: str, email: str | None = None) -> None:
    """Encrypt and store one user's Garmin OAuth tokens, plus basic metadata."""
    r = _get_redis()
    encrypted = _get_fernet().encrypt(garmin_token_json.encode()).decode()
    r.set(f"user:{user_auth_token}:garmin_tokens", encrypted)

    meta = {"updated_at": datetime.now(timezone.utc).isoformat()}
    existing_meta_raw = r.get(f"user:{user_auth_token}:meta")
    if existing_meta_raw:
        try:
            existing_meta = json.loads(existing_meta_raw)
            meta["created_at"] = existing_meta.get("created_at", meta["updated_at"])
        except (json.JSONDecodeError, TypeError):
            meta["created_at"] = meta["updated_at"]
    else:
        meta["created_at"] = meta["updated_at"]
    r.set(f"user:{user_auth_token}:meta", json.dumps(meta))

    if email:
        _record_email_token(email, user_auth_token)


def load_user_tokens(user_auth_token: str) -> str | None:
    """Look up and decrypt one user's Garmin OAuth tokens, or None if unknown."""
    encrypted = _get_redis().get(f"user:{user_auth_token}:garmin_tokens")
    if encrypted is None:
        return None
    return _get_fernet().decrypt(encrypted.encode()).decode()


def user_exists(user_auth_token: str) -> bool:
    return _get_redis().get(f"user:{user_auth_token}:garmin_tokens") is not None
