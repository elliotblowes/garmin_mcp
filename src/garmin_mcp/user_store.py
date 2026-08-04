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

DEFAULT_PLAN = {
    "start_date": "2026-08-04",
    "race_date": "2026-09-05",
    "weeks": [
        {"title": "Week 1 · Build", "range": "Aug 4 – 9", "days": [
            {"date": "2026-08-04", "day_label": "Tue", "day_num": "4", "type": "easy", "badge": None, "description": "4–5 mi conversational pace", "note": None},
            {"date": "2026-08-05", "day_label": "Wed", "day_num": "5", "type": "quality", "badge": None, "description": "5 mi — 1 mi warm-up, 3 mi moderately hard, 1 mi cool-down", "note": None},
            {"date": "2026-08-06", "day_label": "Thu", "day_num": "6", "type": "easy", "badge": None, "description": "4 mi easy", "note": "+ optional 20 min light strength: calf raises, mobility"},
            {"date": "2026-08-07", "day_label": "Fri", "day_num": "7", "type": "rest", "badge": None, "description": "Full rest", "note": None},
            {"date": "2026-08-08", "day_label": "Sat", "day_num": "8", "type": "easy", "badge": None, "description": "3 mi shakeout", "note": None},
            {"date": "2026-08-09", "day_label": "Sun", "day_num": "9", "type": "long", "badge": None, "description": "11–12 mi easy to moderate", "note": None},
        ]},
        {"title": "Week 2 · Peak", "range": "Aug 10 – 16", "days": [
            {"date": "2026-08-10", "day_label": "Mon", "day_num": "10", "type": "strength", "badge": None, "description": "Main session — after yesterday's long run, keep loads moderate not maximal", "note": None},
            {"date": "2026-08-11", "day_label": "Tue", "day_num": "11", "type": "easy", "badge": None, "description": "4–5 mi recovery pace", "note": None},
            {"date": "2026-08-12", "day_label": "Wed", "day_num": "12", "type": "quality", "badge": None, "description": "5 mi moderate tempo — keep it controlled, peak week", "note": None},
            {"date": "2026-08-13", "day_label": "Thu", "day_num": "13", "type": "easy", "badge": None, "description": "4 mi easy", "note": "+ optional light strength, 20 min"},
            {"date": "2026-08-14", "day_label": "Fri", "day_num": "14", "type": "rest", "badge": None, "description": "Full rest — bank freshness for Sunday", "note": None},
            {"date": "2026-08-15", "day_label": "Sat", "day_num": "15", "type": "easy", "badge": None, "description": "3 mi shakeout", "note": None},
            {"date": "2026-08-16", "day_label": "Sun", "day_num": "16", "type": "long", "badge": "PEAK LONG RUN", "description": "16–18 mi — the biggest run of the block", "note": None},
        ]},
        {"title": "Week 3 · Taper begins", "range": "Aug 17 – 23", "days": [
            {"date": "2026-08-17", "day_label": "Mon", "day_num": "17", "type": "strength", "badge": None, "description": "Lighter session — trim load as volume tapers", "note": None},
            {"date": "2026-08-18", "day_label": "Tue", "day_num": "18", "type": "easy", "badge": None, "description": "4 mi easy", "note": None},
            {"date": "2026-08-19", "day_label": "Wed", "day_num": "19", "type": "quality", "badge": None, "description": "3 mi tempo — reduced volume", "note": None},
            {"date": "2026-08-20", "day_label": "Thu", "day_num": "20", "type": "easy", "badge": None, "description": "4 mi easy", "note": None},
            {"date": "2026-08-21", "day_label": "Fri", "day_num": "21", "type": "rest", "badge": None, "description": "Full rest", "note": None},
            {"date": "2026-08-22", "day_label": "Sat", "day_num": "22", "type": "easy", "badge": None, "description": "3 mi shakeout", "note": None},
            {"date": "2026-08-23", "day_label": "Sun", "day_num": "23", "type": "long", "badge": None, "description": "12–13 mi — include a few miles at goal marathon effort", "note": None},
        ]},
        {"title": "Week 4 · Taper deepens", "range": "Aug 24 – 30", "days": [
            {"date": "2026-08-24", "day_label": "Mon", "day_num": "24", "type": "strength", "badge": None, "description": "Light — maintain, don't create soreness", "note": None},
            {"date": "2026-08-25", "day_label": "Tue", "day_num": "25", "type": "easy", "badge": None, "description": "3–4 mi easy", "note": None},
            {"date": "2026-08-26", "day_label": "Wed", "day_num": "26", "type": "easy", "badge": "EASY + STRIDES", "description": "3 mi easy, with 4–6 x 20 sec strides", "note": None},
            {"date": "2026-08-27", "day_label": "Thu", "day_num": "27", "type": "easy", "badge": None, "description": "3 mi easy", "note": None},
            {"date": "2026-08-28", "day_label": "Fri", "day_num": "28", "type": "rest", "badge": None, "description": "Full rest", "note": None},
            {"date": "2026-08-29", "day_label": "Sat", "day_num": "29", "type": "easy", "badge": None, "description": "2–3 mi shakeout", "note": None},
            {"date": "2026-08-30", "day_label": "Sun", "day_num": "30", "type": "long", "badge": None, "description": "8–10 mi easy, no pace pressure", "note": None},
        ]},
        {"title": "Week 5 · Race week", "range": "Aug 31 – Sep 5", "days": [
            {"date": "2026-08-31", "day_label": "Mon", "day_num": "31", "type": "strength", "badge": None, "description": "Optional, very light — or skip if legs feel at all heavy", "note": None},
            {"date": "2026-09-01", "day_label": "Tue", "day_num": "1", "type": "easy", "badge": None, "description": "3–4 mi easy", "note": None},
            {"date": "2026-09-02", "day_label": "Wed", "day_num": "2", "type": "easy", "badge": "EASY + STRIDES", "description": "2–3 mi with a few short strides, stay loose", "note": None},
            {"date": "2026-09-03", "day_label": "Thu", "day_num": "3", "type": "rest", "badge": None, "description": "Full rest", "note": None},
            {"date": "2026-09-04", "day_label": "Fri", "day_num": "4", "type": "rest", "badge": "REST / TRAVEL", "description": "Rest, or a very short 1–2 mi shakeout if travelling in", "note": None},
        ]},
    ],
}


def load_user_plan(user_auth_token: str) -> dict:
    """Return this user's current plan, seeding the default if they don't have one yet."""
    r = _get_redis()
    raw = r.get(f"user:{user_auth_token}:plan")
    if raw is None:
        save_user_plan(user_auth_token, DEFAULT_PLAN)
        return DEFAULT_PLAN
    return json.loads(raw)


def save_user_plan(user_auth_token: str, plan: dict) -> None:
    _get_redis().set(f"user:{user_auth_token}:plan", json.dumps(plan))
