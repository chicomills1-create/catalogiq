"""CatalogIQ — auth primitives (stdlib only).

Passwords: PBKDF2-HMAC-SHA256, 600k iterations, per-user salt (stdlib adaptive
hashing; Argon2id is the named upgrade when a crypto lib is available).
Sessions + action tokens are stored as SHA-256 hashes; raw values only ever
exist in the cookie / emailed link.
"""
import hashlib, hmac, secrets, time
from datetime import datetime, timedelta, timezone

ITER = 600_000


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, ITER)
    return f"pbkdf2${ITER}${salt.hex()}${dk.hex()}"


def check_password(pw: str, stored: str) -> bool:
    try:
        _, iters, salt_hex, dk_hex = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode(),
                                 bytes.fromhex(salt_hex), int(iters))
        return hmac.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False


def tok_hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def new_token() -> str:
    return secrets.token_urlsafe(32)


def expiry(hours: float) -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()


def is_expired(iso_str: str) -> bool:
    try:
        return datetime.fromisoformat(iso_str) < datetime.now(timezone.utc)
    except Exception:
        return True
