# app.py
from fastapi import FastAPI, HTTPException, Query
from jose import jwt
from uuid import uuid4
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import base64
import time
import sqlite3
from typing import Optional, List, Dict, Any

DB_FILE = "totally_not_my_privateKeys.db"

app = FastAPI(title="JWKS SQLite-backed Example")

# ========================
# Helper: Base64URL encoding
# ========================
def b64url_uint(val: int) -> str:
    """Convert integer to Base64URL-encoded string without padding.

    Handles zero and returns a string compatible with JWKS 'n'/'e' values.
    """
    if val == 0:
        raw = b"\x00"
    else:
        length = (val.bit_length() + 7) // 8
        raw = val.to_bytes(length, "big")
    encoded = base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")
    return encoded


# ========================
# Database helpers
# ========================
def get_db_connection() -> sqlite3.Connection:
    # allow usage across threads (fastapi/uvicorn will spawn threads)
    conn = sqlite3.connect(DB_FILE, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
    # store bytes as bytes (default) and return row as dict-like via row_factory if needed
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create DB file and the 'keys' table if missing. Insert at least one expired and one valid key."""
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        # Create table per required schema
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS keys(
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
            """
        )
        conn.commit()

        # Ensure at least one expired and one valid key exist.
        # We'll check by counting rows where exp <= now and exp > now.
        now = int(time.time())
        cur.execute("SELECT COUNT(*) FROM keys WHERE exp <= ?", (now,))
        expired_count = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM keys WHERE exp > ?", (now,))
        valid_count = cur.fetchone()[0]

        if expired_count == 0:
            # generate an expired key (expiry in the past)
            pk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            pem = pk.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            expired_ts = now - 3600  # expired 1 hour ago
            cur.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (pem, expired_ts))
            conn.commit()

        if valid_count == 0:
            # generate a valid key (expiry 1 hour in future)
            pk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            pem = pk.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            valid_ts = now + 3600  # valid for 1 hour
            cur.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (pem, valid_ts))
            conn.commit()
    finally:
        conn.close()


def load_private_key_from_blob(pem_blob: bytes):
    """Deserialize a PEM-encoded private key from bytes."""
    return serialization.load_pem_private_key(pem_blob, password=None)


def select_key_row(expired: bool) -> Optional[sqlite3.Row]:
    """Select one key row from DB according to expired flag.
    - If expired=False -> return one valid (exp > now) key
    - If expired=True  -> return one expired (exp <= now) key
    Selection is parameterized to avoid SQL injection.
    """
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        now = int(time.time())
        if expired:
            cur.execute("SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1", (now,))
        else:
            cur.execute("SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1", (now,))
        row = cur.fetchone()
        return row
    finally:
        conn.close()


def select_nonexpired_key_rows() -> List[sqlite3.Row]:
    """Return all key rows with exp > now (non-expired)."""
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        now = int(time.time())
        cur.execute("SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp ASC", (now,))
        rows = cur.fetchall()
        return list(rows)
    finally:
        conn.close()


# initialize DB and ensure keys exist when module loaded
init_db()


# ========================
# JWKS Endpoint (multiple paths)
# ========================
@app.get("/jwks")
@app.get("/jwks.json")
@app.get("/.well-known/jwks.json")
def get_jwks():
    """Return JWKS containing only non-expired keys loaded from the DB."""
    rows = select_nonexpired_key_rows()
    jwk_keys = []
    for row in rows:
        try:
            pem_blob = row["key"]
            private_key = load_private_key_from_blob(pem_blob)
            public_numbers = private_key.public_key().public_numbers()
            n = b64url_uint(public_numbers.n)
            e = b64url_uint(public_numbers.e)
            jwk_keys.append({
                "kty": "RSA",
                "kid": str(row["kid"]),
                "use": "sig",
                "alg": "RS256",
                "n": n,
                "e": e,
            })
        except Exception as exc:
            # skip keys that cannot be deserialized
            # in production you might log this
            continue
    return {"keys": jwk_keys}


# ========================
# Auth Endpoint
# ========================
@app.post("/auth")
def auth(expired: Optional[bool] = Query(False, description="true -> return token signed by expired key")):
    """Return a valid or expired JWT in JSON format.

    - If expired==True, sign with an expired key (exp in DB <= now).
    - If expired==False, sign with a currently valid key (exp in DB > now).
    """
    row = select_key_row(expired=bool(expired))
    if row is None:
        raise HTTPException(status_code=500, detail="No key available for requested expiry state")

    pem_blob = row["key"]
    private_key = load_private_key_from_blob(pem_blob)

    # create token expiration independent of key expiry; the key determines whether signature is
    # verifiable (expired keys will not be returned by JWKS)
    if expired:
        token_exp = datetime.now(tz=timezone.utc) - timedelta(minutes=5)
    else:
        token_exp = datetime.now(tz=timezone.utc) + timedelta(minutes=5)

    # jose.jwt expects a key in PEM format or a Cryptography key object.
    # We can pass the private_key object directly.
    token = jwt.encode(
        {"sub": "fakeuser", "exp": token_exp},
        private_key,
        algorithm="RS256",
        headers={"kid": str(row["kid"])},
    )
    return {"token": token}


# Explicitly reject GET on /auth
@app.get("/auth")
def auth_get():
    raise HTTPException(status_code=405, detail="Use POST for /auth")
