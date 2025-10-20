from fastapi.testclient import TestClient
from jose import jwt
from app import app, DB_FILE, select_nonexpired_key_rows
import os
import time

client = TestClient(app)

def test_database_exists():
    assert os.path.exists(DB_FILE), "Database file should exist"

def test_jwks_returns_valid_key():
    r = client.get("/.well-known/jwks.json")
    assert r.status_code == 200
    data = r.json()
    assert "keys" in data
    assert len(data["keys"]) >= 1
    key = data["keys"][0]
    for field in ["kty", "kid", "n", "e", "alg"]:
        assert field in key

def test_valid_auth_jwt():
    r = client.post("/auth")
    assert r.status_code == 200
    token = r.json()["token"]
    assert isinstance(token, str)
    # Decode without verifying (since we don't have public key easily here)
    header = jwt.get_unverified_header(token)
    payload = jwt.get_unverified_claims(token)
    assert payload["sub"] == "fakeuser"
    assert payload["exp"] > time.time()

def test_expired_auth_jwt():
    r = client.post("/auth?expired=true")
    assert r.status_code == 200
    token = r.json()["token"]
    payload = jwt.get_unverified_claims(token)
    assert payload["exp"] < time.time()

def test_nonexpired_db_keys_match_jwks():
    db_keys = select_nonexpired_key_rows()
    r = client.get("/.well-known/jwks.json")
    assert len(r.json()["keys"]) == len(db_keys)
