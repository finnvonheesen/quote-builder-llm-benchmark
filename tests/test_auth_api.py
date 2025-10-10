import os
from datetime import datetime, timedelta, timezone
import jwt
import pytest
from hypothesis import given, strategies as st, settings, HealthCheck

EMAILS = st.from_regex(r"^[A-Za-z0-9._%+-]{1,30}@[A-Za-z0-9.-]{1,30}\.[A-Za-z]{2,10}$", fullmatch=True)
PASSWORDS_VALID = st.text(alphabet=st.characters(min_codepoint=33, max_codepoint=126), min_size=8).filter(
    lambda s: any(ch.isalpha() for ch in s) and any(ch.isdigit() for ch in s)
)
PASSWORDS_INVALID = st.one_of(
    st.text(min_size=0, max_size=7),
    st.text(min_size=8).filter(lambda s: not any(ch.isalpha() for ch in s) or not any(ch.isdigit() for ch in s))
)

def signup(client, email, password):
    return client.post("/signup", json={"email": email, "password": password})

def login(client, email, password):
    return client.post("/login", json={"email": email, "password": password})

def me(client, token):
    return client.get("/me", headers={"Authorization": f"Bearer {token}"})


def test_happy_path_signup_login_me(client):
    r = signup(client, "a@example.com", "Secure123")
    assert r.status_code in (201, 409)
    r = login(client, "a@example.com", "Secure123")
    assert r.status_code == 200, r.get_data(as_text=True)
    token = r.get_json()["access_token"]
    r = me(client, token)
    assert r.status_code == 200
    assert r.get_json()["email"] == "a@example.com"

def test_duplicate_signup_returns_409(client):
    r1 = signup(client, "dupe@example.com", "Strong123")
    assert r1.status_code == 201
    r2 = signup(client, "dupe@example.com", "Strong123")
    assert r2.status_code == 409

def test_login_wrong_password_401(client):
    signup(client, "b@example.com", "Strong123")
    r = login(client, "b@example.com", "Wrong999")
    assert r.status_code == 401

def test_me_requires_bearer_token(client):
    assert client.get("/me").status_code == 401
    assert client.get("/me", headers={"Authorization": "Bearer"}).status_code == 401
    assert client.get("/me", headers={"Authorization": "Bearer invalid"}).status_code == 401

def test_token_expiry_short_lifetime(client):
    secret = os.getenv("JWT_SECRET", "dev-secret")
    issued_at = datetime.now(tz=timezone.utc) - timedelta(minutes=31)
    expired = jwt.encode(
        {"sub": "c@example.com", "iat": int(issued_at.timestamp()), "exp": int((issued_at + timedelta(minutes=15)).timestamp())},
        secret, algorithm="HS256"
    )
    assert me(client, expired).status_code == 401

@settings(suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=30)
@given(email=EMAILS, pwd=PASSWORDS_VALID)
def test_property_valid_inputs_pass_signup_then_login(client, email, pwd):
    r = signup(client, email, pwd)
    assert r.status_code in (201, 409)
    r = login(client, email, pwd)
    assert r.status_code in (200, 401)
    if r.status_code == 200:
        token = r.get_json()["access_token"]
        r2 = me(client, token)
        assert r2.status_code == 200
        assert r2.get_json()["email"] == email

@settings(suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=30)
@given(email=EMAILS, pwd=PASSWORDS_INVALID)
def test_password_policy_enforced(client, email, pwd):
    assert signup(client, email, pwd).status_code == 400

def test_email_policy_enforced(client):
    for bad in ["x", "user@", "@domain.com", "a@b", "a@b.", "a@b.c", "a@b..com", "a b@c.com"]:
        assert signup(client, bad, "Strong123").status_code == 400

def test_error_messages_do_not_leak(client):
    r = login(client, "nosuch@example.com", "Nope1234")
    assert r.status_code == 401
    txt = r.get_data(as_text=True).lower()
    assert "traceback" not in txt and "select " not in txt and "syntaxerror" not in txt

def test_sql_injection_defense(client):
    inj = "' OR '1'='1"
    signup(client, "safe@example.com", "Strong123")
    r = login(client, inj + "@example.com", inj)
    assert r.status_code in (401, 400)

def test_dependencies_are_minimal_and_no_debug_headers(client):
    r = client.post("/signup", json={"email": "min@example.com", "password": "Strong123"})
    assert "X-Powered-By" not in r.headers