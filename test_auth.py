# OrderFlow: Authentication test suite

import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient
from app import app
from auth import create_access_token, USERS_DB

client = TestClient(app)


# Pre-written — use this as a reference when writing your own fixtures below.
@pytest.fixture
def auth_token():
    return create_access_token({"sub": "alice@orderflow.com", "role": "admin"})


# Returns the Authorization header dict built from the token above.
@pytest.fixture
def auth_headers(auth_token):
    return {"Authorization": f"Bearer {auth_token}"}


# Bug fix: the endpoint is protected, so a request with no credentials must be
# rejected with 401, not accepted with 200.
def test_unauthenticated_access_rejected():
    response = client.get("/products")
    assert response.status_code == 401


def test_authenticated_access_succeeds(auth_headers):
    response = client.get("/products", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) > 0


def test_malformed_token_rejected():
    headers = {"Authorization": "Bearer not-a-real-jwt"}
    response = client.get("/products", headers=headers)
    assert response.status_code == 401


@pytest.mark.parametrize("email, password, expected_status", [
    ("wrong@orderflow.com", "secret", 401),          # wrong email
    ("alice@orderflow.com", "wrongpassword", 401),   # wrong password
    ("wrong@orderflow.com", "wrongpassword", 401),   # both wrong
])
def test_login_invalid_credentials(email, password, expected_status):
    response = client.post(
        "/auth/login",
        data={"username": email, "password": password},
    )
    assert response.status_code == expected_status


def test_login_with_mocked_users_db():
    mock_db = {
        "test@orderflow.com": {
            "email": "test@orderflow.com",
            # bcrypt hash of "secret"
            "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
            "role": "viewer",
        }
    }
    with patch("auth.USERS_DB", mock_db):
        response = client.post(
            "/auth/login",
            data={"username": "test@orderflow.com", "password": "secret"},
        )
        assert response.status_code == 200
        body = response.json()
        assert "access_token" in body
        assert body["token_type"] == "bearer"
