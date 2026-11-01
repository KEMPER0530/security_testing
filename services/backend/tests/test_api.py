import time
import pytest
from unittest.mock import Mock
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from site_diagnostics.adapters.inbound import api


def test_api_auth_and_validation(ready, monkeypatch):
    service, target, _, _ = ready
    monkeypatch.setattr(api, "service", lambda: service)
    client = TestClient(api.app)
    assert client.get("/v1/targets").status_code == 401
    api.app.dependency_overrides[api.user] = lambda: "alice"
    try:
        response = client.get("/v1/targets")
        assert response.status_code == 200
        assert "pk" not in response.json()["items"][0]
        assert "challenge_hash" not in response.json()["items"][0]
        assert "verified_until" not in response.json()["items"][0]
        assert "assessment" not in response.json()["items"][0]
        assert client.post(f"/v1/targets/{target}/challenge").status_code == 404
        assert client.post(f"/v1/targets/{target}/verify").status_code == 404
        assert client.put(f"/v1/targets/{target}/assessment", json={"answers": {}}).status_code == 404
        assert client.post("/v1/targets", json={"url": "file:///etc/passwd"}).status_code == 422
        assert client.post("/v1/scans", json={"target_id": target}).status_code == 422
        job = client.post("/v1/scans", json={"target_id": target}, headers={"Idempotency-Key": "one"})
        assert job.status_code == 202
        service.execute("alice", job.json()["id"])
        result = client.get(f"/v1/scans/{job.json()['id']}/results")
        assert result.status_code == 200
        assert result.json()["findings"][0]["severity"] in ("高", "中", "低")
        path = f"/v1/scans/{job.json()['id']}/report?format=html"
        report = client.get(path)
        assert report.status_code == 200
        assert "default-src 'none'" in report.headers["content-security-policy"]
    finally:
        api.app.dependency_overrides.clear()


@pytest.mark.parametrize("required_scope", ["openid", "aws.cognito.signin.user.admin"])
def test_jwt_signature_client_expiry_scope(monkeypatch, required_scope):
    monkeypatch.setenv("OIDC_REQUIRED_SCOPE", required_scope)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    monkeypatch.setenv("APP_ENV", "local")
    monkeypatch.setenv("OIDC_ISSUER", "http://issuer.test")
    monkeypatch.setenv("OIDC_CLIENT_ID", "web")
    mock = Mock()
    mock.get_signing_key_from_jwt.return_value.key = key.public_key()
    monkeypatch.setattr(api, "jwks", lambda: mock)
    claims = {
        "sub": "alice",
        "iss": "http://issuer.test",
        "client_id": "web",
        "scope": required_scope,
        "token_use": "access",
        "exp": time.time() + 60,
        "iat": int(time.time()),
    }
    from fastapi import HTTPException
    import pytest

    token = jwt.encode(claims, key, algorithm="RS256")
    assert api.user("Bearer " + token) == "alice"
    for changes in (
        {"client_id": "other"},
        {"iss": "http://other.test"},
        {"exp": 1},
        {"scope": ""},
        {"token_use": "id"},
    ):
        invalid = jwt.encode({**claims, **changes}, key, algorithm="RS256")
        with pytest.raises(HTTPException):
            api.user("Bearer " + invalid)
    wrong = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(HTTPException):
        api.user("Bearer " + jwt.encode(claims, wrong, algorithm="RS256"))
    monkeypatch.setenv("OIDC_REQUIRED_GROUP", "security-testing-users")
    for groups in ([], ["other-app"], "prefix-security-testing-users"):
        restricted = jwt.encode({**claims, "cognito:groups": groups}, key, algorithm="RS256")
        with pytest.raises(HTTPException):
            api.user("Bearer " + restricted)
    permitted = jwt.encode({**claims, "cognito:groups": ["security-testing-users"]}, key, algorithm="RS256")
    assert api.user("Bearer " + permitted) == "alice"


def test_job_history_shows_active_targets_and_hides_deleted(ready, monkeypatch):
    service, target_id, _, _ = ready
    monkeypatch.setattr(api, "service", lambda: service)
    api.app.dependency_overrides[api.user] = lambda: "alice"
    try:
        client = TestClient(api.app)
        job = service.enqueue("alice", target_id, "history")
        rows = client.get("/v1/scans").json()["items"]
        assert [row["id"] for row in rows] == [job["id"]]
        service.remove("alice", target_id)
        assert client.get("/v1/scans").json()["items"] == []
    finally:
        api.app.dependency_overrides.clear()
