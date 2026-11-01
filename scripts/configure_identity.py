"""Idempotent setup of the local-only Keycloak client; never prints access tokens."""

import http.client
import json
import urllib.request
import urllib.parse
import urllib.error
import time

ORIGIN = "http://localhost:8080"


def configure():
    deadline = time.monotonic() + 180
    while True:
        try:
            with urllib.request.urlopen(  # nosec B310 - fixed local-only ORIGIN; no user-supplied URL
                ORIGIN + "/realms/security-testing/.well-known/openid-configuration", timeout=5
            ) as response:
                if response.status == 200:
                    break
        except (urllib.error.URLError, TimeoutError, http.client.RemoteDisconnected):
            if time.monotonic() >= deadline:
                raise RuntimeError("Local identity service did not become ready within 180 seconds") from None
        time.sleep(2)
    form = urllib.parse.urlencode(
        {
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": "local-admin",
            "password": "local-admin-only",
        }
    ).encode()
    with urllib.request.urlopen(  # nosec B310 - fixed local-only ORIGIN; no user-supplied URL
        ORIGIN + "/realms/master/protocol/openid-connect/token", data=form, timeout=10
    ) as response:
        token = json.load(response)["access_token"]

    def request(path, method="GET"):
        req = urllib.request.Request(
            ORIGIN + "/admin/realms/security-testing/" + path,
            method=method,
            headers={"Authorization": "Bearer " + token},
        )
        with urllib.request.urlopen(req, timeout=10) as response:  # nosec B310 - fixed local-only ORIGIN
            return json.loads(response.read()) if response.status != 204 else None

    client = request("clients?clientId=security-testing-web")[0]["id"]
    scopes = request("client-scopes")
    basic = next(scope["id"] for scope in scopes if scope["name"] == "basic")
    request(f"clients/{client}/default-client-scopes/{basic}", method="PUT")
    print("Local OIDC client configured with mandatory subject claim (basic scope).")


if __name__ == "__main__":
    configure()
