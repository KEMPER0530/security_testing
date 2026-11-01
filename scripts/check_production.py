"""Guard against accidentally embedding local fixture secrets in the web build."""

from pathlib import Path

for path in Path("apps/web/dist").rglob("*.js"):
    data = path.read_text()
    for forbidden in (
        "local-development-only",
        "local-admin-only",
        "LOCALSTACK_AUTH_TOKEN",
        "AWS_SECRET_ACCESS_KEY",
    ):
        if forbidden in data:
            raise SystemExit(f"Forbidden development secret in {path.name}")
print("No local-only credentials found in web bundle")
