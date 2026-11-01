"""Controlled fixture only: set challenge content or switch response headers."""

import argparse
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("action", choices=["token", "secure", "insecure"])
parser.add_argument("value", nargs="?")
args = parser.parse_args()
root = Path(__file__).resolve().parents[1] / "local/fixtures"
if args.action == "token":
    if (
        not args.value
        or len(args.value) > 128
        or any(
            c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for c in args.value
        )
    ):
        parser.error("Pass a verification token only, not a secret or URL")
    (root / "html/.well-known/security-testing-verification.txt").write_text(args.value)
else:
    headers = ""
    if args.action == "secure":
        headers = "add_header Content-Security-Policy \"default-src 'self'; frame-ancestors 'none'\" always;\nadd_header X-Content-Type-Options nosniff always;\nserver_tokens off;"
    (root / "nginx.conf").write_text(
        "server { listen 80; server_name fixture.security-testing.test; root /usr/share/nginx/html; "
        + headers
        + "\nlocation / { limit_except GET HEAD { deny all; } }\n}\n"
    )
    print("Reload fixture nginx: docker compose exec fixture nginx -s reload")
