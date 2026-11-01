"""Materialize an ignored deployment config from a masked GitHub Environment secret."""

import json
import os
from pathlib import Path


def main():
    raw = os.environ.get("PRODUCTION_CONFIG_JSON")
    if not raw:
        raise SystemExit("PRODUCTION_CONFIG_JSON secret is required")
    try:
        config = json.loads(raw)
        required = {
            "account",
            "region",
            "domain",
            "zone_name",
            "hosted_zone_id",
            "certificate_arn",
            "user_pool_id",
            "github_oidc_subject_prefix",
        }
        if (
            not isinstance(config, dict)
            or not required.issubset(config)
            or not all(isinstance(config[k], str) and config[k] for k in required)
        ):
            raise ValueError()
        if config["account"] in {"000000000000", "111122223333"} or config["domain"].endswith(".example.com"):
            raise ValueError()
    except (ValueError, TypeError):
        raise SystemExit("Production settings are invalid or still use example values") from None
    path = Path("infra/cdk/production.json")
    # The file is ignored by Git and contains environment-specific identifiers.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(config, f, indent=2)
        f.write("\n")
    path.chmod(0o600)
    print("Private production settings loaded (values hidden)")


if __name__ == "__main__":
    main()
