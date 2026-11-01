"""Sync non-secret production identifiers to the GitHub production Environment."""

import argparse
import os
import json
from pathlib import Path
import subprocess

import boto3


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", default="default")
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY"))
    args = parser.parse_args()
    config = json.loads(Path("infra/cdk/production.json").read_text())
    session = boto3.Session(profile_name=args.profile, region_name=config["region"])
    assert session.client("sts").get_caller_identity()["Account"] == config["account"]
    cf = session.client("cloudformation")

    def outputs(name):
        return {
            r["OutputKey"]: r["OutputValue"]
            for r in cf.describe_stacks(StackName=name)["Stacks"][0]["Outputs"]
        }

    foundation = outputs("SecurityTestingFoundation")
    app = outputs("SecurityTestingApplication")
    repo = (
        args.repo
        or subprocess.run(
            ["gh", "repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"],
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip()
    )
    oidc_result = subprocess.run(
        ["gh", "api", f"repos/{repo}/actions/oidc/customization/sub"],
        text=True,
        capture_output=True,
        check=True,
    )
    actual_prefix = json.loads(oidc_result.stdout).get("sub_claim_prefix")
    if actual_prefix != config["github_oidc_subject_prefix"]:
        raise SystemExit("GitHub OIDC subject prefix differs from production.json; update CDK trust first")
    endpoint = f"repos/{repo}/environments/production"
    subprocess.run(
        ["gh", "api", "--method", "PUT", endpoint, "--input", "-"],
        input=json.dumps(
            {"deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True}}
        ),
        text=True,
        capture_output=True,
        check=True,
    )
    result = subprocess.run(
        ["gh", "api", endpoint + "/deployment-branch-policies"], text=True, capture_output=True, check=True
    )
    policies = json.loads(result.stdout)["branch_policies"]
    if not any(p["name"] == "main" and p["type"] == "branch" for p in policies):
        subprocess.run(
            [
                "gh",
                "api",
                "--method",
                "POST",
                endpoint + "/deployment-branch-policies",
                "-f",
                "name=main",
                "-f",
                "type=branch",
            ],
            capture_output=True,
            check=True,
        )
    values = {
        "PRODUCTION_CONFIG_JSON": json.dumps(config),
        "AWS_REGION": config["region"],
        "AWS_ACCOUNT_ID": config["account"],
        "AWS_ROLE_ARN": foundation["GitHubRoleArn"],
        "APP_DOMAIN": config["domain"],
        "HOSTED_ZONE_ID": config["hosted_zone_id"],
        "CERTIFICATE_ARN": config["certificate_arn"],
        "FOUNDATION_STACK": "SecurityTestingFoundation",
        "APPLICATION_STACK": "SecurityTestingApplication",
        "COGNITO_USER_POOL_ID": foundation["UserPoolId"],
        "VITE_API_URL": app["ApiUrl"],
        "VITE_OIDC_ISSUER": foundation["Issuer"],
        "VITE_OIDC_CLIENT_ID": foundation["ClientId"],
        "VITE_OIDC_DOMAIN": foundation["LoginUrl"],
        "WEB_BUCKET": foundation["WebBucket"],
        "CLOUDFRONT_DISTRIBUTION_ID": foundation["DistributionId"],
    }
    values.update({f"PRODUCTION_{key.upper()}": value for key, value in config.items()})
    values.update({f"FOUNDATION_{key.upper()}": value for key, value in foundation.items()})
    values.update({f"APPLICATION_{key.upper()}": value for key, value in app.items()})
    for name, value in values.items():
        subprocess.run(
            ["gh", "secret", "set", name, "--repo", repo, "--env", "production", "--body", value],
            check=True,
        )
        print("Configured production secret:", name)
    subprocess.run(
        ["gh", "variable", "set", "PRODUCTION_DEPLOY_ENABLED", "--repo", repo, "--body", "true"], check=True
    )
    print("Production delivery enabled after private settings were stored")


if __name__ == "__main__":
    main()
