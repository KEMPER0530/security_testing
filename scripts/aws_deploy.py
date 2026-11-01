"""Initial foundation creation or application-only releases to the configured AWS account."""

import argparse
import json
import mimetypes
import os
from pathlib import Path
import subprocess
import uuid

import boto3
from botocore.exceptions import ClientError


def run(command, env):
    subprocess.run(command, check=True, env=env)


def outputs(cf, name):
    stack = cf.describe_stacks(StackName=name)["Stacks"][0]
    mask_identifiers([stack.get("StackId", "")])
    return {row["OutputKey"]: row["OutputValue"] for row in stack.get("Outputs", [])}


def mask_existing_stacks(cf):
    # The deployment role can describe Foundation outputs, but cannot list its resources.
    for stack in ("SecurityTestingFoundation", "SecurityTestingApplication"):
        mask_identifiers(outputs(cf, stack).values())


def mask_identifiers(values):
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return
    for value in values:
        text = str(value)
        if len(text) < 8:
            continue
        text = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print("::add-mask::" + text, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--initial", action="store_true")
    parser.add_argument("--profile")
    args = parser.parse_args()
    config = json.loads(Path("infra/cdk/production.json").read_text())
    mask_identifiers(config.values())
    env = dict(os.environ)
    env["PRODUCTION_CONFIG_FILE"] = "infra/cdk/production.json"
    if env.get("APP_DOMAIN", config["domain"]) != config["domain"]:
        raise SystemExit("APP_DOMAIN does not match the CDK production configuration")
    if args.profile:
        for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
            env.pop(name, None)
        env["AWS_PROFILE"] = args.profile
    # A local endpoint must never silently redirect a production release.
    if any(k.startswith("AWS_ENDPOINT_URL") and v for k, v in env.items()):
        raise SystemExit("Unset local AWS_ENDPOINT_URL settings before an AWS deployment")
    env["AWS_REGION"] = env["AWS_DEFAULT_REGION"] = config["region"]
    session = boto3.Session(profile_name=args.profile, region_name=config["region"])
    account = session.client("sts").get_caller_identity()["Account"]
    if account != config["account"]:
        raise SystemExit("The selected AWS account does not match production.json")
    cf = session.client("cloudformation")
    if not args.initial:
        mask_existing_stacks(cf)
    if args.initial:
        try:
            cf.describe_stacks(StackName="CDKToolkit")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ValidationError":
                raise
            run(["pnpm", "exec", "cdk", "bootstrap", f"aws://{account}/{config['region']}"], env)
    run(["make", "package"], env)
    cdk = ["pnpm", "exec", "cdk", "--output", ".build/cdk-production", "-c", "stage=production"]
    run(cdk + ["synth", "--quiet"], env)
    if args.initial:
        run(
            cdk + ["deploy", "SecurityTestingFoundation", "--exclusively", "--require-approval", "never"], env
        )
    run(cdk + ["deploy", "SecurityTestingApplication", "--exclusively", "--require-approval", "never"], env)
    foundation = outputs(cf, "SecurityTestingFoundation")
    app = outputs(cf, "SecurityTestingApplication")
    env.update(
        VITE_API_URL=app["ApiUrl"],
        VITE_OIDC_ISSUER=foundation["Issuer"],
        VITE_OIDC_CLIENT_ID=foundation["ClientId"],
        VITE_OIDC_DOMAIN=foundation["LoginUrl"],
    )
    run(["pnpm", "build"], env)
    run([".venv/bin/python", "scripts/check_production.py"], env)
    s3 = session.client("s3")
    dist = Path("apps/web/dist")
    paths = sorted(p for p in dist.rglob("*") if p.is_file())
    # Publish hashed assets before the entry point; retain old assets for in-flight sessions/rollback.
    paths.sort(key=lambda p: p.name == "index.html")
    for path in paths:
        key = path.relative_to(dist).as_posix()
        cache = "public,max-age=31536000,immutable" if key.startswith("assets/") else "no-cache,max-age=0"
        s3.upload_file(
            str(path),
            foundation["WebBucket"],
            key,
            ExtraArgs={
                "ContentType": mimetypes.guess_type(path.name)[0] or "application/octet-stream",
                "CacheControl": cache,
            },
        )
    cloudfront = session.client("cloudfront")
    invalidation = cloudfront.create_invalidation(
        DistributionId=foundation["DistributionId"],
        InvalidationBatch={"Paths": {"Quantity": 1, "Items": ["/*"]}, "CallerReference": str(uuid.uuid4())},
    )
    cloudfront.get_waiter("invalidation_completed").wait(
        DistributionId=foundation["DistributionId"], Id=invalidation["Invalidation"]["Id"]
    )
    Path(".build/production-outputs.json").write_text(json.dumps({**foundation, **app}, indent=2) + "\n")
    print("Application deployed:", foundation["WebUrl"])


if __name__ == "__main__":
    main()
