"""Verify production resource ownership and the cross-stack deployment boundary."""

import os
import json
from pathlib import Path

base = Path(".build/cdk-production")
foundation = json.loads((base / "SecurityTestingFoundation.template.json").read_text())
application = json.loads((base / "SecurityTestingApplication.template.json").read_text())
fr = foundation["Resources"]
ar = application["Resources"]
assert not any(r["Type"] == "AWS::Cognito::UserPool" for r in fr.values()), "Reuse the existing directory"
assert any(r["Type"] == "AWS::Cognito::UserPoolClient" for r in fr.values())
for r in fr.values():
    if r["Type"] == "AWS::SQS::Queue":
        assert r["Properties"].get("SqsManagedSseEnabled") is True, (
            "Every SQS queue must explicitly enable SSE-SQS"
        )
    if r["Type"] in ("AWS::DynamoDB::Table", "AWS::S3::Bucket"):
        assert r["DeletionPolicy"] == "Retain"
    if r["Type"] == "AWS::DynamoDB::Table":
        assert r["Properties"]["DeletionProtectionEnabled"]
assert not any(
    r["Type"]
    in (
        "AWS::DynamoDB::Table",
        "AWS::S3::Bucket",
        "AWS::SQS::Queue",
        "AWS::Cognito::UserPool",
        "AWS::Cognito::UserPoolClient",
    )
    for r in ar.values()
)
assert any(r["Type"] == "AWS::ApiGateway::RestApi" for r in ar.values())
assert not any(r["Type"] == "AWS::ApiGateway::Account" for r in ar.values())
for r in ar.values():
    if r["Type"] == "AWS::ApiGateway::RestApi":
        assert "application/pdf" in r["Properties"]["BinaryMediaTypes"]
assume_policies = []
for name, resource in ar.items():
    if resource["Type"] == "AWS::IAM::Policy":
        for statement in resource["Properties"]["PolicyDocument"]["Statement"]:
            actions = statement["Action"]
            if "sts:AssumeRole" in ([actions] if isinstance(actions, str) else actions):
                assume_policies.append((name, statement))
assert len(assume_policies) == 1 and assume_policies[0][0].startswith("Worker")
assert "role/security-testing-audit-*" in json.dumps(assume_policies[0][1]["Resource"])
assert any(
    r["Type"] == "AWS::Lambda::Function"
    and "AUDIT_WORKER_ROLE_ARN" in r["Properties"]["Environment"]["Variables"]
    for r in ar.values()
)
config_path = Path(os.environ.get("PRODUCTION_CONFIG_FILE", "infra/cdk/production.json"))
if not config_path.exists():
    config_path = Path("infra/cdk/production.example.json")
config = json.loads(config_path.read_text())
assert config["github_oidc_subject_prefix"] + ":environment:production" in json.dumps(foundation)
for r in ar.values():
    if r["Type"] == "AWS::Lambda::Function":
        env = r["Properties"]["Environment"]["Variables"]
        assert env["APP_ENV"] == "production" and "AWS_ENDPOINT_URL" not in env
        assert env["OIDC_REQUIRED_GROUP"] == "security-testing-users"
        assert env["OIDC_REQUIRED_SCOPE"] == "aws.cognito.signin.user.admin"
assert "SecurityTestingApplication" not in json.dumps(foundation), "Foundation must not depend on application"
print("Production boundary, retained data, existing Cognito, OIDC trust and fixture exclusion verified")
