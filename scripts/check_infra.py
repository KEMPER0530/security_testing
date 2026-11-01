"""Check the actual synthesized contract, including DynamoDB transaction authorization."""

import json
from pathlib import Path

template = json.loads(Path("cdk.out/SecurityTesting.template.json").read_text())
resources = template["Resources"]
assert any(r["Type"] == "AWS::ApiGateway::RestApi" for r in resources.values())
for r in resources.values():
    if r["Type"] == "AWS::ApiGateway::RestApi":
        assert "application/pdf" in r["Properties"]["BinaryMediaTypes"]
assert not any(r["Type"].startswith("AWS::ApiGatewayV2::") for r in resources.values())
policies = [r["Properties"]["PolicyDocument"] for r in resources.values() if r["Type"] == "AWS::IAM::Policy"]
assert "dynamodb:TransactWriteItems" not in json.dumps(policies)
assert "dynamodb:EnclosingOperation" in json.dumps(policies)
assert "dynamodb:PutItem" in json.dumps(policies)
print("REST API and DynamoDB transactional IAM contract verified")
