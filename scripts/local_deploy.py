"""Only deploys synthesized assets and CloudFormation to explicit loopback LocalStack."""

import json
import os
import zipfile
from pathlib import Path
import boto3

os.environ.update(
    AWS_ACCESS_KEY_ID="test",
    AWS_SECRET_ACCESS_KEY="test",
    AWS_DEFAULT_REGION="ap-northeast-1",
    AWS_EC2_METADATA_DISABLED="true",
)
endpoint = "http://localhost:4566"


def client(name):
    return boto3.client(name, endpoint_url=endpoint, region_name="ap-northeast-1")


s3 = client("s3")
cf = client("cloudformation")
region = "ap-northeast-1"
bucket = "security-testing-local-assets"
try:
    s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
except s3.exceptions.BucketAlreadyOwnedByYou:
    pass
manifest = json.loads(Path("cdk.out/SecurityTesting.assets.json").read_text())
for asset in manifest["files"].values():
    source = Path("cdk.out") / asset["source"]["path"]
    if source.is_dir():
        archive = Path(".build") / (source.name + ".zip")
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as z:
            for path in source.rglob("*"):
                if path.is_file():
                    z.write(path, path.relative_to(source))
    else:
        archive = source
    for dest in asset["destinations"].values():
        try:
            s3.create_bucket(
                Bucket=dest["bucketName"], CreateBucketConfiguration={"LocationConstraint": region}
            )
        except s3.exceptions.BucketAlreadyOwnedByYou:
            pass
        s3.upload_file(str(archive), dest["bucketName"], dest["objectKey"])
template = json.loads(Path("cdk.out/SecurityTesting.template.json").read_text())
# Local deployment does not use a real CDK bootstrap SSM parameter.
template.get("Parameters", {}).pop("BootstrapVersion", None)
template.pop("Rules", None)
template = json.dumps(template)
operation = "stack_create_complete"
try:
    cf.create_stack(StackName="SecurityTesting", TemplateBody=template, Capabilities=["CAPABILITY_IAM"])
except cf.exceptions.AlreadyExistsException:
    operation = "stack_update_complete"
    try:
        cf.update_stack(StackName="SecurityTesting", TemplateBody=template, Capabilities=["CAPABILITY_IAM"])
    except cf.exceptions.ClientError as exc:
        if "No updates" not in exc.response.get("Error", {}).get("Message", ""):
            raise
        operation = None
if operation:
    print("Stack submitted; waiting for LocalStack resources.")
    cf.get_waiter(operation).wait(StackName="SecurityTesting", WaiterConfig={"Delay": 5, "MaxAttempts": 120})
else:
    print("Stack already up to date.")
outputs = {
    item["OutputKey"]: item["OutputValue"]
    for item in cf.describe_stacks(StackName="SecurityTesting")["Stacks"][0]["Outputs"]
}
resources = cf.list_stack_resources(StackName="SecurityTesting")["StackResourceSummaries"]
api_id = next(r["PhysicalResourceId"] for r in resources if r["ResourceType"] == "AWS::ApiGateway::RestApi")
if not api_id or api_id == "unknown":
    raise RuntimeError("API Gateway was not provisioned; check LocalStack license and stack events")
client("apigateway").get_rest_api(restApiId=api_id)
api_url = f"http://localhost:4566/_aws/execute-api/{api_id}/local"
path = Path(".env")
values = {
    "VITE_API_URL": api_url,
    "QUEUE_URL": outputs["QueueUrl"],
    "TABLE_NAME": outputs["TableName"],
    "REPORT_BUCKET": outputs["ReportBucket"],
}
lines = path.read_text().splitlines()
for key, value in values.items():
    lines = [line for line in lines if not line.startswith(key + "=")]
    lines.append(key + "=" + value)
path.write_text("\n".join(lines) + "\n")
path.chmod(0o600)
print("LocalStack deployment completed; local API and queue configured in .env (credentials hidden).")
