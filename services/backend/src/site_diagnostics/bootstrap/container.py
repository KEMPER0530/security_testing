import os
import time
from functools import lru_cache
from urllib.parse import urlsplit
import boto3
from site_diagnostics.application.service import Service
from site_diagnostics.adapters.outbound.aws import DynamoStore, SqsPublisher, S3Reports
from site_diagnostics.adapters.outbound.web import SafeFetcher
from site_diagnostics.adapters.outbound.cvss import CvssCalculator
from site_diagnostics.adapters.outbound.pdf import ReportPdf


@lru_cache
def service():
    env = os.environ.get("APP_ENV", "production")
    endpoint = os.environ.get("AWS_ENDPOINT_URL")
    if env == "local":
        if not endpoint or urlsplit(endpoint).hostname not in {
            "localhost",
            "localstack",
            "localhost.localstack.cloud",
        }:
            raise RuntimeError("Local mode requires an explicit LocalStack endpoint")
    elif endpoint or any(key.startswith("FIXTURE_") for key in os.environ):
        raise RuntimeError("Production forbids local endpoints and fixture settings")
    kwargs = {"region_name": os.environ.get("AWS_DEFAULT_REGION", "ap-northeast-1")}
    if endpoint:
        kwargs["endpoint_url"] = endpoint
        kwargs.update(aws_access_key_id="test", aws_secret_access_key="test")
    fixture_host = "fixture.security-testing.test" if env == "local" else None
    fixture_ip = "172.30.0.10" if env == "local" else None
    return Service(
        DynamoStore(boto3.client("dynamodb", **kwargs), os.environ["TABLE_NAME"]),
        SafeFetcher(fixture_ip, fixture_host),
        SqsPublisher(boto3.client("sqs", **kwargs), os.environ["QUEUE_URL"]),
        S3Reports(boto3.client("s3", **kwargs), os.environ["REPORT_BUCKET"]),
        time.time,
        CvssCalculator(),
        ReportPdf(),
    )
