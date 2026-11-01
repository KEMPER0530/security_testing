import boto3
import pytest
from moto import mock_aws
from site_diagnostics.adapters.outbound.aws import DynamoStore, SqsPublisher, S3Reports
from site_diagnostics.application.service import Service
from site_diagnostics.domain.model import Observation
from site_diagnostics.adapters.outbound.cvss import CvssCalculator
from site_diagnostics.adapters.outbound.pdf import ReportPdf


class FakeFetcher:
    def __init__(self):
        self.html = "<html><h1>controlled</h1></html>"
        self.headers = {}
        self.hook = None

    def fetch(self, scope):
        if self.hook:
            self.hook()
        return Observation(scope.url, self.headers, [], self.html, {"valid": True})


@pytest.fixture
def environment(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    with mock_aws():
        client = boto3.client("dynamodb", region_name="us-east-1")
        client.create_table(
            TableName="test",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": n, "AttributeType": "S"} for n in ("pk", "sk", "work_pk", "work_sk")
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "work",
                    "KeySchema": [
                        {"AttributeName": "work_pk", "KeyType": "HASH"},
                        {"AttributeName": "work_sk", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                }
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        sqs = boto3.client("sqs", region_name="us-east-1")
        url = sqs.create_queue(QueueName="test")["QueueUrl"]
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="reports-test")
        clock = [1000.0]
        fetcher = FakeFetcher()
        service = Service(
            DynamoStore(client, "test"),
            fetcher,
            SqsPublisher(sqs, url),
            S3Reports(s3, "reports-test"),
            lambda: clock[0],
            CvssCalculator(),
            ReportPdf(),
        )
        yield service, fetcher, clock, sqs, url


@pytest.fixture
def ready(environment):
    service, fetcher, clock, *_ = environment
    target = service.register("alice", "https://example.com/")
    target_id = target["sk"].split("#")[1]
    fetcher.html = "<html>controlled</html>"
    return service, target_id, fetcher, clock
