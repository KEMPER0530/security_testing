import json
from decimal import Decimal
from boto3.dynamodb.types import TypeSerializer, TypeDeserializer
from botocore.exceptions import ClientError
from site_diagnostics.domain.model import Conflict

SER, DES = TypeSerializer(), TypeDeserializer()


def encode(item):
    clean = json.loads(json.dumps(item), parse_float=Decimal)
    return {k: SER.serialize(v) for k, v in clean.items()}


def decode(item):
    def numbers(value):
        if isinstance(value, Decimal):
            return int(value) if value % 1 == 0 else float(value)
        if isinstance(value, dict):
            return {k: numbers(v) for k, v in value.items()}
        if isinstance(value, list):
            return [numbers(v) for v in value]
        return value

    return numbers({k: DES.deserialize(v) for k, v in item.items()})


class DynamoStore:
    def __init__(self, client, table):
        self.client, self.table = client, table

    def get(self, owner, key):
        raw = self.client.get_item(
            TableName=self.table, Key=encode({"pk": owner, "sk": key}), ConsistentRead=True
        )
        return decode(raw["Item"]) if "Item" in raw else None

    def query(self, owner, prefix):
        return self._query(
            KeyConditionExpression="pk = :pk AND begins_with(sk, :sk)",
            ExpressionAttributeValues=encode({":pk": owner, ":sk": prefix}),
            ConsistentRead=True,
        )

    def work(self, state):
        return self._query(
            IndexName="work",
            KeyConditionExpression="work_pk = :pk",
            ExpressionAttributeValues=encode({":pk": state}),
        )

    def _query(self, **kwargs):
        items: list[dict] = []
        while True:
            result = self.client.query(TableName=self.table, **kwargs)
            items.extend(decode(i) for i in result["Items"])
            if "LastEvaluatedKey" not in result:
                return items
            kwargs["ExclusiveStartKey"] = result["LastEvaluatedKey"]

    def commit(self, changes):
        operations = []
        for item in changes:
            rev = item.get("rev", 0)
            write = {**item, "rev": rev + 1}
            put = {
                "TableName": self.table,
                "Item": encode(write),
                "ConditionExpression": "#rev = :rev" if rev else "attribute_not_exists(pk)",
                **(
                    {
                        "ExpressionAttributeNames": {"#rev": "rev"},
                        "ExpressionAttributeValues": encode({":rev": rev}),
                    }
                    if rev
                    else {}
                ),
            }
            operations.append({"Put": put})
        try:
            self.client.transact_write_items(TransactItems=operations)
        except ClientError as exc:
            if exc.response["Error"]["Code"] in (
                "TransactionCanceledException",
                "ConditionalCheckFailedException",
            ):
                raise Conflict("競合しました。再取得して再実行してください") from exc
            raise
        for item in changes:
            item["rev"] = item.get("rev", 0) + 1


class SqsPublisher:
    def __init__(self, client, url):
        self.client, self.url = client, url

    def send(self, owner, job_id):
        self.client.send_message(
            QueueUrl=self.url, MessageBody=json.dumps({"owner": owner, "job_id": job_id})
        )


class S3Reports:
    def __init__(self, client, bucket):
        self.client, self.bucket = client, bucket

    def key(self, owner, job_id):
        import hashlib

        return f"{hashlib.sha256(owner.encode()).hexdigest()}/{job_id}.json"

    def put(self, owner, job_id, report):
        self.client.put_object(
            Bucket=self.bucket,
            Key=self.key(owner, job_id),
            Body=json.dumps(report, ensure_ascii=False).encode(),
            ContentType="application/json",
            ServerSideEncryption="AES256",
        )

    def get(self, owner, job_id):
        response = self.client.get_object(Bucket=self.bucket, Key=self.key(owner, job_id))
        return json.loads(response["Body"].read())
