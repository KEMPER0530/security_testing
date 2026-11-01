import json
import logging
from site_diagnostics.bootstrap.container import service


def worker(event, context):
    failures = []
    for record in event.get("Records", []):
        try:
            body = json.loads(record["body"])
            service().execute(body["owner"], body["job_id"])
        except Exception as exc:
            logging.getLogger(__name__).warning(
                json.dumps(
                    {
                        "message_id": record.get("messageId"),
                        "status": "failed",
                        "error_type": type(exc).__name__,
                    }
                )
            )
            failures.append({"itemIdentifier": record["messageId"]})
    return {"batchItemFailures": failures}


def dispatch(event, context):
    service().dispatch()


def recovery(event, context):
    service().recover()
