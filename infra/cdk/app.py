import os
import json
from pathlib import Path
from aws_cdk import (
    App,
    Stack,
    Duration,
    RemovalPolicy,
    CfnOutput,
    aws_dynamodb as ddb,
    aws_s3 as s3,
    aws_sqs as sqs,
    aws_lambda as fn,
    aws_lambda_event_sources as sources,
    aws_events as events,
    aws_events_targets as targets,
    aws_apigateway as api,
    aws_logs as logs,
    aws_iam as iam,
)
from constructs import Construct
from security_infra.production import FoundationStack


class SecurityStack(Stack):
    def __init__(self, scope: Construct, id: str, *, foundation=None, **kwargs):
        super().__init__(scope, id, **kwargs)
        local = self.node.try_get_context("stage") == "local"
        if foundation:
            table, bucket = foundation.table, foundation.reports
            dead, queue = foundation.dead, foundation.queue
        else:
            table = ddb.Table(
                self,
                "Data",
                table_name="security-testing" if local else None,
                partition_key=ddb.Attribute(name="pk", type=ddb.AttributeType.STRING),
                sort_key=ddb.Attribute(name="sk", type=ddb.AttributeType.STRING),
                billing_mode=ddb.BillingMode.PAY_PER_REQUEST,
                stream=ddb.StreamViewType.NEW_IMAGE,
                time_to_live_attribute="ttl",
                point_in_time_recovery_specification=ddb.PointInTimeRecoverySpecification(
                    point_in_time_recovery_enabled=True
                ),
                removal_policy=RemovalPolicy.RETAIN,
            )
            table.add_global_secondary_index(
                index_name="work",
                partition_key=ddb.Attribute(name="work_pk", type=ddb.AttributeType.STRING),
                sort_key=ddb.Attribute(name="work_sk", type=ddb.AttributeType.STRING),
            )
            bucket = s3.Bucket(
                self,
                "Reports",
                bucket_name="security-testing-reports" if local else None,
                encryption=s3.BucketEncryption.S3_MANAGED,
                block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                enforce_ssl=not local,
                removal_policy=RemovalPolicy.RETAIN,
                lifecycle_rules=[s3.LifecycleRule(expiration=Duration.days(30))],
            )
            dead = sqs.Queue(self, "Dead", retention_period=Duration.days(14), enforce_ssl=not local)
            queue = sqs.Queue(
                self,
                "Queue",
                visibility_timeout=Duration.seconds(360),
                dead_letter_queue=sqs.DeadLetterQueue(queue=dead, max_receive_count=5),
                enforce_ssl=not local,
            )
        issuer = "http://localhost:8080/realms/security-testing"
        client_id = "security-testing-web"
        if foundation:
            issuer = foundation.issuer
            client_id = foundation.client.user_pool_client_id
        env = {
            "APP_ENV": "local" if local else "production",
            "TABLE_NAME": table.table_name,
            "REPORT_BUCKET": bucket.bucket_name,
            "QUEUE_URL": queue.queue_url,
            "OIDC_ISSUER": issuer,
            "OIDC_CLIENT_ID": client_id,
            "CORS_ORIGIN": "http://localhost:5173" if local else "https://" + config["domain"],
        }
        if foundation:
            env["OIDC_REQUIRED_GROUP"] = "security-testing-users"
            env["OIDC_REQUIRED_SCOPE"] = "aws.cognito.signin.user.admin"
        if local:
            env.update(
                AWS_ENDPOINT_URL="http://localstack:4566",
                OIDC_JWKS_URL="http://identity:8080/realms/security-testing/protocol/openid-connect/certs",
            )
        code = fn.Code.from_asset(".build/lambda")

        def function(name, handler, timeout=30, concurrency=2):
            f = fn.Function(
                self,
                name,
                runtime=fn.Runtime.PYTHON_3_13,
                handler=handler,
                code=code,
                timeout=Duration.seconds(timeout),
                memory_size=512,
                environment=env,
                reserved_concurrent_executions=concurrency,
                log_group=logs.LogGroup(self, name + "Logs", retention=logs.RetentionDays.ONE_MONTH),
            )
            f.metric_errors().create_alarm(self, name + "Errors", threshold=1, evaluation_periods=1)
            return f

        http = function("Api", "site_diagnostics.adapters.inbound.api.handler")
        worker = function("Worker", "site_diagnostics.adapters.inbound.jobs.worker", 60, 2)
        http.add_environment("AUDIT_WORKER_ROLE_ARN", worker.role.role_arn)
        worker.add_to_role_policy(
            iam.PolicyStatement(
                actions=["sts:AssumeRole"],
                resources=[f"arn:{self.partition}:iam::*:role/security-testing-audit-*"],
            )
        )
        dispatcher = function("Dispatcher", "site_diagnostics.adapters.inbound.jobs.dispatch")
        recovery = function("Recovery", "site_diagnostics.adapters.inbound.jobs.recovery")
        for consumer in (http, worker, dispatcher, recovery):
            consumer.add_to_role_policy(
                iam.PolicyStatement(actions=["dynamodb:GetItem"], resources=[table.table_arn])
            )
            consumer.add_to_role_policy(
                iam.PolicyStatement(
                    actions=["dynamodb:Query"], resources=[table.table_arn, table.table_arn + "/index/work"]
                )
            )
            consumer.add_to_role_policy(
                iam.PolicyStatement(
                    actions=["dynamodb:PutItem"],
                    resources=[table.table_arn],
                    conditions={
                        "ForAnyValue:StringEquals": {"dynamodb:EnclosingOperation": ["TransactWriteItems"]}
                    },
                )
            )
        bucket.grant_read(http)
        bucket.grant_put(worker)
        queue.grant_send_messages(dispatcher)
        queue.grant_send_messages(recovery)
        worker.add_event_source(
            sources.SqsEventSource(queue, batch_size=1, report_batch_item_failures=True, max_concurrency=2)
        )
        dispatcher.add_event_source(
            sources.DynamoEventSource(
                table,
                starting_position=fn.StartingPosition.TRIM_HORIZON,
                batch_size=10,
                retry_attempts=3,
                bisect_batch_on_error=True,
                filters=[
                    fn.FilterCriteria.filter(
                        {"eventName": ["INSERT"], "dynamodb": {"NewImage": {"work_pk": {"S": ["OUTBOX"]}}}}
                    )
                ],
            )
        )
        events.Rule(
            self,
            "RecoveryTimer",
            schedule=events.Schedule.rate(Duration.minutes(2)),
            targets=[targets.LambdaFunction(recovery)],
        )
        gateway = api.LambdaRestApi(
            self,
            "Http",
            handler=http,
            proxy=True,
            binary_media_types=["application/pdf"],
            cloud_watch_role=local,
            default_cors_preflight_options=api.CorsOptions(
                allow_origins=[env["CORS_ORIGIN"]],
                allow_headers=["Authorization", "Content-Type", "Idempotency-Key"],
                allow_methods=api.Cors.ALL_METHODS,
            ),
            deploy_options=api.StageOptions(
                stage_name="local" if local else "v1", throttling_rate_limit=10, throttling_burst_limit=20
            ),
        )
        dead.metric_approximate_number_of_messages_visible().create_alarm(
            self, "DeadMessages", threshold=1, evaluation_periods=1
        )
        queue.metric_approximate_age_of_oldest_message().create_alarm(
            self, "QueueAge", threshold=600, evaluation_periods=1
        )
        CfnOutput(self, "ApiUrl", value=gateway.url)
        CfnOutput(self, "QueueUrl", value=queue.queue_url)
        CfnOutput(self, "TableName", value=table.table_name)
        CfnOutput(self, "ReportBucket", value=bucket.bucket_name)
        CfnOutput(self, "Issuer", value=issuer)
        CfnOutput(self, "ClientId", value=client_id)


app = App()
if app.node.try_get_context("stage") == "local":
    SecurityStack(app, "SecurityTesting", env={"account": "000000000000", "region": "ap-northeast-1"})
else:
    config_path = Path(os.environ.get("PRODUCTION_CONFIG_FILE", "infra/cdk/production.json"))
    if not config_path.exists():
        config_path = Path("infra/cdk/production.example.json")
    config = json.loads(config_path.read_text())
    foundation = FoundationStack(
        app,
        "SecurityTestingFoundation",
        config=config,
        env={"account": config["account"], "region": config["region"]},
        termination_protection=True,
    )
    SecurityStack(
        app,
        "SecurityTestingApplication",
        foundation=foundation,
        env={"account": config["account"], "region": config["region"]},
    )
app.synth()
