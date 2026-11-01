"""Persistent AWS resources. Routine releases only deploy ApplicationStack."""

from aws_cdk import (
    CfnOutput,
    Duration,
    RemovalPolicy,
    Stack,
    aws_certificatemanager as acm,
    aws_cloudfront as cloudfront,
    aws_cloudfront_origins as origins,
    aws_cognito as cognito,
    aws_dynamodb as ddb,
    aws_iam as iam,
    aws_route53 as route53,
    aws_route53_targets as dns_targets,
    aws_s3 as s3,
    aws_sqs as sqs,
)
from constructs import Construct


class FoundationStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, *, config: dict, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        self.table = ddb.Table(
            self,
            "Data",
            partition_key=ddb.Attribute(name="pk", type=ddb.AttributeType.STRING),
            sort_key=ddb.Attribute(name="sk", type=ddb.AttributeType.STRING),
            billing_mode=ddb.BillingMode.PAY_PER_REQUEST,
            stream=ddb.StreamViewType.NEW_IMAGE,
            time_to_live_attribute="ttl",
            deletion_protection=True,
            point_in_time_recovery_specification=ddb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled=True
            ),
            removal_policy=RemovalPolicy.RETAIN,
        )
        self.table.add_global_secondary_index(
            index_name="work",
            partition_key=ddb.Attribute(name="work_pk", type=ddb.AttributeType.STRING),
            sort_key=ddb.Attribute(name="work_sk", type=ddb.AttributeType.STRING),
        )
        self.reports = s3.Bucket(
            self,
            "Reports",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            versioned=True,
            removal_policy=RemovalPolicy.RETAIN,
            lifecycle_rules=[
                s3.LifecycleRule(
                    expiration=Duration.days(30), noncurrent_version_expiration=Duration.days(30)
                )
            ],
        )
        self.dead = sqs.Queue(
            self,
            "Dead",
            retention_period=Duration.days(14),
            enforce_ssl=True,
            encryption=sqs.QueueEncryption.SQS_MANAGED,
        )
        self.queue = sqs.Queue(
            self,
            "Queue",
            encryption=sqs.QueueEncryption.SQS_MANAGED,
            visibility_timeout=Duration.seconds(360),
            enforce_ssl=True,
            dead_letter_queue=sqs.DeadLetterQueue(queue=self.dead, max_receive_count=5),
        )
        # Reuse the existing directory; this stack owns only this application's client/domain/group.
        pool = cognito.UserPool.from_user_pool_id(self, "ExistingUsers", config["user_pool_id"])
        self.group = cognito.CfnUserPoolGroup(
            self,
            "ApplicationUsers",
            user_pool_id=pool.user_pool_id,
            group_name="security-testing-users",
            description="Users permitted to access Security Testing",
        )
        domain = cognito.UserPoolDomain(
            self,
            "LoginDomain",
            user_pool=pool,
            cognito_domain=cognito.CognitoDomainOptions(domain_prefix=f"security-testing-{self.account}"),
        )
        self.client = cognito.UserPoolClient(
            self,
            "WebClient",
            user_pool=pool,
            generate_secret=False,
            auth_flows=cognito.AuthFlow(user_srp=True),
            prevent_user_existence_errors=True,
            enable_token_revocation=True,
            access_token_validity=Duration.minutes(30),
            id_token_validity=Duration.minutes(30),
            refresh_token_validity=Duration.days(1),
            supported_identity_providers=[cognito.UserPoolClientIdentityProvider.COGNITO],
            o_auth=cognito.OAuthSettings(
                flows=cognito.OAuthFlows(authorization_code_grant=True),
                scopes=[cognito.OAuthScope.OPENID, cognito.OAuthScope.PROFILE],
                callback_urls=[f"https://{config['domain']}/callback"],
                logout_urls=[f"https://{config['domain']}"],
            ),
        )
        self.issuer = f"https://cognito-idp.{self.region}.{self.url_suffix}/{pool.user_pool_id}"
        self.login_url = domain.base_url()
        self.assets = s3.Bucket(
            self,
            "WebAssets",
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            versioned=True,
            removal_policy=RemovalPolicy.RETAIN,
            lifecycle_rules=[s3.LifecycleRule(noncurrent_version_expiration=Duration.days(30))],
        )
        self.distribution = cloudfront.Distribution(
            self,
            "Web",
            domain_names=[config["domain"]],
            certificate=acm.Certificate.from_certificate_arn(self, "Certificate", config["certificate_arn"]),
            default_root_object="index.html",
            minimum_protocol_version=cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021,
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.S3BucketOrigin.with_origin_access_control(self.assets),
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                response_headers_policy=cloudfront.ResponseHeadersPolicy.SECURITY_HEADERS,
                cache_policy=cloudfront.CachePolicy.CACHING_OPTIMIZED,
                compress=True,
            ),
            error_responses=[
                cloudfront.ErrorResponse(
                    http_status=status,
                    response_http_status=200,
                    response_page_path="/index.html",
                    ttl=Duration.seconds(0),
                )
                for status in (403, 404)
            ],
        )
        zone = route53.HostedZone.from_hosted_zone_attributes(
            self, "Zone", hosted_zone_id=config["hosted_zone_id"], zone_name=config["zone_name"]
        )
        for record in (route53.ARecord, route53.AaaaRecord):
            record(
                self,
                record.__name__,
                zone=zone,
                record_name=config["domain"],
                target=route53.RecordTarget.from_alias(dns_targets.CloudFrontTarget(self.distribution)),
            )
        provider = iam.OpenIdConnectProvider.from_open_id_connect_provider_arn(
            self,
            "GitHubProvider",
            f"arn:aws:iam::{self.account}:oidc-provider/token.actions.githubusercontent.com",
        )
        deploy = iam.Role(
            self,
            "GitHubDeployRole",
            role_name="security-testing-github-production",
            assumed_by=iam.FederatedPrincipal(
                provider.open_id_connect_provider_arn,
                {
                    "StringEquals": {
                        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                        "token.actions.githubusercontent.com:sub": config["github_oidc_subject_prefix"]
                        + ":environment:production",
                    }
                },
                "sts:AssumeRoleWithWebIdentity",
            ),
            max_session_duration=Duration.hours(1),
        )
        deploy.add_to_policy(
            iam.PolicyStatement(
                actions=["sts:AssumeRole"],
                resources=[
                    f"arn:aws:iam::{self.account}:role/cdk-hnb659fds-{kind}-role-{self.account}-{self.region}"
                    for kind in ("deploy", "file-publishing", "lookup")
                ],
            )
        )
        deploy.add_to_policy(
            iam.PolicyStatement(
                actions=["cloudformation:DescribeStacks"],
                resources=[f"arn:aws:cloudformation:{self.region}:{self.account}:stack/SecurityTesting*/*"],
            )
        )
        deploy.add_to_policy(
            iam.PolicyStatement(
                actions=["ssm:GetParameter"],
                resources=[
                    f"arn:aws:ssm:{self.region}:{self.account}:parameter/cdk-bootstrap/hnb659fds/version"
                ],
            )
        )
        self.assets.grant_read_write(deploy)
        deploy.add_to_policy(
            iam.PolicyStatement(
                actions=["cloudfront:CreateInvalidation", "cloudfront:GetInvalidation"],
                resources=[self.distribution.distribution_arn],
            )
        )
        for name, value in {
            "WebUrl": f"https://{config['domain']}",
            "WebBucket": self.assets.bucket_name,
            "DistributionId": self.distribution.distribution_id,
            "Issuer": self.issuer,
            "ClientId": self.client.user_pool_client_id,
            "LoginUrl": self.login_url,
            "UserPoolId": pool.user_pool_id,
            "RequiredGroup": "security-testing-users",
            "GitHubRoleArn": deploy.role_arn,
        }.items():
            CfnOutput(self, name, value=value)
