"""Read-only cross-account configuration and collected vulnerability evidence."""

import json
import re
import time
from datetime import datetime, timezone
import boto3
from cvss import CVSS3, CVSS4
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from site_diagnostics.domain.model import Rejected
from site_diagnostics.domain.plans import PROFILES, finding, role_arn

READ_ACTIONS = [
    "ssm:DescribeInstanceInformation",
    "ssm:ListInventoryEntries",
    "inspector2:ListFindings",
    "inspector2:ListCoverage",
    "iam:GetAccountSummary",
    "s3:GetBucketPublicAccessBlock",
    "s3:GetEncryptionConfiguration",
    "ec2:DescribeSecurityGroups",
    "cloudtrail:GetTrailStatus",
]
REFERENCE = "https://docs.aws.amazon.com/security/"
REFERENCES = {
    "root_mfa": "https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountSummary.html",
    "s3": "https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetPublicAccessBlock.html",
    "security_groups": "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSecurityGroups.html",
    "cloudtrail": "https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_GetTrailStatus.html",
    "inventory": "https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_ListInventoryEntries.html",
    "inspector": "https://docs.aws.amazon.com/inspector/v2/APIReference/API_ListFindings.html",
}
CONFIG = Config(connect_timeout=1, read_timeout=2, retries={"max_attempts": 0})
DENIED = {"AccessDenied", "AccessDeniedException"}
SEVERITIES = {"CRITICAL": "緊急", "HIGH": "高", "MEDIUM": "中", "LOW": "低", "INFORMATIONAL": "なし"}


class AwsAudit:
    def __init__(self, worker_role, endpoint=None, client_factory=None):
        self.worker_role, self.endpoint = worker_role, endpoint
        self.factory = client_factory or boto3.client

    def template(self, connection):
        if not self.worker_role:
            raise Rejected("AWS診断の実行ロールが未設定です。管理者によるアプリケーション更新が必要です")
        return {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": "Read-only Security Testing audit connection. No OS command or data-object access.",
            "Resources": {
                "AuditRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": "security-testing-audit-"
                        + connection["external_id"].removeprefix("security-testing-"),
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"AWS": self.worker_role},
                                    "Action": "sts:AssumeRole",
                                    "Condition": {
                                        "StringEquals": {"sts:ExternalId": connection["external_id"]}
                                    },
                                }
                            ],
                        },
                        "Policies": [
                            {
                                "PolicyName": "AuditReadOnly",
                                "PolicyDocument": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {"Effect": "Allow", "Action": READ_ACTIONS, "Resource": "*"}
                                    ],
                                },
                            }
                        ],
                    },
                }
            },
            "Outputs": {"RoleArn": {"Value": {"Fn::GetAtt": ["AuditRole", "Arn"]}}},
        }

    def client(self, service, region, credentials=None):
        args = {"region_name": region, "config": CONFIG}
        if self.endpoint:
            args.update(endpoint_url=self.endpoint, aws_access_key_id="test", aws_secret_access_key="test")
        if credentials:
            args.update(
                aws_access_key_id=credentials["AccessKeyId"],
                aws_secret_access_key=credentials["SecretAccessKey"],
                aws_session_token=credentials["SessionToken"],
            )
        return self.factory(service, **args)

    def credentials(self, plan, connection):
        role = role_arn(connection["role_arn"])
        sts = self.client("sts", plan["region"])
        args = {
            "RoleArn": role,
            "RoleSessionName": "security-testing-audit",
            "DurationSeconds": 900,
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Action": READ_ACTIONS, "Resource": "*"}],
                },
                separators=(",", ":"),
            ),
        }
        # Reject trust policies which would allow this service to act for another customer.
        for external in (None, "security-testing-invalid-external-id"):
            try:
                sts.assume_role(**args, **({"ExternalId": external} if external else {}))
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in DENIED:
                    raise Rejected("AWS接続の信頼条件を検証できませんでした") from exc
            else:
                raise Rejected("ロールの信頼ポリシーに、この接続専用ExternalIdを必須設定してください")
        return sts.assume_role(**args, ExternalId=connection["external_id"])["Credentials"]

    def run(self, plan, connection):
        if not connection or not connection.get("role_arn"):
            raise Rejected("この対象のAWS読み取り専用ロールを設定してください")
        deadline = time.monotonic() + 40
        try:
            credentials = self.credentials(plan, connection)
        except (BotoCoreError, ClientError) as exc:
            raise Rejected(
                "AWS接続に失敗しました。ロール・ExternalId・権限・リージョンを確認してください"
            ) from exc
        account = connection["role_arn"].split(":")[4]
        clients = {}

        def call(service, operation, **kwargs):
            if time.monotonic() >= deadline:
                raise Rejected("実行時間の上限に達したため確認できませんでした")
            if service not in clients:
                clients[service] = self.client(service, plan["region"], credentials)
            return getattr(clients[service], operation)(**kwargs)

        rows = []
        resources = plan["resources"]
        for check in plan["checks"]:
            values = resources.get(
                {
                    "inventory": "instances",
                    "inspector": "instances",
                    "s3": "buckets",
                    "security_groups": "security_groups",
                    "cloudtrail": "trails",
                }.get(check, ""),
                ["account"],
            )
            for index, resource in enumerate(values):
                try:
                    result = self.check(check, resource, account, plan["region"], call)
                    for row in result:
                        row["rule_id"] += f"_{index}"
                    rows.extend(result)
                except (ClientError, BotoCoreError, Rejected) as exc:
                    code = (
                        exc.response["Error"]["Code"] if isinstance(exc, ClientError) else type(exc).__name__
                    )
                    rows.append(
                        finding(
                            f"AWS_{check.upper()}_{index}",
                            f"{PROFILES[plan['profile']]['checks'][check]} / {resource}",
                            "確認不能",
                            f"取得未完了（{code}）。権限・対象・収集設定・通信を確認してください。",
                            "読み取り権限と対象リソース、サービスの有効化を管理者が確認する",
                            reference=REFERENCE,
                        )
                    )
        return {
            "findings": rows,
            "coverage": {
                "profile": plan["profile"],
                "scope": PROFILES[plan["profile"]]["scope"],
                "checks": plan["checks"],
                "resources": resources,
                "region": plan["region"],
                "not_tested": [
                    "未選択リソース",
                    "OSへの新規コマンド実行",
                    "アプリ内部の操作",
                    "侵入・権限昇格・横展開",
                    "SSM/Inspector未収集の情報",
                ],
            },
        }

    def check(self, check, resource, account, region, call):
        def row(suffix, title, state, evidence, fix, **kw):
            return finding(
                "AWS_" + suffix,
                title + " / " + resource,
                state,
                evidence,
                fix,
                reference=REFERENCES.get(check, REFERENCE),
                **kw,
            )

        if check == "root_mfa":
            summary = call("iam", "get_account_summary")["SummaryMap"]
            value = summary.get("AccountMFAEnabled")
            return [
                row(
                    "ROOT_MFA",
                    "ルート利用者の多要素認証",
                    "問題を検出" if value == 0 else "問題を検出せず" if value == 1 else "確認不能",
                    f"AccountMFAEnabled={value}。一般利用者やOrganizations配下の別アカウントは未確認です。",
                    "ルート利用者のMFAを設定する。ルート資格情報を集中管理している場合はその方針を確認する",
                    severity="高",
                    explanation="アカウント全体を管理できる利用者のログインを、パスワード以外の認証でも守る設定です。",
                    criteria="IAMアカウントサマリーのMFA有効フラグを確認します。",
                )
            ]
        if check == "s3":
            args = {"Bucket": resource, "ExpectedBucketOwner": account}
            result = []
            # Separate checks: one failed permission must not erase another observation.
            for operation, suffix in [
                ("get_public_access_block", "S3_PUBLIC"),
                ("get_bucket_encryption", "S3_ENCRYPTION"),
            ]:
                try:
                    data = call("s3", operation, **args)
                    if suffix == "S3_PUBLIC":
                        flags = data.get("PublicAccessBlockConfiguration", {})
                        names = (
                            "BlockPublicAcls",
                            "IgnorePublicAcls",
                            "BlockPublicPolicy",
                            "RestrictPublicBuckets",
                        )
                        ok = all(flags.get(k) is True for k in names)
                        evidence = (
                            ", ".join(f"{k}={flags.get(k, '不明')}" for k in names)
                            + "。バケット単位の防御設定のみ。実際の公開可否・アカウント/組織設定は未検証です。"
                        )
                        title, fix = "S3の公開防止", "公開用途を確認し、不要な公開をブロックする"
                    else:
                        algorithms = [
                            r.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm")
                            for r in data.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                        ]
                        ok = bool(algorithms) and all(
                            a in ("AES256", "aws:kms", "aws:kms:dsse") for a in algorithms
                        )
                        evidence = f"既定暗号化方式：{', '.join(str(a) for a in algorithms) or '取得なし'}。既存オブジェクトや鍵の利用権限は未検証です。"
                        title, fix = "S3の保存時暗号化", "既定暗号化を確認し、必要な鍵の管理方針を設定する"
                    result.append(
                        row(
                            suffix,
                            title,
                            "問題を検出せず"
                            if ok
                            else "問題を検出"
                            if suffix == "S3_PUBLIC" and all(k in flags for k in names)
                            else "確認不能",
                            evidence,
                            fix,
                            severity="中",
                            explanation="S3はファイルを保管するAWSの機能です。公開を防ぐ設定と保存時の暗号化設定を確認します。ファイルは読みません。",
                            criteria="選択バケットの設定だけを読み取ります。保存ファイルの内容は取得しません。",
                        )
                    )
                except (ClientError, BotoCoreError, Rejected):
                    result.append(
                        row(
                            suffix,
                            "S3設定の取得",
                            "確認不能",
                            "この設定は取得できませんでした。未設定や安全と断定しません。",
                            "権限・バケット所有者・設定を確認する",
                        )
                    )
            return result
        if check == "security_groups":
            data = call("ec2", "describe_security_groups", GroupIds=[resource])["SecurityGroups"]
            group = next(
                (g for g in data if g.get("GroupId") == resource and g.get("OwnerId") == account), None
            )
            if not group:
                raise Rejected("選択グループを取得できませんでした")
            dangerous = []
            for permission in group.get("IpPermissions", []):
                public = any(v.get("CidrIp") == "0.0.0.0/0" for v in permission.get("IpRanges", [])) or any(
                    v.get("CidrIpv6") == "::/0" for v in permission.get("Ipv6Ranges", [])
                )
                if public and (
                    permission.get("IpProtocol") == "-1"
                    or (
                        permission.get("IpProtocol") in ("tcp", "6")
                        and any(
                            permission.get("FromPort", 0) <= p <= permission.get("ToPort", 0)
                            for p in (22, 3389, 3306, 5432, 6379)
                        )
                    )
                ):
                    dangerous.append(
                        f"{permission.get('IpProtocol')}:{permission.get('FromPort', 'all')}-{permission.get('ToPort', 'all')}"
                    )
            return [
                row(
                    "SG_PUBLIC",
                    "管理・DBポートの全世界許可",
                    "問題を検出" if dangerous else "問題を検出せず",
                    "全世界に許可："
                    + (", ".join(dangerous) or "対象の管理・DBポートに該当なし")
                    + "。経路・実際の到達性・他の広い接続元範囲は未検証です。",
                    "管理・DB接続を必要な送信元に限定する",
                    severity="高",
                    explanation="サーバーの管理口やデータベースに、誰の通信を通すか決める設定です。",
                    criteria="IPv4/IPv6全世界宛の全プロトコル、またはTCP管理・DBポート許可を検査します。",
                )
            ]
        if check == "cloudtrail":
            if resource.split(":")[4] != account or resource.split(":")[3] != region:
                raise Rejected("接続アカウント・リージョンと異なる証跡です")
            data = call("cloudtrail", "get_trail_status", Name=resource)
            enabled = data.get("IsLogging")
            errors = any(
                data.get(k)
                for k in (
                    "LatestDeliveryError",
                    "LatestCloudWatchLogsDeliveryError",
                    "LatestDigestDeliveryError",
                )
            )
            state = (
                "問題を検出"
                if enabled is False or errors
                else "問題を検出せず"
                if enabled is True
                else "確認不能"
            )
            return [
                row(
                    "TRAIL",
                    "AWS操作記録",
                    state,
                    f"記録中={enabled}、配信エラーあり={errors}。記録対象イベントや全リージョン網羅、ログの中身は未確認です。",
                    "CloudTrailの記録と配信を有効にし、記録範囲も確認する",
                    severity="中",
                    explanation="誰がAWSを操作したか、後から調べるための記録です。",
                    criteria="選択した証跡の記録フラグと配信エラーを確認します。",
                )
            ]
        if check == "inventory":
            info = call(
                "ssm",
                "describe_instance_information",
                Filters=[{"Key": "InstanceIds", "Values": [resource]}],
                MaxResults=5,
            )
            item = next(
                (v for v in info.get("InstanceInformationList", []) if v.get("InstanceId") == resource), None
            )
            if not item:
                return [
                    row(
                        "INVENTORY",
                        "SSM収集状態",
                        "未実施",
                        "SSM管理情報がありません。OSやパッケージの安全性は未確認です。",
                        "対象をSSM管理対象にし、Inventory収集を設定する",
                    )
                ]
            inventory = call(
                "ssm",
                "list_inventory_entries",
                InstanceId=resource,
                TypeName="AWS:InstanceInformation",
                MaxResults=50,
            )
            capture = inventory.get("CaptureTime")
            fresh = fresh_time(capture)
            evidence = f"OS：{item.get('PlatformName', '不明')} {item.get('PlatformVersion', '')}。SSM接続：{item.get('PingStatus', '不明')}。Inventory収集：{capture or '記録なし'}。"
            ok = (
                fresh
                and bool(inventory.get("Entries"))
                and not inventory.get("NextToken")
                and item.get("PingStatus") == "Online"
            )
            return [
                row(
                    "INVENTORY",
                    "SSM収集状態",
                    "問題を検出せず" if ok else "確認不能",
                    evidence
                    + "7日以内の収集・接続状態のみの判定です。OSの既知脆弱性はInspector項目で確認します。",
                    "SSM接続・定期収集を確認し、情報を更新する",
                    explanation="AWSの管理機能が、サーバーのOSなどの情報を最近集められているか確認します。OSの安全性そのものの判定ではありません。",
                    criteria="選択EC2のSSM情報とInventory取得日時。ソフトウェアの新規検査やOS変更はしません。",
                )
            ]
        # Inspector's stored evidence. No scan-starting or package execution API.
        coverage = call(
            "inspector2",
            "list_coverage",
            filterCriteria={
                "resourceId": [{"comparison": "EQUALS", "value": resource}],
                "scanType": [{"comparison": "EQUALS", "value": "PACKAGE"}],
            },
            maxResults=10,
        )
        covered = [
            v
            for v in coverage.get("coveredResources", [])
            if v.get("resourceId") == resource
            and v.get("accountId") == account
            and v.get("scanType") == "PACKAGE"
        ]
        fresh = (
            bool(covered)
            and all(
                v.get("scanStatus", {}).get("statusCode") == "ACTIVE" and fresh_time(v.get("lastScannedAt"))
                for v in covered
            )
            and not coverage.get("nextToken")
        )
        data = call(
            "inspector2",
            "list_findings",
            filterCriteria={
                "resourceId": [{"comparison": "EQUALS", "value": resource}],
                "findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}],
            },
            maxResults=10,
            sortCriteria={"field": "SEVERITY", "sortOrder": "DESC"},
        )
        results = []
        for number, item in enumerate(data.get("findings", [])):
            if item.get("awsAccountId") != account or not any(
                r.get("id") == resource for r in item.get("resources", [])
            ):
                continue
            scores = item.get("packageVulnerabilityDetails", {}).get("cvss", [])
            score = next((provided_cvss(v) for v in scores if provided_cvss(v)), None)
            vulnerability = item.get("packageVulnerabilityDetails", {}).get("vulnerabilityId", "識別子なし")
            results.append(
                row(
                    f"INSPECTOR_{number}",
                    "Inspector検出 " + vulnerability,
                    "問題を検出",
                    f"{item.get('title', '')[:180]}。最終更新：{item.get('updatedAt', '不明')}。AWS収集情報であり、今回の侵入成功を示しません。",
                    "Inspectorの推奨修正と対象パッケージを管理者が確認し、修正版を適用する",
                    severity=SEVERITIES.get(item.get("severity"), "未評価"),
                    cvss=score,
                    explanation="AWSが収集したソフトウェアの既知の弱点です。使い方や公開範囲で実際の影響は変わります。",
                    criteria="指定EC2に対するACTIVE検出。CVSSは提供元のベクトルと数値が揃う場合だけ掲載します。",
                )
            )
        results.append(
            row(
                "INSPECTOR_COVERAGE",
                "Inspector確認範囲",
                "問題を検出せず" if fresh and not data.get("nextToken") else "確認不能",
                f"今回取得した検出 {len(results)}件。検査対象の収集が有効かつ7日以内={fresh}。続きあり={bool(data.get('nextToken'))}。最大10件の既存情報です。",
                "InspectorのEC2パッケージ検査を有効にし、未収集や続きの検出をInspectorで確認する",
                explanation="AWSの脆弱性検査がこのサーバーを検査対象にし、最近の情報を持っているか確認します。情報がなければ、検出が0件でも安全とは言えません。",
                criteria="収集範囲・有効状態・最終検査日時を別判定。0件でも未収集時は安全と判定しません。",
            )
        )
        return results


def fresh_time(value):
    try:
        if isinstance(value, str):
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        delta = (datetime.now(timezone.utc) - value).total_seconds()
        return 0 <= delta <= 7 * 86400
    except (TypeError, ValueError, AttributeError):
        return False


def provided_cvss(value):
    vector = value.get("scoringVector", "")
    version = value.get("version")
    score = value.get("baseScore")
    if (
        version not in ("3.0", "3.1", "4.0")
        or type(score) not in (float, int)
        or not 0 <= score <= 10
        or not re.fullmatch(r"CVSS:(3\.[01]|4\.0)/[A-Za-z0-9:/.-]+", vector)
        or not vector.startswith("CVSS:" + version + "/")
    ):
        return None
    try:
        calculated = (CVSS4(vector) if version == "4.0" else CVSS3(vector)).scores()[0]
        if abs(float(calculated) - score) > 0.05:
            return None
    except Exception:
        return None
    return {
        "score": score,
        "version": version,
        "vector": vector,
        "severity": "なし"
        if score == 0
        else "低"
        if score < 4
        else "中"
        if score < 7
        else "高"
        if score < 9
        else "緊急",
        "assessment": "provider",
        "source": value.get("source", "Inspector"),
        "rationale": {},
        "scenario": "提供元による既知脆弱性の評価。対象での悪用成立は実証していません。",
    }
