from datetime import datetime, timedelta, timezone
from io import BytesIO
from unittest.mock import Mock
import boto3
import pytest
from botocore.exceptions import ClientError
from botocore.validate import ParamValidator
from fastapi.testclient import TestClient
from pypdf import PdfReader
from site_diagnostics.adapters.inbound import api
from site_diagnostics.adapters.outbound.advanced import AdvancedRunner, ORIGIN, MARKER
from site_diagnostics.adapters.outbound.aws_audit import AwsAudit, READ_ACTIONS, provided_cvss
from site_diagnostics.adapters.outbound.web import SafeFetcher
from site_diagnostics.domain.model import Scope, Rejected, NotFound, Conflict
from site_diagnostics.domain.plans import plan_for, finding

ACCOUNT = "123456789012"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/security-testing-audit-test"
CONNECTION = {"role_arn": ROLE, "external_id": "security-testing-test"}
WORKER = f"arn:aws:iam::{ACCOUNT}:role/example-worker"
INSTANCE = "i-0123456789abcdef0"
VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def denied(operation="GetAccountSummary"):
    return ClientError({"Error": {"Code": "AccessDenied", "Message": "private-detail"}}, operation)


class CloudCalls:
    """Validate actual botocore request shapes; return controlled collected evidence."""

    def __init__(self, responses):
        self.responses, self.calls, self.clients = responses, [], {}

    def __call__(self, service, operation, **kwargs):
        if service not in self.clients:
            self.clients[service] = boto3.client(
                service, region_name="ap-northeast-1", aws_access_key_id="test", aws_secret_access_key="test"
            )
        model = self.clients[service].meta.service_model.operation_model(
            self.clients[service].meta.method_to_api_mapping[operation]
        )
        validation = ParamValidator().validate(kwargs, model.input_shape)
        assert not validation.has_errors(), validation.generate_report()
        self.calls.append((service, operation, kwargs))
        value = self.responses[operation]
        if isinstance(value, Exception):
            raise value
        return value


@pytest.mark.parametrize(
    "args",
    [
        {"profile": "network", "checks": ["ports"], "ports": [443]},
        {"profile": "pentest", "checks": ["delete"], "authorized": True},
        {"profile": "network", "checks": ["ports"], "ports": [1], "authorized": True},
        {
            "profile": "network",
            "checks": ["ports"],
            "ports": [22, 25, 53, 80, 443, 3306, 3389, 5432, 6379],
            "authorized": True,
        },
        {
            "profile": "host",
            "checks": ["inventory"],
            "resources": {"instances": ["../secret"]},
            "authorized": True,
        },
        {"profile": "cloud", "checks": ["s3"], "authorized": True},
    ],
)
def test_reject_unbounded_or_unapproved_plans(args):
    with pytest.raises(Rejected):
        plan_for(**args)


class FakeDiagnostics:
    def __init__(self):
        self.calls = []
        self.hook = None

    def run(self, plan, scope, connection):
        self.calls.append((plan, scope, connection))
        if self.hook:
            self.hook()
        return {
            "findings": [
                finding(
                    "TCP_TEST", "限定検査", "確認不能", "TCPのみ", "管理者が確認", criteria="接続確認のみ"
                )
            ],
            "coverage": {"profile": plan["profile"], "scope": "限定", "not_tested": ["侵入"]},
        }


def configure(service, target):
    service.aws = AwsAudit(WORKER)
    prepared = service.aws_connection("alice", target, prepare=True)
    assert prepared["role_arn"] is None
    assert service.aws_connection("alice", target, prepare=True)["external_id"] == prepared["external_id"]
    service.aws_connection("alice", target, arn=ROLE)
    return prepared


def test_queue_pins_plan_and_connection_and_preserves_partial_unknown(ready):
    service, target, fetcher, _ = ready
    prepared = configure(service, target)
    diagnostics = FakeDiagnostics()
    service.diagnostics = diagnostics
    fetcher.hook = lambda: pytest.fail("AWS plan must not fetch the public website")
    plan = dict(profile="host", checks=["inventory"], resources={"instances": [INSTANCE]}, authorized=True)
    job = service.enqueue("alice", target, "host-once", plan)
    assert service.enqueue("alice", target, "host-once", plan)["id"] == job["id"]
    with pytest.raises(Conflict):
        service.enqueue("alice", target, "host-once", {**plan, "checks": ["inspector"]})
    service.aws_connection("alice", target, arn=ROLE + "-changed")
    service.execute("alice", job["id"])
    assert diagnostics.calls[0][2] == {"role_arn": ROLE, "external_id": prepared["external_id"]}
    result = service.result("alice", job["id"])
    assert result["attack_analysis"] is None
    assert result["findings"][0]["status"] == "確認不能"
    assert all(i["coverage"] == "未実施" for i in result["ipa_checklist"])
    assert result["summary"]["check_status_counts"] == {"確認不能": 1}
    assert "要確認" in "\n".join(
        p.extract_text() for p in PdfReader(BytesIO(service.document("alice", job["id"]))).pages
    )


@pytest.mark.parametrize("remove", ["target", "history", "cancel"])
def test_advanced_work_obeys_existing_cancel_delete_fences(ready, remove):
    service, target, _, _ = ready
    service.diagnostics = runner = FakeDiagnostics()
    job = service.enqueue("alice", target, "fence", dict(profile="network", checks=["dns"], authorized=True))
    runner.hook = (
        lambda: service.remove("alice", target)
        if remove == "target"
        else service.remove_scan("alice", job["id"])
        if remove == "history"
        else service.cancel("alice", job["id"])
    )
    service.execute("alice", job["id"])
    if remove == "cancel":
        assert service.visible_job("alice", job["id"])["state"] == "CANCELLED"
    else:
        with pytest.raises(NotFound):
            service.result("alice", job["id"])


def test_aws_connection_auth_owner_scope_and_no_credentials_in_jobs(ready, monkeypatch):
    service, target, _, _ = ready
    configure(service, target)
    service.diagnostics = FakeDiagnostics()
    monkeypatch.setattr(api, "service", lambda: service)
    client = TestClient(api.app)
    path = f"/v1/targets/{target}/aws-connection"
    assert client.get(path).status_code == 401
    api.app.dependency_overrides[api.user] = lambda: "bob"
    try:
        for method in (client.get, client.post):
            assert method(path).status_code == 404
        assert client.put(path, json={"role_arn": ROLE}).status_code == 404
        api.app.dependency_overrides[api.user] = lambda: "alice"
        assert client.put(path, json={"role_arn": f"arn:aws:iam::{ACCOUNT}:role/Admin"}).status_code == 422
        data = client.get(path).json()
        assert data["external_id"].startswith("security-testing-")
        assert "pk" not in data and "rev" not in data
        assert (
            client.post(
                "/v1/scans",
                headers={"Idempotency-Key": "no-approval"},
                json={"target_id": target, "profile": "network", "checks": ["dns"]},
            ).status_code
            == 422
        )
        response = client.post(
            "/v1/scans",
            headers={"Idempotency-Key": "approved"},
            json={
                "target_id": target,
                "profile": "host",
                "checks": ["inventory"],
                "resources": {"instances": [INSTANCE]},
                "authorized": True,
            },
        )
        assert response.status_code == 202
        assert response.json()["plan"]["profile"] == "host"
        assert "aws_connection" not in response.json()
        assert data["external_id"] not in response.text
    finally:
        api.app.dependency_overrides.clear()


def test_cross_account_template_and_session_only_allow_audit_reads():
    audit = AwsAudit(WORKER)
    template = audit.template(CONNECTION)
    role = template["Resources"]["AuditRole"]["Properties"]
    trust = role["AssumeRolePolicyDocument"]["Statement"][0]
    assert trust["Principal"] == {"AWS": WORKER}
    assert trust["Condition"] == {"StringEquals": {"sts:ExternalId": CONNECTION["external_id"]}}
    actions = role["Policies"][0]["PolicyDocument"]["Statement"][0]["Action"]
    assert actions == READ_ACTIONS
    assert not any(v in str(actions) for v in ("SendCommand", "Start", "Put", "GetObject", "Delete", "*"))
    sts = Mock()
    sts.assume_role.side_effect = [
        denied("AssumeRole"),
        denied("AssumeRole"),
        {"Credentials": {"AccessKeyId": "test"}},
    ]
    audit.client = lambda *args: sts
    assert (
        audit.credentials(
            plan_for("host", ["inventory"], resources={"instances": [INSTANCE]}, authorized=True), CONNECTION
        )["AccessKeyId"]
        == "test"
    )
    calls = sts.assume_role.call_args_list
    assert "ExternalId" not in calls[0].kwargs
    assert calls[1].kwargs["ExternalId"] != CONNECTION["external_id"]
    assert calls[2].kwargs["ExternalId"] == CONNECTION["external_id"]
    assert '"Action"' in calls[2].kwargs["Policy"]
    sts.assume_role.side_effect = [{"Credentials": {"AccessKeyId": "never-use"}}]
    with pytest.raises(Rejected, match="ExternalId"):
        audit.credentials(plan_for(), CONNECTION)


def test_cloud_partial_permissions_keep_observations_and_no_object_reads():
    audit = AwsAudit(WORKER)
    calls = CloudCalls(
        {
            "get_public_access_block": {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False,
                }
            },
            "get_bucket_encryption": denied(),
        }
    )
    rows = audit.check("s3", "example-audit", ACCOUNT, "ap-northeast-1", calls)
    assert [f["status"] for f in rows] == ["問題を検出", "確認不能"]
    assert "公開可否" in rows[0]["evidence"]
    assert all(c[2]["ExpectedBucketOwner"] == ACCOUNT for c in calls.calls)
    assert not any("object" in c[1] for c in calls.calls)


def test_security_group_and_trail_scope_checks():
    audit = AwsAudit(WORKER)
    calls = CloudCalls(
        {
            "describe_security_groups": {
                "SecurityGroups": [
                    {
                        "GroupId": "sg-0123456789abcdef0",
                        "OwnerId": ACCOUNT,
                        "IpPermissions": [
                            {
                                "IpProtocol": "tcp",
                                "FromPort": 22,
                                "ToPort": 22,
                                "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                            }
                        ],
                    }
                ]
            }
        }
    )
    rows = audit.check("security_groups", "sg-0123456789abcdef0", ACCOUNT, "ap-northeast-1", calls)
    assert rows[0]["status"] == "問題を検出"
    assert rows[0]["severity"] == "高"
    assert "到達性" in rows[0]["evidence"]
    with pytest.raises(Rejected):
        audit.check(
            "cloudtrail",
            f"arn:aws:cloudtrail:us-east-1:{ACCOUNT}:trail/example",
            ACCOUNT,
            "ap-northeast-1",
            calls,
        )


def test_empty_or_old_inspector_data_never_claims_no_vulnerabilities():
    audit = AwsAudit(WORKER)
    calls = CloudCalls({"list_coverage": {"coveredResources": []}, "list_findings": {"findings": []}})
    rows = audit.check("inspector", INSTANCE, ACCOUNT, "ap-northeast-1", calls)
    assert len(rows) == 1 and rows[0]["status"] == "確認不能"
    assert calls.calls[-1][2]["maxResults"] == 10


def test_inspector_preserves_provider_cvss_and_records_truncation(ready):
    service, target, _, _ = ready
    audit = AwsAudit(WORKER)
    now = datetime.now(timezone.utc)
    calls = CloudCalls(
        {
            "list_coverage": {
                "coveredResources": [
                    {
                        "resourceId": INSTANCE,
                        "accountId": ACCOUNT,
                        "scanType": "PACKAGE",
                        "scanStatus": {"statusCode": "ACTIVE"},
                        "lastScannedAt": now,
                    }
                ]
            },
            "list_findings": {
                "nextToken": "more",
                "findings": [
                    {
                        "awsAccountId": ACCOUNT,
                        "resources": [{"id": INSTANCE}],
                        "findingArn": f"arn:aws:inspector2:ap-northeast-1:{ACCOUNT}:finding/example-stable-id",
                        "title": "Example package vulnerability",
                        "updatedAt": now,
                        "severity": "CRITICAL",
                        "packageVulnerabilityDetails": {
                            "vulnerabilityId": "CVE-2025-0001",
                            "cvss": [
                                {"version": "3.1", "baseScore": 9.8, "scoringVector": VECTOR, "source": "NVD"}
                            ],
                        },
                    }
                ],
            },
        }
    )
    rows = audit.check("inspector", INSTANCE, ACCOUNT, "ap-northeast-1", calls)
    assert rows[0]["cvss"]["score"] == 9.8
    assert rows[1]["status"] == "確認不能"

    class Runner:
        def run(self, *args):
            return {
                "findings": rows,
                "coverage": {"profile": "host", "scope": "Inspector収集済み情報", "not_tested": ["侵入"]},
            }

    configure(service, target)
    service.diagnostics = Runner()
    job = service.enqueue(
        "alice",
        target,
        "provider",
        dict(profile="host", checks=["inspector"], resources={"instances": [INSTANCE]}, authorized=True),
    )
    service.execute("alice", job["id"])
    result = service.result("alice", job["id"])
    assert result["findings"][0]["cvss"]["assessment"] == "provider"
    assert result["summary"]["highest_severity"] == "緊急"
    text = "\n".join(p.extract_text() for p in PdfReader(BytesIO(service.document("alice", job["id"]))).pages)
    assert "CVSS 3.1" in text and "提供元評価" in text and "9.8" in text
    assert provided_cvss({"version": "3.1", "baseScore": 9.8, "scoringVector": "CVSS:3.1/AV:N"}) is None
    assert provided_cvss({"version": "3.1", "baseScore": 1, "scoringVector": VECTOR}) is None


def test_stale_ssm_inventory_is_unknown_not_healthy():
    calls = CloudCalls(
        {
            "describe_instance_information": {
                "InstanceInformationList": [
                    {
                        "InstanceId": INSTANCE,
                        "PlatformName": "Example OS",
                        "PlatformVersion": "1",
                        "PingStatus": "Online",
                    }
                ]
            },
            "list_inventory_entries": {
                "Entries": [{"PlatformName": "Example OS"}],
                "CaptureTime": (datetime.now(timezone.utc) - timedelta(days=8)).isoformat(),
            },
        }
    )
    assert (
        AwsAudit(WORKER).check("inventory", INSTANCE, ACCOUNT, "ap-northeast-1", calls)[0]["status"]
        == "確認不能"
    )


def test_network_rejects_private_or_mixed_dns_before_connect(monkeypatch):
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 443)), (2, 1, 6, "", ("127.0.0.1", 443))],
    )
    connect = Mock(side_effect=AssertionError("must not connect"))
    monkeypatch.setattr("socket.create_connection", connect)
    with pytest.raises(Rejected):
        AdvancedRunner(SafeFetcher(), None).run(
            plan_for("network", ["ports"], [443], authorized=True), Scope.parse("https://example.com/"), None
        )
    connect.assert_not_called()


def test_open_management_port_is_not_declared_exploitable(monkeypatch):
    web = SafeFetcher()
    web.addresses = lambda scope: ["93.184.216.34"]
    context = Mock()
    context.__enter__ = Mock(return_value=context)
    context.__exit__ = Mock(return_value=False)
    monkeypatch.setattr("socket.create_connection", Mock(return_value=context))
    report = AdvancedRunner(web, None).run(
        plan_for("network", ["ports"], [22], authorized=True), Scope.parse("https://example.com/"), None
    )
    assert report["findings"][0]["status"] == "確認不能"
    assert "公開意図" in report["findings"][0]["evidence"]


def test_limited_web_tests_do_not_send_credentials_or_write_methods():
    runner = AdvancedRunner(SafeFetcher(), None)
    runner.probe = Mock(
        return_value=(
            200,
            {"access-control-allow-origin": ORIGIN, "access-control-allow-credentials": "true"},
            b"",
        )
    )
    assert runner._check(Scope.parse("https://example.com/"), "cors")["status"] == "問題を検出"
    assert runner.probe.call_args.args[1:] == ("GET", {"Origin": ORIGIN})
    runner.probe.return_value = (200, {"allow": "GET, PUT, DELETE"}, b"")
    assert runner._check(Scope.parse("https://example.com/"), "methods")["status"] == "確認不能"
    assert runner.probe.call_args.args[1] == "OPTIONS"
    runner.probe.return_value = (200, {}, MARKER.encode())
    assert runner._check(Scope.parse("https://example.com/"), "trace")["status"] == "問題を検出"
    assert runner.probe.call_args.args[1:] == ("TRACE", {"X-Security-Testing-Probe": MARKER})


def test_inspector_identity_survives_reordering_and_comparison_detects_new_cve(ready, monkeypatch):
    service, target, _, clock = ready
    audit = AwsAudit(WORKER)
    now = datetime.now(timezone.utc)

    def item(name):
        return {
            "awsAccountId": ACCOUNT,
            "findingArn": f"arn:aws:inspector2:ap-northeast-1:{ACCOUNT}:finding/{name}",
            "resources": [{"id": INSTANCE}],
            "title": name,
            "severity": "HIGH",
            "packageVulnerabilityDetails": {"vulnerabilityId": name},
        }

    def inspect(items):
        calls = CloudCalls(
            {
                "list_coverage": {
                    "coveredResources": [
                        {
                            "resourceId": INSTANCE,
                            "accountId": ACCOUNT,
                            "scanType": "PACKAGE",
                            "scanStatus": {"statusCode": "ACTIVE"},
                            "lastScannedAt": now,
                        }
                    ]
                },
                "list_findings": {"findings": [item(n) for n in items]},
            }
        )
        return audit.check("inspector", INSTANCE, ACCOUNT, "ap-northeast-1", calls)

    ab, ba = inspect(["CVE-A", "CVE-B"]), inspect(["CVE-B", "CVE-A"])
    assert {f["title"]: f["rule_id"] for f in ab} == {f["title"]: f["rule_id"] for f in ba}
    assert ab[0]["rule_id"] != ab[1]["rule_id"]
    configure(service, target)

    class Runner:
        rows = inspect(["CVE-A"])

        def run(self, *args):
            return {
                "findings": self.rows,
                "coverage": {"profile": "host", "scope": "既存情報", "not_tested": ["侵入"]},
            }

    service.diagnostics = runner = Runner()
    plan = dict(profile="host", checks=["inspector"], resources={"instances": [INSTANCE]}, authorized=True)
    before = service.enqueue("alice", target, "before-cve", plan)
    service.execute("alice", before["id"])
    clock[0] += 150
    runner.rows = inspect(["CVE-B"])
    after = service.enqueue("alice", target, "after-cve", plan)
    service.execute("alice", after["id"])
    monkeypatch.setattr(api, "service", lambda: service)
    api.app.dependency_overrides[api.user] = lambda: "alice"
    try:
        response = TestClient(api.app).get(
            f"/v1/scans/{after['id']}/comparison", params={"previous_id": before["id"]}
        )
        assert response.status_code == 200
        b_id = next(f["rule_id"] for f in runner.rows if "CVE-B" in f["title"])
        assert next(f["change"] for f in response.json()["items"] if f["rule_id"] == b_id) == "新規"
        clock[0] += 150
        service.aws_connection("alice", target, arn=ROLE + "-changed")
        changed = service.enqueue("alice", target, "changed-connection", plan)
        service.execute("alice", changed["id"])
        assert (
            TestClient(api.app)
            .get(f"/v1/scans/{changed['id']}/comparison", params={"previous_id": after["id"]})
            .status_code
            == 409
        )
    finally:
        api.app.dependency_overrides.clear()


def test_inspector_missing_identity_is_incomplete():
    calls = CloudCalls(
        {
            "list_coverage": {"coveredResources": []},
            "list_findings": {
                "findings": [
                    {"awsAccountId": ACCOUNT, "resources": [{"id": INSTANCE}], "title": "missing identifier"}
                ]
            },
        }
    )
    rows = AwsAudit(WORKER).check("inspector", INSTANCE, ACCOUNT, "ap-northeast-1", calls)
    assert len(rows) == 1 and rows[0]["status"] == "確認不能"
    assert "識別子の欠落=True" in rows[0]["evidence"]
