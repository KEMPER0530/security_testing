"""Bounded, selectable diagnostic plans. No user-supplied commands or payloads."""

import re
from site_diagnostics.domain.model import Rejected

PROFILES: dict[str, dict] = {
    "web": {
        "title": "Web診断",
        "checks": {"headers": "公開ページの応答・保護設定"},
        "scope": "単一URLの静的HTMLと応答設定",
    },
    "network": {
        "title": "ネットワーク診断",
        "checks": {
            "dns": "公開IPの名前解決",
            "ports": "選択したTCPポートの接続確認",
            "tls": "Web通信とTLS証明書",
        },
        "scope": "登録URLのホスト・指定TCPポートのみ",
    },
    "pentest": {
        "title": "ペネトレーション（限定検証）",
        "checks": {
            "headers": "公開ページの設定",
            "cors": "異なるサイトからの読み取り許可",
            "methods": "許可メソッドの応答",
            "trace": "TRACE応答",
        },
        "scope": "単一URLに対する低負荷の限定検証。侵入・権限昇格・横展開の実証は含まない",
    },
    "host": {
        "title": "AWSホスト診断",
        "checks": {"inventory": "SSMのOS・収集状態", "inspector": "Amazon Inspectorの既存検出結果"},
        "scope": "指定EC2の収集済みSSM/Inspector情報。新規のOSコマンド実行は含まない",
    },
    "cloud": {
        "title": "AWSクラウド診断",
        "checks": {
            "root_mfa": "ルート利用者の多要素認証",
            "s3": "指定S3の公開制御・暗号化",
            "security_groups": "指定セキュリティグループの公開設定",
            "cloudtrail": "指定CloudTrailの記録状態",
        },
        "scope": "指定AWSリソースの読み取り専用設定検査",
    },
}
ADVANCED_RULE_VERSION = "2026-11-02.2"
PORTS = (22, 25, 53, 80, 443, 3306, 3389, 5432, 6379, 8080, 8443)
ROLE_PATTERN = r"arn:aws:iam::[0-9]{12}:role/security-testing-audit-[A-Za-z0-9+=,.@_-]{1,40}"
RESOURCE_PATTERNS = {
    "instances": r"i-[0-9a-f]{8,17}",
    "buckets": r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]",
    "security_groups": r"sg-[0-9a-f]{8,17}",
    "trails": r"arn:aws:cloudtrail:[a-z0-9-]+:[0-9]{12}:trail/[A-Za-z0-9_./-]{1,128}",
}


def plan_for(
    profile="web", checks=None, ports=None, resources=None, region="ap-northeast-1", authorized=False
):
    if profile not in PROFILES:
        raise Rejected("診断の種類が不正です")
    checks = list(dict.fromkeys(checks or (["headers"] if profile == "web" else [])))
    if not checks or not set(checks) <= set(PROFILES[profile]["checks"]):
        raise Rejected("実施する検査を選択してください")
    if profile != "web" and authorized is not True:
        raise Rejected("対象と検査範囲について実施許可の確認が必要です")
    ports = list(dict.fromkeys(ports or []))
    if len(ports) > 8 or any(type(p) is not int or p not in PORTS for p in ports):
        raise Rejected("対応するTCPポートを8個まで選択してください")
    if profile == "network" and "ports" in checks and not ports:
        raise Rejected("確認するTCPポートを選択してください")
    if ports and (profile != "network" or "ports" not in checks):
        raise Rejected("TCPポートはネットワーク診断の接続確認で指定してください")
    resources = resources or {}
    if set(resources) - set(RESOURCE_PATTERNS):
        raise Rejected("対応しないAWSリソース指定です")
    for kind, values in resources.items():
        if (
            not isinstance(values, list)
            or len(values) > 3
            or any(not isinstance(v, str) or not re.fullmatch(RESOURCE_PATTERNS[kind], v) for v in values)
        ):
            raise Rejected("AWSリソースは種類ごとに正しい識別子を3個まで指定してください")
    if not re.fullmatch(r"[a-z]{2}-[a-z]+-[1-9]", region):
        raise Rejected("AWSリージョンを確認してください")
    required = (
        ["instances"]
        if profile == "host"
        else [
            key
            for check, key in [
                ("s3", "buckets"),
                ("security_groups", "security_groups"),
                ("cloudtrail", "trails"),
            ]
            if check in checks
        ]
        if profile == "cloud"
        else []
    )
    if any(not resources.get(kind) for kind in required):
        raise Rejected("選択した検査の対象AWSリソースを指定してください")
    if profile not in ("host", "cloud") and any(resources.values()):
        raise Rejected("AWSリソースはAWS診断で指定してください")
    return {
        "profile": profile,
        "checks": checks,
        "ports": ports,
        "resources": resources,
        "region": region,
        "authorized": authorized,
    }


def role_arn(value):
    if not re.fullmatch(ROLE_PATTERN, value):
        raise Rejected("security-testing-audit-で始まる読み取り専用ロールARNを指定してください")
    return value


def finding(
    code,
    title,
    status,
    evidence,
    fix,
    *,
    severity="未評価",
    explanation="",
    criteria="",
    reference="https://owasp.org/www-project-web-security-testing-guide/",
    cvss=None,
    details=None,
):
    return {
        "rule_id": code,
        "rule_version": ADVANCED_RULE_VERSION,
        "title": title,
        "status": status,
        "evidence": evidence[:1800],
        "fix": fix,
        "kind": "vulnerability" if cvss else "configuration",
        "severity": severity
        if status == "問題を検出"
        else "検出なし"
        if status == "問題を検出せず"
        else "未評価",
        "severity_basis": "観測した状態による評価。検査していない条件は含みません。",
        "priority": (
            "P1 · 優先対応"
            if severity in ("緊急", "高")
            else "P2 · 計画対応"
            if severity == "中"
            else "P3 · 改善推奨"
        )
        if status == "問題を検出"
        else "要確認"
        if status in ("未実施", "確認不能")
        else "対応不要",
        "explanation": explanation or title,
        "purpose": "確認した状態と未検証の範囲を区別して、必要な対策を選ぶためです。",
        "criteria": criteria,
        "cvss": cvss,
        "cvss_status": "提供元評価" if cvss else "未実施" if status in ("未実施", "確認不能") else "適用外",
        "cvss_reason": f"提供元：{cvss.get('source', 'Inspector')}。提供元が報告した既知脆弱性の評価です。"
        if cvss
        else "この観測だけでは具体的な悪用条件と影響を確定できないため、数値を割り当てません。",
        "reference": reference,
        "details": details or {},
    }
