from collections import Counter
from copy import deepcopy
from site_diagnostics.domain.checks import (
    CHECKS,
    SCENARIOS,
    EVALUATION_VERSION,
    CVSS_NOTICE,
    assessment_profile,
)
from site_diagnostics.application.ports import Evaluator
from site_diagnostics.domain.attack_analysis import analyze
from site_diagnostics.domain.ipa import ipa_checklist


def evaluate(report: dict, evaluator: Evaluator, target_url: str | None = None) -> dict:
    """Enrich saved observations without rescanning or mutating the stored report."""
    data = deepcopy(report)
    for finding in data["findings"]:
        code = finding["rule_id"]
        if code in CHECKS:
            explanation, criteria, purpose, reference = CHECKS[code]
            finding.update(explanation=explanation, criteria=criteria, purpose=purpose, reference=reference)
        if finding.get("cvss"):
            continue
        if code not in CHECKS and finding.get("criteria"):
            continue
        state = finding["status"]
        finding["cvss_status"] = "適用外"
        if state != "問題を検出":
            finding["cvss_reason"] = {
                "問題を検出せず": "このチェックでは問題を検出していないため採点対象外です。安全性全体の保証ではありません。",
                "対象外": "このページにはチェックの適用条件がないため採点対象外です。",
            }.get(state, "チェックを完了していないため、採点できません。問題なしとは扱いません。")
            if state not in ("問題を検出せず", "対象外"):
                finding["cvss_status"] = "未実施"
        elif code in SCENARIOS:
            vector, rationale, scenario = assessment_profile(code)
            finding["cvss"] = {
                **evaluator.calculate(vector, rationale),
                "assessment": "scenario_reference",
                "scenario": scenario,
                "policy_version": EVALUATION_VERSION,
            }
            finding["cvss_status"] = "参考評価"
            finding["cvss_reason"] = CVSS_NOTICE
        else:
            finding["cvss_reason"] = (
                "識別情報の公開だけでは機密性・完全性・可用性への具体的な影響が確認できないため、CVSSの採点対象外です。"
                if code == "DISCLOSURE"
                else "この旧チェックには評価基準がありません。詳細な検証が必要です。"
            )
            if code != "DISCLOSURE":
                finding["cvss_status"] = "未評価"
    detected = [f for f in data["findings"] if f["status"] == "問題を検出"]
    scored = [f for f in detected if f.get("cvss")]
    data["summary"].update(
        cvss_severity_counts={
            k: sum(f["cvss"]["severity"] == k for f in scored) for k in ("なし", "低", "中", "高", "緊急")
        },
        reference_assessed_count=sum(f["cvss"].get("assessment") == "scenario_reference" for f in scored),
        unassessed_count=sum(f.get("cvss_status") == "未評価" for f in detected),
        cvss_not_applicable_count=sum(f.get("cvss_status") == "適用外" for f in detected),
        check_status_counts=dict(Counter(f["status"] for f in data["findings"])),
    )
    data["evaluation_policy_version"] = EVALUATION_VERSION
    data["attack_analysis"] = (
        analyze(data["findings"], target_url)
        if data.get("coverage", {}).get("profile", "web") == "web"
        else None
    )
    data["ipa_checklist"] = ipa_checklist(data["findings"])
    return data
