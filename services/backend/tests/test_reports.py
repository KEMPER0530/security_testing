from io import BytesIO
import pytest
from pypdf import PdfReader
from fastapi.testclient import TestClient
from site_diagnostics.adapters.inbound import api
from site_diagnostics.application.evaluation import evaluate
from site_diagnostics.adapters.outbound.cvss import CvssCalculator
from site_diagnostics.domain.model import NotFound, FetchFailure


def test_history_pdf_auth_binary_content_and_deletion(ready, monkeypatch):
    service, target, _, _ = ready
    job = service.enqueue("alice", target, "pdf")
    monkeypatch.setattr(api, "service", lambda: service)
    client = TestClient(api.app)
    path = f"/v1/scans/{job['id']}"
    assert client.get(path + "/report.pdf").status_code == 401
    api.app.dependency_overrides[api.user] = lambda: "bob"
    try:
        assert client.get(path + "/report.pdf").status_code == 404
        assert client.delete(path).status_code == 404
        api.app.dependency_overrides[api.user] = lambda: "alice"
        assert client.get(path + "/report.pdf").status_code == 409
        service.execute("alice", job["id"])
        response = client.get(path + "/report.pdf", headers={"Accept": "application/pdf"})
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/pdf"
        assert response.headers["cache-control"] == "no-store"
        assert "attachment" in response.headers["content-disposition"]
        assert response.content.startswith(b"%PDF-")
        reader = PdfReader(BytesIO(response.content))
        text = "\n".join(page.extract_text() for page in reader.pages)
        for value in [
            "https://example.com/",
            job["id"],
            "判定基準",
            "採点時の仮定",
            "CVSS:4.0/",
            "Cookie",
            "参考評価",
        ]:
            assert value in text
        assert "値は保存せず" in text
        for page in reader.pages:
            fonts = page["/Resources"]["/Font"].get_object()
            assert any(
                "/FontDescriptor" in font.get_object()
                and "/FontFile2" in font.get_object()["/FontDescriptor"]
                for font in fonts.values()
            )
        assert client.delete(path).status_code == 204
        assert client.get("/v1/scans").json()["items"] == []
        for suffix in ["", "/results", "/report", "/report.pdf", "/comparison?previous_id=" + job["id"]]:
            assert client.get(path + suffix).status_code == 404
        assert client.post(path + "/cancel").status_code == 404
        assert client.delete(path).status_code == 404
        assert client.get(f"/v1/targets/{target}").status_code == 200
        service.execute("alice", job["id"])  # Delayed SQS delivery is harmless.
    finally:
        api.app.dependency_overrides.clear()


@pytest.mark.parametrize("failure", [False, True])
def test_history_delete_during_fetch_never_resurrects(ready, failure):
    service, target, fetcher, _ = ready
    job = service.enqueue("alice", target, "race")

    def hook():
        service.remove_scan("alice", job["id"])
        if failure:
            raise FetchFailure("DNS_RESOLUTION", "DNS確認不能")

    fetcher.hook = hook
    service.execute("alice", job["id"])
    saved = service.store.get("alice", f"JOB#{job['id']}")
    assert saved["deleted"] is True
    assert saved["state"] == "CANCELLED"
    assert saved["work_pk"] == "DELETED"
    service.recover()
    service.execute("alice", job["id"])
    with pytest.raises(NotFound):
        service.document("alice", job["id"])
    service.remove("alice", target)  # Already-deleted history must not break target deletion.


def test_failed_and_cancelled_pdf_do_not_claim_clean_results(ready):
    service, target, fetcher, clock = ready
    job = service.enqueue("alice", target, "failure")
    fetcher.hook = lambda: (_ for _ in ()).throw(FetchFailure("TLS_CERTIFICATE", "<b>証明書エラー</b>"))
    service.execute("alice", job["id"])
    text = "\n".join(p.extract_text() for p in PdfReader(BytesIO(service.document("alice", job["id"]))).pages)
    assert "<b>証明書エラー</b>" in text  # Escaped text, never interpreted markup.
    assert "問題なし" in text
    assert "診断失敗" in text
    clock[0] += 150
    cancelled = service.enqueue("alice", target, "cancel")
    service.cancel("alice", cancelled["id"])
    service.execute("alice", cancelled["id"])
    text = PdfReader(BytesIO(service.document("alice", cancelled["id"]))).pages[0].extract_text()
    assert "キャンセル" in text
    assert "設定改善候補：0" not in text


def test_saved_results_are_evaluated_without_refetch_or_storage_mutation(ready):
    service, target, fetcher, _ = ready
    job = service.enqueue("alice", target, "saved")
    service.execute("alice", job["id"])
    key = service.require("alice", f"JOB#{job['id']}")["report_key"]
    report = service.reports.get("alice", key)
    for f in report["findings"]:
        f["cvss"] = None
        f["rule_version"] = "legacy"
    service.reports.put("alice", key, report)
    fetcher.hook = lambda: pytest.fail("PDF/result reads must never refetch the target")
    scored = service.result("alice", job["id"])
    csp = next(f for f in scored["findings"] if f["rule_id"] == "CSP")
    assert csp["cvss"]["score"] == 2.3
    assert csp["cvss"]["assessment"] == "scenario_reference"
    assert csp["rule_version"] == "legacy"
    assert csp["explanation"] and csp["criteria"] and csp["purpose"]
    assert service.reports.get("alice", key)["findings"][0]["cvss"] is None
    service.document("alice", job["id"])


def test_cvss_applicability_and_missing_evidence():
    findings = [
        {"rule_id": code, "title": code, "status": state, "cvss": None}
        for code, state in [
            ("DISCLOSURE", "問題を検出"),
            ("CSP", "問題を検出せず"),
            ("COOKIE", "対象外"),
            ("REDIRECT", "未実施"),
        ]
    ]
    result = evaluate({"findings": findings, "summary": {}}, CvssCalculator())
    assert all(f["cvss"] is None for f in result["findings"])
    assert [f["cvss_status"] for f in result["findings"]] == ["適用外", "適用外", "適用外", "未実施"]
    assert result["summary"]["unassessed_count"] == 0


def test_all_reference_scenarios_have_complete_metric_reasons():
    from site_diagnostics.domain.checks import SCENARIOS

    report = evaluate(
        {
            "findings": [
                {"rule_id": code, "title": code, "status": "問題を検出", "cvss": None} for code in SCENARIOS
            ],
            "summary": {},
        },
        CvssCalculator(),
    )
    for f in report["findings"]:
        score = f["cvss"]
        assert 0 < score["score"] <= 10
        assert score["assessment"] == "scenario_reference"
        assert set(score["rationale"]) == {"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"}
        assert score["scenario"] and "仮定" in score["scenario"]
        assert "確認したものではありません" in f["cvss_reason"]
    assert report["summary"]["reference_assessed_count"] == len(SCENARIOS)


def test_attack_analysis_matches_evidence_and_explains_unchecked_areas(ready):
    service, target, _, _ = ready
    job = service.enqueue("alice", target, "attack-analysis")
    service.execute("alice", job["id"])
    report = service.result("alice", job["id"])
    analysis = report["attack_analysis"]
    assert analysis["target_url"] == "https://example.com/"
    assert analysis["total_findings"] == report["summary"]["configuration_count"]
    assert sum(i["finding_count"] for i in analysis["items"]) == analysis["total_findings"]
    assert "確率" in analysis["notice"] and "サイト全体" in analysis["scope"]
    codes = [e["rule_id"] for i in analysis["items"] for e in i["evidence"]]
    assert len(codes) == len(set(codes))
    assert set(codes) == {f["rule_id"] for f in report["findings"] if f["status"] == "問題を検出"}
    assert any("DDoS" in i["title"] for i in analysis["not_evaluated"])
    assert all(i["conditions"] and i["possible_impact"] and i["actions"] for i in analysis["items"])
    text = "\n".join(p.extract_text() for p in PdfReader(BytesIO(service.document("alice", job["id"]))).pages)
    assert "どこに注意が必要？" in text
    assert "今回評価していない攻撃" in text
    assert "AI分析" in text and "工事中" in text


def test_no_detected_configuration_does_not_mean_all_attack_types_are_safe():
    from site_diagnostics.domain.attack_analysis import analyze

    analysis = analyze(
        [{"rule_id": "CSP", "status": "問題を検出せず"}, {"rule_id": "REDIRECT", "status": "未実施"}]
    )
    assert analysis["items"] == []
    assert analysis["total_findings"] == 0
    assert len(analysis["not_evaluated"]) == 3


def test_ai_is_under_construction_even_with_credentials_and_is_owner_scoped(ready, monkeypatch):
    service, target, fetcher, _ = ready
    job = service.enqueue("alice", target, "ai-pending")
    monkeypatch.setattr(api, "service", lambda: service)
    monkeypatch.setenv("OPENAI_API_KEY", "test-only-not-used")
    fetcher.hook = lambda: pytest.fail("Construction status must not perform diagnostic or AI work")
    client = TestClient(api.app)
    path = f"/v1/scans/{job['id']}/ai-analysis"
    assert client.get(path).status_code == 401
    api.app.dependency_overrides[api.user] = lambda: "bob"
    try:
        assert client.get(path).status_code == 404
        api.app.dependency_overrides[api.user] = lambda: "alice"
        data = client.get(path).json()
        assert data["status"] == "under_construction"
        assert data["provider"] == "openai"
        assert data["result"] is None
        assert client.post(path, json={"prompt": "run"}).status_code == 405
        service.remove_scan("alice", job["id"])
        assert client.get(path).status_code == 404
    finally:
        api.app.dependency_overrides.clear()


def test_ipa_table_distinguishes_related_settings_from_root_protections(ready):
    service, target, fetcher, _ = ready
    job = service.enqueue("alice", target, "ipa-checklist")
    service.execute("alice", job["id"])
    rows = service.result("alice", job["id"])["ipa_checklist"]
    assert len(rows) == 14
    assert next(i for i in rows if i["section"] == "1.1")["coverage"] == "未実施"
    assert next(i for i in rows if i["section"] == "1.5")["coverage"] == "関連設定のみ観測"
    assert all(
        i["pdf_page"] == i["page"] + 2 and i["source"].startswith("https://www.ipa.go.jp/") for i in rows
    )
    fetcher.hook = lambda: pytest.fail("Checklist exports must use the saved result")
    reader = PdfReader(BytesIO(service.document("alice", job["id"])))
    text = "\n".join(p.extract_text() for p in reader.pages)
    for word in (
        "診断結果一覧",
        "項目別の分析",
        "追加で必要な確認",
        "IPA対策との対応関係",
        "2021年3月",
        "根本的な対策",
    ):
        assert word in text
    for unwanted in (
        "対応記録",
        "記入欄",
        "[ ]",
        "担当：",
        "期限：",
        "チェックリスト",
        "DIAGNOSTIC CHECKLIST",
    ):
        assert unwanted not in text
    assert reader.metadata.title == "Security Testing 診断レポート"
    # No blank/orphan pages: every page contains a meaningful report section/table.
    assert all(len(p.extract_text()) > 180 for p in reader.pages)
