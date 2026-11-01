import socket
import pytest
from site_diagnostics.domain.model import Scope, Rejected, Observation, severity
from site_diagnostics.domain.rules import diagnose
from site_diagnostics.adapters.outbound.web import SafeFetcher
from site_diagnostics.adapters.outbound.cvss import CvssCalculator


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "http://localhost/",
        "http://127.0.0.1/",
        "http://169.254.169.254/",
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
        "https://a:b@example.com/",
        "http://example.com:8080/",
        "https://example.com/a/../b",
        "https://example.com/%2f",
        "https://example.com/?secret=1",
        "http://example.com/\n",
    ],
)
def test_scope_rejects(url):
    with pytest.raises(Rejected):
        Scope.parse(url)


def test_scope_exact():
    scope = Scope.parse("https://Example.com/")
    assert scope.url == "https://example.com/"
    assert scope.permits("https://example.com/")
    assert not scope.permits("https://sub.example.com/")
    assert not scope.permits("http://example.com/")


@pytest.mark.parametrize(
    "addresses", [["127.0.0.1"], ["8.8.8.8", "10.1.2.3"], ["::ffff:127.0.0.1"], ["169.254.169.254"]]
)
def test_dns_all_answers_validated(monkeypatch, addresses):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443)) for ip in addresses],
    )
    with pytest.raises(Rejected):
        SafeFetcher().addresses(Scope.parse("https://example.com/"))


def test_dual_stack_prefers_ipv4_even_when_ipv6_sorts_first(monkeypatch, caplog):
    answers = ["2600:9000:abcd::1", "3.173.238.58"]
    assert sorted(answers)[0].startswith("2600:")
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **kw: [
            (socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443))
            for ip in answers
        ],
    )
    result = SafeFetcher().addresses(Scope.parse("https://example.com/"))
    assert result == ["3.173.238.58", "2600:9000:abcd::1"]
    assert '"selected_version": 4' in caplog.text
    assert "example.com" not in caplog.text
    assert all(address not in caplog.text for address in answers)


def test_ipv4_preference_does_not_hide_private_ipv6_answers(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **kw: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("3.173.238.58", 443)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 443)),
        ],
    )
    from unittest.mock import Mock
    from site_diagnostics.adapters.outbound import web

    connect = Mock()
    monkeypatch.setattr(web, "PinnedHTTPS", connect)
    with pytest.raises(Rejected):
        SafeFetcher().fetch(Scope.parse("https://example.com/"))
    connect.assert_not_called()


def test_ipv6_only_answer_is_not_discarded(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **kw: [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2600:9000:abcd::1", 443)),
        ],
    )
    assert SafeFetcher().addresses(Scope.parse("https://example.com/")) == ["2600:9000:abcd::1"]


@pytest.mark.parametrize(
    "score,label",
    [
        (None, "未評価"),
        (0, "なし"),
        (0.1, "低"),
        (3.9, "低"),
        (4, "中"),
        (6.9, "中"),
        (7, "高"),
        (8.9, "高"),
        (9, "緊急"),
        (10, "緊急"),
    ],
)
def test_severity_boundaries(score, label):
    assert severity(score) == label


def test_findings_are_not_fabricated_cvss():
    findings = diagnose(
        Observation(
            "https://example.com/", {}, ["sid=secret"], '<img src="http://example.com/a">', {"valid": True}
        ),
    )
    assert all(f["cvss"] is None for f in findings)
    assert next(f for f in findings if f["rule_id"] == "MIXED")["status"] == "問題を検出"
    assert "secret" not in str(findings)


def test_configuration_improvement_changes_findings():
    secure = {
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "strict-transport-security": "max-age=31536000",
        "x-content-type-options": "nosniff",
    }
    results = diagnose(Observation("https://example.com/", secure, [], "<p>safe</p>", {"valid": True}))
    assert not [f for f in results if f["status"] == "問題を検出"]


def test_cvss_reference_vectors():
    vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
    rationale = {p.split(":")[0]: "Known reference vector; all impacts high" for p in vector.split("/")[1:]}
    calc = CvssCalculator()
    assert calc.calculate(vector, rationale)["score"] == 10.0
    zero = vector.replace("VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", "VC:N/VI:N/VA:N/SC:N/SI:N/SA:N")
    assert calc.calculate(zero, rationale)["score"] == 0.0
    with pytest.raises(Rejected):
        calc.calculate(vector, {"AV": "insufficient"})


def test_https_connect_uses_validated_ip_and_original_sni(monkeypatch):
    from unittest.mock import Mock
    from site_diagnostics.adapters.outbound.web import PinnedHTTPS

    create = Mock()
    monkeypatch.setattr(socket, "create_connection", create)
    context = Mock()
    connection = PinnedHTTPS("example.com", "8.8.8.8", 443, context)
    connection.connect()
    create.assert_called_once_with(("8.8.8.8", 443), timeout=5)
    context.wrap_socket.assert_called_once_with(create.return_value, server_hostname="example.com")


def test_duplicate_csp_uses_first_directive():
    response = Observation(
        "https://example.com/",
        {"content-security-policy": "script-src *; script-src 'self'"},
        [],
        "",
        {"valid": True},
    )
    assert next(f for f in diagnose(response) if f["rule_id"] == "CSP")["status"] == "問題を検出"


@pytest.mark.parametrize("value", ["max-age=0", "max-age=oops", "max-age=0; max-age=31536000"])
def test_hsts_invalid_values_not_passed(value):
    response = Observation(
        "https://example.com/", {"strict-transport-security": value}, [], "", {"valid": True}
    )
    assert next(f for f in diagnose(response) if f["rule_id"] == "HSTS")["status"] == "問題を検出"


def test_provisional_severity_is_sorted_and_cvss_remains_unknown():
    findings = diagnose(
        Observation("https://example.com/", {}, [], '<img src="http://example.com/a">', {"valid": True})
    )
    detected = [f for f in findings if f["status"] == "問題を検出"]
    assert detected[0]["rule_id"] == "MIXED"
    assert detected[0]["severity"] == "高"
    assert detected[0]["priority"] == "P1 · 優先対応"
    ranks = {"高": 0, "中": 1, "低": 2}
    assert [ranks[f["severity"]] for f in detected] == sorted(ranks[f["severity"]] for f in detected)
    assert all(f["cvss"] is None for f in findings)
    assert all(
        f["severity"] != "検出なし" for f in findings if f["status"] in ("未実施", "対象外", "確認不能")
    )
