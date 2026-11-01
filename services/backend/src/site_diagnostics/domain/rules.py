from html.parser import HTMLParser
from http.cookies import SimpleCookie, CookieError
from site_diagnostics.domain.model import Observation, RULE_VERSION


class MixedContent(HTMLParser):
    def __init__(self):
        super().__init__()
        self.found = False

    def handle_starttag(self, tag, attrs):
        resource_attrs = {
            "script": "src",
            "img": "src",
            "iframe": "src",
            "link": "href",
            "audio": "src",
            "video": "src",
            "source": "src",
            "object": "data",
        }
        attr = resource_attrs.get(tag)
        for key, value in attrs:
            if key == attr and value and value.strip().lower().startswith("http://"):
                self.found = True


def diagnose(observation: Observation) -> list[dict]:
    h = {k.lower(): v for k, v in observation.headers.items()}
    secure = observation.url.startswith("https:")
    csp = h.get("content-security-policy", "")
    directives: dict[str, list[str]] = {}
    for directive in csp.split(";"):
        parts = directive.strip().split()
        if parts:
            directives.setdefault(parts[0].lower(), parts[1:])
    ages = [
        part.strip().split("=", 1)[1].strip().strip('"')
        for part in h.get("strict-transport-security", "").split(";")
        if part.strip().lower().startswith("max-age=")
    ]
    valid_hsts = len(ages) == 1 and ages[0].isdigit() and int(ages[0]) > 0
    fallback = directives.get("script-src", directives.get("default-src", []))
    csp_weak = not fallback or any(v in fallback for v in ("*", "'unsafe-inline'", "'unsafe-eval'", "http:"))
    cookie_bad = False
    for raw in observation.cookies:
        cookie: SimpleCookie = SimpleCookie()
        try:
            cookie.load(raw)
            cookie_bad |= not bool(cookie)
            for item in cookie.values():
                cookie_bad |= (
                    not item["secure"]
                    or not item["httponly"]
                    or item["samesite"].lower() not in ("lax", "strict", "none")
                )
        except CookieError:
            cookie_bad = True
    parser = MixedContent()
    parser.feed(observation.html)
    checks = [
        (
            "TLS",
            "TLS証明書",
            observation.tls.get("valid") is not True,
            "TLS検証に成功" if observation.tls.get("valid") else "TLSの観測なし",
            "信頼できる証明書・ホスト名・期限を確認する",
            secure,
        ),
        (
            "HTTPS",
            "HTTPS利用",
            not secure and observation.redirect_https is not True,
            "HTTPSで取得" if secure else "HTTP応答を観測",
            "HTTPSへ移行しHTTPからリダイレクトする",
            True,
        ),
        (
            "CSP",
            "CSPの設定",
            csp_weak,
            "有効なscript-src/default-src制約なし" if csp_weak else "スクリプト制約あり（完全性は未保証）",
            "実際のリソースに合わせnonce/hash方式等でCSPを設計する",
            True,
        ),
        (
            "HSTS",
            "HSTS",
            not valid_hsts,
            "HSTS設定の有無・停止値を確認",
            "HTTPSで適切なmax-ageのHSTSを設定する",
            secure,
        ),
        (
            "NOSNIFF",
            "MIME型保護",
            h.get("x-content-type-options", "").lower() != "nosniff",
            "nosniff指定を確認",
            "X-Content-Type-Options: nosniff を設定する",
            True,
        ),
        (
            "FRAME",
            "フレーム埋込制御",
            not (
                h.get("x-frame-options", "").upper() in ("DENY", "SAMEORIGIN")
                or "frame-ancestors" in directives
            ),
            "埋込制御を確認",
            "CSP frame-ancestorsで許可元を限定する",
            True,
        ),
        (
            "COOKIE",
            "Cookie属性",
            cookie_bad,
            "Cookie値は保存していません",
            "用途に応じSecure、HttpOnly、SameSiteを設定する",
            bool(observation.cookies),
        ),
        (
            "MIXED",
            "Mixed Content",
            parser.found,
            "静的HTMLの外部リソース参照のみ確認",
            "リソース参照をHTTPSへ変更する",
            secure,
        ),
        (
            "DISCLOSURE",
            "バージョン情報",
            bool(h.get("server") or h.get("x-powered-by")),
            "サーバー識別ヘッダーの有無を確認（値は非保存）",
            "不要なサーバー識別情報を抑制する",
            True,
        ),
    ]
    results: list[dict] = []
    for code, title, bad, evidence, fix, applicable in checks:
        state = ("問題を検出" if bad else "問題を検出せず") if applicable else "対象外"
        results.append(
            {
                "rule_id": code,
                "rule_version": RULE_VERSION,
                "title": title,
                "status": state,
                "evidence": evidence,
                "impact": "設定の改善候補。悪用可能性は未確認",
                "confidence": "設定観測",
                "fix": fix,
                "kind": "configuration",
                "cvss": None,
                "cvss_reason": "悪用条件・影響を検証していないため未評価",
                "priority": "未評価",
                "reference": "https://owasp.org/www-project-secure-headers/",
            }
        )
    results.append(
        {
            "rule_id": "REDIRECT",
            "rule_version": RULE_VERSION,
            "title": "HTTP→HTTPS誘導",
            "status": "問題を検出せず"
            if observation.redirect_https is True
            else "問題を検出"
            if observation.redirect_https is False
            else "未実施",
            "evidence": "HTTP応答のLocationを確認。リダイレクト先は取得しません",
            "kind": "coverage",
            "fix": "同一ホストのHTTPS URLへHTTPをリダイレクトする",
            "cvss": None,
            "cvss_reason": "設定観測のみで悪用条件・影響は未評価",
            "priority": "確認待ち",
        }
    )
    # Provisional configuration ratings, not business criticality or CVSS scores.
    ratings = {
        "TLS": "高",
        "HTTPS": "高",
        "MIXED": "高",
        "REDIRECT": "高",
        "CSP": "中",
        "HSTS": "中",
        "FRAME": "中",
        "COOKIE": "中",
        "NOSNIFF": "低",
        "DISCLOSURE": "低",
    }
    ranks = {"緊急": 0, "高": 1, "中": 2, "低": 3, "未評価": 4, "検出なし": 5}
    for finding in results:
        detected = finding["status"] == "問題を検出"
        finding["severity"] = (
            ratings.get(finding["rule_id"], "未評価")
            if detected
            else ("検出なし" if finding["status"] == "問題を検出せず" else "未評価")
        )
        finding["severity_basis"] = (
            "公開ページの設定観測による暫定評価。CVSSスコア・業務影響の評価ではありません"
        )
        finding["priority"] = (
            {"高": "P1 · 優先対応", "中": "P2 · 計画対応", "低": "P3 · 改善推奨"}.get(
                finding["severity"], "要確認"
            )
            if detected
            else "対応不要"
            if finding["status"] == "問題を検出せず"
            else "要確認"
        )
    return sorted(results, key=lambda f: (f["status"] != "問題を検出", ranks[f["severity"]]))
