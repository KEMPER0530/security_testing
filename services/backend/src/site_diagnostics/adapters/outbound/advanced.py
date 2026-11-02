"""Bounded network checks and manually selected, non-destructive HTTP checks."""

import errno
import http.client
import socket
import time
from site_diagnostics.domain.model import Scope, Rejected
from site_diagnostics.domain.plans import PROFILES, finding
from site_diagnostics.domain.rules import diagnose
from site_diagnostics.adapters.outbound.web import SafeFetcher, PinnedHTTPS

ORIGIN = "https://security-testing.invalid"
MARKER = "security-testing-trace-probe"


class AdvancedRunner:
    def __init__(self, web: SafeFetcher, aws):
        self.web, self.aws = web, aws

    def run(self, plan, scope: Scope, connection):
        profile = plan["profile"]
        if profile in ("host", "cloud"):
            return self.aws.run(plan, connection)
        deadline = time.monotonic() + 30
        rows = []
        # Resolve and validate every answer before a socket is opened.
        try:
            addresses = self.web.addresses(scope)
        except OSError as exc:
            raise Rejected("接続先の名前解決を確認できませんでした") from exc
        if profile == "network":
            if "dns" in plan["checks"]:
                rows.append(
                    finding(
                        "DNS",
                        "名前解決と接続先",
                        "問題を検出せず",
                        f"公開IPを{len(addresses)}件確認。接続には検証済みIPを使用。",
                        "DNSの運用・管理権限も別途確認する",
                        explanation="サイト名から接続先の住所（IPアドレス）を調べる仕組みです。DNSの運用権限や登録内容全体を検査するものではありません。",
                        criteria="全DNS応答が公開IPであること。DNS運用全体の健全性は検査しません。",
                    )
                )
            if "ports" in plan["checks"]:
                for port in plan["ports"]:
                    status, evidence = "確認不能", "制限時間に達し未確認です。"
                    if time.monotonic() < deadline:
                        try:
                            with socket.create_connection((addresses[0], port), timeout=1):
                                status = "問題を検出せず" if port in (80, 443) else "確認不能"
                                evidence = (
                                    "TCP接続に成功。公開意図とアクセス制御の妥当性は別途確認が必要です。"
                                )
                        except OSError as exc:
                            if exc.errno == errno.ECONNREFUSED:
                                status, evidence = (
                                    "問題を検出せず",
                                    "今回の接続は拒否されました。別経路や他ポートは未確認です。",
                                )
                            else:
                                evidence = "タイムアウトまたは通信経路の制限により確認できません。閉じたポートとは断定しません。"
                    rows.append(
                        finding(
                            f"PORT_{port}",
                            f"TCP {port}の接続",
                            status,
                            evidence,
                            "不要なサービス公開を閉じ、必要な接続元だけ許可する",
                            explanation="サーバーへの通信の入口です。つながることだけでは侵入できるとは分からないため、公開が必要か管理者が確認します。",
                            criteria="指定した1ホスト・1ポートへのTCP接続のみ。サービス製品・既知脆弱性は未検査です。",
                        )
                    )
            if "tls" in plan["checks"]:
                try:
                    rows.extend(
                        f for f in diagnose(self.web.fetch(scope)) if f["rule_id"] in ("TLS", "HTTPS")
                    )
                except Rejected as exc:
                    rows.append(
                        finding(
                            "NETWORK_TLS",
                            "Web通信・証明書",
                            "確認不能",
                            str(exc),
                            "URL・証明書・通信経路を確認する",
                        )
                    )
        else:
            for check in plan["checks"]:
                if time.monotonic() >= deadline:
                    rows.append(
                        finding(
                            check.upper(),
                            PROFILES[profile]["checks"][check],
                            "未実施",
                            "制限時間に達したため実施していません。",
                            "必要な検査を絞って再実行する",
                        )
                    )
                    continue
                try:
                    if check == "headers":
                        rows.extend(diagnose(self.web.fetch(scope)))
                    else:
                        rows.append(self._check(scope, check))
                except Rejected as exc:
                    rows.append(
                        finding(
                            check.upper(),
                            PROFILES[profile]["checks"][check],
                            "確認不能",
                            str(exc),
                            "通信経路や対象の応答を確認する",
                        )
                    )
        return {
            "findings": rows,
            "coverage": {
                "profile": profile,
                "scope": PROFILES[profile]["scope"],
                "checks": plan["checks"],
                "ports": plan["ports"],
                "not_tested": ["認証後の操作", "SQL等の入力攻撃", "侵入・権限昇格・横展開", "負荷試験"],
            },
        }

    def probe(self, scope, method, headers):
        if method not in ("GET", "OPTIONS", "TRACE"):
            raise Rejected("この検証で対応しないHTTPメソッドです")
        started = time.monotonic()
        try:
            ip = self.web.addresses(scope)[0]
        except OSError as exc:
            raise Rejected("接続先の名前解決を確認できませんでした") from exc
        connection = (
            PinnedHTTPS(scope.host, ip, scope.port, self.web.context)
            if scope.scheme == "https"
            else http.client.HTTPConnection(ip, scope.port, timeout=3)
        )
        connection.timeout = 3
        try:
            connection.connect()
            connection.request(
                method,
                scope.path,
                headers={
                    "Host": scope.host,
                    "User-Agent": "SecurityTesting/0.3 (manual limited check)",
                    "Accept-Encoding": "identity",
                    **headers,
                },
            )
            response = connection.getresponse()
            parts, total = [], 0
            while True:
                if time.monotonic() - started > 8:
                    raise Rejected("HTTP検証の制限時間に達しました")
                chunk = response.read1(min(16384, 65537 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > 65536:
                    raise Rejected("応答が検査サイズの上限を超えました")
                parts.append(chunk)
            body = b"".join(parts)
            # Only the selected response fields are consumed; cookies and page bodies are not persisted.
            return response.status, {k.lower(): v for k, v in response.getheaders()}, body
        except (OSError, http.client.HTTPException) as exc:
            raise Rejected("対象との接続またはHTTP応答を確認できませんでした") from exc
        finally:
            connection.close()

    def _check(self, scope, check):
        if check == "cors":
            status, h, _ = self.probe(scope, "GET", {"Origin": ORIGIN})
            if status != 200:
                return finding(
                    "CORS",
                    "別サイトからの読み取り許可",
                    "確認不能",
                    f"HTTP {status}のため検証未完了です。",
                    "正常応答するURLで再確認する",
                )
            bad = (
                h.get("access-control-allow-origin") == ORIGIN
                and h.get("access-control-allow-credentials", "").lower() == "true"
            )
            return finding(
                "CORS",
                "別サイトからの読み取り許可",
                "問題を検出" if bad else "問題を検出せず",
                "任意の検証Originを資格情報付きで許可する応答を確認。機密データの閲覧は未検証です。"
                if bad
                else "検証Originへの資格情報付き読み取り許可は観測されませんでした。",
                "許可するOriginを固定し、資格情報が必要な範囲だけ許可する",
                severity="中",
                explanation="別のサイトに、このサイトの応答を読ませる許可の設定です。",
                criteria="検証用Originの反映とAllow-Credentials:trueの組合せだけを確認します。認証情報は送りません。",
            )
        if check == "methods":
            status, h, _ = self.probe(scope, "OPTIONS", {})
            methods = sorted(
                set(h.get("allow", "").upper().replace(" ", "").split(","))
                & {"GET", "HEAD", "OPTIONS", "POST", "PUT", "DELETE", "PATCH", "TRACE", "CONNECT"}
            )
            return finding(
                "METHODS",
                "許可メソッドの応答",
                "確認不能",
                f"HTTP {status}。Allow表示：{', '.join(methods) or '記載なし'}。書き込み操作は実行していません。",
                "許可表示と実際の認証・認可設定を管理者が確認する",
                explanation="サイトにどの種類の操作を受け付けるか尋ねます。表示された操作が、実際に認証なしで使えるという意味ではありません。",
                criteria="OPTIONS応答だけを収集します。Allowの表示だけで書き込み可能とは判断しません。",
            )
        status, _, body = self.probe(scope, "TRACE", {"X-Security-Testing-Probe": MARKER})
        enabled = status == 200 and MARKER.encode() in body
        state = "問題を検出" if enabled else "問題を検出せず" if status in (403, 405, 501) else "確認不能"
        return finding(
            "TRACE",
            "TRACE応答",
            state,
            "検証用ヘッダーがTRACE応答に返りました。"
            if enabled
            else f"HTTP {status}。TRACE反射は確認されませんでした。",
            "不要なTRACEを無効にする",
            severity="低",
            explanation="送った通信の内容をそのまま返すデバッグ用の機能です。不要なら無効にし、情報を余分に返さないようにします。",
            criteria="秘密情報を含まない検証用ヘッダーの反射を確認します。Cookie等は送信・保存しません。",
        )
