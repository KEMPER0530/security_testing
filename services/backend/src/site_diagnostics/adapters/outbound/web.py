"""DNS checked once, connection pinned to the validated IP; no proxy environment use."""

import http.client
import errno
import json
import logging
import ipaddress
import socket
import ssl
import time
from urllib.parse import urlsplit, urljoin
from site_diagnostics.domain.model import Observation, Rejected, FetchFailure

LIMIT = 262144
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, ip, port, context):
        super().__init__(host, port, timeout=5, context=context)
        self.ip = ip
        self.context = context

    def connect(self):
        raw = socket.create_connection((self.ip, self.port), timeout=self.timeout)
        try:
            self.sock = self.context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


class SafeFetcher:
    def __init__(self, fixture_ip=None, fixture_host=None, context=None):
        self.fixture_ip, self.fixture_host = fixture_ip, fixture_host
        self.context = context or ssl.create_default_context()

    def addresses(self, scope):
        addresses = sorted(
            {entry[4][0] for entry in socket.getaddrinfo(scope.host, scope.port, type=socket.SOCK_STREAM)}
        )
        if not addresses:
            raise FetchFailure(
                "DNS_FAILURE",
                "対象ドメインのIPアドレスを取得できませんでした。URLとDNS設定を確認してください。",
            )
        for addr in addresses:
            ip = ipaddress.ip_address(addr)
            fixture = scope.host == self.fixture_host and addr == self.fixture_ip
            if not ip.is_global and not fixture:
                raise Rejected("DNSが禁止された接続先を返しました")
        # Validate every DNS answer before selecting one. Non-VPC Lambda has IPv4
        # egress; plain string sorting can put an unusable IPv6 address first.
        ordered = sorted(addresses, key=lambda addr: (ipaddress.ip_address(addr).version, addr))
        versions = [ipaddress.ip_address(addr).version for addr in ordered]
        if 4 in versions and 6 in versions:
            logger.info(
                json.dumps(
                    {
                        "event": "target_address_selection",
                        "ipv4_count": versions.count(4),
                        "ipv6_count": versions.count(6),
                        "selected_version": versions[0],
                    }
                )
            )
        return ordered

    def fetch(self, scope):
        started = time.monotonic()
        connection: http.client.HTTPConnection | None = None
        phase = "dns"
        try:
            ip = self.addresses(scope)[0]
            phase = "connect"
            if scope.scheme == "https":
                connection = PinnedHTTPS(scope.host, ip, scope.port, self.context)
            else:
                connection = http.client.HTTPConnection(ip, scope.port, timeout=5)
            connection.connect()
            cert = (
                connection.sock.getpeercert()
                if scope.scheme == "https" and isinstance(connection.sock, ssl.SSLSocket)
                else None
            )
            tls = {"valid": True, "expires": cert.get("notAfter")} if cert else {}
            phase = "response"
            connection.request(
                "GET",
                scope.path,
                headers={
                    "Host": scope.host,
                    "Accept-Encoding": "identity",
                    "User-Agent": "SecurityTesting/0.2 (+public-page-check)",
                },
            )
            response = connection.getresponse()
            if 300 <= response.status < 400:
                location = urlsplit(urljoin(scope.url, response.getheader("Location", "")))
                if (
                    scope.scheme == "http"
                    and location.scheme == "https"
                    and location.hostname == scope.host
                    and (location.port or 443) == 443
                    and not location.username
                ):
                    return Observation(
                        scope.url,
                        {k.lower(): v for k, v in response.getheaders()},
                        [],
                        "",
                        redirect_https=True,
                    )
                raise FetchFailure(
                    "REDIRECT_NOT_FOLLOWED",
                    "登録URLが別のページへ転送されました。最終的に表示されるURLを登録してください。転送先へは接続していません。",
                )
            if response.status != 200:
                raise FetchFailure(
                    "HTTP_STATUS",
                    f"対象サイトがHTTP {response.status}を返しました。公開ページのURLとアクセス制限を確認してください。",
                )
            if response.getheader("Content-Encoding", "identity").lower() != "identity":
                raise FetchFailure(
                    "UNSUPPORTED_ENCODING",
                    "対象サイトが圧縮された応答を返したため、現在の診断では読み取れませんでした。",
                )
            phase = "read"
            parts = []
            total = 0
            while True:
                if time.monotonic() - started > 15:
                    raise FetchFailure(
                        "FETCH_TIMEOUT",
                        "ページの取得が上限15秒を超えました。時間を置いて再実行してください。",
                    )
                chunk = response.read1(min(16384, LIMIT + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > LIMIT:
                    raise FetchFailure(
                        "BODY_TOO_LARGE", "ページが取得上限256KiBを超えたため、診断を完了できませんでした。"
                    )
                parts.append(chunk)
            return Observation(
                scope.url,
                {k.lower(): v for k, v in response.getheaders()},
                response.headers.get_all("Set-Cookie", []),
                b"".join(parts).decode("utf-8", "replace"),
                tls,
                redirect_https=False if scope.scheme == "http" else None,
            )
        except socket.gaierror as exc:
            raise self.failure(
                "DNS_FAILURE",
                "診断サーバーから対象ドメインのIPアドレスを取得できませんでした。URLとDNS設定を確認してください。",
                phase,
                exc,
            ) from exc
        except ssl.SSLCertVerificationError as exc:
            raise self.failure(
                "TLS_CERTIFICATE",
                "対象サイトのHTTPS証明書を検証できませんでした。有効期限・対象ドメイン・中間証明書を確認してください。",
                phase,
                exc,
            ) from exc
        except ssl.SSLError as exc:
            raise self.failure(
                "TLS_HANDSHAKE",
                "対象サイトとのHTTPS通信を開始できませんでした。TLS設定や通信制限を確認してください。",
                phase,
                exc,
            ) from exc
        except TimeoutError as exc:
            message = (
                "対象サイトへの接続が時間切れになりました。通信状態や接続制限を確認してください。"
                if phase == "connect"
                else "対象サイトからの応答が時間切れになりました。時間を置いて再実行してください。"
            )
            raise self.failure(
                "CONNECT_TIMEOUT" if phase == "connect" else "RESPONSE_TIMEOUT", message, phase, exc
            ) from exc
        except ConnectionRefusedError as exc:
            raise self.failure(
                "CONNECTION_REFUSED",
                "対象サイトに接続を拒否されました。公開ポートやアクセス制限を確認してください。",
                phase,
                exc,
            ) from exc
        except OSError as exc:
            unreachable = exc.errno in (
                errno.ENETUNREACH,
                errno.EHOSTUNREACH,
                errno.EAFNOSUPPORT,
                errno.EADDRNOTAVAIL,
            )
            code = "NETWORK_UNREACHABLE" if unreachable else "CONNECTION_FAILED"
            message = (
                "診断サーバーから接続先ネットワークへ到達できませんでした。IPv4・IPv6の到達性と通信経路を確認してください。"
                if unreachable
                else "対象サイトとの接続が失敗または切断されました。通信状態や接続制限を確認してください。"
            )
            raise self.failure(code, message, phase, exc) from exc
        except (http.client.HTTPException, UnicodeError) as exc:
            raise self.failure(
                "HTTP_PROTOCOL",
                "対象サイトのHTTP通信を処理できませんでした。URLとサーバーの応答形式を確認してください。",
                phase,
                exc,
            ) from exc
        finally:
            if connection:
                connection.close()

    @staticmethod
    def failure(code, message, phase, exc):
        # No URL, credentials, certificate subject, response headers, or body in logs.
        details = {
            "event": "target_fetch_failed",
            "code": code,
            "phase": phase,
            "exception_type": type(exc).__name__,
        }
        if isinstance(getattr(exc, "errno", None), int):
            details["errno"] = exc.errno
        if isinstance(getattr(exc, "verify_code", None), int):
            details["verify_code"] = exc.verify_code
        logger.warning(json.dumps(details))
        return FetchFailure(code, message)
