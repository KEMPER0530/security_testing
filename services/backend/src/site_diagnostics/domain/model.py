"""Pure business rules: no SDK, framework, or network imports."""

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit
import ipaddress

RULE_VERSION = "2026-11-01.2"


class Rejected(Exception):
    pass


class FetchFailure(Rejected):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class NotFound(Exception):
    pass


class Conflict(Exception):
    pass


@dataclass(frozen=True)
class Scope:
    url: str
    host: str
    scheme: str
    port: int
    path: str

    @classmethod
    def parse(cls, url: str) -> "Scope":
        if any(ord(c) <= 32 for c in url) or "\\" in url:
            raise Rejected("URLに制御文字や空白を含められません")
        try:
            p = urlsplit(url)
            host = (p.hostname or "").encode("idna").decode("ascii").lower().rstrip(".")
            port = p.port or (443 if p.scheme == "https" else 80)
        except (ValueError, UnicodeError) as exc:
            raise Rejected("URLが不正です") from exc
        if p.scheme not in ("https", "http") or not host or p.username is not None or p.password is not None:
            raise Rejected("HTTP/HTTPSのホストを指定してください")
        if port != (443 if p.scheme == "https" else 80) or p.query or p.fragment:
            raise Rejected("標準ポートとクエリなしURLのみ対応します")
        if host == "localhost" or host.endswith(".localhost"):
            raise Rejected("ローカルホストは禁止です")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            address = None
        if address is not None and not address.is_global:
            raise Rejected("非公開IPは禁止です")
        authority = f"[{host}]" if ":" in host else host
        path = p.path or "/"
        if "%" in path or any(part in (".", "..") for part in path.split("/")):
            raise Rejected("曖昧なパスは指定できません")
        return cls(f"{p.scheme}://{authority}{path}", host, p.scheme, port, path)

    def permits(self, url: str) -> bool:
        try:
            other = Scope.parse(url)
        except Rejected:
            return False
        return (self.host, self.scheme, self.port, self.path) == (
            other.host,
            other.scheme,
            other.port,
            other.path,
        )


@dataclass
class Observation:
    url: str
    headers: dict[str, str]
    cookies: list[str]
    html: str
    tls: dict[str, Any] = field(default_factory=dict)
    redirect_https: bool | None = None


def severity(score: float | None) -> str:
    if score is None:
        return "未評価"
    if not 0 <= score <= 10:
        raise Rejected("CVSSは0から10の範囲です")
    if score == 0:
        return "なし"
    if score < 4:
        return "低"
    if score < 7:
        return "中"
    if score < 9:
        return "高"
    return "緊急"
