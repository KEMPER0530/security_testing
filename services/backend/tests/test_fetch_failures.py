import errno
import http.client
import socket
import ssl
from unittest.mock import Mock

import pytest
from site_diagnostics.adapters.outbound import web
from site_diagnostics.adapters.inbound.dto import JobResponse
from site_diagnostics.domain.model import FetchFailure, Scope


@pytest.mark.parametrize(
    "error,code",
    [
        (ssl.SSLCertVerificationError(1, "sensitive-certificate-detail"), "TLS_CERTIFICATE"),
        (ssl.SSLError(1, "sensitive-tls-detail"), "TLS_HANDSHAKE"),
        (TimeoutError("sensitive-timeout-detail"), "CONNECT_TIMEOUT"),
        (ConnectionRefusedError(errno.ECONNREFUSED, "sensitive-network-detail"), "CONNECTION_REFUSED"),
        (OSError(errno.ENETUNREACH, "sensitive-network-detail"), "NETWORK_UNREACHABLE"),
        (OSError(errno.ECONNRESET, "sensitive-network-detail"), "CONNECTION_FAILED"),
    ],
)
def test_connection_failures_are_distinct_and_do_not_log_sensitive_details(monkeypatch, caplog, error, code):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))],
    )
    connection = Mock()
    connection.connect.side_effect = error
    monkeypatch.setattr(web, "PinnedHTTPS", Mock(return_value=connection))
    fetcher = web.SafeFetcher()
    with pytest.raises(FetchFailure) as result:
        fetcher.fetch(Scope.parse("https://example.com/"))
    assert result.value.code == code
    assert result.value.__cause__ is error
    connection.close.assert_called_once()
    connection.request.assert_not_called()
    assert fetcher.context.verify_mode == ssl.CERT_REQUIRED
    assert fetcher.context.check_hostname
    assert '"code": "' + code + '"' in caplog.text
    assert "sensitive-" not in caplog.text
    assert "example.com" not in caplog.text


def test_dns_failure_is_identified_before_connecting(monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo", Mock(side_effect=socket.gaierror(socket.EAI_NONAME, "unresolved"))
    )
    connect = Mock()
    monkeypatch.setattr(web, "PinnedHTTPS", connect)
    with pytest.raises(FetchFailure) as result:
        web.SafeFetcher().fetch(Scope.parse("https://example.com/"))
    assert result.value.code == "DNS_FAILURE"
    connect.assert_not_called()


@pytest.mark.parametrize(
    "error,code",
    [(TimeoutError(), "RESPONSE_TIMEOUT"), (http.client.BadStatusLine("private"), "HTTP_PROTOCOL")],
)
def test_response_failures_are_not_reported_as_dns(monkeypatch, error, code):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))],
    )
    connection = Mock()
    connection.getresponse.side_effect = error
    monkeypatch.setattr(web, "PinnedHTTPS", Mock(return_value=connection))
    with pytest.raises(FetchFailure) as result:
        web.SafeFetcher().fetch(Scope.parse("https://example.com/"))
    assert result.value.code == code
    connection.close.assert_called_once()


def test_worker_persists_failure_code_and_api_exposes_it(ready):
    service, target, fetcher, _ = ready

    def fail(scope):
        raise FetchFailure("TLS_CERTIFICATE", "HTTPS証明書を検証できませんでした")

    fetcher.fetch = fail
    job = service.enqueue("alice", target, "certificate-failure")
    service.execute("alice", job["id"])
    current = service.require("alice", f"JOB#{job['id']}")
    response = JobResponse.model_validate(current)
    assert response.state == "FAILED"
    assert response.error_code == "TLS_CERTIFICATE"
    assert response.findings is None
