from unittest.mock import Mock
import pytest
from site_diagnostics.bootstrap import container


def test_local_sdk_uses_dummy_credentials_even_inside_lambda(monkeypatch):
    container.service.cache_clear()
    monkeypatch.setenv("APP_ENV", "local")
    monkeypatch.setenv("AWS_ENDPOINT_URL", "http://localstack:4566")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "lambda-injected-identity")
    monkeypatch.setenv("TABLE_NAME", "test")
    monkeypatch.setenv("QUEUE_URL", "http://localstack:4566/000000000000/test")
    monkeypatch.setenv("REPORT_BUCKET", "reports-test")
    client = Mock()
    monkeypatch.setattr(container.boto3, "client", client)
    container.service()
    for call in client.call_args_list:
        assert call.kwargs["aws_access_key_id"] == "test"
        assert call.kwargs["aws_secret_access_key"] == "test"
        assert call.kwargs["endpoint_url"] == "http://localstack:4566"
    container.service.cache_clear()


def test_production_rejects_local_endpoint(monkeypatch):
    container.service.cache_clear()
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("AWS_ENDPOINT_URL", "http://localstack:4566")
    with pytest.raises(RuntimeError):
        container.service()
    container.service.cache_clear()
