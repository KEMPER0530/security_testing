"""Deployment secrets never become public example settings or output."""

import importlib.util
import json
from pathlib import Path
import pytest


def writer():
    source = Path(__file__).resolve().parents[3] / "scripts/write_production_config.py"
    spec = importlib.util.spec_from_file_location("write_production_config", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("raw", ["", "{}", "not-json", "[]", '{"account":"111122223333"}'])
def test_invalid_secret_never_creates_a_config(tmp_path, monkeypatch, raw):
    module = writer()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PRODUCTION_CONFIG_JSON", raw)
    with pytest.raises(SystemExit):
        module.main()
    assert not (tmp_path / "infra/cdk/production.json").exists()


def test_example_is_rejected_and_valid_secret_is_private(tmp_path, monkeypatch, capsys):
    module = writer()
    config = json.loads(
        (Path(__file__).resolve().parents[3] / "infra/cdk/production.example.json").read_text()
    )
    monkeypatch.chdir(tmp_path)
    (tmp_path / "infra/cdk").mkdir(parents=True)
    monkeypatch.setenv("PRODUCTION_CONFIG_JSON", json.dumps(config))
    with pytest.raises(SystemExit):
        module.main()
    config.update(account="222233334444", domain="app.project.test")
    monkeypatch.setenv("PRODUCTION_CONFIG_JSON", json.dumps(config))
    module.main()
    path = tmp_path / "infra/cdk/production.json"
    assert path.stat().st_mode & 0o777 == 0o600
    assert json.loads(path.read_text()) == config
    assert config["account"] not in capsys.readouterr().out
