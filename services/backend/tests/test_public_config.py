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


def deployer():
    source = Path(__file__).resolve().parents[3] / "scripts/aws_deploy.py"
    spec = importlib.util.spec_from_file_location("aws_deploy", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_masking_uses_only_the_existing_describe_stacks_permission(monkeypatch, capsys):
    module = deployer()
    monkeypatch.setenv("GITHUB_ACTIONS", "true")

    class DescribeOnly:
        def __init__(self):
            self.calls = []

        def describe_stacks(self, *, StackName):
            self.calls.append(StackName)
            return {
                "Stacks": [
                    {
                        "StackId": "fake-stack-identifier",
                        "Outputs": [{"OutputKey": "ApiUrl", "OutputValue": "https://masked.test/"}],
                    }
                ]
            }

    cf = DescribeOnly()
    module.mask_existing_stacks(cf)
    assert cf.calls == ["SecurityTestingFoundation", "SecurityTestingApplication"]
    lines = capsys.readouterr().out.splitlines()
    assert all(line.startswith("::add-mask::") for line in lines)
    assert "::add-mask::fake-stack-identifier" in lines
    assert "::add-mask::https://masked.test/" in lines


def test_log_masks_escape_control_characters_and_are_ci_only(monkeypatch, capsys):
    module = deployer()
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    module.mask_identifiers(["value%with\nnewline"])
    assert not capsys.readouterr().out
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    module.mask_identifiers(["value%with\nnewline"])
    assert capsys.readouterr().out == "::add-mask::value%25with%0Anewline\n"
