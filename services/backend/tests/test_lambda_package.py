"""Exercise SDK client construction using only the models shipped to Lambda."""

import ast
import importlib.util
import shutil
from pathlib import Path

import boto3
import botocore
import botocore.session
from botocore.loaders import Loader


def test_trimmed_models_support_all_runtime_clients(tmp_path):
    root = Path(__file__).resolve().parents[3]
    spec = importlib.util.spec_from_file_location("package_lambda", root / "scripts/package_lambda.py")
    package = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(package)
    data = tmp_path / "botocore" / "data"
    shutil.copytree(Path(botocore.__file__).parent / "data", data)
    package.trim_sdk_models(tmp_path)
    assert (data / "endpoints.json").is_file()
    assert (data / "partitions.json").is_file()
    assert {path.name for path in data.iterdir() if path.is_dir()} == package.RUNTIME_AWS_SERVICES
    # Default model paths are disabled so the full developer SDK cannot mask a missing model.
    core = botocore.session.Session()
    core.register_component(
        "data_loader", Loader(extra_search_paths=[str(data)], include_default_search_paths=False)
    )
    session = boto3.Session(botocore_session=core)
    source = ast.parse((root / "services/backend/src/site_diagnostics/bootstrap/container.py").read_text())
    used = {
        node.args[0].value
        for node in ast.walk(source)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "boto3"
        and node.func.attr == "client"
        and node.args
        and isinstance(node.args[0], ast.Constant)
    }
    assert used <= package.RUNTIME_AWS_SERVICES, "Add models when a runtime client is added"
    for service in used:
        client = session.client(
            service,
            region_name="ap-northeast-1",
            aws_access_key_id="test",
            aws_secret_access_key="test",
            endpoint_url="http://127.0.0.1:9",
        )
        assert client.meta.service_model.service_name == service
        client.close()
