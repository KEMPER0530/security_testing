import shutil
import subprocess
from pathlib import Path

RUNTIME_AWS_SERVICES = frozenset({"dynamodb", "s3", "sqs"})


def trim_sdk_models(package: Path) -> None:
    """Keep runtime services and shared SDK configuration in the generated artifact."""
    models = package / "botocore" / "data"
    for service in RUNTIME_AWS_SERVICES:
        if not any((models / service).glob("*/service-2.json*")):
            raise RuntimeError(f"Missing required AWS service model: {service}")
    for sdk in ("botocore", "boto3"):
        data = package / sdk / "data"
        if data.is_dir():
            for path in data.iterdir():
                if path.is_dir() and path.name not in RUNTIME_AWS_SERVICES:
                    shutil.rmtree(path)


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    out = root / ".build/lambda"
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)
    requirements = root / ".build/requirements.txt"
    subprocess.run(
        [
            "uv",
            "export",
            "--package",
            "site-diagnostics",
            "--no-dev",
            "--no-emit-workspace",
            "--format",
            "requirements-txt",
            "--output-file",
            str(requirements),
        ],
        check=True,
        cwd=root,
        stdout=subprocess.DEVNULL,
    )
    subprocess.run(
        [
            "uv",
            "pip",
            "install",
            "--python-version",
            "3.13",
            "--python-platform",
            # Python 3.13 runs on Amazon Linux 2023 (glibc 2.34).
            "x86_64-manylinux_2_34",
            "--only-binary",
            ":all:",
            "--target",
            str(out),
            "-r",
            str(requirements),
        ],
        check=True,
    )
    shutil.copytree(
        root / "services/backend/src/site_diagnostics", out / "site_diagnostics", dirs_exist_ok=True
    )
    trim_sdk_models(out)
    print("Lambda SDK models: dynamodb, s3, sqs (shared configuration retained)")


if __name__ == "__main__":
    main()
