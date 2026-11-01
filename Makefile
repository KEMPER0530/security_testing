.DEFAULT_GOAL := bootstrap
export UV_CACHE_DIR ?= /tmp/security-testing-uv
export JSII_RUNTIME_PACKAGE_CACHE_ROOT ?= /tmp/security-testing-jsii
export PYTHONPATH := services/backend/src
.PHONY: bootstrap local-up local-down local-deploy package synth dev-api dev-web test check generate
.PHONY: aws-initial aws-app github-production
AWS_PROFILE ?= default
aws-initial:
	.venv/bin/python scripts/aws_deploy.py --initial --profile $(AWS_PROFILE)
aws-app:
	.venv/bin/python scripts/aws_deploy.py --profile $(AWS_PROFILE)
github-production:
	.venv/bin/python scripts/configure_github_production.py --profile $(AWS_PROFILE)
bootstrap:
	uv sync --python 3.13 --all-packages --frozen
	pnpm install --frozen-lockfile
local-up:
	docker compose --env-file .env up -d --wait
	.venv/bin/python scripts/configure_identity.py
local-down:
	docker compose --env-file .env stop
package:
	.venv/bin/python scripts/package_lambda.py
synth:
	pnpm exec cdk synth --quiet
generate:
	.venv/bin/python scripts/export_openapi.py
	pnpm generate
local-deploy: package synth
	.venv/bin/python scripts/local_deploy.py
dev-api:
	.venv/bin/uvicorn site_diagnostics.adapters.inbound.api:app --host 127.0.0.1 --port 8000 --no-access-log --env-file .env
dev-web:
	pnpm dev
test:
	.venv/bin/pytest -q
	pnpm test
check:
	.venv/bin/ruff check services infra scripts
	.venv/bin/mypy services/backend/src
	.venv/bin/lint-imports
	pnpm lint
	pnpm build
