"""HTTP response contracts. Storage keys are not business identifiers."""

from typing import Any, Literal
from pydantic import BaseModel, ConfigDict


class TargetResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    sk: str
    url: str
    host: str
    created_at: str


class TargetPage(BaseModel):
    items: list[TargetResponse]
    next_offset: int | None


class FindingResponse(BaseModel):
    model_config = ConfigDict(extra="allow")
    rule_id: str
    rule_version: str
    title: str
    status: Literal["問題を検出", "問題を検出せず", "確認不能", "未実施", "対象外"]
    evidence: str
    kind: str
    cvss: dict[str, Any] | None
    cvss_reason: str
    priority: str
    severity: str = "未評価"
    severity_basis: str = "旧レポートのため未評価"


class JobResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    target_id: str
    url: str
    state: Literal["QUEUED", "RUNNING", "CANCEL_REQUESTED", "CANCELLED", "FAILED", "SUCCEEDED"]
    created_at: str
    error: str | None = None
    error_code: str | None = None
    findings: list[FindingResponse] | None = None
    plan: dict[str, Any] | None = None


class JobPage(BaseModel):
    items: list[JobResponse]
    next_offset: int | None


class ResultResponse(BaseModel):
    plan: dict[str, Any] | None = None
    ipa_checklist: list[dict[str, Any]] | None = None
    attack_analysis: dict[str, Any] | None = None
    evaluation_policy_version: str | None = None
    job_id: str
    findings: list[FindingResponse]
    coverage: dict[str, Any]
    summary: dict[str, Any]


class AwsConnectionResponse(BaseModel):
    external_id: str
    role_arn: str | None
    template: dict[str, Any]
    status: str


class AiAnalysisStatusResponse(BaseModel):
    job_id: str
    status: Literal["under_construction"]
    provider: Literal["openai"]
    message: str
    result: None = None
