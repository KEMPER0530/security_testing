from site_diagnostics.adapters.inbound.dto import (
    TargetResponse,
    TargetPage,
    JobResponse,
    JobPage,
    ResultResponse,
    AiAnalysisStatusResponse,
    AwsConnectionResponse,
)
import os
import json
import html
from functools import lru_cache
from typing import Annotated, Literal
from uuid import uuid4
import jwt
from fastapi import FastAPI, Depends, Header, HTTPException, Request, Query
from fastapi.responses import JSONResponse, HTMLResponse, Response
from fastapi.exceptions import RequestValidationError
import logging
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, ConfigDict
from mangum import Mangum
from site_diagnostics.bootstrap.container import service
from site_diagnostics.domain.model import Rejected, NotFound, Conflict
from site_diagnostics.domain.plans import PROFILES, PORTS, plan_for


class Register(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str = Field(max_length=2048)


class Scan(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_id: str
    profile: Literal["web", "network", "pentest", "host", "cloud"] = "web"
    checks: list[str] | None = Field(default=None, max_length=6)
    ports: list[int] | None = Field(default=None, max_length=8)
    resources: dict[str, list[str]] | None = None
    region: str = Field(default="ap-northeast-1", max_length=30)
    authorized: bool = False


class AwsRole(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role_arn: str = Field(max_length=200)


@lru_cache
def jwks():
    issuer = os.environ["OIDC_ISSUER"]
    if os.environ.get("APP_ENV") != "local" and not issuer.startswith("https://cognito-idp."):
        raise RuntimeError("Production requires Cognito HTTPS issuer")
    url = os.environ.get("OIDC_JWKS_URL", issuer + "/.well-known/jwks.json")
    if os.environ.get("APP_ENV") != "local" and url != issuer + "/.well-known/jwks.json":
        raise RuntimeError("Production cannot override JWKS URL")
    return jwt.PyJWKClient(url, cache_jwk_set=True, lifespan=300)


def user(authorization: Annotated[str, Header()] = "") -> str:
    try:
        if not authorization.startswith("Bearer "):
            raise ValueError()
        token = authorization[7:]
        key = jwks().get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            key.key,
            algorithms=["RS256"],
            issuer=os.environ["OIDC_ISSUER"],
            options={"verify_aud": False, "require": ["exp", "iat", "sub", "iss"]},
        )
        if claims.get("token_use", "access" if os.environ.get("APP_ENV") == "local" else "") != "access":
            raise ValueError()
        if claims.get("client_id", claims.get("azp")) != os.environ["OIDC_CLIENT_ID"]:
            raise ValueError()
        required_scope = os.environ.get("OIDC_REQUIRED_SCOPE", "openid")
        if required_scope not in claims.get("scope", "").split():
            raise ValueError()
        required_group = os.environ.get("OIDC_REQUIRED_GROUP")
        groups = claims.get("cognito:groups", [])
        if required_group and (not isinstance(groups, list) or required_group not in groups):
            raise ValueError()
        return claims["sub"]
    except (jwt.PyJWTError, ValueError, KeyError) as exc:
        logging.getLogger(__name__).warning(
            json.dumps(
                {
                    "event": "authentication_rejected",
                    "error_type": type(exc).__name__,
                    "bearer_present": authorization.startswith("Bearer "),
                }
            )
        )
        raise HTTPException(401, "有効なアクセストークンが必要です") from exc


app = FastAPI(title="Security Testing API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.environ.get("CORS_ORIGIN", "http://localhost:5173")],
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "Idempotency-Key"],
)


@app.middleware("http")
async def request_id(request: Request, call_next):
    request.state.request_id = str(uuid4())
    response = await call_next(request)
    response.headers["X-Request-ID"] = request.state.request_id
    response.headers["Cache-Control"] = "no-store"
    return response


async def business_error(request: Request, exc: Exception):
    status = 404 if isinstance(exc, NotFound) else 409 if isinstance(exc, Conflict) else 422
    return JSONResponse(
        {"error": {"code": type(exc).__name__, "message": str(exc), "request_id": request.state.request_id}},
        status_code=status,
    )


for error in (Rejected, NotFound, Conflict):
    app.add_exception_handler(error, business_error)


@app.exception_handler(HTTPException)
async def http_error(request: Request, exc: HTTPException):
    return JSONResponse(
        {"error": {"code": "HttpError", "message": str(exc.detail), "request_id": request.state.request_id}},
        status_code=exc.status_code,
    )


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    return JSONResponse(
        {
            "error": {
                "code": "InvalidInput",
                "message": "入力項目を確認してください",
                "request_id": request.state.request_id,
            }
        },
        status_code=422,
    )


@app.exception_handler(Exception)
async def internal_error(request: Request, exc: Exception):
    logging.getLogger(__name__).error(
        json.dumps({"request_id": request.state.request_id, "error_type": type(exc).__name__})
    )
    return JSONResponse(
        {
            "error": {
                "code": "InternalError",
                "message": "処理に失敗しました",
                "request_id": request.state.request_id,
            }
        },
        status_code=500,
    )


User = Annotated[str, Depends(user)]


@app.get("/health")
def health():
    return {"status": "ok", "version": "0.1.0"}


@app.get("/v1/targets", response_model=TargetPage)
def targets(owner: User, offset: int = Query(0, ge=0), limit: int = Query(20, ge=1, le=100)):
    rows = [i for i in service().store.query(owner, "TARGET#") if not i.get("deleted")]
    return {
        "items": rows[offset : offset + limit],
        "next_offset": offset + limit if len(rows) > offset + limit else None,
    }


@app.post("/v1/targets", status_code=201, response_model=TargetResponse)
def register(body: Register, owner: User):
    return service().register(owner, body.url)


@app.get("/v1/targets/{target_id}", response_model=TargetResponse)
def target(target_id: str, owner: User):
    return service().require(owner, f"TARGET#{target_id}")


@app.delete("/v1/targets/{target_id}", status_code=204)
def remove(target_id: str, owner: User):
    service().remove(owner, target_id)


@app.get("/v1/diagnostic-profiles")
def profiles(owner: User):
    return {"profiles": PROFILES, "ports": PORTS}


@app.post("/v1/targets/{target_id}/aws-connection", response_model=AwsConnectionResponse)
def prepare_aws(target_id: str, owner: User):
    return service().aws_connection(owner, target_id, prepare=True)


@app.get("/v1/targets/{target_id}/aws-connection", response_model=AwsConnectionResponse)
def read_aws(target_id: str, owner: User):
    return service().aws_connection(owner, target_id)


@app.put("/v1/targets/{target_id}/aws-connection", response_model=AwsConnectionResponse)
def configure_aws(target_id: str, body: AwsRole, owner: User):
    return service().aws_connection(owner, target_id, arn=body.role_arn)


@app.post("/v1/scans", status_code=202, response_model=JobResponse)
def enqueue(body: Scan, owner: User, idempotency_key: Annotated[str, Header(min_length=1, max_length=128)]):
    return service().enqueue(owner, body.target_id, idempotency_key, body.model_dump(exclude={"target_id"}))


@app.get("/v1/scans", response_model=JobPage)
def scans(owner: User, offset: int = Query(0, ge=0), limit: int = Query(20, ge=1, le=100)):
    rows = sorted(service().store.query(owner, "JOB#"), key=lambda i: i["created_at"], reverse=True)
    rows = [
        row
        for row in rows
        if not row.get("deleted")
        and (target := service().store.get(owner, f"TARGET#{row['target_id']}"))
        and not target.get("deleted", False)
    ]
    return {
        "items": rows[offset : offset + limit],
        "next_offset": offset + limit if len(rows) > offset + limit else None,
    }


@app.get("/v1/scans/{job_id}", response_model=JobResponse)
def scan(job_id: str, owner: User):
    return service().visible_job(owner, job_id)


@app.delete("/v1/scans/{job_id}", status_code=204)
def remove_scan(job_id: str, owner: User):
    service().remove_scan(owner, job_id)


@app.post("/v1/scans/{job_id}/cancel", response_model=JobResponse)
def cancel(job_id: str, owner: User):
    service().visible_job(owner, job_id)
    return service().cancel(owner, job_id)


@app.get(
    "/v1/scans/{job_id}/report.pdf",
    responses={200: {"content": {"application/pdf": {"schema": {"type": "string", "format": "binary"}}}}},
    response_class=Response,
)
def pdf_report(job_id: str, owner: User):
    data = service().document(owner, job_id)
    # Filename is fixed; user input never becomes a response header.
    return Response(
        data,
        media_type="application/pdf",
        headers={
            "Content-Disposition": 'attachment; filename="security-testing-report.pdf"',
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.get("/v1/scans/{job_id}/results", response_model=ResultResponse)
def result(job_id: str, owner: User):
    return service().result(owner, job_id)


@app.get("/v1/scans/{job_id}/ai-analysis", response_model=AiAnalysisStatusResponse)
def ai_analysis_status(job_id: str, owner: User):
    # No enable flag or credentials can activate an outbound call in this release.
    service().visible_job(owner, job_id)
    return {
        "job_id": job_id,
        "status": "under_construction",
        "provider": "openai",
        "message": "AI分析は工事中です",
        "result": None,
    }


@app.get("/v1/scans/{job_id}/report")
def report(job_id: str, owner: User, format: Literal["json", "html"] = "json"):
    data = service().result(owner, job_id)
    if format == "html":
        text = html.escape(json.dumps(data, ensure_ascii=False, indent=2))
        return HTMLResponse(
            f'<!doctype html><html lang="ja"><meta charset="utf-8"><title>診断結果</title><h1>診断結果</h1><pre>{text}</pre></html>',
            headers={"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'"},
        )
    return data


@app.get("/v1/scans/{job_id}/comparison")
def comparison(job_id: str, previous_id: str, owner: User):
    current, previous = service().result(owner, job_id), service().result(owner, previous_id)
    a, b = service().require(owner, f"JOB#{job_id}"), service().require(owner, f"JOB#{previous_id}")
    if (
        a["target_id"] != b["target_id"]
        or a["rule_version"] != b["rule_version"]
        or a.get("plan", plan_for()) != b.get("plan", plan_for())
        or a.get("aws_connection") != b.get("aws_connection")
    ):
        raise Conflict("同一対象・ルール版・検査範囲・AWS接続の結果だけ比較できます")
    old = {f["rule_id"]: f for f in previous["findings"]}
    changes = []
    for f in current["findings"]:
        before = old.get(f["rule_id"])
        state = "未確認" if f["status"] in ("未実施", "確認不能", "対象外") else "継続"
        if f["status"] == "問題を検出" and (not before or before["status"] != "問題を検出"):
            state = "新規"
        elif f["status"] == "問題を検出せず" and before and before["status"] == "問題を検出":
            state = "解消"
        changes.append({"rule_id": f["rule_id"], "change": state})
    return {"items": changes}


handler = Mangum(app, lifespan="off")
