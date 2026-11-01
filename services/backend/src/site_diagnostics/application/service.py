import hashlib
from datetime import datetime, timezone
from typing import Callable
from uuid import uuid4
from site_diagnostics.application.ports import Store, Fetcher, Publisher, Reports, Evaluator, PdfRenderer
from site_diagnostics.application.evaluation import evaluate
from site_diagnostics.domain.model import Scope, Rejected, NotFound, Conflict, FetchFailure, RULE_VERSION
from site_diagnostics.domain.rules import diagnose

TERMINAL = {"SUCCEEDED", "FAILED", "CANCELLED"}


class Service:
    def __init__(
        self,
        store: Store,
        fetcher: Fetcher,
        publisher: Publisher,
        reports: Reports,
        clock: Callable[[], float],
        evaluator: Evaluator | None = None,
        pdf: PdfRenderer | None = None,
    ):
        self.store, self.fetcher, self.publisher, self.reports, self.clock = (
            store,
            fetcher,
            publisher,
            reports,
            clock,
        )
        self.evaluator, self.pdf = evaluator, pdf

    def timestamp(self):
        return datetime.fromtimestamp(self.clock(), timezone.utc).isoformat()

    def require(self, owner, key):
        item = self.store.get(owner, key)
        if not item or item.get("deleted"):
            raise NotFound("対象が見つかりません")
        return item

    def save(self, item):
        self.store.commit([item])
        return item

    def audit(self, owner, action, entity):
        self.save(
            {
                "pk": owner,
                "sk": f"AUDIT#{uuid4()}",
                "action": action,
                "entity": entity,
                "at": self.timestamp(),
                "ttl": int(self.clock()) + 90 * 86400,
            }
        )

    def register(self, owner, url):
        scope = Scope.parse(url)
        target = {
            "pk": owner,
            "sk": f"TARGET#{uuid4()}",
            "url": scope.url,
            "host": scope.host,
            "created_at": self.timestamp(),
        }
        self.save(target)
        self.audit(owner, "target.register", target["sk"])
        return target

    def enqueue(self, owner, target_id, key):
        if not key or len(key) > 128:
            raise Rejected("Idempotency-Keyは1〜128文字です")
        digest = hashlib.sha256(key.encode()).hexdigest()
        old = self.store.get(owner, f"IDEMPOTENCY#{digest}")
        if old and old["ttl"] > self.clock():
            if old["target_id"] != target_id:
                raise Conflict("同じキーを異なる対象へ使用できません")
            return self.require(owner, f"JOB#{old['job_id']}")
        target = self.require(owner, f"TARGET#{target_id}")
        # A per-owner queue lock bounds outstanding jobs; cooldown additionally limits repeated runs.
        rate = self.store.get(owner, "RATE") or {"pk": owner, "sk": "RATE", "next_at": 0}
        if rate["next_at"] > self.clock():
            raise Conflict("次の診断まで60秒待ってください")
        active = [j for j in self.store.query(owner, "JOB#") if j["state"] not in TERMINAL]
        if len(active) >= 2:
            raise Conflict("同時受付上限は2件です")
        rate["next_at"] = int(self.clock()) + 60
        job_id = str(uuid4())
        job = {
            "pk": owner,
            "sk": f"JOB#{job_id}",
            "id": job_id,
            "target_id": target_id,
            "url": target["url"],
            "host": target["host"],
            "state": "QUEUED",
            "attempt": 0,
            "created_at": self.timestamp(),
            "rule_version": RULE_VERSION,
            "ttl": int(self.clock()) + 30 * 86400,
            "lease_until": 0,
            "work_pk": "QUEUED",
            "work_sk": str(int(self.clock())),
        }
        event = {
            "pk": owner,
            "sk": f"OUTBOX#{job_id}",
            "job_id": job_id,
            "work_pk": "OUTBOX",
            "work_sk": str(int(self.clock())),
            "sent": False,
        }
        idem = {
            "pk": owner,
            "sk": f"IDEMPOTENCY#{digest}",
            "job_id": job_id,
            "target_id": target_id,
            "ttl": int(self.clock()) + 86400,
        }
        if old:
            idem["rev"] = old["rev"]
        self.store.commit([job, event, idem, rate])
        return job

    def dispatch(self):
        for event in self.store.work("OUTBOX"):
            self.publisher.send(event["pk"], event["job_id"])
            event.update(sent=True, work_pk="SENT")
            try:
                self.save(event)
            except Conflict:
                pass  # A duplicate delivery is safe; worker is fenced.

    def cancel(self, owner, job_id):
        job = self.require(owner, f"JOB#{job_id}")
        if job["state"] not in TERMINAL:
            job["state"] = "CANCEL_REQUESTED"
            self.save(job)
        return job

    def visible_job(self, owner, job_id):
        job = self.require(owner, f"JOB#{job_id}")
        self.require(owner, f"TARGET#{job['target_id']}")
        return job

    def remove_scan(self, owner, job_id):
        job = self.visible_job(owner, job_id)
        job.update(deleted=True, deleted_at=self.timestamp(), work_pk="DELETED")
        if job["state"] not in TERMINAL:
            job.update(state="CANCELLED", finished_at=self.timestamp())
        self.save(job)  # CAS revision fences an already-running worker.
        self.audit(owner, "scan.delete", job_id)

    def remove(self, owner, target_id):
        target = self.require(owner, f"TARGET#{target_id}")
        target.update(deleted=True, deleted_at=self.timestamp(), ttl=int(self.clock()) + 30 * 86400)
        self.save(target)  # Tombstone is the write barrier; running workers recheck it before commit.
        for job in self.store.query(owner, "JOB#"):
            if job["target_id"] == target_id and not job.get("deleted"):
                self.cancel(owner, job["id"])
        self.audit(owner, "target.delete", target["sk"])

    def finish(self, job, state, **fields):
        job.update(state=state, work_pk=state, finished_at=self.timestamp(), **fields)
        return self.save(job)

    def execute(self, owner, job_id):
        job = self.store.get(owner, f"JOB#{job_id}")
        if not job or job.get("deleted"):
            return
        if job["state"] in TERMINAL:
            return
        if job["state"] == "CANCEL_REQUESTED":
            self.finish(job, "CANCELLED")
            return
        if job["state"] == "RUNNING" and job["lease_until"] > self.clock():
            raise Conflict("既に実行中です")
        target = self.store.get(owner, f"TARGET#{job['target_id']}")
        if not target or target.get("deleted"):
            self.finish(job, "CANCELLED")
            return
        lock = self.store.get("HOST", job["host"]) or {"pk": "HOST", "sk": job["host"], "until": 0}
        if lock["until"] > self.clock():
            raise Conflict("対象ホストは実行中または待機期間です")
        if job["attempt"] >= 3:
            self.finish(job, "FAILED", error="再試行上限です")
            return
        job.update(
            state="RUNNING",
            work_pk="RUNNING",
            lease_until=int(self.clock()) + 90,
            attempt=job["attempt"] + 1,
            rule_version=RULE_VERSION,
        )
        lock["until"] = int(self.clock()) + 120
        self.store.commit([job, lock])
        fence = job["rev"]
        try:
            observed = self.fetcher.fetch(Scope.parse(job["url"]))
            findings = diagnose(observed)
            for finding in findings:
                finding.update(target=job["url"], checked_at=self.timestamp())
        except Rejected as exc:
            current = self.store.get(owner, f"JOB#{job_id}")
            if not current or current.get("deleted"):
                return
            if current["rev"] != fence:
                if current["state"] == "CANCEL_REQUESTED":
                    self.finish(current, "CANCELLED")
                    return
                raise Conflict("実行権が失効しました") from exc
            fields = {"error": str(exc)}
            if isinstance(exc, FetchFailure):
                fields["error_code"] = exc.code
            self.finish(job, "FAILED", **fields)
            return
        current = self.store.get(owner, f"JOB#{job_id}")
        if not current or current.get("deleted"):
            return
        target = self.store.get(owner, f"TARGET#{job['target_id']}")
        if current["state"] == "CANCEL_REQUESTED" or not target or target.get("deleted"):
            self.finish(current, "CANCELLED")
            return
        if current["rev"] != fence or current["lease_until"] <= self.clock():
            raise Conflict("実行権が失効しました")
        report = {
            "job_id": job_id,
            "findings": findings,
            "coverage": {
                "pages": 1,
                "scope": "単一URLの静的HTML",
                "not_tested": ["認証後", "業務ロジック", "内部構成", "動的DOM"],
            },
        }
        from collections import Counter

        counts = Counter(f["status"] for f in findings)
        detected = [f for f in findings if f["status"] == "問題を検出"]
        report["summary"] = {
            "severity_counts": dict(Counter(f["severity"] for f in detected)),
            "highest_severity": next((f["severity"] for f in findings if f["status"] == "問題を検出"), None),
            "cvss_severity_counts": {name: 0 for name in ("なし", "低", "中", "高", "緊急")},
            "configuration_count": counts["問題を検出"],
            "unassessed_count": counts["問題を検出"],
            "check_status_counts": dict(counts),
        }
        if self.evaluator:
            report = evaluate(report, self.evaluator, job["url"])
            findings = report["findings"]
        # Store report first. It cannot be read until the fenced terminal transaction succeeds.
        report_key = f"{job_id}-{fence}"
        self.reports.put(owner, report_key, report)
        current.update(
            state="SUCCEEDED",
            work_pk="SUCCEEDED",
            finished_at=self.timestamp(),
            report_key=report_key,
            summary={"count": len(findings)},
            findings=findings,
        )
        self.store.commit([current, target])

    def result(self, owner, job_id):
        job = self.visible_job(owner, job_id)
        if job["state"] != "SUCCEEDED":
            raise Conflict("診断結果はまだ確定していません")
        report = self.reports.get(owner, job["report_key"])
        return evaluate(report, self.evaluator, job["url"]) if self.evaluator else report

    def document(self, owner, job_id):
        job = self.visible_job(owner, job_id)
        if job["state"] not in TERMINAL:
            raise Conflict("診断終了後にPDFをダウンロードできます")
        if not self.pdf:
            raise RuntimeError("PDF renderer is not configured")
        return self.pdf.render(job, self.result(owner, job_id) if job["state"] == "SUCCEEDED" else None)

    def recover(self):
        self.dispatch()
        for job in self.store.work("RUNNING"):
            if job["lease_until"] < self.clock():
                if job["attempt"] >= 3:
                    self.finish(job, "FAILED", error="実行時間超過・再試行上限")
                else:
                    self.publisher.send(job["pk"], job["id"])
        for job in self.store.work("QUEUED"):
            self.publisher.send(job["pk"], job["id"])
