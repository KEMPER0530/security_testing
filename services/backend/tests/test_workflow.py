import pytest
from site_diagnostics.domain.model import Conflict, NotFound


def test_real_adapters_workflow(ready, environment):
    service, target_id, fetcher, clock = ready
    job = service.enqueue("alice", target_id, "first")
    assert service.enqueue("alice", target_id, "first")["id"] == job["id"]
    service.dispatch()
    _, _, _, sqs, url = environment
    assert sqs.receive_message(QueueUrl=url)["Messages"]
    service.execute("alice", job["id"])
    result = service.result("alice", job["id"])
    assert result["findings"]
    assert "assessment" not in result
    assert result["summary"]["highest_severity"] == "中"
    assert result["findings"][0]["status"] == "問題を検出"
    service.execute("alice", job["id"])  # Duplicate is terminal no-op.
    with pytest.raises(NotFound):
        service.result("bob", job["id"])


def test_public_target_can_scan_without_ownership_or_questionnaire(environment):
    service, *_ = environment
    target = service.register("alice", "https://example.com/")
    target_id = target["sk"].split("#")[1]
    assert "assessment" not in target
    assert "verified_until" not in target
    job = service.enqueue("alice", target_id, "public-page")
    service.execute("alice", job["id"])
    assert service.result("alice", job["id"])["findings"]


def test_legacy_expired_target_and_cross_user(ready):
    service, target_id, _, clock = ready
    target = service.require("alice", f"TARGET#{target_id}")
    target.update(verified_until=1, assessment=None)
    service.save(target)
    clock[0] += 90000
    with pytest.raises(NotFound):
        service.enqueue("bob", target_id, "cross-user")
    job = service.enqueue("alice", target_id, "expired-legacy")
    # Jobs queued by the prior release may contain an assessment; it is ignored.
    job["assessment"] = {"confirmed_level": 3}
    job["rule_version"] = "2026-10-31.1"
    service.save(job)
    service.execute("alice", job["id"])
    result = service.result("alice", job["id"])
    stored_job = service.require("alice", f"JOB#{job['id']}")
    assert result["summary"]["configuration_count"] > 0
    assert stored_job["rule_version"] == result["findings"][0]["rule_version"]


def test_outbox_failure_is_recoverable(ready):
    service, target, _, _ = ready
    job = service.enqueue("alice", target, "key")
    publisher = service.publisher

    class Failing:
        def send(self, *args):
            raise OSError("queue unavailable")

    service.publisher = Failing()
    with pytest.raises(OSError):
        service.dispatch()
    assert service.store.work("OUTBOX")
    service.publisher = publisher
    service.dispatch()
    service.execute("alice", job["id"])
    assert service.result("alice", job["id"])


def test_cancel_during_fetch(ready):
    service, target, fetcher, _ = ready
    job = service.enqueue("alice", target, "key")
    fetcher.hook = lambda: service.cancel("alice", job["id"])
    service.execute("alice", job["id"])
    assert service.require("alice", f"JOB#{job['id']}")["state"] == "CANCELLED"
    with pytest.raises(Conflict):
        service.result("alice", job["id"])


def test_delete_during_fetch(ready):
    service, target, fetcher, _ = ready
    job = service.enqueue("alice", target, "key")
    fetcher.hook = lambda: service.remove("alice", target)
    service.execute("alice", job["id"])
    assert service.require("alice", f"JOB#{job['id']}")["state"] == "CANCELLED"
    with pytest.raises(NotFound):
        service.result("alice", job["id"])


def test_lease_expiry_cannot_publish(ready):
    service, target, fetcher, clock = ready
    job = service.enqueue("alice", target, "key")
    fetcher.hook = lambda: clock.__setitem__(0, clock[0] + 100)
    with pytest.raises(Conflict):
        service.execute("alice", job["id"])
    assert service.require("alice", f"JOB#{job['id']}")["state"] == "RUNNING"


def test_optimistic_update(ready):
    service, target, _, _ = ready
    a = service.require("alice", f"TARGET#{target}")
    b = service.require("alice", f"TARGET#{target}")
    service.save(a)
    with pytest.raises(Conflict):
        service.save(b)


def test_pending_cancel(ready):
    service, target, _, _ = ready
    job = service.enqueue("alice", target, "key")
    service.cancel("alice", job["id"])
    service.execute("alice", job["id"])
    assert service.require("alice", f"JOB#{job['id']}")["state"] == "CANCELLED"


def test_direct_scans_still_enforce_cooldown_and_shared_host_lock(ready):
    service, target, _, _ = ready
    alice = service.enqueue("alice", target, "first")
    with pytest.raises(Conflict):
        service.enqueue("alice", target, "too-soon")
    service.execute("alice", alice["id"])
    other = service.register("bob", "https://example.com/")
    bob = service.enqueue("bob", other["sk"].split("#")[1], "other-account")
    with pytest.raises(Conflict):
        service.execute("bob", bob["id"])
