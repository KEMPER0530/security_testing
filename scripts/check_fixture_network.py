"""Local integration check, after a diagnostic has started a worker runtime."""

import json
import os
import subprocess


def docker(*args):
    return subprocess.run(["docker", *args], capture_output=True, text=True, env=os.environ)


def container(service):
    value = docker("compose", "ps", "-q", service).stdout.strip()
    if not value:
        raise RuntimeError(f"Start {service} before checking fixture isolation")
    return value


def networks(cid):
    return json.loads(docker("inspect", "--format", "{{json .NetworkSettings.Networks}}", cid).stdout)


def main():
    fixture = container("fixture")
    gateway = container("fixture-gateway")
    assert set(networks(fixture)) == {"security-testing-fixtures"}
    for name, port in [("localstack", 4566), ("identity", 8080)]:
        ip = networks(container(name))["security-testing-runtime"]["IPAddress"]
        attempt = docker("exec", fixture, "wget", "-q", "-T", "2", "-O", "/dev/null", f"http://{ip}:{port}/")
        assert attempt.returncode != 0, f"Fixture unexpectedly reached {name}"
        print(f"Fixture cannot reach {name}")
    assert docker("exec", gateway, "cat", "/proc/sys/net/ipv4/ip_forward").stdout.strip() == "0"
    for name in docker("ps", "--format", "{{.Names}}").stdout.splitlines():
        if "-worker" not in name.lower():
            continue
        code = (
            "from site_diagnostics.adapters.outbound.web import SafeFetcher; "
            "from site_diagnostics.domain.model import Scope; "
            "r=SafeFetcher('172.30.0.10','fixture.security-testing.test').fetch("
            "Scope.parse('http://fixture.security-testing.test/')); assert r.html"
        )
        result = docker("exec", name, "python", "-c", code)
        assert result.returncode == 0, "Worker could not fetch the fixed fixture gateway"
        print("Worker fetch and fixture isolation verified")
        return
    raise RuntimeError("Run one local diagnostic first to start a worker runtime")


if __name__ == "__main__":
    main()
