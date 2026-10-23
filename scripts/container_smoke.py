"""Actual Linux image: nonroot, live proofs, SIGKILL persistence and torn-tail rejection."""

from __future__ import annotations

import json
import subprocess
import time
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:18093"
TOKEN = "synthetic-seal-ci-key-0001"


def request(path: str, data=None):
    req = urllib.request.Request(
        BASE + path,
        data=None if data is None else json.dumps(data).encode(),
        headers={"Authorization": "Bearer " + TOKEN},
    )
    with urllib.request.urlopen(req, timeout=5) as response:
        return json.load(response)


def ready() -> None:
    for _ in range(100):
        try:
            if request("/api/health")["status"] == "ready":
                return
        except (OSError, urllib.error.HTTPError):
            time.sleep(0.2)
    raise AssertionError("image readiness failed")


def main() -> None:
    name = "seal-ci-smoke"
    subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            name,
            "-p",
            "127.0.0.1:18093:8093",
            "-e",
            "SEAL_TOKEN=" + TOKEN,
            "seal:test",
        ],
        check=True,
    )
    try:
        ready()
        uid = subprocess.check_output(["docker", "exec", name, "id", "-u"], text=True).strip()
        assert uid == "10001"
        with urllib.request.urlopen(BASE) as response:
            assert b"Seal" in response.read()
        for asset in ("/app.js", "/style.css"):
            with urllib.request.urlopen(BASE + asset) as response:
                assert response.status == 200
        try:
            urllib.request.urlopen(BASE + "/api/state")
            raise AssertionError("unauthorized access")
        except urllib.error.HTTPError as error:
            assert error.code == 401
        saved = request("/api/append", {})
        proofs = request("/api/bundle")
        for kind in ("inclusion", "consistency"):
            assert request(
                "/api/verify",
                {
                    "kind": kind,
                    "bundle": proofs[kind],
                    "public_key": saved["public_key"],
                    "log_id": saved["log_id"],
                },
            )["verified"]
        subprocess.run(["docker", "kill", "--signal", "KILL", name], check=True)
        subprocess.run(["docker", "start", name], check=True)
        ready()
        restored = request("/api/state")
        assert restored["checkpoint"] == saved["checkpoint"] and restored["size"] == saved["size"]
        subprocess.run(
            ["docker", "exec", name, "sh", "-c", "printf '{' >> /app/data/entries.jsonl"],
            check=True,
        )
        subprocess.run(["docker", "restart", name], check=True)
        exit_code = subprocess.check_output(["docker", "wait", name], text=True, timeout=10).strip()
        assert exit_code == "1"
        print(
            json.dumps(
                {
                    "actual_image": True,
                    "uid": uid,
                    "static_assets": True,
                    "auth": True,
                    "valid_proofs": True,
                    "sigkill_checkpoint_persisted": True,
                    "incomplete_tail_startup_rejected": True,
                }
            )
        )
    finally:
        subprocess.run(["docker", "logs", name], check=True)
        subprocess.run(["docker", "rm", "-f", name], check=True)


if __name__ == "__main__":
    main()
