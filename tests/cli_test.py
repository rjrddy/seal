"""Real file/CLI/process and HTTP tests against the release Rust executable."""

from __future__ import annotations

import fcntl
import json
import os
import signal
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "target/release/seal"


class Files(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.folder = Path(self.tmp.name)
        self.store = self.folder / "log"
        self.key = self.folder / "private"
        self.public = self.run_cli("keygen", self.key)["public_key"]
        self.log_id = "27" * 32
        self.run_cli("init", self.store, self.key, self.log_id)
        for i in range(5):
            self.run_cli("append", self.store, self.key, self.log_id, f"synthetic-{i}")
        self.anchor = self.folder / "anchor.json"
        self.anchor.write_text(
            json.dumps(self.run_cli("checkpoint", self.store, self.key, self.log_id))
        )

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, *args):
        result = subprocess.run(
            [str(BIN), *map(str, args)], capture_output=True, text=True, check=True
        )
        return json.loads(result.stdout)

    def rejected(self, *args):
        result = subprocess.run([str(BIN), *map(str, args)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertFalse(json.loads(result.stderr)["verified"])
        return result

    def test_key_file_protection_and_complete_cli_proofs(self):
        self.assertEqual(self.key.stat().st_mode & 0o777, 0o600)
        self.rejected("keygen", self.key)
        entries = self.store / "entries.jsonl"
        self.run_cli("verify-log", entries, self.anchor, self.public, self.log_id)
        proof = self.run_cli("inclusion", entries, self.anchor, 3)
        file = self.folder / "proof.json"
        file.write_text(json.dumps(proof))
        self.run_cli("verify-inclusion", file, self.public, self.log_id)
        proof["entry"]["payload"] = "00"
        file.write_text(json.dumps(proof))
        self.rejected("verify-inclusion", file, self.public, self.log_id)

    def test_actual_disk_byte_deletion_reorder_and_tail_rollback(self):
        entries = self.store / "entries.jsonl"
        original = entries.read_bytes()
        rows = original.splitlines(keepends=True)
        variants = [
            bytes([original[0] ^ 1]) + original[1:],
            b"".join(rows[:-1]),
            b"".join(rows[1:]),
            b"".join([rows[1], rows[0], *rows[2:]]),
            b"\n" + original,
            original + b"\n",
        ]
        for changed in variants:
            entries.write_bytes(changed)
            self.rejected("verify-log", entries, self.anchor, self.public, self.log_id)
        entries.write_bytes(original)
        self.run_cli("verify-log", entries, self.anchor, self.public, self.log_id)

    def test_incomplete_tail_fails_closed_and_is_never_silently_repaired(self):
        entries = self.store / "entries.jsonl"
        bad = entries.read_bytes() + b'{"seq":5'
        entries.write_bytes(bad)
        self.rejected("append", self.store, self.key, self.log_id, "must not append")
        self.assertEqual(entries.read_bytes(), bad)
        cp = self.store / "checkpoints.jsonl"
        cp.write_bytes(cp.read_bytes() + b'{"version":')
        self.rejected("checkpoint", self.store, self.key, self.log_id)

    def test_real_cross_process_writer_fence(self):
        with (self.store / "writer.lock").open("r+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = self.rejected("append", self.store, self.key, self.log_id, "no write")
            self.assertIn("writer already active", result.stderr)
        self.run_cli("append", self.store, self.key, self.log_id, "allowed after unlock")


class Service(unittest.TestCase):
    def test_sigkill_restart_http_validation_and_auth(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            data = folder / "demo"
            token = "synthetic-seal-test-key-0001"

            def start():
                log = (folder / "server.log").open("w")
                child = subprocess.Popen(
                    [str(BIN), "serve", str(data)],
                    cwd=ROOT,
                    env={**os.environ, "SEAL_ADDR": "127.0.0.1:0", "SEAL_TOKEN": token},
                    stdout=log,
                    stderr=log,
                )
                for _ in range(300):
                    for line in (folder / "server.log").read_text().splitlines():
                        row = json.loads(line)
                        if row.get("event") == "ready":
                            return child, log, row["url"]
                    if child.poll() is not None:
                        raise AssertionError((folder / "server.log").read_text())
                    time.sleep(0.02)
                child.kill()
                child.wait()
                log.close()
                raise AssertionError("server readiness timeout")

            child, log, base = start()
            try:

                def request(path, data=None, auth=True, extra=None):
                    req = urllib.request.Request(
                        base + path,
                        data=None if data is None else json.dumps(data).encode(),
                        headers={
                            **({"Authorization": "Bearer " + token} if auth else {}),
                            **(extra or {}),
                        },
                    )
                    with urllib.request.urlopen(req, timeout=5) as response:
                        return json.load(response)

                with self.assertRaises(urllib.error.HTTPError) as error:
                    request("/api/state", auth=False)
                self.assertEqual(error.exception.code, 401)
                original = request("/api/state")
                saved = request("/api/append", {})
                self.assertEqual(saved["size"], original["size"] + 1)
                proofs = request("/api/bundle")
                for kind in ("inclusion", "consistency"):
                    result = request(
                        "/api/verify",
                        {
                            "kind": kind,
                            "bundle": proofs[kind],
                            "public_key": saved["public_key"],
                            "log_id": saved["log_id"],
                        },
                    )
                    self.assertTrue(result["verified"])
                with self.assertRaises(urllib.error.HTTPError) as error:
                    request("/api/append", {}, extra={"Origin": "https://other.invalid"})
                self.assertEqual(error.exception.code, 403)
                child.send_signal(signal.SIGKILL)
                child.wait(timeout=5)
                log.close()
                child, log, base = start()
                restored = request("/api/state")
                self.assertEqual(restored["checkpoint"], saved["checkpoint"])
                self.assertEqual(restored["size"], saved["size"])
                with self.assertRaises(urllib.error.HTTPError) as error:
                    request("/api/verify", {"x": "z" * 65537})
                self.assertEqual(error.exception.code, 400)
            finally:
                child.terminate()
                child.wait(timeout=5)
                log.close()


if __name__ == "__main__":
    unittest.main()
