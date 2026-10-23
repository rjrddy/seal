"""Capture commands, runtime, machine and source hashes alongside local measurements."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    env = os.environ.copy()
    compiler = shutil.which("rustc")
    if compiler is None:
        base = Path(env.get("SEAL_RUST_ROOT", str(ROOT.parent / ".cache/seal-tools")))
        env.update({"CARGO_HOME": str(base / "cargo"), "RUSTUP_HOME": str(base / "rustup")})
        compiler = str(base / "cargo/bin/rustc")
    data = {
        "command": "make lint test bench",
        "platform": platform.platform(),
        "python": platform.python_version(),
        "rustc": subprocess.check_output([compiler, "--version"], env=env, text=True).strip(),
        "cargo": subprocess.check_output(["./scripts/cargo.sh", "--version"], text=True).strip(),
        "source_sha256": {
            str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
            for folder in ("src", "web", "tests")
            for p in (ROOT / folder).rglob("*")
            if p.is_file() and "__pycache__" not in str(p)
        },
    }
    if platform.system() == "Darwin":
        data["hardware"] = {
            key: subprocess.check_output(["sysctl", "-n", key], text=True).strip()
            for key in ("hw.model", "hw.ncpu", "hw.memsize")
        }
    else:
        data["hardware"] = {"logical_cpus": os.cpu_count(), "processor": platform.processor()}
    (ROOT / "docs/results/environment.json").write_text(json.dumps(data, indent=2) + "\n")


if __name__ == "__main__":
    main()
