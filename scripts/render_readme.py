"""Generate figures only from retained real command outputs."""

from __future__ import annotations

import json
import re
import statistics
from pathlib import Path
from string import Template

root = Path(__file__).resolve().parents[1]
r = json.loads((root / "docs/results/bench.json").read_text())
b = json.loads((root / "docs/results/browser/review.json").read_text())
tests = (root / "docs/results/gates.txt").read_text()
rust = re.findall(r"test result: ok\. (\d+) passed", tests)
python = re.findall(r"(\d+) passed in", tests)
p = r["proofs"]
per_entry = [v["entries_per_second"] for v in r["append_trials"] if v["mode"] == "per_entry_fsync"]
batch = [
    v["entries_per_second"] for v in r["append_trials"] if v["mode"] == "checkpoint_batch_fsync"
]
values = {
    "detected": r["tamper"]["detected"],
    "injected": r["tamper"]["injected"],
    "bits_detected": r["tamper"]["file_bit_flips_detected"],
    "bits": r["tamper"]["file_bit_flips"],
    "fsync_rate": f"{statistics.median(per_entry):,.1f}",
    "batch_rate": f"{statistics.median(batch):,.1f}",
    "trials": len(per_entry),
    "tree": p["tree_size"],
    "inc_bytes": p["inclusion_hash_bytes"],
    "con_bytes": p["consistency_hash_bytes"],
    "inc_us": f"{p['inclusion_verify_median_us']:.2f}",
    "con_us": f"{p['consistency_verify_median_us']:.2f}",
    "inc_json": p["inclusion_bundle_json_bytes"],
    "con_json": p["consistency_bundle_json_bytes"],
    "duration": f"{float(b['ffprobe']['format']['duration']):.2f}",
    "rust_tests": sum(map(int, rust)),
    "python_tests": python[-1],
}
(root / "README.md").write_text(
    Template((root / "docs/README.template.md").read_text()).substitute(values)
)
