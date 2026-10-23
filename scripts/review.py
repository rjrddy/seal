"""Real browser WebCrypto/Rust agreement, tamper, trust-anchor and recovery checks."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs/results/browser"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--record", action="store_true")
    args = parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    errors, receipts = [], []
    with tempfile.TemporaryDirectory() as temp:
        logpath = Path(temp) / "server.log"
        with logpath.open("w") as log:
            process = subprocess.Popen(
                [str(ROOT / "target/release/seal"), "serve", str(Path(temp) / "data")],
                cwd=ROOT,
                env={**os.environ, "SEAL_ADDR": "127.0.0.1:0"},
                stdout=log,
                stderr=log,
            )
            try:
                base = ""
                for _ in range(300):
                    for line in logpath.read_text().splitlines():
                        value = json.loads(line)
                        if value.get("event") == "ready":
                            base = value["url"]
                    if base:
                        break
                    if process.poll() is not None:
                        raise RuntimeError(logpath.read_text())
                    time.sleep(0.025)
                assert base, "readiness timeout"
                with sync_playwright() as p:
                    browser = p.chromium.launch(executable_path=p.chromium.executable_path)
                    context = browser.new_context(
                        viewport={"width": 1440, "height": 1100},
                        accept_downloads=True,
                        **(
                            {
                                "record_video_dir": temp,
                                "record_video_size": {"width": 1440, "height": 1100},
                            }
                            if args.record
                            else {}
                        ),
                    )
                    page = context.new_page()
                    page.on("pageerror", lambda e: errors.append(str(e)))
                    page.goto(base)
                    expect(page.locator("#connection")).to_have_text("LOCAL LOG CONNECTED")
                    started = time.monotonic()
                    trusted_key = page.locator("#public-key").input_value()
                    trusted_id = page.locator("#log-id").input_value()

                    def click(selector):
                        page.locator(selector).click()

                    def verify(expected: bool):
                        click("#verify")
                        expect(page.locator("#receipt")).to_have_attribute(
                            "data-verified", str(expected).lower()
                        )
                        expect(page.locator("#receipt")).to_have_attribute("data-agreement", "true")
                        receipts.append(
                            {
                                "verified": expected,
                                "verifier_agreement": True,
                                "receipt": page.locator("#receipt").inner_text(),
                            }
                        )

                    def lifecycle():
                        click("#inclusion")
                        verify(True)
                        click("#flip")
                        verify(False)
                        click("#load")
                        click("#drop")
                        verify(False)
                        click("#load")
                        click("#reorder")
                        verify(False)
                        click("#load")
                        verify(True)
                        click("#consistency")
                        verify(True)
                        click("#drop")
                        verify(False)
                        click("#load")
                        verify(True)

                    lifecycle()
                    # A refresh/append must not silently replace a user-pinned key.
                    page.locator("#public-key").fill("00" * 32)
                    click("#append")
                    expect(page.locator("#public-key")).to_have_value("00" * 32)
                    verify(False)
                    page.locator("#public-key").fill(trusted_key)
                    verify(True)
                    # Larger independent native fixtures also verify in the browser.
                    measured = json.loads((ROOT / "docs/results/bench.json").read_text())
                    for kind in ["inclusion", "consistency"]:
                        click("#" + kind)
                        page.locator("#public-key").fill(measured["public_key"])
                        page.locator("#log-id").fill(measured["log_id"])
                        page.locator("#bundle").fill(
                            (ROOT / f"docs/results/{kind}.json").read_text()
                        )
                        verify(True)
                        click("#drop")
                        verify(False)
                    page.locator("#public-key").fill(trusted_key)
                    page.locator("#log-id").fill(trusted_id)
                    click("#inclusion")
                    verify(True)
                    with page.expect_download() as downloaded:
                        click("#download")
                    downloaded.value.save_as(str(Path(temp) / "bundle.json"))
                    assert (
                        json.loads((Path(temp) / "bundle.json").read_text())["entry"]["seq"] == 37
                    )
                    page.screenshot(path=str(OUT / "desktop.png"), full_page=True)
                    widths = []
                    for width in [390, 768, 1024, 1440]:
                        page.set_viewport_size({"width": width, "height": 1000})
                        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
                        widths.append(width)
                    page.set_viewport_size({"width": 390, "height": 1000})
                    page.screenshot(path=str(OUT / "mobile.png"), full_page=True)
                    page.set_viewport_size({"width": 1440, "height": 1100})
                    page.route("**/api/verify", lambda route: route.abort())
                    click("#verify")
                    expect(page.get_by_role("alert")).to_contain_text("Action failed")
                    page.unroute("**/api/verify")
                    verify(True)
                    expect(page.get_by_role("alert")).to_be_empty()
                    page.keyboard.press("Tab")
                    assert page.evaluate("document.activeElement !== document.body")
                    if args.record:
                        while time.monotonic() - started < 92:
                            lifecycle()
                    video = page.video
                    context.close()
                    if video:
                        video.save_as(str(OUT / "demo.webm"))
                    browser.close()
                    assert not errors, errors
                    result = {
                        "responsive_widths": widths,
                        "page_errors": errors,
                        "checks": receipts,
                        "trust_anchor_preserved_on_append": True,
                        "native_large_fixtures_verified": True,
                        "download_valid": True,
                        "network_failure_recovery": True,
                        "keyboard_focus": True,
                        "elapsed_s": time.monotonic() - started,
                    }
                    if args.record:
                        result["ffprobe"] = json.loads(
                            subprocess.check_output(
                                [
                                    "ffprobe",
                                    "-v",
                                    "quiet",
                                    "-show_format",
                                    "-of",
                                    "json",
                                    str(OUT / "demo.webm"),
                                ],
                                text=True,
                            )
                        )
                        assert float(result["ffprobe"]["format"]["duration"]) >= 90
                    (OUT / "review.json").write_text(json.dumps(result, indent=2) + "\n")
                    print(json.dumps({k: v for k, v in result.items() if k != "checks"}))
            finally:
                process.terminate()
                process.wait(timeout=10)


if __name__ == "__main__":
    main()
