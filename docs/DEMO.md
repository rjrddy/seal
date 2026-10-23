# Run, verify and record

Prerequisites: Rust/rustup, Python and Node. `make demo` fetches locked Rust dependencies, installs pinned Python development tools, builds the release CLI and opens a local synthetic log at `.cache/demo`. Visit http://127.0.0.1:8093. No account, model, database or signing secret is needed for this public-key demonstration. SEAL_ADDR overrides the bind address. Ctrl-C stops the viewer; the synthetic files remain for restart verification.

The viewer's deterministic key is public and provides no private identity. Every page labels that boundary. For a caller-managed key use `seal keygen <private-file>`; it creates a new OS-random key file with restrictive Unix permissions and refuses overwrite, printing only the public key. Keep it outside the repository. `seal init` creates a store using that private file and a chosen fixed log identity. Append acknowledges fsync, while `seal checkpoint` explicitly seals the current tail. Automatic checkpoints also occur periodically. `seal help` gives the precise CLI arguments.

Verify exported bundles using a separately trusted public-key/log-ID pair. `verify-log` also takes the caller's retained checkpoint file. Do not discover the authoritative key from the untrusted bundle you are trying to check, and do not use the latest head from an untrusted log as your only rollback protection. Verify a stable snapshot or cooperate with the writer lock.

`make lint test bench` reruns native and real CLI/HTTP/process checks and measurements, then regenerates the README from their outputs. Cargo audit is enforced by CI with warnings denied; install its pinned scanner using `cargo install cargo-audit --locked --version 0.22.2` for a local audit. Source-level signature/hash assumptions are not a security audit certification.

## An actual ninety-second recording

Record the screen before performing and narrating the following; do not pad a short clip:

- Read the public-key banner and caller-pinned identity fields. Select an entry, load its authentic inclusion bundle and verify it.
- Show the agreement between browser WebCrypto and Rust. Flip a payload byte, verify rejection, and reload the authentic bundle.
- Drop or reorder path nodes and verify rejection. Explain that the log files themselves remain unchanged by these bundle challenges.
- Switch to consistency. Verify that the earlier retained tree is a prefix of the newer signed tree; remove a proof node and show rejection.
- Append a real synthetic record, then load and verify a new proof. Show that append/refresh did not replace an edited/pinned key.
- Download a bundle and explain independent CLI verification. Finish with the rollback negative control: an older signed prefix can pass unless you retained a newer head.

Automated recorder: install `requirements-browser.txt` in the local venv, run `.venv/bin/python -m playwright install chromium ffmpeg`, then `.venv/bin/python scripts/review.py --record`. It starts/stops its own server and performs repeated actual verification/challenge lifecycles. PLAYWRIGHT_BROWSERS_PATH may point to a compatible existing browser cache. The output is docs/results/browser/demo.webm; inspect actual duration with `ffprobe -v quiet -show_format -of json docs/results/browser/demo.webm`.

## Deployment preparation only

Dockerfile and Render free-plan blueprint are prepared; no account or deployment was created. An approved future deployment would set a long SEAL_TOKEN and expose the labelled public synthetic demo. The image runs nonroot. Its default data directory needs an explicitly managed persistent volume for persistence beyond container replacement; free-plan hosted files are ephemeral and cannot be marketed as durable hosted custody. No real private signing identity is accepted by the demo HTTP service. Production identity, key custody, proxy timeouts, abuse control and witnesses remain separate work.
