.PHONY: setup build lint test bench demo
setup:
	./scripts/cargo.sh fetch --locked
	python3 -m venv .venv
	.venv/bin/python -m pip install -r requirements-dev.txt
build:
	./scripts/cargo.sh build --release --locked
lint:
	./scripts/cargo.sh fmt --check
	./scripts/cargo.sh clippy --all-targets --locked -- -D warnings
	.venv/bin/ruff check scripts tests
	.venv/bin/ruff format --check scripts tests
	node --check web/app.js
test: build
	./scripts/cargo.sh test --locked
	.venv/bin/python -m pytest -q tests/cli_test.py
bench: build
	./target/release/seal bench docs/results
	python3 scripts/render_readme.py
demo: setup build
	./target/release/seal serve .cache/demo
