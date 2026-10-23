.PHONY: setup build lint test bench demo
setup:
	./scripts/cargo.sh fetch --locked
build:
	./scripts/cargo.sh build --release --locked
lint:
	./scripts/cargo.sh fmt --check
	./scripts/cargo.sh clippy --all-targets --locked -- -D warnings
	python3 -m py_compile scripts/*.py tests/*.py
test:
	./scripts/cargo.sh test --locked
	python3 -m unittest discover -s tests -p '*_test.py' -v
bench: build
	./target/release/seal bench docs/results
	python3 scripts/render_readme.py
demo: setup build
	./target/release/seal serve .cache/demo
