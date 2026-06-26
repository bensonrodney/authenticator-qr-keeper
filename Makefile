.PHONY: dev install test lint fmt fix-fmt check load-example

.venv: pyproject.toml
	uv sync --extra dev

dev: .venv

install:
	uv tool install --reinstall .

test: .venv
	uv run pytest -vv

lint: .venv
	uv run ruff check .

fmt: .venv
	uv run ruff format --check .

fix-fmt: .venv
	uv run ruff format .

check: lint fmt test

load-example:
	@if [ -f "$(HOME)/.qr/.qrcodes" ]; then \
		echo "ERROR: $(HOME)/.qr/.qrcodes already exists. Aborting to avoid overwriting existing codes."; \
		exit 1; \
	fi; \
	echo "This will encrypt example.qrcodes.file and write it to $(HOME)/.qr/.qrcodes"; \
	printf "Continue? [y/N]: "; \
	read confirm; \
	if ! echo "$$confirm" | grep -qE "^[yY]([eE][sS])?$$"; then \
		echo "Aborted."; \
		exit 1; \
	fi; \
	mkdir -p $(HOME)/.qr; \
	bash scripts/encrypt-file.sh example.qrcodes.file $(HOME)/.qr/.qrcodes; \
	chmod 600 $(HOME)/.qr/.qrcodes; \
	echo "Done. $(HOME)/.qr/.qrcodes created."
