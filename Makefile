.PHONY: dev install test lint fmt fix-fmt check

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
