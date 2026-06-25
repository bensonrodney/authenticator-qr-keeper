.PHONY: dev install test lint fmt check

.venv: pyproject.toml
	uv sync --extra dev

dev: .venv

install:
	uv tool install --reinstall .

test: .venv
	uv run pytest

lint: .venv
	uv run ruff check .

fmt: .venv
	uv run ruff format .

check: .venv
	uv run ruff check .
	uv run ruff format --check .
	uv run pytest -v
