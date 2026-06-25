.PHONY: dev install test lint fmt check

dev:
	uv sync --extra dev

install:
	uv tool install --reinstall .

test:
	uv run pytest

lint:
	uv run ruff check .

fmt:
	uv run ruff format .

check:
	uv run ruff check .
	uv run ruff format --check .
	uv run pytest
