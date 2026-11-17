PY ?= .venv/Scripts/python

up:
	docker compose up -d --build

down:
	docker compose down

test: test-lab test-cp

test-lab:
	cd target-plane/nimbus-air && ../../$(PY) -m pytest -q tests

test-cp:
	cd control-plane && ../$(PY) -m pytest -q tests --cov=app --cov-report=term

.PHONY: up down test test-lab test-cp
