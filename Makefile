PY ?= .venv/Scripts/python

up:
	docker compose up -d --build

down:
	docker compose down

test: test-lab

test-lab:
	cd target-plane/nimbus-air && ../../$(PY) -m pytest -q tests

.PHONY: up down test test-lab
