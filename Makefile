PY ?= .venv/Scripts/python
ENGINES ?= authz,api_checks,zap,nuclei

# one command: secrets generated on first run, everything built and started, lab self-verified
up:
	python scripts/init_env.py
	docker compose up -d --build
	@echo "dashboard: http://127.0.0.1:8000/dashboard/   lab: http://127.0.0.1:8080/docs"

down:
	docker compose down

identities:
	docker compose exec -T nimbus-air python -m app.identities > identities.json
	@echo "wrote identities.json (gitignored)"

refuse-demo:
	docker compose exec -T api python -m app.cli try-unverified http://example.com

scan:
	docker compose exec -T nimbus-air python -m app.identities | docker compose exec -T api python -m app.cli scan --identities - --engines $(ENGINES)

test: test-lab test-cp

test-lab:
	cd target-plane/nimbus-air && ../../$(PY) -m pytest -q tests

test-cp:
	cd control-plane && ../$(PY) -m pytest -q tests --cov=app --cov-report=term

.PHONY: up down identities refuse-demo scan test test-lab test-cp
