PROJECT := pyasice
VENV := ./venv/bin
export PATH := $(VENV):$(PATH)

.PHONY:
venv:
	python -m venv venv
	pip install -r requirements-dev.txt

.PHONY:
lint:
	black --check .
	isort --check-only --project=$(PROJECT) .
	flake8

.PHONY:
fmt:
	black .
	isort --project=$(PROJECT) .

.PHONY:
test:
	pytest

.PHONY:
coverage:
	pytest --cov=$(PROJECT) --cov-report html --cov-report term-missing
