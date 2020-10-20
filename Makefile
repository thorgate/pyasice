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
	isort --check-only --project=pyasice .
	flake8

.PHONY:
fmt:
	black .
	isort --project=pyasice .

.PHONY:
test:
	pytest

.PHONY:
coverage:
	pytest --cov=$(PROJECT)
	coverage html
