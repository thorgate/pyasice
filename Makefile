PROJECT := pyasice
VENV := ./venv/bin
export PATH := $(VENV):$(PATH)

.PHONY:
setup:
	@poetry install

.PHONY:
lint:
	poetry run black --check .
	poetry run isort --check-only --project=$(PROJECT) .
	poetry run flake8

.PHONY:
fmt:
	poetry run black .
	poetry run isort --project=$(PROJECT) .

.PHONY:
test:
	poetry run pytest

.PHONY:
coverage:
	poetry run pytest --cov=$(PROJECT) --cov-report html --cov-report term-missing

.PHONY:
build:
	@poetry build -f wheel
