PROJECT := pyasice
VENV := ./venv/bin
export PATH := $(VENV):$(PATH)

.PHONY:
setup:
	@poetry install

.PHONY:
lint:
	poetry run ruff format . --diff
	poetry run ruff --select I . --diff

.PHONY:
fmt:
	poetry run ruff format .
	poetry run ruff --select I . --fix

.PHONY:
test:
	poetry run pytest

.PHONY:
coverage:
	poetry run pytest --cov=$(PROJECT) --cov-report html --cov-report term-missing

.PHONY:
build:
	@poetry build

.PHONY:
publish: build
	@poetry publish
