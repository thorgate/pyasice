PROJECT := pyasice
VENV := ./venv/bin

.PHONY:
lint:
	$(VENV)/black --check .
	$(VENV)/isort --check-only --project=pyasice .
	$(VENV)/flake8

.PHONY:
fmt:
	$(VENV)/black .
	$(VENV)/isort --project=pyasice .

.PHONY:
test:
	$(VENV)/pytest

.PHONY:
coverage:
	$(VENV)/pytest --cov=$(PROJECT)
	coverage html
