VENV := ./venv/bin

.PHONY:
lint:
	$(VENV)/black --check .
	$(VENV)/isort --check-only --project=pyasice .

.PHONY:
fmt:
	$(VENV)/black .
	$(VENV)/isort --project=pyasice .