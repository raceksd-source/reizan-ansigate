.PHONY: test demo

PYTHON ?= python3

test:
	PYTHONPATH=src $(PYTHON) -m pytest

demo:
	@echo "== CLEAN =="
	@PYTHONPATH=src $(PYTHON) -m reizan_ansigate scan fixtures/clean.txt
	@echo
	@echo "== POISONED =="
	@PYTHONPATH=src $(PYTHON) -m reizan_ansigate scan fixtures/poisoned_jqwik_ansi.txt; code=$$?; if [ $$code -ne 2 ]; then exit $$code; fi
