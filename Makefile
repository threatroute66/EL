.PHONY: install doctor test snapshot clean help

VENV := .venv
EL := $(VENV)/bin/el
PYTEST := $(VENV)/bin/pytest

help:
	@echo "EL — common workflows"
	@echo "  make install      bootstrap from a fresh SIFT (apt + venv + pip + snapshot)"
	@echo "  make doctor       verify EL is healthy on this host"
	@echo "  make test         run the test suite"
	@echo "  make snapshot     capture a fresh provisioning snapshot of current host state"
	@echo "  make clean        remove .venv and pytest caches"

install:
	./install.sh

doctor:
	$(EL) doctor

test:
	$(PYTEST) -q

snapshot:
	$(EL) provision-snapshot

clean:
	rm -rf $(VENV) .pytest_cache build dist *.egg-info el.egg-info
