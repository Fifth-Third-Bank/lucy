PYTHON ?= python3

.PHONY: check install public-metadata-check syntax test uninstall verify-toolbox

check: syntax test public-metadata-check verify-toolbox

syntax:
	$(PYTHON) -m compileall -q lucy tools tests

test:
	$(PYTHON) -m unittest discover -s tests -v

public-metadata-check:
	$(PYTHON) tools/check_public_metadata.py

verify-toolbox:
	$(PYTHON) tools/import_toolbox.py --verify --destination lucy/toolbox

install:
	./install.sh

uninstall:
	./uninstall.sh
