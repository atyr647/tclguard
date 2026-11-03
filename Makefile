# TclGuard build / test helpers.  Needs: tclsh8.6, tcllib, tcl-udp (for UDP tests), python3.
TCLSH ?= tclsh8.6
RUNTIME ?=

.PHONY: help test unit lint integration fuzz kernel gui-test gui-shots selftest kit starpack tarball clean

help:
	@echo "make test         unit tests + lint + self-test (no root needed)"
	@echo "make integration  socket-level tests against real backends and a local HTTPS update server (about 3 min)"
	@echo "make fuzz         HTTP parser fuzzer, deterministic smoke run (about 2 min; see tests/fuzz/README.md)"
	@echo "make kernel       real nftables tests in network namespaces (needs root)"
	@echo "make gui-test     drive every GUI flow under a virtual display"
	@echo "make kit          dist/tclguard.kit  (payload only; run it with any tclkit)"
	@echo "make starpack RUNTIME=path/to/tclkit   single-file program for that platform"
	@echo "make tarball      source tarball that runs with any Tcl 8.6 install"

test: unit lint selftest

unit:
	cd tests && $(TCLSH) all.tcl

lint:
	python3 tools/lint_vars.py

selftest:
	$(TCLSH) tclguard.vfs/main.tcl selftest

integration:
	cd tests/integration && python3 test_http.py && python3 test_features.py && python3 test_update.py && python3 test_reserve.py

fuzz:
	python3 tests/fuzz/fuzz.py ci

kernel:
	python3 tests/kernel/run_kernel_tests.py

gui-test:
	cd tests/gui && xvfb-run -a -s "-screen 0 1300x900x24" wish8.6 smoke.tcl

gui-shots:
	cd tests/gui && xvfb-run -a -s "-screen 0 1280x900x24" $(TCLSH) shots.tcl /tmp/tclguard-shots

kit:
	$(TCLSH) build.tcl --format zip --out dist/tclguard.kit --check

starpack:
	@test -n "$(RUNTIME)" || (echo "usage: make starpack RUNTIME=path/to/tclkit-or-basekit"; exit 1)
	$(TCLSH) build.tcl --runtime $(RUNTIME) --out dist/tclguard$(if $(findstring .exe,$(RUNTIME)),.exe,)

tarball:
	mkdir -p dist && tar --exclude='.git' --exclude=dist --exclude=__pycache__ -czf dist/tclguard-src.tar.gz \
		-C .. $(notdir $(CURDIR))

clean:
	rm -rf dist
