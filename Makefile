SHELL_FILES := bin/net-security-check tests/mocks/mockcmd tests/mocks/ping tests/mocks/openssl tests/net-security-check.bats
GITLEAKS_IMAGE := ghcr.io/gitleaks/gitleaks:v8.30.1
PREFIX ?= /usr/local

.PHONY: all lint test scan install
all: lint test

lint:
	shellcheck -x -S style $(SHELL_FILES)
	shellcheck -x -S style -o check-unassigned-uppercase,require-double-brackets bin/net-security-check

test:
	bats tests

scan:
	docker run --rm -v "$(CURDIR):/repo:ro" $(GITLEAKS_IMAGE) git /repo --redact --no-banner

install:
	install -D -m 0755 bin/net-security-check $(DESTDIR)$(PREFIX)/bin/net-security-check
