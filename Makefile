GO ?= go
GOVULNCHECK ?= $(GO) run golang.org/x/vuln/cmd/govulncheck@latest
BIN := bin
PKGS := ./...
PUBLIC := server/public
LAB := lab

.PHONY: all test test-go test-fingerprint-db fingerprints fmt fmt-check vet csp-check build test-lab test-oom-control test-live vulncheck \
	package-binaries packages clean

all: test

# The canonical "did I break something" target.
test: fmt-check vet test-go csp-check

# External GPL rules are downloaded separately and are not packaged with the binary.
fingerprints:
	$(GO) run ./cmd/php2shell fingerprints local/fingerprints

test-fingerprint-db:
	PHP2SHELL_FINGERPRINT_DB="$(CURDIR)/local/fingerprints/php.json" $(GO) test -count=1 -v -run '^TestExternalDatabase$$' ./engine/probe/

test-go:
	$(GO) test -race $(PKGS)

fmt:
	gofmt -w .

fmt-check:
	@files=$$(gofmt -l .); \
	if [ -n "$$files" ]; then \
		echo "gofmt required for:"; echo "$$files"; exit 1; \
	fi

vet:
	$(GO) vet $(PKGS)

# The content policy admits no inline style and no inline script, and no text
# carries a typographic dash or quotation mark. A JSON-LD block is data, not
# script. The bytes are spelled in octal so this file passes its own check.
TYPOGRAPHIC := $(shell printf '\342\200[\223\224\230\231\234\235]')
csp-check:
	@fail=0; \
	if grep -rnE '(style="|<style)' $(PUBLIC); then \
		echo "inline styles are not allowed"; fail=1; \
	fi; \
	if grep -rn '<script' $(PUBLIC) | grep -v -e 'src=' -e 'type="application/ld+json"'; then \
		echo "inline scripts are not allowed"; fail=1; \
	fi; \
	if LC_ALL=C grep -rnI --exclude-dir=.git --exclude-dir=$(BIN) --exclude-dir=dist \
		--exclude-dir=plans --exclude-dir=local -e '$(TYPOGRAPHIC)' .; then \
		echo "typographic dashes and quotation marks are not allowed"; fail=1; \
	fi; \
	exit $$fail

build:
	$(GO) build -o $(BIN)/php2shell ./cmd/php2shell

# The live acceptance tests against the Docker lab. Requires Docker, so it is
# never part of `test`.
test-lab:
	docker compose -f $(LAB)/docker-compose.yml up -d --build
	PHP2SHELL_LAB=1 $(GO) test -count=1 -run Lab ./engine/probe/; \
	status=$$?; \
	docker compose -f $(LAB)/docker-compose.yml down --rmi local; \
	exit $$status

# Ordinary OOM responses in disconnected local PHP containers, never a CVE trigger.
test-oom-control:
	PHP2SHELL_OOM_CONTROL=1 $(GO) test -count=1 -v -run '^TestOOMControl$$' ./lab/

# The lab's expectations against public instances of our own, under the
# public address policy. Name them in PHP2SHELL_LIVE_UNPATCHED,
# PHP2SHELL_LIVE_PATCHED and PHP2SHELL_LIVE_STATIC; an unset one is skipped.
# Network-dependent and never part of `test`.
test-live:
	$(GO) test -count=1 -run Live -v ./engine/probe/

# Network-dependent and never part of `test`.
vulncheck:
	$(GOVULNCHECK) ./...

# Packaging: one .deb and one .rpm per architecture, built with nfpm. The tag
# is the only place a version number is written.
# Without a tag, the Go pseudo-version the binary reports, as packages need a
# leading digit.
GIT_TAG_VERSION = $(shell git describe --tags --dirty 2>/dev/null | sed 's/^v//')
GIT_PSEUDO_VERSION = $(shell TZ=UTC git log -1 --abbrev=12 --date=format-local:%Y%m%d%H%M%S --format=0.0.0-%cd-%h 2>/dev/null)
VERSION ?= $(or $(GIT_TAG_VERSION),$(GIT_PSEUDO_VERSION))
PACKAGE_ARCHES ?= amd64 arm64
DIST := dist
PKG_DIR := $(DIST)/packages
NFPM_CONF := $(DIST)/nfpm
NFPM := $(GO) run github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.48.0

package-binaries:
	@for arch in $(PACKAGE_ARCHES); do \
		echo "building linux/$$arch"; \
		mkdir -p $(DIST)/linux_$$arch; \
		GOOS=linux GOARCH=$$arch CGO_ENABLED=0 $(GO) build -trimpath -ldflags='-s -w' \
			-o $(DIST)/linux_$$arch/php2shell ./cmd/php2shell || exit 1; \
	done

packages: package-binaries
	@test -n "$(VERSION)" || { echo "no version; pass VERSION=x.y.z"; exit 1; }
	@mkdir -p $(PKG_DIR) $(NFPM_CONF)
	@for arch in $(PACKAGE_ARCHES); do \
		sed -e "s|\$${ARCH}|$$arch|g" -e "s|\$${VERSION}|$(VERSION)|g" \
			packaging/nfpm/php2shell.yaml > $(NFPM_CONF)/php2shell-$$arch.yaml || exit 1; \
		for packager in deb rpm; do \
			echo "packaging $$arch $$packager"; \
			$(NFPM) pkg --config $(NFPM_CONF)/php2shell-$$arch.yaml \
				--packager $$packager --target $(PKG_DIR)/ || exit 1; \
		done; \
	done
	@ls -1 $(PKG_DIR)

clean:
	rm -rf $(BIN) $(DIST)
