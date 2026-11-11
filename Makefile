GOCACHE ?= $(CURDIR)/.cache/go-build
GOMODCACHE ?= $(CURDIR)/.cache/go-mod
GOLANGCI_LINT_CACHE := $(CURDIR)/.cache/golangci-lint
GOENV := GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) GOLANGCI_LINT_CACHE=$(GOLANGCI_LINT_CACHE)

# Coverage floor (ADR-0121 §4). Baseline measured at 73%; floor set at 70%.
COVERAGE_FLOOR ?= 70

.PHONY: gate relaytoken-check hermetic-check release-image build vet test cover lint vuln gofmt-check soak gen-vectors verify-vectors fuzz makefile-cache-isolation

gate: gofmt-check build vet relaytoken-check hermetic-check makefile-cache-isolation lint vuln cover verify-vectors fuzz release-image

relaytoken-check:
	cd relaytoken && $(GOENV) GOTOOLCHAIN=local GOPROXY=off GOVCS='*:off' GOENV=off go vet ./...
	cd relaytoken && $(GOENV) GOTOOLCHAIN=local GOPROXY=off GOVCS='*:off' GOENV=off go test -race ./...

# Public dependencies are prefetched into the module cache. The actual clean-tree
# build, vet, and test run with an empty environment, no Git configuration, and
# both module-proxy and VCS resolution disabled; relaytoken must resolve in-tree.
hermetic-check:
	@set -eu; \
	test -z "$$(git status --porcelain --untracked-files=all)" || { \
		echo 'hermetic-check requires a clean committed tree' >&2; \
		exit 1; \
	}; \
	repo_copy=$$(mktemp -d); \
	trap 'rm -rf "$$repo_copy"' EXIT INT TERM; \
	git archive --format=tar HEAD | tar -xf - -C "$$repo_copy"; \
	mkdir -p "$$repo_copy/.home" "$$repo_copy/.cache/go-build"; \
	clean_go() { \
		proxy=$$1; \
		shift; \
		env -i PATH="$$PATH" HOME="$$repo_copy/.home" TMPDIR="$${TMPDIR:-/tmp}" \
			GOCACHE="$$repo_copy/.cache/go-build" GOMODCACHE="$(abspath $(GOMODCACHE))" \
			GOPROXY="$$proxy" GOVCS='*:off' GOENV=off GOWORK=off GOTOOLCHAIN=local \
			GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0 "$$@"; \
	}; \
	cd "$$repo_copy"; \
	clean_go https://proxy.golang.org go mod download all; \
	clean_go off go build ./...; \
	clean_go off go vet ./...; \
	clean_go off go test ./...; \
	cd relaytoken; \
	clean_go off go vet ./...; \
	clean_go off go test ./...

release-image:
	@set -eu; \
	docker_host=$$(docker context inspect --format '{{.Endpoints.docker.Host}}'); \
	docker_platform=$$(docker version --format '{{.Server.Os}}/{{.Server.Arch}}'); \
	docker_config=$$(mktemp -d); \
	release_tar=$$(mktemp); \
	trap 'rm -rf "$$docker_config"; rm -f "$$release_tar"' EXIT INT TERM; \
	if command -v docker-buildx >/dev/null 2>&1; then buildx=docker-buildx; else buildx='docker buildx'; fi; \
	SOURCE_DATE_EPOCH=$$(git show -s --format=%ct HEAD); \
	DOCKER_CONFIG="$$docker_config" DOCKER_HOST="$$docker_host" $$buildx build --pull \
		--output "type=docker,dest=$$release_tar,rewrite-timestamp=true" \
		--build-arg "SOURCE_DATE_EPOCH=$$SOURCE_DATE_EPOCH" \
		--platform "$$docker_platform" --tag beamfall-relay:gate .

build:
	$(GOENV) go build ./...

vet:
	$(GOENV) go vet ./...

# lint: run golangci-lint (ADR-0121 §4). Install: brew install golangci-lint.
lint:
	$(GOENV) golangci-lint run ./... --allow-parallel-runners

makefile-cache-isolation:
	sh script/makefile-cache-isolation_test.sh

# vuln: pin govulncheck to an explicit release rather than `@latest` so the
# CI toolchain is reproducible and can't fetch-and-execute a newer build
# (SECREV-RELAY-7, compounds SECREV-RELAY-2).
vuln:
	$(GOENV) go run golang.org/x/vuln/cmd/govulncheck@v1.5.0 ./...

# cover: run tests with -race + -coverprofile, then enforce the floor.
cover:
	$(GOENV) go test -race -p 1 -coverprofile=coverage.out ./...
	@total=$$(go tool cover -func=coverage.out | awk '/^total:/ {gsub(/%/,""); print int($$3)}'); \
	if [ -z "$$total" ]; then \
	  echo "FAIL: could not parse total coverage"; \
	  exit 1; \
	fi; \
	echo "Coverage: $${total}% (floor: $(COVERAGE_FLOOR)%)"; \
	if [ "$$total" -lt "$(COVERAGE_FLOOR)" ]; then \
	  echo "FAIL: coverage $${total}% is below floor $(COVERAGE_FLOOR)%"; \
	  exit 1; \
	fi

test:
	$(GOENV) go test -race ./...

gofmt-check:
	@test -z "$$(gofmt -l $$(find . -name '*.go' -not -path './.cache/*'))"

# fuzz: replay the committed seed corpora for the attacker-facing parsers
# (protocol frame reader, ClientHello SNI parser, HMAC tunnel-token verifier)
# as fast deterministic subtests via `go test -run`, not time-boxed mutation
# fuzzing. Mirrors the hosted-CI-only fuzz smoke steps in
# .github/workflows/gate.yml so local `make gate` — the real merge gate,
# since hosted runners aren't used — also catches known crashers.
fuzz:
	$(GOENV) go test ./internal/protocol -run=FuzzReadFrame
	$(GOENV) go test ./internal/sni -run=FuzzParseClientHelloRecord
	$(GOENV) go test ./internal/relay -run=FuzzHMACVerifyV2

soak:
	$(GOENV) go run ./cmd/relay-loadgen -duration 30s -streams $${STREAMS:-8} -mbps $${MBPS:-32} -transport $${TRANSPORT:-tcp}

# netem-soak: QUIC-vs-TCP carrier soak under injected RTT/loss (ADR-0018 §1).
# Linux + tc/netem + CAP_NET_ADMIN only; refuses cleanly elsewhere (never hangs).
# e.g. sudo make netem-soak  |  sudo RTTS="0 50" LOSSES="0 3" make netem-soak
netem-soak:
	script/netem-soak.sh

# Committed contract vector sets, as cmd/gen-vectors -set name=golden path.
# frames: wire frames from internal/protocol. hmac-token-v2: carrier tokens
# minted from fixed inputs per PROTOCOL.md "Carrier token v2", replayed against
# the live verifier by internal/relay TestHMACTokenV2VectorsMatchVerifier.
VECTOR_SETS := frames=contracts/protocol/v1/vectors.json hmac-token-v2=contracts/protocol/v1/hmac-token-v2-vectors.json

# gen-vectors: regenerate every committed vector set in VECTOR_SETS.
# Run after any change to internal/protocol/protocol.go or to the token spec.
gen-vectors:
	@set -e; for pair in $(VECTOR_SETS); do \
	  $(GOENV) go run ./cmd/gen-vectors -set "$${pair%%=*}" > "$${pair#*=}"; \
	done

# verify-vectors: golden-drift tripwire (REVSWEEP-TEST-2). Regenerates each
# VECTOR_SETS entry to a temp path and diffs it against the committed golden.
# Fails if any differ: either the committed golden was hand-edited without
# regenerating (regen was blind), or the contract moved (internal/protocol or
# the token spec) without updating the committed vectors via `make gen-vectors`.
verify-vectors:
	@tmp=$$(mktemp); \
	trap 'rm -f "$$tmp"' EXIT; \
	status=0; \
	for pair in $(VECTOR_SETS); do \
	  golden=$${pair#*=}; \
	  $(GOENV) go run ./cmd/gen-vectors -set "$${pair%%=*}" > "$$tmp" || exit 1; \
	  if ! diff -u "$$golden" "$$tmp" >/dev/null 2>&1; then \
	    echo "FAIL: $$golden is stale — regen was blind or the contract moved."; \
	    echo "Run 'make gen-vectors' and commit the result if the change is intentional."; \
	    diff -u "$$golden" "$$tmp" || true; \
	    status=1; \
	  fi; \
	done; \
	exit $$status
