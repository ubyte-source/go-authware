.PHONY: all test race bench lint vuln fuzz clean vet cover ci pgo

all: vet test bench

# CI pipeline: every gate documented in SECURITY.md.
# gosec runs inside golangci-lint with the project config — no separate target.
ci: vet lint vuln test cover bench

# Run all tests.
test:
	go test -count=1 ./...

# Run all tests with race detector.
race:
	go test -race -count=1 ./...

# Run benchmarks.
bench:
	go test -bench=. -benchmem -count=6 -run=^$$ ./...

# Run go vet.
vet:
	go vet ./...

# Run golangci-lint (includes gosec with the project's exclusion config).
lint:
	@if command -v golangci-lint >/dev/null 2>&1; then golangci-lint run ./...; else echo "golangci-lint not installed, skipping"; fi

# Run govulncheck against module dependencies.
vuln:
	@if command -v govulncheck >/dev/null 2>&1; then govulncheck ./...; else echo "govulncheck not installed, skipping"; fi

# Run every fuzz target for FUZZTIME (default 30s).
FUZZTIME ?= 30s
fuzz:
	go test -run=^$$ -fuzz=FuzzSplitJWT          -fuzztime=$(FUZZTIME) .
	go test -run=^$$ -fuzz=FuzzParseJWTHeaderDirect -fuzztime=$(FUZZTIME) .
	go test -run=^$$ -fuzz=FuzzExtractClaims     -fuzztime=$(FUZZTIME) .
	go test -run=^$$ -fuzz=FuzzDecodeAlg         -fuzztime=$(FUZZTIME) .
	go test -run=^$$ -fuzz=FuzzDecodeClaimValue  -fuzztime=$(FUZZTIME) .
	go test -run=^$$ -fuzz=FuzzSanitiseHeaderValue -fuzztime=$(FUZZTIME) .
	go test -run=^$$ -fuzz=FuzzRequireHTTPS      -fuzztime=$(FUZZTIME) .
	go test -run=^$$ -fuzz=FuzzAlgorithmConfusion -fuzztime=$(FUZZTIME) .
	go test -run=^$$ -fuzz=FuzzVerify            -fuzztime=$(FUZZTIME) ./replay

# Regenerate the PGO profile from every package's benchmarks.
# go test -cpuprofile cannot target multiple packages, so each is
# profiled separately and the per-package profiles are merged.
pgo:
	@rm -f cpu.*.prof default.pgo
	@for pkg in $$(go list ./...); do \
		name=$$(echo $$pkg | tr '/.' '__'); \
		go test -run=^$$$$ -bench=. -benchmem -count=5 \
			-cpuprofile=cpu.$$name.prof $$pkg || exit 1; \
	done
	go tool pprof -proto cpu.*.prof > default.pgo
	@rm -f cpu.*.prof
	@echo "default.pgo updated — rebuild with: go build -pgo=auto ./..."

# Clean test cache and generated files.
clean:
	go clean -testcache
	@rm -f coverage.out coverage.html *.prof default.pgo

# Show test coverage.
cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@go tool cover -func=coverage.out | tail -1
	@echo "Coverage report: coverage.html"
