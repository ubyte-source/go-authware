.PHONY: all test bench lint clean vet cover ci pgo

all: vet test bench

# CI pipeline: vet + lint + test + coverage + benchmarks.
ci: vet lint test cover bench

# Run all tests with verbose output and race detector.
test:
	go test -v -race -count=1 ./...

# Run benchmarks.
bench:
	go test -bench=. -benchmem -count=6 ./...

# Run go vet.
vet:
	go vet ./...

# Run staticcheck and golangci-lint if available.
lint:
	@if command -v staticcheck >/dev/null 2>&1; then staticcheck ./...; else echo "staticcheck not installed, skipping"; fi
	@if command -v golangci-lint >/dev/null 2>&1; then golangci-lint run ./...; else echo "golangci-lint not installed, skipping"; fi

# Regenerate the PGO profile from all benchmarks and replace default.pgo.
# Run this before building for production to give the compiler accurate hot-path data.
pgo:
	go test -run='^$$' -bench=. -benchmem -count=5 \
		-cpuprofile=cpu.prof ./...
	go tool pprof -proto cpu.prof > default.pgo
	@rm -f cpu.prof
	@echo "default.pgo updated — rebuild with: go build -pgo=auto ./..."

# Clean test cache and generated files.
clean:
	go clean -testcache
	@rm -f coverage.out coverage.html *.prof

# Show test coverage.
cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@go tool cover -func=coverage.out | tail -1
	@echo "Coverage report: coverage.html"
