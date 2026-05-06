# Contributing to go-authware

## Development Prerequisites

- **Go 1.25+**
- Make

## Getting Started

```bash
git clone https://github.com/ubyte-source/go-authware.git
cd go-authware
make all
```

## Running Tests

```bash
make test        # All tests
make race        # All tests with race detector
make bench       # Benchmarks with memory profiling
make cover       # Coverage report
make vet         # go vet
make lint        # golangci-lint (39 linters incl. gosec, 0 issues)
make vuln        # govulncheck against module deps
make fuzz        # All fuzz targets (FUZZTIME=30s by default)
make ci          # Full CI pipeline (vet+lint+sec+vuln+test+cover+bench)
```

## Performance Constraints

All authentication hot paths must use:
- `crypto/subtle.ConstantTimeCompare` for token/key comparison
- Zero-allocation `unsafe.Slice` for string→[]byte conversion where safe
- Pooled combined buffer (via `sync.Pool`) for JWT decode to minimize allocations

## Code Style

Follow the Go standard project layout. Run `gofmt` and `golangci-lint` before submitting.
