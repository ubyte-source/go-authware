# Contributing

## Prerequisites

- Go 1.25.1 or later (the version in `go.mod`), with cgo for the race detector
- make, and jq for `make testtime`

The Makefile runs every tool at a pinned version through `go run`:
golangci-lint v2.14.0, govulncheck v1.8.0, deadcode v0.50.0 and nilaway.
Nothing needs a global install; `GOLANGCI_LINT=<path>`, `GOVULNCHECK=<path>`,
`DEADCODE=<path>` and `NILAWAY=<path>` point the targets at local binaries of
the same versions. golangci-lint builds and runs with Go 1.27.1
(`GOTOOLCHAIN=go1.27.1`), the others with Go 1.26 or later; the go command
fetches a missing toolchain.

```bash
git clone https://github.com/ubyte-source/go-authware.git
cd go-authware
make ci
```

## Workflow

1. Branch from `main` (`feature/…`, `fix/…`, `docs/…`).
2. Change the code together with its tests and with every document the
   change makes untrue: README (API and configuration), SECURITY (defenses
   and limits), `.env.example` (environment variables).
3. Run `make ci` until it passes.
4. Open a pull request describing what changes, why, and how it was tested.

`make ci` runs these targets, and the workflows run the same ones: `lint.yml`
runs `vet`, `lint` and `deadcode`, `test.yml` runs `modcheck`, `test`, `cover`
and `bench-smoke` on Go 1.25.14 and 1.27.1, `security.yml` runs `vuln` next to
CodeQL.

| Target        | Gate |
|---------------|------|
| `modcheck`    | `go mod download`, `go mod verify` and `go mod tidy -diff` |
| `vet`         | `go vet ./...` |
| `lint`        | golangci-lint v2.14.0 with `.golangci.yml` (gosec runs inside it) |
| `vuln`        | govulncheck v1.8.0 on the module and the toolchain |
| `deadcode`    | deadcode v0.50.0 `-test ./...`; any output fails |
| `test`        | the tests with `-shuffle=on`, without the race detector |
| `race`        | the tests with `-race`, `-shuffle=on` and `CGO_ENABLED=1`, writing `coverage.out` |
| `bench-smoke` | every benchmark 100 times, `-benchtime=100x` |
| `cover`       | `race`, then `coverage.html` and the total; fails below 100% |

`make testtime` runs the tests one at a time under the race detector and fails
on any test slower than `TESTTIME_MAX` seconds (10). `make final` runs the
delivery gates on an idle machine: `fmtcheck` (`gofmt -s`), `ci`, `nilaway`,
`race-repeat` (`-race -count=10 -shuffle=on`), `fuzz-final` (every fuzz target
for 60 s), `testtime` and `treecheck`, which after `make clean` fails on an
artefact, an untracked file of no source kind, an empty directory, a file not
stored with LF, or a `.gitattributes` without `* text=auto eol=lf`.

`make help` lists every target. The fuzz workflow runs every fuzz target
weekly, reading the list through `make fuzz-list`, which asks
`go test -list '^Fuzz'` for every `Fuzz` function of the module and
fails when there is none. `make fuzz` runs the same list for `FUZZTIME`
each, or only the `pkg:Target` entries of `FUZZ_TARGETS`, and fails on
an entry that names no fuzz target.

## Code

- Control flow stays linear; one helper per concern, no duplicated logic,
  no dead code, no code that exists only for tests, no mutable package state.
- Errors are wrapped with `%w` and context where they leave the package that
  met them; the errors of the internal packages, which carry their context,
  and those a decorator of `http.RoundTripper`, `slog.Handler` or
  `cred.TokenSource` forwards from its delegate pass unchanged. Callers that
  branch get sentinel or typed errors, and tests declare one sentinel per
  purpose instead of building errors inline.
- Contexts are propagated, never stored for later.
- A type is declared above its first use in the file.
- Struct fields are grouped by meaning, with the boolean flags pooled in one
  trailing block; govet runs every analyzer but `fieldalignment`.
- JSON goes through go-jsonfast, walked as strings, so its views are
  substrings safe to keep; a value kept longer than its document, such as
  cached metadata, keys and token responses, is copied to let the document go.
- Secrets are `secret.Value`; compare them with `Equal`, never `==`.
- `//nolint` names one linter and says why the code is safe.
- Production code imports neither `encoding/json` nor `unsafe`, and
  go-jsonfast is the only dependency.

## Comments

- English, present tense, short: at most 3 lines per block and 88 columns.
- They explain what the code cannot say. No history ("previously", "no
  longer", "legacy", "replaces", "deprecated"), no notes to self ("todo",
  "for now"), no citation of an RFC or a Markdown file, no restated code, no
  commented-out code.
- One package comment per package, in `doc.go`, which may be longer.

## Tests

- Every code file `foo.go` has exactly one sibling `foo_test.go` holding all
  its tests, benchmarks, fuzz targets and examples. `doc.go` has none.
- Test names start with a symbol declared in the sibling file:
  `Test<Symbol><Scenario>` in CamelCase, such as `TestCacheGetStale`.
- `doc_test.go` holds package fixtures only (helpers, `TestMain`, shared
  literals), never tests.
- Assertions use the standard library only (`t.Fatalf` and `t.Errorf` with
  got and want).
- Every fuzz target has a real oracle: the standard library or a reference
  written independently of the code under test.
- A test must fail when the behavior it names breaks; check it by breaking
  the code once before you trust it. Every security check has such a test,
  and a negative test asserts the specific sentinel with `errors.Is`.
  other package selects: of every package, or in library mode of the
  internal packages only.

## Commit messages

Imperative mood, a subject of at most 50 characters, a blank line, then what
changes and why.

## License

Contributions are licensed under the MIT license of the project.
