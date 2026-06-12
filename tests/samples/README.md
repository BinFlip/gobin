# Test samples

Reproducible binary fixtures for the integration suite. This directory is
excluded from the published crate (`exclude = ["tests/samples/"]` in
`Cargo.toml`), so size is not a concern.

Every fixture is built with **`-trimpath`**, so no local filesystem paths leak
in — embedded source paths are module-relative (e.g. `gobin.test/basic/main.go`).

## Naming

```
<prog>_go<minor>_<goos>_<goarch>[_stripped][.exe]
```

The Go minor version maps to a moduledata + pclntab layout the parser must
detect:

| Tag     | Toolchain      | pclntab | Moduledata | Notes                              |
|---------|----------------|---------|------------|------------------------------------|
| `go116` | go1.16.15      | Go116   | V2         | pre-1.18 pcHeader/functab/_func, legacy type-name encoding |
| `go119` | go1.19.13      | Go118   | V3         | +rodata/gofunc; _func without startLine |
| `go121` | go1.21.13      | Go120   | V3         | +covctrs, +inittasks; no epclntab  |
| `go124` | go1.24.13      | Go120   | V3         | no epclntab (added in 1.26)        |
| `go126` | go1.26 (system)| Go120   | V4         | +epclntab, `.go.module` section    |
| `go127` | gotip (1.27dev)| Go120   | V5         | inline itabs, no typelinks         |

`_stripped` = `-ldflags="-s -w"`. `.exe` = PE/Windows.

## Programs (sources under `src/`)

- `src/basic/` — the primary fixture: `main.main`, `main.worker`,
  `main.(*TestStruct).DoSomething`, interfaces with multiple implementors
  (itabs), a goroutine + channel, `defer`, a closure, and `fmt`/`strings` use.
  Also the source for the `fips_*` (built with `GOFIPS140`) and wasm fixtures.
- `src/minimal/` — smallest useful program (no `fmt`); near-empty metadata.
- `src/plugin/` — a `-buildmode=plugin` Go plugin with exported symbols. Built
  natively (CGO) it is a Mach-O dylib using **chained fixups**, exercising the
  pointer-rebasing path (`plugin_go126_darwin_arm64.so`).
- `src/embed/` — `//go:embed assets/*` (multi-file `embed.FS` with a nested
  dir and a binary blob) plus a single-file `//go:embed` string.

## Rebuilding

```sh
tests/samples/build.sh
```

The script rebuilds the whole matrix from `src/` with `-trimpath` and
`GOTOOLCHAIN=local` (so each toolchain builds with itself rather than
auto-upgrading). It removes the old `basic_*` / `minimal_*` binaries first.

Toolchains (install once):

```sh
go install golang.org/dl/go1.21.13@latest && go1.21.13 download
go install golang.org/dl/go1.24.13@latest && go1.24.13 download
go install golang.org/dl/gotip@latest      && gotip download   # 1.27 dev
# go1.26 is the system `go`
```

The integration suite's `mod matrix` discovers fixtures by filename, so adding
a build line to `build.sh` automatically extends test coverage.
