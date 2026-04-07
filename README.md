# gobin

Static analysis library for Go compiled binaries.

This crate extracts metadata that the Go runtime embeds in every binary:
function names, source file paths, Go version, module dependencies, build
settings, and type descriptors. All of this survives stripping
(`-ldflags="-s -w"`) because the runtime needs it at execution time.

## Quick start

```rust
use gobin::GoBinary;

let data = std::fs::read("some_go_binary").unwrap();
if let Some(bin) = GoBinary::parse(&data) {
    println!("Go version: {}", bin.go_version().unwrap_or("unknown"));
    println!("Functions:  {}", bin.function_count().unwrap_or(0));

    for f in bin.functions() {
        println!("  {}", f.name);
    }
}
```

## What it parses

- **Format detection** for ELF, Mach-O, and PE binaries
- **Build ID** extraction (ELF note + raw text-segment marker)
- **Build info** blob: Go version, module path, dependencies, build settings (GOOS, GOARCH, VCS info)
- **pclntab** (PC/line table): function names, source file paths, line numbers, entry offsets
- **Type descriptors**: `abi.Type` structs via `.typelink` section or moduledata walking
- **Architecture inference** from pclntab header fields (`minLC`, `ptrSize`)
- **Confidence scoring**: High (structural proof), Medium (version string), Low (heuristic)

## Example tool

The included `dump` example produces a full metadata dump of a Go binary:

```sh
cargo run --example dump -- path/to/go_binary
```

## Disclaimer

The Go binary format is defined by the Go compiler and runtime source code
(`src/runtime/`, `src/internal/abi/`, `src/cmd/link/`). All structure layouts
and field semantics in this crate are derived from the Go 1.26.1 source tree.
The pclntab format has been stable across versions with well-defined magic
numbers for version detection, but future Go releases may introduce changes.

## License

Apache-2.0
