# Changelog

All notable changes to `gobin` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1]

Full WebAssembly container support, a broad set of public-API ergonomics
upgrades, and a redesigned pclntab caching model that does not leak memory.

### Added

WebAssembly support — `GOOS=js GOARCH=wasm` (and the newer `wasip1` Go 1.21+
target) now parses end-to-end with the same surface as ELF / Mach-O / PE:

- New `BinaryFormat::Wasm` variant; `\0asm` magic detection in
  `detect_format`.
- New `structures::wasm` module exposes a minimal section walker, a Data
  section segment decoder (`data_segments`), and a linear-memory image
  reconstructor (`build_linear_memory_image`). Several Go runtime
  structures (pcHeader, moduledata, type descriptors) span multiple
  disjoint segments in linear memory; the reconstructed image lets the
  same parsers that handle native formats address them by VA.
- pclntab parsing, function enumeration, type extraction, string scanning,
  inline-tree walking, and moduledata discovery all work on wasm. The
  Go-emitted `go:buildid` custom section is recognized; build ID and Go
  version extraction succeed. Test sample committed at
  `tests/samples/basic_wasm.wasm`.
- Adversarial wasm with absurd linear-memory offsets is gated behind a
  256 MiB sanity cap on the reconstructed image.

New accessors and ergonomics helpers:

- `bin.entry_va(func)` / `bin.entry_rva(func)` — fold
  `text_va + entry_off` (and the PE-only `image_base` subtraction) into
  one accessor so downstream disassemblers do not have to reimplement it.
  `BinaryContext::image_base()` exposed in support.
- `bin.arch()` — format-disambiguated architecture accessor that resolves
  the `(minLC=1, ptrSize=8)` ambiguity between `Arch::X86_64` and
  `Arch::Wasm` using the container format, and falls back to build-info
  `GOARCH` when no pclntab is present.
- `Display` and stable `as_str` on every public enum that downstreams
  persist: `Confidence`, `PclntabVersion`, `Arch`, plus `kind_str` on
  `TypeDetail` and `ObfuscationKind`. Stability contract documented
  on each type.
- `BuildMode::as_str() -> Cow<'static, str>` + `Display`, round-tripping
  through `BuildMode::parse`.
- `ParsedPclntab::decode_pcln_with_files(func)` — joined iterator yielding
  `(pc, line, file_path)` per source-line transition with the active file
  pre-attached, replacing the "walk pcln and pcfile in lockstep" loop
  callers otherwise reinvent.
- Direct `TypeDetail` accessors: `array_len`, `chan_dir`, `func_arity`,
  `struct_field_count`, `interface_method_count`.
- Stdlib / runtime classification on `GoType` (`is_runtime`, `is_internal`,
  `is_stdlib`) plus shared free helpers `is_runtime_path` /
  `is_internal_path` / `is_stdlib_path` so type-side and function-side
  classifications agree on one canonical rule.
- `FuncData::args_size() -> u32` — typed view of the raw signed `args`
  field (negative readings collapse to `0`).
- `GoString::as_bytes()` and `try_as_str() -> Result<&str, Utf8Error>`.
  The string scanner no longer silently drops non-UTF-8 length-prefixed
  payloads (common in malware rodata).

Address-space + caching internals:

- `BinaryContext::structure_search_data()` returns the wasm linear-memory
  image for wasm and the file bytes otherwise; `BinaryContext::va_to_file`
  produces offsets into this view for every format.
- `BinaryContext::slice_at_va(va)` — borrow a slice starting at the byte
  at virtual address `va`; spans wasm data-segment boundaries seamlessly.
- `PclntabMeta` — scalar metadata of a `ParsedPclntab` without the
  borrowed `data`. Cache it; rehydrate via `PclntabMeta::attach(data)`.
  `ParsedPclntab::meta()` extracts it.
- `ParsedPclntab` is now `Copy` (every field already was).

### Changed

`GoBinary` no longer caches a `ParsedPclntab` borrowing from the input.
Instead it caches the scalar `PclntabMeta` and rebuilds the borrowing
struct against `&self.ctx.structure_search_data()` per call. This is what
allows wasm support without a `Box::leak` — the wasm linear-memory image
is owned by `BinaryContext` and borrows handed out to callers tie to
`&self`.

- `GoBinary::pclntab(&self) -> Option<ParsedPclntab<'_>>` — was
  `Option<&ParsedPclntab<'a>>` (breaking). Method calls and
  `let Some(pcl) = ...` patterns are unchanged; sites that explicitly
  named the reference type must drop the `&`.
- `FunctionIter::new(pcl: Option<ParsedPclntab<'a>>)` — takes the struct
  by value (it's `Copy`) instead of by reference. The iterator is no
  longer parameterized on the pcl-borrow lifetime: `FunctionIter<'a>`
  (was `FunctionIter<'p, 'a>`).
- `TypeIter`, `ItabIter`, `GoStringIter`, `InlineTreeIter` — lost their
  `'ctx` / `'pcl` lifetime parameter; yielded items borrow from
  `&BinaryContext` (was the input lifetime). Callers that collect into a
  `Vec` keep working as long as they hold the `GoBinary`.
- `pclntab::parse(ctx)` now takes `&'a BinaryContext<'a>` — required so
  the returned struct can borrow from either the input bytes or the wasm
  linear-memory image with one lifetime.
- Stability-policy sections lifted to type-level rustdoc on `Confidence`,
  `BuildMode`, `ObfuscationKind`, `Arch`, `PclntabVersion`, `TypeDetail`:
  variants append-only, `Display` strings frozen, `Debug` not a stability
  surface.
- `bin.strings()` no longer pre-filters UTF-8. Use `GoString::try_as_str` /
  `as_str` for text or `as_bytes` for raw rodata.
- `ParsedPclntab::arch()` rustdoc clarified: `(1, 8)` always returns
  `Arch::X86_64`; use `GoBinary::arch()` for format-aware disambiguation.
- `text_va()` rustdoc no longer publishes a manual translation recipe —
  it points to the new `entry_va` / `entry_rva` instead.
- Lints moved from a `#![deny(...)]` attribute on `lib.rs` to a `[lints]`
  table in `Cargo.toml`, so they enforce on every consuming workspace
  build (not just standalone). Tests, examples, and the integration test
  binary explicitly `#![allow(...)]` the test-friendly subset.
- `InlineEntry::depth` rustdoc documents the realistic upper bound (real
  Go inline chains are < 5 deep; the walker caps at 32). Type stays `u32`
  for forward compatibility.

### Fixed

- Wasm binaries now report `Arch::Wasm` from `GoBinary::arch()`
  (previously misreported as `X86_64`, a side-effect of the
  `(minLC=1, ptrSize=8)` ambiguity).
- `examples/dump.rs`: `--explain` argv handling no longer panics if
  `argv[0]` is missing; SDK-file path arithmetic uses checked offsets.
- Workspace lint enforcement caught a handful of pre-existing lint
  violations in `examples/dump.rs` (indexing and arithmetic on
  input-derived values), now fixed.

### Documentation

- `BinaryFormat::Wasm` rustdoc explains why wasm gets a reconstructed
  linear-memory image, why `image_base = 0`, and why `text_va`/`etext_va`
  are PC values rather than file offsets.
- `BinaryContext` accessor block reordered (basic accessors → translation
  → address-space helpers → format-specific) with the wasm-aware members
  documented inline.
- Top-level `## Supported Formats` table now includes Wasm.
- All inline `crate::...` paths in code (not docs) hoisted to `use`
  statements at the top of their files.

## [0.2.0]

A large feature pass plus internal hardening for use in malware analysis
pipelines. **Many breaking API changes** — see *Removed* and *Changed*.

### Added — new extraction surfaces

- **Per-PC inlining tree** — `bin.inline_tree(func)` yields
  `inline::InlineEntry { pc_range, function_name, parent_pc, start_line,
  func_id, depth }` per PC range with cycle-safe parent-chain walk for
  depth computation.
- **Go string literal scanner** — `bin.strings()` yields `GoString<'a> {
  va, len, bytes }` for every `(ptr, len)` header that resolves to in-binary
  UTF-8. Recovers strings a generic byte-string extractor would miss or
  split on internal NULs.
- **Itab pairs** — `bin.itab_pairs()` yields `ItabPair { iface_type_va,
  concrete_type_va, hash, itab_va }` for every `(interface, concrete type)`
  pair the linker proved at build time.
- **Per-function inlining accessors** — `FuncData::func_off`,
  `ParsedPclntab::pcdata_at`, `ParsedPclntab::funcdata_at` for the
  variable-length tables after the `_func` 44-byte prefix.
- **Garble obfuscation detection** — `bin.obfuscation()` returns
  `ObfuscationKind { None, Garble { confidence }, Other { reason } }`;
  `bin.is_likely_garbled()` convenience.
- **Compiler identification** — `bin.compiler()` returns `Compiler { Gc,
  TinyGo, Gccgo, Unknown }`.
- **Cgo / concurrency presence** — `bin.has_cgo()` and
  `bin.uses_concurrency()` short-circuit on the first matching function.
  Per-call-site enumeration deferred (needs disassembler).
- **Runtime address accessors** — `bin.text_va()`, `bin.etext_va()` expose
  `runtime.text` / `runtime.etext` with documented translation recipe for
  `entry_off → VA / RVA`.
- **Runtime commit hash** — `bin.runtime_commit()` extracts the dev commit
  from `devel go1.X-<hash>` version strings.
- **Build mode / tags / dependencies** — `BuildInfo::build_mode()` returns
  `BuildMode` enum; `build_tags()` iterates `-tags`; `dependencies()` and
  `build_settings_iter()` provide iterator accessors.
- **Module replacements + sums** — `DepEntry { path, version, sum,
  replacement }` + `DepReplacement` parsed from modinfo `dep` /
  `=>` / sum lines.
- **Method extraction on types** — `GoType.methods: Vec<MethodEntry>` for
  every type with an `UncommonType`. Resolves names, type-descriptor
  offsets, text offsets, and exported flag.
- **Deep type structure** — `TypeDetail` extended with:
  - `Struct.fields: Vec<StructField>` with name / type VA / offset / embedded
  - `Interface.methods: Vec<InterfaceMethod>`
  - `Map { key_va, elem_va }`, `Pointer { elem_va }`, `Slice { elem_va }`,
    `Chan { dir, elem_va }`, `Array { len, elem_va }`
  - `Func { in_count, out_count, is_variadic, inputs: Vec<u64>,
    outputs: Vec<u64> }`
- **`FuncFlags` newtype** — `FunctionInfo::func_flags()` returns typed view
  of the `_func.flag` byte; `is_top_frame()`, `is_sp_write()`,
  `is_asm()`, `is_systemstack()` accessors.
- **Receiver parsing** — `FunctionInfo::receiver_type() ->
  Option<ReceiverSpec { name, pointer, generic_args }>` plus
  `method_name()` and `generic_args()` accessors.
- **Per-PC file resolution** — `ParsedPclntab::resolve_file_via_cu` is now
  `pub`; `decode_pcfile_paths(func)` streams `(pc, &str)` per inlined
  region.
- **Structured detection report** — `GoBinary::try_parse() ->
  Result<GoBinary, ParseError>` returning `ConfidenceReport` of typed
  `ConfidenceSignal` variants on success or failure. `bin.report()`
  accessor exposes the same on success.
- **Bulk function decoder** — `metadata::for_each_function(pcl, |info,
  tables|)` walks every function with reusable per-PC table buffers,
  amortizing allocation across the whole binary.
- **Fast detection** — `gobin::detect(&[u8]) -> bool` does magic-byte +
  buildinfo header check without invoking `goblin` parse.
- **`examples/dump --explain`** — prints structured detection report
  (Confidence tier + per-signal breakdown).
- **moduledata accessors** — `bin.moduledata()`, `Moduledata::rodata`,
  `Moduledata::gofunc` exposed.
- **Iterator-style API throughout** — `bin.functions()`, `bin.types()`,
  `bin.itab_pairs()`, `bin.strings()`, `bin.inline_tree()` are all true
  streaming iterators (`FunctionIter`, `TypeIter`, `ItabIter`,
  `GoStringIter`, `InlineTreeIter`). Per-PC table decoders likewise
  (`PcValueIter`, `PcLineIter`, `PcFileIter`, `PcFilePathIter`).
- **Property tests** — `package() + "." + short_name() == name` round-trip
  property test plus a corpus of well-known Go function-name shapes.
- **Centralized helpers** in `structures::util`: `slice_at::<N>`,
  `advance`, `advance_n`, `align_up`, `align_up_u64`, `read_uvarint`,
  `read_uintptr`, `read_u32`, `read_i32`, `read_u16` — single source of
  truth for offset arithmetic and primitive reads.

### Changed — borrowed metadata types (breaking)

All metadata types now borrow from the input binary via lifetime `'a`,
matching `FunctionInfo<'a>`. Callers that need to outlive the binary's
lifetime must `.to_owned()` at the boundary.

- `GoType` → `GoType<'a>` — `name: String` becomes `&'a str`; `methods:
  Vec<MethodEntry<'a>>`; `detail: TypeDetail<'a>`.
- `MethodEntry`, `StructField`, `InterfaceMethod` — same treatment.
- `BuildInfo` → `BuildInfo<'a>` — all string fields borrow from the modinfo
  blob.
- `DepEntry` → `DepEntry<'a>`, `DepReplacement` → `DepReplacement<'a>`.
- `GoBinary.go_version` and `GoBinary.build_id` — now `Option<&'a str>`
  storage; accessors return `Option<&'a str>`.

### Changed — name parsing rewrites (breaking semantics)

- `FunctionInfo::package()` and `short_name()` rewritten — boundary is now
  "first `.` after the last `/`" plus a `gopkg.in`-style `.vN` extension.
  Third-party functions like `github.com/spf13/cobra.(*Command).Run` now
  return `package = "github.com/spf13/cobra"` instead of `"github"`.
- `FunctionInfo::is_method()` — structural parser. Catches value-receiver
  methods (`time.Time.String`) the old `".("` substring heuristic missed,
  and excludes closures.
- `FunctionInfo::is_closure()` — strict: requires `.funcN` / `.gowrapN`
  numeric suffix and excludes asm-flagged functions.
- `decode_pcvalue` for pcfile — `decode_pcfile(func)` yields `(u32, u32)`
  (was `(u32, i32)`); file indices are unsigned.

### Changed — streaming-only iterator API (breaking)

Every `Vec`-returning method that had a streaming counterpart was dropped.
Iterators replace them under the same names:

- `bin.types() -> TypeIter` (was `Vec<GoType>`).
- `bin.itab_pairs() -> ItabIter` (was `Vec<ItabPair>`).
- `pclntab.decode_pcvalue / decode_pcln / decode_pcfile / decode_pcfile_paths`
  now return iterators (were `Vec`).
- `BuildInfo::build_tags() -> impl Iterator<Item = &'a str>` (was
  `Vec<&str>`).
- Internal helpers `for_each_function`, `bin.has_cgo()`,
  `bin.uses_concurrency()`, `bin.obfuscation()` now use the new iterators
  internally; `has_cgo` and `uses_concurrency` short-circuit on the first
  match.

To get an owned `Vec`, call `.collect()`.

### Changed — module renames

- `structures::gostring::GoString` → `GoStringHeader` (it was always just
  the `(ptr, len)` header pair). The `GoString<'a>` name now belongs to
  the public scanned-string type in `structures::strings`.

### Removed — legacy convenience APIs (breaking)

- `metadata::extract_functions(pcl) -> Vec<FunctionInfo>` — use
  `bin.functions()` or `FunctionIter::new(Some(pcl))`.
- `bin.types_iter()` / `bin.itab_pairs_iter()` aliases — the canonical
  names (`bin.types()` / `bin.itab_pairs()`) now return the iterators.
- `pclntab.decode_pcvalue_into / decode_pcln_into / decode_pcfile_into`
  buffer-reuse variants — use `buf.clear(); buf.extend(decode_*(...))`
  with the streaming iterators (same allocation behavior).
- `ParsedPclntab::read_ptr` — was dead code internally.

### Fixed

- `read_pointer_array` and several other internal helpers now bounds-check
  every read.
- Heuristic obfuscation thresholds ignore runtime / internal packages so
  the ratio reflects user code only.
- Buildinfo modinfo parser now handles `=>` replacement lines and `dep`
  sum-hash columns it previously ignored.
- `gopkg.in/yaml.v3.Marshal`-style names no longer split as
  `package = "gopkg.in/yaml"` (now `"gopkg.in/yaml.v3"`).

### Security — panic-free lint sweep

This crate is used for malware analysis: every input byte is adversarial
and must not be allowed to panic the parser.

- Adopted `#![deny(missing_docs, clippy::unwrap_used, clippy::expect_used,
  clippy::panic, clippy::arithmetic_side_effects, clippy::indexing_slicing)]`
  in `lib.rs` (test code allows them).
- Swept **413 violations** across all 22 source files to zero. Every
  indexing operation now uses `.get(...)?`, every arithmetic on
  input-derived values uses `checked_*` / `saturating_*` per intent, every
  `unwrap` outside tests is replaced with `?` propagation.
- Wrapping arithmetic preserved where intentional (the pcvalue zigzag
  decoder matches Go's runtime behaviour) with explanatory comments.

A non-malicious adversarial binary can no longer panic the parser through
any `parse` / `extract` / `decode` path. Failures degrade to `None` /
`Err` / empty iterator / zero items.

### Documentation

- `examples/dump.rs` extended with `--explain` mode; updated for the
  iterator-first API and borrowed metadata types.
- `bin.text_va()` doc now includes the `entry_off` translation recipe.
- pclntab parser docs reference exact Go runtime source line ranges.

### Coverage

- 222 tests pass (130 unit + 88 integration + 4 doc).
- Property tests cover `package()` / `short_name()` invariants.
- Integration tests verify zero-copy borrowing (asserting `BuildInfo`
  fields' pointers fall inside the input slice).
- Inline-tree decoder exercised on the basic_normal corpus: 1,979
  functions with inlining, 24,438 entries, depth distribution
  `{0: 17686, 1: 5604, 2: 1022, 3: 124, 4: 2}`.
- String scanner verified across Mach-O / ELF / PE plus stripped
  binaries (1k–1.5k unique strings recovered per binary).

## [0.1.0] — initial release

Initial public release.

- Detection of ELF, Mach-O, and PE Go binaries.
- pclntab parsing with magic-byte + structural-fallback strategies.
- Build info, build ID, Go version extraction.
- Function metadata (`FunctionInfo`) and source file resolution.
- Type descriptor extraction via `.typelink` and descriptor walking.
- Heuristic confidence scoring (`Confidence` enum).

[0.2.1]: https://github.com/BinFlip/gobin/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/BinFlip/gobin/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/BinFlip/gobin/releases/tag/v0.1.0
