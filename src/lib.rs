//! # gobin: Go Binary Reverse Engineering Library
//!
//! A pure-Rust library for statically analyzing compiled Go binaries. Given an arbitrary
//! byte slice, `gobin` can determine whether it was produced by the Go toolchain and
//! extract rich metadata that the Go runtime embeds in every binary.
//!
//! ## Motivation
//!
//! Go binaries are unusually rich targets for static analysis. Unlike C/C++ binaries,
//! stripped Go binaries still contain:
//!
//! - **Full function names** (package-qualified, e.g. `net/http.(*Client).Do`)
//! - **Source file paths** (the full path used at compile time)
//! - **Go version** and **module dependency** information
//! - **Type descriptors** for every type used in the program
//!
//! This metadata survives stripping (`-ldflags="-s -w"`) because the Go runtime requires
//! it for stack traces, garbage collection, and interface dispatch. These structures are
//! defined in the Go source tree under `src/runtime/` and `src/internal/abi/`.
//!
//! ## Quick Start
//!
//! ```no_run
//! use gobin::GoBinary;
//!
//! let data = std::fs::read("some_binary").unwrap();
//! if let Some(bin) = GoBinary::parse(&data) {
//!     println!("Go version: {:?}", bin.go_version());
//!     for f in bin.functions() {
//!         println!("  {}", f.name);
//!     }
//! }
//! ```
//!
//! ## Supported Formats
//!
//! | Format | Detection | Build ID | Build Info | pclntab | Functions |
//! |--------|-----------|----------|------------|---------|-----------|
//! | ELF    | Yes       | ELF note + raw | Yes   | Yes     | Yes       |
//! | Mach-O | Yes       | Raw marker     | Yes   | Yes     | Yes       |
//! | PE     | Yes       | Raw marker     | Yes   | Yes     | Yes       |
//!
//! ## Architecture
//!
//! The crate is organized into two API layers:
//!
//! - **Low-level**: [`formats::BinaryContext`] parses the binary format once and provides
//!   zero-copy section slicing, VA translation, and ELF note access. Individual structure
//!   parsers ([`structures::pclntab`], [`structures::buildid`], etc.) take `&BinaryContext`.
//! - **High-level**: [`GoBinary`] wraps `BinaryContext` and performs the full Go metadata
//!   extraction pipeline, exposing comfortable accessors for functions, types, build info, etc.

// This crate is used for malware analysis: every input byte is
// adversarial and must not be allowed to panic the parser.
#![deny(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::arithmetic_side_effects,
        clippy::indexing_slicing
    )
)]

pub mod detection;
pub mod formats;
pub mod metadata;
pub mod structures;

use crate::{
    detection::{
        Confidence, ConfidenceReport, ConfidenceSignal, ParseError, VersionSource, heuristic_hits,
    },
    formats::{BinaryContext, BinaryFormat},
    metadata::{BuildInfo, Compiler, FunctionIter, ObfuscationKind},
    structures::{
        buildid, buildinfo, inline, itab,
        moduledata::Moduledata,
        pclntab::{self, FuncData, ParsedPclntab},
        strings as gostrings, types,
    },
};

/// A parsed Go binary with all extractable metadata.
///
/// Created via [`GoBinary::parse`], which performs a multi-layered analysis:
///
/// 1. **Binary context** -- Parses the executable format once (via `goblin`),
///    collecting section locations, VA mappings, and ELF notes.
/// 2. **Section discovery** -- `.gopclntab`, `.go.buildinfo`, `.note.go.buildid`, etc.
/// 3. **Magic byte scanning** -- build ID prefix, build info header, pclntab magic
/// 4. **Structure parsing** -- pcHeader, functab, _func structs, build info blobs
/// 5. **Heuristic fallback** -- runtime string patterns for heavily patched binaries
///
/// The lifetime `'a` ties all extracted string references back to the original byte slice,
/// enabling zero-copy access to function names and source file paths.
pub struct GoBinary<'a> {
    report: ConfidenceReport,
    ctx: BinaryContext<'a>,
    build_id: Option<&'a str>,
    build_info: Option<BuildInfo<'a>>,
    pclntab: Option<ParsedPclntab<'a>>,
    go_version: Option<&'a str>,
    moduledata: Option<Moduledata>,
}

impl<'a> GoBinary<'a> {
    /// Analyze a byte slice and return a [`GoBinary`] if it appears to be a Go binary.
    ///
    /// Returns `None` if no Go-specific indicators are found. The detection uses
    /// multiple independent signals so that even binaries with some markers patched
    /// out can still be identified (at a lower [`Confidence`] level).
    ///
    /// # Detection Order
    ///
    /// 1. Section names (`.gopclntab`, `.go.buildinfo`, `.note.go.buildid`)
    /// 2. Build ID raw marker (`\xff Go build ID: "..."`)
    /// 3. Build info header (`\xff Go buildinf:`)
    /// 4. pclntab magic bytes (`0xfffffff1` etc.)
    /// 5. Heuristic string patterns (`runtime.main`, `runtime.goexit`, etc.)
    ///
    /// # Working with mmap-ed input
    ///
    /// `parse` borrows the input for the lifetime of the returned [`GoBinary`].
    /// Any byte slice works — including one backed by `memmap2::Mmap` —
    /// regardless of source. There is no separate mmap-specific entry point;
    /// just pass `&mmap[..]`.
    ///
    /// Convenience wrapper around [`Self::try_parse`] that discards the
    /// [`ParseError`] detail. Use `try_parse` if you need the structured
    /// detection report on failure (for diagnostics or analyst-facing output).
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        Self::try_parse(data).ok()
    }

    /// Like [`Self::parse`], but returns a structured [`ParseError`] on failure
    /// containing the [`ConfidenceReport`] gathered during detection.
    ///
    /// Detection signals are also retained on success, accessible via
    /// [`Self::report`] — useful for surfacing analyst-facing diagnostics
    /// (e.g. "Go binary, but pclntab missing — likely heavily patched").
    pub fn try_parse(data: &'a [u8]) -> Result<Self, ParseError> {
        let ctx = BinaryContext::new(data);
        let mut report = ConfidenceReport::empty();

        let sections = ctx.sections();
        if sections.has_gopclntab {
            report.push(ConfidenceSignal::GopclntabSectionPresent);
            report.raise_to(Confidence::High);
        }
        if sections.has_go_buildinfo {
            report.push(ConfidenceSignal::BuildinfoSectionPresent);
            report.raise_to(Confidence::High);
        }
        if sections.has_go_buildid_note {
            report.push(ConfidenceSignal::BuildidNotePresent);
            report.raise_to(Confidence::High);
        }

        let build_id = buildid::extract(&ctx);
        if build_id.is_some() {
            report.push(ConfidenceSignal::BuildIdMarkerFound);
            report.raise_to(Confidence::High);
        }

        let build_info_result = buildinfo::extract(&ctx);
        match build_info_result.as_ref() {
            Some(_) => {
                report.push(ConfidenceSignal::BuildinfoParsed);
                report.raise_to(Confidence::Medium);
            }
            None => {
                report.push(ConfidenceSignal::BuildinfoMissing {
                    reason: "no buildinfo magic header found",
                });
            }
        }

        let pclntab_result = pclntab::parse(&ctx);
        match pclntab_result.as_ref() {
            Some(p) => {
                report.push(ConfidenceSignal::PclntabParsed {
                    version: p.version,
                    nfunc: p.nfunc,
                });
                report.raise_to(Confidence::High);
            }
            None => {
                report.push(ConfidenceSignal::PclntabMissing {
                    reason: "no pclntab magic / structural pattern matched",
                });
            }
        }

        let (go_version, version_source): (Option<&'a str>, VersionSource) =
            match build_info_result.as_ref().and_then(|bi| bi.go_version) {
                Some(v) => (Some(v), VersionSource::BuildInfoBlob),
                None => (
                    buildinfo::find_version_string(data),
                    VersionSource::StringScan,
                ),
            };
        if let Some(v) = go_version {
            report.push(ConfidenceSignal::GoVersionString {
                version: v.to_string(),
                source: version_source,
            });
            report.raise_to(Confidence::Medium);
        }

        if report.tier == Confidence::None {
            let hits = heuristic_hits(data);
            if hits >= 3 {
                report.push(ConfidenceSignal::HeuristicStringsMatched { hits });
                report.raise_to(Confidence::Low);
            }
        }

        if report.tier == Confidence::None {
            return Err(ParseError::NotAGoBinary { report });
        }

        let moduledata = pclntab_result
            .as_ref()
            .and_then(|p| find_moduledata(&ctx, p, go_version));

        Ok(GoBinary {
            report,
            ctx,
            build_id,
            build_info: build_info_result,
            pclntab: pclntab_result,
            go_version,
            moduledata,
        })
    }

    /// The raw byte slice this analysis was built from.
    pub fn data(&self) -> &'a [u8] {
        self.ctx.data()
    }

    /// The low-level binary context providing section data and VA translation.
    pub fn context(&self) -> &BinaryContext<'a> {
        &self.ctx
    }

    /// How confident the library is that this is a Go binary.
    pub fn confidence(&self) -> Confidence {
        self.report.tier
    }

    /// Structured detection report — the confidence tier plus every signal
    /// observed during parse.
    ///
    /// Useful for analyst-facing diagnostics ("Go binary, but pclntab is
    /// missing — likely heavily patched") and for surfacing details in bug
    /// reports.
    pub fn report(&self) -> &ConfidenceReport {
        &self.report
    }

    /// The Go toolchain version, e.g. `"go1.26.1"`.
    ///
    /// Extracted from the build info blob or by scanning for `"go1."` string patterns.
    pub fn go_version(&self) -> Option<&'a str> {
        self.go_version
    }

    /// The Go build ID.
    ///
    /// For executables this is a 4-part string: `actionID/actionID/contentID/contentID`,
    /// where each part is 20 characters of URL-safe base64 derived from SHA256 hashes.
    ///
    /// See [`structures::buildid`] for format details.
    pub fn build_id(&self) -> Option<&'a str> {
        self.build_id
    }

    /// Build metadata including module path, dependencies, and build settings.
    ///
    /// Contains GOOS, GOARCH, CGO_ENABLED, VCS info, and the full dependency list.
    /// See [`BuildInfo`] for accessor methods.
    pub fn build_info(&self) -> Option<&BuildInfo<'a>> {
        self.build_info.as_ref()
    }

    /// The parsed pclntab, if found. Provides zero-copy access to function names,
    /// source files, architecture, pointer size, and all other pclntab metadata.
    pub fn pclntab(&self) -> Option<&ParsedPclntab<'a>> {
        self.pclntab.as_ref()
    }

    /// Streaming iterator over every function recovered from the pclntab.
    ///
    /// Yields zero items if the binary has no recoverable pclntab.
    ///
    /// For bulk per-function processing where you also need decoded pcsp /
    /// pcln / pcfile tables, use [`crate::metadata::for_each_function`]
    /// instead — it amortizes table-decode buffers across the whole walk.
    pub fn functions(&self) -> FunctionIter<'_, 'a> {
        FunctionIter::new(self.pclntab.as_ref())
    }

    /// Streaming iterator over the per-PC inlining tree for a function.
    ///
    /// Yields one [`inline::InlineEntry`] per PC range during which an inlined
    /// frame is active. PC ranges with no inlining are skipped silently.
    /// Returns an empty iterator when:
    ///
    /// - The function has no inlined calls (no `funcdata[FUNCDATA_InlTree]`).
    /// - The binary has no recoverable pclntab.
    /// - `moduledata.gofunc` is unavailable (Go 1.16-1.19 / V2 binaries do not
    ///   expose this base, so funcdata cannot be resolved).
    ///
    /// Source: `src/runtime/symtabinl.go` (`inlineUnwinder`).
    pub fn inline_tree<'p>(&'p self, func: &FuncData) -> inline::InlineTreeIter<'p, 'a> {
        let pcl = match self.pclntab.as_ref() {
            Some(p) => p,
            None => return inline::InlineTreeIter::empty(),
        };
        inline::extract_iter(&self.ctx, pcl, self.moduledata.as_ref(), func)
    }

    /// The parsed moduledata, if discoverable.
    ///
    /// This carries cross-cutting runtime addresses such as the start/end of
    /// the Go-emitted text segment ([`Self::text_va`], [`Self::etext_va`]),
    /// the type-descriptor region, and slice headers for the runtime tables.
    pub fn moduledata(&self) -> Option<&Moduledata> {
        self.moduledata.as_ref()
    }

    /// Virtual address of `runtime.text` — the first byte of Go-emitted code.
    ///
    /// To translate a [`crate::structures::pclntab::FuncData::entry_off`] (a
    /// PC offset relative to `runtime.text`) into a binary-level VA:
    ///
    /// ```text
    /// va  = bin.text_va()? + func.entry_off as u64
    /// rva = va - image_base   // for image-base-relative formats (PE)
    /// ```
    ///
    /// Note: `entry_off` is **not** a `goblin`-derived RVA. Without adding
    /// `text_va`, addresses computed from `entry_off` will be wrong by the
    /// distance between the image base and `runtime.text`.
    pub fn text_va(&self) -> Option<u64> {
        self.moduledata.as_ref().map(|m| m.text)
    }

    /// Virtual address of `runtime.etext` — one past the last byte of
    /// Go-emitted code.
    ///
    /// `etext_va() - text_va()` gives the total size of all Go-emitted code,
    /// useful as an "amount of Go code in this binary" metric.
    pub fn etext_va(&self) -> Option<u64> {
        self.moduledata.as_ref().map(|m| m.etext)
    }

    /// Which Go compiler toolchain produced this binary.
    ///
    /// Detection order:
    /// 1. `-compiler` build setting (`gc`, `gccgo`, etc.) — authoritative.
    /// 2. `tinygo` substring in the Go version string.
    /// 3. Presence of pclntab → `gc` (TinyGo and gccgo do not produce it).
    /// 4. Otherwise [`Compiler::Unknown`].
    pub fn compiler(&self) -> Compiler {
        if let Some(info) = self.build_info.as_ref() {
            match info.setting("-compiler") {
                Some("gc") => return Compiler::Gc,
                Some("gccgo") => return Compiler::Gccgo,
                Some("tinygo") => return Compiler::TinyGo,
                _ => {}
            }
        }
        if self
            .go_version
            .map(|v| v.to_ascii_lowercase().contains("tinygo"))
            .unwrap_or(false)
        {
            return Compiler::TinyGo;
        }
        if self.pclntab.is_some() {
            return Compiler::Gc;
        }
        Compiler::Unknown
    }

    /// Heuristic obfuscation/protection detection.
    ///
    /// Currently recognizes `garble`-processed binaries by combining:
    /// - A high fraction of function package names matching the garble token
    ///   shape (`^[A-Za-z0-9_]{8,16}$`, no `/` separators).
    /// - Scrubbed module dependency list (typical of `garble -tiny`).
    /// - Buildinfo missing or buildinfo deps absent (`-trimpath`-like).
    pub fn obfuscation(&self) -> ObfuscationKind {
        if self.pclntab.is_none() {
            return ObfuscationKind::None;
        }

        let mut user_pkgs = std::collections::BTreeSet::new();
        for f in self.functions() {
            if f.is_runtime() || f.is_internal() {
                continue;
            }
            if let Some(pkg) = f.package() {
                user_pkgs.insert(pkg.to_string());
            }
        }
        if user_pkgs.is_empty() {
            return ObfuscationKind::None;
        }
        let total = user_pkgs.len();
        let obfuscated = user_pkgs.iter().filter(|p| is_garble_token(p)).count();
        let ratio = obfuscated as f32 / total as f32;

        let deps_scrubbed = self
            .build_info
            .as_ref()
            .map(|i| i.deps.is_empty())
            .unwrap_or(true);

        let confidence = if ratio >= 0.5 && deps_scrubbed {
            Confidence::High
        } else if ratio >= 0.5 {
            Confidence::Medium
        } else if ratio >= 0.2 {
            Confidence::Low
        } else {
            return ObfuscationKind::None;
        };
        ObfuscationKind::Garble { confidence }
    }

    /// Convenience: `true` if [`Self::obfuscation`] returned a `Garble` verdict.
    pub fn is_likely_garbled(&self) -> bool {
        matches!(self.obfuscation(), ObfuscationKind::Garble { .. })
    }

    /// The Go internal commit hash, if the binary was built from a development
    /// toolchain (e.g. `"devel go1.23-abc1234 ..."`).
    ///
    /// Returns `None` for released-version binaries (`"go1.22.3"`), where the
    /// commit hash is not stamped into the version string.
    ///
    /// For CVE matching against the Go toolchain itself, the commit hash is
    /// more precise than the marketing version — released versions only narrow
    /// to a tag.
    pub fn runtime_commit(&self) -> Option<&str> {
        let v = self.go_version?;
        let bytes = v.as_bytes();
        let mut i: usize = 0;
        while let Some(&byte) = bytes.get(i) {
            if byte == b'-' {
                let start = i.checked_add(1)?;
                let mut end = start;
                while bytes.get(end).is_some_and(|b| b.is_ascii_hexdigit()) {
                    end = end.checked_add(1)?;
                }
                if end.checked_sub(start)? >= 7 {
                    return v.get(start..end);
                }
                i = end;
            } else {
                i = i.checked_add(1)?;
            }
        }
        None
    }

    /// All `(interface, concrete type)` pairs the linker proved at build time.
    ///
    /// Decoded from the `.itablink` / `__itablink` section if present, falling
    /// back to `moduledata.itablinks`. Returns an empty `Vec` when neither
    /// source is available (heavily stripped binaries, future Go versions
    /// that drop itablinks).
    ///
    /// Useful for "what implements `io.Reader` in this binary?" queries —
    /// pair with [`Self::types`] to resolve each VA back to a named type.
    pub fn itab_pairs(&self) -> itab::ItabIter<'_, 'a> {
        let ptr_size = self.pclntab.as_ref().map(|p| p.ptr_size).unwrap_or(0);
        let itablinks = self
            .moduledata
            .as_ref()
            .and_then(|md| md.itablinks.as_ref());
        itab::extract_iter(&self.ctx, ptr_size, itablinks)
    }

    /// Whether the binary's pclntab references any cgo-related runtime
    /// functions (`runtime.cgocall`, `runtime.cgocallback`, etc.).
    ///
    /// This is a binary-level "did this binary use cgo at all?" signal — a
    /// strong indicator the program may execute native code from C (DLLs,
    /// syscalls, exploits). Per-call-site enumeration would require
    /// disassembly support, which the crate does not have today.
    pub fn has_cgo(&self) -> bool {
        // Short-circuits on the first matching function via the streaming
        // iterator — does not materialize the whole function list.
        self.functions().any(|f| is_cgo_runtime_fn(f.name))
    }

    /// Whether the binary references Go concurrency primitives
    /// (`runtime.newproc`, channel send/recv, select).
    ///
    /// Like [`Self::has_cgo`], this is a binary-level signal. A binary that
    /// imports `sync` but never calls `go` may still trigger this if the
    /// stdlib internally spawns goroutines. Short-circuits on the first
    /// matching function.
    pub fn uses_concurrency(&self) -> bool {
        self.functions().any(|f| is_concurrency_runtime_fn(f.name))
    }

    /// Streaming iterator over all types extracted from Go `abi.Type` descriptors.
    ///
    /// Uses the `.typelink` section (an array of `int32` offsets) and the
    /// `abi.Type` struct layout to recover every type the binary exposes to
    /// reflection. Each yielded [`types::GoType`] includes its name, kind, size,
    /// flags, kind-specific detail and resolved methods.
    ///
    /// Yields zero items if the required sections (`.typelink` / `.go.module`)
    /// or moduledata are not present. Adversarial input cannot panic the
    /// iteration; failed descriptor parses are skipped silently.
    ///
    /// Collect with `bin.types().collect::<Vec<_>>()` if you need an owned
    /// container.
    pub fn types(&self) -> types::TypeIter<'_, 'a> {
        let pclntab = match self.pclntab.as_ref() {
            Some(p) => p,
            None => return types::extract_types_iter(&self.ctx, 0, None, None, None),
        };
        let go_version_minor = self.go_version().and_then(parse_go_minor_version);
        types::extract_types_iter(
            &self.ctx,
            pclntab.ptr_size,
            Some(pclntab.version),
            Some(pclntab.offset),
            go_version_minor,
        )
    }

    /// Streaming iterator over Go string literals discovered by scanning the
    /// binary for `(ptr, len)` headers that resolve to in-binary UTF-8 bytes.
    ///
    /// Recovers strings that a generic byte-string extractor would miss
    /// (Go strings are not NUL-terminated) or split (they may contain
    /// internal NULs). Useful for TLSH / SSDeep / MinHash signal recovery
    /// on Go binaries.
    ///
    /// Yields zero items when the binary lacks VA mapping. Length filter:
    /// 2..=4096 bytes. UTF-8 validated. Pointers into the text segment
    /// (`[moduledata.text, moduledata.etext)`) are excluded. **Duplicates
    /// are not filtered** — a string referenced from N positions yields N
    /// times. Collect into a `HashSet<&str>` if you want unique results.
    pub fn strings(&self) -> gostrings::GoStringIter<'_, 'a> {
        let ptr_size = self.pclntab.as_ref().map(|p| p.ptr_size).unwrap_or(0);
        gostrings::extract_iter(&self.ctx, self.moduledata.as_ref(), ptr_size)
    }
}

/// Fast best-effort check for "is this byte slice a Go binary?" without
/// running the full parse pipeline.
///
/// Scans for any of three structural markers:
/// - The buildinfo magic header (`"\xff Go buildinf:"`)
/// - The build-id raw marker (`"\xff Go build ID:"`)
/// - A pclntab magic value at any 4-byte aligned offset
///
/// This is dramatically cheaper than [`GoBinary::parse`] because it does no
/// `goblin` format parse, no header decode, and no string-table walks. Use it
/// in ingest pipelines that need to *tag* a binary before deciding whether to
/// invoke the full analyzer.
///
/// False negatives are possible (heavily patched binaries where every marker
/// has been wiped). False positives are unlikely — these magic byte sequences
/// don't naturally appear in non-Go binaries.
pub fn detect(data: &[u8]) -> bool {
    use crate::detection::find_bytes;
    if find_bytes(data, b"\xff Go buildinf:").is_some() {
        return true;
    }
    if find_bytes(data, b"\xff Go build ID:").is_some() {
        return true;
    }
    const PCLNTAB_MAGICS: &[[u8; 4]] = &[
        [0xf1, 0xff, 0xff, 0xff],
        [0xf0, 0xff, 0xff, 0xff],
        [0xfa, 0xff, 0xff, 0xff],
        [0xfb, 0xff, 0xff, 0xff],
    ];
    let limit = data.len().saturating_sub(4);
    let mut offset: usize = 0;
    while offset <= limit {
        let end = match offset.checked_add(4) {
            Some(e) => e,
            None => break,
        };
        let m = match data.get(offset..end) {
            Some(s) => s,
            None => break,
        };
        for magic in PCLNTAB_MAGICS {
            if m == magic {
                return true;
            }
        }
        offset = match offset.checked_add(4) {
            Some(o) => o,
            None => break,
        };
    }
    false
}

/// Runtime function names indicating cgo usage.
///
/// Source: `src/runtime/cgo.go`, `src/runtime/cgocall.go`,
/// `src/runtime/cgocallback.go`.
const CGO_RUNTIME_FNS: &[&str] = &[
    "runtime.cgocall",
    "runtime.cgocallback",
    "runtime.cgocall_native",
    "runtime.asmcgocall",
    "runtime.cgoCheckPointer",
    "runtime._cgo_panic",
];

/// Runtime function names indicating goroutine / channel use.
///
/// Source: `src/runtime/proc.go` (newproc), `src/runtime/chan.go`
/// (chan{send,recv,close,recv1,recv2}), `src/runtime/select.go`.
const CONCURRENCY_RUNTIME_FNS: &[&str] = &[
    "runtime.newproc",
    "runtime.chansend",
    "runtime.chansend1",
    "runtime.chanrecv",
    "runtime.chanrecv1",
    "runtime.chanrecv2",
    "runtime.closechan",
    "runtime.selectgo",
];

fn is_cgo_runtime_fn(name: &str) -> bool {
    CGO_RUNTIME_FNS.contains(&name)
}

fn is_concurrency_runtime_fn(name: &str) -> bool {
    CONCURRENCY_RUNTIME_FNS.contains(&name)
}

/// Whether `pkg` looks like a garble-emitted obfuscated package token: 8-16
/// characters of `[A-Za-z0-9_]` with no `/` (path) separators and at least
/// one digit (real Go package names rarely contain digits).
fn is_garble_token(pkg: &str) -> bool {
    if pkg.contains('/') || pkg.contains('.') {
        return false;
    }
    let len = pkg.len();
    if !(8..=16).contains(&len) {
        return false;
    }
    let mut has_digit = false;
    for b in pkg.bytes() {
        if !(b.is_ascii_alphanumeric() || b == b'_') {
            return false;
        }
        if b.is_ascii_digit() {
            has_digit = true;
        }
    }
    has_digit
}

/// Parse the minor version from a Go version string like `"go1.26.1"` -> `26`.
fn parse_go_minor_version(version: &str) -> Option<u32> {
    let rest = version.strip_prefix("go1.")?;
    let minor_str = rest.split('.').next()?;
    minor_str.parse().ok()
}

/// Locate and parse the moduledata for accessor-only use (text/etext/types
/// region addresses).
///
/// Mirrors the moduledata-finding strategies in
/// [`crate::structures::types::extract_types`]: prefer the dedicated
/// `.go.module` section, fall back to PE pointer-scan discovery. Returns
/// `None` if the binary lacks VA mappings or moduledata can't be located —
/// callers degrade gracefully (the affected accessors return `None`).
fn find_moduledata(
    ctx: &BinaryContext<'_>,
    pclntab: &ParsedPclntab<'_>,
    go_version: Option<&str>,
) -> Option<Moduledata> {
    if !ctx.has_va_mapping() {
        return None;
    }

    let data = ctx.data();
    let sections = ctx.sections();
    let go_minor = go_version.and_then(parse_go_minor_version);
    let has_typelink = sections.typelink.is_some();

    if let Some(ref range) = sections.go_module {
        let end = range.offset.checked_add(range.size)?;
        let md_data = data.get(range.offset..end)?;
        return Moduledata::parse(
            md_data,
            pclntab.ptr_size,
            pclntab.version,
            has_typelink,
            go_minor,
        );
    }

    if ctx.format() == BinaryFormat::Pe {
        return find_moduledata_pe(ctx, pclntab, has_typelink, go_minor);
    }

    None
}

/// PE moduledata discovery: scan for a pointer-aligned value matching the
/// pclntab VA, then validate by parsing.
fn find_moduledata_pe(
    ctx: &BinaryContext<'_>,
    pclntab: &ParsedPclntab<'_>,
    has_typelink: bool,
    go_minor: Option<u32>,
) -> Option<Moduledata> {
    let data = ctx.data();
    let pclntab_va = ctx.file_to_va(pclntab.offset)?;
    let ps = pclntab.ptr_size as usize;
    if ps == 0 {
        return None;
    }

    let target_bytes: Vec<u8> = match ps {
        4 => (pclntab_va as u32).to_le_bytes().to_vec(),
        8 => pclntab_va.to_le_bytes().to_vec(),
        _ => return None,
    };

    let search_start = data.len().checked_div(4).unwrap_or(0);
    let mut offset = search_start;
    while let Some(end) = offset.checked_add(ps) {
        if end > data.len() {
            break;
        }
        let rem = offset.checked_rem(ps).unwrap_or(0);
        if rem != 0 {
            let bump = ps.saturating_sub(rem);
            offset = match offset.checked_add(bump) {
                Some(o) => o,
                None => break,
            };
            continue;
        }
        let window = match data.get(offset..end) {
            Some(w) => w,
            None => break,
        };
        if window == target_bytes.as_slice() {
            let remaining = match data.get(offset..) {
                Some(r) => r,
                None => break,
            };
            if let Some(md) = Moduledata::parse(
                remaining,
                pclntab.ptr_size,
                pclntab.version,
                has_typelink,
                go_minor,
            ) {
                if md.minpc < md.maxpc
                    && md.types != 0
                    && ctx.va_to_file(md.funcnametab.ptr).is_some()
                {
                    return Some(md);
                }
            }
        }
        offset = match offset.checked_add(ps) {
            Some(o) => o,
            None => break,
        };
    }
    None
}
