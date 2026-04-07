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
//! use gobin::metadata::{FunctionInfo, extract_functions};
//!
//! let data = std::fs::read("some_binary").unwrap();
//! if let Some(bin) = GoBinary::parse(&data) {
//!     println!("Go version: {:?}", bin.go_version());
//!     if let Some(pclntab) = bin.pclntab() {
//!         println!("Functions: {}", pclntab.nfunc);
//!         for f in extract_functions(pclntab) {
//!             println!("  {}", f.name);
//!         }
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

#![warn(missing_docs)]

pub mod detection;
pub mod formats;
pub mod metadata;
pub mod structures;

use crate::{
    detection::{Confidence, heuristic_check},
    formats::BinaryContext,
    metadata::BuildInfo,
    structures::{
        buildid, buildinfo,
        pclntab::{self, ParsedPclntab},
        types::{self, GoType},
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
    confidence: Confidence,
    ctx: BinaryContext<'a>,
    build_id: Option<String>,
    build_info: Option<BuildInfo>,
    pclntab: Option<ParsedPclntab<'a>>,
    go_version: Option<String>,
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
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        let ctx = BinaryContext::new(data);
        let mut confidence = Confidence::None;

        let sections = ctx.sections();
        if sections.has_gopclntab || sections.has_go_buildinfo || sections.has_go_buildid_note {
            confidence = Confidence::High;
        }

        let build_id = buildid::extract(&ctx);
        if build_id.is_some() && confidence < Confidence::High {
            confidence = Confidence::High;
        }

        let build_info_result = buildinfo::extract(&ctx);
        if build_info_result.is_some() && confidence < Confidence::Medium {
            confidence = Confidence::Medium;
        }

        let pclntab_result = pclntab::parse(&ctx);
        if pclntab_result.is_some() && confidence < Confidence::High {
            confidence = Confidence::High;
        }

        let go_version = build_info_result
            .as_ref()
            .and_then(|bi| bi.go_version.clone())
            .or_else(|| buildinfo::find_version_string(data));

        if go_version.is_some() && confidence < Confidence::Medium {
            confidence = Confidence::Medium;
        }

        if confidence == Confidence::None && heuristic_check(data) {
            confidence = Confidence::Low;
        }

        if confidence == Confidence::None {
            return None;
        }

        Some(GoBinary {
            confidence,
            ctx,
            build_id,
            build_info: build_info_result,
            pclntab: pclntab_result,
            go_version,
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
        self.confidence
    }

    /// The Go toolchain version, e.g. `"go1.26.1"`.
    ///
    /// Extracted from the build info blob or by scanning for `"go1."` string patterns.
    pub fn go_version(&self) -> Option<&str> {
        self.go_version.as_deref()
    }

    /// The Go build ID.
    ///
    /// For executables this is a 4-part string: `actionID/actionID/contentID/contentID`,
    /// where each part is 20 characters of URL-safe base64 derived from SHA256 hashes.
    ///
    /// See [`structures::buildid`] for format details.
    pub fn build_id(&self) -> Option<&str> {
        self.build_id.as_deref()
    }

    /// Build metadata including module path, dependencies, and build settings.
    ///
    /// Contains GOOS, GOARCH, CGO_ENABLED, VCS info, and the full dependency list.
    /// See [`BuildInfo`] for accessor methods.
    pub fn build_info(&self) -> Option<&BuildInfo> {
        self.build_info.as_ref()
    }

    /// The parsed pclntab, if found. Provides zero-copy access to function names,
    /// source files, architecture, pointer size, and all other pclntab metadata.
    pub fn pclntab(&self) -> Option<&ParsedPclntab<'a>> {
        self.pclntab.as_ref()
    }

    /// Types extracted deterministically from Go `abi.Type` descriptors.
    ///
    /// Uses the `.typelink` section (an array of `int32` offsets) and the `abi.Type`
    /// struct layout to extract every type the binary exposes to reflection. Each
    /// type includes its name, kind (struct/pointer/slice/etc.), size, and flags.
    ///
    /// Returns an empty list if the required sections (`.typelink`, `.go.module`)
    /// are not present in the binary.
    pub fn types(&self) -> Vec<GoType> {
        let pclntab = match self.pclntab.as_ref() {
            Some(p) => p,
            None => return Vec::new(),
        };
        let go_version_minor = self.go_version().and_then(parse_go_minor_version);
        types::extract_types(
            &self.ctx,
            pclntab.ptr_size,
            Some(pclntab.version),
            Some(pclntab.offset),
            go_version_minor,
        )
    }
}

/// Parse the minor version from a Go version string like `"go1.26.1"` -> `26`.
fn parse_go_minor_version(version: &str) -> Option<u32> {
    let rest = version.strip_prefix("go1.")?;
    let minor_str = rest.split('.').next()?;
    minor_str.parse().ok()
}
