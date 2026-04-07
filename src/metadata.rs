//! High-level metadata extracted from Go binaries.
//!
//! This module defines the data types returned by [`GoBinary`](crate::GoBinary) methods
//! and provides the extraction logic that transforms raw pclntab structures into
//! user-friendly function lists, file paths, and type information.
//!
//! ## What's Extractable
//!
//! | Data                  | Source Structure       | Survives Stripping? |
//! |-----------------------|------------------------|---------------------|
//! | Function names        | pclntab `funcnametab`  | Yes                 |
//! | Source file paths     | pclntab `filetab`      | Yes                 |
//! | Function boundaries   | pclntab `functab`      | Yes                 |
//! | Line numbers          | pclntab `pctab`        | Yes                 |
//! | Go version            | build info blob        | Yes                 |
//! | Module dependencies   | build info blob        | Yes                 |
//! | Build settings        | build info blob        | Yes                 |
//! | Build ID              | ELF note / raw marker  | Yes                 |
//! | Type names            | type descriptors       | Yes                 |
//! | DWARF debug info      | `.debug_*` sections    | **No** (`-w` flag)  |
//! | Symbol table          | `.symtab` / `.strtab`  | **No** (`-s` flag)  |
//!
//! ## Why Everything Survives
//!
//! Go's `-ldflags="-s -w"` only removes DWARF debug info (`-w`) and the ELF/PE
//! symbol table (`-s`). The pclntab, build info, and type descriptors are in separate
//! sections that the runtime accesses at execution time:
//!
//! - **pclntab**: needed for `runtime.Caller`, panic stack traces, GC stack scanning
//! - **Build info**: accessed by `runtime/debug.ReadBuildInfo()`
//! - **Types**: needed for `reflect`, interface dispatch, `fmt.Printf("%T", x)`

use crate::structures::pclntab::ParsedPclntab;

/// Build metadata embedded in the Go binary.
///
/// Extracted from the build info blob (see [`crate::structures::buildinfo`]).
/// Contains everything `go version -m <binary>` would print.
///
/// ## Build Setting Keys
///
/// Common keys found in `build_settings` (from `src/runtime/debug/mod.go:69-95`):
///
/// | Key              | Example Value | Description                    |
/// |------------------|---------------|--------------------------------|
/// | `-buildmode`     | `exe`         | Build mode                     |
/// | `-compiler`      | `gc`          | Compiler toolchain             |
/// | `CGO_ENABLED`    | `1`           | CGo enablement                 |
/// | `GOOS`           | `linux`       | Target OS                      |
/// | `GOARCH`         | `amd64`       | Target architecture            |
/// | `GOAMD64`        | `v1`          | AMD64 microarch level          |
/// | `GOARM`          | `7`           | ARM version                    |
/// | `vcs`            | `git`         | Version control system         |
/// | `vcs.revision`   | `abc123...`   | Commit hash                    |
/// | `vcs.time`       | `2024-...`    | Commit timestamp (RFC3339)     |
/// | `vcs.modified`   | `true`        | Working tree dirty flag        |
#[derive(Debug, Clone, Default)]
pub struct BuildInfo {
    /// Go toolchain version (e.g. `"go1.26.1"`).
    pub go_version: Option<String>,
    /// Main package import path (e.g. `"github.com/user/project/cmd/tool"`).
    pub main_path: Option<String>,
    /// Main module name (e.g. `"github.com/user/project"`).
    pub main_module: Option<String>,
    /// Main module version (e.g. `"(devel)"` or `"v1.2.3"`).
    pub main_version: Option<String>,
    /// Module dependencies as `(path, version)` pairs.
    pub deps: Vec<(String, Option<String>)>,
    /// Build settings as `(key, value)` pairs.
    pub build_settings: Vec<(String, String)>,
}

impl BuildInfo {
    /// Look up a build setting by key name.
    pub fn setting(&self, key: &str) -> Option<&str> {
        self.build_settings
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Target operating system (`GOOS` build setting).
    pub fn goos(&self) -> Option<&str> {
        self.setting("GOOS")
    }

    /// Target architecture (`GOARCH` build setting).
    pub fn goarch(&self) -> Option<&str> {
        self.setting("GOARCH")
    }

    /// Whether CGo was enabled at build time.
    pub fn cgo_enabled(&self) -> Option<bool> {
        self.setting("CGO_ENABLED").map(|v| v == "1")
    }

    /// VCS commit hash, if the binary was built from a VCS checkout.
    pub fn vcs_revision(&self) -> Option<&str> {
        self.setting("vcs.revision")
    }

    /// Whether the VCS working tree was dirty at build time.
    pub fn vcs_modified(&self) -> Option<bool> {
        self.setting("vcs.modified").map(|v| v == "true")
    }
}

/// Metadata for a single function extracted from the pclntab.
///
/// Function names in Go are package-qualified and follow a consistent naming scheme:
///
/// | Pattern                        | Example                          |
/// |--------------------------------|----------------------------------|
/// | `pkg.Function`                 | `fmt.Println`                    |
/// | `pkg.(*Type).Method`           | `net/http.(*Client).Do`          |
/// | `pkg.Type.Method`              | `time.Time.String`               |
/// | `pkg.function.closureN`        | `main.main.func1`               |
/// | `pkg.function.gowrapN`         | `main.main.gowrap1`             |
///
/// These names survive stripping because they're stored in the pclntab's `funcnametab`,
/// not in the ELF/PE symbol table.
#[derive(Debug, Clone)]
pub struct FunctionInfo<'a> {
    /// Full package-qualified function name (borrowed from pclntab funcnametab).
    pub name: &'a str,
    /// PC offset from `runtime.text` (the start of executable code).
    pub entry_offset: u32,
    /// Total argument size in bytes (input + output parameters).
    pub args_size: i32,
    /// Source line number where the `func` keyword appears.
    pub start_line: i32,
    /// Special function ID (0 = normal). See [`crate::structures::pclntab::FuncData`]
    /// for the FuncID value table.
    pub func_id: u8,
    /// Function flags (top-frame, SP-write, asm).
    pub flags: u8,
    /// Offset from function entry to the `deferreturn` call (0 if no defer).
    pub deferreturn: u32,
    /// Offset into `pctab` for the stack-pointer delta table.
    pub pcsp: u32,
    /// Offset into `pctab` for the PC-to-file mapping table.
    pub pcfile: u32,
    /// Offset into `pctab` for the PC-to-line mapping table.
    pub pcln: u32,
    /// Number of PCDATA entries (metadata tables per PC range).
    pub npcdata: u32,
    /// Compilation unit offset in `cutab`.
    pub cu_offset: u32,
    /// Number of FUNCDATA entries (per-function data blobs like stack maps).
    pub nfuncdata: u8,
    /// Source file path for this function's entry point (resolved from pcfile + cutab).
    pub source_file: Option<&'a str>,
    /// Last source line in the function (decoded from the pcln table).
    pub end_line: i32,
    /// Maximum stack frame size in bytes (decoded from the pcsp table).
    pub frame_size: i32,
}

impl FunctionInfo<'_> {
    /// Extract the package path from the function name.
    ///
    /// Go function names are `"package/path.FunctionName"`, so we split at the
    /// first `.` to get the package. For methods like `"pkg.(*T).M"`, we still
    /// split at the first `.`.
    ///
    /// ```
    /// # use gobin::metadata::FunctionInfo;
    /// # let f = FunctionInfo { name: "net/http.(*Client).Do", entry_offset: 0, args_size: 0, start_line: 0, func_id: 0, flags: 0, deferreturn: 0, pcsp: 0, pcfile: 0, pcln: 0, npcdata: 0, cu_offset: 0, nfuncdata: 0, source_file: None, end_line: 0, frame_size: 0 };
    /// assert_eq!(f.package(), Some("net/http"));
    /// ```
    pub fn package(&self) -> Option<&str> {
        self.name.find('.').map(|dot| &self.name[..dot])
    }

    /// Whether this function is a method (has a receiver type).
    ///
    /// Detected by the `".("` pattern in the name, which indicates a receiver
    /// like `"pkg.(*Type).Method"` or `"pkg.Type.Method"`.
    pub fn is_method(&self) -> bool {
        self.name.contains(".(")
    }

    /// Whether this is a Go runtime function (`"runtime."` prefix).
    pub fn is_runtime(&self) -> bool {
        self.name.starts_with("runtime.")
    }

    /// The short name (without package prefix).
    /// E.g. `"net/http.(*Client).Do"` -> `"(*Client).Do"`.
    pub fn short_name(&self) -> &str {
        self.name
            .find('.')
            .map(|dot| &self.name[dot + 1..])
            .unwrap_or(self.name)
    }

    /// Whether this function uses `defer` (nonzero `deferreturn` offset).
    pub fn uses_defer(&self) -> bool {
        self.deferreturn != 0
    }

    /// Whether this looks like a closure (`".func"` or `".gowrap"` suffix pattern).
    pub fn is_closure(&self) -> bool {
        self.name.contains(".func") || self.name.contains(".gowrap")
    }

    /// Whether this is a Go internal package (runtime, internal/*, vendor/*).
    pub fn is_internal(&self) -> bool {
        let pkg = self.package().unwrap_or("");
        pkg.starts_with("runtime")
            || pkg.starts_with("internal/")
            || pkg.starts_with("vendor/")
            || pkg.starts_with("type:")
    }

    /// Whether this is a standard library function (not user code, not runtime internals).
    pub fn is_stdlib(&self) -> bool {
        !self.is_internal() && self.package().is_some_and(|p| !p.contains('.'))
    }

    /// Human-readable FuncID label, if this is a special runtime function.
    pub fn func_id_name(&self) -> Option<&'static str> {
        match self.func_id {
            0 => None,
            80 => Some("abort"),
            81 => Some("asmcgocall"),
            82 => Some("asyncPreempt"),
            83 => Some("cgocallback"),
            84 => Some("debugCallV2"),
            85 => Some("gcBgMarkWorker"),
            86 => Some("goexit"),
            87 => Some("gogo"),
            88 => Some("gopanic"),
            89 => Some("handleAsyncEvent"),
            90 => Some("mcall"),
            91 => Some("morestack"),
            92 => Some("mstart"),
            93 => Some("panicwrap"),
            94 => Some("rt0_go"),
            95 => Some("runfinq"),
            96 => Some("runtime_main"),
            97 => Some("sigpanic"),
            98 => Some("systemstack"),
            99 => Some("systemstack_switch"),
            100 => Some("wrapper"),
            _ => Some("unknown_special"),
        }
    }
}

/// Extract function metadata from a parsed pclntab.
///
/// Walks the functab entries, parses each `_func` struct, and resolves the
/// function name from `funcnametab`.
pub fn extract_functions<'a>(pclntab: &ParsedPclntab<'a>) -> Vec<FunctionInfo<'a>> {
    let entries = pclntab.func_entries();
    let mut functions = Vec::with_capacity(entries.len());

    for (_entry_off, func_off) in entries {
        if let Some(func_data) = pclntab.parse_func(func_off) {
            let name = pclntab
                .func_name(func_data.name_off as u32)
                .unwrap_or("<unknown>");

            let source_file = pclntab.resolve_source_file(&func_data);
            let end_line = pclntab
                .line_range(&func_data)
                .map(|(_, end)| end)
                .unwrap_or(0);
            let frame_size = pclntab.max_frame_size(&func_data).unwrap_or(0);

            functions.push(FunctionInfo {
                name,
                entry_offset: func_data.entry_off,
                args_size: func_data.args,
                start_line: func_data.start_line,
                func_id: func_data.func_id,
                flags: func_data.flag,
                deferreturn: func_data.deferreturn,
                pcsp: func_data.pcsp,
                pcfile: func_data.pcfile,
                pcln: func_data.pcln,
                npcdata: func_data.npcdata,
                cu_offset: func_data.cu_offset,
                nfuncdata: func_data.nfuncdata,
                source_file,
                end_line,
                frame_size,
            });
        }
    }

    functions
}
