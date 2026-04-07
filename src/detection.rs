//! Go binary detection via heuristic string matching.
//!
//! This module provides the lowest-confidence detection layer. When a binary's format
//! cannot be parsed (corrupted headers, unknown format) and no structural markers are
//! found (no pclntab magic, no build ID), we fall back to scanning for strings that
//! appear in virtually every Go binary.
//!
//! ## Why These Strings Survive
//!
//! The Go runtime references these function names and error messages at runtime for
//! stack traces, panic output, and goroutine management. Even heavily stripped or
//! obfuscated Go binaries retain them in the pclntab's `funcnametab` (which is
//! separate from the ELF/PE symbol table).
//!
//! ## Confidence Levels
//!
//! The [`Confidence`] enum represents how certain we are that a binary is Go-compiled:
//!
//! | Level    | Meaning                                                     |
//! |----------|-------------------------------------------------------------|
//! | `None`   | No Go indicators found                                      |
//! | `Low`    | Heuristic string matches only (could be false positive)     |
//! | `Medium` | Build info or version string found                          |
//! | `High`   | Structural proof: pclntab magic, section names, or build ID |

/// Confidence level for Go binary identification.
///
/// Ordered from lowest to highest, so you can use comparison operators:
/// ```
/// # use gobin::detection::Confidence;
/// assert!(Confidence::Low < Confidence::High);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    /// No Go-specific indicators were found.
    None,
    /// Only heuristic string patterns matched (e.g. `"runtime.main"` in binary).
    /// May produce false positives for binaries that embed Go-like strings.
    Low,
    /// A Go version string (`"go1.XX"`) or build info blob was found, but no
    /// structural proof (pclntab, section names) could be verified.
    Medium,
    /// Definitive structural markers confirmed: pclntab magic bytes, Go-specific
    /// section names (`.gopclntab`, `.go.buildinfo`), or ELF build ID notes.
    High,
}

/// Strings that appear in virtually every Go binary.
///
/// These are function names stored in the pclntab `funcnametab` and runtime error
/// strings compiled into the `.rodata` section. They survive both stripping and
/// the removal of the ELF/PE symbol table.
///
/// Source: `runtime/proc.go` (runtime.main), `runtime/panic.go` (fatal errors),
/// `runtime/asm_*.s` (rt0_go, mstart, goexit), `runtime/proc.go` (newproc).
const HEURISTIC_PATTERNS: &[&[u8]] = &[
    b"runtime.main",
    b"runtime.goexit",
    b"runtime.mstart",
    b"runtime.rt0_go",
    b"fatal error: all goroutines are asleep",
    b"runtime.gopanic",
    b"runtime.newproc",
];

/// Threshold: how many distinct patterns must match before we declare "Go binary".
const HEURISTIC_THRESHOLD: usize = 3;

/// Perform heuristic string-based detection.
///
/// Scans the entire binary for known Go runtime strings. Returns `true` if at least
/// 3 distinct patterns are found, which makes false positives
/// unlikely (a non-Go binary would need to embed multiple Go-specific error messages).
pub fn heuristic_check(data: &[u8]) -> bool {
    let mut hits = 0;
    for pattern in HEURISTIC_PATTERNS {
        if find_bytes(data, pattern).is_some() {
            hits += 1;
            if hits >= HEURISTIC_THRESHOLD {
                return true;
            }
        }
    }
    false
}

/// Find the first occurrence of `needle` in `haystack`.
///
/// Uses a simple sliding-window scan. For the sizes we deal with (binaries up to
/// ~100MB, needles of 10-40 bytes), this is fast enough and avoids pulling in a
/// heavier substring search dependency.
pub(crate) fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}
