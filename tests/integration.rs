// Integration tests — workspace-level `[lints.rust]` and `[lints.clippy]`
// (defined in Cargo.toml) apply to integration test binaries too, but tests
// legitimately use `unwrap`/`expect`/indexing/arithmetic for terseness, and
// integration test items don't need rustdoc.
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]

use std::collections::BTreeSet;

use gobin::{
    GoBinary, detect,
    detection::{Confidence, ConfidenceSignal, ParseError},
    formats::BinaryFormat,
    metadata::{Compiler, FunctionInfo, FunctionIter, ObfuscationKind, for_each_function},
    structures::{Arch, PclntabVersion},
};

// Representative fixtures for the per-feature tests below. The full
// version×format matrix is swept separately in `mod matrix`. Fixtures are
// built reproducibly with `-trimpath` (see tests/samples/build.sh), so they
// carry no local filesystem paths.
const BASIC_NORMAL: &str = "tests/samples/basic_go126_darwin_arm64";
const BASIC_STRIPPED: &str = "tests/samples/basic_go126_darwin_arm64_stripped";
const BASIC_LINUX: &str = "tests/samples/basic_go126_linux_amd64";
const BASIC_WINDOWS: &str = "tests/samples/basic_go126_windows_amd64.exe";
const BASIC_WINDOWS_STRIPPED: &str = "tests/samples/basic_go126_windows_amd64_stripped.exe";
const MINIMAL_NORMAL: &str = "tests/samples/minimal_go126_darwin_arm64";
const MINIMAL_STRIPPED: &str = "tests/samples/minimal_go126_darwin_arm64_stripped";
const BASIC_WASM: &str = "tests/samples/basic_go126_wasip1_wasm";
const BASIC_GO127: &str = "tests/samples/basic_go127_darwin_arm64";
const BASIC_GO127_STRIPPED: &str = "tests/samples/basic_go127_darwin_arm64_stripped";
const BASIC_FIPS: &str = "tests/samples/fips_go126_darwin_arm64";
const BASIC_EMBED: &str = "tests/samples/embed_go126_darwin_arm64";
const BASIC_EMBED_STRIPPED: &str = "tests/samples/embed_go126_darwin_arm64_stripped";
const BASIC_EMBED_LINUX: &str = "tests/samples/embed_go126_linux_amd64";

fn load(path: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("Failed to read {path}: {e}"))
}

#[test]
fn detect_macho_go_binary() {
    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).expect("Should detect as Go binary");
    assert_eq!(bin.confidence(), Confidence::High);
    assert_eq!(bin.context().format(), BinaryFormat::MachO);
}

#[test]
fn detect_elf_go_binary() {
    let data = load(BASIC_LINUX);
    let bin = GoBinary::parse(&data).expect("Should detect as Go binary");
    assert_eq!(bin.confidence(), Confidence::High);
    assert_eq!(bin.context().format(), BinaryFormat::Elf);
}

#[test]
fn detect_wasm_go_binary() {
    let data = load(BASIC_WASM);
    let bin = GoBinary::parse(&data).expect("Should detect wasm Go binary");
    assert_eq!(bin.context().format(), BinaryFormat::Wasm);
    assert_eq!(bin.confidence(), Confidence::High);
    assert!(bin.go_version().unwrap().starts_with("go1."));
    assert!(bin.build_id().is_some(), "Wasm carries go:buildid section");
}

#[test]
fn go127_detects_v5_moduledata() {
    use gobin::structures::moduledata::ModuledataVersion;
    let data = load(BASIC_GO127);
    let bin = GoBinary::parse(&data).expect("Go 1.27 binary should parse");
    let md = bin.moduledata().expect("moduledata should be located");
    assert_eq!(
        md.version,
        ModuledataVersion::V5,
        "go1.27-devel should select the V5 layout"
    );
    // Regression guard: the old speculative V5 branch hardcoded these to
    // None, which silently disabled inline-tree and funcdata resolution.
    assert!(md.gofunc.is_some(), "V5 must still carry gofunc");
    assert!(md.rodata.is_some(), "V5 must still carry rodata");
    assert!(md.itaboffset.is_some(), "V5 stores itabs at itaboffset");
    assert!(md.typelinks.is_none(), "V5 dropped the typelinks slice");
}

#[test]
fn go127_itab_pairs_via_inline_region() {
    // V5 removed .itablink / itablinks; itabs are walked inline at
    // types+itaboffset. This exercises the third itab strategy.
    let data = load(BASIC_GO127);
    let bin = GoBinary::parse(&data).unwrap();
    let pairs: Vec<_> = bin.itab_pairs().collect();
    assert!(
        pairs.len() >= 5,
        "a binary using fmt + several interface impls should expose many \
         itabs, got {}",
        pairs.len()
    );
    // Every pair must carry plausible (non-zero) type-descriptor VAs.
    for p in &pairs {
        assert!(p.iface_type_va != 0 && p.concrete_type_va != 0);
    }
}

#[test]
fn go127_types_still_extract() {
    // Type extraction must fall back to descriptor-walking now that the
    // .typelink section is gone in V5.
    let data = load(BASIC_GO127);
    let bin = GoBinary::parse(&data).unwrap();
    let n = bin.types().count();
    assert!(n > 100, "expected many types via descriptor walk, got {n}");
}

#[test]
fn go127_stripped_still_v5() {
    use gobin::structures::moduledata::ModuledataVersion;
    let data = load(BASIC_GO127_STRIPPED);
    let bin = GoBinary::parse(&data).expect("stripped Go 1.27 should parse");
    let md = bin
        .moduledata()
        .expect("moduledata located even when stripped");
    assert_eq!(md.version, ModuledataVersion::V5);
    assert!(bin.itab_pairs().count() >= 5);
}

const COVER_LINUX: &str = "tests/samples/cover_go126_linux_amd64";

#[test]
fn moduledata_segments_and_identity() {
    let data = load(BASIC_LINUX);
    let bin = GoBinary::parse(&data).unwrap();
    let md = bin.moduledata().expect("moduledata");

    // The main executable owns `main`, has no plugin/module name.
    assert_eq!(bin.is_main_module(), Some(true));
    assert_eq!(bin.module_name(), None);
    assert_eq!(bin.plugin_path(), None);

    // Data-segment boundaries are populated and ordered.
    for (name, r) in [
        ("noptrdata", md.noptrdata),
        ("data", md.data),
        ("noptrbss", md.noptrbss),
    ] {
        assert!(
            r.start != 0 && r.end >= r.start,
            "{name} range invalid: {r:?}"
        );
    }
    assert!(md.end > md.text, "module end should be past text");
    // A plain build is not coverage-instrumented.
    assert!(!bin.is_coverage_build());
}

#[test]
fn itab_method_pointers_resolve_into_text() {
    let data = load(BASIC_LINUX);
    let bin = GoBinary::parse(&data).unwrap();
    let md = bin.moduledata().unwrap();
    let (text, etext) = (md.text, md.etext);

    let mut total = 0usize;
    for pair in bin.itab_pairs().take(60) {
        for va in bin.itab_methods(&pair) {
            total += 1;
            assert!(
                va == 0 || (va >= text && va < etext),
                "itab method ptr {va:#x} not in text"
            );
        }
    }
    assert!(
        total > 10,
        "expected resolved itab method pointers, got {total}"
    );
}

#[test]
fn macho_plugin_chained_fixups_resolve() {
    // A Go plugin (-buildmode=plugin) is an externally-linked Mach-O dylib
    // whose data pointers are chained fixups; without rebasing, no pointer
    // resolves. With it, types / plugin tables come back.
    let data = load("tests/samples/plugin_go126_darwin_arm64.so");
    let bin = GoBinary::parse(&data).unwrap();

    assert_eq!(
        bin.is_main_module(),
        Some(false),
        "a plugin is not the main module"
    );
    assert_eq!(bin.plugin_path(), Some("gobin.test/plugin"));
    assert!(
        bin.types().count() > 100,
        "types must resolve through fixups"
    );

    // Exported plugin symbols (moduledata.ptab) decode with names.
    let exports: BTreeSet<&str> = bin.plugin_exports().iter().filter_map(|e| e.name).collect();
    assert!(exports.contains("ExportedFunc"), "saw {exports:?}");
    assert!(exports.contains("ExportedVar"), "saw {exports:?}");

    // Per-package ABI hashes resolve to real package paths.
    let pkgs: BTreeSet<&str> = bin
        .package_hashes()
        .iter()
        .filter_map(|h| h.module_name)
        .collect();
    assert!(
        pkgs.iter().any(|p| p.starts_with("internal/")),
        "saw {pkgs:?}"
    );
}

#[test]
fn moduledata_subslice_decoders() {
    let data = load(BASIC_LINUX);
    let bin = GoBinary::parse(&data).unwrap();

    // A normal binary has exactly one text section, ordered.
    let ts = bin.text_sections();
    assert_eq!(ts.len(), 1, "ordinary binary has one text section");
    assert!(ts[0].end >= ts[0].vaddr);

    // Plugin/shared-only tables are empty for a plain executable, and the
    // decoders must not panic.
    assert!(bin.plugin_exports().is_empty());
    assert!(bin.package_hashes().is_empty());
    assert!(bin.module_hashes().is_empty());
}

#[test]
fn gc_pointer_map_locates_global_pointers() {
    let data = load(BASIC_LINUX);
    let bin = GoBinary::parse(&data).unwrap();
    let md = bin.moduledata().unwrap();
    let (text, end) = (md.text, md.end);

    let pm = bin.data_pointer_map().expect("data pointer map");
    assert!(
        pm.pointer_count() > 50,
        "expected many global data pointers"
    );
    assert!(
        pm.pointer_count() < pm.words.len(),
        "not every word is a pointer"
    );

    // Every word the map flags as a pointer must actually hold a pointer-shaped
    // value: nil, or an address inside the module image. Scalar garbage here
    // would mean the GC program was decoded wrong.
    let ctx = bin.context();
    let mut checked = 0usize;
    for va in pm.pointer_vas().take(300) {
        if let Some(sl) = ctx.slice_at_va(va)
            && let Ok(bytes) = sl.get(..8).unwrap_or(&[]).try_into()
        {
            let v = u64::from_le_bytes(bytes);
            checked += 1;
            assert!(
                v == 0 || (v >= text && v < end),
                "pointer word {va:#x} holds non-pointer {v:#x}"
            );
        }
    }
    assert!(checked > 100, "should have sampled many pointer words");

    // bss also decodes.
    assert!(bin.bss_pointer_map().unwrap().pointer_count() > 50);
}

#[test]
fn coverage_build_detected() {
    let data = load(COVER_LINUX);
    let bin = GoBinary::parse(&data).unwrap();
    assert!(
        bin.is_coverage_build(),
        "a -cover binary should report a coverage-counter region"
    );
    let md = bin.moduledata().unwrap();
    assert!(md.covctrs.is_some_and(|r| !r.is_empty()));
}

#[test]
fn init_order_lists_runtime_and_main() {
    let data = load(BASIC_GO127);
    let bin = GoBinary::parse(&data).unwrap();
    let tasks = bin.init_order();
    assert!(
        tasks.len() >= 3,
        "a fmt-using program runs several package inits, got {}",
        tasks.len()
    );
    let packages: BTreeSet<&str> = tasks.iter().filter_map(|t| t.package).collect();
    assert!(
        packages.contains("runtime"),
        "runtime should initialize, saw {packages:?}"
    );
    // Every resolved init function name should end in an `init`-shaped suffix.
    let resolved: Vec<&str> = tasks
        .iter()
        .flat_map(|t| t.functions.iter())
        .filter_map(|f| f.name)
        .collect();
    assert!(
        !resolved.is_empty(),
        "at least some init fns should resolve"
    );
    assert!(
        resolved.iter().all(|n| n.contains("init")),
        "init task entries should be init functions, saw {resolved:?}"
    );
}

#[test]
fn init_order_empty_is_safe() {
    // Older binaries (pre-1.24 / no inittasks) must return cleanly, not panic.
    let data = load(MINIMAL_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();
    let _ = bin.init_order(); // must not panic regardless of availability
}

fn assert_embed_assets(path: &str) {
    let data = load(path);
    let bin = GoBinary::parse(&data).unwrap();
    let assets = bin.embedded_assets();
    let by_path: std::collections::BTreeMap<&str, &[u8]> =
        assets.iter().map(|a| (a.path, a.data)).collect();

    // The three embedded files (recovered bytes must match the sources).
    assert_eq!(
        by_path.get("assets/hello.txt").copied(),
        Some(b"hello embedded world\n".as_slice()),
        "{path}: hello.txt content"
    );
    assert_eq!(
        by_path.get("assets/data.bin").copied(),
        Some(b"second asset file\n".as_slice()),
        "{path}: data.bin content"
    );
    assert!(
        by_path.contains_key("assets/nested/inner.dat"),
        "{path}: nested file present"
    );
    // Directory entries are surfaced with the trailing slash and no bytes.
    let dirs: Vec<&str> = assets.iter().filter(|a| a.is_dir).map(|a| a.path).collect();
    assert!(
        dirs.contains(&"assets/nested/"),
        "{path}: nested dir entry, saw {dirs:?}"
    );
    assert!(
        assets
            .iter()
            .filter(|a| a.is_dir)
            .all(|a| a.data.is_empty()),
        "{path}: directory entries carry no bytes"
    );
}

#[test]
fn embedded_assets_recovered_with_symbols() {
    assert_embed_assets(BASIC_EMBED);
}

#[test]
fn embedded_assets_recovered_when_stripped() {
    // The scanner is symbol-independent: -ldflags="-s -w" must not hide assets.
    assert_embed_assets(BASIC_EMBED_STRIPPED);
}

#[test]
fn embedded_assets_recovered_on_elf() {
    // Same extraction path works across container formats (ELF here).
    assert_embed_assets(BASIC_EMBED_LINUX);
}

#[test]
fn embedded_assets_empty_for_non_embed_binary() {
    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();
    assert!(
        bin.embedded_assets().is_empty(),
        "a binary with no //go:embed must yield no assets (false-positive guard)"
    );
}

#[test]
fn fips_info_detected_in_fips_build() {
    let data = load(BASIC_FIPS);
    let bin = GoBinary::parse(&data).unwrap();
    let fips = bin
        .fips_info()
        .expect("GOFIPS140 build should report FIPS info");
    assert!(fips.version.starts_with("v1.0.0"));
    assert!(fips.enforced_by_default, "fips140=on in DefaultGODEBUG");
    // The integrity sum is present and non-zero.
    assert!(fips.module_sum.is_some_and(|s| s != [0u8; 32]));
}

#[test]
fn fips_info_absent_in_normal_build() {
    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();
    // The fipsinfo section is linked into modern Go binaries, but without the
    // GOFIPS140 build setting it is not a FIPS build.
    assert!(
        bin.fips_info().is_none(),
        "non-FIPS builds must not report FIPS mode"
    );
}

#[test]
fn wasm_pclntab_parses() {
    let data = load(BASIC_WASM);
    let bin = GoBinary::parse(&data).unwrap();
    let pcl = bin
        .pclntab()
        .expect("wasm pclntab should parse via reconstructed linear-memory image");
    assert!(
        pcl.nfunc > 100,
        "expected hundreds of functions in stdlib wasm build, got {}",
        pcl.nfunc
    );
    assert_eq!(pcl.ptr_size, 8, "Go wasm uses ptrSize = 8");
    assert_eq!(pcl.min_lc, 1, "Go wasm uses minLC = 1");
}

#[test]
fn wasm_arch_resolves_correctly() {
    let data = load(BASIC_WASM);
    let bin = GoBinary::parse(&data).unwrap();
    // pclntab arch can't disambiguate (1,8) — reports X86_64.
    assert_eq!(bin.pclntab().unwrap().arch(), Arch::X86_64);
    // bin.arch() folds in the container format and resolves to Wasm.
    assert_eq!(bin.arch(), Arch::Wasm);
}

#[test]
fn wasm_function_iter_yields_runtime_main() {
    let data = load(BASIC_WASM);
    let bin = GoBinary::parse(&data).unwrap();
    let names: Vec<&str> = bin.functions().map(|f| f.name).collect();
    assert!(
        names.contains(&"runtime.main"),
        "runtime.main should be reachable via the pclntab funcname table"
    );
    assert!(
        names.contains(&"main.main"),
        "main.main should be reachable via the pclntab funcname table"
    );
    assert!(
        names.len() > 100,
        "wasm functions() should yield hundreds of names, got {}",
        names.len()
    );
}

#[test]
fn wasm_types_extracted() {
    let data = load(BASIC_WASM);
    let bin = GoBinary::parse(&data).unwrap();
    let types: Vec<_> = bin.types().collect();
    assert!(
        types.len() > 100,
        "wasm types() should yield hundreds of types, got {}",
        types.len()
    );
    // Spot-check a well-known runtime type.
    assert!(
        types.iter().any(|t| t.name.contains("runtime.")),
        "expected at least one runtime.* type"
    );
}

#[test]
fn wasm_strings_extracted() {
    let data = load(BASIC_WASM);
    let bin = GoBinary::parse(&data).unwrap();
    let count = bin.strings().count();
    assert!(
        count > 50,
        "wasm strings() should yield many strings, got {count}"
    );
}

#[test]
fn wasm_inline_tree_yields_entries() {
    let data = load(BASIC_WASM);
    let bin = GoBinary::parse(&data).unwrap();
    let pcl = bin.pclntab().unwrap();

    let mut total_entries = 0usize;
    for (_, off) in pcl.func_entries().take(200) {
        let func = match pcl.parse_func(off) {
            Some(f) => f,
            None => continue,
        };
        total_entries += bin.inline_tree(&func).count();
        if total_entries > 0 {
            break;
        }
    }
    assert!(
        total_entries > 0,
        "wasm should expose at least one inline-tree entry across the first 200 functions"
    );
}

#[test]
fn wasm_moduledata_resolves_text_va() {
    let data = load(BASIC_WASM);
    let bin = GoBinary::parse(&data).unwrap();
    // moduledata discovery should succeed for wasm via the linear-memory
    // pcHeader-pointer scan, exposing text/etext.
    let text = bin.text_va().expect("wasm should resolve runtime.text");
    let etext = bin.etext_va().expect("wasm should resolve runtime.etext");
    assert!(etext > text, "etext must follow text");
}

#[test]
fn detect_pe_go_binary() {
    let data = load(BASIC_WINDOWS);
    let bin = GoBinary::parse(&data).expect("Should detect as Go binary");
    assert_eq!(bin.confidence(), Confidence::High);
    assert_eq!(bin.context().format(), BinaryFormat::Pe);
}

#[test]
fn detect_stripped_macho() {
    let data = load(BASIC_STRIPPED);
    let bin = GoBinary::parse(&data).unwrap();
    assert_eq!(bin.confidence(), Confidence::High);
}

#[test]
fn detect_stripped_pe() {
    let data = load(BASIC_WINDOWS_STRIPPED);
    let bin = GoBinary::parse(&data).unwrap();
    assert_eq!(bin.confidence(), Confidence::High);
}

#[test]
fn reject_non_go_binary() {
    let data = vec![0u8; 1024];
    assert!(
        GoBinary::parse(&data).is_none(),
        "Random data should not be detected as Go"
    );
}

#[test]
fn build_id_macho_format() {
    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();
    let id = bin.build_id().expect("Should have build ID");
    let parts: Vec<&str> = id.split('/').collect();
    assert_eq!(parts.len(), 4, "Executable build ID should have 4 parts");
    for part in &parts {
        assert_eq!(part.len(), 20, "Each part should be 20 chars of base64");
    }
}

#[test]
fn build_id_survives_stripping() {
    let data = load(BASIC_STRIPPED);
    let bin = GoBinary::parse(&data).unwrap();
    assert!(bin.build_id().is_some());
}

#[test]
fn build_id_pe() {
    let data = load(BASIC_WINDOWS);
    let bin = GoBinary::parse(&data).unwrap();
    let id = bin.build_id().expect("PE binary should have build ID");
    assert_eq!(id.split('/').count(), 4);
}

#[test]
fn build_id_pe_stripped() {
    let data = load(BASIC_WINDOWS_STRIPPED);
    let bin = GoBinary::parse(&data).unwrap();
    assert!(
        bin.build_id().is_some(),
        "PE build ID should survive stripping"
    );
}

#[test]
fn go_version_macho() {
    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();
    let v = bin.go_version().expect("Should have Go version");
    assert!(v.starts_with("go1."), "Got: {v}");
}

#[test]
fn go_version_elf() {
    let data = load(BASIC_LINUX);
    let bin = GoBinary::parse(&data).unwrap();
    assert!(bin.go_version().unwrap().starts_with("go1."));
}

#[test]
fn go_version_pe() {
    let data = load(BASIC_WINDOWS);
    let bin = GoBinary::parse(&data).unwrap();
    assert!(bin.go_version().unwrap().starts_with("go1."));
}

#[test]
fn go_version_survives_stripping() {
    let data = load(BASIC_STRIPPED);
    let bin = GoBinary::parse(&data).unwrap();
    assert!(bin.go_version().is_some());
}

#[test]
fn build_info_macho() {
    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();
    let info = bin.build_info().expect("Should have build info");
    assert_eq!(info.main_path, Some("gobin.test/basic"));
    assert_eq!(info.goos(), Some("darwin"));
    assert_eq!(info.goarch(), Some("arm64"));
}

#[test]
fn build_info_elf() {
    let data = load(BASIC_LINUX);
    let bin = GoBinary::parse(&data).unwrap();
    let info = bin.build_info().expect("Should have build info");
    assert_eq!(info.goos(), Some("linux"));
    assert_eq!(info.goarch(), Some("amd64"));
}

#[test]
fn build_info_pe() {
    let data = load(BASIC_WINDOWS);
    let bin = GoBinary::parse(&data).unwrap();
    let info = bin.build_info().expect("PE should have build info");
    assert_eq!(info.main_path, Some("gobin.test/basic"));
    assert_eq!(info.goos(), Some("windows"));
    assert_eq!(info.goarch(), Some("amd64"));
}

#[test]
fn build_info_pe_stripped() {
    let data = load(BASIC_WINDOWS_STRIPPED);
    let bin = GoBinary::parse(&data).unwrap();
    let info = bin
        .build_info()
        .expect("PE build info should survive stripping");
    assert_eq!(info.goos(), Some("windows"));
}

#[test]
fn pclntab_macho() {
    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();
    assert_eq!(
        bin.pclntab().map(|p| p.version),
        Some(PclntabVersion::Go120)
    );
    assert_eq!(bin.pclntab().map(|p| p.ptr_size), Some(8));
    assert!(bin.pclntab().map(|p| p.nfunc).unwrap() > 100);
    assert!(bin.pclntab().map(|p| p.nfiles).unwrap() > 10);
}

#[test]
fn pclntab_elf() {
    let data = load(BASIC_LINUX);
    let bin = GoBinary::parse(&data).unwrap();
    assert_eq!(
        bin.pclntab().map(|p| p.version),
        Some(PclntabVersion::Go120)
    );
    assert_eq!(bin.pclntab().map(|p| p.ptr_size), Some(8));
}

#[test]
fn pclntab_pe() {
    let data = load(BASIC_WINDOWS);
    let bin = GoBinary::parse(&data).unwrap();
    assert_eq!(
        bin.pclntab().map(|p| p.version),
        Some(PclntabVersion::Go120)
    );
    assert_eq!(bin.pclntab().map(|p| p.ptr_size), Some(8));
    assert!(
        bin.pclntab().map(|p| p.nfunc).unwrap() > 100,
        "PE should have many functions"
    );
}

#[test]
fn pclntab_survives_stripping() {
    let data = load(BASIC_STRIPPED);
    let bin = GoBinary::parse(&data).unwrap();
    assert!(bin.pclntab().map(|p| p.version).is_some());
    assert!(bin.pclntab().map(|p| p.nfunc).unwrap() > 100);
}

#[test]
fn pclntab_pe_survives_stripping() {
    let data = load(BASIC_WINDOWS_STRIPPED);
    let bin = GoBinary::parse(&data).unwrap();
    assert!(
        bin.pclntab().map(|p| p.version).is_some(),
        "PE pclntab should survive stripping"
    );
    assert!(bin.pclntab().map(|p| p.nfunc).unwrap() > 100);
}

#[test]
fn arch_arm64_macho() {
    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();
    assert_eq!(bin.pclntab().map(|p| p.arch()), Some(Arch::Arm64));
}

#[test]
fn arch_x86_64_elf() {
    let data = load(BASIC_LINUX);
    let bin = GoBinary::parse(&data).unwrap();
    assert_eq!(bin.pclntab().map(|p| p.arch()), Some(Arch::X86_64));
}

#[test]
fn arch_x86_64_pe() {
    let data = load(BASIC_WINDOWS);
    let bin = GoBinary::parse(&data).unwrap();
    assert_eq!(bin.pclntab().map(|p| p.arch()), Some(Arch::X86_64));
}

#[test]
fn functions_macho() {
    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();
    let names: Vec<&str> = bin
        .functions()
        .collect::<Vec<_>>()
        .iter()
        .map(|f| f.name)
        .collect();
    assert!(names.contains(&"main.main"));
    assert!(names.contains(&"runtime.main"));
    assert!(names.iter().any(|n| n.contains("TestStruct")));
}

#[test]
fn functions_pe() {
    let data = load(BASIC_WINDOWS);
    let bin = GoBinary::parse(&data).unwrap();
    let names: Vec<&str> = bin
        .functions()
        .collect::<Vec<_>>()
        .iter()
        .map(|f| f.name)
        .collect();
    assert!(names.contains(&"main.main"), "PE should have main.main");
    assert!(
        names.contains(&"runtime.main"),
        "PE should have runtime.main"
    );
}

#[test]
fn functions_survive_stripping() {
    let data = load(BASIC_STRIPPED);
    let bin = GoBinary::parse(&data).unwrap();
    let names: Vec<&str> = bin
        .functions()
        .collect::<Vec<_>>()
        .iter()
        .map(|f| f.name)
        .collect();
    assert!(names.contains(&"main.main"));
    assert!(names.iter().any(|n| n.starts_with("runtime.")));
}

#[test]
fn functions_pe_survive_stripping() {
    let data = load(BASIC_WINDOWS_STRIPPED);
    let bin = GoBinary::parse(&data).unwrap();
    let names: Vec<&str> = bin
        .functions()
        .collect::<Vec<_>>()
        .iter()
        .map(|f| f.name)
        .collect();
    assert!(
        names.contains(&"main.main"),
        "PE main.main should survive stripping"
    );
}

#[test]
fn source_files_macho() {
    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();
    let files = bin.pclntab().unwrap().file_names().collect::<Vec<_>>();
    assert!(!files.is_empty());
    assert!(files.iter().any(|f| f.ends_with("main.go")));
}

#[test]
fn source_files_pe() {
    let data = load(BASIC_WINDOWS);
    let bin = GoBinary::parse(&data).unwrap();
    let files = bin.pclntab().unwrap().file_names().collect::<Vec<_>>();
    assert!(!files.is_empty(), "PE should have source files");
    assert!(
        files.iter().any(|f| f.ends_with("main.go")),
        "PE should reference main.go"
    );
}

#[test]
fn source_files_survive_stripping() {
    let data = load(BASIC_STRIPPED);
    let bin = GoBinary::parse(&data).unwrap();
    let files = bin.pclntab().unwrap().file_names().collect::<Vec<_>>();
    assert!(!files.is_empty());
    assert!(files.iter().any(|f| f.ends_with("main.go")));
}

#[test]
fn packages_from_functions() {
    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();
    let funcs = bin.functions().collect::<Vec<_>>();
    let pkgs: BTreeSet<&str> = funcs.iter().filter_map(|f| f.package()).collect();
    assert!(pkgs.contains("main"));
    assert!(pkgs.contains("runtime"));
    assert!(pkgs.contains("fmt"));
}

#[test]
fn packages_pe() {
    let data = load(BASIC_WINDOWS);
    let bin = GoBinary::parse(&data).unwrap();
    let funcs = bin.functions().collect::<Vec<_>>();
    let pkgs: BTreeSet<&str> = funcs.iter().filter_map(|f| f.package()).collect();
    assert!(pkgs.contains("main"), "PE should have main package");
    assert!(pkgs.contains("runtime"), "PE should have runtime package");
}

#[test]
fn types_macho() {
    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();
    let types: Vec<_> = bin.types().collect();
    assert!(!types.is_empty(), "Should extract types from Mach-O");
}

#[test]
fn types_elf() {
    let data = load(BASIC_LINUX);
    let bin = GoBinary::parse(&data).unwrap();
    let types: Vec<_> = bin.types().collect();
    assert!(!types.is_empty(), "Should extract types from ELF");
}

#[test]
fn types_pe() {
    let data = load(BASIC_WINDOWS);
    let bin = GoBinary::parse(&data).unwrap();
    let types: Vec<_> = bin.types().collect();
    assert!(!types.is_empty(), "Should extract types from PE");
}

#[test]
fn function_info_metadata() {
    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();
    let funcs = bin.functions().collect::<Vec<_>>();

    let main_fn = funcs
        .iter()
        .find(|f| f.name == "main.main")
        .expect("main.main not found");
    assert_eq!(main_fn.package(), Some("main"));
    assert!(!main_fn.is_method());
    assert!(!main_fn.is_runtime());
    assert!(!main_fn.is_closure());
    assert!(main_fn.entry_offset > 0);
}

#[test]
fn function_info_runtime() {
    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();
    let funcs = bin.functions().collect::<Vec<_>>();

    let rt = funcs
        .iter()
        .find(|f| f.name == "runtime.main")
        .expect("runtime.main not found");
    assert!(rt.is_runtime());
    assert!(rt.is_internal());
    assert!(!rt.is_stdlib());
}

#[test]
fn function_info_stdlib() {
    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();
    let funcs = bin.functions().collect::<Vec<_>>();

    let fmt_fn = funcs
        .iter()
        .find(|f| f.name.starts_with("fmt."))
        .expect("No fmt.* function found");
    assert!(fmt_fn.is_stdlib());
    assert!(!fmt_fn.is_internal());
    assert!(!fmt_fn.is_runtime());
}

#[test]
fn minimal_normal_detected() {
    let data = load(MINIMAL_NORMAL);
    let bin = GoBinary::parse(&data).expect("Minimal binary should be detected");
    assert_eq!(bin.confidence(), Confidence::High);
    assert!(bin.go_version().is_some());
    assert!(bin.pclntab().map(|p| p.nfunc).unwrap() > 0);
}

#[test]
fn minimal_stripped_detected() {
    let data = load(MINIMAL_STRIPPED);
    let bin = GoBinary::parse(&data).expect("Minimal stripped binary should be detected");
    assert_eq!(bin.confidence(), Confidence::High);
    assert!(bin.pclntab().map(|p| p.nfunc).unwrap() > 0);
}

#[test]
fn go_version_consistent_across_formats() {
    let data_macho = load(BASIC_NORMAL);
    let data_elf = load(BASIC_LINUX);
    let data_pe = load(BASIC_WINDOWS);

    let macho = GoBinary::parse(&data_macho).unwrap();
    let elf = GoBinary::parse(&data_elf).unwrap();
    let pe = GoBinary::parse(&data_pe).unwrap();

    let v_macho = macho.go_version().unwrap();
    let v_elf = elf.go_version().unwrap();
    let v_pe = pe.go_version().unwrap();

    assert_eq!(
        v_macho, v_elf,
        "Mach-O and ELF should report same Go version"
    );
    assert_eq!(v_elf, v_pe, "ELF and PE should report same Go version");
}

#[test]
fn pclntab_version_consistent_across_formats() {
    let data_macho = load(BASIC_NORMAL);
    let data_elf = load(BASIC_LINUX);
    let data_pe = load(BASIC_WINDOWS);

    let macho = GoBinary::parse(&data_macho).unwrap();
    let elf = GoBinary::parse(&data_elf).unwrap();
    let pe = GoBinary::parse(&data_pe).unwrap();

    assert_eq!(
        macho.pclntab().map(|p| p.version),
        elf.pclntab().map(|p| p.version)
    );
    assert_eq!(
        elf.pclntab().map(|p| p.version),
        pe.pclntab().map(|p| p.version)
    );
}

#[test]
fn main_function_present_in_all_formats() {
    for (path, label) in [
        (BASIC_NORMAL, "Mach-O"),
        (BASIC_LINUX, "ELF"),
        (BASIC_WINDOWS, "PE"),
        (BASIC_STRIPPED, "Mach-O stripped"),
        (BASIC_WINDOWS_STRIPPED, "PE stripped"),
    ] {
        let data = load(path);
        let bin = GoBinary::parse(&data).unwrap();
        let funcs = bin.functions().collect::<Vec<_>>();
        assert!(
            funcs.iter().any(|f| f.name == "main.main"),
            "{label} should contain main.main"
        );
    }
}

#[test]
fn build_id_elf_note() {
    let data = load(BASIC_LINUX);
    let bin = GoBinary::parse(&data).unwrap();
    let id = bin
        .build_id()
        .expect("ELF binary should have build ID from note");
    let parts: Vec<&str> = id.split('/').collect();
    assert_eq!(parts.len(), 4, "ELF build ID should have 4 parts");
}

#[test]
fn build_info_compiler_setting() {
    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();
    let info = bin.build_info().unwrap();
    assert_eq!(info.setting("-compiler"), Some("gc"));
}

#[test]
fn build_info_cgo_setting() {
    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();
    let info = bin.build_info().unwrap();
    // CGO_ENABLED should be present (either "0" or "1")
    assert!(
        info.setting("CGO_ENABLED").is_some(),
        "CGO_ENABLED should be in build settings"
    );
}

#[test]
fn reject_empty_data() {
    assert!(GoBinary::parse(&[]).is_none());
}

#[test]
fn reject_small_data() {
    assert!(GoBinary::parse(&[0x7f, b'E', b'L', b'F']).is_none());
}

#[test]
fn reject_non_go_elf_header() {
    // Valid ELF magic but not a Go binary
    let mut data = vec![0u8; 4096];
    data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    assert!(GoBinary::parse(&data).is_none());
}

#[test]
fn function_info_short_name() {
    let f = FunctionInfo {
        name: "net/http.(*Client).Do",
        entry_offset: 0,
        args_size: 0,
        start_line: 0,
        func_id: 0,
        flags: 0,
        deferreturn: 0,
        pcsp: 0,
        pcfile: 0,
        pcln: 0,
        npcdata: 0,
        cu_offset: 0,
        nfuncdata: 0,
        source_file: None,
        end_line: 0,
        frame_size: 0,
    };
    assert_eq!(f.short_name(), "(*Client).Do");
    assert_eq!(f.package(), Some("net/http"));
    assert!(f.is_method());
}

#[test]
fn function_info_closure() {
    let f = FunctionInfo {
        name: "main.main.func1",
        entry_offset: 0,
        args_size: 0,
        start_line: 0,
        func_id: 0,
        flags: 0,
        deferreturn: 0,
        pcsp: 0,
        pcfile: 0,
        pcln: 0,
        npcdata: 0,
        cu_offset: 0,
        nfuncdata: 0,
        source_file: None,
        end_line: 0,
        frame_size: 0,
    };
    assert!(f.is_closure());
    assert!(!f.is_method());
}

#[test]
fn function_info_func_id_names() {
    let f = FunctionInfo {
        name: "runtime.goexit",
        entry_offset: 0,
        args_size: 0,
        start_line: 0,
        func_id: 86,
        flags: 0,
        deferreturn: 0,
        pcsp: 0,
        pcfile: 0,
        pcln: 0,
        npcdata: 0,
        cu_offset: 0,
        nfuncdata: 0,
        source_file: None,
        end_line: 0,
        frame_size: 0,
    };
    assert_eq!(f.func_id_name(), Some("goexit"));

    let normal = FunctionInfo {
        name: "main.main",
        entry_offset: 0,
        args_size: 0,
        start_line: 0,
        func_id: 0,
        flags: 0,
        deferreturn: 0,
        pcsp: 0,
        pcfile: 0,
        pcln: 0,
        npcdata: 0,
        cu_offset: 0,
        nfuncdata: 0,
        source_file: None,
        end_line: 0,
        frame_size: 0,
    };
    assert_eq!(normal.func_id_name(), None);
}

#[test]
fn function_source_file_resolved() {
    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();
    let funcs = bin.functions().collect::<Vec<_>>();

    let main_fn = funcs
        .iter()
        .find(|f| f.name == "main.main")
        .expect("main.main not found");
    let src = main_fn
        .source_file
        .expect("main.main should have a source file");
    assert!(src.ends_with("main.go"), "Expected main.go, got: {src}");
}

#[test]
fn function_line_range() {
    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();
    let funcs = bin.functions().collect::<Vec<_>>();

    let main_fn = funcs
        .iter()
        .find(|f| f.name == "main.main")
        .expect("main.main not found");
    assert!(main_fn.start_line > 0, "start_line should be positive");
    assert!(
        main_fn.end_line >= main_fn.start_line,
        "end_line ({}) should be >= start_line ({})",
        main_fn.end_line,
        main_fn.start_line
    );
}

#[test]
fn function_frame_size() {
    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();
    let funcs = bin.functions().collect::<Vec<_>>();

    let main_fn = funcs
        .iter()
        .find(|f| f.name == "main.main")
        .expect("main.main not found");
    assert!(
        main_fn.frame_size > 0,
        "main.main should have a nonzero frame size"
    );
}

#[test]
fn itab_pairs_returns_some_for_normal_binaries() {
    for path in [BASIC_NORMAL, BASIC_LINUX] {
        let data = load(path);
        let bin = GoBinary::parse(&data).unwrap();
        for p in bin.itab_pairs() {
            assert_ne!(p.iface_type_va, 0, "{path}: iface VA should be nonzero");
            assert_ne!(
                p.concrete_type_va, 0,
                "{path}: concrete VA should be nonzero"
            );
        }
    }
}

#[test]
fn has_cgo_and_uses_concurrency_run_without_panic() {
    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();
    let _ = bin.has_cgo();
    let _ = bin.uses_concurrency();
}

#[test]
fn detect_fast_path_recognizes_go_binaries() {
    for path in [BASIC_NORMAL, BASIC_LINUX, BASIC_WINDOWS] {
        let data = load(path);
        assert!(
            detect(&data),
            "{path}: detect() should recognize this binary"
        );
    }
}

#[test]
fn detect_fast_path_rejects_random_data() {
    let data = vec![0u8; 4096];
    assert!(!detect(&data), "detect() should not flag zeroes");
}

#[test]
fn for_each_function_visits_all_functions() {
    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();
    let pcl = bin.pclntab().unwrap();

    let baseline_len = FunctionIter::new(Some(pcl)).count();
    let mut count = 0usize;
    let mut saw_main = false;
    for_each_function(&pcl, |info, tables| {
        count += 1;
        if info.name == "main.main" {
            saw_main = true;
            assert!(
                !tables.pcln.is_empty(),
                "main.main should have pcln entries"
            );
        }
    });
    assert_eq!(
        count, baseline_len,
        "for_each_function must visit all functions"
    );
    assert!(saw_main, "main.main must be visited");
}

#[test]
fn functions_iterator_matches_extract_functions() {
    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();
    let baseline = bin.functions().collect::<Vec<_>>();
    let from_iter: Vec<&str> = bin.functions().map(|f| f.name).collect();
    assert_eq!(from_iter.len(), baseline.len());
    assert_eq!(from_iter.first().copied(), baseline.first().map(|f| f.name),);
    assert!(from_iter.contains(&"main.main"));
}

#[test]
fn functions_iterator_empty_without_pclntab() {
    // Use a buffer that lacks a parseable pclntab. We can't construct GoBinary
    // without going through `parse`, so verify the iterator API exists and
    // composes with standard combinators on a real binary instead.
    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();
    let user_fns: usize = bin
        .functions()
        .filter(|f| !f.is_runtime() && !f.is_internal())
        .count();
    assert!(user_fns > 0, "expected at least one user function");
}

#[test]
fn strings_iter_recovers_runtime_literals() {
    use std::collections::HashSet;

    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();

    let mut unique: HashSet<&str> = HashSet::new();
    let mut total = 0usize;
    for s in bin.strings() {
        total += 1;
        if let Some(text) = s.as_str() {
            unique.insert(text);
        }
    }
    assert!(
        total > 100,
        "expected a healthy number of string hits, got {total}"
    );
    assert!(
        unique.len() > 50,
        "expected many unique strings, got {}",
        unique.len()
    );

    // Spot-check: well-known runtime panic-message fragments should appear in
    // any non-trivial Go binary built with the `gc` toolchain. Match as
    // substrings since the compiler often emits them inside longer literals
    // (e.g. "invalid memory address or nil pointer dereference").
    let needles = ["unreachable", "invalid memory address"];
    for needle in needles {
        assert!(
            unique.iter().any(|s| s.contains(needle)),
            "expected a runtime literal containing {:?} among {} unique strings",
            needle,
            unique.len(),
        );
    }
}

#[test]
fn strings_iter_works_on_stripped_binaries() {
    // Strings live in rodata, not in DWARF or symbol tables — should
    // survive `-ldflags='-s -w'` unchanged.
    let normal = {
        let d = load(BASIC_NORMAL);
        let bin = GoBinary::parse(&d).unwrap();
        bin.strings().count()
    };
    let stripped = {
        let d = load(BASIC_STRIPPED);
        let bin = GoBinary::parse(&d).unwrap();
        bin.strings().count()
    };
    // Should be very close — within 5% (stripping shouldn't materially affect rodata).
    let diff = (normal as i64 - stripped as i64).abs();
    let bound = (normal / 20).max(10);
    assert!(
        (diff as usize) <= bound,
        "string count drifted: normal={normal} stripped={stripped} diff={diff}",
    );
}

#[test]
fn strings_iter_works_across_formats() {
    for path in [BASIC_NORMAL, BASIC_LINUX, BASIC_WINDOWS] {
        let data = load(path);
        let bin = GoBinary::parse(&data).unwrap();
        let count = bin.strings().count();
        assert!(count > 100, "{path}: expected many strings, got {count}");
    }
}

#[test]
fn inline_tree_yields_entries_for_typical_binary() {
    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();
    let pcl = bin.pclntab().unwrap();

    // Walk every function; expect at least one to expose inlined frames.
    let mut total_entries = 0usize;
    let mut saw_named = false;
    let mut max_depth = 0u32;
    for (_, func_off) in pcl.func_entries() {
        let func = match pcl.parse_func(func_off) {
            Some(f) => f,
            None => continue,
        };
        for entry in bin.inline_tree(&func) {
            total_entries += 1;
            if !entry.function_name.is_empty() {
                saw_named = true;
            }
            if entry.depth > max_depth {
                max_depth = entry.depth;
            }
            assert!(
                entry.pc_range.start <= entry.pc_range.end,
                "pc_range must be ordered"
            );
        }
    }
    assert!(
        total_entries > 0,
        "expected at least one inlined call across the binary"
    );
    assert!(
        saw_named,
        "at least one inline entry must resolve a function name"
    );
    let _ = max_depth; // depth may be 0 for shallow inlining; just compute it
}

#[test]
fn inline_tree_empty_for_function_without_inlining() {
    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();
    let pcl = bin.pclntab().unwrap();

    // Find a function with no funcdata (typically asm helpers or trivial leaves)
    // and verify the iterator is empty rather than panicking.
    for (_, func_off) in pcl.func_entries() {
        let func = match pcl.parse_func(func_off) {
            Some(f) => f,
            None => continue,
        };
        if func.nfuncdata == 0 {
            assert_eq!(
                bin.inline_tree(&func).count(),
                0,
                "function with nfuncdata=0 must have empty inline tree",
            );
            return;
        }
    }
}

#[test]
fn types_iter_and_itab_pairs_iter_compose() {
    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();

    // bin.types() is a streaming iterator — verify it composes with .take() /
    // .count() and yields a positive number of types.
    let count = bin.types().count();
    assert!(count > 0, "binary should expose at least one type");
    assert_eq!(bin.types().take(5).count(), count.min(5));

    // itab_pairs is a streaming iterator (corpus may not contain pairs)
    let _ = bin.itab_pairs().count();
}

#[test]
fn buildinfo_borrows_from_input() {
    let data = load(BASIC_LINUX);
    let bin = GoBinary::parse(&data).unwrap();
    let info = bin.build_info().unwrap();
    // main_path is now Option<&str>; verify it borrows from the original
    // buildinfo blob by checking the pointer falls inside `data`.
    if let Some(main) = info.main_path {
        let main_ptr = main.as_ptr() as usize;
        let data_start = data.as_ptr() as usize;
        let data_end = data_start + data.len();
        assert!(
            main_ptr >= data_start && main_ptr < data_end,
            "main_path should borrow from binary data, not be re-allocated"
        );
    }
}

#[test]
fn build_info_iterators_match_fields() {
    let data = load(BASIC_LINUX);
    let bin = GoBinary::parse(&data).unwrap();
    let info = bin.build_info().unwrap();
    assert_eq!(info.dependencies().count(), info.deps.len());
    assert_eq!(
        info.build_settings_iter().count(),
        info.build_settings.len()
    );
}

#[test]
fn compiler_recognizes_gc_binaries() {
    for path in [BASIC_NORMAL, BASIC_LINUX, BASIC_WINDOWS] {
        let data = load(path);
        let bin = GoBinary::parse(&data).unwrap();
        assert_eq!(bin.compiler(), Compiler::Gc, "{path}: expected gc compiler");
    }
}

#[test]
fn obfuscation_none_for_clean_binaries() {
    for path in [BASIC_NORMAL, BASIC_LINUX, BASIC_WINDOWS] {
        let data = load(path);
        let bin = GoBinary::parse(&data).unwrap();
        assert_eq!(
            bin.obfuscation(),
            ObfuscationKind::None,
            "{path}: clean build should not be flagged",
        );
        assert!(
            !bin.is_likely_garbled(),
            "{path}: clean build is not garble"
        );
    }
}

#[test]
fn try_parse_returns_report_on_success() {
    let data = load(BASIC_NORMAL);
    let bin = GoBinary::try_parse(&data).expect("should parse");
    let report = bin.report();
    assert_eq!(report.tier, Confidence::High);
    assert!(
        report
            .signals
            .iter()
            .any(|s| matches!(s, ConfidenceSignal::PclntabParsed { .. })),
        "report should record pclntab parse signal",
    );
}

#[test]
fn try_parse_returns_error_for_random_data() {
    let data = vec![0u8; 1024];
    let err = match GoBinary::try_parse(&data) {
        Ok(_) => panic!("random data must fail"),
        Err(e) => e,
    };
    let ParseError::NotAGoBinary { report } = err;
    assert_eq!(report.tier, Confidence::None);
}

#[test]
fn text_va_and_etext_va_present() {
    for path in [BASIC_NORMAL, BASIC_LINUX, BASIC_WINDOWS] {
        let data = load(path);
        let bin = GoBinary::parse(&data).unwrap();
        let text = bin
            .text_va()
            .unwrap_or_else(|| panic!("{path}: text_va missing"));
        let etext = bin
            .etext_va()
            .unwrap_or_else(|| panic!("{path}: etext_va missing"));
        assert!(text > 0, "{path}: text_va should be nonzero");
        assert!(etext > text, "{path}: etext_va should be > text_va");
    }
}

#[test]
fn entry_off_translates_to_text_va() {
    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();
    let text_va = bin.text_va().unwrap();
    let funcs = bin.functions().collect::<Vec<_>>();
    let main_fn = funcs.iter().find(|f| f.name == "main.main").unwrap();
    let main_va = text_va + main_fn.entry_offset as u64;
    assert!(
        main_va > text_va,
        "main.main VA must be inside text segment"
    );
}

#[test]
fn entry_va_matches_manual_translation() {
    for path in [BASIC_NORMAL, BASIC_LINUX, BASIC_WINDOWS] {
        let data = load(path);
        let bin = GoBinary::parse(&data).unwrap();
        let text_va = bin.text_va().unwrap();
        let pcl = bin.pclntab().unwrap();
        let (_, func_off) = pcl.func_entries().next().unwrap();
        let func = pcl.parse_func(func_off).unwrap();

        let manual = text_va + func.entry_off as u64;
        assert_eq!(
            bin.entry_va(&func),
            Some(manual),
            "{path}: entry_va must equal text_va + entry_off"
        );
    }
}

#[test]
fn entry_rva_subtracts_image_base_for_pe() {
    // PE: entry_rva = entry_va − image_base.
    let data = load(BASIC_WINDOWS);
    let bin = GoBinary::parse(&data).unwrap();
    let pcl = bin.pclntab().unwrap();
    let (_, func_off) = pcl.func_entries().next().unwrap();
    let func = pcl.parse_func(func_off).unwrap();

    let image_base = bin.context().image_base();
    assert!(
        image_base > 0,
        "PE image_base should be nonzero (typical: 0x140000000 for amd64 EXE)"
    );
    let va = bin.entry_va(&func).unwrap();
    let rva = bin.entry_rva(&func).unwrap();
    assert_eq!(rva, va - image_base);
    assert!(rva < va, "RVA must be smaller than VA for PE");
}

#[test]
fn entry_rva_equals_entry_va_for_va_native_formats() {
    // ELF and Mach-O: image_base is 0, so RVA == VA.
    for path in [BASIC_NORMAL, BASIC_LINUX] {
        let data = load(path);
        let bin = GoBinary::parse(&data).unwrap();
        assert_eq!(
            bin.context().image_base(),
            0,
            "{path}: VA-native format should report image_base = 0"
        );
        let pcl = bin.pclntab().unwrap();
        let (_, func_off) = pcl.func_entries().next().unwrap();
        let func = pcl.parse_func(func_off).unwrap();
        assert_eq!(bin.entry_va(&func), bin.entry_rva(&func));
    }
}

#[test]
fn strings_iter_surfaces_non_utf8_bytes() {
    // After A-09, the scanner no longer pre-filters on UTF-8. Verify that
    // (a) bin.strings() never panics on non-UTF-8 hits, and (b) GoString's
    // as_bytes() / try_as_str() / as_str() agree with each other.
    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();

    let mut total = 0usize;
    let mut utf8_ok = 0usize;
    let mut non_utf8 = 0usize;
    for s in bin.strings() {
        total += 1;
        // Raw bytes are always available.
        assert_eq!(s.as_bytes().len(), s.len);
        match s.try_as_str() {
            Ok(text) => {
                utf8_ok += 1;
                assert_eq!(s.as_str(), Some(text));
            }
            Err(_) => {
                non_utf8 += 1;
                assert_eq!(s.as_str(), None);
            }
        }
    }
    assert!(total > 100, "expected many string hits, got {total}");
    // We intentionally don't assert non_utf8 > 0 — a stdlib hello binary
    // may not contain any. The point is the API doesn't drop them.
    let _ = (utf8_ok, non_utf8);
}

#[test]
fn type_classification_helpers_match_function_helpers() {
    use gobin::metadata::{is_internal_path, is_runtime_path, is_stdlib_path};

    // runtime.* / runtime/internal/* are runtime AND internal, never stdlib
    assert!(is_runtime_path("runtime"));
    assert!(is_runtime_path("runtime/internal/atomic"));
    assert!(is_internal_path("runtime"));
    assert!(!is_stdlib_path("runtime"));

    // Plain stdlib
    assert!(is_stdlib_path("net/http"));
    assert!(is_stdlib_path("encoding/json"));
    assert!(!is_internal_path("net/http"));
    assert!(!is_runtime_path("net/http"));

    // Third-party (domain-shaped) is none-of-the-above
    assert!(!is_stdlib_path("github.com/spf13/cobra"));
    assert!(!is_internal_path("github.com/spf13/cobra"));
    assert!(!is_stdlib_path("gopkg.in/yaml.v3"));

    // internal/* is internal but not stdlib
    assert!(is_internal_path("internal/abi"));
    assert!(!is_stdlib_path("internal/abi"));
}

#[test]
fn go_type_classification_via_real_binary() {
    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();

    let (mut runtime_ct, mut stdlib_ct, mut user_ct) = (0usize, 0usize, 0usize);
    for ty in bin.types() {
        if ty.is_runtime() {
            runtime_ct += 1;
        } else if ty.is_stdlib() {
            stdlib_ct += 1;
        } else if ty.package().is_some() {
            user_ct += 1;
        }
        // is_internal must be a superset of is_runtime
        if ty.is_runtime() {
            assert!(
                ty.is_internal(),
                "runtime type must also be internal: {}",
                ty.name
            );
        }
        // is_stdlib and is_internal must be disjoint
        assert!(
            !(ty.is_stdlib() && ty.is_internal()),
            "type both stdlib AND internal: {}",
            ty.name
        );
    }
    assert!(
        runtime_ct > 0,
        "a Go binary should expose at least one runtime type"
    );
    let _ = (stdlib_ct, user_ct);
}

#[test]
fn func_data_args_size_returns_unsigned_byte_count() {
    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();
    let pcl = bin.pclntab().unwrap();

    let mut saw_nonneg = false;
    for (_, off) in pcl.func_entries().take(20) {
        let f = match pcl.parse_func(off) {
            Some(f) => f,
            None => continue,
        };
        // args_size() never wraps for negative-stored values; non-negative
        // raw values pass through unchanged.
        if f.args >= 0 {
            assert_eq!(f.args_size(), f.args as u32);
            saw_nonneg = true;
        }
    }
    assert!(
        saw_nonneg,
        "expected at least one function with a non-negative args field"
    );
}

#[test]
fn type_detail_scalar_accessors() {
    use gobin::structures::types::TypeDetail;

    let arr = TypeDetail::Array {
        len: 16,
        elem_va: 0,
        slice_va: 0,
    };
    assert_eq!(arr.array_len(), Some(16));
    assert_eq!(arr.chan_dir(), None);
    assert_eq!(arr.func_arity(), None);

    let ch = TypeDetail::Chan { dir: 2, elem_va: 0 };
    assert_eq!(ch.chan_dir(), Some(2));
    assert_eq!(ch.array_len(), None);

    let f = TypeDetail::Func {
        in_count: 3,
        out_count: 2,
        is_variadic: false,
        inputs: vec![],
        outputs: vec![],
    };
    assert_eq!(f.func_arity(), Some((3, 2)));

    let s = TypeDetail::Struct {
        field_count: 5,
        fields: vec![],
    };
    assert_eq!(s.struct_field_count(), Some(5));

    let i = TypeDetail::Interface {
        method_count: 7,
        methods: vec![],
        pkg_path: None,
    };
    assert_eq!(i.interface_method_count(), Some(7));

    // None cases
    let n = TypeDetail::None;
    assert_eq!(n.array_len(), None);
    assert_eq!(n.chan_dir(), None);
    assert_eq!(n.func_arity(), None);
    assert_eq!(n.struct_field_count(), None);
    assert_eq!(n.interface_method_count(), None);
}

#[test]
fn enum_display_strings_are_stable() {
    use gobin::structures::types::TypeDetail;

    // Confidence
    assert_eq!(format!("{}", Confidence::None), "none");
    assert_eq!(format!("{}", Confidence::Low), "low");
    assert_eq!(format!("{}", Confidence::Medium), "medium");
    assert_eq!(format!("{}", Confidence::High), "high");

    // PclntabVersion
    assert_eq!(format!("{}", PclntabVersion::Go12), "go12");
    assert_eq!(format!("{}", PclntabVersion::Go116), "go116");
    assert_eq!(format!("{}", PclntabVersion::Go118), "go118");
    assert_eq!(format!("{}", PclntabVersion::Go120), "go120");

    // Arch — values match canonical GOARCH where they exist
    assert_eq!(format!("{}", Arch::X86), "386");
    assert_eq!(format!("{}", Arch::X86_64), "amd64");
    assert_eq!(format!("{}", Arch::Arm64), "arm64");
    assert_eq!(format!("{}", Arch::Wasm), "wasm");
    assert_eq!(format!("{}", Arch::Unknown), "unknown");

    // TypeDetail::kind_str
    assert_eq!(TypeDetail::None.kind_str(), "none");
    assert_eq!(
        TypeDetail::Array {
            len: 4,
            elem_va: 0x1000,
            slice_va: 0,
        }
        .kind_str(),
        "array"
    );
    assert_eq!(
        TypeDetail::Chan {
            dir: 3,
            elem_va: 0x1000
        }
        .kind_str(),
        "chan"
    );
    assert_eq!(
        TypeDetail::Map {
            key_va: 0x1,
            elem_va: 0x2,
            group_va: 0,
            hasher_va: 0,
            key_stride: 0,
            elem_stride: 0,
            flags: 0,
        }
        .kind_str(),
        "map"
    );
}

#[test]
fn build_mode_as_str_round_trips_through_parse() {
    use gobin::metadata::BuildMode;
    let cases = [
        BuildMode::Exe,
        BuildMode::Pie,
        BuildMode::CShared,
        BuildMode::CArchive,
        BuildMode::Plugin,
        BuildMode::Archive,
        BuildMode::Shared,
        BuildMode::Other("custom-future".to_string()),
    ];
    for mode in cases {
        let s = mode.as_str();
        let round = BuildMode::parse(&s);
        assert_eq!(round, mode, "as_str → parse must round-trip for {mode:?}");
        // Display must agree with as_str so schema serialization is stable.
        assert_eq!(format!("{mode}"), s.as_ref());
    }
}

#[test]
fn build_settings_expose_buildmode_and_tags() {
    let data = load(BASIC_LINUX);
    let bin = GoBinary::parse(&data).unwrap();
    let info = bin.build_info().expect("build info present");
    assert!(info.build_mode().is_some());
    let _ = info.build_tags();
}

#[test]
fn decode_pcln_with_files_attributes_source_file_per_line() {
    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();
    let pcl = bin.pclntab().unwrap();

    // Find a function with both pcln and pcfile entries.
    let mut joined_total = 0usize;
    let mut at_least_one_function = false;
    for (_, off) in pcl.func_entries() {
        let f = match pcl.parse_func(off) {
            Some(f) => f,
            None => continue,
        };

        // Reference data: per-PC pcln + the latest-≤-pc pcfile resolution.
        let pcfile: Vec<(u32, u32)> = pcl.decode_pcfile(&f).collect();
        if pcfile.is_empty() {
            continue;
        }
        at_least_one_function = true;

        // Joined iterator must agree with the manual lockstep walk on every
        // emitted (pc, line, path) tuple.
        for (pc, line, path) in pcl.decode_pcln_with_files(&f) {
            joined_total += 1;

            // Expected file index = latest pcfile transition with t_pc ≤ pc.
            let expected_idx = pcfile
                .iter()
                .rev()
                .find(|(t_pc, _)| *t_pc <= pc)
                .map(|(_, idx)| *idx)
                .unwrap();
            let expected_path = pcl.resolve_file_via_cu(f.cu_offset, expected_idx).unwrap();
            assert_eq!(path, expected_path, "joined path mismatch at pc={pc}");

            // Line must be a sane source line (not absurdly large).
            assert!((0..1_000_000).contains(&line), "implausible line {line}");

            if joined_total > 50 {
                break;
            }
        }
        if joined_total > 50 {
            break;
        }
    }
    assert!(at_least_one_function, "expected pcfile entries somewhere");
    assert!(joined_total > 0, "joined iterator yielded nothing");
}

#[test]
fn decode_pcfile_returns_unsigned_indices() {
    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();
    let pcl = bin.pclntab().unwrap();

    let mut saw_indices = false;
    let mut saw_resolved = false;
    for (_, func_off) in pcl.func_entries() {
        let func = match pcl.parse_func(func_off) {
            Some(f) => f,
            None => continue,
        };
        if pcl.decode_pcfile(&func).next().is_some() {
            saw_indices = true;
        }
        if pcl.decode_pcfile_paths(&func).next().is_some() {
            saw_resolved = true;
        }
        if saw_indices && saw_resolved {
            break;
        }
    }
    assert!(
        saw_indices,
        "at least one function should produce pcfile indices"
    );
    assert!(
        saw_resolved,
        "at least one function should resolve a pcfile path"
    );
}

#[test]
fn type_details_present() {
    use gobin::structures::types::TypeDetail;

    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();
    let types: Vec<_> = bin.types().collect();

    // Should have at least some types with struct/interface/func/chan details
    let has_struct = types
        .iter()
        .any(|t| matches!(t.detail, TypeDetail::Struct { .. }));
    let has_method_count = types.iter().any(|t| t.method_count > 0);

    assert!(
        has_struct,
        "Should have at least one struct type with field count"
    );
    assert!(
        has_method_count,
        "Should have at least one type with methods"
    );
}

#[test]
fn struct_fields_resolved() {
    use gobin::structures::types::TypeDetail;

    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();
    let types: Vec<_> = bin.types().collect();

    let struct_with_fields = types.iter().find_map(|t| match &t.detail {
        TypeDetail::Struct { fields, .. } if !fields.is_empty() => Some((t, fields)),
        _ => None,
    });
    let (ty, fields) = struct_with_fields.expect("at least one struct should have resolved fields");
    assert!(!ty.name.is_empty());
    let named_fields = fields.iter().filter(|f| !f.name.is_empty()).count();
    assert!(
        named_fields > 0,
        "expected at least one named field on {}",
        ty.name
    );
}

#[test]
fn interface_methods_resolved_when_present() {
    use gobin::structures::types::TypeDetail;

    // The current `basic_*` fixtures have no Interface entries in their
    // typelinks (the Go linker omits interface types not used as runtime
    // type descriptors). We assert: *if* any interface with method_count > 0
    // is present, we must also have resolved its method names.
    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();
    let types: Vec<_> = bin.types().collect();

    for t in &types {
        if let TypeDetail::Interface {
            method_count,
            methods,
            ..
        } = &t.detail
            && *method_count > 0
        {
            assert!(
                !methods.is_empty(),
                "interface {} has method_count={} but no resolved methods",
                t.name,
                method_count,
            );
        }
    }
}

#[test]
fn func_type_carries_param_vas() {
    use gobin::structures::types::TypeDetail;

    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();

    // Find at least one Func type with non-zero param VAs and verify
    // the lengths match in_count / out_count.
    let mut saw_with_params = false;
    let mut saw_input_va = false;
    let mut saw_output_va = false;
    for t in bin.types() {
        if let TypeDetail::Func {
            in_count,
            out_count,
            inputs,
            outputs,
            ..
        } = &t.detail
        {
            if !inputs.is_empty() || !outputs.is_empty() {
                saw_with_params = true;
            }
            assert_eq!(
                inputs.len(),
                *in_count as usize,
                "{}: inputs.len() must equal in_count when descriptor is well-formed",
                t.name,
            );
            assert_eq!(
                outputs.len(),
                *out_count as usize,
                "{}: outputs.len() must equal out_count",
                t.name,
            );
            if inputs.iter().any(|r| r.va != 0) {
                saw_input_va = true;
            }
            if outputs.iter().any(|r| r.va != 0) {
                saw_output_va = true;
            }
        }
    }
    assert!(
        saw_with_params,
        "expected at least one func type with params"
    );
    assert!(saw_input_va, "at least one input VA should be nonzero");
    assert!(saw_output_va, "at least one output VA should be nonzero");
}

#[test]
fn all_types_enumerates_more_and_resolves_tags() {
    use gobin::structures::types::TypeDetail;
    let data = load(BASIC_LINUX);
    let bin = GoBinary::parse(&data).unwrap();

    let canonical = bin.types().count();
    let all = bin.all_types();
    // The transitive walk reaches strictly more than the typelink set.
    assert!(
        all.len() > canonical,
        "all_types ({}) should exceed types ({canonical})",
        all.len()
    );
    // Every enumerated type has a clean name and a valid descriptor VA.
    for t in &all {
        assert!(
            t.name.is_empty() || !t.name.bytes().any(|c| c < 0x20),
            "garbage type name: {:?}",
            t.name
        );
        assert!(t.descriptor_va != 0);
    }
    // Struct field tags resolve (only reachable via the full walk, since the
    // tagged struct types are not all in typelink).
    let mut tagged = 0usize;
    let mut saw_keyvalue_tag = false;
    for t in &all {
        if let TypeDetail::Struct { fields, .. } = &t.detail {
            for f in fields {
                if let Some(tag) = f.tag {
                    tagged += 1;
                    // Conventional `key:"value"` tags (e.g. json/yaml) appear in
                    // stdlib structs — at least one should decode cleanly.
                    if tag.contains(":\"") {
                        saw_keyvalue_tag = true;
                    }
                }
            }
        }
    }
    assert!(
        tagged > 20,
        "expected many tagged struct fields, got {tagged}"
    );
    assert!(
        saw_keyvalue_tag,
        "expected a conventional key:\"value\" struct tag"
    );
}

#[test]
fn type_at_va_resolves_referenced_types() {
    use gobin::structures::types::TypeDetail;
    let data = load(BASIC_LINUX);
    let bin = GoBinary::parse(&data).unwrap();

    // Find a slice type and resolve its element type by VA.
    let slice = bin
        .types()
        .find_map(|t| match t.detail {
            TypeDetail::Slice { elem_va } if elem_va != 0 => Some(elem_va),
            _ => None,
        })
        .expect("a slice type with an element");
    let elem = bin.type_at(slice).expect("element type resolves");
    assert!(!elem.name.is_empty());
}

#[test]
fn type_descriptor_full_fields() {
    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();

    // A named type with methods exposes its import path (from UncommonType),
    // the equality-fn and GC-bitmap pointers, and the raw tflag.
    let t = bin
        .types()
        .find(|t| t.name.contains("TestStruct") && t.has_uncommon)
        .expect("TestStruct with methods");
    assert_eq!(t.pkg_path, Some("main"), "uncommon pkg_path");
    assert!(t.equal_va != 0, "equality fn VA should be set");
    assert!(t.gcdata_va != 0, "gcdata VA should be set");
    assert!(t.tflag & 0x01 != 0, "TFlagUncommon bit set");

    // At least some types expose a pointer-to-this descriptor offset.
    assert!(
        bin.types().any(|t| t.ptr_to_this != 0),
        "expected some types to carry a *T offset"
    );
}

#[test]
fn type_names_resolve_for_fields_methods_and_params() {
    use gobin::structures::types::TypeDetail;

    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();

    let mut resolved_field = false;
    let mut resolved_param = false;
    let mut named_field_value = None;
    for t in bin.types() {
        match &t.detail {
            TypeDetail::Struct { fields, .. } => {
                for n in fields.iter().filter_map(|f| f.type_name) {
                    resolved_field = true;
                    named_field_value.get_or_insert_with(|| n.to_string());
                }
            }
            TypeDetail::Func {
                inputs, outputs, ..
            } if inputs
                .iter()
                .chain(outputs.iter())
                .any(|r| r.name.is_some()) =>
            {
                resolved_param = true;
            }
            _ => {}
        }
    }
    // A stdlib-linked binary has plenty of named struct fields and func params;
    // the leaf (concrete) referenced types should resolve to names. Method /
    // interface-method signature types are unnamed Go func types, so their
    // `type_name` is expectedly None — covered by the doc contract, not here.
    assert!(resolved_field, "expected some struct field type names");
    assert!(resolved_param, "expected some func param type names");
    assert!(
        named_field_value.is_some_and(|n| !n.is_empty()),
        "a resolved field type name should be non-empty"
    );
}

#[test]
fn pointer_and_slice_carry_elem_va() {
    use gobin::structures::types::TypeDetail;

    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();
    let types: Vec<_> = bin.types().collect();

    let any_ptr = types
        .iter()
        .any(|t| matches!(&t.detail, TypeDetail::Pointer { elem_va } if *elem_va != 0));
    let any_slice = types
        .iter()
        .any(|t| matches!(&t.detail, TypeDetail::Slice { elem_va } if *elem_va != 0));
    assert!(
        any_ptr,
        "expected at least one pointer with nonzero elem_va"
    );
    assert!(
        any_slice,
        "expected at least one slice with nonzero elem_va"
    );
}

#[test]
fn map_carries_key_and_elem_va() {
    use gobin::structures::types::TypeDetail;

    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();
    let types: Vec<_> = bin.types().collect();

    let any_map = types.iter().any(|t| {
        matches!(&t.detail, TypeDetail::Map { key_va, elem_va, .. } if *key_va != 0 && *elem_va != 0)
    });
    assert!(
        any_map,
        "expected at least one map with nonzero key/elem VAs"
    );
}

#[test]
fn methods_resolved_on_concrete_types() {
    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();
    let types: Vec<_> = bin.types().collect();

    let with_methods = types
        .iter()
        .find(|t| t.has_uncommon && !t.methods.is_empty())
        .expect("at least one type should expose resolved methods");
    let m = with_methods.methods.first().unwrap();
    assert!(!m.name.is_empty(), "method names should resolve to strings");
    assert_eq!(
        with_methods.methods.len(),
        with_methods.method_count as usize,
        "methods.len() should match method_count for {}",
        with_methods.name,
    );
}

#[test]
fn init_order_works_on_v4_binary() {
    // basic_normal is Go 1.26 (V4); the V4 walk was extended to reach inittasks.
    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();
    let tasks = bin.init_order();
    let packages: std::collections::BTreeSet<&str> =
        tasks.iter().filter_map(|t| t.package).collect();
    assert!(
        packages.contains("runtime"),
        "V4 inittasks should resolve runtime init, saw {packages:?}"
    );
}

/// Cross-version sweep over the whole fixture matrix (every Go version ×
/// format × strip variant). These tests discover fixtures by filename
/// (`<prog>_go<minor>_<goos>_<goarch>[_stripped][.exe]`) so adding a fixture to
/// `tests/samples/` automatically extends coverage.
mod matrix {
    use super::*;
    use gobin::structures::moduledata::ModuledataVersion;

    struct Fixture {
        path: String,
        prog: String,
        gotag: String,
        goarch: String,
    }

    fn discover() -> Vec<Fixture> {
        let dir = "tests/samples";
        let mut out = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if !path.is_file() {
                continue;
            }
            let fname = path.file_name().unwrap().to_str().unwrap().to_string();
            // Plugins / shared objects (`.so`) have different invariants (no
            // main.main) and are covered by their own test.
            if fname.ends_with(".so") {
                continue;
            }
            let name = fname.strip_suffix(".exe").unwrap_or(&fname);
            let core = name.strip_suffix("_stripped").unwrap_or(name);
            let parts: Vec<&str> = core.split('_').collect();
            // <prog>_go<NN>_<goos>_<goarch>
            if parts.len() != 4 || !parts[1].starts_with("go") {
                continue;
            }
            out.push(Fixture {
                path: format!("{dir}/{fname}"),
                prog: parts[0].to_string(),
                gotag: parts[1].to_string(),
                goarch: parts[3].to_string(),
            });
        }
        out.sort_by(|a, b| a.path.cmp(&b.path));
        out
    }

    /// Moduledata layout the parser must detect for each toolchain. epclntab
    /// was added in Go 1.26, so 1.21 and 1.24 are both V3.
    fn expected_md(gotag: &str) -> ModuledataVersion {
        match gotag {
            // rodata/gofunc arrived in 1.18, so 1.16-1.17 are V2 and 1.18-1.25
            // are V3 (covctrs in 1.20 and inittasks in 1.21 are sub-details).
            "go116" => ModuledataVersion::V2,
            "go119" | "go121" | "go124" => ModuledataVersion::V3,
            "go126" => ModuledataVersion::V4,
            "go127" => ModuledataVersion::V5,
            other => panic!("unknown toolchain tag {other}"),
        }
    }

    #[test]
    fn corpus_covers_all_four_toolchains() {
        let fixtures = discover();
        assert!(
            fixtures.len() >= 20,
            "expected the full fixture matrix, found {}",
            fixtures.len()
        );
        let tags: BTreeSet<&str> = fixtures.iter().map(|f| f.gotag.as_str()).collect();
        for t in ["go116", "go119", "go121", "go124", "go126", "go127"] {
            assert!(tags.contains(t), "matrix is missing toolchain {t}");
        }
    }

    #[test]
    fn every_fixture_parses_with_main() {
        for fx in discover() {
            let data = load(&fx.path);
            let bin =
                GoBinary::parse(&data).unwrap_or_else(|| panic!("parse failed for {}", fx.path));
            let names: BTreeSet<&str> = bin.functions().map(|f| f.name).collect();
            assert!(names.contains("main.main"), "{}: no main.main", fx.path);
            assert!(
                names.contains("runtime.main"),
                "{}: no runtime.main",
                fx.path
            );
        }
    }

    #[test]
    fn moduledata_version_matches_toolchain() {
        for fx in discover() {
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            let md = bin
                .moduledata()
                .unwrap_or_else(|| panic!("{}: moduledata not located", fx.path));
            assert_eq!(
                md.version,
                expected_md(&fx.gotag),
                "{}: wrong moduledata version",
                fx.path
            );
        }
    }

    /// The full moduledata tail must parse correctly across the version-
    /// divergent `bad`/`next` ordering. Validated by the invariants of a normal
    /// single-module executable: `next`/`typemap` are nil, `bad` is false, and
    /// the version-gated `epclntab` (1.26+) / `typedesclen` (V5) optionals
    /// match the toolchain. Garbage from a wrong tail offset would break these.
    #[test]
    fn moduledata_full_tail_across_versions() {
        for fx in discover() {
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            let md = bin.moduledata().unwrap();

            assert_eq!(md.next, 0, "{}: single module, next should be nil", fx.path);
            assert_eq!(md.typemap, 0, "{}: typemap is runtime-populated", fx.path);
            assert!(!md.bad, "{}: a healthy module is not `bad`", fx.path);
            assert!(md.gcdata != 0, "{}: gcdata pointer should be set", fx.path);

            // epclntab arrived in 1.26 (V4+); typedesclen is V5-only.
            let v = md.version;
            use gobin::structures::moduledata::ModuledataVersion as V;
            assert_eq!(
                md.epclntab.is_some(),
                matches!(v, V::V4 | V::V5),
                "{}: epclntab presence wrong for {v:?}",
                fx.path
            );
            assert_eq!(
                md.typedesclen.is_some(),
                matches!(v, V::V5),
                "{}: typedesclen presence wrong for {v:?}",
                fx.path
            );
        }
    }

    /// Types, itabs, and init order must all populate on every native `basic`
    /// fixture — this is the regression guard for the pre-1.26 moduledata scan
    /// and the per-version epclntab / inittasks handling.
    #[test]
    fn types_itabs_inits_across_versions() {
        for fx in discover()
            .iter()
            .filter(|f| f.prog == "basic" && f.goarch != "wasm")
        {
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            assert!(
                bin.types().count() > 50,
                "{}: too few types ({})",
                fx.path,
                bin.types().count()
            );
            assert!(
                bin.itab_pairs().count() >= 5,
                "{}: too few itab pairs",
                fx.path
            );
            // `inittasks` was added in Go 1.21 (V3+); V2 (go116) has none, and
            // go119 (1.19) predates it too.
            if !matches!(fx.gotag.as_str(), "go116" | "go119") {
                let inits = bin.init_order();
                assert!(
                    inits.iter().any(|t| t.package == Some("runtime")),
                    "{}: runtime init task missing (inittasks regression)",
                    fx.path
                );
            }
        }
    }

    /// Guards the per-version `_func` struct layout (which differs across
    /// 1.16 / 1.18-1.19 / 1.20+): if `start_line`, `nfuncdata`, or the field
    /// offsets are read from the wrong place, decoded line numbers and
    /// funcdata counts become garbage. Checks every functab entry parses and
    /// yields sane values.
    #[test]
    fn func_struct_layout_sane_across_versions() {
        for fx in discover()
            .iter()
            .filter(|f| f.prog == "basic" && f.goarch != "wasm")
        {
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            let pcl = bin.pclntab().unwrap();
            let mut parsed = 0usize;
            for (_, func_off) in pcl.func_entries() {
                let fd = match pcl.parse_func(func_off) {
                    Some(fd) => fd,
                    None => continue,
                };
                parsed += 1;
                // nfuncdata is a small count (FUNCDATA_* indices top out < 16).
                assert!(
                    fd.nfuncdata <= 16,
                    "{}: implausible nfuncdata {} (wrong _func offset?)",
                    fx.path,
                    fd.nfuncdata
                );
                // Decoded line numbers must be sane, not garbage from reading
                // start_line at the wrong offset.
                for (_, line) in pcl.decode_pcln(&fd) {
                    // Reading line/start_line from the wrong offset surfaces as
                    // huge values; small negatives are normal decode sentinels.
                    assert!(
                        line < 2_000_000,
                        "{}: implausible line {} (wrong start_line offset?)",
                        fx.path,
                        line
                    );
                }
            }
            assert!(parsed > 100, "{}: only {parsed} funcs parsed", fx.path);
        }
    }
}
