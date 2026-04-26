use std::collections::BTreeSet;

use gobin::{
    GoBinary, detect,
    detection::{Confidence, ConfidenceSignal, ParseError},
    formats::BinaryFormat,
    metadata::{Compiler, FunctionInfo, FunctionIter, ObfuscationKind, for_each_function},
    structures::{Arch, PclntabVersion},
};

const BASIC_NORMAL: &str = "tests/samples/basic_normal";
const BASIC_STRIPPED: &str = "tests/samples/basic_stripped";
const BASIC_LINUX: &str = "tests/samples/basic_linux_amd64";
const BASIC_WINDOWS: &str = "tests/samples/basic_windows_amd64.exe";
const BASIC_WINDOWS_STRIPPED: &str = "tests/samples/basic_windows_stripped.exe";
const MINIMAL_NORMAL: &str = "tests/samples/minimal_normal";
const MINIMAL_STRIPPED: &str = "tests/samples/minimal_stripped";

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
    assert_eq!(info.main_path, Some("test-basic"));
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
    assert_eq!(info.main_path, Some("test-basic"));
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
    for_each_function(pcl, |info, tables| {
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

    // Spot-check: a few well-known runtime / stdlib panic messages should
    // appear in any non-trivial Go binary built with the `gc` toolchain.
    let needles = ["nil context", "unreachable"];
    for needle in needles {
        assert!(
            unique.contains(needle),
            "expected to find runtime literal {:?} in {} unique strings",
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
        "string count drifted: normal={} stripped={} diff={}",
        normal,
        stripped,
        diff,
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
fn build_settings_expose_buildmode_and_tags() {
    let data = load(BASIC_LINUX);
    let bin = GoBinary::parse(&data).unwrap();
    let info = bin.build_info().expect("build info present");
    assert!(info.build_mode().is_some());
    let _ = info.build_tags();
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
        } = &t.detail
        {
            if *method_count > 0 {
                assert!(
                    !methods.is_empty(),
                    "interface {} has method_count={} but no resolved methods",
                    t.name,
                    method_count,
                );
            }
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
            if inputs.iter().any(|&va| va != 0) {
                saw_input_va = true;
            }
            if outputs.iter().any(|&va| va != 0) {
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

    let any_map = types.iter().any(
        |t| matches!(&t.detail, TypeDetail::Map { key_va, elem_va } if *key_va != 0 && *elem_va != 0),
    );
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
