use std::collections::BTreeSet;

use gobin::{
    GoBinary,
    detection::Confidence,
    formats::BinaryFormat,
    metadata::{FunctionInfo, extract_functions},
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
    assert_eq!(info.main_path.as_deref(), Some("test-basic"));
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
    assert_eq!(info.main_path.as_deref(), Some("test-basic"));
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
    let names: Vec<&str> = extract_functions(bin.pclntab().unwrap())
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
    let names: Vec<&str> = extract_functions(bin.pclntab().unwrap())
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
    let names: Vec<&str> = extract_functions(bin.pclntab().unwrap())
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
    let names: Vec<&str> = extract_functions(bin.pclntab().unwrap())
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
    let funcs = extract_functions(bin.pclntab().unwrap());
    let pkgs: BTreeSet<&str> = funcs.iter().filter_map(|f| f.package()).collect();
    assert!(pkgs.contains("main"));
    assert!(pkgs.contains("runtime"));
    assert!(pkgs.contains("fmt"));
}

#[test]
fn packages_pe() {
    let data = load(BASIC_WINDOWS);
    let bin = GoBinary::parse(&data).unwrap();
    let funcs = extract_functions(bin.pclntab().unwrap());
    let pkgs: BTreeSet<&str> = funcs.iter().filter_map(|f| f.package()).collect();
    assert!(pkgs.contains("main"), "PE should have main package");
    assert!(pkgs.contains("runtime"), "PE should have runtime package");
}

#[test]
fn types_macho() {
    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();
    let types = bin.types();
    assert!(!types.is_empty(), "Should extract types from Mach-O");
}

#[test]
fn types_elf() {
    let data = load(BASIC_LINUX);
    let bin = GoBinary::parse(&data).unwrap();
    let types = bin.types();
    assert!(!types.is_empty(), "Should extract types from ELF");
}

#[test]
fn types_pe() {
    let data = load(BASIC_WINDOWS);
    let bin = GoBinary::parse(&data).unwrap();
    let types = bin.types();
    assert!(!types.is_empty(), "Should extract types from PE");
}

#[test]
fn function_info_metadata() {
    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();
    let funcs = extract_functions(bin.pclntab().unwrap());

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
    let funcs = extract_functions(bin.pclntab().unwrap());

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
    let funcs = extract_functions(bin.pclntab().unwrap());

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
        let funcs = extract_functions(bin.pclntab().unwrap());
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
        name: "net/http.(*Client).Do".into(),
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
        name: "main.main.func1".into(),
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
        name: "runtime.goexit".into(),
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
        name: "main.main".into(),
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
    let funcs = extract_functions(bin.pclntab().unwrap());

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
    let funcs = extract_functions(bin.pclntab().unwrap());

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
    let funcs = extract_functions(bin.pclntab().unwrap());

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
fn type_details_present() {
    use gobin::structures::types::TypeDetail;

    let data = load(BASIC_NORMAL);
    let bin = GoBinary::parse(&data).unwrap();
    let types = bin.types();

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
