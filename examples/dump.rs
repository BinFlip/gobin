//! Complete Go binary metadata dump.
//!
//! Usage: `cargo run --example dump -- <path-to-go-binary>`
//!
//! Outputs ALL extractable metadata in a structured, grep-friendly format.
//! User code is listed first, followed by standard library, then runtime internals.

use std::collections::BTreeMap;

use gobin::{
    GoBinary,
    metadata::{FunctionInfo, extract_functions},
    structures::{
        Arch,
        types::{GoType, TypeDetail},
    },
};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <go-binary>", args[0]);
        std::process::exit(1);
    }

    let path = &args[1];
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error reading {}: {}", path, e);
            std::process::exit(1);
        }
    };

    let bin = match GoBinary::parse(&data) {
        Some(b) => b,
        None => {
            eprintln!("{}: Not a Go binary", path);
            std::process::exit(1);
        }
    };

    let pclntab = bin.pclntab();
    let funcs = pclntab.map(|p| extract_functions(p)).unwrap_or_default();
    let files: Vec<&str> = pclntab
        .map(|p| p.file_names().collect())
        .unwrap_or_default();
    let types = bin.types();

    print_header(&bin, &funcs, &files, path, data.len());
    print_build_info(&bin);
    print_functions_and_packages(&funcs, &types);
    print_source_files(&files);
}

fn print_header(
    bin: &GoBinary<'_>,
    funcs: &[FunctionInfo<'_>],
    files: &[&str],
    path: &str,
    size: usize,
) {
    println!("================================================================================");
    println!("  Go Binary Analysis: {}", path);
    println!("================================================================================");
    println!();
    println!("[Binary]");
    println!(
        "  File size    : {} bytes ({:.1} MB)",
        size,
        size as f64 / 1_048_576.0
    );
    println!("  Format       : {:?}", bin.context().format());
    println!("  Confidence   : {:?}", bin.confidence());
    println!();

    println!("[Go Toolchain]");
    println!("  Go version   : {}", bin.go_version().unwrap_or("unknown"));
    if let Some(p) = bin.pclntab() {
        println!(
            "  pclntab ver  : {:?} ({})",
            p.version,
            p.version.go_version_range()
        );
    }
    println!("  Build ID     : {}", bin.build_id().unwrap_or("none"));
    println!();

    println!("[Target]");
    if let Some(p) = bin.pclntab() {
        println!("  Architecture : {:?}", p.arch());
        println!("  Pointer size : {} bytes", p.ptr_size);
    } else {
        println!("  Architecture : {:?}", Arch::Unknown);
    }
    if let Some(info) = bin.build_info() {
        println!("  GOOS         : {}", info.goos().unwrap_or("unknown"));
        println!("  GOARCH       : {}", info.goarch().unwrap_or("unknown"));
        if let Some(cgo) = info.cgo_enabled() {
            println!(
                "  CGO          : {}",
                if cgo { "enabled" } else { "disabled" }
            );
        }
    }
    println!();

    println!("[Counts]");
    println!("  Functions    : {}", funcs.len());
    println!("  Source files : {}", files.len());
    println!();
}

fn print_build_info(bin: &GoBinary<'_>) {
    let info = match bin.build_info() {
        Some(i) => i,
        None => return,
    };

    println!("================================================================================");
    println!("  Build Info");
    println!("================================================================================");
    println!();

    if let Some(ref path) = info.main_path {
        println!("  Main path    : {}", path);
    }
    if let Some(ref module) = info.main_module {
        let ver = info.main_version.as_deref().unwrap_or("");
        println!("  Module       : {} {}", module, ver);
    }

    // VCS info
    if let Some(vcs) = info.setting("vcs") {
        print!("  VCS          : {}", vcs);
        if let Some(rev) = info.vcs_revision() {
            print!(" @ {}", rev);
        }
        if info.vcs_modified() == Some(true) {
            print!(" (dirty)");
        }
        println!();
    }
    println!();

    // Build settings
    if !info.build_settings.is_empty() {
        println!("  Build settings:");
        for (key, value) in &info.build_settings {
            if !value.is_empty() {
                println!("    {} = {}", key, value);
            } else {
                println!("    {}", key);
            }
        }
        println!();
    }

    // Dependencies
    if !info.deps.is_empty() {
        println!("  Dependencies ({}):", info.deps.len());
        for (dep, version) in &info.deps {
            println!("    {} {}", dep, version.as_deref().unwrap_or(""));
        }
        println!();
    }
}

/// Classify a package into a tier for output ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum PackageTier {
    User,
    Stdlib,
    Internal,
}

fn classify_package(pkg: &str) -> PackageTier {
    if pkg == "main" || pkg.contains('.') {
        PackageTier::User
    } else if pkg.starts_with("runtime")
        || pkg.starts_with("internal/")
        || pkg.starts_with("vendor/")
        || pkg.starts_with("type:")
        || pkg == "(unknown)"
    {
        PackageTier::Internal
    } else {
        PackageTier::Stdlib
    }
}

fn tier_label(tier: PackageTier) -> &'static str {
    match tier {
        PackageTier::User => "USER CODE",
        PackageTier::Stdlib => "STANDARD LIBRARY",
        PackageTier::Internal => "RUNTIME & INTERNAL",
    }
}

fn print_functions_and_packages(funcs: &[FunctionInfo<'_>], types: &[GoType]) {
    println!("================================================================================");
    println!("  Packages, Functions & Types");
    println!("================================================================================");
    println!();

    let mut packages: BTreeMap<String, Vec<&FunctionInfo<'_>>> = BTreeMap::new();
    for f in funcs {
        let pkg = f.package().unwrap_or("(unknown)").to_string();
        packages.entry(pkg).or_default().push(f);
    }

    let mut type_by_pkg: BTreeMap<String, Vec<&GoType>> = BTreeMap::new();
    for t in types {
        let pkg = t.package().unwrap_or("(unknown)").to_string();
        type_by_pkg.entry(pkg).or_default().push(t);
    }

    let mut all_pkgs: Vec<(PackageTier, &str)> = packages
        .keys()
        .map(|p| (classify_package(p), p.as_str()))
        .collect();
    for pkg in type_by_pkg.keys() {
        if !packages.contains_key(pkg.as_str()) {
            all_pkgs.push((classify_package(pkg), pkg.as_str()));
        }
    }
    all_pkgs.sort();
    all_pkgs.dedup();

    let mut current_tier: Option<PackageTier> = None;

    for (tier, pkg) in &all_pkgs {
        if current_tier != Some(*tier) {
            if current_tier.is_some() {
                println!();
            }
            println!("  --- {} {:-<60}", tier_label(*tier), "");
            println!();
            current_tier = Some(*tier);
        }

        let pkg_funcs = packages.get(*pkg);
        let pkg_types = type_by_pkg.get(*pkg);
        let func_count = pkg_funcs.map(|f| f.len()).unwrap_or(0);
        let type_count = pkg_types.map(|t| t.len()).unwrap_or(0);

        print!("  [{}]", pkg);
        if func_count > 0 {
            print!("  {} functions", func_count);
        }
        if type_count > 0 {
            print!("  {} types", type_count);
        }
        println!();

        if let Some(pkg_types) = pkg_types {
            for t in pkg_types {
                let mut tags = Vec::new();
                tags.push(format!("{}", t.kind));
                tags.push(format!("size:{}", t.size));
                tags.push(format!("align:{}", t.align));
                if t.field_align != t.align {
                    tags.push(format!("field_align:{}", t.field_align));
                }
                if t.ptr_bytes > 0 {
                    tags.push(format!("ptrbytes:{}", t.ptr_bytes));
                }
                tags.push(format!("hash:0x{:08x}", t.hash));
                match &t.detail {
                    TypeDetail::Array { len } => tags.push(format!("len:{}", len)),
                    TypeDetail::Chan { dir } => {
                        let d = match dir {
                            1 => "<-chan",
                            2 => "chan<-",
                            _ => "chan",
                        };
                        tags.push(format!("dir:{}", d));
                    }
                    TypeDetail::Func {
                        in_count,
                        out_count,
                        is_variadic,
                    } => {
                        tags.push(format!("in:{}", in_count));
                        tags.push(format!("out:{}", out_count));
                        if *is_variadic {
                            tags.push("variadic".into());
                        }
                    }
                    TypeDetail::Interface { method_count } => {
                        tags.push(format!("iface_methods:{}", method_count));
                    }
                    TypeDetail::Map => {}
                    TypeDetail::Struct { field_count } => {
                        tags.push(format!("fields:{}", field_count));
                    }
                    TypeDetail::None => {}
                }
                if t.method_count > 0 {
                    if t.exported_method_count == t.method_count {
                        tags.push(format!("methods:{}", t.method_count));
                    } else {
                        tags.push(format!(
                            "methods:{}/{}exported",
                            t.method_count, t.exported_method_count
                        ));
                    }
                }
                if t.is_named {
                    tags.push("named".into());
                }
                println!("    type {}  [{}]", t.name, tags.join(", "));
            }
        }

        if let Some(pkg_funcs) = pkg_funcs {
            let mut sorted: Vec<&&FunctionInfo<'_>> = pkg_funcs.iter().collect();
            sorted.sort_by(|a, b| {
                let a_closure = a.is_closure();
                let b_closure = b.is_closure();
                let a_method = a.is_method();
                let b_method = b.is_method();
                match (a_method, b_method) {
                    (true, false) if !b_closure => return std::cmp::Ordering::Less,
                    (false, true) if !a_closure => return std::cmp::Ordering::Greater,
                    _ => {}
                }
                match (a_closure, b_closure) {
                    (true, false) => return std::cmp::Ordering::Greater,
                    (false, true) => return std::cmp::Ordering::Less,
                    _ => {}
                }
                a.name.cmp(&b.name)
            });

            for f in sorted {
                let mut tags = Vec::new();
                if f.start_line > 0 {
                    if f.end_line > f.start_line {
                        tags.push(format!("lines:{}-{}", f.start_line, f.end_line));
                    } else {
                        tags.push(format!("line:{}", f.start_line));
                    }
                }
                tags.push(format!("addr:0x{:x}", f.entry_offset));
                if f.args_size > 0 {
                    tags.push(format!("args:{}B", f.args_size));
                }
                if f.frame_size > 0 {
                    tags.push(format!("frame:{}B", f.frame_size));
                }
                if f.uses_defer() {
                    tags.push(format!("defer:0x{:x}", f.deferreturn));
                }
                if f.nfuncdata > 0 {
                    tags.push(format!("funcdata:{}", f.nfuncdata));
                }
                if f.npcdata > 0 {
                    tags.push(format!("pcdata:{}", f.npcdata));
                }
                if let Some(id_name) = f.func_id_name() {
                    tags.push(format!("funcID:{}", id_name));
                }
                if f.flags != 0 {
                    let mut flag_parts = Vec::new();
                    if f.flags & 0x01 != 0 {
                        flag_parts.push("TopFrame");
                    }
                    if f.flags & 0x02 != 0 {
                        flag_parts.push("SPWrite");
                    }
                    if f.flags & 0x04 != 0 {
                        flag_parts.push("Asm");
                    }
                    if !flag_parts.is_empty() {
                        tags.push(flag_parts.join("|"));
                    }
                }

                let tag_str = if tags.is_empty() {
                    String::new()
                } else {
                    format!("  [{}]", tags.join(", "))
                };

                let prefix = if f.is_method() {
                    "method"
                } else if f.is_closure() {
                    "closure"
                } else {
                    "func"
                };

                println!("    {} {}{}", prefix, f.short_name(), tag_str);
                if let Some(src) = f.source_file {
                    if *tier == PackageTier::User {
                        println!("           src: {}", src);
                    }
                }
            }
        }

        println!();
    }

    let user_funcs = funcs
        .iter()
        .filter(|f| classify_package(f.package().unwrap_or("")) == PackageTier::User)
        .count();
    let stdlib_funcs = funcs
        .iter()
        .filter(|f| classify_package(f.package().unwrap_or("")) == PackageTier::Stdlib)
        .count();
    let internal_funcs = funcs
        .iter()
        .filter(|f| classify_package(f.package().unwrap_or("")) == PackageTier::Internal)
        .count();
    let defer_funcs = funcs.iter().filter(|f| f.uses_defer()).count();
    let method_funcs = funcs.iter().filter(|f| f.is_method()).count();
    let closure_funcs = funcs.iter().filter(|f| f.is_closure()).count();

    println!("  --- SUMMARY {:-<65}", "");
    println!();
    println!("  Total functions : {}", funcs.len());
    println!("    User code     : {}", user_funcs);
    println!("    Stdlib        : {}", stdlib_funcs);
    println!("    Internal      : {}", internal_funcs);
    println!("  Methods         : {}", method_funcs);
    println!("  Closures        : {}", closure_funcs);
    println!("  Using defer     : {}", defer_funcs);
    println!("  Total packages  : {}", packages.len());
    println!("  Total types     : {}", types.len());
    println!();
}

fn print_source_files(files: &[&str]) {
    println!("================================================================================");
    println!("  Source Files ({})", files.len());
    println!("================================================================================");
    println!();

    let mut user_files: Vec<&&str> = Vec::new();
    let mut sdk_files: BTreeMap<String, Vec<&&str>> = BTreeMap::new();

    for f in files {
        if f.contains("/libexec/src/") || f.contains("/go/src/") || f.contains("GOROOT") {
            if let Some(src_idx) = f.rfind("/src/") {
                let after_src = &f[src_idx + 5..];
                let pkg = if let Some(last_slash) = after_src.rfind('/') {
                    &after_src[..last_slash]
                } else {
                    after_src
                };
                sdk_files.entry(pkg.to_string()).or_default().push(f);
            } else {
                sdk_files.entry("(other)".to_string()).or_default().push(f);
            }
        } else {
            user_files.push(f);
        }
    }

    if !user_files.is_empty() {
        println!("  --- USER SOURCE FILES {:-<56}", "");
        println!();
        for f in &user_files {
            println!("  {}", f);
        }
        println!();
    }

    if !sdk_files.is_empty() {
        println!(
            "  --- SDK SOURCE FILES ({} packages, {} files) {:-<33}",
            sdk_files.len(),
            sdk_files.values().map(|v| v.len()).sum::<usize>(),
            ""
        );
        println!();

        for (pkg, pkg_files) in &sdk_files {
            println!("  [{}]  ({} files)", pkg, pkg_files.len());
            for f in pkg_files {
                let basename = f.rsplit('/').next().unwrap_or(f);
                println!("    {}", basename);
            }
        }
        println!();
    }
}
