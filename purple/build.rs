fn main() {
    // Build the eBPF programs from the ebpf-probes crate
    println!("cargo:rerun-if-changed=../ebpf-probes/src/syscall.bpf.rs");
    println!("cargo:rerun-if-changed=../ebpf-probes/src/file.bpf.rs");
    println!("cargo:rerun-if-changed=../ebpf-probes/src/network.bpf.rs");
    println!("cargo:rerun-if-changed=../ebpf-probes/Cargo.toml");

    // Generate syscall table from kernel headers
    generate_syscall_table();

    #[cfg(feature = "ebpf")]
    {
        use std::path::PathBuf;
        use std::process::Command;

        // Get paths
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let ebpf_dir = PathBuf::from(&manifest_dir).join("../ebpf-probes");
        let ebpf_manifest = ebpf_dir.join("Cargo.toml");
        let out_dir = std::env::var("OUT_DIR").unwrap();
        let target_dir = PathBuf::from(&out_dir).join("ebpf-target");

        println!("cargo:warning=Building eBPF programs from {:?}", ebpf_dir);
        println!("cargo:warning=eBPF output directory: {:?}", target_dir);

        // Build each eBPF binary
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
        for bin_name in &["syscall", "file_access", "network", "network_filter"] {
            let status = Command::new(&cargo)
                .args([
                    "build",
                    "--manifest-path",
                    ebpf_manifest.to_str().unwrap(),
                    "-Z",
                    "build-std=core",
                    "--target",
                    "bpfel-unknown-none",
                    "--release",
                    "--bin",
                    bin_name,
                    "--target-dir",
                    target_dir.to_str().unwrap(),
                ])
                .env_remove("RUSTC")
                .env_remove("RUSTC_WORKSPACE_WRAPPER")
                .env(
                    "CARGO_ENCODED_RUSTFLAGS",
                    "--cfg=bpf_target_arch=\"x86_64\"",
                )
                .status()
                .expect("Failed to execute cargo build for eBPF");

            if !status.success() {
                panic!("Failed to build eBPF binary: {}", bin_name);
            }
        }

        // Output the path where the compiled eBPF programs are
        let ebpf_output = target_dir.join("bpfel-unknown-none/release");
        println!(
            "cargo:rustc-env=EBPF_PROGRAMS_DIR={}",
            ebpf_output.display()
        );
    }
}

fn generate_syscall_table() {
    use std::env;
    use std::fs;
    use std::path::PathBuf;

    let target_arch = if env::var("CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU").is_ok() {
        "x86_64"
    } else if let Ok(arch) = env::var("CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU") {
        if arch == "aarch64" {
            "aarch64"
        } else {
            "x86_64"
        }
    } else if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        eprintln!("cargo:warning=Unknown target architecture, defaulting to x86_64");
        "x86_64"
    };

    println!(
        "cargo:warning=Generating syscall table for architecture: {}",
        target_arch
    );

    // Find the syscall header
    let header_paths: Vec<&str> = match target_arch {
        "x86_64" => vec![
            "/usr/include/asm/unistd_64.h",
            "/usr/include/asm/unistd.h",
            "/usr/include/x86_64-linux-gnu/asm/unistd_64.h",
        ],
        "aarch64" => vec![
            "/usr/include/asm/unistd.h",
            "/usr/include/aarch64-linux-gnu/asm/unistd.h",
        ],
        _ => {
            eprintln!("cargo:warning=Unsupported architecture: {}", target_arch);
            return;
        }
    };

    let mut syscall_definitions = Vec::new();
    let mut header_found = false;

    for header_path in &header_paths {
        println!("cargo:rerun-if-changed={}", header_path);
        if let Ok(content) = fs::read_to_string(header_path) {
            header_found = true;
            parse_syscall_header(&content, &mut syscall_definitions);
            break;
        }
    }

    if !header_found {
        eprintln!(
            "cargo:error=Could not find syscall header for {} architecture",
            target_arch
        );
        eprintln!("cargo:error=Searched paths: {:?}", header_paths);
        // Generate an empty table - the build will fail with a clearer error later
    }

    // Add newer syscalls that might be in separate headers
    add_newer_syscalls(&mut syscall_definitions);

    // Sort and deduplicate by syscall name
    syscall_definitions.sort_by_key(|(name, _)| name.clone());
    syscall_definitions.dedup_by_key(|(name, _)| name.clone());

    // Generate the Rust source file
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let syscall_table_path = out_dir.join("syscall_table.rs");

    let content = generate_syscall_table_rs(&syscall_definitions, target_arch);

    if let Err(e) = fs::write(&syscall_table_path, content) {
        eprintln!("cargo:error=Failed to write syscall table: {}", e);
    }

    println!(
        "cargo:warning=Generated syscall table with {} syscalls",
        syscall_definitions.len()
    );
}

fn parse_syscall_header(content: &str, syscalls: &mut Vec<(String, i64)>) {
    for line in content.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("#define") {
            continue;
        }

        let after_define = &trimmed[7..].trim();
        if !after_define.starts_with("__NR_") {
            continue;
        }

        // Find where the name ends (space after name)
        let name_end = match after_define.find(|c: char| c.is_ascii_whitespace()) {
            Some(pos) => pos,
            None => continue,
        };

        let name = &after_define[5..name_end]; // Skip __NR_ prefix
        let value_str = after_define[name_end..].trim();

        if let Ok(num) = value_str.parse::<i64>() {
            // Normalize syscall name: remove any trailing spaces or comments
            let clean_name = name.split_whitespace().next().unwrap_or(name);
            if !clean_name.is_empty() {
                syscalls.push((clean_name.to_string(), num));
            }
        }
    }
}

fn add_newer_syscalls(syscalls: &mut Vec<(String, i64)>) {
    // Newer syscalls that might not be in all kernel headers
    // These are added to ensure completeness across different kernel versions
    let newer = [
        ("pidfd_send_signal", 424),
        ("io_uring_setup", 425),
        ("io_uring_enter", 426),
        ("io_uring_register", 427),
        ("open_tree", 428),
        ("move_mount", 429),
        ("fsopen", 430),
        ("fsconfig", 431),
        ("fsmount", 432),
        ("fspick", 433),
        ("pidfd_open", 434),
        ("clone3", 435),
        ("close_range", 436),
        ("openat2", 437),
        ("pidfd_getfd", 438),
        ("faccessat2", 439),
        ("process_madvise", 440),
        ("epoll_pwait2", 441),
        ("mount_setattr", 442),
        ("quotactl_fd", 443),
        ("landlock_create_ruleset", 444),
        ("landlock_add_rule", 445),
        ("landlock_restrict_self", 446),
        ("memfd_secret", 447),
        ("process_mrelease", 448),
        ("futex_waitv", 449),
        ("set_mempolicy_home_node", 450),
        ("cachestat", 451),
        ("fchmodat2", 452),
        ("map_shadow_stack", 453),
        ("futex_wake", 454),
        ("futex_wait", 455),
        ("futex_requeue", 456),
        ("statmount", 457),
        ("listmount", 458),
        ("lsm_get_self_attr", 459),
        ("lsm_set_self_attr", 460),
        ("lsm_list_modules", 461),
        ("mseal", 462),
        ("setxattrat", 463),
        ("getxattrat", 464),
        ("listxattrat", 465),
        ("removexattrat", 466),
        ("open_tree_attr", 467),
        ("file_getattr", 468),
        ("file_setattr", 469),
    ];

    for (name, num) in newer {
        if !syscalls.iter().any(|(n, _)| n == name) {
            syscalls.push((name.to_string(), num));
        }
    }
}

fn generate_syscall_table_rs(syscalls: &[(String, i64)], arch: &str) -> String {
    let mut output = String::new();

    output.push_str(&format!("// Auto-generated syscall table for {}\n", arch));
    output.push_str("// Generated by build.rs from kernel headers - DO NOT EDIT\n\n");

    // Generate const array for binary search
    output.push_str("pub const SYSCALL_TABLE: &[(&str, i64)] = &[\n");
    for (name, num) in syscalls {
        output.push_str(&format!("    (\"{}\", {}),\n", name, num));
    }
    output.push_str("];\n");

    output
}
