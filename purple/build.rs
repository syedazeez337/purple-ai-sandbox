fn main() {
    // Build the eBPF programs from the ebpf-probes crate
    println!("cargo:rerun-if-changed=../ebpf-probes/src/syscall.bpf.rs");
    println!("cargo:rerun-if-changed=../ebpf-probes/src/file.bpf.rs");
    println!("cargo:rerun-if-changed=../ebpf-probes/src/network.bpf.rs");
    println!("cargo:rerun-if-changed=../ebpf-probes/Cargo.toml");

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
        for bin_name in &["syscall", "file_access", "network"] {
            let status = Command::new("rustup")
                .args([
                    "run",
                    "nightly",
                    "cargo",
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
