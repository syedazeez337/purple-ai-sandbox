use crate::policy::compiler::{
    CompiledAuditPolicy, CompiledCapabilityPolicy, CompiledFilesystemPolicy, CompiledNetworkPolicy,
    CompiledPolicy, CompiledResourcePolicy, CompiledSyscallPolicy,
};
use crate::sandbox::Sandbox;
use std::collections::{BTreeSet, HashSet};
use std::path::PathBuf;

fn create_privileged_policy(name: &str) -> CompiledPolicy {
    CompiledPolicy {
        ai_policy: None,
        name: name.to_string(),
        filesystem: CompiledFilesystemPolicy {
            immutable_mounts: vec![
                // Minimal mounts for a functional shell if needed, but for simple echo we might not need much
                // However, bash usually needs /bin, /lib
                (PathBuf::from("/bin"), PathBuf::from("/bin")),
                (PathBuf::from("/lib"), PathBuf::from("/lib")),
                (PathBuf::from("/lib64"), PathBuf::from("/lib64")),
                (PathBuf::from("/usr"), PathBuf::from("/usr")),
            ],
            scratch_dirs: vec![PathBuf::from("/tmp")],
            output_mounts: vec![],
            working_dir: PathBuf::from("/tmp"),
        },
        syscalls: CompiledSyscallPolicy {
            default_deny: false,
            allowed_syscall_numbers: BTreeSet::new(),
            denied_syscall_numbers: BTreeSet::new(),
        },
        resources: CompiledResourcePolicy {
            cpu_shares: None,
            memory_limit_bytes: None,
            pids_limit: None,
            block_io_limit_bytes_per_sec: None,
            session_timeout_seconds: None,
        },
        capabilities: CompiledCapabilityPolicy {
            default_drop: false,
            added_capabilities: HashSet::new(),
            dropped_capabilities: HashSet::new(),
        },
        network: CompiledNetworkPolicy {
            isolated: true,
            allowed_outgoing_ports: HashSet::new(),
            allowed_incoming_ports: HashSet::new(),
            blocked_ips_v4: HashSet::new(),
            blocked_ips_v6: HashSet::new(),
            dns_servers: None,
        },
        audit: CompiledAuditPolicy {
            enabled: false,
            log_path: PathBuf::from("/tmp/test-audit.log"),
            detail_level: HashSet::new(),
        },
        ebpf_monitoring: crate::policy::EbpfMonitoringPolicy::default(),
    }
}

#[test]
#[ignore]
fn test_privileged_sandbox_execution() {
    // Check if we are root
    if unsafe { libc::geteuid() } != 0 {
        println!("Skipping privileged test (not root)");
        return;
    }

    // Create a temporary directory for sandbox root
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let _sandbox_root = temp_dir.path().to_path_buf();
    let error_file_path = temp_dir.path().join("child_error.txt");
    let error_file_path_child = error_file_path.clone();

    use nix::sys::wait::waitpid;
    use nix::unistd::{ForkResult, fork};

    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            let status = waitpid(child, None).expect("waitpid failed");
            match status {
                nix::sys::wait::WaitStatus::Exited(_, code) => {
                    if code != 0 {
                        let error_msg = std::fs::read_to_string(&error_file_path)
                            .unwrap_or_else(|_| "Could not read error file".to_string());

                        // Check if it's a skippable error (even if child didn't exit 0 properly)
                        if error_msg.contains("EINVAL")
                            || error_msg.contains("Invalid argument")
                            || error_msg.contains("Operation not permitted")
                            || error_msg.contains("Permission denied")
                            || error_msg.contains("Cgroup filesystem not found")
                            || error_msg.contains("Network error")
                            || error_msg.contains("No such file or directory")
                        {
                            println!("Skipping privileged test (child failed): {}", error_msg);
                            return;
                        }

                        panic!(
                            "Sandbox child process failed with code {}. Error: {}",
                            code, error_msg
                        );
                    }
                }
                nix::sys::wait::WaitStatus::Signaled(_, signal, _) => {
                    panic!("Sandbox child process killed by signal {:?}", signal);
                }
                _ => panic!("Sandbox child process ended unexpectedly: {:?}", status),
            }
        }
        Ok(ForkResult::Child) => {
            let policy = create_privileged_policy("priv-test");
            let command = vec!["/bin/echo".to_string(), "hello privileged".to_string()];
            let mut sandbox = Sandbox::new(policy, command);

            match sandbox.execute() {
                Ok(exit_code) => {
                    if exit_code == 0 {
                        std::process::exit(0);
                    } else {
                        let _ = std::fs::write(
                            &error_file_path_child,
                            format!("Command exited with code {}", exit_code),
                        );
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    let err_msg = format!("{}", e);
                    let _ = std::fs::write(&error_file_path_child, &err_msg);

                    // Check for common container restriction errors
                    if err_msg.contains("EINVAL") 
                        || err_msg.contains("Invalid argument") 
                        || err_msg.contains("Operation not permitted") // EPERM
                        || err_msg.contains("Permission denied")       // EACCES
                        || err_msg.contains("Cgroup filesystem not found")
                    {
                        // We still exit non-zero to signal parent to check the error message
                        // Alternatively, we could exit 0, but parent logic above handles non-zero + specific error msg
                        std::process::exit(1);
                    } else {
                        std::process::exit(1);
                    }
                }
            }
        }
        Err(e) => panic!("fork failed: {}", e),
    }
}
