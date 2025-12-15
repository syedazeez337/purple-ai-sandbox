// purple/src/policy/compiler.rs

use super::Policy;
use std::collections::{HashSet, BTreeSet};
use std::path::PathBuf;

/// A strict, internal representation of a policy, directly consumable by the sandbox.
#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    pub name: String,
    pub filesystem: CompiledFilesystemPolicy,
    pub syscalls: CompiledSyscallPolicy,
    pub resources: CompiledResourcePolicy,
    pub capabilities: CompiledCapabilityPolicy,
    pub network: CompiledNetworkPolicy,
    pub audit: CompiledAuditPolicy,
}

/// Compiled filesystem rules.
#[derive(Debug, Clone)]
pub struct CompiledFilesystemPolicy {
    // These will likely become more complex, e.g., `Vec<MountConfig>`
    pub immutable_mounts: Vec<(PathBuf, PathBuf)>, // (host_path, sandbox_path)
    pub scratch_dirs: Vec<PathBuf>, // Paths *within* the sandbox
    pub output_mounts: Vec<(PathBuf, PathBuf)>, // (host_path, sandbox_path)
    pub working_dir: PathBuf,
}

/// Compiled syscall rules. Uses `BTreeSet` for efficient checking and ordering.
#[derive(Debug, Clone)]
pub struct CompiledSyscallPolicy {
    pub default_deny: bool,
    pub allowed_syscall_numbers: BTreeSet<i64>,
}

/// Compiled resource limits.
#[derive(Debug, Clone)]
pub struct CompiledResourcePolicy {
    pub cpu_shares: Option<f64>,
    pub memory_limit_bytes: Option<u64>, // Parsed into bytes
    pub pids_limit: Option<u64>,
    pub block_io_limit_bytes_per_sec: Option<u64>, // Parsed into bytes/sec
    pub session_timeout_seconds: Option<u64>,
}

/// Compiled capability rules.
#[derive(Debug, Clone)]
pub struct CompiledCapabilityPolicy {
    pub default_drop: bool,
    pub added_capabilities: HashSet<String>, // Linux capability names (e.g., "CAP_NET_RAW")
}

/// Compiled network rules.
#[derive(Debug, Clone)]
pub struct CompiledNetworkPolicy {
    pub isolated: bool,
    pub allowed_outgoing_ports: HashSet<u16>, // e.g., 443, 53
    pub allowed_incoming_ports: HashSet<u16>,
}

/// Compiled audit rules.
#[derive(Debug, Clone)]
pub struct CompiledAuditPolicy {
    pub enabled: bool,
    pub log_path: PathBuf,
    pub detail_level: HashSet<String>,
}

impl Policy {
    /// Compiles a declarative Policy into a strict, internal CompiledPolicy.
    pub fn compile(&self) -> Result<CompiledPolicy, String> {
        // --- Filesystem Compilation ---
        let compiled_filesystem = CompiledFilesystemPolicy {
            immutable_mounts: self.filesystem.immutable_paths.iter()
                .map(|pm| (pm.host_path.clone(), pm.sandbox_path.clone()))
                .collect(),
            scratch_dirs: self.filesystem.scratch_paths.clone(),
            output_mounts: self.filesystem.output_paths.iter()
                .map(|pm| (pm.host_path.clone(), pm.sandbox_path.clone()))
                .collect(),
            working_dir: self.filesystem.working_dir.clone(),
        };

        // --- Syscall Compilation ---
        // TODO: Map string syscall names to actual Linux syscall numbers
        // This is a placeholder and needs a robust mapping.
        let mut allowed_syscall_numbers = BTreeSet::new();
        for sname in &self.syscalls.allow {
            // For now, just a dummy mapping or direct number if policy specifies it
            // In a real system, this would use a `syscall_names_to_numbers` map
            match sname.as_str() {
                "read" => { allowed_syscall_numbers.insert(0); } // __NR_read
                "write" => { allowed_syscall_numbers.insert(1); } // __NR_write
                "openat" => { allowed_syscall_numbers.insert(257); } // __NR_openat
                "close" => { allowed_syscall_numbers.insert(3); } // __NR_close
                "fstat" => { allowed_syscall_numbers.insert(5); } // __NR_fstat
                "newfstatat" => { allowed_syscall_numbers.insert(262); } // __NR_newfstatat
                "mmap" => { allowed_syscall_numbers.insert(9); } // __NR_mmap
                "mprotect" => { allowed_syscall_numbers.insert(10); } // __NR_mprotect
                "munmap" => { allowed_syscall_numbers.insert(11); } // __NR_munmap
                "brk" => { allowed_syscall_numbers.insert(12); } // __NR_brk
                "access" => { allowed_syscall_numbers.insert(21); } // __NR_access
                "execve" => { allowed_syscall_numbers.insert(59); } // __NR_execve
                "arch_prctl" => { allowed_syscall_numbers.insert(158); } // __NR_arch_prctl
                "set_tid_address" => { allowed_syscall_numbers.insert(178); } // __NR_set_tid_address
                "set_robust_list" => { allowed_syscall_numbers.insert(179); } // __NR_set_robust_list
                "rseq" => { allowed_syscall_numbers.insert(293); } // __NR_rseq
                "prlimit64" => { allowed_syscall_numbers.insert(261); } // __NR_prlimit64
                "getrandom" => { allowed_syscall_numbers.insert(318); } // __NR_getrandom
                "exit_group" => { allowed_syscall_numbers.insert(231); } // __NR_exit_group
                "clone3" => { allowed_syscall_numbers.insert(435); } // __NR_clone3
                _ => return Err(format!("Unknown syscall: {}", sname)),
            }
        }
        // Deny overrides allow - not strictly necessary with default_deny=true,
        // but good for explicit overriding.
        for sname in &self.syscalls.deny {
             match sname.as_str() {
                "mount" => { allowed_syscall_numbers.remove(&165); }
                "unmount" => { allowed_syscall_numbers.remove(&166); }
                "reboot" => { allowed_syscall_numbers.remove(&169); }
                "kexec_load" => { allowed_syscall_numbers.remove(&283); }
                "bpf" => { allowed_syscall_numbers.remove(&321); }
                "unlinkat" => { allowed_syscall_numbers.remove(&263); }
                "renameat2" => { allowed_syscall_numbers.remove(&316); }
                _ => return Err(format!("Unknown syscall to deny: {}", sname)),
            }
        }

        let compiled_syscalls = CompiledSyscallPolicy {
            default_deny: self.syscalls.default_deny,
            allowed_syscall_numbers,
        };

        // --- Resource Compilation ---
        let memory_limit_bytes = if let Some(mem_str) = &self.resources.memory_limit_bytes {
            // Simple parsing for "2G", "512M". More robust parsing might be needed.
            if mem_str.ends_with("G") {
                mem_str[..mem_str.len() - 1].parse::<u64>().ok().map(|g| g * 1024 * 1024 * 1024)
            } else if mem_str.ends_with("M") {
                mem_str[..mem_str.len() - 1].parse::<u64>().ok().map(|m| m * 1024 * 1024)
            } else {
                mem_str.parse::<u64>().ok()
            }
        } else {
            None
        };
        let block_io_limit_bytes_per_sec = if let Some(io_str) = &self.resources.block_io_limit {
            // Placeholder, needs proper parsing (e.g., "100MBps")
            // For now, just a dummy value if string contains "MBps"
            if io_str.ends_with("MBps") {
                io_str[..io_str.len() - 4].parse::<u64>().ok().map(|mb| mb * 1024 * 1024)
            } else {
                None
            }
        } else {
            None
        };

        let compiled_resources = CompiledResourcePolicy {
            cpu_shares: self.resources.cpu_shares,
            memory_limit_bytes,
            pids_limit: self.resources.pids_limit,
            block_io_limit_bytes_per_sec,
            session_timeout_seconds: self.resources.session_timeout_seconds,
        };

        // --- Capability Compilation ---
        let compiled_capabilities = CompiledCapabilityPolicy {
            default_drop: self.capabilities.default_drop,
            added_capabilities: self.capabilities.add.iter().cloned().collect(),
        };

        // --- Network Compilation ---
        let mut allowed_outgoing_ports = HashSet::new();
        for port_str in &self.network.allow_outgoing {
            if let Ok(port) = port_str.parse::<u16>() {
                allowed_outgoing_ports.insert(port);
            } else {
                // For now, only simple port numbers are supported.
                // More complex rules like "8.8.8.8:53" would need a more sophisticated parser.
                eprintln!("Warning: Skipping invalid outgoing network rule: {}", port_str);
            }
        }
        let mut allowed_incoming_ports = HashSet::new();
        for port_str in &self.network.allow_incoming {
            if let Ok(port) = port_str.parse::<u16>() {
                allowed_incoming_ports.insert(port);
            } else {
                eprintln!("Warning: Skipping invalid incoming network rule: {}", port_str);
            }
        }
        let compiled_network = CompiledNetworkPolicy {
            isolated: self.network.isolated,
            allowed_outgoing_ports,
            allowed_incoming_ports,
        };

        // --- Audit Compilation ---
        let compiled_audit = CompiledAuditPolicy {
            enabled: self.audit.enabled,
            log_path: self.audit.log_path.clone(),
            detail_level: self.audit.detail_level.iter().cloned().collect(),
        };


        Ok(CompiledPolicy {
            name: self.name.clone(),
            filesystem: compiled_filesystem,
            syscalls: compiled_syscalls,
            resources: compiled_resources,
            capabilities: compiled_capabilities,
            network: compiled_network,
            audit: compiled_audit,
        })
    }
}

// TODO: Add a more comprehensive syscall name to number mapping.
// This might involve reading /usr/include/asm/unistd_64.h or using a crate like `syscalls` or `libseccomp` bindings.
