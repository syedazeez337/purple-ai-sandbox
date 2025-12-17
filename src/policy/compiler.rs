// purple/src/policy/compiler.rs

use super::Policy;
use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};

/// List of sensitive system paths that should never be exposed to sandboxes
const FORBIDDEN_HOST_PATHS: &[&str] = &[
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/sudoers.d",
    "/root",
    "/boot",
    "/proc",
    "/sys",
    "/dev",
];

/// Prefixes that are forbidden for host path bindings (sensitive areas)
const FORBIDDEN_HOST_PREFIXES: &[&str] = &[
    "/etc/ssh",
    "/etc/ssl/private",
    "/var/lib/private",
    "/home/", // Protect all user home directories by default
    "/root/",
];

/// Validates a path for security issues
/// Returns Ok(normalized_path) or Err(description of security issue)
fn validate_path(path: &Path, path_type: &str, is_host_path: bool) -> Result<PathBuf, String> {
    let path_str = path.to_string_lossy();

    // Check for path traversal sequences
    if path_str.contains("..") {
        return Err(format!(
            "Path traversal detected in {}: '{}'. Paths containing '..' are not allowed.",
            path_type, path_str
        ));
    }

    // Check for relative paths (all paths must be absolute)
    if !path.is_absolute() {
        return Err(format!(
            "Relative path detected in {}: '{}'. All paths must be absolute.",
            path_type, path_str
        ));
    }

    // Check for null bytes (potential injection)
    if path_str.contains('\0') {
        return Err(format!(
            "Null byte detected in {}: path contains invalid characters.",
            path_type
        ));
    }

    // Additional checks for host paths (paths on the actual system)
    if is_host_path {
        // Check against forbidden paths
        for forbidden in FORBIDDEN_HOST_PATHS {
            if path_str == *forbidden || path_str.starts_with(&format!("{}/", forbidden)) {
                return Err(format!(
                    "Forbidden path in {}: '{}'. Access to '{}' is not allowed for security reasons.",
                    path_type, path_str, forbidden
                ));
            }
        }

        // Check against forbidden prefixes
        for prefix in FORBIDDEN_HOST_PREFIXES {
            if path_str.starts_with(prefix) {
                return Err(format!(
                    "Forbidden path prefix in {}: '{}'. Paths starting with '{}' are not allowed.",
                    path_type, path_str, prefix
                ));
            }
        }
    }

    // Normalize the path (remove redundant separators, resolve . components)
    // Note: We can't use canonicalize() here as the path might not exist yet
    let mut normalized = PathBuf::new();
    for component in path.components() {
        use std::path::Component;
        match component {
            Component::RootDir => normalized.push("/"),
            Component::Normal(c) => normalized.push(c),
            Component::CurDir => {} // Skip "."
            Component::ParentDir => {
                // This shouldn't happen due to earlier check, but be defensive
                return Err(format!(
                    "Path traversal detected in {}: cannot use parent directory references.",
                    path_type
                ));
            }
            Component::Prefix(_) => {} // Windows-only, skip
        }
    }

    Ok(normalized)
}

/// Validates a sandbox-internal path (less restrictive than host paths)
fn validate_sandbox_path(path: &Path, path_type: &str) -> Result<PathBuf, String> {
    validate_path(path, path_type, false)
}

/// Parses a memory size string (e.g., "2G", "512M", "1073741824") into bytes
/// Returns an error for invalid formats instead of silently failing
fn parse_memory_size(size_str: &str) -> Result<u64, String> {
    let size_str = size_str.trim();

    if size_str.is_empty() {
        return Err("empty value".to_string());
    }

    // Try parsing with suffix
    if let Some(num_str) = size_str.strip_suffix('G') {
        let num: u64 = num_str
            .parse()
            .map_err(|_| format!("invalid number '{}' before 'G' suffix", num_str))?;
        return Ok(num * 1024 * 1024 * 1024);
    }

    if let Some(num_str) = size_str.strip_suffix("GB") {
        let num: u64 = num_str
            .parse()
            .map_err(|_| format!("invalid number '{}' before 'GB' suffix", num_str))?;
        return Ok(num * 1024 * 1024 * 1024);
    }

    if let Some(num_str) = size_str.strip_suffix('M') {
        let num: u64 = num_str
            .parse()
            .map_err(|_| format!("invalid number '{}' before 'M' suffix", num_str))?;
        return Ok(num * 1024 * 1024);
    }

    if let Some(num_str) = size_str.strip_suffix("MB") {
        let num: u64 = num_str
            .parse()
            .map_err(|_| format!("invalid number '{}' before 'MB' suffix", num_str))?;
        return Ok(num * 1024 * 1024);
    }

    if let Some(num_str) = size_str.strip_suffix('K') {
        let num: u64 = num_str
            .parse()
            .map_err(|_| format!("invalid number '{}' before 'K' suffix", num_str))?;
        return Ok(num * 1024);
    }

    if let Some(num_str) = size_str.strip_suffix("KB") {
        let num: u64 = num_str
            .parse()
            .map_err(|_| format!("invalid number '{}' before 'KB' suffix", num_str))?;
        return Ok(num * 1024);
    }

    // Try parsing as raw bytes
    size_str.parse::<u64>()
        .map_err(|_| "expected format: <number>G, <number>M, <number>K, or raw bytes (e.g., '2G', '512M', '1073741824')".to_string())
}

/// Parses an I/O rate string (e.g., "100MBps", "1GBps") into bytes per second
/// Returns an error for invalid formats instead of silently failing
fn parse_io_rate(rate_str: &str) -> Result<u64, String> {
    let rate_str = rate_str.trim();

    if rate_str.is_empty() {
        return Err("empty value".to_string());
    }

    if let Some(num_str) = rate_str.strip_suffix("GBps") {
        let num: u64 = num_str
            .parse()
            .map_err(|_| format!("invalid number '{}' before 'GBps' suffix", num_str))?;
        return Ok(num * 1024 * 1024 * 1024);
    }

    if let Some(num_str) = rate_str.strip_suffix("MBps") {
        let num: u64 = num_str
            .parse()
            .map_err(|_| format!("invalid number '{}' before 'MBps' suffix", num_str))?;
        return Ok(num * 1024 * 1024);
    }

    if let Some(num_str) = rate_str.strip_suffix("KBps") {
        let num: u64 = num_str
            .parse()
            .map_err(|_| format!("invalid number '{}' before 'KBps' suffix", num_str))?;
        return Ok(num * 1024);
    }

    if let Some(num_str) = rate_str.strip_suffix("Bps") {
        let num: u64 = num_str
            .parse()
            .map_err(|_| format!("invalid number '{}' before 'Bps' suffix", num_str))?;
        return Ok(num);
    }

    // Try parsing as raw bytes per second
    rate_str.parse::<u64>()
        .map_err(|_| "expected format: <number>GBps, <number>MBps, <number>KBps, or raw bytes/sec (e.g., '100MBps', '1GBps')".to_string())
}

/// Parses a port string into a valid port number (1-65535)
/// Returns an error for invalid formats or out-of-range values
fn parse_port(port_str: &str) -> Result<u16, String> {
    let port_str = port_str.trim();

    if port_str.is_empty() {
        return Err("empty value".to_string());
    }

    // Try parsing as u16 first
    match port_str.parse::<u16>() {
        Ok(port) => {
            if port == 0 {
                Err("port 0 is reserved and not allowed".to_string())
            } else {
                Ok(port)
            }
        }
        Err(_) => {
            // Check if it's a number that's too large
            if let Ok(large_port) = port_str.parse::<u64>() {
                Err(format!(
                    "port {} exceeds maximum allowed value (65535)",
                    large_port
                ))
            } else if port_str.starts_with('-') {
                Err("negative port numbers are not allowed".to_string())
            } else {
                Err("must be a valid port number (1-65535)".to_string())
            }
        }
    }
}

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
    pub scratch_dirs: Vec<PathBuf>,                // Paths *within* the sandbox
    pub output_mounts: Vec<(PathBuf, PathBuf)>,    // (host_path, sandbox_path)
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

impl CompiledResourcePolicy {
    /// Checks if any resource limits are specified in the policy.
    pub fn has_resource_limits(&self) -> bool {
        self.cpu_shares.is_some()
            || self.memory_limit_bytes.is_some()
            || self.pids_limit.is_some()
            || self.block_io_limit_bytes_per_sec.is_some()
            || self.session_timeout_seconds.is_some()
    }
}

/// Compiled capability rules.
#[derive(Debug, Clone)]
pub struct CompiledCapabilityPolicy {
    pub default_drop: bool,
    pub added_capabilities: HashSet<String>, // Linux capability names (e.g., "CAP_NET_RAW")
    pub dropped_capabilities: HashSet<String>, // Capabilities to drop when default_drop=false
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
        // --- Filesystem Compilation with Security Validation ---

        // Validate and collect immutable mounts
        let mut immutable_mounts = Vec::new();
        for (idx, pm) in self.filesystem.immutable_paths.iter().enumerate() {
            let host_path = validate_path(
                &pm.host_path,
                &format!("immutable_paths[{}].host_path", idx),
                true, // is_host_path
            )?;
            let sandbox_path = validate_sandbox_path(
                &pm.sandbox_path,
                &format!("immutable_paths[{}].sandbox_path", idx),
            )?;
            immutable_mounts.push((host_path, sandbox_path));
        }

        // Validate scratch directories (sandbox-internal only)
        let mut scratch_dirs = Vec::new();
        for (idx, scratch_path) in self.filesystem.scratch_paths.iter().enumerate() {
            let validated =
                validate_sandbox_path(scratch_path, &format!("scratch_paths[{}]", idx))?;
            scratch_dirs.push(validated);
        }

        // Validate and collect output mounts
        let mut output_mounts = Vec::new();
        for (idx, pm) in self.filesystem.output_paths.iter().enumerate() {
            let host_path = validate_path(
                &pm.host_path,
                &format!("output_paths[{}].host_path", idx),
                true, // is_host_path
            )?;
            let sandbox_path = validate_sandbox_path(
                &pm.sandbox_path,
                &format!("output_paths[{}].sandbox_path", idx),
            )?;
            output_mounts.push((host_path, sandbox_path));
        }

        // Validate working directory (sandbox-internal)
        let working_dir = validate_sandbox_path(&self.filesystem.working_dir, "working_dir")?;

        let compiled_filesystem = CompiledFilesystemPolicy {
            immutable_mounts,
            scratch_dirs,
            output_mounts,
            working_dir,
        };

        // --- Syscall Compilation ---
        // TODO: Map string syscall names to actual Linux syscall numbers
        // This is a placeholder and needs a robust mapping.
        let mut allowed_syscall_numbers = BTreeSet::new();
        for sname in &self.syscalls.allow {
            // For now, just a dummy mapping or direct number if policy specifies it
            // In a real system, this would use a `syscall_names_to_numbers` map
            match sname.as_str() {
                "read" => {
                    allowed_syscall_numbers.insert(0);
                } // __NR_read
                "write" => {
                    allowed_syscall_numbers.insert(1);
                } // __NR_write
                "openat" => {
                    allowed_syscall_numbers.insert(257);
                } // __NR_openat
                "close" => {
                    allowed_syscall_numbers.insert(3);
                } // __NR_close
                "fstat" => {
                    allowed_syscall_numbers.insert(5);
                } // __NR_fstat
                "newfstatat" => {
                    allowed_syscall_numbers.insert(262);
                } // __NR_newfstatat
                "mmap" => {
                    allowed_syscall_numbers.insert(9);
                } // __NR_mmap
                "mprotect" => {
                    allowed_syscall_numbers.insert(10);
                } // __NR_mprotect
                "munmap" => {
                    allowed_syscall_numbers.insert(11);
                } // __NR_munmap
                "brk" => {
                    allowed_syscall_numbers.insert(12);
                } // __NR_brk
                "access" => {
                    allowed_syscall_numbers.insert(21);
                } // __NR_access
                "execve" => {
                    allowed_syscall_numbers.insert(59);
                } // __NR_execve
                "arch_prctl" => {
                    allowed_syscall_numbers.insert(158);
                } // __NR_arch_prctl
                "set_tid_address" => {
                    allowed_syscall_numbers.insert(178);
                } // __NR_set_tid_address
                "set_robust_list" => {
                    allowed_syscall_numbers.insert(179);
                } // __NR_set_robust_list
                "rseq" => {
                    allowed_syscall_numbers.insert(293);
                } // __NR_rseq
                "prlimit64" => {
                    allowed_syscall_numbers.insert(261);
                } // __NR_prlimit64
                "getrandom" => {
                    allowed_syscall_numbers.insert(318);
                } // __NR_getrandom
                "exit_group" => {
                    allowed_syscall_numbers.insert(231);
                } // __NR_exit_group
                "clone3" => {
                    allowed_syscall_numbers.insert(435);
                } // __NR_clone3

                // Added for basic shell utilities (echo, ls, cat, etc.)
                "ioctl" => {
                    allowed_syscall_numbers.insert(16);
                }
                "pread64" => {
                    allowed_syscall_numbers.insert(17);
                }
                "writev" => {
                    allowed_syscall_numbers.insert(20);
                }
                "lseek" => {
                    allowed_syscall_numbers.insert(8);
                }
                // "mprotect" already handled above (10)
                "rt_sigaction" => {
                    allowed_syscall_numbers.insert(13);
                }
                "rt_sigprocmask" => {
                    allowed_syscall_numbers.insert(14);
                }
                "rt_sigreturn" => {
                    allowed_syscall_numbers.insert(15);
                }
                "pipe" => {
                    allowed_syscall_numbers.insert(22);
                }
                "fcntl" => {
                    allowed_syscall_numbers.insert(72);
                }
                "getcwd" => {
                    allowed_syscall_numbers.insert(79);
                }
                "mkdir" => {
                    allowed_syscall_numbers.insert(83);
                }
                "rmdir" => {
                    allowed_syscall_numbers.insert(84);
                }
                "unlink" => {
                    allowed_syscall_numbers.insert(87);
                }
                "getuid" => {
                    allowed_syscall_numbers.insert(102);
                }
                "getgid" => {
                    allowed_syscall_numbers.insert(104);
                }
                "geteuid" => {
                    allowed_syscall_numbers.insert(107);
                }
                "getegid" => {
                    allowed_syscall_numbers.insert(108);
                }
                "capget" => {
                    allowed_syscall_numbers.insert(125);
                }
                "capset" => {
                    allowed_syscall_numbers.insert(126);
                }
                "prctl" => {
                    allowed_syscall_numbers.insert(157);
                }
                "stat" => {
                    allowed_syscall_numbers.insert(4);
                }
                "lstat" => {
                    allowed_syscall_numbers.insert(6);
                }
                "poll" => {
                    allowed_syscall_numbers.insert(7);
                }

                _ => return Err(format!("Unknown syscall: {}", sname)),
            }
        }
        // Deny overrides allow - not strictly necessary with default_deny=true,
        // but good for explicit overriding.
        for sname in &self.syscalls.deny {
            match sname.as_str() {
                "mount" => {
                    allowed_syscall_numbers.remove(&165);
                }
                "unmount" => {
                    allowed_syscall_numbers.remove(&166);
                }
                "reboot" => {
                    allowed_syscall_numbers.remove(&169);
                }
                "kexec_load" => {
                    allowed_syscall_numbers.remove(&283);
                }
                "bpf" => {
                    allowed_syscall_numbers.remove(&321);
                }
                "unlinkat" => {
                    allowed_syscall_numbers.remove(&263);
                }
                "renameat2" => {
                    allowed_syscall_numbers.remove(&316);
                }
                _ => return Err(format!("Unknown syscall to deny: {}", sname)),
            }
        }

        let compiled_syscalls = CompiledSyscallPolicy {
            default_deny: self.syscalls.default_deny,
            allowed_syscall_numbers,
        };

        // Validate syscall policy - empty allow list with default_deny makes sandbox unusable
        if compiled_syscalls.default_deny && compiled_syscalls.allowed_syscall_numbers.is_empty() {
            return Err(
                "Invalid syscall policy: default_deny is true but no syscalls are allowed. \
                 This would create an unusable sandbox where all syscalls are blocked. \
                 At minimum, add 'exit_group' to allow the process to terminate gracefully."
                    .to_string(),
            );
        }

        // --- Resource Compilation with Strict Validation ---
        let memory_limit_bytes = if let Some(mem_str) = &self.resources.memory_limit_bytes {
            Some(
                parse_memory_size(mem_str)
                    .map_err(|e| format!("Invalid memory_limit_bytes '{}': {}", mem_str, e))?,
            )
        } else {
            None
        };

        let block_io_limit_bytes_per_sec = if let Some(io_str) = &self.resources.block_io_limit {
            Some(
                parse_io_rate(io_str)
                    .map_err(|e| format!("Invalid block_io_limit '{}': {}", io_str, e))?,
            )
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
            dropped_capabilities: self.capabilities.drop.iter().cloned().collect(),
        };

        // --- Network Compilation with Strict Validation ---
        let mut allowed_outgoing_ports = HashSet::new();
        for (idx, port_str) in self.network.allow_outgoing.iter().enumerate() {
            let port = parse_port(port_str)
                .map_err(|e| format!("Invalid allow_outgoing[{}] '{}': {}", idx, port_str, e))?;
            allowed_outgoing_ports.insert(port);
        }

        let mut allowed_incoming_ports = HashSet::new();
        for (idx, port_str) in self.network.allow_incoming.iter().enumerate() {
            let port = parse_port(port_str)
                .map_err(|e| format!("Invalid allow_incoming[{}] '{}': {}", idx, port_str, e))?;
            allowed_incoming_ports.insert(port);
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
