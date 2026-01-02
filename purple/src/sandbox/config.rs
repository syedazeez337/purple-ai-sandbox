// purple/src/sandbox/config.rs
//!
//! Sandbox configuration for path externalization
//!
//! This module provides configurable paths for the sandboxing system.
//! All hardcoded paths have been externalized to allow for customization
//! and better portability across different Linux distributions and setups.

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Sandbox configuration containing all configurable paths
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SandboxConfig {
    /// Cgroup parent path (default: /sys/fs/cgroup/purple)
    pub cgroup_parent_path: PathBuf,
    /// iptables binary path (default: /usr/sbin/iptables)
    pub iptables_path: PathBuf,
    /// Sandbox root directory (default: /tmp/purple-sandbox)
    pub sandbox_root: PathBuf,
    /// Default scratch directory inside sandbox (default: /tmp)
    pub default_scratch_dir: PathBuf,
    /// Default audit log path (default: /tmp/audit.log)
    pub default_audit_log: PathBuf,
    /// proc filesystem path (default: /proc)
    pub proc_path: PathBuf,
    /// sys filesystem path (default: /sys)
    pub sys_path: PathBuf,
    /// Default PATH inside sandbox (default: /usr/local/sbin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin)
    pub sandbox_path: String,
    /// Essential host paths to mount (default: /usr/bin, /bin, /usr/lib, /lib, /lib64)
    pub essential_host_paths: Vec<PathBuf>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            cgroup_parent_path: PathBuf::from("/sys/fs/cgroup/purple"),
            iptables_path: PathBuf::from("/usr/sbin/iptables"),
            sandbox_root: PathBuf::from("/tmp/purple-sandbox"),
            default_scratch_dir: PathBuf::from("/tmp"),
            default_audit_log: PathBuf::from("/tmp/audit.log"),
            proc_path: PathBuf::from("/proc"),
            sys_path: PathBuf::from("/sys"),
            sandbox_path: "/usr/local/sbin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
                .to_string(),
            essential_host_paths: vec![
                PathBuf::from("/usr/bin"),
                PathBuf::from("/bin"),
                PathBuf::from("/usr/lib"),
                PathBuf::from("/lib"),
                PathBuf::from("/lib64"),
            ],
        }
    }
}

/// Global sandbox configuration - uses Lazy for thread-safe one-time initialization
static SANDBOX_CONFIG: Lazy<Mutex<SandboxConfig>> =
    Lazy::new(|| Mutex::new(SandboxConfig::default()));

/// Set the global sandbox configuration (for testing or customization)
pub fn set_config(config: SandboxConfig) {
    let mut config_ref = SANDBOX_CONFIG.lock().unwrap();
    *config_ref = config;
}

/// Get the cgroup parent path
#[inline]
pub fn cgroup_parent_path() -> PathBuf {
    SANDBOX_CONFIG.lock().unwrap().cgroup_parent_path.clone()
}

/// Get the iptables binary path
#[inline]
pub fn iptables_path() -> PathBuf {
    SANDBOX_CONFIG.lock().unwrap().iptables_path.clone()
}

/// Get the sandbox root directory
#[inline]
pub fn sandbox_root() -> PathBuf {
    SANDBOX_CONFIG.lock().unwrap().sandbox_root.clone()
}

/// Get the default scratch directory
#[inline]
pub fn default_scratch_dir() -> PathBuf {
    SANDBOX_CONFIG.lock().unwrap().default_scratch_dir.clone()
}

/// Get the default audit log path
#[inline]
pub fn default_audit_log() -> PathBuf {
    SANDBOX_CONFIG.lock().unwrap().default_audit_log.clone()
}

/// Get the proc filesystem path
#[inline]
pub fn proc_path() -> &'static Path {
    static PROC_PATH: Lazy<PathBuf> =
        Lazy::new(|| SANDBOX_CONFIG.lock().unwrap().proc_path.clone());
    &PROC_PATH
}

/// Get the sys filesystem path
#[inline]
pub fn sys_path() -> &'static Path {
    static SYS_PATH: Lazy<PathBuf> = Lazy::new(|| SANDBOX_CONFIG.lock().unwrap().sys_path.clone());
    &SYS_PATH
}

/// Get the PATH variable for inside sandbox
#[inline]
pub fn sandbox_path() -> String {
    SANDBOX_CONFIG.lock().unwrap().sandbox_path.clone()
}

/// Get essential host paths to mount
#[inline]
pub fn essential_host_paths() -> Vec<PathBuf> {
    SANDBOX_CONFIG.lock().unwrap().essential_host_paths.clone()
}

/// Generate a sandbox-specific root path
#[inline]
pub fn sandbox_root_for_id(sandbox_id: &str) -> PathBuf {
    let config = SANDBOX_CONFIG.lock().unwrap();
    config
        .sandbox_root
        .join(format!("purple-sandbox-{}", sandbox_id))
}

/// Generate cgroup path for a sandbox
#[inline]
pub fn cgroup_path_for_id(sandbox_id: &str) -> PathBuf {
    let config = SANDBOX_CONFIG.lock().unwrap();
    // The sandbox_id already contains the full identifier (e.g., "test-123")
    // We need to produce "purple-sandbox-test-123" not "purple-test-123"
    config
        .cgroup_parent_path
        .join(format!("purple-sandbox-{}", sandbox_id))
}
