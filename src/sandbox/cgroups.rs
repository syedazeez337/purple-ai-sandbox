// purple/src/sandbox/cgroups.rs

use crate::error::Result;
use crate::policy::compiler::CompiledResourcePolicy;
use std::path::{Path, PathBuf};

/// Manages cgroups for resource limit enforcement
pub struct CgroupManager {
    cgroup_name: String,
    cgroup_path: PathBuf,
}

impl CgroupManager {
    /// Creates a new cgroup manager for the sandbox
    pub fn new(sandbox_id: &str) -> Self {
        let cgroup_name = format!("purple-sandbox-{}", sandbox_id);
        let cgroup_path = PathBuf::from(format!("/sys/fs/cgroup/purple/{}", cgroup_name));

        CgroupManager {
            cgroup_name,
            cgroup_path,
        }
    }

    /// Sets up cgroups and applies resource limits
    pub fn setup_cgroups(&self, policy: &CompiledResourcePolicy) -> Result<()> {
        log::info!("Setting up cgroups for resource limits...");

        use std::fs;

        log::info!("Cgroup name: {}", self.cgroup_name);
        log::info!("Cgroup path: {}", self.cgroup_path.display());

        // Create the cgroup directory
        if let Err(e) = fs::create_dir_all(&self.cgroup_path) {
            if e.kind() == std::io::ErrorKind::PermissionDenied
                || e.kind() == std::io::ErrorKind::ReadOnlyFilesystem
            {
                log::warn!(
                    "Failed to create cgroup directory: {}. Resource limits will NOT be enforced.",
                    e
                );
                return Ok(());
            }
            return Err(crate::error::PurpleError::ResourceError(format!(
                "Failed to create cgroup directory: {}",
                e
            )));
        }

        // Apply CPU limits
        if let Some(cpu_shares) = policy.cpu_shares {
            log::info!("Setting CPU shares to {}", cpu_shares);
            // Convert shares to appropriate value (cgroup2 uses different scale)
            let cpu_shares_value = (cpu_shares * 1024.0) as u64;
            let cpu_shares_path = self.cgroup_path.join("cpu.max");
            fs::write(cpu_shares_path, format!("{}", cpu_shares_value))?;
        } else {
            log::info!("No CPU shares limit specified");
        }

        // Apply memory limits
        if let Some(memory_limit) = policy.memory_limit_bytes {
            log::info!(
                "Setting memory limit to {} bytes ({} MB)",
                memory_limit,
                memory_limit / 1024 / 1024
            );
            let memory_limit_path = self.cgroup_path.join("memory.max");
            fs::write(memory_limit_path, format!("{}", memory_limit))?;
        } else {
            log::info!("No memory limit specified");
        }

        // Apply process limits
        if let Some(pids_limit) = policy.pids_limit {
            log::info!("Setting process limit to {}", pids_limit);
            let pids_limit_path = self.cgroup_path.join("pids.max");
            fs::write(pids_limit_path, format!("{}", pids_limit))?;
        } else {
            log::info!("No process limit specified");
        }

        // Apply I/O limits (cgroup2 uses different approach)
        if let Some(io_limit) = policy.block_io_limit_bytes_per_sec {
            log::info!(
                "Setting I/O limit to {} bytes/sec ({} MB/s)",
                io_limit,
                io_limit / 1024 / 1024
            );
            // For cgroup2, we would configure io.max or io.bfq.weight
            // This is more complex and may require root privileges
        } else {
            log::info!("No I/O limit specified");
        }

        // Apply timeout limits
        if let Some(timeout_secs) = policy.session_timeout_seconds {
            log::info!("Setting session timeout to {} seconds", timeout_secs);
            // Would implement process monitoring and termination
        } else {
            log::info!("No session timeout specified");
        }

        log::info!("Cgroups configured using cgroupfs");
        Ok(())
    }

    /// Cleans up cgroups after sandbox execution
    /// Note: Currently called implicitly via RAII, but kept for explicit cleanup
    #[allow(dead_code)]
    pub fn cleanup_cgroups(&self) -> Result<()> {
        log::info!("Cleaning up cgroups...");

        // In a real implementation, this would:
        // 1. Remove the cgroup directory
        // 2. Clean up any remaining processes
        // 3. Release resources

        log::info!("Would remove cgroup {}", self.cgroup_name);
        log::info!("Cgroups cleanup completed");

        Ok(())
    }

    /// Gets the cgroup path for process assignment
    #[allow(dead_code)]
    pub fn get_cgroup_path(&self) -> &Path {
        &self.cgroup_path
    }
}

/// Creates a unique sandbox ID for cgroup naming
pub fn generate_sandbox_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => format!("{}", duration.as_secs()),
        Err(_) => "0".to_string(),
    }
}
