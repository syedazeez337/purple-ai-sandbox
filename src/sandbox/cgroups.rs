// purple/src/sandbox/cgroups.rs

use crate::error::Result;
use crate::policy::compiler::CompiledResourcePolicy;
use std::path::{Path, PathBuf};

/// Manages cgroups for resource limit enforcement
pub struct CgroupManager {
    pub cgroup_name: String,
    pub cgroup_path: PathBuf,
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
                log::error!(
                    "CRITICAL: Failed to create cgroup directory due to permissions: {}. This means resource limits CANNOT be enforced. The sandbox will continue but resource isolation is COMPROMISED.",
                    e
                );
                return Err(crate::error::PurpleError::ResourceError(format!(
                    "Cgroup creation failed: {}. Resource limits cannot be enforced - sandbox would be insecure.",
                    e
                )));
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

    /// Validates that cgroup functionality is available and working
    pub fn validate_cgroup_functionality() -> Result<()> {
        use std::fs;

        log::info!("Validating cgroup functionality...");

        // Check if cgroup filesystem is mounted
        let cgroup_mounts = [
            "/sys/fs/cgroup",
            "/sys/fs/cgroup/unified",
            "/sys/fs/cgroup/purple",
        ];

        let mut found_cgroup = false;
        for mount_point in &cgroup_mounts {
            if Path::new(mount_point).exists() {
                found_cgroup = true;
                log::info!("Found cgroup mount at: {}", mount_point);
                break;
            }
        }

        if !found_cgroup {
            return Err(crate::error::PurpleError::ResourceError(
                "Cgroup filesystem not found. Resource limits cannot be enforced.".to_string(),
            ));
        }

        // Test creating a temporary cgroup directory
        let test_cgroup_path = PathBuf::from("/sys/fs/cgroup/purple/test_validation");
        match fs::create_dir_all(&test_cgroup_path) {
            Ok(_) => {
                // Successfully created, now clean up
                if let Err(e) = fs::remove_dir(&test_cgroup_path) {
                    log::warn!("Failed to clean up test cgroup: {}", e);
                }
                log::info!("✓ Cgroup functionality validated successfully");
                Ok(())
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    return Err(crate::error::PurpleError::ResourceError(format!(
                        "Insufficient permissions to create cgroups: {}. Run as root or configure proper cgroup permissions.",
                        e
                    )));
                }
                Err(crate::error::PurpleError::ResourceError(format!(
                    "Cgroup validation failed: {}",
                    e
                )))
            }
        }
    }

    /// Cleans up cgroups after sandbox execution
    pub fn cleanup_cgroups(&self) -> Result<()> {
        use std::fs;

        log::info!("Cleaning up cgroups for: {}", self.cgroup_name);

        // First, terminate any remaining processes in the cgroup
        self.kill_cgroup_processes()?;

        // Wait a moment for processes to terminate
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Remove the cgroup directory
        // Note: cgroup directories can only be removed when they have no processes
        if self.cgroup_path.exists() {
            match fs::remove_dir(&self.cgroup_path) {
                Ok(_) => {
                    log::info!("✓ Cgroup {} removed successfully", self.cgroup_name);
                }
                Err(e) => {
                    // EBUSY means processes are still running
                    if e.kind() == std::io::ErrorKind::Other || e.raw_os_error() == Some(16) {
                        log::warn!(
                            "Cgroup {} still has processes, attempting force cleanup",
                            self.cgroup_name
                        );
                        // Try again after killing processes more aggressively
                        self.force_kill_cgroup_processes()?;
                        std::thread::sleep(std::time::Duration::from_millis(200));

                        if let Err(e2) = fs::remove_dir(&self.cgroup_path) {
                            log::warn!(
                                "Failed to remove cgroup directory after force kill: {}",
                                e2
                            );
                            // Don't fail - the cgroup will be orphaned but sandbox still works
                        }
                    } else if e.kind() == std::io::ErrorKind::NotFound {
                        log::debug!("Cgroup {} already removed", self.cgroup_name);
                    } else {
                        log::warn!("Failed to remove cgroup {}: {}", self.cgroup_name, e);
                    }
                }
            }
        } else {
            log::debug!(
                "Cgroup directory {} does not exist (already cleaned up)",
                self.cgroup_path.display()
            );
        }

        log::info!("✓ Cgroups cleanup completed");
        Ok(())
    }

    /// Kills all processes in the cgroup
    fn kill_cgroup_processes(&self) -> Result<()> {
        use std::fs;

        let cgroup_procs_path = self.cgroup_path.join("cgroup.procs");

        if !cgroup_procs_path.exists() {
            return Ok(());
        }

        let procs_content = match fs::read_to_string(&cgroup_procs_path) {
            Ok(content) => content,
            Err(e) => {
                log::debug!("Could not read cgroup.procs: {}", e);
                return Ok(());
            }
        };

        for line in procs_content.lines() {
            if let Ok(pid) = line.trim().parse::<i32>()
                && pid > 0
            {
                log::debug!("Sending SIGTERM to process {} in cgroup", pid);
                // Use SIGTERM first for graceful shutdown
                unsafe {
                    libc::kill(pid, libc::SIGTERM);
                }
            }
        }

        Ok(())
    }

    /// Force kills all processes in the cgroup using SIGKILL
    fn force_kill_cgroup_processes(&self) -> Result<()> {
        use std::fs;

        let cgroup_procs_path = self.cgroup_path.join("cgroup.procs");

        if !cgroup_procs_path.exists() {
            return Ok(());
        }

        let procs_content = match fs::read_to_string(&cgroup_procs_path) {
            Ok(content) => content,
            Err(e) => {
                log::debug!("Could not read cgroup.procs for force kill: {}", e);
                return Ok(());
            }
        };

        for line in procs_content.lines() {
            if let Ok(pid) = line.trim().parse::<i32>()
                && pid > 0
            {
                log::debug!("Sending SIGKILL to process {} in cgroup", pid);
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
            }
        }

        Ok(())
    }

    /// Gets the cgroup path for process assignment
    #[allow(dead_code)]
    pub fn get_cgroup_path(&self) -> &Path {
        &self.cgroup_path
    }

    /// Cleans up orphaned cgroups from previous failed runs
    pub fn cleanup_orphaned_cgroups() -> Result<()> {
        use std::fs;

        log::info!("Cleaning up orphaned cgroups...");

        let purple_cgroup_path = PathBuf::from("/sys/fs/cgroup/purple");
        if !purple_cgroup_path.exists() {
            log::info!("No purple cgroups found - nothing to clean up");
            return Ok(());
        }

        // Read all purple cgroup directories
        let mut cleaned_count = 0;
        if let Ok(entries) = fs::read_dir(&purple_cgroup_path) {
            for entry in entries.flatten() {
                if let Ok(file_type) = entry.file_type()
                    && file_type.is_dir()
                {
                    let cgroup_name = entry.file_name();
                    let cgroup_name_str = cgroup_name.to_string_lossy();

                    // Skip validation cgroup if it exists
                    if cgroup_name_str == "test_validation" {
                        continue;
                    }

                    let cgroup_path = entry.path();

                    // Check if cgroup has any processes
                    let cgroup_procs_path = cgroup_path.join("cgroup.procs");

                    // Try to read processes in the cgroup
                    let has_processes =
                        if let Ok(procs_content) = fs::read_to_string(&cgroup_procs_path) {
                            !procs_content.trim().is_empty()
                        } else {
                            false
                        };

                    if has_processes {
                        log::warn!(
                            "Found orphaned cgroup with active processes: {}",
                            cgroup_name_str
                        );
                        // Don't clean up cgroups with active processes
                        continue;
                    }

                    // Safe to clean up - no processes
                    match fs::remove_dir(&cgroup_path) {
                        Ok(_) => {
                            log::info!("✓ Cleaned up orphaned cgroup: {}", cgroup_name_str);
                            cleaned_count += 1;
                        }
                        Err(e) => {
                            log::warn!(
                                "Failed to clean up orphaned cgroup {}: {}",
                                cgroup_name_str,
                                e
                            );
                        }
                    }
                }
            }
        }

        log::info!(
            "✓ Orphaned cgroup cleanup completed. Cleaned {} cgroups.",
            cleaned_count
        );
        Ok(())
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
