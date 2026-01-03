// purple/src/sandbox/cgroups.rs

use crate::error::Result;
use crate::policy::compiler::CompiledResourcePolicy;
use crate::sandbox::config;
use std::fs;
use std::io::{BufRead, BufReader};
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
        let cgroup_path = config::cgroup_path_for_id(sandbox_id);

        CgroupManager {
            cgroup_name,
            cgroup_path,
        }
    }

    /// Detect the root device major:minor numbers dynamically
    /// Returns (major, minor) or None if detection fails
    fn detect_root_device() -> Option<(u64, u64)> {
        // Try to read from /proc/self/mountinfo first
        if let Ok(file) = fs::File::open("/proc/self/mountinfo") {
            let reader = BufReader::new(file);
            for line in reader.lines().map_while(|r| r.ok()) {
                // Look for the root filesystem entry
                if line.contains(" / ") {
                    // Parse format: <id> <parent> <major>:<minor> <root> <mountpoint> <options>
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 4 {
                        let device_parts: Vec<&str> = parts[2].split(':').collect();
                        if device_parts.len() == 2
                            && let (Ok(major), Ok(minor)) = (
                                device_parts[0].parse::<u64>(),
                                device_parts[1].parse::<u64>(),
                            )
                        {
                            return Some((major, minor));
                        }
                    }
                }
            }
        }

        // Fallback: try to detect common devices
        // Check if /dev/sda exists (common for traditional disks)
        if Path::new("/dev/sda").exists() {
            return Some((8, 0)); // Traditional SCSI/SATA device
        }

        // Check if /dev/nvme0n1 exists (common for NVMe)
        if Path::new("/dev/nvme0n1").exists() {
            return Some((259, 0)); // NVMe device
        }

        // Check if /dev/vda exists (common for virtual machines)
        if Path::new("/dev/vda").exists() {
            return Some((253, 0)); // Virtio device
        }

        // Default fallback to traditional device (8:0)
        Some((8, 0))
    }

    /// Sets up cgroups and applies resource limits
    pub fn setup_cgroups(&self, policy: &CompiledResourcePolicy) -> Result<()> {
        log::info!("Setting up cgroups for resource limits...");

        use std::fs;

        log::info!("Cgroup name: {}", self.cgroup_name);
        log::info!("Cgroup path: {}", self.cgroup_path.display());

        // Ensure parent cgroup directory exists and has controllers enabled
        let parent_cgroup_path = config::cgroup_parent_path();
        if !parent_cgroup_path.exists() {
            if let Err(e) = fs::create_dir_all(&parent_cgroup_path) {
                return Err(crate::error::PurpleError::ResourceError(format!(
                    "Failed to create parent cgroup directory: {}",
                    e
                )));
            }
            log::info!(
                "Created parent cgroup directory: {}",
                parent_cgroup_path.display()
            );
        }

        // Enable controllers in parent cgroup's subtree_control
        // This is required for child cgroups to have controller files (cpu.max, memory.max, etc.)
        let subtree_control_path = parent_cgroup_path.join("cgroup.subtree_control");
        if subtree_control_path.exists() {
            // Read current controllers
            let current_controllers = fs::read_to_string(&subtree_control_path).unwrap_or_default();
            let needs_cpu = !current_controllers.contains("cpu");
            let needs_memory = !current_controllers.contains("memory");
            let needs_pids = !current_controllers.contains("pids");
            let needs_io = !current_controllers.contains("io");

            if needs_cpu || needs_memory || needs_pids || needs_io {
                log::info!("Enabling cgroup controllers in parent subtree_control...");

                // Build list of controllers to enable
                let mut controllers_to_enable = Vec::new();
                if needs_cpu {
                    controllers_to_enable.push("+cpu");
                }
                if needs_memory {
                    controllers_to_enable.push("+memory");
                }
                if needs_pids {
                    controllers_to_enable.push("+pids");
                }
                if needs_io {
                    controllers_to_enable.push("+io");
                }

                // Enable each controller individually (some systems require this)
                for controller in &controllers_to_enable {
                    if let Err(e) = fs::write(&subtree_control_path, controller) {
                        log::warn!(
                            "Failed to enable controller {} in subtree_control: {}",
                            controller,
                            e
                        );
                    } else {
                        log::info!("Enabled controller {} in parent cgroup", controller);
                    }
                }
            } else {
                log::info!("All required cgroup controllers already enabled");
            }
        }

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
            // cgroup2 cpu.max format: "$MAX $PERIOD" where MAX is quota in microseconds
            // and PERIOD is the period (typically 100000 = 100ms)
            // For example, 0.5 shares = 50% CPU = "50000 100000"
            let period: u64 = 100000; // 100ms period
            let quota = (cpu_shares * period as f64) as u64;
            let cpu_max_path = self.cgroup_path.join("cpu.max");
            fs::write(&cpu_max_path, format!("{} {}", quota, period))?;
            log::info!(
                "CPU limit set: {} us / {} us period ({}%)",
                quota,
                period,
                (cpu_shares * 100.0) as u32
            );
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

            // Disable swap to ensure strict enforcement
            let swap_limit_path = self.cgroup_path.join("memory.swap.max");
            if swap_limit_path.exists() {
                if let Err(e) = fs::write(swap_limit_path, "0") {
                    log::warn!("Failed to disable swap (non-fatal): {}", e);
                } else {
                    log::info!("Swap disabled for strict memory enforcement");
                }
            }
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

        // Apply I/O limits using cgroup2 io.max interface
        if let Some(io_limit) = policy.block_io_limit_bytes_per_sec {
            log::info!(
                "Setting I/O limit to {} bytes/sec ({} MB/s)",
                io_limit,
                io_limit / 1024 / 1024
            );

            // For cgroup2, use io.max to set I/O rate limits
            // Format: "<major>:<minor> <type> <limit>"
            // Detect root device dynamically
            if let Some((major, minor)) = Self::detect_root_device() {
                let io_max_path = self.cgroup_path.join("io.max");
                let io_max_content = format!(
                    "{}:{} rbytes={} wbytes={}",
                    major, minor, io_limit, io_limit
                );

                match fs::write(io_max_path, io_max_content) {
                    Ok(_) => log::info!("✓ I/O rate limit applied successfully"),
                    Err(e) => {
                        log::warn!(
                            "Failed to set I/O rate limit: {}. This may require root privileges.",
                            e
                        );
                        log::warn!("I/O rate limiting will not be enforced.");
                    }
                }
            } else {
                log::warn!("Failed to detect root device, I/O limits will not be applied");
            }
        } else {
            log::info!("No I/O limit specified");
        }

        // Apply timeout limits
        if let Some(timeout_secs) = policy.session_timeout_seconds {
            log::info!("Setting session timeout to {} seconds", timeout_secs);
            // Note: Actual timeout enforcement happens in the sandbox execution
            // through the parent's wait loop with timeout checking
        } else {
            log::info!("No session timeout specified");
        }

        log::info!("Cgroups configured using cgroupfs");
        Ok(())
    }

    /// Adds a process to this cgroup
    pub fn add_pid(&self, pid: u64) -> Result<()> {
        use std::fs;

        let cgroup_procs_path = self.cgroup_path.join("cgroup.procs");

        log::info!(
            "Adding PID {} to cgroup at {}",
            pid,
            cgroup_procs_path.display()
        );

        fs::write(&cgroup_procs_path, format!("{}", pid)).map_err(|e| {
            crate::error::PurpleError::ResourceError(format!(
                "Failed to add PID {} to cgroup: {}",
                pid, e
            ))
        })?;

        log::info!("✓ PID {} added to cgroup successfully", pid);
        Ok(())
    }

    /// Validates that cgroup functionality is available and working
    pub fn validate_cgroup_functionality() -> Result<()> {
        use std::fs;

        log::info!("Validating cgroup functionality...");

        // Check if cgroup filesystem is mounted
        let cgroup_mounts = ["/sys/fs/cgroup", "/sys/fs/cgroup/unified"];

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

        // Check if our purple cgroup parent exists
        let purple_cgroup_path = config::cgroup_parent_path();
        if !purple_cgroup_path.exists() {
            log::info!(
                "Creating purple cgroup parent directory: {}",
                purple_cgroup_path.display()
            );
            if let Err(e) = fs::create_dir_all(&purple_cgroup_path) {
                return Err(crate::error::PurpleError::ResourceError(format!(
                    "Failed to create purple cgroup directory: {}",
                    e
                )));
            }
        }

        // Test creating a temporary cgroup directory
        let test_cgroup_path = purple_cgroup_path.join("test_validation");
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

        // Remove the cgroup directory with retries
        if self.cgroup_path.exists() {
            let max_retries = 5;
            let mut last_error = None;

            for attempt in 1..=max_retries {
                match fs::remove_dir(&self.cgroup_path) {
                    Ok(_) => {
                        log::info!("✓ Cgroup {} removed successfully", self.cgroup_name);
                        return Ok(());
                    }
                    Err(e) => {
                        // EBUSY means processes are still running or kernel is cleaning up
                        if e.kind() == std::io::ErrorKind::Other || e.raw_os_error() == Some(16) {
                            if attempt == 1 {
                                log::warn!(
                                    "Cgroup {} still busy, attempting force cleanup...",
                                    self.cgroup_name
                                );
                                // Try to force kill if not already done
                                self.force_kill_cgroup_processes()?;
                            }
                            log::debug!("Attempt {}/{} failed: {}", attempt, max_retries, e);
                            std::thread::sleep(std::time::Duration::from_millis(
                                200 * attempt as u64,
                            ));
                            last_error = Some(e);
                        } else if e.kind() == std::io::ErrorKind::NotFound {
                            log::debug!("Cgroup {} already removed", self.cgroup_name);
                            return Ok(());
                        } else {
                            // Other errors are likely fatal/permanent
                            log::warn!("Failed to remove cgroup {}: {}", self.cgroup_name, e);
                            return Err(crate::error::PurpleError::ResourceError(format!(
                                "Failed to remove cgroup: {}",
                                e
                            )));
                        }
                    }
                }
            }

            if let Some(e) = last_error {
                log::warn!(
                    "Failed to remove cgroup directory after {} attempts: {}",
                    max_retries,
                    e
                );
                // Don't fail the sandbox execution for cleanup failure, but log it clearly
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
                // SAFETY: libc::kill is safe to call with any PID - returns -1 on error.
                // The PID was validated to be > 0 and parsed from cgroup.procs.
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
                // SAFETY: libc::kill is safe to call with any PID - returns -1 on error.
                // The PID was validated to be > 0 and parsed from cgroup.procs.
                // SIGKILL is used for force cleanup after graceful shutdown failed.
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

        let purple_cgroup_path = config::cgroup_parent_path();
        if !purple_cgroup_path.exists() {
            log::info!("No purple cgroups found - nothing to clean up");
            return Ok(());
        }

        // Read all purple cgroup directories
        let mut cleaned_count = 0;
        let mut permission_errors = Vec::new();

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
                            log::info!("Cleaned up orphaned cgroup: {}", cgroup_name_str);
                            cleaned_count += 1;
                        }
                        Err(e) => {
                            if e.kind() == std::io::ErrorKind::PermissionDenied {
                                permission_errors.push(cgroup_path.clone());
                            } else {
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
        }

        // Provide helpful instructions if there were permission errors
        if !permission_errors.is_empty() {
            log::warn!("========================================");
            log::warn!("ORPHANED CGROUPS DETECTED");
            log::warn!("========================================");
            log::warn!("Some cgroups could not be cleaned up due to permissions.");
            log::warn!("This typically happens when running with sudo vs without.");

            // Try to clean up with sudo if available
            log::info!("Attempting cleanup with elevated permissions...");

            let mut sudo_cleaned = 0;
            for cgroup_path in &permission_errors {
                // Use sudo to remove the cgroup if we can
                let output = std::process::Command::new("sudo")
                    .args(["rmdir", cgroup_path.to_str().unwrap_or("")])
                    .output();

                match output {
                    Ok(output) if output.status.success() => {
                        log::info!("Cleaned up cgroup with sudo: {}", cgroup_path.display());
                        sudo_cleaned += 1;
                    }
                    _ => {
                        log::warn!("Could not clean up: {}", cgroup_path.display());
                        log::warn!("To fix manually, run: sudo rmdir {}", cgroup_path.display());
                    }
                }
            }

            cleaned_count += sudo_cleaned;
        }

        log::info!(
            "Orphaned cgroup cleanup completed. Cleaned {} cgroups.",
            cleaned_count
        );
        Ok(())
    }

    /// Reads CPU usage statistics from cgroup
    pub fn get_cpu_stats(&self) -> Result<f64> {
        let cpu_stat_path = self.cgroup_path.join("cpu.stat");

        let content = fs::read_to_string(&cpu_stat_path).map_err(|e| {
            crate::error::PurpleError::ResourceError(format!("Failed to read cpu.stat: {}", e))
        })?;

        // Parse usage_usec value
        for line in content.lines() {
            if line.starts_with("usage_usec") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() == 2 {
                    let usec: u64 = parts[1].parse().map_err(|e| {
                        crate::error::PurpleError::ResourceError(format!(
                            "Failed to parse cpu usage: {}",
                            e
                        ))
                    })?;
                    return Ok(usec as f64 / 1_000_000.0); // Convert to seconds
                }
            }
        }

        Err(crate::error::PurpleError::ResourceError(
            "usage_usec not found in cpu.stat".to_string(),
        ))
    }

    /// Reads peak memory usage from cgroup
    pub fn get_memory_peak(&self) -> Result<u64> {
        let mem_peak_path = self.cgroup_path.join("memory.peak");

        let content = fs::read_to_string(&mem_peak_path).map_err(|e| {
            crate::error::PurpleError::ResourceError(format!("Failed to read memory.peak: {}", e))
        })?;

        content.trim().parse::<u64>().map_err(|e| {
            crate::error::PurpleError::ResourceError(format!("Failed to parse memory peak: {}", e))
        })
    }

    /// Reads I/O statistics from cgroup
    pub fn get_io_stats(&self) -> Result<u64> {
        let io_stat_path = self.cgroup_path.join("io.stat");

        let content: String = fs::read_to_string(&io_stat_path).map_err(|e| {
            crate::error::PurpleError::ResourceError(format!("Failed to read io.stat: {}", e))
        })?;

        let mut total_bytes = 0u64;

        // Parse rbytes and wbytes for all devices
        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            for part in parts.iter() {
                if (part.starts_with("rbytes=") || part.starts_with("wbytes="))
                    && let Some(eq_pos) = part.find('=')
                {
                    let value_str = &part[eq_pos + 1..];
                    if let Ok(bytes) = value_str.parse::<u64>() {
                        total_bytes += bytes;
                    }
                }
            }
        }

        Ok(total_bytes)
    }
}

/// Creates a unique sandbox ID for cgroup naming
pub fn generate_sandbox_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => format!("{}", duration.as_nanos()),
        Err(_) => "0".to_string(),
    }
}
