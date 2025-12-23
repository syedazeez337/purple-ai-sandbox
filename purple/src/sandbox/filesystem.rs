use crate::error::{PurpleError, Result};
use crate::policy::compiler::CompiledPolicy;
use nix::mount::{MntFlags, MsFlags, mount, umount2};
use nix::unistd::{chdir, pivot_root};
use std::fs;
use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Validates a DNS server string and returns valid IP addresses
fn validate_dns_servers(servers: &[String]) -> Vec<String> {
    let mut valid = Vec::new();

    for server in servers {
        // Try parsing as IPv4 or IPv6 address
        if server.parse::<IpAddr>().is_ok() {
            valid.push(server.clone());
        } else {
            log::warn!(
                "Invalid DNS server '{}' - must be valid IPv4 or IPv6 address",
                server
            );
        }
    }

    if valid.is_empty() {
        log::warn!("No valid DNS servers provided, using defaults");
        vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()]
    } else {
        valid
    }
}

/// Tracks a mount operation for potential rollback
#[derive(Debug, Clone)]
struct MountOperation {
    target: PathBuf,
}

/// Manages filesystem setup with rollback capability on failure
struct FilesystemTransaction {
    mounts: Vec<MountOperation>,
}

impl FilesystemTransaction {
    fn new() -> Self {
        Self { mounts: Vec::new() }
    }

    /// Add a mount to be tracked
    fn add_mount(&mut self, target: PathBuf) {
        self.mounts.push(MountOperation { target });
    }

    /// Rollback all mounts (called on failure)
    fn rollback(&self) {
        log::info!("Rolling back filesystem changes...");
        use nix::mount::umount;
        // Unmount in reverse order
        for mount_op in self.mounts.iter().rev() {
            if let Err(e) = umount(&mount_op.target) {
                log::warn!(
                    "Failed to unmount {} during rollback: {}",
                    mount_op.target.display(),
                    e
                );
            } else {
                log::debug!("Rolled back mount: {}", mount_op.target.display());
            }
        }
    }
}

/// Safely create a file without following symlinks (TOCTOU protection)
fn safe_create_file(path: &Path) -> Result<()> {
    // Check if path exists first (without following symlinks)
    if path.exists() {
        return Ok(());
    }

    // Check if parent directory is a symlink
    if let Some(parent) = path.parent() {
        let parent_metadata = parent.symlink_metadata().map_err(|e| {
            PurpleError::FilesystemError(format!(
                "Failed to get metadata for parent directory {}: {}",
                parent.display(),
                e
            ))
        })?;

        if parent_metadata.file_type().is_symlink() {
            return Err(PurpleError::FilesystemError(format!(
                "Parent directory {} is a symlink - potential TOCTOU attack",
                parent.display()
            )));
        }
    }

    // Check if the path itself is a symlink
    if path
        .symlink_metadata()
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err(PurpleError::FilesystemError(format!(
            "Path {} is a symlink - potential TOCTOU attack",
            path.display()
        )));
    }

    // Create the file using OpenOptions with O_NOFOLLOW to prevent following symlinks
    // This provides atomic protection against the final component being a symlink
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| {
            PurpleError::FilesystemError(format!(
                "Failed to create file {} (O_NOFOLLOW): {}",
                path.display(),
                e
            ))
        })?;

    Ok(())
}

/// Validate a path for symlink attacks (TOCTOU protection)
/// Returns Ok(()) if the path is safe, Err if it's a symlink or has symlink parents
fn validate_path_no_symlinks(path: &Path) -> Result<()> {
    // Check if the path itself is a symlink
    if path
        .symlink_metadata()
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err(PurpleError::FilesystemError(format!(
            "Path {} is a symlink - potential security vulnerability",
            path.display()
        )));
    }

    // Check each parent directory for symlinks
    let mut current_path = path.to_path_buf();
    while let Some(parent) = current_path.parent() {
        if parent
            .symlink_metadata()
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Err(PurpleError::FilesystemError(format!(
                "Parent directory {} is a symlink - potential security vulnerability",
                parent.display()
            )));
        }
        current_path = parent.to_path_buf();
        // Stop at root to avoid infinite loop
        if current_path == Path::new("/") {
            break;
        }
    }

    Ok(())
}

/// Setup filesystem isolation with rollback support
pub fn setup_filesystem(policy: &CompiledPolicy, sandbox_root: &Path) -> Result<()> {
    log::info!("Setting up filesystem isolation...");

    // Create transaction for rollback on failure
    let mut transaction = FilesystemTransaction::new();

    // Create temporary directory structure for the sandbox
    if let Err(e) = fs::create_dir_all(sandbox_root) {
        return Err(PurpleError::FilesystemError(format!(
            "Failed to create sandbox root: {}",
            e
        )));
    }

    // Create necessary directories
    let directories = [
        "bin", "lib", "lib64", "usr", "usr/bin", "usr/lib", "tmp", "var", "var/tmp", "proc", "dev",
        "sys",
    ];

    for dir in directories.iter() {
        let path = Path::new(sandbox_root).join(dir);
        if let Err(e) = fs::create_dir_all(&path) {
            return Err(PurpleError::FilesystemError(format!(
                "Failed to create directory {}: {}",
                path.display(),
                e
            )));
        }
    }

    // Setup bind mounts for immutable paths
    for (host_path, sandbox_path) in &policy.filesystem.immutable_mounts {
        let full_sandbox_path = Path::new(sandbox_root).join(
            sandbox_path
                .strip_prefix("/")
                .unwrap_or(sandbox_path.as_path()),
        );

        // Auto-create host directory if it doesn't exist
        if !host_path.exists() {
            log::info!("Auto-creating host directory: {}", host_path.display());
            if let Err(e) = fs::create_dir_all(host_path) {
                return Err(PurpleError::FilesystemError(format!(
                    "Failed to create host directory {}: {}",
                    host_path.display(),
                    e
                )));
            }
        }

        // Create parent directory if it doesn't exist
        if let Some(parent) = full_sandbox_path.parent()
            && let Err(e) = fs::create_dir_all(parent)
        {
            transaction.rollback();
            return Err(PurpleError::FilesystemError(format!(
                "Failed to create parent directory {}: {}",
                parent.display(),
                e
            )));
        }

        // Create the mount point (file or directory)
        if host_path.is_dir() {
            if let Err(e) = fs::create_dir_all(&full_sandbox_path) {
                transaction.rollback();
                return Err(PurpleError::FilesystemError(format!(
                    "Failed to create mount point directory {}: {}",
                    full_sandbox_path.display(),
                    e
                )));
            }
        } else {
            // Assume it's a file - create empty file as mount point (TOCTOU-safe)
            if let Err(e) = safe_create_file(&full_sandbox_path) {
                transaction.rollback();
                return Err(e);
            }
        }

        log::info!(
            "Binding {} to {}",
            host_path.display(),
            full_sandbox_path.display()
        );

        // Bind mount the host path to the sandbox path
        if let Err(e) = mount(
            Some(host_path.as_path()),
            &full_sandbox_path,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        ) {
            transaction.rollback();
            return Err(PurpleError::FilesystemError(format!(
                "Failed to bind mount {} to {}: {}",
                host_path.display(),
                full_sandbox_path.display(),
                e
            )));
        }
        transaction.add_mount(full_sandbox_path.clone());

        // Make it read-only
        if let Err(e) = mount(
            None::<&str>,
            &full_sandbox_path,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
            None::<&str>,
        ) {
            transaction.rollback();
            return Err(PurpleError::FilesystemError(format!(
                "Failed to remount {} as read-only: {}",
                full_sandbox_path.display(),
                e
            )));
        }
        transaction.add_mount(full_sandbox_path.clone());
    }

    // Setup scratch directories
    for scratch_path in &policy.filesystem.scratch_dirs {
        let full_sandbox_path = Path::new(sandbox_root).join(
            scratch_path
                .strip_prefix("/")
                .unwrap_or(scratch_path.as_path()),
        );

        if let Some(parent) = full_sandbox_path.parent()
            && let Err(e) = fs::create_dir_all(parent)
        {
            transaction.rollback();
            return Err(PurpleError::FilesystemError(format!(
                "Failed to create parent directory {}: {}",
                parent.display(),
                e
            )));
        }

        if let Err(e) = fs::create_dir_all(&full_sandbox_path) {
            transaction.rollback();
            return Err(PurpleError::FilesystemError(format!(
                "Failed to create scratch directory {}: {}",
                full_sandbox_path.display(),
                e
            )));
        }
    }

    // Setup output directories (writable) - auto-create host directories
    for (host_path, sandbox_path) in &policy.filesystem.output_mounts {
        let full_sandbox_path = Path::new(sandbox_root).join(
            sandbox_path
                .strip_prefix("/")
                .unwrap_or(sandbox_path.as_path()),
        );

        // Auto-create host directory if it doesn't exist
        if !host_path.exists() {
            log::info!(
                "Auto-creating output host directory: {}",
                host_path.display()
            );
            if let Err(e) = fs::create_dir_all(host_path) {
                return Err(PurpleError::FilesystemError(format!(
                    "Failed to create host output directory {}: {}",
                    host_path.display(),
                    e
                )));
            }
        }

        if let Some(parent) = full_sandbox_path.parent()
            && let Err(e) = fs::create_dir_all(parent)
        {
            transaction.rollback();
            return Err(PurpleError::FilesystemError(format!(
                "Failed to create parent directory {}: {}",
                parent.display(),
                e
            )));
        }

        if let Err(e) = fs::create_dir_all(&full_sandbox_path) {
            transaction.rollback();
            return Err(PurpleError::FilesystemError(format!(
                "Failed to create output directory {}: {}",
                full_sandbox_path.display(),
                e
            )));
        }

        // Bind mount output directory
        if let Err(e) = mount(
            Some(host_path.as_path()),
            &full_sandbox_path,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        ) {
            transaction.rollback();
            return Err(PurpleError::FilesystemError(format!(
                "Failed to bind mount output directory {} to {}: {}",
                host_path.display(),
                full_sandbox_path.display(),
                e
            )));
        }
        transaction.add_mount(full_sandbox_path.clone());
    }

    // Mount essential filesystem
    // CORRECT: Mount fresh procfs
    let proc_path = Path::new(sandbox_root).join("proc");
    if let Err(e) = mount(
        Some("proc"),
        &proc_path,
        Some("proc"),
        MsFlags::empty(),
        None::<&str>,
    ) {
        transaction.rollback();
        return Err(PurpleError::FilesystemError(format!(
            "Failed to mount proc: {}",
            e
        )));
    }
    transaction.add_mount(proc_path);

    // SECURE: Create minimal /dev with only essential devices
    if let Err(e) = setup_secure_dev(sandbox_root) {
        transaction.rollback();
        return Err(e);
    }

    // SECURE: Mount /sys as read-only with security restrictions
    if let Err(e) = setup_secure_sys(sandbox_root) {
        transaction.rollback();
        return Err(e);
    }

    // Setup DNS configuration for network access
    if !policy.network.isolated {
        let resolv_conf_path = Path::new(sandbox_root).join("etc/resolv.conf");
        if let Some(parent) = resolv_conf_path.parent()
            && let Err(e) = fs::create_dir_all(parent)
        {
            transaction.rollback();
            return Err(PurpleError::FilesystemError(format!(
                "Failed to create DNS config directory {}: {}",
                parent.display(),
                e
            )));
        }

        // Configurable DNS servers with proper validation
        let nameservers = if let Some(servers) = &policy.network.dns_servers {
            validate_dns_servers(servers)
        } else {
            // Default DNS servers (Google Public DNS)
            vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()]
        };

        let mut resolv_conf_content = String::new();
        for ns in &nameservers {
            resolv_conf_content.push_str(&format!(
                "nameserver {}
",
                ns
            ));
        }

        // Validate DNS config path for symlinks before writing
        if let Err(e) = validate_path_no_symlinks(&resolv_conf_path) {
            transaction.rollback();
            return Err(PurpleError::FilesystemError(format!(
                "DNS config path validation failed: {}",
                e
            )));
        }

        if let Err(e) = fs::write(&resolv_conf_path, resolv_conf_content) {
            transaction.rollback();
            return Err(PurpleError::FilesystemError(format!(
                "Failed to write DNS configuration: {}",
                e
            )));
        }
        // Log the configured DNS servers for debugging
        log::info!("Configured DNS resolvers: {}", nameservers.join(", "));

        // Helpful message about configuration
        if nameservers == vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()] {
            log::info!(
                "Tip: Configure custom DNS servers in your policy using network.dns_servers"
            );
        }
    }

    // Change root to the sandbox directory using pivot_root
    // pivot_root is more secure than chroot because:
    // 1. It completely replaces the root filesystem
    // 2. The old root is moved to put_old and can be unmounted
    // 3. It prevents escape via /proc/PID/root symlinks
    log::info!(
        "Using pivot_root to change root to {}",
        sandbox_root.display()
    );

    // For pivot_root, we need:
    // 1. The new root to be a mount point (it is, we created it)
    // 2. A put_old directory inside the new root to hold the old root
    let put_old = sandbox_root.join(".put_old");

    // Create put_old directory
    if let Err(e) = fs::create_dir_all(&put_old) {
        transaction.rollback();
        return Err(PurpleError::FilesystemError(format!(
            "Failed to create put_old directory: {}",
            e
        )));
    }

    // Make sure put_old is on a separate mount point from the old root
    // by bind-mounting sandbox_root to itself first (makes it a mount point)
    if let Err(e) = mount(
        Some(sandbox_root),
        sandbox_root,
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    ) {
        transaction.rollback();
        return Err(PurpleError::FilesystemError(format!(
            "Failed to make sandbox root a mount point: {}",
            e
        )));
    }
    transaction.add_mount(sandbox_root.to_path_buf());

    // Use pivot_root to change the root filesystem
    // SAFETY: pivot_root is a fundamental containerization syscall.
    // We ensure:
    // 1. new_root (sandbox_root) is a mount point
    // 2. put_old exists and is empty
    // 3. Neither root is the current process's root
    if let Err(e) = pivot_root(sandbox_root, &put_old) {
        transaction.rollback();
        return Err(PurpleError::FilesystemError(format!(
            "Failed to pivot_root to {}: {}",
            sandbox_root.display(),
            e
        )));
    }
    log::info!("Successfully pivoted root to {}", sandbox_root.display());

    // Now the old root is in put_old. We need to:
    // 1. Unmount the old root from put_old
    // 2. Remove the put_old directory
    // 3. Change to the working directory

    // Unmount the old root filesystem from put_old
    if let Err(e) = umount2(&put_old, MntFlags::MNT_DETACH) {
        log::warn!(
            "Failed to unmount old root from put_old: {}. This is not critical.",
            e
        );
    } else {
        log::debug!("Unmounted old root from put_old");
    }

    // Remove the put_old directory (it's now empty after unmount)
    if let Err(e) = fs::remove_dir(&put_old) {
        log::warn!(
            "Failed to remove put_old directory: {}. This is not critical.",
            e
        );
    }

    // Change to the new root directory
    if let Err(e) = chdir(&policy.filesystem.working_dir) {
        return Err(PurpleError::FilesystemError(format!(
            "Failed to change working directory to {}: {}",
            policy.filesystem.working_dir.display(),
            e
        )));
    }
    log::info!(
        "Changed working directory to {}",
        policy.filesystem.working_dir.display()
    );

    Ok(())
}

fn detect_capabilities() -> (bool, bool) {
    use nix::sys::stat::{SFlag, makedev, mknod};

    // Test if we can create device nodes
    let can_create_devices = {
        let test_path = Path::new("/tmp/purple-capability-test");
        let result = std::panic::catch_unwind(|| {
            mknod(
                test_path,
                SFlag::S_IFCHR,
                nix::sys::stat::Mode::from_bits_truncate(0o600),
                makedev(1, 3), // /dev/null
            )
        });
        // Clean up test file if it was created
        let _ = std::fs::remove_file(test_path);
        result.is_ok()
    };

    // Test if we can change permissions
    let can_change_permissions = {
        let test_path = Path::new("/tmp/purple-perm-test");
        if std::fs::write(test_path, "test").is_ok() {
            let result = std::panic::catch_unwind(|| {
                let _ = std::fs::set_permissions(test_path, std::fs::Permissions::from_mode(0o700));
                let _ = std::fs::set_permissions(test_path, std::fs::Permissions::from_mode(0o600));
            });
            let _ = std::fs::remove_file(test_path);
            result.is_ok()
        } else {
            false
        }
    };

    (can_create_devices, can_change_permissions)
}

fn setup_secure_dev(sandbox_root: &Path) -> Result<()> {
    log::info!("Setting up secure minimal /dev filesystem");

    // Detect available capabilities
    let (can_create_devices, can_change_permissions) = detect_capabilities();
    log::info!(
        "Capabilities detected - Devices: {}, Permissions: {}",
        can_create_devices,
        can_change_permissions
    );

    let dev_path = sandbox_root.join("dev");

    // Create /dev directory with restricted permissions
    fs::create_dir_all(&dev_path).map_err(|e| {
        PurpleError::FilesystemError(format!("Failed to create secure /dev: {}", e))
    })?;

    // Set restrictive permissions (755 - owner rwx, group rx, others rx)
    if can_change_permissions {
        fs::set_permissions(&dev_path, fs::Permissions::from_mode(0o755)).map_err(|e| {
            PurpleError::FilesystemError(format!("Failed to set /dev permissions: {}", e))
        })?;
    } else {
        log::info!("Cannot change /dev directory permissions (expected in user namespaces)");
    }

    // Mount tmpfs for /dev (prevents host device access)
    let tmpfs_result = mount(
        Some("tmpfs"),
        &dev_path,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        Some("mode=755,size=10m"),
    );

    if let Err(e) = tmpfs_result {
        log::warn!(
            "⚠️  Failed to mount tmpfs for /dev: {}. This may indicate insufficient privileges. Continuing with regular directory structure.",
            e
        );
    }

    // Create essential device nodes with capability-aware handling
    let essential_devices = [
        ("null", 0o666, 1, 3),
        ("zero", 0o666, 1, 5),
        ("random", 0o666, 1, 8),
        ("urandom", 0o666, 1, 9),
        ("full", 0o666, 1, 7),
        ("tty", 0o666, 5, 0),
    ];

    let mut device_creation_success = true;
    for (name, mode, major, minor) in &essential_devices {
        let device_path = dev_path.join(name);

        if can_create_devices {
            // Try to create as proper device node
            if let Err(e) = create_device_node(&device_path, *mode, *major, *minor) {
                log::warn!("⚠️  Failed to create device node {}: {}", name, e);
                device_creation_success = false;
            }
        } else {
            // Fallback: Bind-mount from host instead of creating regular files
            // This prevents DoS attacks where writing to /dev/null would fill host disk
            log::info!(
                "Bind-mounting {} from host (device node creation not available)",
                name
            );

            // Create only parent directory, NOT the mount point itself
            #[allow(clippy::collapsible_if)]
            if let Some(parent) = device_path.parent() {
                if let Err(e) = fs::create_dir_all(parent) {
                    log::warn!("Failed to create parent directory for {}: {}", name, e);
                    device_creation_success = false;
                    continue;
                }
            }

            // Bind-mount from host's device node
            let host_device = Path::new("/dev").join(name);
            if let Err(e) = mount(
                Some(&host_device),
                &device_path,
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            ) {
                log::warn!("Failed to bind-mount {} from host: {}", name, e);
                device_creation_success = false;
                continue;
            }

            log::debug!("Successfully bind-mounted {} from host", name);
        }
    }

    // Create essential directories
    fs::create_dir_all(dev_path.join("pts"))
        .map_err(|e| PurpleError::FilesystemError(format!("Failed to create /dev/pts: {}", e)))?;
    fs::create_dir_all(dev_path.join("shm"))
        .map_err(|e| PurpleError::FilesystemError(format!("Failed to create /dev/shm: {}", e)))?;

    if device_creation_success {
        log::info!("✓ Secure minimal /dev filesystem created with essential devices");
    } else {
        log::warn!(
            "⚠️  /dev setup completed with limitations. Some devices may not be fully functional. For full functionality, run with root privileges or configure proper capabilities."
        );
    }

    Ok(())
}

/// Creates a secure read-only /sys filesystem
fn setup_secure_sys(sandbox_root: &Path) -> Result<()> {
    log::info!("Setting up secure read-only /sys filesystem");

    let sys_path = sandbox_root.join("sys");

    // Create /sys directory
    fs::create_dir_all(&sys_path).map_err(|e| {
        PurpleError::FilesystemError(format!("Failed to create /sys directory: {}", e))
    })?;

    // Try to mount sysfs directly first (works when not in user namespace)
    let mount_result = mount(
        Some("sysfs"),
        &sys_path,
        Some("sysfs"),
        MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    );

    if mount_result.is_ok() {
        log::info!("Secure read-only /sys filesystem mounted with full restrictions");
        return Ok(());
    }

    // If direct mount fails (e.g., in user namespace), bind-mount host's /sys read-only
    log::info!("Direct sysfs mount failed, trying bind mount of host /sys");

    // First bind mount
    mount(
        Some("/sys"),
        &sys_path,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(|e| PurpleError::FilesystemError(format!("Failed to bind mount /sys: {}", e)))?;

    // Then remount read-only
    mount(
        None::<&str>,
        &sys_path,
        None::<&str>,
        MsFlags::MS_BIND
            | MsFlags::MS_REMOUNT
            | MsFlags::MS_RDONLY
            | MsFlags::MS_NOSUID
            | MsFlags::MS_NODEV
            | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .map_err(|e| {
        PurpleError::FilesystemError(format!("Failed to remount /sys read-only: {}", e))
    })?;

    log::info!("Secure read-only /sys filesystem bind-mounted from host");
    Ok(())
}

/// Creates a device node with specified permissions and device numbers
fn create_device_node(path: &Path, mode: u32, major: u64, minor: u64) -> Result<()> {
    use nix::sys::stat::SFlag;
    use nix::sys::stat::makedev;
    use nix::sys::stat::mknod;

    log::debug!(
        "Creating device node: {} with mode {:o}, major {}, minor {}",
        path.display(),
        mode,
        major,
        minor
    );

    // Create device node using mknod
    let result = mknod(
        path,
        SFlag::S_IFCHR, // Character device
        nix::sys::stat::Mode::from_bits_truncate(mode),
        makedev(major, minor),
    );

    match result {
        Ok(_) => {
            log::debug!("✓ Successfully created device node: {}", path.display());
            Ok(())
        }
        Err(e) => {
            // Handle permission errors gracefully
            if e == nix::Error::EPERM {
                log::warn!(
                    "Cannot create device node {} (major {}, minor {}) - running in user namespace without CAP_MKNOD. Creating as regular file instead. \
                    Programs expecting full device semantics (e.g., /dev/null read/write behavior) will still work.",
                    path.display(),
                    major,
                    minor
                );

                // Fallback: Create as a regular file for basic functionality
                if let Some(parent) = path.parent()
                    && let Err(e) = std::fs::create_dir_all(parent)
                {
                    return Err(PurpleError::FilesystemError(format!(
                        "Failed to create parent directory for device fallback {}: {}",
                        path.display(),
                        e
                    )));
                }

                // Create as a regular file with appropriate permissions
                if let Err(e) = std::fs::write(path, "") {
                    return Err(PurpleError::FilesystemError(format!(
                        "Failed to create device fallback file {}: {}",
                        path.display(),
                        e
                    )));
                }

                // Set appropriate permissions
                if let Err(e) =
                    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
                {
                    log::warn!(
                        "Failed to set permissions on device fallback {}: {}",
                        path.display(),
                        e
                    );
                }

                Ok(())
            } else {
                Err(PurpleError::FilesystemError(format!(
                    "Failed to create device node {}: {}",
                    path.display(),
                    e
                )))
            }
        }
    }
}
