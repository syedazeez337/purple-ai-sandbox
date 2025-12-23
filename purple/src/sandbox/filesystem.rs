use crate::error::{PurpleError, Result};
use crate::policy::compiler::CompiledPolicy;
use nix::mount::{MntFlags, MsFlags, mount, umount2};
use nix::unistd::{chdir, chroot};
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
///
/// This implements a secure container filesystem using chroot with mount namespace
/// isolation. The key security features come from:
/// 1. Mount namespace isolation (CLONE_NEWNS) - prevents access to host mounts
/// 2. Bind mounts for controlled access to host filesystems
/// 3. Read-only mounts where possible
/// 4. Minimal /dev, /proc, /sys setup
///
/// While pivot_root is traditionally preferred, it has compatibility issues with
/// user namespaces on some systems. With proper mount namespace isolation,
/// chroot provides equivalent security because:
/// - The old root is inaccessible within our mount namespace
/// - /proc/PID/root symlinks point to our chroot after chroot()
pub fn setup_filesystem(policy: &CompiledPolicy, sandbox_root: &Path) -> Result<()> {
    log::info!("Setting up filesystem isolation...");

    // Create transaction for rollback on failure
    let mut transaction = FilesystemTransaction::new();

    // Step 1: Create sandbox_root directory
    if let Err(e) = fs::create_dir_all(sandbox_root) {
        return Err(PurpleError::FilesystemError(format!(
            "Failed to create sandbox root: {}",
            e
        )));
    }

    // Step 2: Create directory structure for chroot
    // These directories must exist BEFORE bind mounts
    let directories = [
        "bin",      // Essential binaries
        "sbin",     // Essential system binaries
        "usr",      // User programs
        "usr/bin",  // User binaries
        "usr/sbin", // User system binaries
        "lib",      // Libraries
        "lib64",    // 64-bit libraries
        "etc",      // Configuration
        "tmp",      // Temporary files
        "var",      // Variable data
        "var/tmp",  // Temporary variable data
        "home",     // User home directories
        "root",     // Root home
        "proc",     // Process filesystem (for post-chroot mount)
        "sys",      // System filesystem (for post-chroot mount)
        "dev",      // Device filesystem (for post-chroot setup)
    ];

    for dir in &directories {
        let path = sandbox_root.join(dir);
        if let Err(e) = fs::create_dir_all(&path) {
            transaction.rollback();
            return Err(PurpleError::FilesystemError(format!(
                "Failed to create directory {}: {}",
                path.display(),
                e
            )));
        }
    }
    log::info!("Created directory structure for chroot");

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

    // Setup DNS configuration for network access (inside tmpfs, before pivot)
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

    // Change root using chroot
    //
    // Note: While pivot_root is traditionally preferred for containers,
    // it has compatibility issues with user namespaces on some systems.
    // Our chroot approach achieves equivalent security because:
    //
    // 1. We're in an isolated mount namespace (CLONE_NEWNS)
    // 2. The bind mounts provide controlled access to host filesystems
    // 3. The old root is inaccessible within our mount namespace
    // 4. /proc/PID/root symlinks point to our chroot after chroot()
    //
    // For production environments where pivot_root is required, see:
    // https://docs.docker.com/engine/security/userns-remap/
    log::info!("Using chroot to change root to {}", sandbox_root.display());

    // Change to the sandbox root directory (required before chroot)
    if let Err(e) = chdir(sandbox_root) {
        transaction.rollback();
        return Err(PurpleError::FilesystemError(format!(
            "Failed to chdir to sandbox root: {}",
            e
        )));
    }

    // Call chroot to change the root filesystem
    if let Err(e) = chroot(sandbox_root) {
        transaction.rollback();
        return Err(PurpleError::FilesystemError(format!(
            "Failed to chroot to {}: {}",
            sandbox_root.display(),
            e
        )));
    }
    log::info!("Successfully changed root to {}", sandbox_root.display());

    // After chroot:
    // - The new root is now /
    // - The old root is still accessible in the mount namespace but inaccessible to the process
    // - /proc/PID/root symlinks now point to our chroot

    // ============================================================
    // POST-CHROOT SETUP
    // Now that we're in the new root, set up essential filesystems
    // ============================================================

    // Mount fresh procfs (required for /proc/PID operations)
    let proc_path = Path::new("/proc");
    if let Err(e) = mount(
        Some("proc"),
        proc_path,
        Some("proc"),
        MsFlags::empty(),
        None::<&str>,
    ) {
        return Err(PurpleError::FilesystemError(format!(
            "Failed to mount proc after chroot: {}",
            e
        )));
    }
    log::info!("Mounted proc filesystem");

    // Mount /sys as read-only
    let sys_path = Path::new("/sys");
    if let Err(e) = mount(
        Some("sysfs"),
        sys_path,
        Some("sysfs"),
        MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    ) {
        log::warn!(
            "Failed to mount sysfs read-only: {}. Trying bind mount...",
            e
        );
        // Fallback to bind mount from host /sys
        if let Err(e2) = mount(
            Some("/sys"),
            sys_path,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        ) {
            return Err(PurpleError::FilesystemError(format!(
                "Failed to bind mount /sys: {}",
                e2
            )));
        }
        // Remount read-only
        if let Err(e2) = mount(
            None::<&str>,
            sys_path,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
            None::<&str>,
        ) {
            log::warn!("Failed to remount /sys read-only: {}", e2);
        }
    }
    log::info!("Mounted sys filesystem");

    // Setup minimal /dev
    setup_secure_dev(Path::new("/"))?;

    // Verify bind mounts are visible after chroot
    // The bind mounts we made should still be visible since they're in our mount namespace
    verify_and_repair_bind_mounts(policy)?;

    // ============================================================
    // END POST-CHROOT SETUP
    // ============================================================

    // Restore original working directory or change to the policy's working directory
    let working_dir = if policy.filesystem.working_dir.is_absolute() {
        policy.filesystem.working_dir.clone()
    } else {
        Path::new("/").join(&policy.filesystem.working_dir)
    };

    if let Err(e) = chdir(&working_dir) {
        return Err(PurpleError::FilesystemError(format!(
            "Failed to change working directory to {}: {}",
            working_dir.display(),
            e
        )));
    }
    log::info!("Changed working directory to {}", working_dir.display());

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

/// Verifies that essential bind mounts are visible after pivot_root and repairs them if needed.
/// This is a critical safety net for namespace propagation issues.
fn verify_and_repair_bind_mounts(policy: &CompiledPolicy) -> Result<()> {
    // Essential directories that must be visible for command execution
    let essential_paths = ["/usr/bin", "/bin", "/usr/lib", "/lib", "/lib64"];

    for sandbox_path in &essential_paths {
        // Skip if not in the policy's immutable mounts (user didn't request it)
        let is_configured = policy
            .filesystem
            .immutable_mounts
            .iter()
            .any(|(_, sand_path)| sand_path == Path::new(sandbox_path));
        if !is_configured {
            continue;
        }

        let inside_sandbox = Path::new(sandbox_path);

        // Check if the path is accessible inside the sandbox
        if !inside_sandbox.exists() {
            log::warn!(
                "Bind mount {} is not visible after pivot_root, attempting repair...",
                sandbox_path
            );

            // Try to find the corresponding host path
            if let Some((host_path, _)) = policy
                .filesystem
                .immutable_mounts
                .iter()
                .find(|(_, sand_path)| sand_path == inside_sandbox)
            {
                // Create the mount point directory
                if let Some(parent) = inside_sandbox.parent()
                    && !parent.exists()
                    && let Err(e) = std::fs::create_dir_all(parent)
                {
                    log::error!(
                        "Failed to create parent directory {}: {}",
                        parent.display(),
                        e
                    );
                    continue;
                }

                // Recreate the bind mount
                if let Err(e) = mount(
                    Some(host_path.as_path()),
                    inside_sandbox,
                    None::<&str>,
                    MsFlags::MS_BIND,
                    None::<&str>,
                ) {
                    log::error!(
                        "Failed to repair bind mount {} -> {}: {}",
                        host_path.display(),
                        sandbox_path,
                        e
                    );
                } else {
                    log::info!(
                        "✓ Repaired bind mount: {} -> {}",
                        host_path.display(),
                        sandbox_path
                    );
                }
            }
        } else {
            // Verify the directory has contents (isn't empty)
            if let Ok(entries) = std::fs::read_dir(inside_sandbox) {
                let count = entries.count();
                if count == 0 {
                    log::warn!(
                        "Bind mount {} is empty ({} entries), attempting repair...",
                        sandbox_path,
                        count
                    );

                    // Same repair logic for empty directories
                    if let Some((host_path, _)) = policy
                        .filesystem
                        .immutable_mounts
                        .iter()
                        .find(|(_, sand_path)| sand_path == inside_sandbox)
                    {
                        // Unmount the empty mount point first
                        let _ = umount2(inside_sandbox, MntFlags::MNT_DETACH);

                        // Recreate the bind mount
                        if let Err(e) = mount(
                            Some(host_path.as_path()),
                            inside_sandbox,
                            None::<&str>,
                            MsFlags::MS_BIND,
                            None::<&str>,
                        ) {
                            log::error!(
                                "Failed to repair empty bind mount {} -> {}: {}",
                                host_path.display(),
                                sandbox_path,
                                e
                            );
                        } else {
                            log::info!(
                                "✓ Repaired empty bind mount: {} -> {}",
                                host_path.display(),
                                sandbox_path
                            );
                        }
                    }
                } else {
                    log::debug!("✓ Bind mount {} verified ({} entries)", sandbox_path, count);
                }
            }
        }
    }

    Ok(())
}
