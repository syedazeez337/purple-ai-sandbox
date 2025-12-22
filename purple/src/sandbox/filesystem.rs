use crate::error::{PurpleError, Result};
use crate::policy::compiler::CompiledPolicy;
use nix::mount::{MsFlags, mount};
use nix::unistd::chroot;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use std::os::unix::fs::OpenOptionsExt;

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

/// Setup filesystem isolation
pub fn setup_filesystem(policy: &CompiledPolicy, sandbox_root: &Path) -> Result<()> {
    log::info!("Setting up filesystem isolation...");

    // Create temporary directory structure for the sandbox
    fs::create_dir_all(sandbox_root).map_err(|e| {
        PurpleError::FilesystemError(format!("Failed to create sandbox root: {}", e))
    })?;

    // Create necessary directories
    let directories = [
        "bin", "lib", "lib64", "usr", "usr/bin", "usr/lib", "tmp", "var", "var/tmp", "proc", "dev",
        "sys",
    ];

    for dir in directories.iter() {
        let path = Path::new(sandbox_root).join(dir);
        fs::create_dir_all(&path).map_err(|e| {
            PurpleError::FilesystemError(format!(
                "Failed to create directory {}: {}",
                path.display(),
                e
            ))
        })?;
    }

    // Setup bind mounts for immutable paths
    for (host_path, sandbox_path) in &policy.filesystem.immutable_mounts {
        let full_sandbox_path = Path::new(sandbox_root).join(
            sandbox_path
                .strip_prefix("/")
                .unwrap_or(sandbox_path.as_path()),
        );

        // Create parent directory if it doesn't exist
        if let Some(parent) = full_sandbox_path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                PurpleError::FilesystemError(format!(
                    "Failed to create parent directory {}: {}",
                    parent.display(),
                    e
                ))
            })?;
        }

        // Create the mount point (file or directory)
        if host_path.is_dir() {
            fs::create_dir_all(&full_sandbox_path).map_err(|e| {
                PurpleError::FilesystemError(format!(
                    "Failed to create mount point directory {}: {}",
                    full_sandbox_path.display(),
                    e
                ))
            })?;
        } else {
            // Assume it's a file - create empty file as mount point (TOCTOU-safe)
            safe_create_file(&full_sandbox_path)?;
        }

        log::info!(
            "Binding {} to {}",
            host_path.display(),
            full_sandbox_path.display()
        );

        // Bind mount the host path to the sandbox path
        mount(
            Some(host_path.as_path()),
            &full_sandbox_path,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .map_err(|e| {
            PurpleError::FilesystemError(format!(
                "Failed to bind mount {} to {}: {}",
                host_path.display(),
                full_sandbox_path.display(),
                e
            ))
        })?;

        // Make it read-only
        mount(
            None::<&str>,
            &full_sandbox_path,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
            None::<&str>,
        )
        .map_err(|e| {
            PurpleError::FilesystemError(format!(
                "Failed to remount {} as read-only: {}",
                full_sandbox_path.display(),
                e
            ))
        })?;
    }

    // Setup scratch directories
    for scratch_path in &policy.filesystem.scratch_dirs {
        let full_sandbox_path = Path::new(sandbox_root).join(
            scratch_path
                .strip_prefix("/")
                .unwrap_or(scratch_path.as_path()),
        );

        if let Some(parent) = full_sandbox_path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                PurpleError::FilesystemError(format!(
                    "Failed to create parent directory {}: {}",
                    parent.display(),
                    e
                ))
            })?;
        }

        fs::create_dir_all(&full_sandbox_path).map_err(|e| {
            PurpleError::FilesystemError(format!(
                "Failed to create scratch directory {}: {}",
                full_sandbox_path.display(),
                e
            ))
        })?;
    }

    // Setup output directories (writable)
    for (host_path, sandbox_path) in &policy.filesystem.output_mounts {
        let full_sandbox_path = Path::new(sandbox_root).join(
            sandbox_path
                .strip_prefix("/")
                .unwrap_or(sandbox_path.as_path()),
        );

        if let Some(parent) = full_sandbox_path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                PurpleError::FilesystemError(format!(
                    "Failed to create parent directory {}: {}",
                    parent.display(),
                    e
                ))
            })?;
        }

        fs::create_dir_all(&full_sandbox_path).map_err(|e| {
            PurpleError::FilesystemError(format!(
                "Failed to create output directory {}: {}",
                full_sandbox_path.display(),
                e
            ))
        })?;

        // Bind mount output directory
        mount(
            Some(host_path.as_path()),
            &full_sandbox_path,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .map_err(|e| {
            PurpleError::FilesystemError(format!(
                "Failed to bind mount output directory {} to {}: {}",
                host_path.display(),
                full_sandbox_path.display(),
                e
            ))
        })?;
    }

    // Mount essential filesystem
    // CORRECT: Mount fresh procfs
    mount(
        Some("proc"),
        &Path::new(sandbox_root).join("proc"),
        Some("proc"),
        MsFlags::empty(),
        None::<&str>,
    )
    .map_err(|e| PurpleError::FilesystemError(format!("Failed to mount proc: {}", e)))?;

    // SECURE: Create minimal /dev with only essential devices
    setup_secure_dev(sandbox_root)?;

    // SECURE: Mount /sys as read-only with security restrictions
    setup_secure_sys(sandbox_root)?;

    // Setup DNS configuration for network access
    if !policy.network.isolated {
        let resolv_conf_path = Path::new(sandbox_root).join("etc/resolv.conf");
        if let Some(parent) = resolv_conf_path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                PurpleError::FilesystemError(format!(
                    "Failed to create DNS config directory {}: {}",
                    parent.display(),
                    e
                ))
            })?;
        }

        // Configurable DNS servers with validation
        let nameservers = if let Some(servers) = &policy.network.dns_servers {
            // Validate DNS server formats
            let mut valid_servers = Vec::new();
            for server in servers {
                // Basic validation: should be IPv4, IPv6, or hostname
                if server.contains('.') || server.contains(':') {
                    valid_servers.push(server.clone());
                } else {
                    log::warn!("Invalid DNS server format '{}' - skipping", server);
                }
            }

            if valid_servers.is_empty() {
                log::warn!("No valid DNS servers in policy, using defaults");
                vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()]
            } else {
                valid_servers
            }
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
        validate_path_no_symlinks(&resolv_conf_path)?;

        fs::write(&resolv_conf_path, resolv_conf_content).map_err(|e| {
            PurpleError::FilesystemError(format!("Failed to write DNS configuration: {}", e))
        })?;
        // Log the configured DNS servers for debugging
        log::info!("Configured DNS resolvers: {}", nameservers.join(", "));

        // Helpful message about configuration
        if nameservers == vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()] {
            log::info!(
                "💡 Tip: Configure custom DNS servers in your policy using network.dns_servers"
            );
        }
    }

    // Change root to the sandbox directory
    log::info!("Changing root to {}", sandbox_root.display());
    chroot(sandbox_root).map_err(|e| {
        PurpleError::FilesystemError(format!(
            "Failed to chroot to {}: {}",
            sandbox_root.display(),
            e
        ))
    })?;

    // Change working directory
    if let Err(e) = std::env::set_current_dir(&policy.filesystem.working_dir) {
        return Err(PurpleError::FilesystemError(format!(
            "Failed to change working directory to {}: {}",
            policy.filesystem.working_dir.display(),
            e
        )));
    }

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
            // Fallback: Create as regular file with appropriate content
            log::info!(
                "Creating {} as regular file (device node creation not available)",
                name
            );

            // Create parent directory if needed
            if let Some(parent) = device_path.parent()
                && let Err(e) = fs::create_dir_all(parent)
            {
                log::warn!("Failed to create parent directory for {}: {}", name, e);
                device_creation_success = false;
                continue;
            }

            // Create file with appropriate permissions
            if let Err(e) = fs::write(&device_path, "") {
                log::warn!("Failed to create fallback file for {}: {}", name, e);
                device_creation_success = false;
                continue;
            }

            // Set permissions if possible
            if can_change_permissions
                && let Err(e) = fs::set_permissions(&device_path, fs::Permissions::from_mode(*mode))
            {
                log::debug!("Failed to set permissions on {}: {}", name, e);
            }
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
                    "⚠️  Insufficient permissions to create device node {} (major {}, minor {}). This is expected when running without root privileges. Device will be created as a regular file with similar behavior.",
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
