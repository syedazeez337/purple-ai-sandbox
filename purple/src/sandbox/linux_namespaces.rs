// purple/src/sandbox/linux_namespaces.rs

use nix::sched::{CloneFlags, unshare};
use nix::unistd::{Gid, Uid, setresgid, setresuid};
use std::ffi::CStr; // Added import
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf}; // Added Path import

/// Creates a new user namespace and maps the current user and group IDs.
///
/// This is a critical step for isolation, as it allows the sandboxed process to run as
/// an unprivileged user (e.g., nobody) inside the sandbox, while its parent process
/// can still manage it.
///
/// Returns the new UID and GID for the sandboxed process if successful.
pub fn unshare_user_namespace() -> Result<(Uid, Gid), String> {
    // Capture current real user ID (ruid) and group ID (rgid) BEFORE unsharing.
    // Once we unshare, we are in a new namespace where we don't exist yet (overflow UID),
    // so we need these original IDs to create the mapping.
    let ruid = Uid::current();
    let rgid = Gid::current();

    // Unshare user namespace
    unshare(CloneFlags::CLONE_NEWUSER)
        .map_err(|e| {
            if e == nix::errno::Errno::EINVAL {
                format!("Failed to unshare user namespace: {}. This can happen if user namespaces are disabled, the process is multi-threaded, or you are already in a restricted nested namespace environment.", e)
            } else {
                format!("Failed to unshare user namespace: {}", e)
            }
        })?;
    log::info!("User namespace unshared.");

    // Write "deny" to setgroups FIRST.
    // This is strictly required before writing to gid_map for unprivileged users,
    // and good practice to do early.
    let setgroups_path = PathBuf::from("/proc/self/setgroups");
    match fs::File::options().write(true).open(&setgroups_path) {
        Ok(mut setgroups_file) => {
            if let Err(e) = setgroups_file.write_all(b"deny\n") {
                return Err(format!(
                    "Failed to write 'deny' to {}: {}",
                    setgroups_path.display(),
                    e
                ));
            }
            log::info!("setgroups denied.");
        }
        Err(e) => {
            // In some container environments (like GitHub Actions runners or Docker with certain profiles),
            // opening setgroups might fail with EPERM even after unshare.
            // Check if setgroups is already denied before proceeding
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                // Verify setgroups is already denied by reading current value
                let current = fs::read_to_string(&setgroups_path).unwrap_or_default();
                if current.trim() == "deny" {
                    log::info!("setgroups already denied");
                } else {
                    return Err(format!(
                        "Cannot write to {} and it's not already denied. Current value: '{}'. \
                         This is a security requirement. Error: {}",
                        setgroups_path.display(),
                        current.trim(),
                        e
                    ));
                }
            } else {
                return Err(format!(
                    "Failed to open {}: {}",
                    setgroups_path.display(),
                    e
                ));
            }
        }
    }

    // Write UID map
    let uid_map_path = PathBuf::from("/proc/self/uid_map");
    match fs::File::options().write(true).open(&uid_map_path) {
        Ok(mut uid_map_file) => {
            let uid_map_content = format!("0 {} 1\n", ruid);
            if let Err(e) = uid_map_file.write_all(uid_map_content.as_bytes()) {
                return Err(format!(
                    "Failed to write to {}: {}",
                    uid_map_path.display(),
                    e
                ));
            } else {
                log::info!("UID map written: {}", uid_map_content.trim());
            }
        }
        Err(e) => return Err(format!("Failed to open {}: {}", uid_map_path.display(), e)),
    }

    // Write GID map
    let gid_map_path = PathBuf::from("/proc/self/gid_map");
    match fs::File::options().write(true).open(&gid_map_path) {
        Ok(mut gid_map_file) => {
            let gid_map_content = format!("0 {} 1\n", rgid);
            if let Err(e) = gid_map_file.write_all(gid_map_content.as_bytes()) {
                return Err(format!(
                    "Failed to write to {}: {}",
                    gid_map_path.display(),
                    e
                ));
            } else {
                log::info!("GID map written: {}", gid_map_content.trim());
            }
        }
        Err(e) => return Err(format!("Failed to open {}: {}", gid_map_path.display(), e)),
    }

    // Set new UIDs/GIDs within the namespace. After mapping,
    // the process can set its IDs to 0 (root inside new namespace)
    // without requiring root privileges outside.
    // Note: setgroups is not allowed because we wrote "deny" to /proc/self/setgroups
    // setgroups(&[Gid::from_raw(0)]).map_err(|e| format!("Failed to setgroups in new user namespace: {}", e))?;

    setresgid(Gid::from_raw(0), Gid::from_raw(0), Gid::from_raw(0))
        .map_err(|e| format!("Failed to setresgid in new user namespace: {}", e))?;
    setresuid(Uid::from_raw(0), Uid::from_raw(0), Uid::from_raw(0))
        .map_err(|e| format!("Failed to setresuid in new user namespace: {}", e))?;
    log::info!("User/Group IDs set to 0 (root within new namespace).");

    Ok((Uid::from_raw(0), Gid::from_raw(0)))
}

/// Creates a new PID namespace.
/// Processes inside this namespace will have their own PID 1.
pub fn unshare_pid_namespace() -> Result<(), String> {
    unshare(CloneFlags::CLONE_NEWPID)
        .map_err(|e| format!("Failed to unshare PID namespace: {}", e))?;
    log::info!("PID namespace unshared.");
    Ok(())
}

/// Creates a new mount namespace.
/// This allows the sandbox to have its own view of the filesystem mounts.
/// Uses MS_SHARED propagation so that bind mounts created in the parent
/// are visible in this child namespace - critical for pivot_root to work.
pub fn unshare_mount_namespace() -> Result<(), String> {
    unshare(CloneFlags::CLONE_NEWNS)
        .map_err(|e| format!("Failed to unshare mount namespace: {}", e))?;
    log::info!("Mount namespace unshared.");

    // CRITICAL: Use SHARED propagation so parent's bind mounts are visible.
    // Without this, bind mounts created before fork won't be visible after
    // we enter the mount namespace, causing "command not found" errors.
    nix::mount::mount(
        None::<&Path>,
        Path::new("/"),
        None::<&CStr>,
        nix::mount::MsFlags::MS_REC | nix::mount::MsFlags::MS_SHARED,
        None::<&CStr>,
    )
    .map_err(|e| format!("Failed to make root filesystem shared: {}", e))?;
    log::info!("Root filesystem set to shared propagation.");

    Ok(())
}

/// Creates a new network namespace.
/// This isolates the sandbox from the host network.
pub fn unshare_network_namespace() -> Result<(), String> {
    unshare(CloneFlags::CLONE_NEWNET)
        .map_err(|e| format!("Failed to unshare network namespace: {}", e))?;
    log::info!("Network namespace unshared.");
    // In a real implementation, you would then set up a veth pair to connect to the host or provide no network.
    Ok(())
}
