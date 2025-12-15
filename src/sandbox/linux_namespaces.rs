// purple/src/sandbox/linux_namespaces.rs

use nix::sched::{unshare, CloneFlags};
use nix::unistd::{setgroups, setresgid, setresuid, Gid, Uid};
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
    // Unshare user namespace
    unshare(CloneFlags::CLONE_NEWUSER).map_err(|e| format!("Failed to unshare user namespace: {}", e))?;
    log::info!("User namespace unshared.");

    // Map current real user ID (ruid) and group ID (rgid) to unprivileged IDs within the new namespace.
    // In a real scenario, you might map to a specific unprivileged user like 'nobody'
    // or a dedicated user for the sandbox. For now, we map '0' (root inside container) to
    // current real UID outside.
    let ruid = Uid::current();
    let rgid = Gid::current();

    // Write UID map
    let uid_map_path = PathBuf::from("/proc/self/uid_map");
    let mut uid_map_file = fs::File::options().write(true).open(&uid_map_path)
        .map_err(|e| format!("Failed to open {}: {}", uid_map_path.display(), e))?;
    // Format: "container_id host_id length"
    // Mapping current user (ruid) to UID 0 inside the new namespace
    let uid_map_content = format!("0 {} 1\n", ruid);
    uid_map_file.write_all(uid_map_content.as_bytes())
        .map_err(|e| format!("Failed to write to {}: {}", uid_map_path.display(), e))?;
    log::info!("UID map written: {}", uid_map_content.trim());

    // Deny setgroups
    // This is important for security to prevent privilege escalation attempts
    // from manipulating group memberships.
    let setgroups_path = PathBuf::from("/proc/self/setgroups");
    let mut setgroups_file = fs::File::options().write(true).open(&setgroups_path)
        .map_err(|e| format!("Failed to open {}: {}", setgroups_path.display(), e))?;
    setgroups_file.write_all(b"deny\n")
        .map_err(|e| format!("Failed to write 'deny' to {}: {}", setgroups_path.display(), e))?;
    log::info!("setgroups denied.");

    // Write GID map
    let gid_map_path = PathBuf::from("/proc/self/gid_map");
    let mut gid_map_file = fs::File::options().write(true).open(&gid_map_path)
        .map_err(|e| format!("Failed to open {}: {}", gid_map_path.display(), e))?;
    // Mapping current group (rgid) to GID 0 inside the new namespace
    let gid_map_content = format!("0 {} 1\n", rgid);
    gid_map_file.write_all(gid_map_content.as_bytes())
        .map_err(|e| format!("Failed to write to {}: {}", gid_map_path.display(), e))?;
    log::info!("GID map written: {}", gid_map_content.trim());

    // Set new UIDs/GIDs within the namespace. After mapping,
    // the process can set its IDs to 0 (root inside new namespace)
    // without requiring root privileges outside.
    setgroups(&[Gid::from_raw(0)]).map_err(|e| format!("Failed to setgroups in new user namespace: {}", e))?;
    setresgid(Gid::from_raw(0), Gid::from_raw(0), Gid::from_raw(0)).map_err(|e| format!("Failed to setresgid in new user namespace: {}", e))?;
    setresuid(Uid::from_raw(0), Uid::from_raw(0), Uid::from_raw(0)).map_err(|e| format!("Failed to setresuid in new user namespace: {}", e))?;
    log::info!("User/Group IDs set to 0 (root within new namespace).");

    Ok((Uid::from_raw(0), Gid::from_raw(0)))
}

/// Creates a new PID namespace.
/// Processes inside this namespace will have their own PID 1.
pub fn unshare_pid_namespace() -> Result<(), String> {
    unshare(CloneFlags::CLONE_NEWPID).map_err(|e| format!("Failed to unshare PID namespace: {}", e))?;
    log::info!("PID namespace unshared.");
    Ok(())
}

/// Creates a new mount namespace.
/// This allows the sandbox to have its own view of the filesystem mounts.
pub fn unshare_mount_namespace() -> Result<(), String> {
    unshare(CloneFlags::CLONE_NEWNS).map_err(|e| format!("Failed to unshare mount namespace: {}", e))?;
    log::info!("Mount namespace unshared.");
    // Make sure the new mount namespace doesn't inherit mounts from the parent.
    // This is crucial before performing any bind mounts.
    nix::mount::mount(
        None::<&Path>, // source
        Path::new("/"), // target
        None::<&CStr>, // fstype
        nix::mount::MsFlags::MS_REC | nix::mount::MsFlags::MS_PRIVATE,
        None::<&CStr>, // data
    ).map_err(|e| format!("Failed to make root filesystem private: {}", e))?;
    log::info!("Root filesystem made private.");
    Ok(())
}

/// Creates a new network namespace.
/// This isolates the sandbox from the host network.
pub fn unshare_network_namespace() -> Result<(), String> {
    unshare(CloneFlags::CLONE_NEWNET).map_err(|e| format!("Failed to unshare network namespace: {}", e))?;
    log::info!("Network namespace unshared.");
    // In a real implementation, you would then set up a veth pair to connect to the host or provide no network.
    Ok(())
}
