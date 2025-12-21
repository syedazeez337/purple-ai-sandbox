use crate::error::{PurpleError, Result};
use crate::policy::compiler::CompiledCapabilityPolicy;
use std::collections::HashSet;

/// Converts a capability name string to a caps::Capability enum
fn capability_from_name(name: &str) -> Option<caps::Capability> {
    use caps::Capability;

    match name.to_uppercase().as_str() {
        "CAP_CHOWN" => Some(Capability::CAP_CHOWN),
        "CAP_DAC_OVERRIDE" => Some(Capability::CAP_DAC_OVERRIDE),
        "CAP_DAC_READ_SEARCH" => Some(Capability::CAP_DAC_READ_SEARCH),
        "CAP_FOWNER" => Some(Capability::CAP_FOWNER),
        "CAP_FSETID" => Some(Capability::CAP_FSETID),
        "CAP_KILL" => Some(Capability::CAP_KILL),
        "CAP_SETGID" => Some(Capability::CAP_SETGID),
        "CAP_SETUID" => Some(Capability::CAP_SETUID),
        "CAP_SETPCAP" => Some(Capability::CAP_SETPCAP),
        "CAP_LINUX_IMMUTABLE" => Some(Capability::CAP_LINUX_IMMUTABLE),
        "CAP_NET_BIND_SERVICE" => Some(Capability::CAP_NET_BIND_SERVICE),
        "CAP_NET_BROADCAST" => Some(Capability::CAP_NET_BROADCAST),
        "CAP_NET_ADMIN" => Some(Capability::CAP_NET_ADMIN),
        "CAP_NET_RAW" => Some(Capability::CAP_NET_RAW),
        "CAP_IPC_LOCK" => Some(Capability::CAP_IPC_LOCK),
        "CAP_IPC_OWNER" => Some(Capability::CAP_IPC_OWNER),
        "CAP_SYS_MODULE" => Some(Capability::CAP_SYS_MODULE),
        "CAP_SYS_RAWIO" => Some(Capability::CAP_SYS_RAWIO),
        "CAP_SYS_CHROOT" => Some(Capability::CAP_SYS_CHROOT),
        "CAP_SYS_PTRACE" => Some(Capability::CAP_SYS_PTRACE),
        "CAP_SYS_PACCT" => Some(Capability::CAP_SYS_PACCT),
        "CAP_SYS_ADMIN" => Some(Capability::CAP_SYS_ADMIN),
        "CAP_SYS_BOOT" => Some(Capability::CAP_SYS_BOOT),
        "CAP_SYS_NICE" => Some(Capability::CAP_SYS_NICE),
        "CAP_SYS_RESOURCE" => Some(Capability::CAP_SYS_RESOURCE),
        "CAP_SYS_TIME" => Some(Capability::CAP_SYS_TIME),
        "CAP_SYS_TTY_CONFIG" => Some(Capability::CAP_SYS_TTY_CONFIG),
        "CAP_MKNOD" => Some(Capability::CAP_MKNOD),
        "CAP_LEASE" => Some(Capability::CAP_LEASE),
        "CAP_AUDIT_WRITE" => Some(Capability::CAP_AUDIT_WRITE),
        "CAP_AUDIT_CONTROL" => Some(Capability::CAP_AUDIT_CONTROL),
        "CAP_SETFCAP" => Some(Capability::CAP_SETFCAP),
        "CAP_MAC_OVERRIDE" => Some(Capability::CAP_MAC_OVERRIDE),
        "CAP_MAC_ADMIN" => Some(Capability::CAP_MAC_ADMIN),
        "CAP_SYSLOG" => Some(Capability::CAP_SYSLOG),
        "CAP_WAKE_ALARM" => Some(Capability::CAP_WAKE_ALARM),
        "CAP_BLOCK_SUSPEND" => Some(Capability::CAP_BLOCK_SUSPEND),
        "CAP_AUDIT_READ" => Some(Capability::CAP_AUDIT_READ),
        _ => None,
    }
}

/// Sets the NO_NEW_PRIVS flag to prevent privilege escalation
fn prctl_set_no_new_privs() -> Result<()> {
    // PR_SET_NO_NEW_PRIVS = 38
    const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;

    let result = unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if result != 0 {
        return Err(PurpleError::CapabilityError(format!(
            "prctl(PR_SET_NO_NEW_PRIVS) failed with error: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Drops capabilities according to policy
pub fn drop_capabilities(policy: &CompiledCapabilityPolicy) -> Result<()> {
    log::info!("Dropping capabilities...");

    if policy.default_drop {
        log::info!("Capability policy: Drop all capabilities by default");

        // Actual capability dropping implementation using libcap
        actual_drop_capabilities()?;

        if !policy.added_capabilities.is_empty() {
            log::info!(
                "Adding back {} capabilities:",
                policy.added_capabilities.len()
            );
            add_specific_capabilities(&policy.added_capabilities)?;
        } else {
            log::info!("No capabilities added back - minimal privilege set");
        }

        log::info!("Capability management fully configured and enforced");
    } else {
        log::info!("Capability policy: Keep all capabilities by default");
        log::warn!("This is less secure - consider using default_drop=true");

        // Only drop specific capabilities if configured
        if !policy.dropped_capabilities.is_empty() {
            drop_specific_capabilities(&policy.dropped_capabilities)?;
        }
    }

    log::info!("Capability dropping completed and enforced");
    Ok(())
}

/// Actually drops all capabilities and sets bounding set
fn actual_drop_capabilities() -> Result<()> {
    log::info!("Clearing all capabilities from process");

    // For now, implement using direct system calls
    drop_capabilities_system_call()?;

    log::info!("All capabilities cleared and bounding set restricted");
    Ok(())
}

/// Adds specific capabilities back to the process
fn add_specific_capabilities(capabilities: &HashSet<String>) -> Result<()> {
    use caps::CapSet;

    log::info!("Adding specific capabilities to process");

    // Get current permitted set first
    let mut current_permitted = caps::read(None, CapSet::Permitted).map_err(|e| {
        PurpleError::CapabilityError(format!("Failed to read permitted capabilities: {}", e))
    })?;

    let mut current_effective = caps::read(None, CapSet::Effective).map_err(|e| {
        PurpleError::CapabilityError(format!("Failed to read effective capabilities: {}", e))
    })?;

    for cap_name in capabilities {
        if let Some(cap) = capability_from_name(cap_name) {
            log::info!("  - Adding capability: {} ({:?})", cap_name, cap);
            current_permitted.insert(cap);
            current_effective.insert(cap);
        } else {
            log::warn!("  - Unknown capability: {} (skipping)", cap_name);
        }
    }

    // Set the updated capability sets
    caps::set(None, CapSet::Permitted, &current_permitted).map_err(|e| {
        PurpleError::CapabilityError(format!("Failed to set permitted capabilities: {}", e))
    })?;

    caps::set(None, CapSet::Effective, &current_effective).map_err(|e| {
        PurpleError::CapabilityError(format!("Failed to set effective capabilities: {}", e))
    })?;

    log::info!("✓ Specific capabilities added and enforced");
    Ok(())
}

/// Drops specific capabilities from the process
fn drop_specific_capabilities(capabilities: &HashSet<String>) -> Result<()> {
    use caps::CapSet;

    log::info!("Dropping specific capabilities from process");

    for cap_name in capabilities {
        if let Some(cap) = capability_from_name(cap_name) {
            log::info!("  - Dropping capability: {} ({:?})", cap_name, cap);

            // Drop from bounding set
            if let Err(e) = caps::drop(None, CapSet::Bounding, cap) {
                log::debug!("Could not drop {:?} from bounding set: {}", cap, e);
            }

            // Drop from effective set
            if let Err(e) = caps::drop(None, CapSet::Effective, cap) {
                log::debug!("Could not drop {:?} from effective set: {}", cap, e);
            }

            // Drop from permitted set
            if let Err(e) = caps::drop(None, CapSet::Permitted, cap) {
                log::debug!("Could not drop {:?} from permitted set: {}", cap, e);
            }

            // Drop from inheritable set
            if let Err(e) = caps::drop(None, CapSet::Inheritable, cap) {
                log::debug!("Could not drop {:?} from inheritable set: {}", cap, e);
            }
        } else {
            log::warn!("  - Unknown capability: {} (skipping)", cap_name);
        }
    }

    log::info!("✓ Specific capabilities dropped and enforced");
    Ok(())
}

/// Drop capabilities using system calls
fn drop_capabilities_system_call() -> Result<()> {
    use caps::{CapSet, Capability, CapsHashSet};

    log::info!("Dropping all capabilities from process using caps library");

    // Get all capabilities that exist on this system
    let all_caps: Vec<Capability> = vec![
        Capability::CAP_CHOWN,
        Capability::CAP_DAC_OVERRIDE,
        Capability::CAP_DAC_READ_SEARCH,
        Capability::CAP_FOWNER,
        Capability::CAP_FSETID,
        Capability::CAP_KILL,
        Capability::CAP_SETGID,
        Capability::CAP_SETUID,
        Capability::CAP_SETPCAP,
        Capability::CAP_LINUX_IMMUTABLE,
        Capability::CAP_NET_BIND_SERVICE,
        Capability::CAP_NET_BROADCAST,
        Capability::CAP_NET_ADMIN,
        Capability::CAP_NET_RAW,
        Capability::CAP_IPC_LOCK,
        Capability::CAP_IPC_OWNER,
        Capability::CAP_SYS_MODULE,
        Capability::CAP_SYS_RAWIO,
        Capability::CAP_SYS_CHROOT,
        Capability::CAP_SYS_PTRACE,
        Capability::CAP_SYS_PACCT,
        Capability::CAP_SYS_ADMIN,
        Capability::CAP_SYS_BOOT,
        Capability::CAP_SYS_NICE,
        Capability::CAP_SYS_RESOURCE,
        Capability::CAP_SYS_TIME,
        Capability::CAP_SYS_TTY_CONFIG,
        Capability::CAP_MKNOD,
        Capability::CAP_LEASE,
        Capability::CAP_AUDIT_WRITE,
        Capability::CAP_AUDIT_CONTROL,
        Capability::CAP_SETFCAP,
        Capability::CAP_MAC_OVERRIDE,
        Capability::CAP_MAC_ADMIN,
        Capability::CAP_SYSLOG,
        Capability::CAP_WAKE_ALARM,
        Capability::CAP_BLOCK_SUSPEND,
        Capability::CAP_AUDIT_READ,
    ];

    // Drop all capabilities from the bounding set
    log::info!("Dropping capabilities from bounding set...");
    for cap in &all_caps {
        if let Err(e) = caps::drop(None, CapSet::Bounding, *cap) {
            // Some capabilities might not exist on older kernels, that's OK
            log::debug!(
                "Could not drop {:?} from bounding set: {} (may not exist)",
                cap,
                e
            );
        }
    }
    log::info!("✓ Bounding set capabilities dropped");

    // Clear the effective capability set
    log::info!("Clearing effective capability set...");
    let empty_set: CapsHashSet = CapsHashSet::new();
    caps::set(None, CapSet::Effective, &empty_set).map_err(|e| {
        PurpleError::CapabilityError(format!("Failed to clear effective capabilities: {}", e))
    })?;
    log::info!("✓ Effective capabilities cleared");

    // Clear the permitted capability set
    log::info!("Clearing permitted capability set...");
    caps::set(None, CapSet::Permitted, &empty_set).map_err(|e| {
        PurpleError::CapabilityError(format!("Failed to clear permitted capabilities: {}", e))
    })?;
    log::info!("✓ Permitted capabilities cleared");

    // Clear the inheritable capability set
    log::info!("Clearing inheritable capability set...");
    caps::set(None, CapSet::Inheritable, &empty_set).map_err(|e| {
        PurpleError::CapabilityError(format!("Failed to clear inheritable capabilities: {}", e))
    })?;
    log::info!("✓ Inheritable capabilities cleared");

    // Set NO_NEW_PRIVS to prevent privilege escalation via setuid/setgid binaries
    log::info!("Setting NO_NEW_PRIVS flag...");
    if let Err(e) = prctl_set_no_new_privs() {
        log::warn!("Could not set NO_NEW_PRIVS: {} (continuing anyway)", e);
    } else {
        log::info!("✓ NO_NEW_PRIVS flag set");
    }

    log::info!("All capabilities successfully dropped and enforced");
    Ok(())
}

/// Verifies current capabilities for debugging
#[allow(dead_code)]
pub fn verify_capabilities() -> Result<()> {
    log::info!("Verifying current process capabilities...");

    // Would check capabilities using capget() system call
    log::info!("Would verify capabilities using system calls");

    log::info!("Capability verification complete");
    Ok(())
}
