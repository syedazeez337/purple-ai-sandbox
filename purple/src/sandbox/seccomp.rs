// purple/src/sandbox/seccomp.rs

use crate::error::Result;
use crate::policy::compiler::CompiledSyscallPolicy;
use libseccomp::{ScmpAction, ScmpFilterContext, ScmpSyscall};
use std::collections::BTreeSet;

/// Applies seccomp filtering based on the compiled syscall policy
pub fn apply_seccomp_filter(policy: &CompiledSyscallPolicy) -> Result<()> {
    log::info!("Applying seccomp syscall filter...");

    // Determine default action based on policy
    let default_action = if policy.default_deny {
        ScmpAction::KillProcess
    } else {
        ScmpAction::Allow
    };

    // Create a new seccomp filter context
    let mut ctx = ScmpFilterContext::new_filter(default_action)?;

    if policy.default_deny {
        log::info!("Seccomp: Setting default action to DENY (kill process)");
        log::info!(
            "Seccomp: Allowing {} syscalls",
            policy.allowed_syscall_numbers.len()
        );

        // Add rules for each allowed syscall
        for syscall_num in &policy.allowed_syscall_numbers {
            let syscall = ScmpSyscall::from(*syscall_num as i32);
            ctx.add_rule(ScmpAction::Allow, syscall)?;
            log::debug!("Seccomp: Allowed syscall {}", syscall_num);
        }
    } else {
        log::info!("Seccomp: Setting default action to ALLOW");
        log::info!(
            "Seccomp: Denying {} syscalls",
            policy.denied_syscall_numbers.len()
        );

        // In allow-by-default mode, explicitly deny specific syscalls
        for syscall_num in &policy.denied_syscall_numbers {
            let syscall = ScmpSyscall::from(*syscall_num as i32);
            ctx.add_rule(ScmpAction::KillProcess, syscall)?;
            log::debug!("Seccomp: Denied syscall {}", syscall_num);
        }
    }

    // Load the filter into the kernel
    ctx.load()?;

    if policy.default_deny {
        log::info!(
            "Syscall filtering policy enforced with {} allowed syscalls",
            policy.allowed_syscall_numbers.len()
        );
    } else {
        log::info!(
            "Syscall filtering policy enforced with {} denied syscalls",
            policy.denied_syscall_numbers.len()
        );
    }

    Ok(())
}

/// Syscall name to number mapping for common syscalls
/// Note: Kept for potential future dynamic syscall resolution
#[allow(dead_code)]
/// Syscall name to number mapping - uses libseccomp's built-in database
/// This is more reliable than hardcoded mappings and works across different kernel versions
pub fn get_syscall_number(name: &str) -> Option<i64> {
    match ScmpSyscall::from_name(name) {
        Ok(syscall) => Some(i32::from(syscall) as i64),
        Err(_) => {
            log::debug!("Failed to resolve syscall name: {}", name);
            None
        }
    }
}

/// Converts syscall names to numbers for the policy
/// Note: Kept for potential future dynamic syscall resolution
#[allow(dead_code)]
pub fn resolve_syscall_names(names: &[String]) -> BTreeSet<i64> {
    let mut numbers = BTreeSet::new();
    for name in names {
        if let Some(num) = get_syscall_number(name) {
            numbers.insert(num);
        } else {
            log::warn!("Unknown syscall name: {}", name);
        }
    }
    numbers
}
