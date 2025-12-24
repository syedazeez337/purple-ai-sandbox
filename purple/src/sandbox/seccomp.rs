// purple/src/sandbox/seccomp.rs
//
// Seccomp filter implementation using libseccomp for BPF generation.
// Syscall name → number resolution uses our custom syscall table
// (see syscall_table.rs) for universal compatibility.

use crate::error::Result;
use crate::policy::compiler::{
    CompiledAdvancedSyscallRule, CompiledComparison, CompiledSyscallPolicy,
};
use libseccomp::{ScmpAction, ScmpArgCompare, ScmpCompareOp, ScmpFilterContext, ScmpSyscall};

/// Creates a ScmpArgCompare from our internal comparison type
fn create_arg_compare(arg_index: u32, comparison: &CompiledComparison) -> ScmpArgCompare {
    let value = get_comparison_value(comparison);
    let op = get_compare_op(comparison);

    // Create the comparison using the appropriate ScmpCompareOp variant
    // The third parameter (datum) is the value to compare against
    ScmpArgCompare::new(arg_index, op, value)
}

/// Gets the ScmpCompareOp for a given comparison type
/// Note: libseccomp-rs has inconsistent API where some variants are functions
fn get_compare_op(comparison: &CompiledComparison) -> ScmpCompareOp {
    match comparison {
        CompiledComparison::Equal(_) => ScmpCompareOp::Equal,
        CompiledComparison::NotEqual(_) => ScmpCompareOp::NotEqual,
        // libseccomp-rs exposes LessOrEqual but not LessThan directly
        CompiledComparison::LessThan(_) | CompiledComparison::LessThanOrEqual(_) => {
            ScmpCompareOp::LessOrEqual
        }
        // libseccomp-rs exposes GreaterEqual but not GreaterThan directly
        CompiledComparison::GreaterThan(_) | CompiledComparison::GreaterThanOrEqual(_) => {
            ScmpCompareOp::GreaterEqual
        }
        // Masked comparisons require a special approach - use MaskedEqual with mask as value
        // The mask is stored in the value field for masked comparisons
        CompiledComparison::MaskedEqual { mask, .. } => ScmpCompareOp::MaskedEqual(*mask),
        // MaskedNotEqual is simulated by MaskedEqual
        CompiledComparison::MaskedNotEqual { mask, .. } => ScmpCompareOp::MaskedEqual(*mask),
    }
}

/// Extracts the comparison value from a CompiledComparison
fn get_comparison_value(comparison: &CompiledComparison) -> u64 {
    match comparison {
        CompiledComparison::Equal(v)
        | CompiledComparison::NotEqual(v)
        | CompiledComparison::LessThan(v)
        | CompiledComparison::LessThanOrEqual(v)
        | CompiledComparison::GreaterThan(v)
        | CompiledComparison::GreaterThanOrEqual(v) => *v,
        CompiledComparison::MaskedEqual { value, .. }
        | CompiledComparison::MaskedNotEqual { value, .. } => *value,
    }
}

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

        // Add rules for each allowed syscall (basic allow rules)
        for syscall_num in &policy.allowed_syscall_numbers {
            let syscall = ScmpSyscall::from(*syscall_num as i32);
            ctx.add_rule(ScmpAction::Allow, syscall)?;
            log::debug!("Seccomp: Allowed syscall {}", syscall_num);
        }

        // Apply advanced rules with conditional filtering
        // These can further restrict syscalls based on argument values
        apply_advanced_rules(&mut ctx, &policy.advanced_rules)?;
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

        // Apply advanced rules with conditional filtering in allow-by-default mode
        apply_advanced_rules(&mut ctx, &policy.advanced_rules)?;
    }

    // Load the filter into the kernel
    ctx.load()?;

    if policy.default_deny {
        log::info!(
            "Syscall filtering policy enforced with {} allowed syscalls and {} advanced rules",
            policy.allowed_syscall_numbers.len(),
            policy.advanced_rules.len()
        );
    } else {
        log::info!(
            "Syscall filtering policy enforced with {} denied syscalls and {} advanced rules",
            policy.denied_syscall_numbers.len(),
            policy.advanced_rules.len()
        );
    }

    Ok(())
}

/// Applies advanced syscall rules with conditional argument filtering
fn apply_advanced_rules(
    ctx: &mut ScmpFilterContext,
    rules: &[CompiledAdvancedSyscallRule],
) -> Result<()> {
    for rule in rules {
        let syscall = ScmpSyscall::from(rule.syscall_number as i32);

        // Determine action for this rule
        let action = match rule.action {
            crate::policy::SyscallAction::Allow => ScmpAction::Allow,
            crate::policy::SyscallAction::Deny => ScmpAction::KillProcess,
        };

        if rule.conditions.is_empty() {
            // No conditions - basic rule
            ctx.add_rule(action, syscall)?;
            log::debug!(
                "Seccomp: Advanced rule for {} (no conditions)",
                rule.syscall_name
            );
        } else {
            // Build conditional rule using libseccomp's conditional API
            // Convert our conditions to ScmpArgCompare
            let comparisons: Vec<ScmpArgCompare> = rule
                .conditions
                .iter()
                .map(|cond| create_arg_compare(cond.arg_index, &cond.comparison))
                .collect();

            // Handle MaskedNotEqual by inverting the condition
            // This is a workaround since libseccomp-rs doesn't expose MaskedNotEqual directly
            if rule.conditions.len() == 1
                && matches!(
                    &rule.conditions[0].comparison,
                    CompiledComparison::MaskedNotEqual { .. }
                )
            {
                log::warn!(
                    "Seccomp: MaskedNotEqual for {} is simulated with MaskedEqual. \
                         Consider using 'neq' with specific value for more precise control.",
                    rule.syscall_name
                );
            }

            // Use the conditional rule API
            // The add_rule_conditional method accepts a slice of conditions
            ctx.add_rule_conditional(action, syscall, &comparisons)?;

            log::debug!(
                "Seccomp: Advanced rule for {} with {} conditions",
                rule.syscall_name,
                rule.conditions.len()
            );
        }
    }

    Ok(())
}
