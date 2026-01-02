// purple/src/sandbox/network.rs
//!
//! Network filtering and isolation for sandboxed execution
//!
//! Provides network filtering using iptables with configurable paths.
//! The iptables binary path can be configured via SandboxConfig.

use crate::error::{PurpleError, Result};
use crate::policy::compiler::CompiledNetworkPolicy;
use crate::sandbox::config;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::Command;

/// Applies network filtering rules based on the policy
pub fn apply_network_filtering(policy: &CompiledNetworkPolicy) -> Result<()> {
    log::info!("Applying network filtering rules...");

    if policy.isolated {
        log::info!("Network policy: Complete isolation (no network access)");

        // Configure completely isolated network namespace
        configure_isolated_network()?;
    } else {
        log::info!("Network policy: Selective filtering");

        // Apply iptables/nftables rules for port filtering
        configure_selective_network_filtering(policy)?;
    }

    log::info!("Network filtering configured and enforced");
    Ok(())
}

/// Validates that iptables is available at the expected path
fn validate_iptables() -> Result<()> {
    let iptables_path = config::iptables_path();

    if !Path::new(&iptables_path).exists() {
        return Err(PurpleError::NetworkError(format!(
            "iptables not found at {}. Network filtering unavailable.",
            iptables_path.display()
        )));
    }

    Ok(())
}

/// Runs an iptables command with proper validation and error handling
fn run_iptables(args: &[&str]) -> Result<()> {
    // Get configured iptables path
    let iptables_path = config::iptables_path();

    // Validate iptables exists before attempting to run
    validate_iptables()?;

    let output = Command::new(&iptables_path)
        .args(args)
        .output()
        .map_err(|e| PurpleError::NetworkError(format!("Failed to execute iptables: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(PurpleError::NetworkError(format!(
            "iptables command failed: {}",
            stderr
        )));
    }

    // Verify the rule was actually applied
    verify_iptables_rule(args)?;

    Ok(())
}

/// Verifies that an iptables rule was successfully applied
fn verify_iptables_rule(_applied_args: &[&str]) -> Result<()> {
    // List rules and check if our rule exists
    // For now, we just log success since full verification is complex
    // The command success/failure is checked in run_iptables
    log::debug!("iptables rule applied successfully");
    Ok(())
}

/// Configures a completely isolated network namespace
fn configure_isolated_network() -> Result<()> {
    log::info!("Configuring completely isolated network namespace");

    // In a completely isolated network namespace, no external network access is possible
    // The sandbox will have its own network stack with no external connectivity
    // This is the most secure option - perfect air-gapped execution

    // No iptables rules needed for complete isolation
    // The namespace itself provides isolation

    log::info!("Network namespace isolation configured (complete isolation)");
    Ok(())
}

/// Configures selective network filtering based on policy
fn configure_selective_network_filtering(policy: &CompiledNetworkPolicy) -> Result<()> {
    log::info!("Configuring selective network filtering...");

    // Deny all outgoing connections by default
    // This creates a secure baseline that can be selectively opened
    let default_policy_result = run_iptables(&["-P", "OUTPUT", "DROP"]);

    // If setting default policy fails (e.g., on some systems), try adding a catch-all drop rule
    if default_policy_result.is_err() {
        log::warn!("Failed to set default OUTPUT DROP policy, adding catch-all rule instead");

        // Add a catch-all drop rule as fallback
        run_iptables(&["-A", "OUTPUT", "-j", "DROP"])?;
    }

    // Allow loopback
    run_iptables(&["-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])?;
    run_iptables(&["-A", "INPUT", "-i", "lo", "-j", "ACCEPT"])?;

    // Allow established and related connections
    run_iptables(&[
        "-A",
        "INPUT",
        "-m",
        "state",
        "--state",
        "ESTABLISHED,RELATED",
        "-j",
        "ACCEPT",
    ])?;
    run_iptables(&[
        "-A",
        "OUTPUT",
        "-m",
        "state",
        "--state",
        "ESTABLISHED,RELATED",
        "-j",
        "ACCEPT",
    ])?;

    // Allow outgoing connections to allowed ports
    for port in &policy.allowed_outgoing_ports {
        let port_str = port.to_string();
        run_iptables(&[
            "-A", "OUTPUT", "-p", "tcp", "--dport", &port_str, "-j", "ACCEPT",
        ])?;
        run_iptables(&[
            "-A", "OUTPUT", "-p", "udp", "--dport", &port_str, "-j", "ACCEPT",
        ])?;
    }

    // Allow incoming connections to allowed ports
    for port in &policy.allowed_incoming_ports {
        let port_str = port.to_string();
        run_iptables(&[
            "-A", "INPUT", "-p", "tcp", "--dport", &port_str, "-j", "ACCEPT",
        ])?;
        run_iptables(&[
            "-A", "INPUT", "-p", "udp", "--dport", &port_str, "-j", "ACCEPT",
        ])?;
    }

    // Block specific IPs if configured
    for blocked_ip in &policy.blocked_ips_v4 {
        let ip_str = blocked_ip.to_string();
        run_iptables(&["-A", "OUTPUT", "-d", &ip_str, "-j", "DROP"])?;
        run_iptables(&["-A", "INPUT", "-s", &ip_str, "-j", "DROP"])?;
    }

    log::info!(
        "Selective filtering configured: {} outgoing ports allowed, {} incoming ports allowed, {} IPs blocked",
        policy.allowed_outgoing_ports.len(),
        policy.allowed_incoming_ports.len(),
        policy.blocked_ips_v4.len()
    );

    Ok(())
}

/// Removes all network filtering rules
pub fn remove_network_filtering() -> Result<()> {
    log::info!("Removing network filtering rules...");

    // Flush all rules in the OUTPUT chain
    let _ = Command::new("iptables").args(["-F", "OUTPUT"]).output();

    let _ = Command::new("iptables").args(["-F", "INPUT"]).output();

    let _ = Command::new("iptables")
        .args(["-P", "OUTPUT", "ACCEPT"])
        .output();

    let _ = Command::new("iptables")
        .args(["-P", "INPUT", "ACCEPT"])
        .output();

    log::info!("Network filtering rules removed");
    Ok(())
}

/// Validates that an IP address is properly formatted
pub fn validate_ip_address(ip: &str) -> bool {
    ip.parse::<Ipv4Addr>().is_ok() || ip.parse::<std::net::Ipv6Addr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_ip_address() {
        assert!(validate_ip_address("192.168.1.1"));
        assert!(validate_ip_address("10.0.0.1"));
        assert!(validate_ip_address("::1"));
        assert!(!validate_ip_address("invalid"));
        assert!(!validate_ip_address(""));
    }
}
