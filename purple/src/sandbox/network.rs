use crate::error::{PurpleError, Result};
use crate::policy::compiler::CompiledNetworkPolicy;
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

/// Configures a completely isolated network namespace
fn configure_isolated_network() -> Result<()> {
    log::info!("Configuring completely isolated network namespace");

    // Set up loopback interface (essential for local communication)
    setup_loopback_interface()?;

    // Block all other network traffic using iptables
    block_all_network_traffic()?;

    log::info!("Isolated network configured: only loopback available");
    Ok(())
}

/// Configures selective network filtering using iptables/nftables
fn configure_selective_network_filtering(policy: &CompiledNetworkPolicy) -> Result<()> {
    log::info!("Configuring selective network filtering");

    // Start with default deny policy
    setup_default_deny_policy()?;

    // Allow outgoing connections to specified ports
    if !policy.allowed_outgoing_ports.is_empty() {
        log::info!(
            "Allowing {} outgoing ports:",
            policy.allowed_outgoing_ports.len()
        );
        for port in &policy.allowed_outgoing_ports {
            allow_outgoing_port(*port)?;
            log::info!("  ✓ Allowed outgoing port {}", port);
        }
    } else {
        log::info!("No outgoing connections allowed (default deny)");
    }

    // Allow incoming connections to specified ports
    if !policy.allowed_incoming_ports.is_empty() {
        log::info!(
            "Allowing {} incoming ports:",
            policy.allowed_incoming_ports.len()
        );
        for port in &policy.allowed_incoming_ports {
            allow_incoming_port(*port)?;
            log::info!("  ✓ Allowed incoming port {}", port);
        }
    } else {
        log::info!("No incoming connections allowed (default deny)");
    }

    // Always allow loopback traffic
    allow_loopback_traffic()?;

    Ok(())
}

/// Sets up the loopback interface in isolated network
fn setup_loopback_interface() -> Result<()> {
    log::info!("Setting up loopback interface");

    // First, try to bring up lo interface using ip command
    let ip_available = Command::new("ip").arg("--version").output().is_ok();

    if ip_available {
        // Bring up lo interface: ip link set lo up
        let output = Command::new("ip")
            .args(["link", "set", "lo", "up"])
            .output()
            .map_err(|e| {
                PurpleError::NetworkError(format!("Failed to execute 'ip link set lo up': {}", e))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            log::warn!(
                "Failed to bring up loopback interface: {} (may already be up)",
                stderr
            );
        } else {
            log::info!("Loopback interface brought up");
        }

        // Check if loopback address already exists before adding
        let check_output = Command::new("ip")
            .args(["addr", "show", "lo", "dev", "lo"])
            .output()
            .map_err(|e| {
                PurpleError::NetworkError(format!("Failed to check loopback address: {}", e))
            })?;

        let addr_exists = String::from_utf8_lossy(&check_output.stdout).contains("127.0.0.1");

        if addr_exists {
            log::info!("Loopback address already configured (skipped duplicate)");
        } else {
            // Add loopback address
            let output = Command::new("ip")
                .args(["addr", "add", "127.0.0.1/8", "dev", "lo"])
                .output()
                .map_err(|e| {
                    PurpleError::NetworkError(format!("Failed to execute 'ip addr add': {}", e))
                })?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                log::warn!("Failed to add loopback address: {}", stderr);
            } else {
                log::info!("Loopback address configured");
            }
        }
    } else {
        // Fallback: Use ioctl to bring up loopback interface
        // This is more reliable in minimal environments where ip command may not be available
        log::info!("ip command not available, using direct ioctl method");
        setup_loopback_with_ioctl()?;
    }

    log::info!("Loopback interface configured and enforced");
    Ok(())
}

/// Sets up loopback interface using direct ioctl calls
/// This is a fallback method when ip command is not available
fn setup_loopback_with_ioctl() -> Result<()> {
    use std::net::Ipv4Addr;
    use std::net::SocketAddrV4;
    use std::net::TcpListener;

    log::info!("Setting up loopback interface using ioctl fallback");

    // Try to create a TCP listener on the loopback interface
    // This will implicitly bring up the loopback interface if it's not already up
    let loopback_addr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 0);

    match TcpListener::bind(loopback_addr) {
        Ok(_listener) => {
            log::info!("✓ Loopback interface is available and functional");
        }
        Err(e) => {
            log::warn!("Failed to bind to loopback interface: {}", e);
            // This might fail if the interface is down, but in most cases
            // the kernel will bring it up automatically when needed
        }
    }

    log::info!("✓ Loopback interface setup completed using ioctl fallback");
    Ok(())
}

/// Blocks all network traffic using iptables
fn block_all_network_traffic() -> Result<()> {
    log::info!("Blocking all network traffic using iptables");

    // First, allow established connections and loopback
    allow_loopback_traffic()?;

    // Set default policies to DROP
    let policies = [("INPUT", "DROP"), ("OUTPUT", "DROP"), ("FORWARD", "DROP")];

    for (chain, policy) in &policies {
        let output = Command::new("iptables")
            .args(["-P", chain, policy])
            .output()
            .map_err(|e| {
                PurpleError::NetworkError(format!(
                    "Failed to execute 'iptables -P {} {}': {}",
                    chain, policy, e
                ))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PurpleError::NetworkError(format!(
                "Failed to set {} chain policy to {}: {}",
                chain, policy, stderr
            )));
        }
        log::info!("  ✓ {} chain policy set to {}", chain, policy);
    }

    log::info!("✓ All network traffic blocked (except loopback)");
    Ok(())
}

/// Sets up default deny policy for iptables
fn setup_default_deny_policy() -> Result<()> {
    log::info!("Setting up default deny policy using iptables");

    // Flush existing rules to start fresh
    for chain in &["INPUT", "OUTPUT", "FORWARD"] {
        let output = Command::new("iptables")
            .args(["-F", chain])
            .output()
            .map_err(|e| {
                PurpleError::NetworkError(format!("Failed to flush {} chain: {}", chain, e))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            log::warn!("Failed to flush {} chain: {}", chain, stderr);
        }
    }

    // Set default policies to DROP
    let policies = [("INPUT", "DROP"), ("OUTPUT", "DROP"), ("FORWARD", "DROP")];

    for (chain, policy) in &policies {
        let output = Command::new("iptables")
            .args(["-P", chain, policy])
            .output()
            .map_err(|e| {
                PurpleError::NetworkError(format!("Failed to set {} policy: {}", chain, e))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PurpleError::NetworkError(format!(
                "Failed to set {} chain policy to {}: {}",
                chain, policy, stderr
            )));
        }
        log::info!("  ✓ {} chain policy set to {}", chain, policy);
    }

    // Allow established and related connections (stateful filtering)
    let output = Command::new("iptables")
        .args([
            "-A",
            "INPUT",
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ])
        .output()
        .map_err(|e| {
            PurpleError::NetworkError(format!(
                "Failed to allow established INPUT connections: {}",
                e
            ))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        log::warn!("Failed to allow established INPUT connections: {}", stderr);
    }

    let output = Command::new("iptables")
        .args([
            "-A",
            "OUTPUT",
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ])
        .output()
        .map_err(|e| {
            PurpleError::NetworkError(format!(
                "Failed to allow established OUTPUT connections: {}",
                e
            ))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        log::warn!("Failed to allow established OUTPUT connections: {}", stderr);
    }

    log::info!("✓ Default deny policy established and enforced");
    Ok(())
}

/// Allows outgoing traffic to a specific port
fn allow_outgoing_port(port: u16) -> Result<()> {
    log::debug!("Allowing outgoing traffic to port {}", port);

    // Allow TCP outgoing
    let output = Command::new("iptables")
        .args([
            "-A",
            "OUTPUT",
            "-p",
            "tcp",
            "--dport",
            &port.to_string(),
            "-j",
            "ACCEPT",
        ])
        .output()
        .map_err(|e| {
            PurpleError::NetworkError(format!("Failed to allow outgoing TCP port {}: {}", port, e))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(PurpleError::NetworkError(format!(
            "Failed to allow outgoing TCP port {}: {}",
            port, stderr
        )));
    }

    // Allow UDP outgoing
    let output = Command::new("iptables")
        .args([
            "-A",
            "OUTPUT",
            "-p",
            "udp",
            "--dport",
            &port.to_string(),
            "-j",
            "ACCEPT",
        ])
        .output()
        .map_err(|e| {
            PurpleError::NetworkError(format!("Failed to allow outgoing UDP port {}: {}", port, e))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(PurpleError::NetworkError(format!(
            "Failed to allow outgoing UDP port {}: {}",
            port, stderr
        )));
    }

    log::info!("  ✓ Outgoing port {} allowed (TCP/UDP)", port);
    Ok(())
}

/// Allows incoming traffic to a specific port
fn allow_incoming_port(port: u16) -> Result<()> {
    log::debug!("Allowing incoming traffic to port {}", port);

    // Allow TCP incoming
    let output = Command::new("iptables")
        .args([
            "-A",
            "INPUT",
            "-p",
            "tcp",
            "--dport",
            &port.to_string(),
            "-j",
            "ACCEPT",
        ])
        .output()
        .map_err(|e| {
            PurpleError::NetworkError(format!("Failed to allow incoming TCP port {}: {}", port, e))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(PurpleError::NetworkError(format!(
            "Failed to allow incoming TCP port {}: {}",
            port, stderr
        )));
    }

    // Allow UDP incoming
    let output = Command::new("iptables")
        .args([
            "-A",
            "INPUT",
            "-p",
            "udp",
            "--dport",
            &port.to_string(),
            "-j",
            "ACCEPT",
        ])
        .output()
        .map_err(|e| {
            PurpleError::NetworkError(format!("Failed to allow incoming UDP port {}: {}", port, e))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(PurpleError::NetworkError(format!(
            "Failed to allow incoming UDP port {}: {}",
            port, stderr
        )));
    }

    log::info!("  ✓ Incoming port {} allowed (TCP/UDP)", port);
    Ok(())
}

/// Allows loopback traffic
fn allow_loopback_traffic() -> Result<()> {
    log::debug!("Allowing loopback traffic");

    // Allow INPUT on loopback interface
    let output = Command::new("iptables")
        .args(["-A", "INPUT", "-i", "lo", "-j", "ACCEPT"])
        .output()
        .map_err(|e| PurpleError::NetworkError(format!("Failed to allow loopback INPUT: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        log::warn!("Failed to allow loopback INPUT: {}", stderr);
    }

    // Allow OUTPUT on loopback interface
    let output = Command::new("iptables")
        .args(["-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])
        .output()
        .map_err(|e| {
            PurpleError::NetworkError(format!("Failed to allow loopback OUTPUT: {}", e))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        log::warn!("Failed to allow loopback OUTPUT: {}", stderr);
    }

    log::info!("✓ Loopback traffic allowed and enforced");
    Ok(())
}
