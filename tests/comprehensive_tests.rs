// Comprehensive test suite for Purple AI Agent Sandbox
//
// NOTE: Tests marked with #[ignore] require Linux namespace support which is not
// available in most CI environments (including GitHub Actions). Run these tests
// locally on a Linux system with: cargo test -- --ignored

use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
#[ignore] // Requires Linux namespace support - run with: cargo test -- --ignored
fn test_basic_sandbox_execution() {
    // Test basic command execution in sandbox
    let output = Command::new("cargo")
        .args([
            "run",
            "--",
            "run",
            "--profile",
            "ai-dev-safe",
            "--",
            "echo",
            "Hello",
        ])
        .output()
        .expect("Failed to execute sandbox");

    if !output.status.success() {
        println!(
            "Sandbox execution failed. Stderr:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert!(output.status.success(), "Sandbox execution should succeed");
    assert!(String::from_utf8_lossy(&output.stderr).contains("Sandbox execution completed"));
}

#[test]
#[ignore] // Requires Linux namespace support
fn test_filesystem_isolation() {
    // Test that sandbox cannot access host filesystem
    let output = Command::new("cargo")
        .args([
            "run",
            "--",
            "run",
            "--profile",
            "ai-dev-safe",
            "--",
            "bash",
            "-c",
            "cat /etc/passwd 2>/dev/null || echo 'Access blocked'",
        ])
        .output()
        .expect("Failed to execute sandbox");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Access blocked"),
        "Should not be able to access /etc/passwd"
    );
}

#[test]
#[ignore] // Requires Linux namespace support
fn test_network_isolation() {
    // Test network isolation with ai-strict profile
    let output = Command::new("cargo")
        .args([
            "run",
            "--",
            "run",
            "--profile",
            "ai-strict",
            "--",
            "ping",
            "-c",
            "1",
            "8.8.8.8",
        ])
        .output()
        .expect("Failed to execute sandbox");

    // Should fail due to network isolation
    assert!(
        !output.status.success(),
        "Network access should be blocked in ai-strict profile"
    );
}

#[test]
#[ignore] // Requires Linux namespace support
fn test_syscall_filtering() {
    // Test that syscall filtering works with ai-strict profile
    let output = Command::new("cargo")
        .args([
            "run",
            "--",
            "run",
            "--profile",
            "ai-strict",
            "--",
            "echo",
            "Test",
        ])
        .output()
        .expect("Failed to execute sandbox");

    let stderr = String::from_utf8_lossy(&output.stderr);
    // Should show syscall filtering is active
    assert!(
        stderr.contains("Syscall filtering policy enforced"),
        "Syscall filtering should be active"
    );
    // Should be killed by SIGSYS (syscall violation)
    assert!(
        stderr.contains("Signaled") || stderr.contains("SIGSYS"),
        "Should be killed by syscall filter"
    );
}

#[test]
#[ignore] // Requires Linux namespace support
fn test_resource_limits() {
    // Test that resource limits are configured
    let output = Command::new("cargo")
        .args([
            "run",
            "--",
            "run",
            "--profile",
            "ai-dev-safe",
            "--",
            "echo",
            "Test",
        ])
        .output()
        .expect("Failed to execute sandbox");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Applying resource limits"),
        "Resource limits should be applied"
    );
    assert!(
        stderr.contains("Cgroups configured")
            || stderr.contains("Resource limits will NOT be enforced"),
        "Cgroups should be configured or explicitly skipped"
    );
}

#[test]
#[ignore] // Requires Linux namespace support
fn test_dns_configuration() {
    // Test that DNS is configured in sandbox
    let output = Command::new("cargo")
        .args([
            "run",
            "--",
            "run",
            "--profile",
            "ai-dev-safe",
            "--",
            "bash",
            "-c",
            "cat /etc/resolv.conf | grep nameserver",
        ])
        .output()
        .expect("Failed to execute sandbox");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("8.8.8.8") || stdout.contains("8.8.4.4"),
        "DNS should be configured with Google servers"
    );
}

#[test]
#[ignore] // Requires Linux namespace support
fn test_policy_validation() {
    // Test that invalid policies are rejected
    // Note: We write to the policies directory because the CLI expects it there
    let invalid_policy_path = Path::new("policies/invalid-policy.yaml");

    let invalid_content = r#"
name: "invalid-policy"
syscalls:
  default_deny: true
  allow:
    - "nonexistent_syscall"
resources: # Added missing required sections to pass parsing
  cpu_shares: 0.5
  memory_limit_bytes: "1G"
  pids_limit: 100
  block_io_limit: "100MBps"
  session_timeout_seconds: 60
capabilities:
  default_drop: true
  add: []
network:
  isolated: true
  allow_outgoing: []
  allow_incoming: []
filesystem: # Added missing filesystem section
  immutable_paths: []
  scratch_paths: []
  output_paths: []
  working_dir: "/tmp"
audit: # Added missing audit section
  enabled: false
  log_path: "/tmp/audit.log"
  detail_level: []
"#;

    fs::write(invalid_policy_path, invalid_content).expect("Failed to write invalid policy");

    let output = Command::new("cargo")
        .args([
            "run",
            "--",
            "run",
            "--profile",
            "invalid-policy",
            "--",
            "echo",
            "Test",
        ])
        .output();

    // Clean up first
    let _ = fs::remove_file(invalid_policy_path);

    let output = output.expect("Failed to execute sandbox");

    assert!(
        !output.status.success(),
        "Invalid policy should be rejected"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Unknown syscall"),
        "Should report unknown syscall"
    );
}

#[test]
#[ignore] // Requires Linux namespace support
fn test_error_reporting() {
    // Test enhanced error reporting
    let output = Command::new("cargo")
        .args([
            "run",
            "--",
            "run",
            "--profile",
            "ai-dev-safe",
            "--",
            "echo",
            "Test",
        ])
        .output()
        .expect("Failed to execute sandbox");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("=== Sandbox Execution Summary ==="),
        "Should show execution summary"
    );
    assert!(
        stderr.contains("Security features enabled"),
        "Should list security features"
    );
}

#[test]
fn test_profile_management() {
    // Test profile list and show commands
    let output = Command::new("cargo")
        .args(["run", "--", "profile", "list"])
        .output()
        .expect("Failed to list profiles");

    assert!(output.status.success(), "Profile list should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("ai-dev-safe"),
        "Should list ai-dev-safe profile"
    );
    assert!(
        stdout.contains("ai-strict"),
        "Should list ai-strict profile"
    );
}

#[test]
#[ignore] // Requires Linux namespace support
fn test_filesystem_operations() {
    // Test filesystem operations in sandbox
    let output = Command::new("cargo")
        .args([
            "run",
            "--",
            "run",
            "--profile",
            "ai-dev-safe",
            "--",
            "bash",
            "-c",
            "touch /tmp/test_file && ls /tmp/test_file && rm /tmp/test_file",
        ])
        .output()
        .expect("Failed to execute sandbox");

    assert!(output.status.success(), "Filesystem operations should work");
}

#[test]
#[ignore] // Requires Linux namespace support
fn test_multi_process() {
    // Test multi-process workloads
    let output = Command::new("cargo")
        .args([
            "run",
            "--",
            "run",
            "--profile",
            "ai-dev-safe",
            "--",
            "bash",
            "-c",
            "(sleep 1 & wait)",
        ])
        .output()
        .expect("Failed to execute sandbox");

    assert!(output.status.success(), "Multi-process should work");
}

// Note: Tests marked with #[ignore] require Linux namespace support.
// Run them locally on a Linux system with proper permissions:
//   cargo test -- --ignored
//
// The test_profile_management test runs in CI as it only tests CLI commands
// that don't require namespace isolation.
