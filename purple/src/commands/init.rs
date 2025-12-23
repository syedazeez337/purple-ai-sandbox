// purple/src/commands/init.rs
// Initialization command for Purple AI Sandbox

use crate::error::Result;
use std::path::Path;

pub fn handle_init() -> Result<()> {
    println!("🚀 Initializing Purple AI Sandbox environment...");

    // Create necessary directories
    let dirs = ["policies", "sessions", "logs", "audit"];
    for dir in dirs.iter() {
        if let Err(e) = std::fs::create_dir_all(dir) {
            eprintln!("⚠️  Failed to create {} directory: {}", dir, e);
        } else {
            println!("✅ Created {} directory", dir);
        }
    }

    // Create default policy if it doesn't exist
    let default_policy_path = "./policies/development.yaml";
    if !Path::new(default_policy_path).exists() {
        println!("📝 Creating default development policy...");
        let default_policy = r#"# Purple AI Sandbox - Default Development Policy
# This policy provides a balanced approach for AI development
# with reasonable security constraints while allowing flexibility

name: "development"
description: "Default development policy with balanced security"
version: "1.0"

filesystem:
  working_directory: "/tmp/purple-work"
  immutable_paths:
    - host_path: "/etc/passwd"
      sandbox_path: "/etc/passwd"
    - host_path: "/etc/group"
      sandbox_path: "/etc/group"
  scratch_dirs:
    - "/tmp/purple-scratch"

resources:
  memory_limit_mb: 1024
  cpu_shares: 512
  pids_limit: 100
  io_limit_mb_per_sec: 50

network:
  isolated: false
  allowed_outgoing_ports:
    - 80
    - 443
    - 8080
  blocked_ips_v4:
    - "0.0.0.0"
  blocked_ips_v6:
    - "::1"

audit:
  enabled: true
  log_path: "./logs/audit.log"

syscalls:
  default_deny: false
  allowed: []
  deny_list:
    - "ptrace"
    - "kill"
    - "reboot"
    - "mount"
    - "umount"
"#;

        if let Err(e) = std::fs::write(default_policy_path, default_policy) {
            eprintln!("⚠️  Failed to create default policy: {}", e);
        } else {
            println!("✅ Created default development policy");
        }
    }

    println!("🎉 Purple AI Sandbox environment initialized!");
    println!("");
    println!("Next steps:");
    println!("  1. Review the default policy: cat policies/development.yaml");
    println!("  2. Create custom policies as needed");
    println!("  3. Run an AI agent: purple run --profile development -- /bin/echo 'Hello World'");

    Ok(())
}