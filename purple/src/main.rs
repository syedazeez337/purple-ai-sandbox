pub mod ai;
// mod api; // API module disabled - requires more implementation work
pub mod cli;
pub mod error;
pub mod policy;
pub mod sandbox;
#[macro_use]
pub mod logging;
pub mod correlation;

#[cfg(test)]
mod tests;

use clap::Parser;
use cli::{Cli, Commands, ProfileCommands, SandboxAction, CorrelationCommands};
use error::PurpleError;
use log::LevelFilter;
use logging::init_logging;
use sandbox::{Sandbox, manager::SandboxManager};

/// Validates a profile name for security
/// Returns Ok(()) if valid, or an error message if invalid
fn validate_profile_name(name: &str) -> Result<(), String> {
    // Check for empty name
    if name.trim().is_empty() {
        return Err("Profile name cannot be empty".to_string());
    }

    // Check for minimum length
    if name.len() < 2 {
        return Err("Profile name must be at least 2 characters".to_string());
    }

    // Check for maximum length
    const MAX_NAME_LENGTH: usize = 64;
    if name.len() > MAX_NAME_LENGTH {
        return Err(format!(
            "Profile name exceeds maximum length of {} characters",
            MAX_NAME_LENGTH
        ));
    }

    // Check for path traversal patterns
    if name.contains("..") || name.contains('/') || name.contains('\\') {
        return Err("Profile name contains invalid path characters (/, \\, ..)".to_string());
    }

    // Check for shell metacharacters
    let shell_chars = [
        ';', '&', '|', '$', '`', '(', ')', '{', '}', '[', ']', '<', '>', '?', '*', '!', '\'', '"',
        '\n', '\r',
    ];
    for c in shell_chars {
        if name.contains(c) {
            return Err(format!("Profile name contains invalid character: '{}'", c));
        }
    }

    // Check for leading/trailing hyphens or underscores (cosmetic, not security)
    let trimmed = name.trim();
    if trimmed.starts_with('-')
        || trimmed.starts_with('_')
        || trimmed.ends_with('-')
        || trimmed.ends_with('_')
    {
        return Err("Profile name should not start or end with hyphen or underscore".to_string());
    }

    Ok(())
}

/// Executes a sandbox via the manager (centralized resource management)
fn execute_via_manager(
    compiled_policy: policy::compiler::CompiledPolicy,
    agent_command: Vec<String>,
    profile_name: &str,
) -> Result<(), PurpleError> {
    use log::info;

    // Create transient manager
    let mut manager = SandboxManager::new();

    // Create sandbox with metadata
    let sandbox_id = manager.create_sandbox(
        compiled_policy,
        agent_command.clone(),
        profile_name.to_string(),
    )?;

    info!("Created sandbox {} for profile {}", sandbox_id, profile_name);

    // Execute sandbox
    info!("Executing sandbox {}...", sandbox_id);
    let exit_code = manager.execute_sandbox(&sandbox_id)?;

    // Get and display resource usage
    let usage = manager.get_resource_usage(&sandbox_id)?;
    println!("\n{}", "=".repeat(60));
    println!("Resource Usage Summary:");
    println!("  CPU time:     {:.2} seconds", usage.cpu_time);
    println!("  Peak memory:  {} MB", usage.memory_peak / 1024 / 1024);
    println!("  Network I/O:  {} bytes", usage.network_bytes);
    println!("{}", "=".repeat(60));

    // Cleanup
    manager.cleanup_sandbox(&sandbox_id)?;

    if exit_code != 0 {
        std::process::exit(exit_code);
    }

    Ok(())
}

fn main() {
    let cli = Cli::parse();

    // Initialize logging based on CLI argument
    let log_level = match cli.log_level.to_lowercase().as_str() {
        "trace" => LevelFilter::Trace,
        "debug" => LevelFilter::Debug,
        "info" => LevelFilter::Info,
        "warn" => LevelFilter::Warn,
        "error" => LevelFilter::Error,
        _ => {
            eprintln!(
                "Invalid log level '{}', defaulting to 'info'",
                cli.log_level
            );
            LevelFilter::Info
        }
    };

    if let Err(e) = init_logging(log_level) {
        eprintln!("Failed to initialize logging: {}", e);
        std::process::exit(1);
    }

    log::info!("Purple sandbox started with log level: {}", cli.log_level);

    match &cli.command {
        Commands::Version => {
            println!("Purple AI Sandbox v{}", env!("CARGO_PKG_VERSION"));
            println!("Enterprise-Grade Secure Runtime for Autonomous AI Agents");
            println!("License: Apache 2.0");
        }
        Commands::Init => {
            println!("🚀 Initializing Purple AI Sandbox environment...");

            // Clean up any leftover test directories from previous runs
            println!("🧹 Cleaning up leftover directories...");
            let leftover_patterns = ["test", "test;rm", "test rm", "test-rm"];
            let policies_dir = std::path::Path::new("policies");
            if policies_dir.exists()
                && let Ok(entries) = std::fs::read_dir(policies_dir)
            {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    // Check if this looks like a leftover test directory
                    let is_leftover = leftover_patterns
                        .iter()
                        .any(|p| name.contains(p) || name.starts_with("test;"));
                    if is_leftover && entry.path().is_dir() {
                        if let Err(e) = std::fs::remove_dir_all(entry.path()) {
                            println!("⚠️  Failed to clean up leftover directory {}: {}", name, e);
                        } else {
                            println!("🧹 Cleaned up leftover directory: {}", name);
                        }
                    }
                }
            }

            // Create necessary directories
            let dirs = ["policies", "sessions", "logs", "audit"];
            for dir in dirs.iter() {
                if let Err(e) = std::fs::create_dir_all(dir) {
                    eprintln!("⚠️  Failed to create {} directory: {}", dir, e);
                } else {
                    println!("✅ Created {} directory", dir);
                }
            }

            // Clean up orphaned cgroups
            println!("🧹 Cleaning up orphaned cgroups...");
            if let Err(e) = sandbox::cgroups::CgroupManager::cleanup_orphaned_cgroups() {
                log::warn!("Failed to cleanup orphaned cgroups: {}", e);
            }

            // Create default policy if it doesn't exist
            let default_policy_path = "./policies/development.yaml";
            if !std::path::Path::new(default_policy_path).exists() {
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
  detail_level:
    - "syscalls"
    - "network"
    - "filesystem"

syscalls:
  default_action: "allow"
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
            } else {
                println!("ℹ️  Default policy already exists");
            }

            println!("✅ Purple environment initialization complete!");
            println!("💡 You can now create custom policies and run sandboxed AI agents.");
        }
        Commands::Profile { command } => match command {
            ProfileCommands::Create { name } => {
                println!("Creating profile: {}", name);

                // Validate profile name
                if let Err(e) = validate_profile_name(name) {
                    eprintln!("Error: {}", e);
                    return;
                }

                // Check if profile already exists
                let policy_path = format!("./policies/{}.yaml", name);
                let policy_path_buf = std::path::PathBuf::from(&policy_path);

                if policy_path_buf.exists() {
                    eprintln!(
                        "Error: Profile '{}' already exists at {}",
                        name, policy_path
                    );
                    return;
                }

                // Create a default policy template
                let default_policy = format!(
                    r#"name: "{name}"
description: "Default sandbox profile for {name}"

filesystem:
  immutable_paths:
    - host_path: "/usr/bin"
      sandbox_path: "/usr/bin"
    - host_path: "/usr/lib"
      sandbox_path: "/usr/lib"
    - host_path: "/usr/lib64"
      sandbox_path: "/usr/lib64"
    - host_path: "/lib"
      sandbox_path: "/lib"
    - host_path: "/lib64"
      sandbox_path: "/lib64"
    - host_path: "/bin"
      sandbox_path: "/bin"
  scratch_paths:
    - "/tmp"
  output_paths: []
  working_dir: "/tmp"

syscalls:
  default_deny: false
  allow: []
  deny:
    - "mount"
    - "umount2"
    - "reboot"
    - "kexec_load"
    - "bpf"
    - "ptrace"

resources:
  cpu_shares: 0.5
  memory_limit_bytes: "1G"
  pids_limit: 100
  block_io_limit: "100MBps"
  session_timeout_seconds: 3600

capabilities:
  default_drop: true
  add: []

network:
  isolated: true
  allow_outgoing: []
  allow_incoming: []

audit:
  enabled: false
  log_path: "/var/log/purple/{name}.log"
  detail_level: []
"#,
                    name = name
                );

                // Create policies directory if it doesn't exist
                if let Some(parent) = policy_path_buf.parent()
                    && let Err(e) = std::fs::create_dir_all(parent)
                {
                    eprintln!("Error creating policies directory: {}", e);
                    return;
                }

                // Write the default policy file
                match std::fs::write(&policy_path_buf, default_policy) {
                    Ok(_) => {
                        println!(
                            "✓ Successfully created profile '{}' at {}",
                            name, policy_path
                        );

                        // Try to validate the created policy
                        match policy::parser::load_policy_from_file(&policy_path_buf) {
                            Ok(policy) => {
                                println!("✓ Policy syntax is valid");
                                match policy.compile() {
                                    Ok(_) => {
                                        println!("✓ Policy compilation successful");
                                    }
                                    Err(e) => {
                                        println!("⚠️  Policy compilation warning: {}", e);
                                        println!(
                                            "   The profile was created but may need adjustments."
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                println!("⚠️  Policy validation warning: {}", e);
                                println!("   The profile was created but has syntax errors.");
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Error writing profile file: {}", e);
                    }
                }
            }
            ProfileCommands::List => {
                println!("Listing available profiles...");

                // List YAML files in the policies directory
                let policies_dir = std::path::Path::new("./policies");
                if !policies_dir.exists() {
                    println!("No policies directory found. Creating one...");
                    if let Err(e) = std::fs::create_dir_all(policies_dir) {
                        eprintln!("Failed to create policies directory: {}", e);
                        return;
                    }
                    println!("Created policies directory at {}", policies_dir.display());
                    return;
                }

                match std::fs::read_dir(policies_dir) {
                    Ok(entries) => {
                        let mut profiles = Vec::new();

                        for entry in entries.flatten() {
                            if let Some(file_name) = entry.file_name().to_str()
                                && (file_name.ends_with(".yaml") || file_name.ends_with(".yml"))
                            {
                                let profile_name = file_name
                                    .trim_end_matches(".yaml")
                                    .trim_end_matches(".yml")
                                    .to_string();
                                profiles.push(profile_name);
                            }
                        }

                        if profiles.is_empty() {
                            println!("No profiles found in {}", policies_dir.display());
                            println!("Create a new profile with: purple profile create <name>");
                        } else {
                            println!("Available profiles:");
                            for (i, profile) in profiles.iter().enumerate() {
                                println!("  {}. {}", i + 1, profile);
                            }
                            println!("\nTotal: {} profile(s)", profiles.len());
                        }
                    }
                    Err(e) => {
                        eprintln!("Error reading policies directory: {}", e);
                    }
                }
            }
            ProfileCommands::Delete { name } => {
                println!("Deleting profile: {}", name);

                // Validate profile name
                if let Err(e) = validate_profile_name(name) {
                    eprintln!("Error: {}", e);
                    return;
                }

                // Check if profile exists
                let policy_path = format!("./policies/{}.yaml", name);
                let policy_path_buf = std::path::PathBuf::from(&policy_path);

                if !policy_path_buf.exists() {
                    eprintln!("Profile '{}' does not exist", name);
                    return;
                }

                // Delete the policy file
                match std::fs::remove_file(&policy_path_buf) {
                    Ok(_) => {
                        println!("Successfully deleted profile: {}", name);
                    }
                    Err(e) => {
                        eprintln!("Error deleting profile '{}': {}", name, e);
                    }
                }
            }
            ProfileCommands::Show { name } => {
                println!("Showing profile: {}", name);

                let policy_path = format!("./policies/{}.yaml", name);
                let policy_path_buf = std::path::PathBuf::from(&policy_path);

                if !policy_path_buf.exists() {
                    eprintln!("Profile '{}' does not exist", name);
                    return;
                }

                match policy::parser::load_policy_from_file(&policy_path_buf) {
                    Ok(policy) => {
                        println!("Profile: {}", policy.name);
                        if let Some(desc) = policy.description {
                            println!("Description: {}", desc);
                        }

                        println!("\nFilesystem Policy:");
                        println!(
                            "  Immutable paths: {}",
                            policy.filesystem.immutable_paths.len()
                        );
                        println!("  Scratch paths: {}", policy.filesystem.scratch_paths.len());
                        println!("  Output paths: {}", policy.filesystem.output_paths.len());
                        println!(
                            "  Working directory: {}",
                            policy.filesystem.working_dir.display()
                        );

                        println!("\nSyscall Policy:");
                        println!("  Default deny: {}", policy.syscalls.default_deny);
                        println!("  Allowed syscalls: {}", policy.syscalls.allow.len());
                        println!("  Denied syscalls: {}", policy.syscalls.deny.len());

                        println!("\nResource Policy:");
                        if let Some(cpu) = policy.resources.cpu_shares {
                            println!("  CPU shares: {}", cpu);
                        }
                        if let Some(mem) = policy.resources.memory_limit_bytes {
                            println!("  Memory limit: {}", mem);
                        }
                        if let Some(pids) = policy.resources.pids_limit {
                            println!("  Process limit: {}", pids);
                        }
                        if let Some(timeout) = policy.resources.session_timeout_seconds {
                            println!("  Timeout: {}s", timeout);
                        }

                        println!("\nCapability Policy:");
                        println!("  Default drop: {}", policy.capabilities.default_drop);
                        println!("  Added capabilities: {}", policy.capabilities.add.len());
                        println!("  Dropped capabilities: {}", policy.capabilities.drop.len());

                        println!("\nNetwork Policy:");
                        println!("  Isolated: {}", policy.network.isolated);
                        println!("  Outgoing ports: {}", policy.network.allow_outgoing.len());
                        println!("  Incoming ports: {}", policy.network.allow_incoming.len());

                        println!("\nAudit Policy:");
                        println!("  Enabled: {}", policy.audit.enabled);
                        println!("  Log path: {}", policy.audit.log_path.display());
                        println!("  Detail levels: {}", policy.audit.detail_level.len());
                    }
                    Err(e) => {
                        eprintln!("Error loading profile '{}': {}", name, e);
                    }
                }
            }
        },
        Commands::Run(args) => {
            let agent_command = args.command.clone();
            let profile_name = args.profile.clone();

            println!(
                "Running AI agent with profile '{}' and command: {:?}",
                profile_name, agent_command
            );

            // Load and compile policy
            let policy_path = format!("./policies/{}.yaml", profile_name);
            let policy_path_buf = std::path::PathBuf::from(&policy_path);
            match policy::parser::load_policy_from_file(&policy_path_buf) {
                Ok(policy) => {
                    match policy.compile() {
                        Ok(compiled_policy) => {
                            // DECISION POINT: Direct or Manager execution
                            if args.direct {
                                log::info!("Using direct execution (bypassing manager)");
                                // Legacy path: Direct execution
                                let mut sandbox = Sandbox::new(compiled_policy, agent_command);
                                match sandbox.execute() {
                                Ok(exit_code) => {
                                    if exit_code != 0 {
                                        std::process::exit(exit_code);
                                    }
                                }
                                Err(e) => {
                                    eprintln!("Sandbox execution failed: {}", e);
                                    eprintln!("\n=== Debugging Information ===");

                                    // Provide context-specific debugging help
                                    match e {
                                        PurpleError::SandboxError(ref msg) => {
                                            eprintln!("Sandbox setup error: {}", msg);
                                            eprintln!("Possible causes:");
                                            eprintln!(
                                                "  - Insufficient permissions for namespace operations"
                                            );
                                            eprintln!(
                                                "  - Missing kernel support for user namespaces"
                                            );
                                            eprintln!("  - Filesystem permissions issues");
                                            eprintln!("\nTry running with:");
                                            eprintln!(
                                                "  sudo sysctl -w kernel.unprivileged_userns_clone=1"
                                            );
                                        }
                                        PurpleError::FilesystemError(ref msg) => {
                                            eprintln!("Filesystem error: {}", msg);
                                            eprintln!("Possible causes:");
                                            eprintln!(
                                                "  - Missing directories or permission issues"
                                            );
                                            eprintln!(
                                                "  - Bind mount failures due to insufficient privileges"
                                            );
                                            eprintln!("  - Disk space or inode limitations");
                                            eprintln!("\nCheck directory permissions and try:");
                                            eprintln!("  sudo mkdir -p /tmp/purple-sandbox");
                                            eprintln!("  sudo chmod 777 /tmp/purple-sandbox");
                                        }
                                        PurpleError::ResourceError(ref msg) => {
                                            eprintln!("Resource limit error: {}", msg);
                                            eprintln!("Possible causes:");
                                            eprintln!(
                                                "  - Insufficient permissions to create cgroups"
                                            );
                                            eprintln!("  - Cgroup filesystem not mounted");
                                            eprintln!("  - System resource limits reached");
                                            eprintln!("\nCheck cgroup setup:");
                                            eprintln!("  mount | grep cgroup");
                                            eprintln!(
                                                "  sudo mount -t cgroup2 none /sys/fs/cgroup"
                                            );
                                        }
                                        PurpleError::SyscallError(ref msg) => {
                                            eprintln!("Syscall filtering error: {}", msg);
                                            eprintln!("Possible causes:");
                                            eprintln!("  - Missing libseccomp library");
                                            eprintln!("  - Invalid syscall names in policy");
                                            eprintln!("  - Kernel seccomp support disabled");
                                            eprintln!("\nInstall required packages:");
                                            eprintln!("  sudo dnf install libseccomp-devel");
                                        }
                                        PurpleError::PolicyError(ref msg) => {
                                            eprintln!("Policy configuration error: {}", msg);
                                            eprintln!("Possible causes:");
                                            eprintln!("  - Invalid YAML syntax in policy file");
                                            eprintln!("  - Unknown syscall or capability names");
                                            eprintln!("  - Missing required policy fields");
                                            eprintln!("\nValidate policy with:");
                                            eprintln!("  ./purple profile show {}", profile_name);
                                        }
                                        _ => {
                                            eprintln!("Unexpected error type: {:?}", e);
                                            eprintln!(
                                                "Please report this issue with the full error message."
                                            );
                                        }
                                    }

                                    std::process::exit(1);
                                }
                            }
                            } else {
                                log::info!("Using manager execution (default)");
                                // NEW DEFAULT: Manager-based execution
                                match execute_via_manager(compiled_policy, agent_command, &profile_name) {
                                    Ok(_) => {
                                        log::info!("Sandbox execution completed successfully");
                                    }
                                    Err(e) => {
                                        eprintln!("Sandbox execution failed: {}", e);
                                        eprintln!("\n=== Debugging Information ===");

                                        // Provide context-specific debugging help
                                        match e {
                                            PurpleError::SandboxError(ref msg) => {
                                                eprintln!("Sandbox setup error: {}", msg);
                                                eprintln!("Possible causes:");
                                                eprintln!(
                                                    "  - Insufficient permissions for namespace operations"
                                                );
                                                eprintln!(
                                                    "  - Missing kernel support for user namespaces"
                                                );
                                                eprintln!("  - Filesystem permissions issues");
                                                eprintln!("\nTry running with:");
                                                eprintln!(
                                                    "  sudo sysctl -w kernel.unprivileged_userns_clone=1"
                                                );
                                            }
                                            PurpleError::FilesystemError(ref msg) => {
                                                eprintln!("Filesystem error: {}", msg);
                                                eprintln!("Possible causes:");
                                                eprintln!(
                                                    "  - Missing directories or permission issues"
                                                );
                                                eprintln!(
                                                    "  - Bind mount failures due to insufficient privileges"
                                                );
                                                eprintln!("  - Disk space or inode limitations");
                                                eprintln!("\nCheck directory permissions and try:");
                                                eprintln!("  sudo mkdir -p /tmp/purple-sandbox");
                                                eprintln!("  sudo chmod 777 /tmp/purple-sandbox");
                                            }
                                            PurpleError::ResourceError(ref msg) => {
                                                eprintln!("Resource limit error: {}", msg);
                                                eprintln!("Possible causes:");
                                                eprintln!(
                                                    "  - Insufficient permissions to create cgroups"
                                                );
                                                eprintln!("  - Cgroup filesystem not mounted");
                                                eprintln!("  - System resource limits reached");
                                                eprintln!("\nCheck cgroup setup:");
                                                eprintln!("  mount | grep cgroup");
                                                eprintln!(
                                                    "  sudo mount -t cgroup2 none /sys/fs/cgroup"
                                                );
                                            }
                                            PurpleError::SyscallError(ref msg) => {
                                                eprintln!("Syscall filtering error: {}", msg);
                                                eprintln!("Possible causes:");
                                                eprintln!("  - Missing libseccomp library");
                                                eprintln!("  - Invalid syscall names in policy");
                                                eprintln!("  - Kernel seccomp support disabled");
                                                eprintln!("\nInstall required packages:");
                                                eprintln!("  sudo dnf install libseccomp-devel");
                                            }
                                            PurpleError::PolicyError(ref msg) => {
                                                eprintln!("Policy configuration error: {}", msg);
                                                eprintln!("Possible causes:");
                                                eprintln!("  - Invalid YAML syntax in policy file");
                                                eprintln!("  - Unknown syscall or capability names");
                                                eprintln!("  - Missing required policy fields");
                                                eprintln!("\nValidate policy with:");
                                                eprintln!("  ./purple profile show {}", profile_name);
                                            }
                                            _ => {
                                                eprintln!("Unexpected error type: {:?}", e);
                                                eprintln!(
                                                    "Please report this issue with the full error message."
                                                );
                                            }
                                        }

                                        std::process::exit(1);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("Error compiling policy for {}: {}", profile_name, e);
                            eprintln!("\n=== Policy Compilation Debugging ===");
                            eprintln!("Possible causes:");
                            eprintln!("  - Invalid YAML syntax in policy file");
                            eprintln!(
                                "  - Unknown syscall names (check src/sandbox/seccomp.rs for supported syscalls)"
                            );
                            eprintln!(
                                "  - Unknown capability names (must match Linux capability names)"
                            );
                            eprintln!("  - Missing required fields in policy");
                            eprintln!("\nPolicy file location: policies/{}.yaml", profile_name);
                            eprintln!("Validate with: ./purple profile show {}", profile_name);
                            eprintln!(
                                "Supported syscalls: read, write, openat, close, fstat, newfstatat, mmap, mprotect, munmap, brk, access, execve, arch_prctl, set_tid_address, set_robust_list, rseq, prlimit64, getrandom, exit_group, clone3"
                            );
                            eprintln!(
                                "Supported deny syscalls: mount, unmount, reboot, kexec_load, bpf, unlinkat, renameat2"
                            );
                            std::process::exit(1);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error loading policy for {}: {}", profile_name, e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Monitor(args) => {
            println!("Monitoring eBPF events for profile '{}'", args.profile);

            #[cfg(feature = "ebpf")]
            {
                use sandbox::ebpf::{EbpfConfig, EbpfEvent, EbpfLoader};
                use std::sync::Arc;
                use std::sync::atomic::{AtomicBool, Ordering};

                // Load policy to check eBPF settings
                let policy_path = format!("./policies/{}.yaml", args.profile);
                let policy_path_buf = std::path::PathBuf::from(&policy_path);

                match policy::parser::load_policy_from_file(&policy_path_buf) {
                    Ok(policy) => {
                        if !policy.ebpf_monitoring.enabled {
                            println!("eBPF monitoring not enabled in policy '{}'", args.profile);
                            println!("Enable it by adding to your policy file:");
                            println!("  ebpf_monitoring:");
                            println!("    enabled: true");
                            return;
                        }

                        // Create config from policy
                        let config = EbpfConfig {
                            trace_syscalls: policy.ebpf_monitoring.trace_syscalls,
                            trace_files: policy.ebpf_monitoring.trace_files,
                            trace_network: policy.ebpf_monitoring.trace_network,
                            enable_network_filter: false, // Monitor mode doesn't enforce blocking usually
                        };

                        // Create and load eBPF programs
                        let mut loader = match EbpfLoader::with_config(config) {
                            Ok(l) => l,
                            Err(e) => {
                                eprintln!("Failed to create eBPF loader: {}", e);
                                std::process::exit(1);
                            }
                        };

                        if let Err(e) = loader.load_programs() {
                            eprintln!("Failed to load eBPF programs: {}", e);
                            eprintln!("Note: eBPF loading requires root privileges (CAP_BPF)");
                            std::process::exit(1);
                        }

                        if let Err(e) = loader.attach_programs() {
                            eprintln!("Failed to attach eBPF programs: {}", e);
                            std::process::exit(1);
                        }

                        println!("eBPF monitoring active. Press Ctrl+C to stop.");
                        println!(
                            "Tracing: syscalls={}, files={}, network={}",
                            policy.ebpf_monitoring.trace_syscalls,
                            policy.ebpf_monitoring.trace_files,
                            policy.ebpf_monitoring.trace_network
                        );
                        println!("---");

                        // Set up Ctrl+C handler
                        let running = Arc::new(AtomicBool::new(true));
                        let r = running.clone();
                        if let Err(e) = ctrlc::set_handler(move || {
                            r.store(false, Ordering::SeqCst);
                        }) {
                            eprintln!("Warning: Could not set signal handler: {}", e);
                        }

                        // Note: Without registering any PIDs, we won't see events
                        // This monitor mode shows all events from registered sandboxes
                        // For testing, you could register the current PID:
                        // loader.register_sandbox_pid(std::process::id() as i32).ok();

                        // Poll events
                        let mut event_count = 0u64;
                        while running.load(Ordering::SeqCst) {
                            match loader.poll_events() {
                                Ok(events) => {
                                    for event in events {
                                        event_count += 1;
                                        match event {
                                            EbpfEvent::Syscall(e) => {
                                                println!("[{}] {}", event_count, e);
                                            }
                                            EbpfEvent::FileAccess(e) => {
                                                println!("[{}] {}", event_count, e);
                                            }
                                            EbpfEvent::Network(e) => {
                                                println!("[{}] {}", event_count, e);
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    eprintln!("Error polling events: {}", e);
                                }
                            }
                            // Small sleep to avoid busy loop
                            std::thread::sleep(std::time::Duration::from_millis(10));
                        }

                        println!("\nStopping eBPF monitoring...");
                        println!("Total events captured: {}", event_count);
                    }
                    Err(e) => {
                        eprintln!("Failed to load policy: {}", e);
                        std::process::exit(1);
                    }
                }
            }

            #[cfg(not(feature = "ebpf"))]
            {
                println!("eBPF feature not enabled. Please compile with --features ebpf");
            }
        }
        Commands::Replay(args) => {
            println!("🎬 Replaying session {}", args.session_id);

            // Check if session directory exists
            let session_dir = format!("./sessions/{}", args.session_id);
            if !std::path::Path::new(&session_dir).exists() {
                eprintln!("❌ Session {} not found", args.session_id);
                return;
            }

            // Look for audit log
            let audit_log_path = format!("{}/audit.log", session_dir);
            if std::path::Path::new(&audit_log_path).exists() {
                println!("📊 Session Audit Log:");
                println!("===================");

                if let Ok(log_content) = std::fs::read_to_string(&audit_log_path) {
                    // Show last 50 lines or full content if shorter
                    let lines: Vec<&str> = log_content.lines().collect();
                    let start = if lines.len() > 50 {
                        lines.len() - 50
                    } else {
                        0
                    };

                    for line in lines.iter().skip(start) {
                        println!("{}", line);
                    }

                    if lines.len() > 50 {
                        println!("... (showing last 50 of {} lines)", lines.len());
                    }
                } else {
                    eprintln!("⚠️  Failed to read audit log");
                }
            } else {
                println!("ℹ️  No audit log found for this session");
            }

            // Look for session metadata
            let metadata_path = format!("{}/metadata.json", session_dir);
            if std::path::Path::new(&metadata_path).exists() {
                println!("\n📋 Session Metadata:");
                println!("===================");

                if let Ok(metadata) = std::fs::read_to_string(&metadata_path) {
                    println!("{}", metadata);
                } else {
                    eprintln!("⚠️  Failed to read session metadata");
                }
            }

            println!(
                "\n💡 Tip: Use `purple audit --session {} --format json` for detailed analysis",
                args.session_id
            );
        }
        Commands::Sandboxes { action } => {
            let state_path = std::path::Path::new("./sessions/manager-state.json");

            // Load existing state or create new manager
            let mut manager = if state_path.exists() {
                match SandboxManager::load_state(state_path) {
                    Ok(state) => match SandboxManager::restore_from_state(state) {
                        Ok(mgr) => {
                            log::info!("Loaded manager state from {}", state_path.display());
                            mgr
                        }
                        Err(e) => {
                            log::warn!("Failed to restore manager state: {}, creating new manager", e);
                            SandboxManager::new()
                        }
                    },
                    Err(e) => {
                        log::warn!("Failed to load manager state: {}, creating new manager", e);
                        SandboxManager::new()
                    }
                }
            } else {
                log::info!("No existing manager state, creating new manager");
                SandboxManager::new()
            };

            match action {
                SandboxAction::List => match manager.list_sandboxes() {
                    Ok(sandboxes) => {
                        if sandboxes.is_empty() {
                            println!("📋 No running sandboxes found.");
                        } else {
                            println!("📋 Running Sandboxes:");
                            for (id, status) in sandboxes {
                                println!("  - {}: (status: {:?})", id, status);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("❌ Failed to list sandboxes: {}", e);
                        std::process::exit(1);
                    }
                },
                SandboxAction::Create { profile, name } => {
                    match manager.create_sandbox_from_profile(name.clone(), profile.clone()) {
                        Ok(sandbox_id) => {
                            println!(
                                "✅ Sandbox '{}' created successfully with ID: {}",
                                name, sandbox_id
                            );

                            // Save state after creation
                            if let Err(e) = std::fs::create_dir_all("./sessions") {
                                log::warn!("Failed to create sessions directory: {}", e);
                            } else if let Err(e) = manager.save_state(state_path) {
                                log::warn!("Failed to save manager state: {}", e);
                            } else {
                                log::info!("Manager state saved to {}", state_path.display());
                            }
                        }
                        Err(e) => {
                            eprintln!("❌ Failed to create sandbox: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
                SandboxAction::Stop { id } => match manager.cleanup_sandbox(id) {
                    Ok(_) => {
                        println!("✅ Sandbox '{}' stopped and cleaned up successfully", id);

                        // Save state after cleanup
                        if let Err(e) = manager.save_state(state_path) {
                            log::warn!("Failed to save manager state: {}", e);
                        } else {
                            log::info!("Manager state saved to {}", state_path.display());
                        }
                    }
                    Err(e) => {
                        eprintln!("❌ Failed to stop sandbox: {}", e);
                        std::process::exit(1);
                    }
                },
            }
        }
        Commands::Audit(args) => {
            println!("Generating audit report...");

            // Determine what to audit
            // Use --all flag or default to auditing all sessions if no specific session given
            let audit_all = args.all || args.session.is_none();
            let target_path = if audit_all {
                // Audit all sessions
                "./sessions/".to_string()
            } else {
                // Audit specific session
                format!("./sessions/{}", args.session.as_ref().unwrap())
            };

            if !std::path::Path::new(&target_path).exists() {
                eprintln!("Target not found: {}", target_path);
                return;
            }

            match args.format.as_str() {
                "json" => {
                    println!("Generating JSON audit report...");

                    // Simple JSON structure for now
                    let json_report = if audit_all {
                        format!(
                            "{{\"audit_type\": \"all_sessions\", \"timestamp\": \"{}\", \"sessions_found\": {}}}",
                            chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                            std::fs::read_dir(&target_path)
                                .map(|d| d.count())
                                .unwrap_or(0)
                        )
                    } else {
                        format!(
                            "{{\"audit_type\": \"session\", \"session_id\": \"{}\", \"timestamp\": \"{}\"}}",
                            args.session.as_ref().unwrap(),
                            chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
                        )
                    };

                    println!("{}", json_report);
                }
                "text" | "txt" => {
                    println!("Generating text audit report...");
                    println!("==============================");

                    if audit_all {
                        println!("Auditing all sessions in: {}", target_path);

                        if let Ok(entries) = std::fs::read_dir(&target_path) {
                            let mut session_count = 0;
                            for entry in entries.flatten() {
                                if entry.path().is_dir() {
                                    session_count += 1;
                                    println!("- Session: {}", entry.file_name().to_string_lossy());
                                }
                            }
                            println!("\nTotal sessions found: {}", session_count);
                        }
                    } else {
                        println!("Auditing session: {}", args.session.as_ref().unwrap());
                        println!("Session directory: {}", target_path);

                        // List session files
                        if let Ok(entries) = std::fs::read_dir(&target_path) {
                            let mut file_count = 0;
                            for entry in entries.flatten() {
                                file_count += 1;
                                println!("- {}", entry.file_name().to_string_lossy());
                            }
                            println!("\nTotal files: {}", file_count);
                        }
                    }
                }
                "html" => {
                    println!("🌐 Generating HTML audit report...");
                    println!("<html><body><h1>Purple AI Sandbox Audit Report</h1>");
                    println!(
                        "<p>Generated: {}</p>",
                        chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
                    );

                    if audit_all {
                        println!("<h2>All Sessions</h2><ul>");
                        if let Ok(entries) = std::fs::read_dir(&target_path) {
                            for entry in entries.flatten() {
                                if entry.path().is_dir() {
                                    println!("<li>{}</li>", entry.file_name().to_string_lossy());
                                }
                            }
                        }
                        println!("</ul>");
                    } else {
                        println!("<h2>Session: {}</h2>", args.session.as_ref().unwrap());
                        println!("<h3>Files:</h3><ul>");
                        if let Ok(entries) = std::fs::read_dir(&target_path) {
                            for entry in entries.flatten() {
                                println!("<li>{}</li>", entry.file_name().to_string_lossy());
                            }
                        }
                        println!("</ul>");
                    }

                    println!("</body></html>");
                }
                _ => {
                    eprintln!("❌ Unsupported format: {}", args.format);
                    println!("Supported formats: json, text, html");
                }
            }

            println!("✅ Audit report generation complete!");
        }
        Commands::Correlation { command } => {
            use correlation::cli::{CorrelationCli, CorrelationCommands};

            let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
            rt.block_on(async {
                match command {
                    CorrelationCommands::Start { profile, sandbox_id, threat_intel, attack } => {
                        let _ = threat_intel;
                        let _ = attack;
                        let config = correlation::models::CorrelationConfig::default();
                        let engine = correlation::engine::CorrelationEngine::new(config);
                        let session_id = engine.start_session(profile.clone(), sandbox_id.clone());
                        println!("\n============================================");
                        println!("Correlation Session Started");
                        println!("============================================");
                        println!("Session ID: {}", session_id);
                        println!("Profile: {}", profile);
                        if let Some(sid) = sandbox_id {
                            println!("Sandbox ID: {}", sid);
                        }
                        println!("Status: Active");
                        println!("============================================\n");
                    }
                    CorrelationCommands::Status { session_id, json: _ } => {
                        let config = correlation::models::CorrelationConfig::default();
                        let engine = correlation::engine::CorrelationEngine::new(config);
                        let session = engine.get_session(&session_id);
                        if let Some(s) = session {
                            println!("\n============================================");
                            println!("Session Status: {}", session_id);
                            println!("============================================");
                            println!("Profile: {}", s.profile_name);
                            println!("Status: {:?}", s.status);
                            println!("Events: {}", s.events.len());
                            println!("Anomalies: {}", s.anomalies.len());
                            println!("Risk Score: {:.1}", s.risk_score.cumulative_score);
                            println!("============================================\n");
                        } else {
                            println!("Session not found: {}", session_id);
                        }
                    }
                    CorrelationCommands::Event { session_id, event_type, pid, details, category, comm } => {
                        let config = correlation::models::CorrelationConfig::default();
                        let engine = correlation::engine::CorrelationEngine::new(config);
                        let event = correlation::models::RawEvent::new(
                            event_type, pid, details, category.parse().unwrap_or(correlation::models::EventCategory::Syscall),
                        );
                        engine.process_event(&session_id, event).await;
                        println!("Event submitted to session: {}", session_id);
                    }
                    CorrelationCommands::Intent { session_id, prompt, expected_actions, confidence } => {
                        let config = correlation::models::CorrelationConfig::default();
                        let engine = correlation::engine::CorrelationEngine::new(config);
                        let intent = correlation::models::LlmIntent::new(prompt, expected_actions, String::new());
                        intent.confidence = confidence;
                        engine.register_intent(&session_id, intent).await;
                        println!("Intent registered for session: {}", session_id);
                    }
                    CorrelationCommands::Complete { session_id, format, save } => {
                        let _ = save;
                        let config = correlation::models::CorrelationConfig::default();
                        let engine = correlation::engine::CorrelationEngine::new(config);
                        let session = engine.complete_session(&session_id).await;
                        if let Some(s) = session {
                            if format == "json" {
                                println!("{}", serde_json::to_string_pretty(&s).unwrap());
                            } else {
                                println!("\n============================================");
                                println!("Correlation Session Report");
                                println!("============================================");
                                println!("Session ID: {}", s.session_id);
                                println!("Profile: {}", s.profile_name);
                                println!("Events: {}", s.events.len());
                                println!("Anomalies: {}", s.anomalies.len());
                                println!("Risk Score: {:.1}/100 ({:?})", 
                                    s.risk_score.cumulative_score, s.risk_score.risk_level);
                                println!("============================================\n");
                            }
                        } else {
                            println!("Session not found: {}", session_id);
                        }
                    }
                    CorrelationCommands::Report { session_id, format, output } => {
                        let config = correlation::models::CorrelationConfig::default();
                        let engine = correlation::engine::CorrelationEngine::new(config);
                        let session = engine.get_session(&session_id);
                        if let Some(s) = session {
                            if format == "json" {
                                println!("{}", serde_json::to_string_pretty(&s).unwrap());
                            } else {
                                println!("\n============================================");
                                println!("Correlation Report for Session: {}", session_id);
                                println!("============================================");
                                println!("Events: {}", s.events.len());
                                println!("Anomalies: {}", s.anomalies.len());
                                println!("Risk: {:?} ({:.1})", s.risk_score.risk_level, s.risk_score.cumulative_score);
                                println!("ATT&CK Techniques: {}", s.attack_coverage.len());
                                for t in &s.attack_coverage {
                                    println!("  - {}", t);
                                }
                                println!("============================================\n");
                            }
                        } else {
                            println!("Session not found: {}", session_id);
                        }
                    }
                    CorrelationCommands::List => {
                        let config = correlation::models::CorrelationConfig::default();
                        let engine = correlation::engine::CorrelationEngine::new(config);
                        let sessions = engine.get_active_sessions();
                        println!("\nActive Correlation Sessions:");
                        println!("============================");
                        for session_id in sessions {
                            println!("  - {}", session_id);
                        }
                        println!("============================");
                        println!("Total: {} active sessions\n", sessions.len());
                    }
                    CorrelationCommands::Rules { action } => {
                        use correlation::rules::RulesEngine;
                        let rules_engine = correlation::rules::RulesEngine::new(true);
                        match action {
                            correlation::cli::RuleCommands::List => {
                                let rules = rules_engine.get_all_rules();
                                println!("\nDetection Rules:");
                                println!("================");
                                for rule in &rules {
                                    println!("  [{}] {}", 
                                        if rule.enabled { "ENABLED" } else { "DISABLED" },
                                        rule.name);
                                }
                                println!("================");
                                println!("Total: {} rules\n", rules.len());
                            }
                            correlation::cli::RuleCommands::Load { directory } => {
                                let _ = rules_engine.load_rules_from_directory(std::path::PathBuf::from(directory));
                            }
                        }
                    }
                }
            });
        }
    }
}
