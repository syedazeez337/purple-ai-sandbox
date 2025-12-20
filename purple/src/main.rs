mod ai;
mod cli;
mod error;
mod policy;
mod sandbox;
#[macro_use]
mod logging;

#[cfg(test)]
mod tests;

use clap::Parser;
use cli::{Cli, Commands, ProfileCommands};
use error::PurpleError;
use log::LevelFilter;
use logging::init_logging;
use sandbox::Sandbox; // Import Sandbox

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
        Commands::Init => {
            println!("Initializing Purple environment...");
            // TODO: Implement environment initialization logic
        }
        Commands::Profile { command } => match command {
            ProfileCommands::Create { name } => {
                println!("Creating profile: {}", name);

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
            let agent_command = args.command.clone(); // Clone to pass into Sandbox::new
            let profile_name = args.profile.clone();

            println!(
                "Running AI agent with profile '{}' and command: {:?}",
                profile_name, agent_command
            );

            // For now, load/compile policy from example file for run command as well.
            // In future, this would load a saved compiled policy for the profile.
            let policy_path = format!("./policies/{}.yaml", profile_name);
            let policy_path_buf = std::path::PathBuf::from(&policy_path);
            match policy::parser::load_policy_from_file(&policy_path_buf) {
                Ok(policy) => {
                    match policy.compile() {
                        Ok(compiled_policy) => {
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
                        ctrlc::set_handler(move || {
                            r.store(false, Ordering::SeqCst);
                        })
                        .expect("Failed to set Ctrl+C handler");

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
            println!("Replaying session {}", args.session_id);
            // TODO: Implement session replay logic
            println!("Session replay not yet implemented");
        }
        Commands::Audit(args) => {
            println!("Generating audit report for session {}", args.session);

            #[cfg(feature = "ebpf")]
            {
                // TODO: Implement actual audit logic
                println!("Audit format: {}", args.format);
                println!("Audit report generation not yet implemented");
            }

            #[cfg(not(feature = "ebpf"))]
            {
                println!("eBPF feature not enabled. Please compile with --features ebpf");
            }
        }
    }
}
