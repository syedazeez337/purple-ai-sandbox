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
                let policy_path = format!("./policies/{}.yaml", name);
                let policy_path_buf = std::path::PathBuf::from(&policy_path);
                match policy::parser::load_policy_from_file(&policy_path_buf) {
                    Ok(policy) => {
                        println!("Successfully loaded policy for {}: {:?}", name, policy);
                        match policy.compile() {
                            Ok(compiled_policy) => {
                                println!(
                                    "Successfully compiled policy for {}: {:?}",
                                    name, compiled_policy
                                );
                                // TODO: Implement actual profile creation logic (e.g., save compiled policy)
                            }
                            Err(e) => {
                                eprintln!("Error compiling policy for {}: {}", name, e);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Error loading policy for {}: {}", name, e);
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
                            let sandbox = Sandbox::new(compiled_policy, agent_command);
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
    }
}
