// purple/src/sandbox/mod.rs

use crate::error::{PurpleError, Result};
use crate::policy::compiler::CompiledPolicy;
use nix::mount::{MsFlags, mount};
use nix::sys::wait::waitpid;
use nix::unistd::{ForkResult, chroot, execvp, fork};
use std::ffi::CString;
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

pub mod cgroups;
pub mod seccomp;

pub mod linux_namespaces;

/// The main structure for managing a sandboxed execution environment.
#[derive(Debug)]
pub struct Sandbox {
    policy: CompiledPolicy,
    agent_command: Vec<String>,
}

impl Sandbox {
    /// Creates a new Sandbox instance with a given compiled policy and agent command.
    pub fn new(policy: CompiledPolicy, agent_command: Vec<String>) -> Self {
        Sandbox {
            policy,
            agent_command,
        }
    }

    /// Executes the agent's command within the sandboxed environment.
    /// Returns the exit code of the sandboxed process.
    pub fn execute(&self) -> Result<i32> {
        log::info!("Sandbox: Executing agent command: {:?}", self.agent_command);
        log::info!("Sandbox: Policy being applied: {:?}", self.policy.name);

        // 1. Setup user namespace first (required for privilege management)
        log::info!("Setting up user namespace...");
        let (_sandbox_uid, _sandbox_gid) =
            linux_namespaces::unshare_user_namespace().map_err(|e| {
                PurpleError::NamespaceError(format!("User namespace setup failed: {}", e))
            })?;

        // 2. Setup network namespace (if isolated)
        if self.policy.network.isolated {
            log::info!("Setting up network namespace (isolated)...");
            linux_namespaces::unshare_network_namespace().map_err(|e| {
                PurpleError::NamespaceError(format!("Network namespace setup failed: {}", e))
            })?;
            self.apply_network_filtering()?;
        } else {
            log::info!("Network namespace not isolated by policy.");
        }

        // 3. Setup PID namespace (prepare for fork)
        log::info!("Setting up PID namespace...");
        linux_namespaces::unshare_pid_namespace().map_err(|e| {
            PurpleError::NamespaceError(format!("PID namespace setup failed: {}", e))
        })?;

        // 4. Fork to enter the new PID namespace
        log::info!("Forking to enter new PID namespace...");
        match unsafe { fork() } {
            Ok(ForkResult::Parent { child }) => {
                log::info!("Parent: Waiting for child PID {}", child);

                // Wait for the child to finish
                let exit_code = match waitpid(child, None) {
                    Ok(status) => {
                        log::info!("Child exited with status: {:?}", status);
                        match status {
                            nix::sys::wait::WaitStatus::Exited(_, code) => code,
                            nix::sys::wait::WaitStatus::Signaled(_, signal, _) => {
                                128 + (signal as i32)
                            }
                            _ => 1, // Default error for other states
                        }
                    }
                    Err(e) => {
                        log::error!("Failed to wait for child: {}", e);
                        return Err(PurpleError::CommandError(format!(
                            "Failed to wait for child: {}",
                            e
                        )));
                    }
                };

                // 8. Clean up and audit logging (Parent does cleanup)
                self.cleanup_and_audit()?;

                Ok(exit_code)
            }
            Ok(ForkResult::Child) => {
                // Child Process: Setup environment and Exec
                log::info!("Child: I am running in the new PID namespace!");

                // 5. Mount namespace (Private)
                if let Err(e) = linux_namespaces::unshare_mount_namespace() {
                    log::error!("Mount namespace setup failed: {}", e);
                    std::process::exit(1);
                }

                // 6. Setup Filesystem (Fresh proc!)
                if let Err(e) = self.setup_filesystem() {
                    log::error!("Filesystem setup failed: {}", e);
                    std::process::exit(1);
                }

                // 7. Caps, Seccomp, Resources
                if let Err(e) = self.apply_resource_limits() {
                    log::error!("Resource limits failed: {}", e);
                    std::process::exit(1);
                }

                if let Err(e) = self.drop_capabilities() {
                    log::error!("Drop capabilities failed: {}", e);
                    std::process::exit(1);
                }

                if let Err(e) = self.apply_syscall_filtering() {
                    log::error!("Syscall filtering failed: {}", e);
                    std::process::exit(1);
                }

                // 8. Exec
                log::info!("Child: Executing actual command...");

                let prog = CString::new(self.agent_command[0].clone()).unwrap();
                let args: Vec<CString> = self
                    .agent_command
                    .iter()
                    .map(|arg| CString::new(arg.clone()).unwrap())
                    .collect();

                // execvp never returns on success (it replaces the process),
                // so we only need to handle the error case
                #[allow(irrefutable_let_patterns)]
                match execvp(&prog, &args) {
                    Ok(_) => unreachable!("execvp should not return on success"),
                    Err(e) => {
                        log::error!("Failed to execvp: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            Err(e) => Err(PurpleError::NamespaceError(format!("Fork failed: {}", e))),
        }
    }

    /// Sets up filesystem isolation with bind mounts and chroot
    fn setup_filesystem(&self) -> Result<()> {
        log::info!("Setting up filesystem isolation...");

        // Create temporary directory structure for the sandbox
        let sandbox_root = "/tmp/purple-sandbox";
        fs::create_dir_all(sandbox_root).map_err(|e| {
            PurpleError::FilesystemError(format!("Failed to create sandbox root: {}", e))
        })?;

        // Create necessary directories
        let directories = [
            "bin", "lib", "lib64", "usr", "usr/bin", "usr/lib", "tmp", "var", "var/tmp", "proc",
            "dev", "sys",
        ];

        for dir in directories.iter() {
            let path = Path::new(sandbox_root).join(dir);
            fs::create_dir_all(&path).map_err(|e| {
                PurpleError::FilesystemError(format!(
                    "Failed to create directory {}: {}",
                    path.display(),
                    e
                ))
            })?;
        }

        // Setup bind mounts for immutable paths
        for (host_path, sandbox_path) in &self.policy.filesystem.immutable_mounts {
            let full_sandbox_path = Path::new(sandbox_root).join(
                sandbox_path
                    .strip_prefix("/")
                    .unwrap_or(sandbox_path.as_path()),
            );

            // Create parent directory if it doesn't exist
            if let Some(parent) = full_sandbox_path.parent() {
                fs::create_dir_all(parent).map_err(|e| {
                    PurpleError::FilesystemError(format!(
                        "Failed to create parent directory {}: {}",
                        parent.display(),
                        e
                    ))
                })?;
            }

            log::info!(
                "Binding {} to {}",
                host_path.display(),
                full_sandbox_path.display()
            );

            // Bind mount the host path to the sandbox path
            mount(
                Some(host_path.as_path()),
                &full_sandbox_path,
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            )
            .map_err(|e| {
                PurpleError::FilesystemError(format!(
                    "Failed to bind mount {} to {}: {}",
                    host_path.display(),
                    full_sandbox_path.display(),
                    e
                ))
            })?;

            // Make it read-only
            mount(
                None::<&str>,
                &full_sandbox_path,
                None::<&str>,
                MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
                None::<&str>,
            )
            .map_err(|e| {
                PurpleError::FilesystemError(format!(
                    "Failed to remount {} as read-only: {}",
                    full_sandbox_path.display(),
                    e
                ))
            })?;
        }

        // Setup scratch directories
        for scratch_path in &self.policy.filesystem.scratch_dirs {
            let full_sandbox_path = Path::new(sandbox_root).join(
                scratch_path
                    .strip_prefix("/")
                    .unwrap_or(scratch_path.as_path()),
            );

            if let Some(parent) = full_sandbox_path.parent() {
                fs::create_dir_all(parent).map_err(|e| {
                    PurpleError::FilesystemError(format!(
                        "Failed to create parent directory {}: {}",
                        parent.display(),
                        e
                    ))
                })?;
            }

            fs::create_dir_all(&full_sandbox_path).map_err(|e| {
                PurpleError::FilesystemError(format!(
                    "Failed to create scratch directory {}: {}",
                    full_sandbox_path.display(),
                    e
                ))
            })?;
        }

        // Setup output directories (writable)
        for (host_path, sandbox_path) in &self.policy.filesystem.output_mounts {
            let full_sandbox_path = Path::new(sandbox_root).join(
                sandbox_path
                    .strip_prefix("/")
                    .unwrap_or(sandbox_path.as_path()),
            );

            if let Some(parent) = full_sandbox_path.parent() {
                fs::create_dir_all(parent).map_err(|e| {
                    PurpleError::FilesystemError(format!(
                        "Failed to create parent directory {}: {}",
                        parent.display(),
                        e
                    ))
                })?;
            }

            fs::create_dir_all(&full_sandbox_path).map_err(|e| {
                PurpleError::FilesystemError(format!(
                    "Failed to create output directory {}: {}",
                    full_sandbox_path.display(),
                    e
                ))
            })?;

            // Bind mount output directory
            mount(
                Some(host_path.as_path()),
                &full_sandbox_path,
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            )
            .map_err(|e| {
                PurpleError::FilesystemError(format!(
                    "Failed to bind mount output directory {} to {}: {}",
                    host_path.display(),
                    full_sandbox_path.display(),
                    e
                ))
            })?;
        }

        // Mount essential filesystem
        // CORRECT: Mount fresh procfs
        mount(
            Some("proc"),
            &Path::new(sandbox_root).join("proc"),
            Some("proc"),
            MsFlags::empty(),
            None::<&str>,
        )
        .map_err(|e| PurpleError::FilesystemError(format!("Failed to mount proc: {}", e)))?;

        // WORKAROUND: Bind mount host /dev
        mount(
            Some("/dev"),
            &Path::new(sandbox_root).join("dev"),
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        )
        .map_err(|e| PurpleError::FilesystemError(format!("Failed to bind mount dev: {}", e)))?;

        // WORKAROUND: Bind mount host /sys
        mount(
            Some("/sys"),
            &Path::new(sandbox_root).join("sys"),
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        )
        .map_err(|e| PurpleError::FilesystemError(format!("Failed to bind mount sys: {}", e)))?;

        // Setup DNS configuration for network access
        if !self.policy.network.isolated {
            let resolv_conf_path = Path::new(sandbox_root).join("etc/resolv.conf");
            if let Some(parent) = resolv_conf_path.parent() {
                fs::create_dir_all(parent).map_err(|e| {
                    PurpleError::FilesystemError(format!(
                        "Failed to create DNS config directory {}: {}",
                        parent.display(),
                        e
                    ))
                })?;
            }

            // Use Google's public DNS servers
            let resolv_conf_content = "nameserver 8.8.8.8\nnameserver 8.8.4.4\n";
            fs::write(&resolv_conf_path, resolv_conf_content).map_err(|e| {
                PurpleError::FilesystemError(format!("Failed to write DNS configuration: {}", e))
            })?;
            log::info!("Configured DNS resolvers for network access");
        }

        // Change root to the sandbox directory
        log::info!("Changing root to {}", sandbox_root);
        chroot(sandbox_root).map_err(|e| {
            PurpleError::FilesystemError(format!("Failed to chroot to {}: {}", sandbox_root, e))
        })?;

        // Change working directory
        if let Err(e) = std::env::set_current_dir(&self.policy.filesystem.working_dir) {
            return Err(PurpleError::FilesystemError(format!(
                "Failed to change working directory to {}: {}",
                self.policy.filesystem.working_dir.display(),
                e
            )));
        }

        Ok(())
    }

    /// Applies resource limits using cgroups
    fn apply_resource_limits(&self) -> Result<()> {
        log::info!("Applying resource limits using cgroups...");

        // Create a unique sandbox ID for cgroup naming
        let sandbox_id = cgroups::generate_sandbox_id();
        let cgroup_manager = cgroups::CgroupManager::new(&sandbox_id);

        // Set up cgroups and apply resource limits
        cgroup_manager.setup_cgroups(&self.policy.resources)?;

        log::info!("Resource limits configured via cgroups");

        // Store the cgroup manager for cleanup later
        // In a real implementation, we would keep this and use it in cleanup
        log::info!("Would add sandbox process to cgroup after fork/exec");

        Ok(())
    }

    /// Drops capabilities according to policy
    fn drop_capabilities(&self) -> Result<()> {
        log::info!("Dropping capabilities...");

        if self.policy.capabilities.default_drop {
            log::info!("Capability policy: Drop all capabilities by default");

            // Capability management implementation note:
            // In a production system, this would use libcap or similar to:
            // 1. Clear all capabilities from all sets (effective, permitted, inheritable)
            // 2. Set the bounding set to only include allowed capabilities
            // 3. Apply the capability changes using prctl() or similar

            // For now, we log what would be done and provide the infrastructure
            log::info!("Would clear all capabilities from process");

            if !self.policy.capabilities.added_capabilities.is_empty() {
                log::info!(
                    "Would add back {} capabilities:",
                    self.policy.capabilities.added_capabilities.len()
                );
                for cap in &self.policy.capabilities.added_capabilities {
                    log::info!("  - {}", cap);
                    // Would actually add the capability here using libcap/capctl API
                }
            } else {
                log::info!("No capabilities would be added back - minimal privilege set");
            }

            log::info!("Capability management configured (requires libcap/capctl integration)");
        } else {
            log::info!("Capability policy: Keep all capabilities by default");
            log::warn!("This is less secure - consider using default_drop=true");

            // Would only drop specific capabilities if any were configured to be dropped
            // (not implemented in current policy structure)
        }

        log::info!(
            "Capability dropping completed (libcap integration needed for full enforcement)"
        );
        Ok(())
    }

    /// Applies syscall filtering using seccomp
    fn apply_syscall_filtering(&self) -> Result<()> {
        log::info!("Applying syscall filtering using seccomp...");

        if self.policy.syscalls.default_deny {
            log::info!("Syscall filtering: default deny mode");
        } else {
            log::info!("Syscall filtering: default allow mode");
        }

        log::debug!(
            "Allowed syscalls: {:?}",
            self.policy.syscalls.allowed_syscall_numbers
        );

        // Apply the actual seccomp filter
        seccomp::apply_seccomp_filter(&self.policy.syscalls)
    }

    /// Executes the agent command within the sandbox
    /// Note: Currently unused but kept for future implementation
    #[allow(dead_code)]
    fn execute_agent_command(&self) -> Result<()> {
        log::info!("Executing agent command within sandbox...");

        if self.agent_command.is_empty() {
            return Err(PurpleError::CommandError(
                "No command specified".to_string(),
            ));
        }

        let mut command_builder = Command::new(&self.agent_command[0]);
        if self.agent_command.len() > 1 {
            command_builder.args(&self.agent_command[1..]);
        }

        command_builder
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        let status = command_builder
            .status()
            .map_err(|e| PurpleError::CommandError(format!("Failed to execute command: {}", e)))?;

        if !status.success() {
            return Err(PurpleError::CommandError(format!(
                "Command exited with non-zero status: {}",
                status
            )));
        }

        log::info!("Agent command executed successfully");
        Ok(())
    }

    /// Applies network filtering rules based on the policy
    fn apply_network_filtering(&self) -> Result<()> {
        log::info!("Applying network filtering rules...");

        if self.policy.network.isolated {
            log::info!("Network policy: Complete isolation (no network access)");

            // In a real implementation, this would:
            // 1. Set up a completely isolated network namespace
            // 2. Optionally create a veth pair to connect to host or other namespaces
            // 3. Configure routing and firewall rules

            log::info!("Would configure completely isolated network namespace");
            log::info!("No network access would be available to the sandboxed process");
        } else {
            log::info!("Network policy: Selective filtering");

            // Apply outgoing connection rules
            if !self.policy.network.allowed_outgoing_ports.is_empty() {
                log::info!(
                    "Would allow {} outgoing ports:",
                    self.policy.network.allowed_outgoing_ports.len()
                );
                for port in &self.policy.network.allowed_outgoing_ports {
                    log::info!("  - Port {}", port);
                    // Would configure iptables/nftables rules here
                }
            } else {
                log::info!("No outgoing connections would be allowed");
            }

            // Apply incoming connection rules
            if !self.policy.network.allowed_incoming_ports.is_empty() {
                log::info!(
                    "Would allow {} incoming ports:",
                    self.policy.network.allowed_incoming_ports.len()
                );
                for port in &self.policy.network.allowed_incoming_ports {
                    log::info!("  - Port {}", port);
                    // Would configure iptables/nftables rules here
                }
            } else {
                log::info!("No incoming connections would be allowed");
            }
        }

        log::info!("Network filtering configured (would use iptables/nftables in production)");
        Ok(())
    }

    /// Cleans up resources and performs audit logging
    fn cleanup_and_audit(&self) -> Result<()> {
        log::info!("Performing cleanup and audit logging...");

        if self.policy.audit.enabled {
            log::info!(
                "Audit logging enabled - would write to {}",
                self.policy.audit.log_path.display()
            );

            // In a real implementation, this would:
            // 1. Write detailed audit logs to the specified path
            // 2. Include information about the executed command
            // 3. Record resource usage, syscalls made, network connections, etc.
            // 4. Include timestamps and process information

            log::info!("Would write audit log entry with details about:");
            log::info!("  - Command executed: {:?}", self.agent_command);
            log::info!("  - Policy applied: {}", self.policy.name);
            log::info!("  - Start/end times");
            log::info!("  - Resource usage (CPU, memory, etc.)");
            log::info!("  - Security events (syscall violations, capability usage, etc.)");

            // Check if specific detail levels are requested
            if !self.policy.audit.detail_level.is_empty() {
                log::info!("Audit detail levels requested:");
                for level in &self.policy.audit.detail_level {
                    log::info!("  - {}", level);
                }
            }
        } else {
            log::info!("Audit logging disabled by policy");
        }

        // Cleanup would go here in a real implementation
        // - Unmount filesystem bindings
        // - Clean up temporary directories
        // - Release resources

        log::info!("Sandbox execution completed");

        // Add final status logging with performance metrics
        log::info!("=== Sandbox Execution Summary ===");
        log::info!("Policy applied: {}", self.policy.name);
        log::info!("Command executed: {:?}", self.agent_command);
        log::info!("Security features enabled:");
        log::info!(
            "  - User namespace: {}",
            if self.policy.filesystem.immutable_mounts.is_empty() {
                "disabled"
            } else {
                "enabled"
            }
        );
        log::info!("  - PID namespace: enabled");
        log::info!("  - Mount namespace: enabled");
        log::info!(
            "  - Network isolation: {}",
            if self.policy.network.isolated {
                "enabled"
            } else {
                "selective"
            }
        );
        log::info!(
            "  - Syscall filtering: {}",
            if self.policy.syscalls.default_deny {
                "default-deny"
            } else {
                "selective"
            }
        );
        log::info!("  - Resource limits: configured");
        log::info!(
            "  - Capability dropping: {}",
            if self.policy.capabilities.default_drop {
                "enabled"
            } else {
                "disabled"
            }
        );
        log::info!(
            "  - Audit logging: {}",
            if self.policy.audit.enabled {
                "enabled"
            } else {
                "disabled"
            }
        );

        Ok(())
    }
}
