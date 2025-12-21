// purple/src/sandbox/mod.rs

use crate::ai::{BudgetEnforcer, LLMAPIMonitor};
use crate::error::{PurpleError, Result};
use crate::policy::compiler::CompiledPolicy;

#[cfg(feature = "ebpf")]
use crate::sandbox::ebpf::{CorrelationEngine, EbpfLoader};

use nix::sys::wait::waitpid;
use nix::unistd::{ForkResult, execvp, fork};

use std::ffi::CString;
use std::fs;

use std::path::Path;
use std::process::{Command, Stdio};

pub mod capabilities;
pub mod cgroups;
pub mod filesystem;
pub mod linux_namespaces;
pub mod network;
pub mod seccomp;

#[cfg(feature = "ebpf")]
pub mod ebpf;

pub mod manager;

/// The main structure for managing a sandboxed execution environment.
#[derive(Debug)]
pub struct Sandbox {
    policy: CompiledPolicy,
    agent_command: Vec<String>,
    sandbox_id: String,
    sandbox_root: std::path::PathBuf,
    /// AI API monitor for tracking LLM calls
    #[allow(dead_code)]
    api_monitor: LLMAPIMonitor,
    /// Budget enforcer for cost/token limits
    budget_enforcer: Option<BudgetEnforcer>,
    /// eBPF loader for system tracing
    #[cfg(feature = "ebpf")]
    ebpf_loader: Option<EbpfLoader>,
    /// Correlation engine for intent-to-action analysis
    #[cfg(feature = "ebpf")]
    correlator: Option<CorrelationEngine>,
}

impl Sandbox {
    /// Creates a new Sandbox instance with a given compiled policy and agent command.
    pub fn new(policy: CompiledPolicy, agent_command: Vec<String>) -> Self {
        // Generate sandbox ID upfront so parent and child can both reference the same cgroup
        let sandbox_id = cgroups::generate_sandbox_id();
        let sandbox_root = std::path::PathBuf::from(format!("/tmp/purple-sandbox-{}", sandbox_id));

        // Initialize AI components
        let api_monitor = LLMAPIMonitor::new();

        // Initialize budget enforcer if policy has AI budget limits
        let budget_enforcer = if let Some(ai_policy) = &policy.ai_policy {
            if let Some(budget_config) = &ai_policy.budget {
                let budget = crate::ai::Budget::new(
                    budget_config.max_tokens,
                    budget_config.max_cost.clone(),
                )
                .ok();

                budget.map(BudgetEnforcer::new)
            } else {
                None
            }
        } else {
            None
        };

        Sandbox {
            policy,
            agent_command,
            sandbox_id,
            sandbox_root,
            api_monitor,
            budget_enforcer,
            #[cfg(feature = "ebpf")]
            ebpf_loader: None,
            #[cfg(feature = "ebpf")]
            correlator: None,
        }
    }

    /// Sets up signal handlers for the parent process
    fn setup_parent_signal_handlers(&self, child_pid: nix::unistd::Pid) {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        log::info!("Parent: Setting up signal handlers for graceful termination");

        // Create a flag to track if we're terminating
        let terminating = Arc::new(AtomicBool::new(false));
        let terminating_clone = terminating.clone();
        let child_pid_clone = child_pid;

        // Set up signal handler for SIGTERM using ctrlc crate approach
        match ctrlc::set_handler(move || {
            if terminating_clone.load(Ordering::SeqCst) {
                // Already terminating, ignore
                return;
            }
            terminating_clone.store(true, Ordering::SeqCst);

            log::info!("Parent: Received SIGTERM/SIGINT, initiating graceful shutdown");

            // Send SIGTERM to child process
            unsafe {
                if libc::kill(child_pid_clone.as_raw(), libc::SIGTERM) != 0 {
                    log::error!(
                        "Parent: Failed to send SIGTERM to child: {}",
                        std::io::Error::last_os_error()
                    );
                }
            }

            // Wait a bit for child to terminate gracefully
            std::thread::sleep(std::time::Duration::from_secs(2));

            // Check if child is still running using waitpid with WNOHANG
            let mut status = 0;
            unsafe {
                if libc::waitpid(child_pid_clone.as_raw(), &mut status, libc::WNOHANG) == 0 {
                    // Child still running, force kill
                    if libc::kill(child_pid_clone.as_raw(), libc::SIGKILL) != 0 {
                        log::error!(
                            "Parent: Failed to send SIGKILL to child: {}",
                            std::io::Error::last_os_error()
                        );
                    }
                } else {
                    // Child has already terminated
                    log::info!("Parent: Child process has already terminated");
                }
            }

            std::process::exit(0);
        }) {
            Ok(_) => {
                log::info!("Parent: Signal handlers configured for SIGTERM and SIGINT");
            }
            Err(e) => {
                log::warn!(
                    "Parent: Failed to set signal handler: {}. Signal handling will be disabled, but sandbox will continue.",
                    e
                );
                // Continue without signal handling rather than panicking
            }
        }
    }

    /// Sets up signal handlers for the child process
    fn setup_child_signal_handlers(&self) {
        log::info!("Child: Setting up signal handlers for graceful cleanup");

        // Store sandbox_id for signal handler access
        let sandbox_id = self.sandbox_id.clone();

        // Set up signal handler for SIGTERM
        match ctrlc::set_handler(move || {
            log::info!("Child: Received SIGTERM/SIGINT, initiating graceful cleanup");

            // Try to clean up cgroups
            let cgroup_manager = cgroups::CgroupManager::new(&sandbox_id);
            if let Err(e) = cgroup_manager.cleanup_cgroups() {
                log::debug!("Child: Failed to cleanup cgroups: {}", e);
            }

            log::info!("Child: Sandbox execution terminated gracefully");
            std::process::exit(143); // 128 + 15 (SIGTERM)
        }) {
            Ok(_) => {
                log::info!("Child: Signal handlers configured for SIGTERM and SIGINT");
            }
            Err(e) => {
                log::warn!(
                    "Child: Failed to set signal handler: {}. Signal handling will be disabled.",
                    e
                );
                // Continue without signal handling rather than panicking
            }
        }
    }

    /// Performs cleanup and exits the child process gracefully
    fn child_cleanup_and_exit(&self, exit_code: i32) -> ! {
        log::info!(
            "Child: Performing cleanup before exit with code {}",
            exit_code
        );

        // Attempt to clean up resources
        // Note: In a child process after fork, we have limited cleanup options
        // but we can try to clean up what we can

        // Try to remove ourselves from cgroups if possible
        let cgroup_manager = cgroups::CgroupManager::new(&self.sandbox_id);
        if let Err(e) = cgroup_manager.cleanup_cgroups() {
            log::debug!(
                "Child: Failed to cleanup cgroups (expected in child): {}",
                e
            );
        }

        // Log final status
        log::info!(
            "Child: Sandbox execution completed with exit code {}",
            exit_code
        );
        log::info!("Child: Policy applied: {}", self.policy.name);

        // Exit the process
        std::process::exit(exit_code)
    }

    /// Sets up a panic hook to attempt cleanup on unexpected failures
    fn setup_panic_cleanup_hook(&self) -> Result<()> {
        // Changed return type to match Result usage in other methods if needed, but original was void. Wait, original was void. I'll keep it void if I can, but I need to handle errors inside? No, it just sets hook.
        use std::panic;

        // Store sandbox_id for the panic hook
        let sandbox_id = self.sandbox_id.clone();
        let sandbox_root = self.sandbox_root.clone();

        // Set up a custom panic hook that attempts cleanup
        let original_hook = panic::take_hook();
        panic::set_hook(Box::new(move |panic_info| {
            // Log the panic information
            log::error!("❌ SANDBOX PANIC: {}", panic_info);

            // Attempt cleanup even during panic
            log::info!("🧹 Attempting emergency cleanup after panic...");

            // Try to clean up cgroups
            let cgroup_manager = cgroups::CgroupManager::new(&sandbox_id);
            if let Err(e) = cgroup_manager.cleanup_cgroups() {
                log::error!("⚠️  Failed to cleanup cgroups during panic: {}", e);
            } else {
                log::info!("✓ Cgroup cleanup completed during panic");
            }

            // Try to clean up filesystem
            if sandbox_root.exists() {
                if let Err(e) = std::fs::remove_dir_all(&sandbox_root) {
                    log::error!(
                        "⚠️  Failed to cleanup sandbox filesystem during panic: {}",
                        e
                    );
                } else {
                    log::info!("✓ Filesystem cleanup completed during panic");
                }
            }

            // Call the original panic hook to maintain normal panic behavior
            original_hook(panic_info);
        }));

        log::info!("✓ Panic cleanup hook installed");
        Ok(())
    }

    /// Cleans up orphaned filesystems from previous failed runs
    fn cleanup_orphaned_filesystems() -> Result<()> {
        use std::fs;

        log::info!("Cleaning up orphaned filesystems...");

        let sandbox_root = Path::new("/tmp/purple-sandbox");
        if !sandbox_root.exists() {
            log::info!("No orphaned sandbox filesystem found");
            return Ok(());
        }

        // Check if the sandbox directory is safe to clean up
        // We'll be conservative and only clean up if it looks like a failed run
        // (e.g., contains typical sandbox structure but no active processes)

        let mut is_safe_to_clean = true;
        let mut entry_count = 0;

        if let Ok(entries) = fs::read_dir(sandbox_root) {
            for entry in entries.flatten() {
                entry_count += 1;
                let entry_path = entry.path();

                // If we find certain critical files, be more cautious
                if entry_path.ends_with("proc") || entry_path.ends_with("sys") {
                    is_safe_to_clean = false;
                    log::warn!("Found mounted filesystem in orphaned sandbox - skipping cleanup");
                    break;
                }
            }
        }

        if is_safe_to_clean && entry_count > 0 {
            match fs::remove_dir_all(sandbox_root) {
                Ok(_) => {
                    log::info!("✓ Cleaned up orphaned sandbox filesystem");
                }
                Err(e) => {
                    log::warn!("⚠️  Failed to clean up orphaned filesystem: {}", e);
                }
            }
        } else if entry_count == 0 {
            // Empty directory, safe to remove
            if let Err(e) = fs::remove_dir(sandbox_root) {
                log::warn!("⚠️  Failed to remove empty sandbox directory: {}", e);
            } else {
                log::info!("✓ Removed empty sandbox directory");
            }
        }

        Ok(())
    }

    /// Executes the agent's command within the sandboxed environment.
    /// Returns the exit code of the sandboxed process.
    pub fn execute(&mut self) -> Result<i32> {
        log::info!("Sandbox: Executing agent command: {:?}", self.agent_command);
        log::info!("Sandbox: Policy being applied: {:?}", self.policy.name);

        // Clean up any orphaned resources from previous failed runs
        log::info!("🧹 Cleaning up orphaned resources from previous runs...");
        if let Err(e) = cgroups::CgroupManager::cleanup_orphaned_cgroups() {
            log::warn!("⚠️  Orphaned cgroup cleanup warning: {}", e);
        }
        if let Err(e) = Self::cleanup_orphaned_filesystems() {
            log::warn!("⚠️  Orphaned filesystem cleanup warning: {}", e);
        }
        log::info!("✓ Orphaned resource cleanup completed");

        // Initialize eBPF tracing if enabled
        #[cfg(feature = "ebpf")]
        if let Err(e) = self.initialize_ebpf_tracing() {
            log::warn!(
                "eBPF tracing initialization failed (continuing without eBPF): {}",
                e
            );
        }

        // Set up panic hook for cleanup on unexpected failures
        if let Err(e) = self.setup_panic_cleanup_hook() {
            log::warn!("Failed to setup panic hook: {}", e);
        }

        // Validate cgroup functionality before proceeding
        if self.policy.resources.has_resource_limits() {
            log::info!("Validating cgroup functionality for resource limits...");
            cgroups::CgroupManager::validate_cgroup_functionality()?;
            log::info!("✓ Cgroup functionality validated");
        } else {
            log::info!("No resource limits specified in policy, skipping cgroup validation");
        }

        // Setup cgroups BEFORE entering user namespace (cgroups require real root)
        let cgroup_manager = if self.policy.resources.has_resource_limits() {
            log::info!("Setting up cgroups before entering namespaces...");
            let manager = cgroups::CgroupManager::new(&self.sandbox_id);
            manager.setup_cgroups(&self.policy.resources)?;
            log::info!("✓ Cgroups configured with resource limits");
            Some(manager)
        } else {
            None
        };

        // Attach eBPF Network Filter to Cgroup if available
        #[cfg(feature = "ebpf")]
        if let Some(ref manager) = cgroup_manager
            && let Err(e) = self.attach_ebpf_to_cgroup(manager)
        {
            log::warn!("Failed to attach eBPF to cgroup: {}", e);
        }

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

                // Add child to cgroup BEFORE it continues execution
                if let Some(ref manager) = cgroup_manager {
                    log::info!("Parent: Adding child PID {} to cgroup", child);
                    if let Err(e) = manager.add_pid(child.as_raw() as u64) {
                        log::error!("Parent: Failed to add child to cgroup: {}", e);
                        // Kill the child and return error
                        let _ = nix::sys::signal::kill(child, nix::sys::signal::Signal::SIGKILL);
                        return Err(e);
                    }
                    log::info!("Parent: ✓ Child added to cgroup");
                }

                // Register child PID with eBPF filters
                #[cfg(feature = "ebpf")]
                if let Err(e) = self.register_child_pid(child.as_raw()) {
                    log::warn!("Failed to register child PID with eBPF filters: {}", e);
                }

                // Set up signal handler for parent to handle graceful termination
                self.setup_parent_signal_handlers(child);

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

                // Set up signal handlers for graceful cleanup
                self.setup_child_signal_handlers();

                // 5. Mount namespace (Private)
                if let Err(e) = linux_namespaces::unshare_mount_namespace() {
                    log::error!("Mount namespace setup failed: {}", e);
                    self.child_cleanup_and_exit(1);
                }

                // 6. Setup Filesystem (Fresh proc!)
                if let Err(e) = self.setup_filesystem() {
                    log::error!("Filesystem setup failed: {}", e);
                    self.child_cleanup_and_exit(1);
                }

                // 7. Caps, Seccomp (Resource limits already set up by parent via cgroups)
                log::info!("Child: Resource limits already applied via parent cgroup");

                if let Err(e) = self.drop_capabilities() {
                    log::error!("Drop capabilities failed: {}", e);
                    self.child_cleanup_and_exit(1);
                }

                if let Err(e) = self.apply_syscall_filtering() {
                    log::error!("Syscall filtering failed: {}", e);
                    self.child_cleanup_and_exit(1);
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
                        self.child_cleanup_and_exit(1);
                    }
                }
            }
            Err(e) => Err(PurpleError::NamespaceError(format!("Fork failed: {}", e))),
        }
    }

    /// Sets up filesystem isolation with bind mounts and chroot
    fn setup_filesystem(&self) -> Result<()> {
        filesystem::setup_filesystem(&self.policy, &self.sandbox_root)
    }

    /// Applies resource limits using cgroups
    #[allow(dead_code)]
    fn apply_resource_limits(&self) -> Result<()> {
        log::info!("Applying resource limits using cgroups...");

        // Use the pre-generated sandbox ID so parent can clean up the cgroup
        let cgroup_manager = cgroups::CgroupManager::new(&self.sandbox_id);

        // Set up cgroups and apply resource limits
        cgroup_manager.setup_cgroups(&self.policy.resources)?;

        // ACTUALLY add current process to the cgroup
        self.add_process_to_cgroup(&cgroup_manager)?;

        log::info!("Resource limits configured and enforced via cgroups");

        // Store cgroup info for cleanup (in real implementation would use RAII)
        log::info!("Process added to cgroup: {}", cgroup_manager.cgroup_name);

        Ok(())
    }

    /// Adds the current process to the specified cgroup
    #[allow(dead_code)]
    fn add_process_to_cgroup(&self, cgroup_manager: &cgroups::CgroupManager) -> Result<()> {
        log::info!("Adding current process to cgroup...");

        // Get current process ID
        let pid = std::process::id();
        log::info!(
            "Adding process {} to cgroup: {}",
            pid,
            cgroup_manager.cgroup_name
        );

        // Write PID to cgroup.procs to add process to cgroup
        let cgroup_procs_path = cgroup_manager.cgroup_path.join("cgroup.procs");

        fs::write(&cgroup_procs_path, pid.to_string()).map_err(|e| {
            PurpleError::ResourceError(format!(
                "Failed to add process {} to cgroup {}: {}",
                pid, cgroup_manager.cgroup_name, e
            ))
        })?;

        log::info!("Process successfully added to cgroup");

        // Verify the process is in the cgroup
        self.verify_process_in_cgroup(cgroup_manager)?;

        Ok(())
    }

    /// Verifies that the current process is in the specified cgroup
    #[allow(dead_code)]
    fn verify_process_in_cgroup(&self, cgroup_manager: &cgroups::CgroupManager) -> Result<()> {
        log::debug!("Verifying process is in cgroup...");

        let cgroup_procs_path = cgroup_manager.cgroup_path.join("cgroup.procs");
        let pid = std::process::id();

        // Read the cgroup.procs file to verify our PID is there
        let procs_content = fs::read_to_string(&cgroup_procs_path).map_err(|e| {
            PurpleError::ResourceError(format!(
                "Failed to read cgroup.procs for verification: {}",
                e
            ))
        })?;

        if procs_content
            .lines()
            .any(|line| line.trim() == pid.to_string())
        {
            log::info!(
                "✓ Verified: Process {} is in cgroup {}",
                pid,
                cgroup_manager.cgroup_name
            );
        } else {
            log::warn!(
                "⚠ Process {} not found in cgroup.procs, but addition appeared successful",
                pid
            );
        }

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

    /// Drops capabilities according to policy
    fn drop_capabilities(&self) -> Result<()> {
        capabilities::drop_capabilities(&self.policy.capabilities)
    }

    /// Applies network filtering rules based on the policy
    fn apply_network_filtering(&self) -> Result<()> {
        network::apply_network_filtering(&self.policy.network)
    }

    /// Cleans up resources and performs audit logging
    pub fn cleanup_and_audit(&self) -> Result<()> {
        log::info!("Performing cleanup and audit logging...");

        if self.policy.audit.enabled {
            log::info!(
                "Audit logging enabled - writing to {}",
                self.policy.audit.log_path.display()
            );

            // Actually write audit log entry
            self.write_audit_log_entry()?;

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

        // Clean up cgroup resources
        log::info!("Cleaning up cgroup resources...");
        let cgroup_manager = cgroups::CgroupManager::new(&self.sandbox_id);
        if let Err(e) = cgroup_manager.cleanup_cgroups() {
            log::warn!("Failed to cleanup cgroups: {} (non-fatal)", e);
        }

        // Clean up temporary sandbox directory
        log::info!("Cleaning up sandbox filesystem...");
        let sandbox_root = &self.sandbox_root;
        if sandbox_root.exists() {
            // Note: We can't unmount from parent process, but we can try to clean up
            // The mounts will be cleaned up automatically when the namespace is destroyed
            log::info!(
                "Sandbox directory exists at {} (will be cleaned by namespace destruction)",
                sandbox_root.display()
            );

            // Actually remove the directory structure
            if let Err(e) = fs::remove_dir_all(sandbox_root) {
                log::warn!("Failed to remove sandbox directory: {}", e);
            } else {
                log::info!("✓ Sandbox directory removed");
            }
        }

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

        // Budget enforcement summary
        if let Some(ref budget_enforcer) = self.budget_enforcer {
            let usage = budget_enforcer.get_usage();
            log::info!("  - Budget enforcement: enabled");
            log::info!("  - Tokens used: {}", usage.tokens_used);
            log::info!(
                "  - Cost incurred: {}",
                crate::ai::cost::CostCalculator::format_cost(usage.cost_cents)
            );
        } else {
            log::info!("  - Budget enforcement: disabled");
        }

        Ok(())
    }

    /// Writes an audit log entry to disk
    fn write_audit_log_entry(&self) -> Result<()> {
        use std::io::Write;
        use std::time::{SystemTime, UNIX_EPOCH};

        log::info!("Writing audit log entry...");

        // Ensure audit log directory exists
        if let Some(parent) = self.policy.audit.log_path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                PurpleError::AuditError(format!(
                    "Failed to create audit log directory {}: {}",
                    parent.display(),
                    e
                ))
            })?;
        }

        // Get current timestamp
        let timestamp = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => duration.as_secs(),
            Err(_) => 0,
        };

        // Create audit log entry
        let audit_entry = format!(
            "{}|{}|{}|{}|{}",
            timestamp,
            "sandbox_execution",
            self.policy.name,
            self.agent_command.join(" "),
            "completed"
        );

        // Write to audit log file (append mode)
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.policy.audit.log_path)
            .map_err(|e| {
                PurpleError::AuditError(format!(
                    "Failed to open audit log file {}: {}",
                    self.policy.audit.log_path.display(),
                    e
                ))
            })?;

        writeln!(file, "{}", audit_entry).map_err(|e| {
            PurpleError::AuditError(format!(
                "Failed to write to audit log file {}: {}",
                self.policy.audit.log_path.display(),
                e
            ))
        })?;

        log::info!("Audit log entry written successfully");

        Ok(())
    }

    /// Initialize eBPF tracing if enabled in policy
    #[cfg(feature = "ebpf")]
    pub fn initialize_ebpf_tracing(&mut self) -> Result<()> {
        use crate::sandbox::ebpf::EbpfConfig;

        // Check if eBPF is enabled in policy
        let ebpf_policy = &self.policy.ebpf_monitoring;
        if !ebpf_policy.enabled {
            log::info!("eBPF monitoring disabled in policy");
            return Ok(());
        }

        log::info!("Initializing eBPF tracing...");

        // Create config from policy
        let config = EbpfConfig {
            trace_syscalls: ebpf_policy.trace_syscalls,
            trace_files: ebpf_policy.trace_files,
            trace_network: ebpf_policy.trace_network,
            enable_network_filter: true,
        };

        // Create the loader with config
        match EbpfLoader::with_config(config) {
            Ok(mut loader) => {
                // Load and attach programs
                if let Err(e) = loader.load_programs() {
                    log::warn!(
                        "Failed to load eBPF programs: {} (continuing without eBPF)",
                        e
                    );
                    return Ok(());
                }

                if let Err(e) = loader.attach_programs() {
                    log::warn!(
                        "Failed to attach eBPF programs: {} (continuing without eBPF)",
                        e
                    );
                    return Ok(());
                }

                self.ebpf_loader = Some(loader);

                // Initialize correlation engine if enabled
                if ebpf_policy.correlation_enabled {
                    self.correlator = Some(CorrelationEngine::new(300));
                }

                log::info!("✓ eBPF tracing initialized and attached");
            }
            Err(e) => {
                log::warn!(
                    "eBPF loader creation failed: {} (continuing without eBPF)",
                    e
                );
            }
        }

        Ok(())
    }

    /// Register child PID with eBPF filters
    #[cfg(feature = "ebpf")]
    pub fn register_child_pid(&mut self, pid: i32) -> Result<()> {
        if let Some(loader) = &mut self.ebpf_loader {
            if let Err(e) = loader.register_sandbox_pid(pid) {
                log::warn!("Failed to register PID {} with eBPF: {}", pid, e);
            } else {
                log::info!("Registered PID {} with eBPF filters", pid);
            }
        }
        Ok(())
    }

    /// Attach eBPF programs to the sandbox cgroup
    #[cfg(feature = "ebpf")]
    pub fn attach_ebpf_to_cgroup(&mut self, cgroup_manager: &cgroups::CgroupManager) -> Result<()> {
        if let Some(loader) = &mut self.ebpf_loader {
            // Open cgroup directory as File
            let cgroup_path = &cgroup_manager.cgroup_path;
            let cgroup_file = std::fs::File::open(cgroup_path).map_err(|e| {
                PurpleError::ResourceError(format!("Failed to open cgroup for eBPF attach: {}", e))
            })?;

            // loader.attach_network_filter takes std::fs::File which implements AsRawFd
            if let Err(e) = loader.attach_network_filter(cgroup_file) {
                log::warn!("Failed to attach network filter: {}", e);
            } else {
                log::info!("✓ Network filter attached to sandbox cgroup");

                // Populate IPv4 blocklist
                if !self.policy.network.blocked_ips_v4.is_empty() {
                    log::info!(
                        "Applying {} IPv4 block rules...",
                        self.policy.network.blocked_ips_v4.len()
                    );
                    for ip in &self.policy.network.blocked_ips_v4 {
                        if let Err(e) = loader.block_ip(*ip) {
                            log::warn!("Failed to block IPv4 {}: {}", ip, e);
                        } else {
                            log::debug!("Blocked IPv4: {}", ip);
                        }
                    }
                }

                // Populate IPv6 blocklist
                if !self.policy.network.blocked_ips_v6.is_empty() {
                    log::info!(
                        "Applying {} IPv6 block rules...",
                        self.policy.network.blocked_ips_v6.len()
                    );
                    for ip in &self.policy.network.blocked_ips_v6 {
                        if let Err(e) = loader.block_ip_v6(*ip) {
                            log::warn!("Failed to block IPv6 {}: {}", ip, e);
                        } else {
                            log::debug!("Blocked IPv6: {}", ip);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Generate correlation report
    #[cfg(feature = "ebpf")]
    #[allow(dead_code)] // TODO: Implement correlation report generation
    pub fn generate_correlation_report(
        &self,
    ) -> Result<Vec<crate::sandbox::ebpf::correlator::CorrelationResult>> {
        if let Some(correlator) = &self.correlator {
            Ok(correlator.correlate())
        } else {
            Ok(Vec::new())
        }
    }
}
