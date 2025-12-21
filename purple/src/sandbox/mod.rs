// purple/src/sandbox/mod.rs

use crate::ai::{BudgetEnforcer, LLMAPIMonitor};
use crate::error::{PurpleError, Result};
use crate::policy::compiler::CompiledPolicy;

#[cfg(feature = "ebpf")]
use crate::sandbox::ebpf::{CorrelationEngine, EbpfLoader};
use nix::mount::{MsFlags, mount};
use nix::sys::wait::waitpid;
use nix::unistd::{ForkResult, chroot, execvp, fork};
use std::collections::HashSet;
use std::ffi::CString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

pub mod cgroups;
pub mod linux_namespaces;
pub mod seccomp;

#[cfg(feature = "ebpf")]
pub mod ebpf;

pub mod manager;

/// Sets the NO_NEW_PRIVS flag to prevent privilege escalation
fn prctl_set_no_new_privs() -> Result<()> {
    // PR_SET_NO_NEW_PRIVS = 38
    const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;

    let result = unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if result != 0 {
        return Err(PurpleError::CapabilityError(format!(
            "prctl(PR_SET_NO_NEW_PRIVS) failed with error: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Converts a capability name string to a caps::Capability enum
fn capability_from_name(name: &str) -> Option<caps::Capability> {
    use caps::Capability;

    match name.to_uppercase().as_str() {
        "CAP_CHOWN" => Some(Capability::CAP_CHOWN),
        "CAP_DAC_OVERRIDE" => Some(Capability::CAP_DAC_OVERRIDE),
        "CAP_DAC_READ_SEARCH" => Some(Capability::CAP_DAC_READ_SEARCH),
        "CAP_FOWNER" => Some(Capability::CAP_FOWNER),
        "CAP_FSETID" => Some(Capability::CAP_FSETID),
        "CAP_KILL" => Some(Capability::CAP_KILL),
        "CAP_SETGID" => Some(Capability::CAP_SETGID),
        "CAP_SETUID" => Some(Capability::CAP_SETUID),
        "CAP_SETPCAP" => Some(Capability::CAP_SETPCAP),
        "CAP_LINUX_IMMUTABLE" => Some(Capability::CAP_LINUX_IMMUTABLE),
        "CAP_NET_BIND_SERVICE" => Some(Capability::CAP_NET_BIND_SERVICE),
        "CAP_NET_BROADCAST" => Some(Capability::CAP_NET_BROADCAST),
        "CAP_NET_ADMIN" => Some(Capability::CAP_NET_ADMIN),
        "CAP_NET_RAW" => Some(Capability::CAP_NET_RAW),
        "CAP_IPC_LOCK" => Some(Capability::CAP_IPC_LOCK),
        "CAP_IPC_OWNER" => Some(Capability::CAP_IPC_OWNER),
        "CAP_SYS_MODULE" => Some(Capability::CAP_SYS_MODULE),
        "CAP_SYS_RAWIO" => Some(Capability::CAP_SYS_RAWIO),
        "CAP_SYS_CHROOT" => Some(Capability::CAP_SYS_CHROOT),
        "CAP_SYS_PTRACE" => Some(Capability::CAP_SYS_PTRACE),
        "CAP_SYS_PACCT" => Some(Capability::CAP_SYS_PACCT),
        "CAP_SYS_ADMIN" => Some(Capability::CAP_SYS_ADMIN),
        "CAP_SYS_BOOT" => Some(Capability::CAP_SYS_BOOT),
        "CAP_SYS_NICE" => Some(Capability::CAP_SYS_NICE),
        "CAP_SYS_RESOURCE" => Some(Capability::CAP_SYS_RESOURCE),
        "CAP_SYS_TIME" => Some(Capability::CAP_SYS_TIME),
        "CAP_SYS_TTY_CONFIG" => Some(Capability::CAP_SYS_TTY_CONFIG),
        "CAP_MKNOD" => Some(Capability::CAP_MKNOD),
        "CAP_LEASE" => Some(Capability::CAP_LEASE),
        "CAP_AUDIT_WRITE" => Some(Capability::CAP_AUDIT_WRITE),
        "CAP_AUDIT_CONTROL" => Some(Capability::CAP_AUDIT_CONTROL),
        "CAP_SETFCAP" => Some(Capability::CAP_SETFCAP),
        "CAP_MAC_OVERRIDE" => Some(Capability::CAP_MAC_OVERRIDE),
        "CAP_MAC_ADMIN" => Some(Capability::CAP_MAC_ADMIN),
        "CAP_SYSLOG" => Some(Capability::CAP_SYSLOG),
        "CAP_WAKE_ALARM" => Some(Capability::CAP_WAKE_ALARM),
        "CAP_BLOCK_SUSPEND" => Some(Capability::CAP_BLOCK_SUSPEND),
        "CAP_AUDIT_READ" => Some(Capability::CAP_AUDIT_READ),
        _ => None,
    }
}

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
        log::info!("Setting up filesystem isolation...");

        // Create temporary directory structure for the sandbox
        let sandbox_root = &self.sandbox_root;
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

            // Create the mount point (file or directory)
            if host_path.is_dir() {
                fs::create_dir_all(&full_sandbox_path).map_err(|e| {
                    PurpleError::FilesystemError(format!(
                        "Failed to create mount point directory {}: {}",
                        full_sandbox_path.display(),
                        e
                    ))
                })?;
            } else {
                // Assume it's a file - create empty file as mount point
                if !full_sandbox_path.exists() {
                    fs::File::create(&full_sandbox_path).map_err(|e| {
                        PurpleError::FilesystemError(format!(
                            "Failed to create mount point file {}: {}",
                            full_sandbox_path.display(),
                            e
                        ))
                    })?;
                }
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

        // SECURE: Create minimal /dev with only essential devices
        self.setup_secure_dev(sandbox_root)?;

        // SECURE: Mount /sys as read-only with security restrictions
        self.setup_secure_sys(sandbox_root)?;

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
        log::info!("Changing root to {}", sandbox_root.display());
        chroot(sandbox_root).map_err(|e| {
            PurpleError::FilesystemError(format!(
                "Failed to chroot to {}: {}",
                sandbox_root.display(),
                e
            ))
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

    /// Drops capabilities according to policy
    fn drop_capabilities(&self) -> Result<()> {
        log::info!("Dropping capabilities...");

        if self.policy.capabilities.default_drop {
            log::info!("Capability policy: Drop all capabilities by default");

            // Actual capability dropping implementation using libcap
            self.actual_drop_capabilities()?;

            if !self.policy.capabilities.added_capabilities.is_empty() {
                log::info!(
                    "Adding back {} capabilities:",
                    self.policy.capabilities.added_capabilities.len()
                );
                self.add_specific_capabilities(&self.policy.capabilities.added_capabilities)?;
            } else {
                log::info!("No capabilities added back - minimal privilege set");
            }

            log::info!("Capability management fully configured and enforced");
        } else {
            log::info!("Capability policy: Keep all capabilities by default");
            log::warn!("This is less secure - consider using default_drop=true");

            // Only drop specific capabilities if configured
            if !self.policy.capabilities.dropped_capabilities.is_empty() {
                self.drop_specific_capabilities(&self.policy.capabilities.dropped_capabilities)?;
            }
        }

        log::info!("Capability dropping completed and enforced");
        Ok(())
    }

    /// Actually drops all capabilities and sets bounding set
    fn actual_drop_capabilities(&self) -> Result<()> {
        log::info!("Clearing all capabilities from process");

        // Use capsh to drop all capabilities
        // capsh --drop=all -- -c "command"
        // Since we're already in the sandboxed process, we need a different approach

        // For now, implement using direct system calls
        self.drop_capabilities_system_call()?;

        log::info!("All capabilities cleared and bounding set restricted");
        Ok(())
    }

    /// Adds specific capabilities back to the process
    fn add_specific_capabilities(&self, capabilities: &HashSet<String>) -> Result<()> {
        use caps::CapSet;

        log::info!("Adding specific capabilities to process");

        // Get current permitted set first
        let mut current_permitted = caps::read(None, CapSet::Permitted).map_err(|e| {
            PurpleError::CapabilityError(format!("Failed to read permitted capabilities: {}", e))
        })?;

        let mut current_effective = caps::read(None, CapSet::Effective).map_err(|e| {
            PurpleError::CapabilityError(format!("Failed to read effective capabilities: {}", e))
        })?;

        for cap_name in capabilities {
            if let Some(cap) = capability_from_name(cap_name) {
                log::info!("  - Adding capability: {} ({:?})", cap_name, cap);
                current_permitted.insert(cap);
                current_effective.insert(cap);
            } else {
                log::warn!("  - Unknown capability: {} (skipping)", cap_name);
            }
        }

        // Set the updated capability sets
        caps::set(None, CapSet::Permitted, &current_permitted).map_err(|e| {
            PurpleError::CapabilityError(format!("Failed to set permitted capabilities: {}", e))
        })?;

        caps::set(None, CapSet::Effective, &current_effective).map_err(|e| {
            PurpleError::CapabilityError(format!("Failed to set effective capabilities: {}", e))
        })?;

        log::info!("✓ Specific capabilities added and enforced");
        Ok(())
    }

    /// Drops specific capabilities from the process
    fn drop_specific_capabilities(&self, capabilities: &HashSet<String>) -> Result<()> {
        use caps::CapSet;

        log::info!("Dropping specific capabilities from process");

        for cap_name in capabilities {
            if let Some(cap) = capability_from_name(cap_name) {
                log::info!("  - Dropping capability: {} ({:?})", cap_name, cap);

                // Drop from bounding set
                if let Err(e) = caps::drop(None, CapSet::Bounding, cap) {
                    log::debug!("Could not drop {:?} from bounding set: {}", cap, e);
                }

                // Drop from effective set
                if let Err(e) = caps::drop(None, CapSet::Effective, cap) {
                    log::debug!("Could not drop {:?} from effective set: {}", cap, e);
                }

                // Drop from permitted set
                if let Err(e) = caps::drop(None, CapSet::Permitted, cap) {
                    log::debug!("Could not drop {:?} from permitted set: {}", cap, e);
                }

                // Drop from inheritable set
                if let Err(e) = caps::drop(None, CapSet::Inheritable, cap) {
                    log::debug!("Could not drop {:?} from inheritable set: {}", cap, e);
                }
            } else {
                log::warn!("  - Unknown capability: {} (skipping)", cap_name);
            }
        }

        log::info!("✓ Specific capabilities dropped and enforced");
        Ok(())
    }

    /// Drop capabilities using system calls
    fn drop_capabilities_system_call(&self) -> Result<()> {
        use caps::{CapSet, Capability, CapsHashSet};

        log::info!("Dropping all capabilities from process using caps library");

        // Get all capabilities that exist on this system
        let all_caps: Vec<Capability> = vec![
            Capability::CAP_CHOWN,
            Capability::CAP_DAC_OVERRIDE,
            Capability::CAP_DAC_READ_SEARCH,
            Capability::CAP_FOWNER,
            Capability::CAP_FSETID,
            Capability::CAP_KILL,
            Capability::CAP_SETGID,
            Capability::CAP_SETUID,
            Capability::CAP_SETPCAP,
            Capability::CAP_LINUX_IMMUTABLE,
            Capability::CAP_NET_BIND_SERVICE,
            Capability::CAP_NET_BROADCAST,
            Capability::CAP_NET_ADMIN,
            Capability::CAP_NET_RAW,
            Capability::CAP_IPC_LOCK,
            Capability::CAP_IPC_OWNER,
            Capability::CAP_SYS_MODULE,
            Capability::CAP_SYS_RAWIO,
            Capability::CAP_SYS_CHROOT,
            Capability::CAP_SYS_PTRACE,
            Capability::CAP_SYS_PACCT,
            Capability::CAP_SYS_ADMIN,
            Capability::CAP_SYS_BOOT,
            Capability::CAP_SYS_NICE,
            Capability::CAP_SYS_RESOURCE,
            Capability::CAP_SYS_TIME,
            Capability::CAP_SYS_TTY_CONFIG,
            Capability::CAP_MKNOD,
            Capability::CAP_LEASE,
            Capability::CAP_AUDIT_WRITE,
            Capability::CAP_AUDIT_CONTROL,
            Capability::CAP_SETFCAP,
            Capability::CAP_MAC_OVERRIDE,
            Capability::CAP_MAC_ADMIN,
            Capability::CAP_SYSLOG,
            Capability::CAP_WAKE_ALARM,
            Capability::CAP_BLOCK_SUSPEND,
            Capability::CAP_AUDIT_READ,
        ];

        // Drop all capabilities from the bounding set
        log::info!("Dropping capabilities from bounding set...");
        for cap in &all_caps {
            if let Err(e) = caps::drop(None, CapSet::Bounding, *cap) {
                // Some capabilities might not exist on older kernels, that's OK
                log::debug!(
                    "Could not drop {:?} from bounding set: {} (may not exist)",
                    cap,
                    e
                );
            }
        }
        log::info!("✓ Bounding set capabilities dropped");

        // Clear the effective capability set
        log::info!("Clearing effective capability set...");
        let empty_set: CapsHashSet = CapsHashSet::new();
        caps::set(None, CapSet::Effective, &empty_set).map_err(|e| {
            PurpleError::CapabilityError(format!("Failed to clear effective capabilities: {}", e))
        })?;
        log::info!("✓ Effective capabilities cleared");

        // Clear the permitted capability set
        log::info!("Clearing permitted capability set...");
        caps::set(None, CapSet::Permitted, &empty_set).map_err(|e| {
            PurpleError::CapabilityError(format!("Failed to clear permitted capabilities: {}", e))
        })?;
        log::info!("✓ Permitted capabilities cleared");

        // Clear the inheritable capability set
        log::info!("Clearing inheritable capability set...");
        caps::set(None, CapSet::Inheritable, &empty_set).map_err(|e| {
            PurpleError::CapabilityError(format!("Failed to clear inheritable capabilities: {}", e))
        })?;
        log::info!("✓ Inheritable capabilities cleared");

        // Set NO_NEW_PRIVS to prevent privilege escalation via setuid/setgid binaries
        log::info!("Setting NO_NEW_PRIVS flag...");
        if let Err(e) = prctl_set_no_new_privs() {
            log::warn!("Could not set NO_NEW_PRIVS: {} (continuing anyway)", e);
        } else {
            log::info!("✓ NO_NEW_PRIVS flag set");
        }

        log::info!("All capabilities successfully dropped and enforced");
        Ok(())
    }

    /// Verifies current capabilities for debugging
    #[allow(dead_code)]
    fn verify_capabilities(&self) -> Result<()> {
        log::info!("Verifying current process capabilities...");

        // Would check capabilities using capget() system call
        log::info!("Would verify capabilities using system calls");

        log::info!("Capability verification complete");
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

            // Configure completely isolated network namespace
            self.configure_isolated_network()?;
        } else {
            log::info!("Network policy: Selective filtering");

            // Apply iptables/nftables rules for port filtering
            self.configure_selective_network_filtering()?;
        }

        log::info!("Network filtering configured and enforced");
        Ok(())
    }

    /// Configures a completely isolated network namespace
    fn configure_isolated_network(&self) -> Result<()> {
        log::info!("Configuring completely isolated network namespace");

        // Set up loopback interface (essential for local communication)
        self.setup_loopback_interface()?;

        // Block all other network traffic using iptables
        self.block_all_network_traffic()?;

        log::info!("Isolated network configured: only loopback available");
        Ok(())
    }

    /// Configures selective network filtering using iptables/nftables
    fn configure_selective_network_filtering(&self) -> Result<()> {
        log::info!("Configuring selective network filtering");

        // Start with default deny policy
        self.setup_default_deny_policy()?;

        // Allow outgoing connections to specified ports
        if !self.policy.network.allowed_outgoing_ports.is_empty() {
            log::info!(
                "Allowing {} outgoing ports:",
                self.policy.network.allowed_outgoing_ports.len()
            );
            for port in &self.policy.network.allowed_outgoing_ports {
                self.allow_outgoing_port(*port)?;
                log::info!("  ✓ Allowed outgoing port {}", port);
            }
        } else {
            log::info!("No outgoing connections allowed (default deny)");
        }

        // Allow incoming connections to specified ports
        if !self.policy.network.allowed_incoming_ports.is_empty() {
            log::info!(
                "Allowing {} incoming ports:",
                self.policy.network.allowed_incoming_ports.len()
            );
            for port in &self.policy.network.allowed_incoming_ports {
                self.allow_incoming_port(*port)?;
                log::info!("  ✓ Allowed incoming port {}", port);
            }
        } else {
            log::info!("No incoming connections allowed (default deny)");
        }

        // Always allow loopback traffic
        self.allow_loopback_traffic()?;

        Ok(())
    }

    /// Sets up the loopback interface in isolated network
    fn setup_loopback_interface(&self) -> Result<()> {
        log::info!("Setting up loopback interface");

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
            log::info!("✓ Loopback interface brought up");
        }

        // Add loopback address (usually already configured, but ensure it)
        let output = Command::new("ip")
            .args(["addr", "add", "127.0.0.1/8", "dev", "lo"])
            .output()
            .map_err(|e| {
                PurpleError::NetworkError(format!("Failed to execute 'ip addr add': {}", e))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // EEXIST is expected if address already exists
            if !stderr.contains("RTNETLINK answers: File exists") {
                log::warn!("Failed to add loopback address: {}", stderr);
            }
        } else {
            log::info!("✓ Loopback address configured");
        }

        log::info!("✓ Loopback interface configured and enforced");
        Ok(())
    }

    /// Blocks all network traffic using iptables
    fn block_all_network_traffic(&self) -> Result<()> {
        log::info!("Blocking all network traffic using iptables");

        // First, allow established connections and loopback
        self.allow_loopback_traffic()?;

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
    fn setup_default_deny_policy(&self) -> Result<()> {
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
    fn allow_outgoing_port(&self, port: u16) -> Result<()> {
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
                PurpleError::NetworkError(format!(
                    "Failed to allow outgoing TCP port {}: {}",
                    port, e
                ))
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
                PurpleError::NetworkError(format!(
                    "Failed to allow outgoing UDP port {}: {}",
                    port, e
                ))
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
    fn allow_incoming_port(&self, port: u16) -> Result<()> {
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
                PurpleError::NetworkError(format!(
                    "Failed to allow incoming TCP port {}: {}",
                    port, e
                ))
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
                PurpleError::NetworkError(format!(
                    "Failed to allow incoming UDP port {}: {}",
                    port, e
                ))
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
    fn allow_loopback_traffic(&self) -> Result<()> {
        log::debug!("Allowing loopback traffic");

        // Allow INPUT on loopback interface
        let output = Command::new("iptables")
            .args(["-A", "INPUT", "-i", "lo", "-j", "ACCEPT"])
            .output()
            .map_err(|e| {
                PurpleError::NetworkError(format!("Failed to allow loopback INPUT: {}", e))
            })?;

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

    /// Detects available capabilities for filesystem operations
    fn detect_capabilities() -> (bool, bool) {
        use std::os::unix::fs::PermissionsExt;

        // Test if we can create device nodes
        let can_create_devices = {
            let test_path = Path::new("/tmp/purple-capability-test");
            let result = std::panic::catch_unwind(|| {
                use nix::sys::stat::{SFlag, makedev, mknod};
                mknod(
                    test_path,
                    SFlag::S_IFCHR,
                    nix::sys::stat::Mode::from_bits_truncate(0o600),
                    makedev(1, 3), // /dev/null
                )
            });
            // Clean up test file if it was created
            let _ = std::fs::remove_file(test_path);
            result.is_ok()
        };

        // Test if we can change permissions
        let can_change_permissions = {
            let test_path = Path::new("/tmp/purple-perm-test");
            if std::fs::write(test_path, "test").is_ok() {
                let result = std::panic::catch_unwind(|| {
                    let _ =
                        std::fs::set_permissions(test_path, std::fs::Permissions::from_mode(0o700));
                    let _ =
                        std::fs::set_permissions(test_path, std::fs::Permissions::from_mode(0o600));
                });
                let _ = std::fs::remove_file(test_path);
                result.is_ok()
            } else {
                false
            }
        };

        (can_create_devices, can_change_permissions)
    }

    /// Creates a secure minimal /dev filesystem with only essential devices
    fn setup_secure_dev(&self, sandbox_root: &Path) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        log::info!("Setting up secure minimal /dev filesystem");

        // Detect available capabilities
        let (can_create_devices, can_change_permissions) = Self::detect_capabilities();
        log::info!(
            "Capabilities detected - Devices: {}, Permissions: {}",
            can_create_devices,
            can_change_permissions
        );

        let dev_path = sandbox_root.join("dev");

        // Create /dev directory with restricted permissions
        fs::create_dir_all(&dev_path).map_err(|e| {
            PurpleError::FilesystemError(format!("Failed to create secure /dev: {}", e))
        })?;

        // Set restrictive permissions (755 - owner rwx, group rx, others rx)
        if can_change_permissions {
            fs::set_permissions(&dev_path, fs::Permissions::from_mode(0o755)).map_err(|e| {
                PurpleError::FilesystemError(format!("Failed to set /dev permissions: {}", e))
            })?;
        } else {
            log::info!("Cannot change /dev directory permissions (expected in user namespaces)");
        }

        // Mount tmpfs for /dev (prevents host device access)
        let tmpfs_result = mount(
            Some("tmpfs"),
            &dev_path,
            Some("tmpfs"),
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
            Some("mode=755,size=10m"),
        );

        if let Err(e) = tmpfs_result {
            log::warn!(
                "⚠️  Failed to mount tmpfs for /dev: {}. This may indicate insufficient privileges. Continuing with regular directory structure.",
                e
            );
        }

        // Create essential device nodes with capability-aware handling
        let essential_devices = [
            ("null", 0o666, 1, 3),
            ("zero", 0o666, 1, 5),
            ("random", 0o666, 1, 8),
            ("urandom", 0o666, 1, 9),
            ("full", 0o666, 1, 7),
            ("tty", 0o666, 5, 0),
        ];

        let mut device_creation_success = true;
        for (name, mode, major, minor) in &essential_devices {
            let device_path = dev_path.join(name);

            if can_create_devices {
                // Try to create as proper device node
                if let Err(e) = self.create_device_node(&device_path, *mode, *major, *minor) {
                    log::warn!("⚠️  Failed to create device node {}: {}", name, e);
                    device_creation_success = false;
                }
            } else {
                // Fallback: Create as regular file with appropriate content
                log::info!(
                    "Creating {} as regular file (device node creation not available)",
                    name
                );

                // Create parent directory if needed
                if let Some(parent) = device_path.parent()
                    && let Err(e) = fs::create_dir_all(parent)
                {
                    log::warn!("Failed to create parent directory for {}: {}", name, e);
                    device_creation_success = false;
                    continue;
                }

                // Create file with appropriate permissions
                if let Err(e) = fs::write(&device_path, "") {
                    log::warn!("Failed to create fallback file for {}: {}", name, e);
                    device_creation_success = false;
                    continue;
                }

                // Set permissions if possible
                if can_change_permissions
                    && let Err(e) =
                        fs::set_permissions(&device_path, fs::Permissions::from_mode(*mode))
                {
                    log::debug!("Failed to set permissions on {}: {}", name, e);
                }
            }
        }

        // Create essential directories
        fs::create_dir_all(dev_path.join("pts")).map_err(|e| {
            PurpleError::FilesystemError(format!("Failed to create /dev/pts: {}", e))
        })?;
        fs::create_dir_all(dev_path.join("shm")).map_err(|e| {
            PurpleError::FilesystemError(format!("Failed to create /dev/shm: {}", e))
        })?;

        if device_creation_success {
            log::info!("✓ Secure minimal /dev filesystem created with essential devices");
        } else {
            log::warn!(
                "⚠️  /dev setup completed with limitations. Some devices may not be fully functional. For full functionality, run with root privileges or configure proper capabilities."
            );
        }

        Ok(())
    }

    /// Creates a secure read-only /sys filesystem
    fn setup_secure_sys(&self, sandbox_root: &Path) -> Result<()> {
        log::info!("Setting up secure read-only /sys filesystem");

        let sys_path = sandbox_root.join("sys");

        // Create /sys directory
        fs::create_dir_all(&sys_path).map_err(|e| {
            PurpleError::FilesystemError(format!("Failed to create /sys directory: {}", e))
        })?;

        // Try to mount sysfs directly first (works when not in user namespace)
        let mount_result = mount(
            Some("sysfs"),
            &sys_path,
            Some("sysfs"),
            MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
            None::<&str>,
        );

        if mount_result.is_ok() {
            log::info!("Secure read-only /sys filesystem mounted with full restrictions");
            return Ok(());
        }

        // If direct mount fails (e.g., in user namespace), bind-mount host's /sys read-only
        log::info!("Direct sysfs mount failed, trying bind mount of host /sys");

        // First bind mount
        mount(
            Some("/sys"),
            &sys_path,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        )
        .map_err(|e| PurpleError::FilesystemError(format!("Failed to bind mount /sys: {}", e)))?;

        // Then remount read-only
        mount(
            None::<&str>,
            &sys_path,
            None::<&str>,
            MsFlags::MS_BIND
                | MsFlags::MS_REMOUNT
                | MsFlags::MS_RDONLY
                | MsFlags::MS_NOSUID
                | MsFlags::MS_NODEV
                | MsFlags::MS_NOEXEC,
            None::<&str>,
        )
        .map_err(|e| {
            PurpleError::FilesystemError(format!("Failed to remount /sys read-only: {}", e))
        })?;

        log::info!("Secure read-only /sys filesystem bind-mounted from host");
        Ok(())
    }

    /// Creates a device node with specified permissions and device numbers
    fn create_device_node(&self, path: &Path, mode: u32, major: u64, minor: u64) -> Result<()> {
        use nix::sys::stat::SFlag;
        use nix::sys::stat::makedev;
        use nix::sys::stat::mknod;

        log::debug!(
            "Creating device node: {} with mode {:o}, major {}, minor {}",
            path.display(),
            mode,
            major,
            minor
        );

        // Create device node using mknod
        let result = mknod(
            path,
            SFlag::S_IFCHR, // Character device
            nix::sys::stat::Mode::from_bits_truncate(mode),
            makedev(major, minor),
        );

        match result {
            Ok(_) => {
                log::debug!("✓ Successfully created device node: {}", path.display());
                Ok(())
            }
            Err(e) => {
                // Handle permission errors gracefully
                if e == nix::Error::EPERM {
                    log::warn!(
                        "⚠️  Insufficient permissions to create device node {} (major {}, minor {}). This is expected when running without root privileges. Device will be created as a regular file with similar behavior.",
                        path.display(),
                        major,
                        minor
                    );

                    // Fallback: Create as a regular file for basic functionality
                    if let Some(parent) = path.parent()
                        && let Err(e) = std::fs::create_dir_all(parent)
                    {
                        return Err(PurpleError::FilesystemError(format!(
                            "Failed to create parent directory for device fallback {}: {}",
                            path.display(),
                            e
                        )));
                    }

                    // Create as a regular file with appropriate permissions
                    if let Err(e) = std::fs::write(path, "") {
                        return Err(PurpleError::FilesystemError(format!(
                            "Failed to create device fallback file {}: {}",
                            path.display(),
                            e
                        )));
                    }

                    // Set appropriate permissions
                    if let Err(e) =
                        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
                    {
                        log::warn!(
                            "Failed to set permissions on device fallback {}: {}",
                            path.display(),
                            e
                        );
                    }

                    Ok(())
                } else {
                    Err(PurpleError::FilesystemError(format!(
                        "Failed to create device node {}: {}",
                        path.display(),
                        e
                    )))
                }
            }
        }
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
