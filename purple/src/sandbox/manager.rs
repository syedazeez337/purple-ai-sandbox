// purple/src/sandbox/manager.rs

/// # Sandbox Manager - Multi-Sandbox Management System
///
/// This module provides advanced sandbox management capabilities including:
/// - Multi-sandbox instance management with UUID-based tracking
/// - Resource allocation and pool management (CPU/memory)
/// - Real resource usage tracking (CPU time, memory peak, disk I/O)
/// - State persistence for sandbox metadata
/// - Concurrent sandbox execution support
///
/// ## Integration Status
///
/// ✅ **FULLY INTEGRATED** - The manager is now the default execution path for all
/// sandbox operations. The `purple run` command uses manager-based execution by default,
/// with a `--direct` flag available for legacy direct execution.
///
/// ## Key Features
///
/// - **Resource Pool Management**: Prevents over-allocation across concurrent sandboxes
/// - **Real Usage Metrics**: Collects actual CPU time, peak memory, and disk I/O from cgroups
/// - **State Persistence**: Sandbox metadata saved to `./sessions/manager-state.json`
/// - **Backward Compatible**: Direct execution still available via `--direct` flag
///
/// ## CLI Integration
///
/// The manager is used in two ways:
///
/// 1. **Transient Mode** (default for `run` command):
///    - Creates manager on-demand
///    - Executes single sandbox
///    - Displays resource usage
///    - Cleans up after completion
///
/// 2. **Persistent Mode** (`sandboxes` subcommand):
///    - Loads/saves state from disk
///    - Manages multiple named sandboxes
///    - Tracks sandboxes across CLI invocations
///
/// ## Usage Example
///
/// ```rust
/// // Create and execute sandbox via manager
/// let mut manager = SandboxManager::new();
/// let sandbox_id = manager.create_sandbox(
///     policy,
///     command,
///     "ai-dev-safe".to_string()
/// )?;
/// let exit_code = manager.execute_sandbox(&sandbox_id)?;
/// let usage = manager.get_resource_usage(&sandbox_id)?;
/// manager.cleanup_sandbox(&sandbox_id)?;
///
/// // State persistence
/// manager.save_state(Path::new("./sessions/manager-state.json"))?;
/// ```
use crate::error::{PurpleError, Result};
use crate::policy::compiler::CompiledPolicy;
use crate::sandbox::Sandbox;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use sysinfo::System;
use uuid::Uuid;

/// Manages multiple concurrent sandbox instances
#[derive(Debug)]
#[allow(dead_code)]
pub struct SandboxManager {
    sandboxes: Arc<Mutex<HashMap<String, SandboxInstance>>>,
    resource_pool: ResourcePool,
}

/// Information about a running sandbox instance
#[derive(Debug)]
#[allow(dead_code)]
pub struct SandboxInstance {
    sandbox: Sandbox,
    status: SandboxStatus,
    start_time: std::time::SystemTime,
    resource_usage: ResourceUsage,
    allocation: ResourceAllocation,
    profile_name: String,        // Track which profile was used
    command: Vec<String>,        // Track executed command
    pid: Option<i32>,           // Child process ID for tracking
}

/// Current status of a sandbox
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum SandboxStatus {
    Initializing,
    Running,
    Completed,
    Failed,
    CleaningUp,
}

/// Resource usage tracking
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct ResourceUsage {
    pub cpu_time: f64,              // seconds
    pub memory_peak: u64,           // bytes
    pub network_bytes: u64,         // bytes (currently disk I/O)
    pub collection_successful: bool, // Track if stats were actually collected
}

/// Manages resource allocation across sandboxes
#[derive(Debug, Default)]
pub struct ResourcePool {
    pub total_cpu_cores: f64,
    pub total_memory_mb: u64,
    pub allocated_cpu: f64,
    pub allocated_memory: u64,
}

impl ResourcePool {
    /// Creates a new resource pool with system resources
    pub fn new() -> Self {
        let mut sys = System::new_all();
        sys.refresh_all();

        let total_cpu = sys.cpus().len() as f64;
        let total_memory = sys.total_memory() / 1024 / 1024; // Convert to MB

        log::info!(
            "Detected system resources: {} CPUs, {}MB RAM",
            total_cpu,
            total_memory
        );

        ResourcePool {
            total_cpu_cores: total_cpu,
            total_memory_mb: total_memory,
            allocated_cpu: 0.0,
            allocated_memory: 0,
        }
    }

    /// Allocates resources for a new sandbox
    pub fn allocate(&mut self, policy: &CompiledPolicy) -> Result<ResourceAllocation> {
        // Calculate required resources from policy
        let required_cpu = policy.resources.cpu_shares.unwrap_or(1.0);
        let required_memory = policy
            .resources
            .memory_limit_bytes
            .map(|b| b / 1024 / 1024)
            .unwrap_or(512);

        // Check if resources are available
        if self.allocated_cpu + required_cpu > self.total_cpu_cores {
            return Err(PurpleError::ResourceError(format!(
                "Insufficient CPU resources: {} required, {} available",
                required_cpu,
                self.total_cpu_cores - self.allocated_cpu
            )));
        }

        if self.allocated_memory + required_memory > self.total_memory_mb {
            return Err(PurpleError::ResourceError(format!(
                "Insufficient memory resources: {}MB required, {}MB available",
                required_memory,
                self.total_memory_mb - self.allocated_memory
            )));
        }

        // Allocate resources
        self.allocated_cpu += required_cpu;
        self.allocated_memory += required_memory;

        Ok(ResourceAllocation {
            cpu_shares: required_cpu,
            memory_mb: required_memory,
        })
    }

    /// Releases resources from a completed sandbox
    pub fn release(&mut self, allocation: &ResourceAllocation) {
        self.allocated_cpu -= allocation.cpu_shares;
        self.allocated_memory -= allocation.memory_mb;
    }
}

/// Resource allocation for a sandbox
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceAllocation {
    pub cpu_shares: f64,
    pub memory_mb: u64,
}

/// Persistable manager state (excludes active Sandbox instances)
#[derive(Debug, Serialize, Deserialize)]
pub struct ManagerState {
    pub sandbox_metadata: HashMap<String, SandboxMetadata>,
    pub total_cpu_cores: f64,
    pub total_memory_mb: u64,
    pub allocated_cpu: f64,
    pub allocated_memory: u64,
    pub last_updated: std::time::SystemTime,
}

/// Metadata about a sandbox instance (serializable)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxMetadata {
    pub id: String,
    pub profile_name: String,
    pub status: SandboxStatus,
    pub start_time: std::time::SystemTime,
    pub resource_usage: ResourceUsage,
    pub allocation: ResourceAllocation,
    pub command: Vec<String>,
    pub pid: Option<i32>,
}

#[allow(dead_code)]
impl SandboxManager {
    /// Creates a new SandboxManager
    pub fn new() -> Self {
        SandboxManager {
            sandboxes: Arc::new(Mutex::new(HashMap::new())),
            resource_pool: ResourcePool::new(),
        }
    }

    /// Creates a new sandbox with resource allocation
    pub fn create_sandbox(
        &mut self,
        policy: CompiledPolicy,
        agent_command: Vec<String>,
        profile_name: String,
    ) -> Result<String> {
        let mut sandboxes = self.sandboxes.lock().map_err(|e| {
            PurpleError::SandboxError(format!("Failed to lock sandbox manager: {}", e))
        })?;

        // Allocate resources
        let allocation = self.resource_pool.allocate(&policy)?;

        // Generate unique sandbox ID
        let sandbox_id = Uuid::new_v4().to_string();

        // Store command before moving it
        let command_clone = agent_command.clone();

        // Create sandbox
        let sandbox = Sandbox::new(policy, agent_command);

        // Create sandbox instance
        let instance = SandboxInstance {
            sandbox,
            status: SandboxStatus::Initializing,
            start_time: std::time::SystemTime::now(),
            resource_usage: ResourceUsage::default(),
            allocation: allocation.clone(),
            profile_name: profile_name.clone(),
            command: command_clone,
            pid: None,
        };

        // Store in manager
        sandboxes.insert(sandbox_id.clone(), instance);

        log::info!(
            "Created sandbox {} with resources: {:.2} CPU, {}MB memory",
            sandbox_id,
            allocation.cpu_shares,
            allocation.memory_mb
        );

        Ok(sandbox_id)
    }

    /// Executes a sandbox and returns the result
    pub fn execute_sandbox(&self, sandbox_id: &str) -> Result<i32> {
        let mut sandboxes = self.sandboxes.lock().map_err(|e| {
            PurpleError::SandboxError(format!("Failed to lock sandbox manager: {}", e))
        })?;

        if let Some(instance) = sandboxes.get_mut(sandbox_id) {
            instance.status = SandboxStatus::Running;

            // Execute the sandbox
            let exit_code = instance.sandbox.execute()?;

            instance.status = SandboxStatus::Completed;

            // Collect resource usage from cgroup
            let cgroup_name = format!("purple-sandbox-{}", sandbox_id);
            let cgroup_mgr = crate::sandbox::cgroups::CgroupManager::new(&cgroup_name);

            let mut collection_successful = true;

            // Collect CPU time
            match cgroup_mgr.get_cpu_stats() {
                Ok(cpu_time) => {
                    instance.resource_usage.cpu_time = cpu_time;
                    log::info!("Collected CPU usage: {:.2}s", cpu_time);
                }
                Err(e) => {
                    log::warn!("Failed to collect CPU stats: {}", e);
                    collection_successful = false;
                }
            }

            // Collect memory peak
            match cgroup_mgr.get_memory_peak() {
                Ok(mem_peak) => {
                    instance.resource_usage.memory_peak = mem_peak;
                    log::info!("Collected memory peak: {} bytes", mem_peak);
                }
                Err(e) => {
                    log::warn!("Failed to collect memory peak: {}", e);
                    collection_successful = false;
                }
            }

            // Collect I/O stats (disk I/O, not network)
            match cgroup_mgr.get_io_stats() {
                Ok(io_bytes) => {
                    instance.resource_usage.network_bytes = io_bytes; // Note: This is disk I/O
                    log::info!("Collected I/O: {} bytes", io_bytes);
                }
                Err(e) => {
                    log::warn!("Failed to collect I/O stats: {}", e);
                    collection_successful = false;
                }
            }

            instance.resource_usage.collection_successful = collection_successful;

            log::info!(
                "Sandbox {} completed with exit code {}",
                sandbox_id,
                exit_code
            );

            Ok(exit_code)
        } else {
            Err(PurpleError::SandboxError(format!(
                "Sandbox {} not found",
                sandbox_id
            )))
        }
    }

    /// Gets the status of a sandbox
    pub fn get_sandbox_status(&self, sandbox_id: &str) -> Result<SandboxStatus> {
        let sandboxes = self.sandboxes.lock().map_err(|e| {
            PurpleError::SandboxError(format!("Failed to lock sandbox manager: {}", e))
        })?;

        if let Some(instance) = sandboxes.get(sandbox_id) {
            Ok(instance.status.clone())
        } else {
            Err(PurpleError::SandboxError(format!(
                "Sandbox {} not found",
                sandbox_id
            )))
        }
    }

    /// Lists all active sandboxes
    pub fn list_sandboxes(&self) -> Result<Vec<(String, SandboxStatus)>> {
        let sandboxes = self.sandboxes.lock().map_err(|e| {
            PurpleError::SandboxError(format!("Failed to lock sandbox manager: {}", e))
        })?;

        Ok(sandboxes
            .iter()
            .map(|(id, instance)| (id.clone(), instance.status.clone()))
            .collect())
    }

    /// Cleans up a completed sandbox
    pub fn cleanup_sandbox(&mut self, sandbox_id: &str) -> Result<()> {
        let mut sandboxes = self.sandboxes.lock().map_err(|e| {
            PurpleError::SandboxError(format!("Failed to lock sandbox manager: {}", e))
        })?;

        if let Some(instance) = sandboxes.remove(sandbox_id) {
            // Perform actual cleanup of resources
            log::info!("Cleaning up resources for sandbox {}", sandbox_id);

            // 1. Clean up filesystem, cgroups, etc.
            if let Err(e) = instance.sandbox.cleanup_and_audit() {
                log::warn!("Error during sandbox cleanup: {}", e);
                // Continue with resource release even if cleanup failed
            }

            // 2. Release allocated resources back to the pool
            self.resource_pool.release(&instance.allocation);

            log::info!("Cleaned up sandbox {}", sandbox_id);
            Ok(())
        } else {
            Err(PurpleError::SandboxError(format!(
                "Sandbox {} not found",
                sandbox_id
            )))
        }
    }

    /// Gets resource usage for a sandbox
    pub fn get_resource_usage(&self, sandbox_id: &str) -> Result<ResourceUsage> {
        let sandboxes = self.sandboxes.lock().map_err(|e| {
            PurpleError::SandboxError(format!("Failed to lock sandbox manager: {}", e))
        })?;

        if let Some(instance) = sandboxes.get(sandbox_id) {
            Ok(instance.resource_usage.clone())
        } else {
            Err(PurpleError::SandboxError(format!(
                "Sandbox {} not found",
                sandbox_id
            )))
        }
    }

    /// Gets overall resource pool status
    pub fn get_resource_pool_status(&self) -> ResourcePoolStatus {
        ResourcePoolStatus {
            total_cpu: self.resource_pool.total_cpu_cores,
            allocated_cpu: self.resource_pool.allocated_cpu,
            total_memory: self.resource_pool.total_memory_mb,
            allocated_memory: self.resource_pool.allocated_memory,
        }
    }

    /// Creates a new sandbox from profile and command strings (CLI helper)
    pub fn create_sandbox_from_profile(
        &mut self,
        name: String,
        profile_name: String,
    ) -> Result<String> {
        // Load policy from file
        let policy_file = format!("./policies/{}.yaml", profile_name);
        let policy =
            crate::policy::parser::load_policy_from_file(std::path::Path::new(&policy_file))?
                .compile()?;

        // Use profile's command or default to echo
        let command = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            format!(
                "echo 'Sandbox {} created with profile {}'",
                name, profile_name
            ),
        ];

        self.create_sandbox(policy, command, profile_name)
    }

    /// Saves manager state to a JSON file
    pub fn save_state(&self, path: &std::path::Path) -> Result<()> {
        let sandboxes = self.sandboxes.lock().map_err(|e| {
            PurpleError::SandboxError(format!("Failed to lock sandbox manager: {}", e))
        })?;

        // Convert SandboxInstance to SandboxMetadata
        let sandbox_metadata: HashMap<String, SandboxMetadata> = sandboxes
            .iter()
            .map(|(id, instance)| {
                (
                    id.clone(),
                    SandboxMetadata {
                        id: id.clone(),
                        profile_name: instance.profile_name.clone(),
                        status: instance.status.clone(),
                        start_time: instance.start_time,
                        resource_usage: instance.resource_usage.clone(),
                        allocation: instance.allocation.clone(),
                        command: instance.command.clone(),
                        pid: instance.pid,
                    },
                )
            })
            .collect();

        let state = ManagerState {
            sandbox_metadata,
            total_cpu_cores: self.resource_pool.total_cpu_cores,
            total_memory_mb: self.resource_pool.total_memory_mb,
            allocated_cpu: self.resource_pool.allocated_cpu,
            allocated_memory: self.resource_pool.allocated_memory,
            last_updated: std::time::SystemTime::now(),
        };

        let json = serde_json::to_string_pretty(&state).map_err(|e| {
            PurpleError::SandboxError(format!("Failed to serialize manager state: {}", e))
        })?;

        std::fs::write(path, json).map_err(|e| {
            PurpleError::SandboxError(format!("Failed to write state file: {}", e))
        })?;

        log::info!("Saved manager state to {}", path.display());
        Ok(())
    }

    /// Loads manager state from a JSON file
    pub fn load_state(path: &std::path::Path) -> Result<ManagerState> {
        let json = std::fs::read_to_string(path).map_err(|e| {
            PurpleError::SandboxError(format!("Failed to read state file: {}", e))
        })?;

        let state: ManagerState = serde_json::from_str(&json).map_err(|e| {
            PurpleError::SandboxError(format!("Failed to deserialize manager state: {}", e))
        })?;

        log::info!("Loaded manager state from {}", path.display());
        Ok(state)
    }

    /// Restores a SandboxManager from saved state (metadata only, no active sandboxes)
    pub fn restore_from_state(state: ManagerState) -> Result<Self> {
        let mut manager = SandboxManager::new();

        // Restore resource pool state
        manager.resource_pool.total_cpu_cores = state.total_cpu_cores;
        manager.resource_pool.total_memory_mb = state.total_memory_mb;
        manager.resource_pool.allocated_cpu = state.allocated_cpu;
        manager.resource_pool.allocated_memory = state.allocated_memory;

        // Note: We don't restore SandboxInstance objects because they contain
        // non-serializable Sandbox instances with active processes/file descriptors.
        // The metadata is preserved for historical/audit purposes but sandboxes
        // themselves are not restarted.

        log::info!(
            "Restored manager state with {} sandbox records",
            state.sandbox_metadata.len()
        );
        log::warn!("Active sandboxes are not restored - only metadata is preserved");

        Ok(manager)
    }
}

impl Default for SandboxManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Resource pool status information
#[derive(Debug)]
#[allow(dead_code)]
pub struct ResourcePoolStatus {
    pub total_cpu: f64,
    pub allocated_cpu: f64,
    pub total_memory: u64,
    pub allocated_memory: u64,
}

#[allow(dead_code)]
impl ResourcePoolStatus {
    pub fn available_cpu(&self) -> f64 {
        self.total_cpu - self.allocated_cpu
    }

    pub fn available_memory(&self) -> u64 {
        self.total_memory - self.allocated_memory
    }

    pub fn cpu_utilization(&self) -> f64 {
        if self.total_cpu > 0.0 {
            self.allocated_cpu / self.total_cpu
        } else {
            0.0
        }
    }

    pub fn memory_utilization(&self) -> f64 {
        if self.total_memory > 0 {
            self.allocated_memory as f64 / self.total_memory as f64
        } else {
            0.0
        }
    }
}

// Implement Clone for SandboxStatus for easier use
impl Clone for SandboxStatus {
    fn clone(&self) -> Self {
        match self {
            SandboxStatus::Initializing => SandboxStatus::Initializing,
            SandboxStatus::Running => SandboxStatus::Running,
            SandboxStatus::Completed => SandboxStatus::Completed,
            SandboxStatus::Failed => SandboxStatus::Failed,
            SandboxStatus::CleaningUp => SandboxStatus::CleaningUp,
        }
    }
}
