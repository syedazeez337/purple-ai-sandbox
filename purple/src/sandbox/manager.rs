// purple/src/sandbox/manager.rs
#![allow(dead_code)]

/// # Sandbox Manager - Multi-Sandbox Management System
///
/// This module provides advanced sandbox management capabilities including:
/// - Multi-sandbox instance management
/// - Resource allocation and tracking
/// - System resource pool management
/// - Concurrent sandbox execution
///
/// ## Current Status
///
/// ⚠️  This module is fully implemented and tested but not yet integrated
/// into the main execution flow. It's currently used in integration tests
/// (`tests/test_manager.rs`) to verify multi-sandbox functionality.
///
/// ## Integration Plan
///
/// To integrate this manager into the main application:
/// 1. Replace direct Sandbox::new() calls with manager.create_sandbox()
/// 2. Use manager.execute_sandbox() instead of sandbox.execute()
/// 3. Implement proper resource cleanup via manager.cleanup_sandbox()
/// 4. Add manager.list_sandboxes() to CLI for monitoring
///
/// ## Benefits of Integration
///
/// - Prevents resource exhaustion from multiple sandboxes
/// - Provides centralized monitoring and management
/// - Enables resource quotas and fair sharing
/// - Supports concurrent sandbox execution
///
/// ## Usage Example
///
/// ```rust
/// let mut manager = SandboxManager::new();
/// let sandbox_id = manager.create_sandbox(policy, command)?;
/// let exit_code = manager.execute_sandbox(&sandbox_id)?;
/// let status = manager.get_sandbox_status(&sandbox_id)?;
/// manager.cleanup_sandbox(&sandbox_id)?;
/// ```
use crate::error::{PurpleError, Result};
use crate::policy::compiler::CompiledPolicy;
use crate::sandbox::Sandbox;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use sysinfo::System;
use uuid::Uuid;

/// Manages multiple concurrent sandbox instances
#[derive(Debug)]
pub struct SandboxManager {
    sandboxes: Arc<Mutex<HashMap<String, SandboxInstance>>>,
    resource_pool: ResourcePool,
}

/// Information about a running sandbox instance
#[derive(Debug)]
pub struct SandboxInstance {
    sandbox: Sandbox,
    status: SandboxStatus,
    start_time: std::time::SystemTime,
    resource_usage: ResourceUsage,
    allocation: ResourceAllocation,
}

/// Current status of a sandbox
#[derive(Debug, PartialEq)]
pub enum SandboxStatus {
    Initializing,
    Running,
    Completed,
    Failed,
    CleaningUp,
}

/// Resource usage tracking
#[derive(Debug, Default, Clone)]
pub struct ResourceUsage {
    pub cpu_time: f64,      // seconds
    pub memory_peak: u64,   // bytes
    pub network_bytes: u64, // bytes
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
#[derive(Debug, Clone)]
pub struct ResourceAllocation {
    pub cpu_shares: f64,
    pub memory_mb: u64,
}

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
    ) -> Result<String> {
        let mut sandboxes = self.sandboxes.lock().map_err(|e| {
            PurpleError::SandboxError(format!("Failed to lock sandbox manager: {}", e))
        })?;

        // Allocate resources
        let allocation = self.resource_pool.allocate(&policy)?;

        // Generate unique sandbox ID
        let sandbox_id = Uuid::new_v4().to_string();

        // Create sandbox
        let sandbox = Sandbox::new(policy, agent_command);

        // Create sandbox instance
        let instance = SandboxInstance {
            sandbox,
            status: SandboxStatus::Initializing,
            start_time: std::time::SystemTime::now(),
            resource_usage: ResourceUsage::default(),
            allocation: allocation.clone(),
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
}

/// Resource pool status information
#[derive(Debug)]
pub struct ResourcePoolStatus {
    pub total_cpu: f64,
    pub allocated_cpu: f64,
    pub total_memory: u64,
    pub allocated_memory: u64,
}

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
