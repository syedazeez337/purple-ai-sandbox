# Purple AI Sandbox Security Implementation Plan

## Current Issues Analysis

### 1. Capability Dropping
**Problem**: The sandbox logs capability dropping but doesn't actually implement it.
**Location**: `src/sandbox/mod.rs` - `Sandbox::setup_capabilities()` method
**Impact**: Processes retain unnecessary privileges, increasing attack surface

### 2. Filesystem Exposure
**Problem**: `/dev` and `/sys` mounts expose host system information and devices
**Location**: `src/sandbox/linux_namespaces.rs` - mount setup
**Impact**: Potential information leakage, device access, privilege escalation

### 3. Resource Limits
**Problem**: No CPU, memory, or process limits enforced
**Location**: Missing implementation in sandbox module
**Impact**: Resource exhaustion, DoS attacks, system instability

### 4. Network Port Filtering
**Problem**: No network port restrictions implemented
**Location**: Missing seccomp rules and network namespace configuration
**Impact**: Unauthorized network access, port scanning, data exfiltration

### 5. Audit Logging
**Problem**: No comprehensive audit trail of sandbox operations
**Location**: Missing throughout sandbox lifecycle
**Impact**: Lack of visibility, difficulty in incident investigation

### 6. Concurrent Sandbox Support
**Problem**: No support for multiple simultaneous sandboxes
**Location**: Global state management issues
**Impact**: Limited scalability, potential resource conflicts

## Implementation Plan

### Phase 1: Capability Dropping (High Priority)
**Files to modify**:
- `src/sandbox/mod.rs`
- `src/sandbox/linux_namespaces.rs`

**Implementation steps**:
1. Use `libcap` or direct syscalls to drop capabilities
2. Implement `drop_capabilities()` function using `cap_set_proc()`
3. Add capability bounding set with `prctl(PR_CAPBSET_DROP)`
4. Verify capabilities are dropped using `cap_get_proc()`
5. Add error handling and logging

**Code example**:
```rust
fn drop_capabilities() -> Result<(), PurpleError> {
    // Drop all capabilities except basic ones needed
    let caps_to_keep = [Capability::CAP_CHOWN, Capability::CAP_FOWNER, Capability::CAP_FSETID];
    
    // Set bounding set
    prctl::set_cap_bounding_set(&caps_to_keep)?;
    
    // Drop capabilities from current process
    cap::set(None, CapSet::Effective, &caps_to_keep)?;
    cap::set(None, CapSet::Permitted, &caps_to_keep)?;
    
    Ok(())
}
```

### Phase 2: Filesystem Security (High Priority)
**Files to modify**:
- `src/sandbox/linux_namespaces.rs`
- `src/sandbox/mod.rs`

**Implementation steps**:
1. Create minimal `/dev` with only required devices
2. Use `tmpfs` for `/dev` with restricted permissions
3. Mount `/sys` as read-only or use synthetic filesystem
4. Implement device whitelisting
5. Add mount namespace restrictions

**Code example**:
```rust
fn setup_secure_mounts() -> Result<(), PurpleError> {
    // Create minimal /dev
    mount::mount(
        Some("tmpfs"), 
        "/dev", 
        Some("tmpfs"), 
        MountFlags::MS_NOSUID | MountFlags::MS_NODEV | MountFlags::MS_NOEXEC,
        Some("mode=755,size=10m")
    )?;
    
    // Create essential devices
    create_device("/dev/null", 0666)?;
    create_device("/dev/zero", 0666)?;
    create_device("/dev/random", 0666)?;
    create_device("/dev/urandom", 0666)?;
    
    // Mount sys read-only
    mount::mount(
        Some("sysfs"),
        "/sys",
        Some("sysfs"),
        MountFlags::MS_RDONLY | MountFlags::MS_NOSUID | MountFlags::MS_NODEV | MountFlags::MS_NOEXEC,
        None
    )?;
    
    Ok(())
}
```

### Phase 3: Resource Limits (High Priority)
**Files to modify**:
- `src/sandbox/mod.rs`
- `src/sandbox/cgroups.rs`

**Implementation steps**:
1. Enhance cgroups implementation
2. Add CPU quota and period limits
3. Implement memory limits (soft and hard)
4. Add process count limits
5. Implement I/O bandwidth limits
6. Add resource monitoring

**Code example**:
```rust
fn setup_resource_limits(config: &SandboxConfig) -> Result<(), PurpleError> {
    // CPU limits
    if let Some(cpu_limit) = config.cpu_limit {
        cgroups::set_cpu_quota(&config.cgroup_path, cpu_limit * 1000)?;
        cgroups::set_cpu_period(&config.cgroup_path, 100000)?;
    }
    
    // Memory limits
    if let Some(mem_limit) = config.memory_limit {
        cgroups::set_memory_limit(&config.cgroup_path, mem_limit)?;
        cgroups::set_memory_swap_limit(&config.cgroup_path, mem_limit)?;
    }
    
    // Process limits
    if let Some(process_limit) = config.process_limit {
        cgroups::set_pids_max(&config.cgroup_path, process_limit)?;
    }
    
    Ok(())
}
```

### Phase 4: Network Port Filtering (Medium Priority)
**Files to modify**:
- `src/sandbox/seccomp.rs`
- `src/sandbox/linux_namespaces.rs`

**Implementation steps**:
1. Enhance seccomp rules for network syscalls
2. Implement port range filtering
3. Add network namespace isolation
4. Implement iptables/nftables rules
5. Add DNS restrictions

**Code example**:
```rust
fn setup_network_filtering(config: &SandboxConfig) -> Result<(), PurpleError> {
    // Create network namespace
    unshare(CloneFlags::CLONE_NEWNET)?;
    
    // Setup seccomp network rules
    let mut filter = SeccompFilter::new(SeccompAction::Allow)?;
    
    // Restrict bind/connect to allowed ports
    if let Some(allowed_ports) = &config.allowed_ports {
        for port in allowed_ports {
            filter.add_rule(
                SeccompAction::Allow,
                Syscall::bind,
                &[SeccompCmpArg::new(1, SeccompCmpOp::Eq, *port as u64)]
            )?;
        }
        filter.set_default_action(SeccompAction::Errno(EINVAL))?;
    }
    
    filter.load()?;
    
    Ok(())
}
```

### Phase 5: Audit Logging (Medium Priority)
**Files to modify**:
- `src/sandbox/mod.rs`
- `src/logging.rs`

**Implementation steps**:
1. Create audit logging module
2. Log all sandbox lifecycle events
3. Implement syscall auditing
4. Add resource usage logging
5. Implement log rotation and retention

**Code example**:
```rust
#[derive(Debug, Serialize)]
struct AuditEvent {
    timestamp: DateTime<Utc>,
    event_type: String,
    sandbox_id: String,
    process_id: u32,
    details: HashMap<String, String>,
    severity: LogLevel,
}

fn log_audit_event(event: AuditEvent) {
    // Write to audit log
    let log_entry = serde_json::to_string(&event).unwrap();
    
    // Write to file
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/var/log/purple/audit.log")
        .and_then(|mut file| writeln!(file, "{}", log_entry))
        .unwrap_or_else(|e| eprintln!("Failed to write audit log: {}", e));
}
```

### Phase 6: Concurrent Sandbox Support (Medium Priority)
**Files to modify**:
- `src/sandbox/mod.rs`
- `src/main.rs`

**Implementation steps**:
1. Implement sandbox ID generation
2. Add sandbox isolation mechanisms
3. Implement resource partitioning
4. Add concurrent execution management
5. Implement cleanup and garbage collection

**Code example**:
```rust
struct SandboxManager {
    sandboxes: HashMap<String, Arc<Mutex<Sandbox>>>,
    resource_pool: ResourcePool,
}

impl SandboxManager {
    fn create_sandbox(&mut self, config: SandboxConfig) -> Result<String, PurpleError> {
        let sandbox_id = Uuid::new_v4().to_string();
        
        // Allocate resources
        let resources = self.resource_pool.allocate(&config)?;
        
        // Create sandbox
        let sandbox = Sandbox::new(sandbox_id.clone(), config, resources)?;
        
        // Store in manager
        self.sandboxes.insert(sandbox_id.clone(), Arc::new(Mutex::new(sandbox)));
        
        Ok(sandbox_id)
    }
    
    fn cleanup_sandbox(&mut self, sandbox_id: &str) -> Result<(), PurpleError> {
        if let Some(sandbox) = self.sandboxes.remove(sandbox_id) {
            sandbox.lock().unwrap().cleanup()?;
            self.resource_pool.release(&sandbox.lock().unwrap().resources);
        }
        Ok(())
    }
}
```

## Testing Strategy

### Unit Tests
- Test capability dropping verification
- Test filesystem mount restrictions
- Test resource limit enforcement
- Test network filtering rules
- Test audit log generation

### Integration Tests
- Test complete sandbox lifecycle
- Test concurrent sandbox execution
- Test resource isolation between sandboxes
- Test security policy enforcement

### Security Tests
- Penetration testing of sandbox boundaries
- Privilege escalation attempts
- Resource exhaustion tests
- Network attack simulations

## Implementation Timeline

| Phase | Task | Estimated Time | Priority |
|-------|------|---------------|----------|
| 1 | Capability Dropping | 2-3 days | High |
| 2 | Filesystem Security | 3-4 days | High |
| 3 | Resource Limits | 4-5 days | High |
| 4 | Network Filtering | 2-3 days | Medium |
| 5 | Audit Logging | 2-3 days | Medium |
| 6 | Concurrent Support | 3-4 days | Medium |
| 7 | Testing | 5-7 days | High |

## Risk Assessment

### High Risk Items
- Capability dropping implementation (could break existing functionality)
- Filesystem restrictions (might affect legitimate operations)
- Resource limits (could cause false positives)

### Mitigation Strategies
- Implement comprehensive testing
- Add fallback mechanisms
- Provide configuration options to disable features
- Implement gradual rollout

## Dependencies

### Required Crates
- `libcap` - For capability manipulation
- `nix` - For advanced system calls
- `serde` - For audit log serialization
- `uuid` - For sandbox ID generation
- `log` - For enhanced logging

### System Requirements
- Linux kernel ≥ 4.15 (for cgroups v2)
- Capability support in kernel
- Mount namespace support
- Network namespace support

## Monitoring and Maintenance

### Metrics to Track
- Sandbox creation success/failure rates
- Resource usage patterns
- Security event frequency
- Performance impact

### Maintenance Tasks
- Regular security audits
- Dependency updates
- Policy rule updates
- Performance optimization

This plan provides a comprehensive approach to addressing all the identified security issues while maintaining system stability and performance.