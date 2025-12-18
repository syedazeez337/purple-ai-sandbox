# Purple AI Sandbox - Comprehensive Code Review Report

**Review Date:** 2025-12-16
**Reviewer:** Security & Code Quality Analysis
**Codebase Version:** commit 86082db

---

## Executive Summary

Purple is a Linux-based sandbox for isolating AI agent execution using namespaces, seccomp, and cgroups. The codebase demonstrates solid security architecture with several production-ready features, but has **critical gaps** that must be addressed before production deployment.

### Overall Assessment: **NOT PRODUCTION READY**

| Category | Score | Status |
|----------|-------|--------|
| Security Architecture | 7/10 | Good foundation, incomplete implementation |
| Code Quality | 8/10 | Clean, well-structured Rust |
| Test Coverage | 6/10 | Unit tests good, integration limited |
| Error Handling | 8/10 | Comprehensive error types |
| Documentation | 7/10 | Inline docs good, user docs missing |
| Production Readiness | 4/10 | Multiple blocking issues |

---

## CRITICAL SECURITY VULNERABILITIES

### 1. **CRITICAL: Capability Dropping Not Implemented**
**Location:** `src/sandbox/mod.rs:400-442`
**Severity:** CRITICAL
**CVSS:** 9.8

```rust
fn drop_capabilities(&self) -> Result<()> {
    // ... only logging, no actual capability dropping
    log::info!("Would clear all capabilities from process");
    // NO ACTUAL IMPLEMENTATION
    Ok(())
}
```

**Impact:** Sandboxed processes retain ALL Linux capabilities, allowing:
- Container escape via `CAP_SYS_ADMIN`
- Network manipulation via `CAP_NET_ADMIN`
- Raw socket access via `CAP_NET_RAW`
- Process tracing via `CAP_SYS_PTRACE`

**Fix Required:** Integrate `caps` or `capctl` crate to actually drop capabilities.

---

### 2. **CRITICAL: /dev Bind Mount Exposes Host Devices**
**Location:** `src/sandbox/mod.rs:321-329`

```rust
// WORKAROUND: Bind mount host /dev
mount(
    Some("/dev"),
    &Path::new(sandbox_root).join("dev"),
    None::<&str>,
    MsFlags::MS_BIND | MsFlags::MS_REC,
    None::<&str>,
)
```

**Impact:** Sandboxed process has access to:
- `/dev/mem` - Direct memory access
- `/dev/kmem` - Kernel memory
- `/dev/sda*` - Raw disk access
- `/dev/tty*` - Terminal hijacking

**Fix Required:** Create minimal `/dev` with only required devices (null, zero, random, urandom).

---

### 3. **CRITICAL: /sys Bind Mount Exposes Kernel Interfaces**
**Location:** `src/sandbox/mod.rs:331-339`

```rust
// WORKAROUND: Bind mount host /sys
mount(
    Some("/sys"),
    &Path::new(sandbox_root).join("sys"),
    None::<&str>,
    MsFlags::MS_BIND | MsFlags::MS_REC,
    None::<&str>,
)
```

**Impact:** Exposes kernel attack surface:
- `/sys/kernel/*` - Kernel parameters
- `/sys/class/*` - Hardware classes
- `/sys/fs/cgroup/*` - Cgroup manipulation

**Fix Required:** Mount minimal sysfs or make read-only with restricted paths.

---

### 4. **HIGH: Network Filtering Not Implemented**
**Location:** `src/sandbox/mod.rs:500-548`

```rust
fn apply_network_filtering(&self) -> Result<()> {
    // Only logging, no actual iptables/nftables rules
    log::info!("Would configure iptables/nftables rules here");
    Ok(())
}
```

**Impact:** When `network.isolated=false`, all network access is allowed regardless of `allow_outgoing`/`allow_incoming` port restrictions.

---

### 5. **HIGH: Cgroup Process Assignment Missing**
**Location:** `src/sandbox/mod.rs:380-398` and `src/sandbox/cgroups.rs`

The cgroup is created but the sandboxed process is **never added to it**:
```rust
fn apply_resource_limits(&self) -> Result<()> {
    cgroup_manager.setup_cgroups(&self.policy.resources)?;
    // MISSING: echo $PID > /sys/fs/cgroup/purple/$name/cgroup.procs
    log::info!("Would add sandbox process to cgroup after fork/exec");
    Ok(())
}
```

**Impact:** Resource limits (CPU, memory, PIDs) are NOT enforced.

---

### 6. **HIGH: Session Timeout Not Enforced**
**Location:** `src/sandbox/cgroups.rs:84-89`

```rust
if let Some(timeout_secs) = policy.session_timeout_seconds {
    log::info!("Setting session timeout to {} seconds", timeout_secs);
    // Would implement process monitoring and termination
}
```

**Impact:** Malicious agents can run indefinitely, consuming resources.

---

### 7. **MEDIUM: Audit Logging Not Implemented**
**Location:** `src/sandbox/mod.rs:550-589`

```rust
fn cleanup_and_audit(&self) -> Result<()> {
    if self.policy.audit.enabled {
        log::info!("Would write audit log entry...");
        // NO ACTUAL FILE WRITING
    }
}
```

**Impact:** No forensic trail for security incidents.

---

### 8. **MEDIUM: Sandbox Root Path Hardcoded**
**Location:** `src/sandbox/mod.rs:158`

```rust
let sandbox_root = "/tmp/purple-sandbox";
```

**Issues:**
- `/tmp` may be world-writable with sticky bit issues
- Race conditions if multiple sandboxes run simultaneously
- No cleanup on crash leaves artifacts

---

### 9. **MEDIUM: CString::unwrap() Can Panic**
**Location:** `src/sandbox/mod.rs:131-136`

```rust
let prog = CString::new(self.agent_command[0].clone()).unwrap();
let args: Vec<CString> = self
    .agent_command
    .iter()
    .map(|arg| CString::new(arg.clone()).unwrap())
    .collect();
```

**Impact:** Command with null byte causes panic, potential DoS.

---

### 10. **LOW: Syscall Number Mismatch Risk**
**Location:** `src/policy/compiler.rs` vs `src/sandbox/seccomp.rs`

Two separate syscall number mappings exist with different values:
- `compiler.rs:410-411`: `rseq => 293`
- `seccomp.rs:395`: `rseq => 333`

**Impact:** Wrong syscall may be allowed/denied.

---

## CODE QUALITY ISSUES

### 1. **Dead Code / Incomplete Features**
Multiple functions marked `#[allow(dead_code)]` that should be implemented:
- `execute_agent_command()` in sandbox/mod.rs
- `cleanup_cgroups()` in cgroups.rs
- `get_cgroup_path()` in cgroups.rs

### 2. **Error Handling Inconsistencies**
Child process errors exit with code 1 without proper error propagation:
```rust
// src/sandbox/mod.rs:103
if let Err(e) = linux_namespaces::unshare_mount_namespace() {
    log::error!("Mount namespace setup failed: {}", e);
    std::process::exit(1);  // Should communicate error to parent
}
```

### 3. **Magic Numbers**
Syscall numbers hardcoded without constants:
```rust
"read" => { allowed_syscall_numbers.insert(0); }
"write" => { allowed_syscall_numbers.insert(1); }
```

Should use `libc::SYS_read` or define constants.

### 4. **Duplicate Syscall Mapping Logic**
Syscall name-to-number mapping exists in both:
- `src/policy/compiler.rs` (partial, in compile())
- `src/sandbox/seccomp.rs` (comprehensive, get_syscall_number())

Should consolidate to single source of truth.

### 5. **Missing Input Sanitization for Profile Names**
**Location:** `src/main.rs:52, 126, 147, 224`

```rust
let policy_path = format!("./policies/{}.yaml", name);
```

Profile name is not validated - could contain `../` for path traversal.

---

## PRODUCTION READINESS GAPS

### 1. **No Privilege Separation**
The sandbox setup and child execution happen in the same trust domain. Production sandboxes typically use:
- Privileged helper for setup
- Unprivileged child for execution

### 2. **No Sandbox Cleanup on Crash**
If the parent process crashes:
- Mounts remain in place
- Cgroups not cleaned up
- Child process orphaned

### 3. **No Concurrent Sandbox Support**
Hardcoded paths like `/tmp/purple-sandbox` prevent multiple sandbox instances.

### 4. **No Metrics/Monitoring**
No Prometheus metrics, health checks, or observability for production monitoring.

### 5. **No Signal Handling**
Parent process doesn't handle SIGTERM/SIGINT gracefully for cleanup.

### 6. **Missing Security Hardening**
- No ASLR verification
- No seccomp notify for audit
- No landlock integration
- No AppArmor/SELinux profiles

---

## RECOMMENDED FIXES BY PRIORITY

### P0 - Critical (Block Production)

| Issue | Fix | Effort |
|-------|-----|--------|
| Capability dropping | Integrate `caps` crate, implement actual dropping | 2-3 days |
| /dev exposure | Create minimal devtmpfs with mknod | 1 day |
| /sys exposure | Mount read-only sysfs or restrict paths | 1 day |
| Cgroup process assignment | Write PID to cgroup.procs | 0.5 day |

### P1 - High (Security Risk)

| Issue | Fix | Effort |
|-------|-----|--------|
| Network filtering | Integrate nftables or iptables rules | 3-4 days |
| Session timeout | Implement watchdog with SIGKILL | 1 day |
| Profile name sanitization | Add validation regex | 0.5 day |
| Sandbox root isolation | Use unique temp dirs with proper cleanup | 1 day |

### P2 - Medium (Production Quality)

| Issue | Fix | Effort |
|-------|-----|--------|
| Audit logging | Implement JSON file writing | 1-2 days |
| Syscall mapping consolidation | Single source of truth | 1 day |
| Error propagation in child | Use exit codes or pipe | 0.5 day |
| CString null byte handling | Proper error handling | 0.5 day |

---

## SECURITY ARCHITECTURE ANALYSIS

### What's Done Well

1. **Namespace Isolation**: User, PID, mount, network namespaces properly created
2. **Seccomp Enforcement**: Default-deny mode with kernel-level filtering
3. **Path Validation**: Strong path traversal and forbidden path checks
4. **Policy Compilation**: Strict validation at compile time, not runtime
5. **Chroot Isolation**: Proper filesystem root change

### Defense in Depth Assessment

| Layer | Status | Notes |
|-------|--------|-------|
| User Namespace | Implemented | UID/GID mapping works |
| PID Namespace | Implemented | Fork-based entry |
| Mount Namespace | Implemented | Private mounts |
| Network Namespace | Partial | Created but not filtered |
| Seccomp | Implemented | Default-deny works |
| Capabilities | NOT IMPLEMENTED | Critical gap |
| Cgroups | Partial | Created but not assigned |
| Chroot | Implemented | Works correctly |
| Audit | NOT IMPLEMENTED | Logging only |

---

## TEST COVERAGE ANALYSIS

### Unit Tests: 35 tests
- Policy loading/compilation: 15 tests
- Security validation: 10 tests
- Error handling: 3 tests
- Seccomp mapping: 3 tests
- General: 4 tests

### Integration Tests: 11 tests (10 ignored in CI)
- Only `test_profile_management` runs in CI
- Others require namespace support

### Missing Test Coverage
- Actual sandbox execution paths
- Capability dropping
- Network filtering
- Resource limit enforcement
- Concurrent sandbox execution
- Cleanup after failures

---

## RECOMMENDATIONS

### Immediate Actions (Before Any Production Use)

1. **Implement capability dropping** using the `caps` crate
2. **Fix /dev and /sys mounts** to minimal required devices
3. **Add cgroup process assignment**
4. **Sanitize profile names** in CLI

### Short-term (1-2 Weeks)

1. Implement network filtering with nftables
2. Add session timeout enforcement
3. Implement audit logging
4. Add unique sandbox directories

### Medium-term (1 Month)

1. Add Prometheus metrics
2. Implement graceful signal handling
3. Add landlock support for additional isolation
4. Create AppArmor/SELinux profiles

### Long-term

1. Consider unprivileged user namespace support
2. Add GPU isolation support
3. Implement sandbox snapshots
4. Add distributed tracing

---

## CONCLUSION

Purple has a **solid security architecture foundation** with proper use of Linux namespaces, seccomp, and chroot. However, several **critical security features are not implemented** (capabilities, proper /dev isolation, cgroup enforcement).

**The application should NOT be used in production** until P0 issues are resolved.

Estimated effort to reach production-ready: **2-3 weeks** of focused development.

---

*Report generated by comprehensive code review analysis*
