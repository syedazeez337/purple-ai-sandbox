# Security

Purple has undergone comprehensive security audits. All findings have been addressed and verified.

## Audit History

### December 2024 — Comprehensive Security Audit

All findings from the security audit have been remediated:

| Finding | Severity | Status |
|---------|----------|--------|
| Signal handler cleanup | Critical | Fixed |
| Fallback signal handler | Critical | Fixed |
| chroot vs pivot_root | Critical | Fixed |
| Audit log injection | Critical | Fixed |
| iptables validation | Critical | Fixed |
| setgroups error handling | High | Fixed |
| DNS validation | High | Fixed |
| Safety comments | High | Fixed |
| API type mismatches | High | Fixed |
| advanced_rules implementation | Medium | Implemented |
| API rate limiting | Medium | Implemented |
| API authentication | Medium | Implemented |
| Device fallback | Medium | Fixed |

## Security Features

Purple implements defense-in-depth with multiple security layers:

### 1. Filesystem Isolation
- **pivot_root** replaces chroot to prevent container escape via `/proc/PID/root`
- Bind mounts with read-only options for immutable paths
- Private mount propagation (MS_PRIVATE) to prevent cross-namespace leaks

### 2. Syscall Filtering
- **Seccomp BPF** with default-deny policy
- **Advanced rules** support fine-grained argument validation
- Example: Allow `openat` only with O_RDONLY flags:
  ```yaml
  advanced_rules:
    - syscall: openat
      action: allow
      conditions:
        - arg: 2
          op: masked_eq
          value: 0
          mask: 0o3
  ```

### 3. Network Security
- **eBPF SKB filtering** for network activity monitoring
- iptables with absolute path validation
- DNS server validation with proper IP address parsing

### 4. Resource Limits
- Cgroups v2 for CPU, memory, and PID limits
- Automatic cleanup on signal interruption
- No orphaned cgroups or mounts

### 5. Audit Logging
- JSON serialization prevents log injection attacks
- Structured output for SIEM integration

### 6. API Security
- Bearer token authentication
- Rate limiting (10 requests/second)
- Absolute path verification for iptables

## Reporting Security Issues

For security vulnerabilities, please contact the maintainers directly.

## Best Practices

When deploying Purple in production:

1. Use `production-secure` profile for untrusted workloads
2. Set `PURPLE_API_KEY` environment variable for API authentication
3. Enable audit logging to a secure, centralized location
4. Regularly update to the latest release
5. Review audit logs for anomalous behavior
