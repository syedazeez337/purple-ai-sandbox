# Security Policy

## Supported Versions

We provide security updates for the following versions:

| Version | Supported          |
|---------|-------------------|
| 0.2.x   | :white_check_mark: |
| 0.1.x   | :x:                |
| < 0.1.0 | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them to our security team at:

📧 [security@purple-sandbox.io](mailto:security@purple-sandbox.io)

### Vulnerability Reporting Process

1. **Report**: Send an email to our security team with:
   - A clear description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Any suggested fixes

2. **Acknowledgment**: We will acknowledge your report within 48 hours

3. **Investigation**: Our security team will investigate and verify the issue

4. **Resolution**: We will develop and test a fix

5. **Disclosure**: We will coordinate disclosure with you

6. **Release**: We will release a security update

## Security Best Practices

### For Users

1. **Run with Least Privilege**: Always run Purple with the minimum required privileges
2. **Use Strict Policies**: Start with restrictive policies and relax as needed
3. **Monitor Logs**: Regularly review audit logs for suspicious activity
4. **Keep Updated**: Always use the latest stable version
5. **Isolate Networks**: Use network isolation for sensitive workloads

### For Developers

1. **Follow Secure Coding Practices**: Use Rust's safety features effectively
2. **Validate All Inputs**: Never trust external data
3. **Use Proper Error Handling**: Don't expose sensitive information in errors
4. **Test Security Features**: Verify security controls work as expected
5. **Review Dependencies**: Keep dependencies updated and audited

## Security Features

### Isolation Mechanisms

- **Linux Namespaces**: User, PID, mount, and network isolation
- **Seccomp Filtering**: Syscall restriction with default-deny or explicit-deny policies
  - Default-deny mode: Blocks all syscalls except those explicitly allowed
  - Deny-list mode: Allows all syscalls except those explicitly blocked
- **Capability Dropping**: Principle of least privilege enforcement
- **Filesystem Isolation**: Read-only mounts and chroot
- **Network Isolation**: Complete network namespace separation
- **eBPF Network Filtering**: IPv4 and IPv6 address blocking via eBPF

### Monitoring & Auditing

- **Comprehensive Logging**: All security events are logged
- **Audit Trails**: Detailed records of all sandbox activities
- **Subsystem Monitoring**: Module-specific logging for debugging

### Resource Management

- **CPU Limits**: Prevent CPU exhaustion attacks
- **Memory Limits**: Control memory usage
- **Process Limits**: Limit process creation
- **I/O Throttling**: Prevent disk I/O abuse
- **Timeout Enforcement**: Automatic session termination

## Dependency Security Audit (RUSTSEC)

This project uses `cargo-audit` to scan dependencies for known RUSTSEC vulnerabilities.

### Last Audit: 2025-12-21

**Status**: No known vulnerabilities detected

```
Scanning Cargo.lock for vulnerabilities (158 crate dependencies)
Result: 0 vulnerabilities found
```

### Running Security Audits

To check for vulnerabilities locally:

```bash
# Install cargo-audit
cargo install cargo-audit

# Run audit
cargo audit
```

### Continuous Integration

Security audits should be automatically run in CI. See `.github/workflows/rust.yml`.

## Security Updates

Security updates are released as patch versions (e.g., 0.2.1) and include:

- Fixes for security vulnerabilities
- Backported security improvements
- Updated dependency versions

## Responsible Disclosure

We follow responsible disclosure practices:

1. **Private Reporting**: Vulnerabilities reported privately
2. **Timely Response**: Acknowledgment within 48 hours
3. **Coordinated Release**: Patch released after fix is ready
4. **Credit**: Proper attribution to reporters (if desired)

## Security Team

Our security team can be reached at:

📧 [security@purple-sandbox.io](mailto:security@purple-sandbox.io)

PGP Key: `0xA1B2C3D4E5F67890` (available on key servers)

## Emergency Contact

For critical security issues requiring immediate attention:

📞 +1 (555) 123-4567 (24/7 security hotline)

## Acknowledgements

We would like to thank the following researchers and organizations for responsibly disclosing vulnerabilities:

- [Researcher Name] - [Organization]
- [Researcher Name] - [Organization]

Thank you for helping keep Purple secure! 🛡️