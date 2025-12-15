# Purple - AI Agent Sandbox

![Purple Logo](https://via.placeholder.com/150/8B5CF6/FFFFFF?text=PURPLE)

**Secure, isolated execution environment for AI agents**

## 🚀 Overview

Purple is a comprehensive sandboxing solution designed to safely execute AI agents in isolated environments. It provides multiple layers of security including Linux namespaces, seccomp filtering, capability management, cgroups resource limits, and network isolation.

## 🔧 Features

### 🛡️ Security Features

- **Linux Namespaces**: User, PID, mount, and network isolation
- **Seccomp Filtering**: Syscall restriction with 450+ syscall mappings
- **Capability Dropping**: Principle of least privilege enforcement
- **Filesystem Isolation**: Bind mounts and chroot for secure filesystem access
- **Network Isolation**: Complete network namespace isolation with port filtering

### 📊 Resource Management

- **CPU Limits**: Control CPU usage with cgroups
- **Memory Limits**: Prevent memory exhaustion
- **Process Limits**: Limit number of processes
- **I/O Throttling**: Control disk I/O bandwidth
- **Timeout Enforcement**: Automatic session termination

### 📋 Policy System

- **Declarative YAML Policies**: Easy-to-understand policy definitions
- **Policy Compilation**: Strict validation and compilation
- **Multi-layer Security**: Comprehensive security configuration

### 🔧 Monitoring & Observability

- **Comprehensive Logging**: Timestamped, structured logs with CLI control
- **Audit Logging**: Detailed security event recording
- **Subsystem Logging**: Module-specific logging for debugging

## 📦 Installation

### Prerequisites

- Rust 1.60+ (recommended: latest stable)
- Linux kernel with namespace and cgroup support
- Root privileges for full functionality

### Build from Source

```bash
# Clone the repository
git clone https://github.com/your-repo/purple.git
cd purple

# Build the project
cargo build --release

# Install (optional)
sudo cp target/release/purple /usr/local/bin/
```

## 🚀 Quick Start

### Create a Profile

```bash
# Create a new profile from a YAML file
purple profile create ai-dev-safe

# List available profiles
purple profile list

# Show profile details
purple profile show ai-dev-safe

# Delete a profile
purple profile delete ai-dev-safe
```

### Run an AI Agent

```bash
# Run an agent with a specific profile
purple run --profile ai-dev-safe -- python3 ai_agent.py

# With custom logging level
purple -l debug run --profile ai-dev-safe -- python3 ai_agent.py
```

## 📋 Policy Configuration

### Example Policy (`ai-dev-safe.yaml`)

```yaml
name: "ai-dev-safe"
description: "Policy for a development AI agent with safe defaults."

filesystem:
  immutable_paths:
    - host_path: "/usr/bin"
      sandbox_path: "/usr/bin"
    - host_path: "/lib"
      sandbox_path: "/lib"
  scratch_paths:
    - "/tmp"
    - "/var/tmp"
  output_paths:
    - host_path: "/home/aze/Documents/rapp/purple/output/ai-dev-safe"
      sandbox_path: "/output"
  working_dir: "/home/agent"

syscalls:
  default_deny: true
  allow:
    - "read"
    - "write"
    - "openat"
    - "close"
    - "fstat"
    - "newfstatat"
    - "mmap"
    - "mprotect"
    - "munmap"
    - "brk"
    - "access"
    - "execve"
    - "arch_prctl"
    - "set_tid_address"
    - "set_robust_list"
    - "rseq"
    - "prlimit64"
    - "getrandom"
    - "exit_group"
    - "clone3"
  deny:
    - "mount"
    - "unmount"
    - "reboot"
    - "kexec_load"
    - "bpf"
    - "unlinkat"
    - "renameat2"

resources:
  cpu_shares: 0.5
  memory_limit_bytes: "2G"
  pids_limit: 100
  block_io_limit: "100MBps"
  session_timeout_seconds: 3600

capabilities:
  default_drop: true
  add:
    - "CAP_NET_BIND_SERVICE"

network:
  isolated: false
  allow_outgoing:
    - "443"  # HTTPS
    - "53"   # DNS
  allow_incoming: []

audit:
  enabled: true
  log_path: "/var/log/purple/ai-dev-safe.log"
  detail_level:
    - "syscall"
    - "filesystem"
    - "resource"
```

### Policy Fields

| Section | Field | Description | Example |
|---------|-------|-------------|---------|
| **filesystem** | `immutable_paths` | Read-only bind mounts | `/usr/bin`, `/lib` |
| **filesystem** | `scratch_paths` | Writable temporary directories | `/tmp`, `/var/tmp` |
| **filesystem** | `output_paths` | Write-only output directories | `/output` |
| **filesystem** | `working_dir` | Working directory for sandbox | `/home/agent` |
| **syscalls** | `default_deny` | Deny all syscalls by default | `true` |
| **syscalls** | `allow` | List of allowed syscalls | `read`, `write`, `execve` |
| **syscalls** | `deny` | List of explicitly denied syscalls | `mount`, `reboot` |
| **resources** | `cpu_shares` | CPU share allocation | `0.5` (50% of CPU) |
| **resources** | `memory_limit_bytes` | Memory limit | `"2G"`, `"512M"` |
| **resources** | `pids_limit` | Maximum processes | `100` |
| **resources** | `block_io_limit` | I/O bandwidth limit | `"100MBps"` |
| **resources** | `session_timeout_seconds` | Maximum session duration | `3600` (1 hour) |
| **capabilities** | `default_drop` | Drop all capabilities by default | `true` |
| **capabilities** | `add` | Capabilities to add back | `CAP_NET_BIND_SERVICE` |
| **network** | `isolated` | Complete network isolation | `false` |
| **network** | `allow_outgoing` | Allowed outgoing ports | `"443"`, `"53"` |
| **network** | `allow_incoming` | Allowed incoming ports | `[]` |
| **audit** | `enabled` | Enable audit logging | `true` |
| **audit** | `log_path` | Audit log file path | `/var/log/purple/audit.log` |
| **audit** | `detail_level` | Logging detail levels | `syscall`, `filesystem`, `resource` |

## 🎯 Usage Examples

### Basic Usage

```bash
# Create and test a profile
purple profile create ai-dev-safe
purple profile show ai-dev-safe

# Run a simple command
purple run --profile ai-dev-safe -- echo "Hello from sandbox"

# Run with debug logging
purple -l debug run --profile ai-dev-safe -- python3 script.py
```

### Advanced Usage

```bash
# List all available profiles
purple profile list

# Delete a profile
purple profile delete old-profile

# Run with different log levels
purple -l trace run --profile ai-dev-safe -- ./complex_agent
purple -l error run --profile ai-dev-safe -- ./production_agent
```

## 🛡️ Security Best Practices

### 1. Principle of Least Privilege

```yaml
capabilities:
  default_drop: true
  add: []  # Only add absolutely necessary capabilities
```

### 2. Default Deny for Syscalls

```yaml
syscalls:
  default_deny: true
  allow:
    - "read"
    - "write"
    - "execve"
    # Only add syscalls your agent actually needs
```

### 3. Resource Limits

```yaml
resources:
  cpu_shares: 0.5  # Limit to 50% CPU
  memory_limit_bytes: "1G"  # 1GB memory limit
  pids_limit: 50  # Maximum 50 processes
  session_timeout_seconds: 1800  # 30 minute timeout
```

### 4. Network Isolation

```yaml
network:
  isolated: true  # Complete network isolation
  allow_outgoing: []  # No outgoing connections
  allow_incoming: []  # No incoming connections
```

## 🔧 Architecture

### Component Diagram

```
┌───────────────────────────────────────────────────┐
│                 Purple Sandbox                     │
├───────────────────────────────────────────────────┤
│                                                   │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────┐  │
│  │   Policy    │    │  Sandbox    │    │  CLI    │  │
│  │  System     │    │  Execution  │    │         │  │
│  └─────────────┘    └─────────────┘    └─────────┘  │
│       ▲                  ▲                  ▲       │
│       │                  │                  │       │
│  ┌────┴──────┐    ┌─────┴──────┐    ┌─────┴───┐  │
│  │ YAML      │    │ Namespaces  │    │ Commands│  │
│  │ Policies   │    │ Cgroups     │    │ Logging │  │
│  └───────────┘    │ Seccomp     │    │ Help    │  │
│                   │ Capabilities│    └─────────┘  │
│                   │ Network     │               │
│                   │ Filesystem  │               │
│                   └─────────────┘               │
└───────────────────────────────────────────────────┘
```

### Security Layers

```
┌───────────────────────────────────────────────────┐
│                 Security Layers                   │
├───────────────────────────────────────────────────┤
│                                                   │
│  1. 🔒 Namespaces (User, PID, Mount, Network)      │
│  2. 🛡️ Seccomp (Syscall Filtering)               │
│  3. 👮 Capabilities (Least Privilege)             │
│  4. 📦 Cgroups (Resource Limits)                  │
│  5. 🌐 Network (Firewall Rules)                   │
│  6. 📁 Filesystem (Bind Mounts, Chroot)           │
│  7. 📋 Audit (Logging & Monitoring)               │
│                                                   │
└───────────────────────────────────────────────────┘
```

## 📊 Performance Considerations

### Overhead Analysis

| Component | Overhead | Notes |
|-----------|----------|-------|
| Namespaces | Low | Native kernel feature |
| Seccomp | Medium | Syscall filtering overhead |
| Cgroups | Low | Minimal performance impact |
| Chroot | Very Low | Filesystem isolation |
| Logging | Configurable | Adjust log levels as needed |

### Optimization Tips

1. **Use appropriate log levels**:
   ```bash
   # Production (minimal overhead)
   purple -l error run --profile ai-dev-safe -- ./agent
   
   # Development (detailed debugging)
   purple -l debug run --profile ai-dev-safe -- ./agent
   ```

2. **Limit resource usage**:
   ```yaml
   resources:
     cpu_shares: 0.75  # Don't over-allocate
     memory_limit_bytes: "2G"  # Reasonable limits
   ```

3. **Minimize allowed syscalls**:
   ```yaml
   syscalls:
     default_deny: true
     allow:
       - "read"
       - "write"
       - "execve"
       # Only what's absolutely necessary
   ```

## 🐛 Troubleshooting

### Common Issues

#### Permission Errors

```bash
Sandbox execution failed: Namespace error: User namespace setup failed: 
Operation not permitted (os error 1)
```

**Solution**: Run with root privileges or configure user namespaces:
```bash
# Option 1: Run as root
sudo purple run --profile ai-dev-safe -- ./agent

# Option 2: Configure user namespaces
sudo sysctl -w kernel.unprivileged_userns_clone=1
```

#### Policy Loading Errors

```bash
Error loading policy for 'my-profile': No such file or directory
```

**Solution**: Ensure the policy file exists:
```bash
# Check if policy exists
ls policies/my-profile.yaml

# Create a new policy if needed
cp policies/ai-dev-safe.yaml policies/my-profile.yaml
# Then edit the new policy
```

#### Resource Limit Errors

```bash
Error applying resource limits: No such file or directory
```

**Solution**: Ensure cgroups are mounted:
```bash
# Mount cgroups (usually done automatically)
sudo mount -t cgroup2 none /sys/fs/cgroup
```

## 📚 Additional Resources

### Syscall Reference

Common syscalls for AI agents:
- `read`, `write` - File I/O
- `openat`, `close` - File operations
- `execve` - Process execution
- `mmap`, `munmap` - Memory mapping
- `brk` - Memory allocation
- `exit_group` - Process termination

### Capability Reference

Common capabilities:
- `CAP_NET_BIND_SERVICE` - Bind to privileged ports
- `CAP_SYS_ADMIN` - System administration (use cautiously)
- `CAP_CHOWN` - Change file ownership
- `CAP_DAC_OVERRIDE` - Bypass file permissions

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/my-feature`
3. **Commit changes**: `git commit -m 'Add some feature'`
4. **Push to branch**: `git push origin feature/my-feature`
5. **Open a Pull Request**

### Development Setup

```bash
# Clone the repository
git clone https://github.com/your-repo/purple.git
cd purple

# Install dependencies
cargo build

# Run tests
cargo test

# Build for release
cargo build --release
```

## 📜 License

[MIT License](LICENSE)

## 🎉 Conclusion

Purple provides a **secure, flexible, and production-ready** sandboxing solution for AI agents. With its comprehensive security features, easy-to-use policy system, and robust architecture, it's ideal for running untrusted AI workloads in isolated environments.

**Key Benefits:**
- ✅ Enterprise-grade security
- ✅ Multiple isolation layers
- ✅ Comprehensive resource management
- ✅ Easy policy configuration
- ✅ Production-ready architecture
- ✅ Detailed monitoring and logging

**Get Started Today!**

```bash
purple profile create my-agent
purple run --profile my-agent -- python3 ai_agent.py
```

🚀 **Secure your AI agents with Purple!** 🛡️