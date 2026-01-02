# Purple AI Sandbox

<p align="center">
  <strong>Enterprise-Grade Secure Runtime for Autonomous AI Agents</strong>
</p>

<p align="center">
  <a href="https://github.com/syedazeez337/purple-ai-sandbox/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License">
  </a>
  <a href="https://www.rust-lang.org/">
    <img src="https://img.shields.io/badge/Rust-1.92+-orange.svg" alt="Rust">
  </a>
  <a href="https://github.com/syedazeez337/purple-ai-sandbox/actions">
    <img src="https://img.shields.io/badge/Build-Passing-brightgreen.svg" alt="Build Status">
  </a>
</p>

---

## Overview

Purple is an enterprise-grade sandbox designed to safely run untrusted AI agents. It provides comprehensive isolation using Linux kernel security features and optional eBPF-based monitoring for complete visibility into agent behavior.

Built with Rust for memory safety and performance, Purple implements defense-in-depth security with multiple independent isolation layers. It is suitable for production AI workloads where security and reliability are paramount.

## Key Features

| Feature | Description |
|---------|-------------|
| **Multi-Layer Isolation** | User, PID, mount, and network namespaces for complete process isolation |
| **Syscall Filtering** | Seccomp-BPF with 450+ syscall mappings and argument validation |
| **Resource Limits** | Cgroups v2 for CPU, memory, PID, and I/O constraints |
| **Capability Dropping** | Linux capabilities management for least-privilege execution |
| **eBPF Monitoring** | Real-time syscall, file, and network event tracing (optional) |
| **Policy Engine** | YAML-based declarative security policies with profiles |
| **Audit Logging** | Structured JSON logs for compliance and forensics |
| **API Server** | RESTful API for programmatic sandbox management |

## Quick Start

### Prerequisites

- Linux kernel 5.10+ (for cgroups v2 full support)
- Rust 1.92 or later
- Root privileges (for namespace and cgroup operations)

### Installation

```bash
# Clone the repository
git clone https://github.com/syedazeez337/purple-ai-sandbox.git
cd purple-ai-sandbox/purple

# Build without eBPF (basic features)
cargo build --release

# Build with eBPF monitoring (requires bpf-linker)
cargo install bpf-linker
cargo build --release --features ebpf
```

### Running Your First Sandbox

```bash
# List available security profiles
./target/release/purple profile list

# Show profile details
./target/release/purple profile show ai-dev-safe

# Run a command in the sandbox
sudo ./target/release/purple run --profile ai-dev-safe -- /bin/echo "Hello from Purple!"
```

### Enable Unprivileged Namespaces (Optional)

For non-root sandbox execution:

```bash
echo "kernel.unprivileged_userns_clone=1" | sudo tee /etc/sysctl.d/99-unprivileged-namespaces.conf
sudo sysctl --system
```

---

## Architecture

### System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        Purple Sandbox                           │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
│  │   CLI    │  │  Policy      │  │  API Server              │  │
│  │          │  │  System      │  │  (Optional)              │  │
│  └────┬─────┘  └──────┬───────┘  └──────────────────────────┘  │
│       │               │                                          │
│       └───────────────┼──────────────────────────────────────────┘
│                       ▼                                          │
│  ┌─────────────────────────────────────────────────────────────┐
│  │                   Sandbox Engine                            │
│  ├─────────┬─────────┬─────────┬─────────┬─────────┬──────────┤
│  │Namespace│Seccomp  │ Cgroups │Capabilities│Network │Filesystem│
│  │Manager  │Filter   │Manager  │Manager   │Filter  │Isolator  │
│  └─────────┴─────────┴─────────┴─────────┴─────────┴──────────┘
│                       │                                          │
│                       ▼                                          │
│  ┌─────────────────────────────────────────────────────────────┐
│  │                    eBPF Layer (Optional)                    │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────────────────────┐  │
│  │  │ Syscall  │  │  File    │  │  Network                 │  │
│  │  │ Tracer   │  │  Tracer  │  │  Tracer & Filter         │  │
│  │  └──────────┘  └──────────┘  └──────────────────────────┘  │
│  └─────────────────────────────────────────────────────────────┘
└─────────────────────────────────────────────────────────────────┘
```

### Execution Flow

```
1. Parse CLI arguments
2. Load and validate YAML policy
3. Compile policy (resolve syscalls, parse resources)
4. Unshare user namespace (map UID/GID)
5. Optionally unshare network namespace
6. Unshare PID namespace, then fork
7. Child process:
   a. Unshare mount namespace
   b. Setup bind mounts and chroot
   c. Apply cgroup resource limits
   d. Drop Linux capabilities
   e. Apply seccomp syscall filter
   f. Execute target command
8. Parent process:
   a. Wait for child completion
   b. Collect resource usage metrics
   c. Generate audit log
   d. Cleanup resources
```

### Security Layers

Purple implements defense-in-depth with seven independent security layers:

| Layer | Technology | Protection |
|-------|------------|------------|
| **Process Isolation** | Linux namespaces (user, PID, mount, network) | Complete process isolation |
| **Syscall Filtering** | Seccomp-BPF with 450+ syscall mappings | Kernel surface area reduction |
| **Resource Limits** | Cgroups v2 (cpu, memory, pids, io) | DoS prevention |
| **Privilege Control** | Linux capabilities (CAP_DROP_ALL) | Least privilege |
| **Filesystem Isolation** | pivot_root + bind mounts | Container escape prevention |
| **Network Security** | eBPF + iptables | Data exfiltration prevention |
| **Audit & Monitoring** | Structured JSON logs | Compliance and forensics |

---

## Security Profiles

Purple includes pre-configured security profiles for common use cases:

| Profile | Description | Use Case |
|---------|-------------|----------|
| `ai-dev-safe` | Development with safe defaults | AI agent development |
| `production-secure` | High-security with default-deny syscalls | Production AI workloads |
| `code-analyst` | Filesystem access for code analysis | Code review agents |
| `data-retriever` | Network access for data fetching | Web scraping agents |
| `cicd-worker` | CI/CD pipeline execution | Automated testing |
| `honeypot` | Restricted with eBPF monitoring | Security testing |

### Example: Creating a Custom Profile

```yaml
# policies/my-custom-profile.yaml
name: "my-custom-agent"
description: "Custom profile for data processing agents"

filesystem:
  immutable_paths:
    - host_path: "/usr/bin"
      sandbox_path: "/usr/bin"
    - host_path: "/usr/lib"
      sandbox_path: "/usr/lib"
  scratch_paths:
    - "/tmp"
  output_paths:
    - host_path: "./outputs"
      sandbox_path: "/output"
  working_dir: "/tmp"

syscalls:
  default_deny: true
  allow:
    - "exit_group"
    - "read"
    - "write"
    - "openat"
    - "close"
    - "brk"
    - "mmap"
    - "mprotect"
    - "munmap"
    - "rt_sigaction"
    - "rt_sigprocmask"
    - "ioctl"
    - "pread64"
    - "pwrite64"
    - "readv"
    - "writev"
    - "sched_yield"
    - "nanosleep"
    - "getitimer"
    - "alarm"
    - "setitimer"
    - "getpid"
    - "socket"
    - "connect"
    - "accept"
    - "sendto"
    - "recvfrom"
    - "sendmsg"
    - "recvmsg"
    - "shutdown"
    - "bind"
    - "listen"
    - "getsockname"
    - "getpeername"
    - "socketpair"
    - "setsockopt"
    - "getsockopt"
    - "clone"
    - "vfork"
    - "execve"
    - "wait4"
    - "kill"
    - "uname"
    - "semget"
    - "semop"
    - "semctl"
    - "shmdt"
    - "msgget"
    - "msgsnd"
    - "msgrcv"
    - "msgctl"
    - "fcntl"
    - "flock"
    - "fsync"
    - "fdatasync"
    - "truncate"
    - "ftruncate"
    - "getcwd"
    - "chdir"
    - "fchdir"
    - "rename"
    - "mkdir"
    - "rmdir"
    - "creat"
    - "link"
    - "unlink"
    - "symlink"
    - "readlink"
    - "chmod"
    - "fchmod"
    - "chown"
    - "fchown"
    - "lchown"
    - "umask"
    - "gettimeofday"
    - "getrlimit"
    - "getrusage"
    - "sysinfo"
    - "times"
    - "ptrace"
    - "getuid"
    - "syslog"
    - "getgid"
    - "setuid"
    - "setgid"
    - "geteuid"
    - "getegid"
    - "setpgid"
    - "getppid"
    - "getpgrp"
    - "setsid"
    - "getgroups"
    - "setgroups"
    - "setresuid"
    - "getresuid"
    - "setresgid"
    - "getresgid"
    - "getpgid"
    - "setfsuid"
    - "setfsgid"
    - "getsid"
    - "capget"
    - "capset"
    - "rt_sigpending"
    - "rt_sigtimedwait"
    - "rt_sigqueueinfo"
    - "rt_sigsuspend"
    - "sigaltstack"
    - "utime"
    - "mknod"
    - "uselib"
    - "personality"
    - "ustat"
    - "statfs"
    - "fstatfs"
    - "sysfs"
    - "getpriority"
    - "setpriority"
    - "sched_setparam"
    - "sched_getparam"
    - "sched_setscheduler"
    - "sched_getscheduler"
    - "sched_get_priority_max"
    - "sched_get_priority_min"
    - "sched_rr_get_interval"
    - "mlock"
    - "munlock"
    - "mlockall"
    - "munlockall"
    - "vhangup"
    - "modify_ldt"
    - "pivot_root"
    - "_sysctl"
    - "prctl"
    - "arch_prctl"
    - "adjtimex"
    - "setrlimit"
    - "chroot"
    - "sync"
    - "acct"
    - "settimeofday"
    - "mount"
    - "umount2"
    - "swapon"
    - "swapoff"
    - "reboot"
    - "sethostname"
    - "setdomainname"
    - "init_module"
    - "delete_module"
    - "quotactl"
    - "gettid"
    - "readahead"
    - "setxattr"
    - "lsetxattr"
    - "fsetxattr"
    - "getxattr"
    - "lgetxattr"
    - "fgetxattr"
    - "listxattr"
    - "llistxattr"
    - "flistxattr"
    - "removexattr"
    - "lremovexattr"
    - "fremovexattr"
    - "tkill"
    - "time"
    - "futex"
    - "sched_setaffinity"
    - "sched_getaffinity"
    - "io_setup"
    - "io_destroy"
    - "io_getevents"
    - "io_submit"
    - "io_cancel"
    - "lookup_dcookie"
    - "epoll_create"
    - "remap_file_pages"
    - "set_tid_address"
    - "timer_create"
    - "timer_settime"
    - "timer_gettime"
    - "timer_getoverrun"
    - "timer_delete"
    - "clock_settime"
    - "clock_gettime"
    - "clock_getres"
    - "clock_nanosleep"
    - "exit_group"
    - "epoll_wait"
    - "tgkill"
    - "utimes"
    - "mbind"
    - "set_mempolicy"
    - "mq_open"
    - "mq_unlink"
    - "mq_timedsend"
    - "mq_timedreceive"
    - "mq_notify"
    - "mq_getsetattr"
    - "kexec_load"
    - "waitid"
    - "add_key"
    - "request_key"
    - "keyctl"
    - "ioprio_set"
    - "ioprio_get"
    - "inotify_init"
    - "inotify_add_watch"
    - "inotify_rm_watch"
    - "migrate_pages"
    - "openat"
    - "mkdirat"
    - "mknodat"
    - "fchownat"
    - "futimesat"
    - "newfstatat"
    - "unlinkat"
    - "renameat"
    - "linkat"
    - "symlinkat"
    - "readlinkat"
    - "fchmodat"
    - "faccessat"
    - "pselect6"
    - "ppoll"
    - "unshare"
    - "set_robust_list"
    - "get_robust_list"
    - "splice"
    - "sync_file_range"
    - "tee"
    - "vmsplice"
    - "move_pages"
    - "utimensat"
    - "epoll_pwait"
    - "signalfd"
    - "timerfd_create"
    - "eventfd"
    - "timerfd_settime"
    - "timerfd_gettime"
    - "accept4"
    - "signalfd4"
    - "eventfd2"
    - "epoll_create1"
    - "dup3"
    - "pipe2"
    - "inotify_init1"
    - "preadv"
    - "pwritev"
    - "rt_tgsigqueueinfo"
    - "perf_event_open"
    - "recvmmsg"
    - "fanotify_init"
    - "fanotify_mark"
    - "prlimit64"
    - "name_to_handle_at"
    - "open_by_handle_at"
    - "clock_adjtime"
    - "syncfs"
    - "sendmmsg"
    - "setns"
    - "getcpu"
    - "process_vm_readv"
    - "process_vm_writev"
    - "kcmp"
    - "finit_module"
    - "sched_setattr"
    - "sched_getattr"
    - "renameat2"
    - "seccomp"
    - "getrandom"
    - "memfd_create"
    - "bpf"
    - "execveat"
    - "userfaultfd"
    - "membarrier"
    - "mlock2"
    - "copy_file_range"
    - "preadv2"
    - "pwritev2"
    - "pkey_mprotect"
    - "pkey_alloc"
    - "pkey_free"
    - "statx"
    - "io_pgetevents"
    - "rseq"
    - "pidfd_send_signal"
    - "io_uring_setup"
    - "io_uring_enter"
    - "io_uring_register"
    - "open_tree"
    - "move_mount"
    - "fsopen"
    - "fsconfig"
    - "fsmount"
    - "fsinfo"
    - "clone3"
    - "close_range"
    - "openat2"
    - "pidfd_getfd"
    - "faccessat2"
    - "process_madvise"
    - "epoll_pwait2"
    - "mount_setattr"
    - "quotactl_fd"
    - "landlock_create_ruleset"
    - "landlock_add_rule"
    - "landlock_restrict_self"
    - "memfd_secret"
    - "cachestat"
    - "fchmodat2"
    - "map_shadow_stack"
    - "futex_waitv"
  advanced_rules:
    - syscall: openat
      action: allow
      conditions:
        - arg: 2  # flags
          op: masked_eq
          value: 0  # O_RDONLY
          mask: 0o3  # O_ACCMODE

resources:
  cpu_shares: 0.5
  memory_limit_bytes: "2G"
  pids_limit: 100
  session_timeout_seconds: 3600

capabilities:
  default_drop: true
  add: []

network:
  isolated: false
  allowed_outgoing_ports:
    - 80
    - 443
    - 53

audit:
  enabled: true
  log_path: "/var/log/purple/audit.log"
  detail_level:
    - resource
    - filesystem
    - syscall
    - network

ebpf_monitoring:
  enabled: false
  trace_syscalls: false
  trace_files: false
  trace_network: false
```

---

## Usage

### Command Line Interface

```bash
# Profile management
purple profile list                          # List all profiles
purple profile show <name>                   # Show profile details
purple profile create <name>                 # Create new profile

# Run a sandbox
purple run --profile <name> -- <command>     # Run command in sandbox

# Monitor eBPF events (requires --features ebpf)
purple monitor --profile <name>              # Real-time event monitoring

# API server
purple api --address 0.0.0.0:8080           # Start REST API server

# Audit and reporting
purple audit --all                           # Generate audit report
purple audit --session <id> --format json    # Session-specific report

# Sandbox management
purple sandboxes list                        # List running sandboxes
purple sandboxes stop --id <uuid>            # Stop a sandbox
```

### Running with Custom Policies

```bash
# Use a specific profile
sudo purple run --profile production-secure -- /bin/bash -c "echo test"

# Direct execution (bypass manager)
sudo purple run --direct --profile ai-dev-safe -- /bin/ls

# With debug logging
RUST_LOG=debug sudo purple run --profile ai-dev-safe -- /bin/echo debug
```

### eBPF Monitoring

```bash
# Start monitoring (requires root and --features ebpf)
sudo purple monitor --profile honeypot

# Monitor with correlation display
sudo purple monitor --profile honeypot --show-correlation
```

### REST API

```bash
# Start API server
export PURPLE_API_KEY="your-secure-key"
sudo purple api --address 127.0.0.1:8080

# Create a sandbox via API
curl -X POST http://localhost:8080/api/v1/sandboxes \
  -H "Authorization: Bearer $PURPLE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "profile": "ai-dev-safe",
    "command": ["/bin/echo", "hello"],
    "timeout_seconds": 300
  }'

# List running sandboxes
curl http://localhost:8080/api/v1/sandboxes \
  -H "Authorization: Bearer $PURPLE_API_KEY"
```

---

## Configuration Reference

### Policy Schema

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Policy name (filename without .yaml) |
| `description` | string | Human-readable description |
| `filesystem` | object | Filesystem isolation settings |
| `syscalls` | object | Syscall filtering rules |
| `resources` | object | Resource limits |
| `capabilities` | object | Linux capabilities policy |
| `network` | object | Network isolation settings |
| `audit` | object | Audit logging configuration |
| `ebpf_monitoring` | object | eBPF tracing configuration |

### Filesystem Configuration

```yaml
filesystem:
  immutable_paths:
    - host_path: "/usr/bin"
      sandbox_path: "/usr/bin"
    - host_path: "/usr/lib"
      sandbox_path: "/usr/lib"
  scratch_paths:
    - "/tmp"
    - "/var/tmp"
  output_paths:
    - host_path: "./results"
      sandbox_path: "/output"
  working_dir: "/tmp"
```

### Syscall Configuration

```yaml
syscalls:
  default_deny: true          # Deny all by default
  allow:                      # List of allowed syscalls
    - "exit_group"
    - "read"
    - "write"
  deny:                       # Syscalls to explicitly deny
    - "mount"
    - "umount2"
  advanced_rules:             # Conditional filtering
    - syscall: openat
      action: allow
      conditions:
        - arg: 2
          op: masked_eq
          value: 0
          mask: 0o3
```

### Resources Configuration

```yaml
resources:
  cpu_shares: 0.5                    # CPU weight (0.0-1.0)
  memory_limit_bytes: "2G"           # Memory limit (supports K, M, G)
  pids_limit: 100                    # Max number of processes
  session_timeout_seconds: 3600      # Session timeout in seconds
  block_io_limit_bytes_per_sec: "100M"  # I/O rate limit
```

### Network Configuration

```yaml
network:
  isolated: false                    # Complete network isolation
  allowed_outgoing_ports:            # Outgoing port allowlist
    - 80
    - 443
    - 53
  allowed_incoming_ports:            # Incoming port allowlist
    - 8080
  blocked_ips_v4:                    # IPv4 addresses to block
    - "1.1.1.1"
  dns_servers:                       # Custom DNS servers
    - "8.8.8.8"
    - "8.8.4.4"
```

### Capabilities Configuration

```yaml
capabilities:
  default_drop: true                 # Drop all capabilities
  add:                               # Capabilities to retain
    - "CAP_NET_RAW"
```

### Audit Configuration

```yaml
audit:
  enabled: true
  log_path: "/var/log/purple/audit.log"
  detail_level:
    - resource       # Resource usage metrics
    - filesystem     # File operations
    - syscall        # Syscall invocations
    - network        # Network activity
```

---

## Monitoring and Observability

### Audit Log Format

```json
{
  "timestamp": "2026-01-02T18:51:47.164Z",
  "event_type": "sandbox_execution",
  "sandbox_id": "0a043674-a668-41c5-a030-b1736e568f9b",
  "policy_name": "honeypot-research",
  "command": ["/bin/echo", "hello"],
  "status": "completed",
  "exit_code": 0,
  "resource_usage": {
    "cpu_time_seconds": 0.05,
    "peak_memory_bytes": 2097152,
    "disk_io_bytes": 8192
  },
  "security_events": [
    {
      "type": "syscall_deny",
      "syscall": "mount",
      "pid": 127477
    }
  ]
}
```

### Resource Usage Tracking

Purple collects real-time resource metrics from cgroups:

| Metric | Source | Description |
|--------|--------|-------------|
| CPU time | cpu.stat | Total CPU consumption in seconds |
| Peak memory | memory.peak | Maximum memory usage |
| I/O bytes | io.stat | Total read/write operations |
| Process count | pids.current | Number of processes in cgroup |

### eBPF Event Types

When eBPF monitoring is enabled, Purple captures:

- **Syscall events**: Every syscall with arguments and return value
- **File events**: Open, read, write, close operations
- **Network events**: Connection attempts, packet metadata

---

## Security Considerations

### Threat Model

Purple is designed to mitigate:

1. **Container Escape**: Multiple namespace layers prevent breakout
2. **Resource Exhaustion**: Cgroups limits prevent DoS attacks
3. **Privilege Escalation**: Capability dropping enforces least privilege
4. **Data Exfiltration**: Network filtering blocks unauthorized transfers
5. **Kernel Exploitation**: Seccomp reduces syscall surface area
6. **Audit Evasion**: Comprehensive logging ensures traceability

### Limitations

- **Not a Replacement for VMs**: Purple provides process isolation, not hardware virtualization
- **Container-Within-Host**: All sandboxes share the host kernel
- **Root in Namespace**: User namespace root is not equivalent to host root
- **Host Kernel Dependencies**: Kernel vulnerabilities affect all sandboxes

### Production Deployment Recommendations

1. **Enable All Security Layers**: Use default-deny syscall policies
2. **Restrict Capabilities**: Set `default_drop: true` with minimal `add` list
3. **Set Conservative Limits**: Memory and CPU limits prevent runaway processes
4. **Enable Audit Logging**: Maintain comprehensive logs for compliance
5. **Use eBPF Monitoring**: Real-time visibility into agent behavior
6. **Network Isolation**: Block unnecessary outgoing connections
7. **Regular Policy Review**: Audit and update security profiles

---

## Testing

```bash
# Run all unit tests
cargo test

# Run with debug logging
RUST_LOG=debug cargo test

# Run specific test
cargo test test_name

# Run tests with eBPF features
cargo test --features ebpf

# Run linting
cargo fmt
cargo clippy
```

### Test Coverage

Purple includes tests for:

- Policy compilation and validation
- Syscall number resolution
- Resource limit enforcement
- Filesystem isolation
- Network filtering
- Sandbox lifecycle management
- Property-based testing for edge cases

---

## Contributing

Contributions are welcome! Please follow these guidelines:

1. **Fork the repository** and create a feature branch
2. **Make your changes** with tests and documentation
3. **Run tests**: `cargo test`
4. **Format code**: `cargo fmt`
5. **Check linting**: `cargo clippy`
6. **Submit a pull request** with clear description

### Development Setup

```bash
# Install development tools
rustup component add rustfmt clippy

# Install bpf-linker for eBPF development
cargo install bpf-linker

# Run full CI locally
cargo fmt && cargo clippy && cargo test
```

---

## Roadmap

| Version | Target | Features |
|---------|--------|----------|
| 0.2.0 | Q1 2026 | Enhanced eBPF correlation engine |
| 0.3.0 | Q2 2026 | REST API with authentication |
| 0.4.0 | Q3 2026 | Kubernetes operator |
| 1.0.0 | Q4 2026 | Production release |

---

## License

Purple is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

---

## Acknowledgments

Purple is built using these excellent open source projects:

- [libseccomp](https://github.com/seccomp/libseccomp) - Linux syscall filtering
- [nix](https://github.com/nix-rs/nix) - Rust bindings to Linux APIs
- [aya](https://github.com/aya-rs/aya) - eBPF tooling for Rust
- [clap](https://github.com/clap-rs/clap) - Command-line argument parsing
- [cgroups-rs](https://github.com/kata-containers/cgroups-rs) - Cgroups management
- [tokio](https://github.com/tokio-rs/tokio) - Async runtime
- [axum](https://github.com/tokio-rs/axum) - HTTP API framework

---

## Support

- **Issues**: Report bugs and feature requests via [GitHub Issues](https://github.com/syedazeez337/purple-ai-sandbox/issues)
- **Documentation**: See [docs/](docs/) for architecture and API documentation
- **Security**: See [SECURITY.md](SECURITY.md) for vulnerability reporting
