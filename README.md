# Purple AI Sandbox

**Enterprise-Grade Secure Runtime for Autonomous AI Agents**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Rust](https://img.shields.io/badge/Rust-1.92+-orange.svg)](https://www.rust-lang.org/)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)](https://github.com/syedazeez337/purple-ai-sandbox)
[![Security Audit](https://img.shields.io/badge/Security-Audited-brightgreen.svg)](#security)

## 🎯 Purpose

Purple is an enterprise-grade sandbox designed to safely run untrusted AI agents. It provides **Active Defense** through multiple layers of security:

- **Active Network Defense** — Blocks data exfiltration using eBPF
- **Advanced Syscall Filtering** — Fine-grained kernel surface area control with argument validation
- **Resource Enforcement** — Hard limits on CPU, RAM, and process count
- **Secure Containerization** — Namespaces, pivot_root, and capability dropping

## 🛡️ Security Architecture

Purple employs a defense-in-depth strategy with multiple security layers:

| Layer | Technology | Protection |
|-------|------------|------------|
| **Network** | eBPF + iptables | Packet filtering, data exfiltration prevention |
| **Filesystem** | pivot_root + bind mounts | Container escape prevention |
| **Syscalls** | Seccomp BPF + advanced rules | Kernel surface area restriction |
| **Resources** | Cgroups v2 | CPU, memory, and PID limits |
| **Capabilities** | Linux capabilities | Fine-grained privilege control |
| **Audit** | Structured JSON logs | Complete activity tracing |

See [SECURITY.md](SECURITY.md) for detailed audit history and remediation details.

## ✨ Key Capabilities

### Advanced Syscall Filtering

Purple supports fine-grained syscall filtering with argument validation:

```yaml
syscalls:
  default_deny: true
  allow:
    - "exit_group"
    - "read"
    - "openat"
  advanced_rules:
    # Read-only file access only
    - syscall: openat
      action: allow
      conditions:
        - arg: 2  # flags argument
          op: masked_eq
          value: 0  # O_RDONLY
          mask: 0o3  # O_ACCMODE mask

    # IPv4/IPv6 sockets only
    - syscall: socket
      action: allow
      conditions:
        - arg: 0  # domain
          op: eq
          value: 2  # AF_INET
```

**Supported comparison operators:**
- `eq` — Equal
- `neq` — Not equal
- `lt` / `lte` — Less than / Less than or equal
- `gt` / `gte` — Greater than / Greater than or equal
- `masked_eq` — Bitmask equality (e.g., check specific flag bits)

### Pre-defined Security Profiles

| Profile | Description | Use Case |
|---------|-------------|----------|
| `ai-dev-safe` | Development with safe defaults | AI agent development |
| `production-secure` | High-security with advanced syscall filtering | Production AI workloads |
| `honeypot` | Restricted with eBPF monitoring | Security testing |

## 🚀 Quick Start

### Prerequisites

```bash
# Install eBPF linker (required for monitoring features)
cargo install bpf-linker

# Clone and build
git clone https://github.com/syedazeez337/purple-ai-sandbox.git
cd purple-ai-sandbox/purple
cargo build --release --features ebpf
```

### Run a Secure Agent

```bash
# List available profiles
./target/release/purple profile list

# Show profile details
./target/release/purple profile show production-secure

# Run a command in the sandbox
sudo ./target/release/purple run --profile production-secure -- /bin/echo "Hello from secure sandbox!"
```

### API Server (with Authentication)

```bash
# Set API key (required for production)
export PURPLE_API_KEY="your-secure-api-key"

# Start API server with rate limiting and authentication
./target/release/purple api --address 127.0.0.1:8080
```

**API Endpoints (Bearer token authentication required):**

```bash
# Create sandbox
curl -X POST http://localhost:8080/sandboxes \
  -H "Authorization: Bearer $PURPLE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "test", "profile": "production-secure", "command": ["/bin/echo", "test"]}'

# List sandboxes
curl http://localhost:8080/sandboxes \
  -H "Authorization: Bearer $PURPLE_API_KEY"
```

## 📊 Monitoring & Observability

### Structured Audit Logs

All sandbox activity is logged in JSON format for security analysis:

```json
{
  "timestamp": 1703325800,
  "event_type": "sandbox_execution",
  "policy_name": "production-secure",
  "command": ["/bin/echo", "test"],
  "status": "completed",
  "sandbox_id": "uuid-here"
}
```

### eBPF Monitoring (Optional)

Enable advanced syscall and network tracing:

```bash
./target/release/purple monitor --profile production-secure
```

## 🏗️ Architecture

### Core Components

```
┌─────────────────────────────────────────────────────────────┐
│                     Purple Sandbox                          │
├─────────────────────────────────────────────────────────────┤
│  CLI (clap)                                                 │
│  ├── profile {create|list|delete|show}                      │
│  ├── run                                                    │
│  ├── monitor (requires --features ebpf)                     │
│  ├── api                                                    │
│  └── audit                                                  │
├─────────────────────────────────────────────────────────────┤
│  Policy System                                              │
│  ├── YAML policy parser                                     │
│  ├── Syscall compiler (resolves names → numbers)            │
│  └── Advanced rules (conditional filtering)                 │
├─────────────────────────────────────────────────────────────┤
│  Sandbox Engine                                             │
│  ├── Linux Namespaces (user, pid, mount, network)           │
│  ├── Seccomp BPF (syscall filtering)                       │
│  ├── Cgroups v2 (resource limits)                           │
│  ├── Capabilities (privilege dropping)                      │
│  ├── pivot_root (secure containerization)                   │
│  └── eBPF (network filtering & tracing)                     │
└─────────────────────────────────────────────────────────────┘
```

### Execution Flow

1. Parse CLI arguments and load policy YAML
2. Compile policy (resolve syscalls, parse resources)
3. Unshare namespaces (user → PID → network → mount)
4. Fork to enter new PID namespace
5. Child: Setup filesystem, apply limits, drop capabilities
6. Apply seccomp filter with advanced rules
7. Execute command
8. Parent: Wait, cleanup, and generate audit log

## 🔧 Configuration Reference

### Policy Schema

```yaml
name: "policy-name"
description: "Policy description"

filesystem:
  immutable_paths:    # Read-only bind mounts
    - host_path: "/usr/bin"
      sandbox_path: "/usr/bin"
  scratch_paths:      # Writable directories
    - "/tmp"
  output_paths:       # Output directories
    - host_path: "./output"
      sandbox_path: "/output"
  working_dir: "/tmp"

syscalls:
  default_deny: true  # Deny all except allowed syscalls
  allow:              # List of allowed syscalls
    - "exit_group"
    - "read"
    - "write"
  advanced_rules:     # Fine-grained filtering
    - syscall: "openat"
      action: allow
      conditions:
        - arg: 2
          op: masked_eq
          value: 0
          mask: 0o3

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
  allow_outgoing:
    - "443"
    - "80"
    - "53"

audit:
  enabled: true
  log_path: "/var/log/purple/audit.log"
  detail_level: ["resource", "filesystem", "syscall", "network"]
```

## 🧪 Testing

```bash
# Run all tests
cargo test

# Run with debug logging
RUST_LOG=debug cargo test

# Run with eBPF features
cargo test --features ebpf
```

## 📦 Dependencies

| Dependency | Purpose |
|------------|---------|
| `clap` | CLI argument parsing |
| `nix` | Linux syscalls (namespaces, mount, fork) |
| `libseccomp` | Seccomp BPF filter creation |
| `cgroups-rs` | Cgroups management |
| `serde`/`serde_yaml` | Policy serialization |
| `aya` | eBPF support (optional) |
| `tokio` | Async runtime for API server |
| `axum` | HTTP API framework |

## 🤝 Contributing

Contributions are welcome! Please ensure:

1. All tests pass: `cargo test`
2. Code is formatted: `cargo fmt`
3. No clippy warnings: `cargo clippy`

## 📄 License

Apache 2.0 — Commercial-friendly and open source.

## 🙏 Acknowledgments

Built with:
- [libseccomp](https://github.com/seccomp/libseccomp) — Linux syscall filtering
- [nix](https://github.com/nix-rs/nix) — Rust bindings to Linux APIs
- [aya](https://github.com/aya-rs/aya) — eBPF tooling for Rust
