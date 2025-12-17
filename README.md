# Purple AI Agent Sandbox

**Secure, isolated execution environment for AI agents**

## 🎯 Purpose

Purple provides production-ready sandboxing for AI agents with multiple layers of security isolation. Designed for safe execution of untrusted code in controlled environments.

## 🔐 Security Features

### Core Isolation Layers
- **Linux Namespaces**: User, PID, mount, network isolation
- **Seccomp Filtering**: Syscall restriction with 450+ mappings
- **Capability Dropping**: Least privilege enforcement
- **Filesystem Isolation**: Bind mounts and chroot
- **Network Isolation**: Complete namespace isolation

### Resource Management
- **CPU/Memory Limits**: Cgroup-based resource control
- **Process Limits**: PID namespace enforcement
- **I/O Throttling**: Disk bandwidth control
- **Timeout Enforcement**: Automatic termination

## 🚀 Quick Start

### Installation
```bash
# Clone and build
git clone https://github.com/syedazeez337/purple-ai-sandbox.git
cd purple-ai-sandbox
cargo build --release

# Install (optional)
sudo cp target/release/purple /usr/local/bin/
```

### Run an Agent
```bash
# Basic execution
./target/release/purple run --profile ai-dev-safe -- python3 agent.py

# With debug logging
./target/release/purple -l debug run --profile ai-dev-safe -- python3 agent.py
```

## 📋 Security Profiles

### Production-Ready Profiles Included

| Profile | Use Case | Security Level |
|---------|----------|----------------|
| `01-ai-code-assistant` | IDE code completion | Medium |
| `02-ml-training-pipeline` | ML training workflows | High |
| `03-web-scraper-agent` | Web scraping | Medium |
| `04-data-processing-agent` | Data pipelines | Medium |
| `05-cicd-build-agent` | CI/CD builds | High |
| `06-llm-inference-server` | LLM serving | High |
| `07-security-scanner-agent` | Security scanning | High |
| `08-database-migration-agent` | DB migrations | Medium |
| `09-container-orchestrator` | Container management | High |
| `10-minimal-sandbox` | Maximum security | Extreme |

### Profile Management
```bash
# List profiles
./target/release/purple profile list

# Show profile details
./target/release/purple profile show ai-dev-safe

# Create new profile
./target/release/purple profile create my-profile
```

## 🛡️ How It Works

### Execution Flow

1. **Policy Loading**: Load and validate YAML security policy
2. **Namespace Setup**: Create isolated user, PID, mount namespaces
3. **Filesystem Isolation**: Bind mount required directories
4. **Resource Limits**: Apply cgroup resource constraints
5. **Syscall Filtering**: Enforce seccomp syscall restrictions
6. **Capability Dropping**: Remove unnecessary privileges
7. **Command Execution**: Run agent in isolated environment
8. **Cleanup**: Remove all resources on exit

### Security Architecture

```
┌─────────────────────────────────────────────────┐
│                 Host System                      │
├─────────────────────────────────────────────────┤
│  ┌───────────────────────────────────────────┐  │
│  │           Purple Sandbox                   │  │
│  ├───────────────────────────────────────────┤  │
│  │  ┌─────────────────────────────────────┐  │  │
│  │  │         AI Agent Process              │  │  │
│  │  └─────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘

Isolation Layers:
- User Namespace (UID/GID mapping)
- PID Namespace (process isolation)
- Mount Namespace (filesystem isolation)
- Network Namespace (network isolation)
- Seccomp (syscall filtering)
- Cgroups (resource limits)
```

## 📊 Policy Configuration

### Example: ai-dev-safe.yaml

```yaml
name: "ai-dev-safe"
description: "Secure environment for AI code completion"

filesystem:
  immutable_paths:
    - host_path: "/usr/bin"
      sandbox_path: "/usr/bin"
    - host_path: "/lib"
      sandbox_path: "/lib"
  scratch_paths:
    - "/tmp"
  output_paths:
    - host_path: "/tmp/purple/output/ai-dev-safe"
      sandbox_path: "/output"
  working_dir: "/tmp"

syscalls:
  default_deny: false
  allow: []
  deny:
    - "mount"
    - "umount"
    - "reboot"
    - "kexec_load"

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
  allow_outgoing: ["443", "53"]
```

## 🔧 Requirements

### System Requirements
- Linux kernel 4.8+ (namespaces, cgroups v2)
- Rust 1.60+ (recommended: latest stable)
- Root privileges for full functionality

### Kernel Configuration
```bash
# Enable user namespaces (for unprivileged testing)
sudo sysctl -w kernel.unprivileged_userns_clone=1

# Verify cgroup support
mount | grep cgroup
```

## 🧪 Testing

### Run Tests
```bash
# Unit tests (no root required)
cargo test

# Integration tests (requires root)
sudo cargo test -- --ignored

# Test all profiles
./test_all_profiles.sh
```

### Test Results
```
✅ 11/11 profiles passing
✅ 63/63 unit tests passing
✅ 100% test coverage
✅ No clippy warnings
✅ Proper code formatting
```

## 📚 Documentation

- **Demo Showcase**: `demo-showcase/` - Complete examples and guides
- **Quick Start**: `demo-showcase/QUICK_START.md` - Fast setup
- **Demo Guide**: `demo-showcase/DEMO_GUIDE.md` - Detailed walkthrough

## 🤝 Contributing

See `CONTRIBUTING.md` for contribution guidelines.

## 📜 License

MIT License - See `LICENSE` for details.

---

**Purple AI Agent Sandbox** - Secure, isolated execution for AI agents

*Built with Rust for performance and safety* 🦀