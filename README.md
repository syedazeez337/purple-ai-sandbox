# Purple AI Sandbox

**Professional Secure Runtime for Autonomous AI Agents**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Rust](https://img.shields.io/badge/Rust-1.92+-orange.svg)](https://www.rust-lang.org/)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)](https://github.com/syedazeez337/purple-ai-sandbox)

## 🎯 Purpose

Purple is an enterprise-grade sandbox designed to safely run untrusted AI agents. It goes beyond passive monitoring to provide **Active Defense**—blocking malicious network activity, enforcing strict resource limits, and isolating filesystems in real-time using Linux Namespaces and eBPF.

## ✨ Key Capabilities

| Feature | Description | Mechanism |
|---------|-------------|-----------|
| **Active Network Defense** | Blocks data exfiltration to specific IPs/domains. | **eBPF (Cgroup SKB)** |
| **Resource Enforcement** | Hard limits on CPU, RAM, and Swap. Auto-kills hogs. | **Cgroups v2** |
| **System Isolation** | Invisible filesystem barriers and private process trees. | **Namespaces (User, PID, Mount)** |
| **Syscall Filtering** | Restricts kernel surface area (e.g., block `execve`, `ptrace`). | **Seccomp BPF** |
| **Lifecycle Management** | Automated cleanup of zombie processes and mounts. | **Rust RAII / Drop** |

## 🚀 Quick Start

### **1. Prerequisites**

Purple requires a Linux system with eBPF support.

```bash
# Install eBPF linker
cargo install bpf-linker
```

### **2. Build**

```bash
# Clone and build (enabling eBPF features)
git clone https://github.com/syedazeez337/purple-ai-sandbox.git
cd purple-ai-sandbox
cargo build --release --features ebpf
```

### **3. Run a Secure Agent**

Create a policy file (`policies/secure-agent.yaml`) to define your security rules:

```yaml
name: "secure-agent"
description: "High-security profile for untrusted agents"

network:
  isolated: false
  blocked_ips:
    - "1.1.1.1"       # Block specific IPs
    - "169.254.169.254" # Block cloud metadata services

resources:
  memory_limit_bytes: "512M"
  cpu_shares: 0.5

filesystem:
  immutable_paths:
    - host_path: "/usr/bin"
      sandbox_path: "/usr/bin"
  scratch_paths:
    - "/tmp"
  output_paths:
    - host_path: "./output"
      sandbox_path: "/output"
```

Run the agent:

```bash
sudo ./target/release/purple run --profile secure-agent -- python3 my_agent.py
```

## 🛡️ Architecture

Purple employs a "Defense in Depth" strategy:

1.  **Outer Ring (Management):** The `SandboxManager` handles resource allocation, lifecycle, and cleanup.
2.  **Middle Ring (Isolation):** Linux Namespaces create a private "view" of the system (Filesystem, PID, Network).
3.  **Inner Ring (Enforcement):**
    *   **Seccomp:** Blocks dangerous syscalls at the kernel boundary.
    *   **Cgroups:** Enforces physical resource limits.
    *   **eBPF:** Actively filters network packets and traces behavior.

## 📊 Monitoring & observability

Purple provides real-time visibility into agent behavior:

*   **Structured Audit Logs:** JSON logs of every syscall, file access, and network connection.
*   **Cost & Token Tracking:** Monitor LLM usage (tokens/cost) via the API Monitor sidecar.
*   **Violation Alerts:** Immediate alerts when an agent hits a resource limit or tries to access blocked resources.

## 🤝 Contributing

Contributions are welcome! Please ensure you run tests with the `ebpf` feature enabled:

```bash
cargo test --features ebpf
```

## 📄 License

Apache 2.0 - Commercial-friendly and open source.
