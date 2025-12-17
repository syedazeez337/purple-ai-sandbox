# 🛡️ Purple AI Sandbox

## Run AI Agents Without Fear

**The open-source security layer that lets you deploy AI agents with confidence.**

---

## The Problem

AI agents are powerful—but they're also unpredictable. Give them too much access, and a single hallucination could:

- 🗑️ Delete your production database
- 🌐 Exfiltrate sensitive data
- 💣 Fork-bomb your infrastructure
- 🔓 Escalate privileges unexpectedly

You need AI agents to be productive. But you also need to sleep at night.

---

## The Solution

**Purple is the runtime security sandbox designed specifically for AI agents.**

We don't just isolate—we provide *defense in depth* with 7 layers of protection:

```
┌─────────────────────────────────────────┐
│         🛡️ PURPLE SECURITY LAYERS       │
├─────────────────────────────────────────┤
│  1. Linux Namespaces    → Process Jail  │
│  2. Seccomp Filters     → Syscall Gate  │
│  3. Capability Dropping → Least Privs   │
│  4. Cgroups v2          → Resource Caps │
│  5. Network Isolation   → Data Firewall │
│  6. Filesystem Chroot   → Path Control  │
│  7. Audit Logging       → Full Trace    │
└─────────────────────────────────────────┘
```

---

## Why Purple?

### 🎯 Built for AI Workloads

Unlike generic containers, Purple understands AI agent patterns:
- Code generation that needs compiler access
- Web scrapers that need controlled network
- ML training that needs high resources
- Agents that need to read but not write

### 📋 Declarative Policy System

Define security as code with simple YAML:

```yaml
name: "my-ai-agent"

syscalls:
  default_deny: true
  allow: ["read", "write", "execve"]

resources:
  memory_limit: "4G"
  cpu_shares: 0.5
  timeout: 3600

network:
  isolated: true
```

### ⚡ Zero Runtime Overhead

Native Linux kernel features mean:
- **Namespace isolation**: Near-zero overhead
- **Seccomp filtering**: Microsecond syscall checks
- **Cgroups limits**: Kernel-enforced, not polled

### 🔓 Open Source Under MIT

- No vendor lock-in
- Audit the security yourself
- Contribute and extend
- Use commercially with confidence

---

## Real-World Scenarios

| Use Case | What Purple Provides |
|----------|---------------------|
| **AI Code Assistants** | Read source files, blocked from network |
| **ML Training Pipelines** | 32GB RAM, 90% CPU, no dangerous syscalls |
| **Web Scraping Agents** | HTTPS only, no incoming connections |
| **CI/CD Build Agents** | Full toolchain, sandboxed execution |
| **LLM Inference Servers** | API serving, GPU access, resource limits |
| **Security Scanners** | Read-only access, comprehensive audit |

---

## Get Started in 60 Seconds

```bash
# Build
cargo build --release

# Create a profile
./purple profile create my-agent

# Run your agent securely
./purple run --profile my-agent -- python3 agent.py
```

---

## The Bottom Line

> **"LLMs make mistakes. Purple makes sure those mistakes stay contained."**

Stop choosing between AI capability and security. With Purple, you get both.

---

<p align="center">
  <strong>Open Source</strong> • <strong>Production Ready</strong> • <strong>Enterprise Grade</strong>
</p>

<p align="center">
  ⭐ Star us on GitHub • 📖 Read the Docs • 💬 Join the Community
</p>

<p align="center">
  <em>Secure your AI agents with Purple.</em> 🛡️
</p>
