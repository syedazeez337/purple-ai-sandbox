# 🚀 Purple AI Sandbox - Demo Showcase

**Everything you need to demonstrate Purple's security capabilities**

This folder contains 10 real-world policy scenarios, demo scripts, and step-by-step guides for showcasing Purple AI Sandbox to the software community.

---

## 📁 Contents

```
demo-showcase/
├── README.md              # This file
├── QUICK_START.md         # First-run commands
├── DEMO_GUIDE.md          # Step-by-step demonstration guide
├── policies/              # 10 real-world YAML policies
│   ├── 01-ai-code-assistant.yaml
│   ├── 02-ml-training-pipeline.yaml
│   ├── 03-web-scraper-agent.yaml
│   ├── 04-data-processing-agent.yaml
│   ├── 05-cicd-build-agent.yaml
│   ├── 06-llm-inference-server.yaml
│   ├── 07-security-scanner-agent.yaml
│   ├── 08-database-migration-agent.yaml
│   ├── 09-container-orchestrator.yaml
│   └── 10-minimal-sandbox.yaml
├── scripts/               # Demo test scripts
│   └── test-agents/       # Simple test programs
└── docs/                  # Additional documentation
```

---

## ⚡ Quick Start

```bash
# 1. Build Purple
cargo build --release

# 2. Copy a policy to the policies folder
sudo cp demo-showcase/policies/10-minimal-sandbox.yaml /etc/purple/policies/

# 3. Create a profile
./target/release/purple profile create minimal-sandbox

# 4. Run a command in the sandbox
./target/release/purple run --profile minimal-sandbox -- echo "Hello from Purple!"
```

---

## 🎯 Demo Scenarios

| # | Policy | Use Case | Security Level |
|---|--------|----------|----------------|
| 1 | AI Code Assistant | IDE code completion agents | 🟡 Medium |
| 2 | ML Training Pipeline | GPU/CPU-intensive ML jobs | 🟡 Medium |
| 3 | Web Scraper Agent | Controlled internet access | 🟢 Low |
| 4 | Data Processing Agent | ETL and data pipelines | 🟡 Medium |
| 5 | CI/CD Build Agent | Build and test automation | 🔴 High |
| 6 | LLM Inference Server | Model serving workloads | 🟡 Medium |
| 7 | Security Scanner Agent | Vulnerability scanning | 🔴 High |
| 8 | Database Migration Agent | Schema changes | 🔴 High |
| 9 | Container Orchestrator | Kubernetes-like workloads | 🔴 High |
| 10 | Minimal Sandbox | Maximum security demo | 🔴 Extreme |

---

## 📖 Documentation

- **[QUICK_START.md](QUICK_START.md)** - Build and first run
- **[DEMO_GUIDE.md](DEMO_GUIDE.md)** - Complete walkthrough

---

## 🛡️ What Purple Demonstrates

1. **Linux Namespace Isolation** - Process, user, mount, network
2. **Seccomp Syscall Filtering** - 450+ syscall control
3. **Cgroups Resource Limits** - CPU, memory, I/O
4. **Capability Dropping** - Least privilege enforcement
5. **Filesystem Isolation** - Read-only mounts, chroot
6. **Network Filtering** - Port-based access control
7. **Audit Logging** - Security event recording

---

Made with 💜 by the Purple Team
