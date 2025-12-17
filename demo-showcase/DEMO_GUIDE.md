# 📖 Purple AI Sandbox - Complete Demo Guide

**Step-by-step walkthrough for showcasing Purple to the community**

---

## Table of Contents

1. [Setup](#-setup)
2. [Demo 1: Basic Sandbox Execution](#-demo-1-basic-sandbox-execution)
3. [Demo 2: Filesystem Isolation](#-demo-2-filesystem-isolation)
4. [Demo 3: Network Isolation](#-demo-3-network-isolation)
5. [Demo 4: Syscall Filtering](#-demo-4-syscall-filtering)
6. [Demo 5: Resource Limits](#-demo-5-resource-limits)
7. [Demo 6: Multi-Profile Comparison](#-demo-6-multi-profile-comparison)
8. [Demo 7: Python Agent Execution](#-demo-7-python-agent-execution)
9. [Demo 8: Audit Logging](#-demo-8-audit-logging)
10. [Demo 9: Security Attack Prevention](#-demo-9-security-attack-prevention)
11. [Demo 10: Production Workflow](#-demo-10-production-workflow)
12. [Troubleshooting](#-troubleshooting)

---

## 🔧 Setup

### Step 1: Transfer to Linux System

```bash
# Copy the demo-showcase folder to your Linux machine
scp -r demo-showcase/ user@linux-host:~/purple/

# Or use git
git clone https://github.com/your-org/purple.git
cd purple
```

### Step 2: Install Dependencies

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y build-essential libseccomp-dev pkg-config curl

# Fedora/RHEL
sudo dnf install -y gcc libseccomp-devel pkg-config curl

# Arch
sudo pacman -S base-devel libseccomp
```

### Step 3: Build Purple

```bash
# Build release binary
cargo build --release

# Verify build
./target/release/purple --version
```

**Expected Output:**
```
purple 0.1.0
```

### Step 4: Create Output Directories

```bash
mkdir -p output/{ai-code-assistant,ml-training,scraped-data,processed-data}
mkdir -p output/{build-artifacts,test-results,inference-logs,security-reports}
mkdir -p output/{migration-logs,orchestrator-logs}
sudo mkdir -p /var/log/purple
```

### Step 5: Copy Policies

```bash
cp demo-showcase/policies/*.yaml policies/
```

---

## 🚀 Demo 1: Basic Sandbox Execution

**Goal:** Show that commands run in an isolated environment

### Commands

```bash
# Create the minimal profile
./target/release/purple profile create minimal-sandbox

# Run basic identity check
sudo ./target/release/purple run --profile minimal-sandbox -- id
```

### Expected Output

```
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
```

### Key Points to Highlight

- ✅ User is mapped to `nobody` (unprivileged)
- ✅ No access to host user's groups
- ✅ Process runs with minimal identity

---

## 📁 Demo 2: Filesystem Isolation

**Goal:** Show that the sandbox has limited filesystem view

### Commands

```bash
# List root filesystem in sandbox
sudo ./target/release/purple run --profile minimal-sandbox -- ls -la /

# Try to access host-specific paths
sudo ./target/release/purple run --profile minimal-sandbox -- cat /etc/shadow
```

### Expected Output

```
# ls -la / shows only allowed paths:
drwxr-xr-x  /lib
drwxr-xr-x  /lib64
drwxr-xr-x  /usr
drwxrwxrwt  /tmp
drwxr-xr-x  /bin

# cat /etc/shadow fails:
cat: /etc/shadow: No such file or directory
```

### Key Points

- ✅ Only explicitly mounted paths are visible
- ✅ Sensitive files are not accessible
- ✅ Temporary directories available for scratch work

---

## 🌐 Demo 3: Network Isolation

**Goal:** Demonstrate network access control

### Commands

```bash
# Minimal sandbox - network isolated
sudo ./target/release/purple run --profile minimal-sandbox -- ping -c 1 google.com

# Web scraper - network allowed
./target/release/purple profile create web-scraper-agent
sudo ./target/release/purple run --profile web-scraper-agent -- curl -s https://httpbin.org/ip
```

### Expected Output

```
# Minimal sandbox (blocked):
ping: socket: Operation not permitted

# Web scraper (allowed):
{
  "origin": "203.0.113.42"
}
```

### Key Points

- ✅ Network can be completely isolated
- ✅ Selective port allowlisting (443, 80, 53)
- ✅ Incoming connections blocked by default

---

## 🔒 Demo 4: Syscall Filtering

**Goal:** Show that dangerous syscalls are blocked

### Commands

```bash
# Try to mount (blocked)
sudo ./target/release/purple run --profile minimal-sandbox -- mount /dev/sda1 /mnt

# Try to load kernel module (blocked)
sudo ./target/release/purple run --profile minimal-sandbox -- insmod test.ko

# Show allowed syscalls work
sudo ./target/release/purple run --profile minimal-sandbox -- echo "Hello, secure world!"
```

### Expected Output

```
# mount (blocked):
mount: /mnt: operation not permitted.

# insmod (blocked):
insmod: ERROR: could not insert module: Operation not permitted

# echo (allowed):
Hello, secure world!
```

### Key Points

- ✅ 450+ syscalls can be controlled
- ✅ Default-deny security model
- ✅ Fine-grained allow/deny lists

---

## 📊 Demo 5: Resource Limits

**Goal:** Show cgroups resource enforcement

### Commands

```bash
# Create ML training profile with high resources
./target/release/purple profile create ml-training-pipeline

# Show profile resource limits
./target/release/purple profile show ml-training-pipeline

# Create minimal profile (very restricted)
./target/release/purple profile show minimal-sandbox
```

### Expected Output

```
Profile: ml-training-pipeline
  CPU: 90%
  Memory: 32GB
  PIDs: 500
  I/O: 500MBps

Profile: minimal-sandbox
  CPU: 10%
  Memory: 256MB
  PIDs: 5
  I/O: 10MBps
  Timeout: 60s
```

### Key Points

- ✅ CPU shares limit usage
- ✅ Memory limits prevent exhaustion
- ✅ PID limits prevent fork bombs
- ✅ Automatic timeouts for runaway processes

---

## 🎭 Demo 6: Multi-Profile Comparison

**Goal:** Show different security profiles for different use cases

### Commands

```bash
# Create all profiles
for policy in demo-showcase/policies/*.yaml; do
  name=$(basename "$policy" .yaml)
  ./target/release/purple profile create "$name" 2>/dev/null
done

# List all profiles
./target/release/purple profile list
```

### Expected Output

```
Available Profiles:
  01-ai-code-assistant       - IDE code completion agents
  02-ml-training-pipeline    - Deep learning training
  03-web-scraper-agent       - Controlled web access
  04-data-processing-agent   - ETL pipelines
  05-cicd-build-agent        - Build automation
  06-llm-inference-server    - Model serving
  07-security-scanner-agent  - Vulnerability scanning
  08-database-migration-agent - Schema migrations
  09-container-orchestrator  - Kubernetes operators
  10-minimal-sandbox         - Maximum security
```

### Key Points

- ✅ One profile per use case
- ✅ Policies are declarative YAML
- ✅ Easy to create, share, audit

---

## 🐍 Demo 7: Python Agent Execution

**Goal:** Run a real Python agent in the sandbox

### Commands

```bash
# Create AI code assistant profile
./target/release/purple profile create ai-code-assistant

# Run Python test agent
sudo ./target/release/purple run --profile ai-code-assistant -- \
  python3 demo-showcase/scripts/test-agents/ai_code_assistant.py
```

### Expected Output

```
🤖 AI Code Assistant Agent
========================================

📍 Environment:
  Working Dir: /home/agent
  User ID: 65534
  Group ID: 65534

📖 Attempting to read source files...
  ✅ Read 100 bytes from /usr/bin/env

📝 Attempting to write files...
  ✅ Write to /tmp succeeded
  ✅ Write to /etc blocked: PermissionError

✨ Agent execution complete
```

### Key Points

- ✅ Python interpreter works in sandbox
- ✅ Read access to immutable paths
- ✅ Write restricted to scratch paths

---

## 📋 Demo 8: Audit Logging

**Goal:** Show comprehensive security logging

### Commands

```bash
# Run with trace logging
sudo ./target/release/purple -l trace run --profile minimal-sandbox -- id

# Check audit logs
sudo cat /var/log/purple/minimal-sandbox.log
```

### Expected Output

```
[TRACE] Sandbox: Setting up namespaces...
[TRACE] Sandbox: Created user namespace
[TRACE] Sandbox: Created PID namespace
[TRACE] Sandbox: Setting up filesystem...
[TRACE] Sandbox: Mounted /lib (read-only)
[TRACE] Sandbox: Mounted /tmp (read-write)
[TRACE] Sandbox: Applying seccomp filter...
[TRACE] Sandbox: Allowed 32 syscalls
[TRACE] Sandbox: Executing: id
[TRACE] Sandbox: Process exited with code 0
[TRACE] Sandbox: Cleanup complete
```

### Key Points

- ✅ Every security action logged
- ✅ Configurable log levels
- ✅ Audit trail for compliance

---

## ⚔️ Demo 9: Security Attack Prevention

**Goal:** Show Purple blocking common attack vectors

### Commands

```bash
# Run security test script
sudo ./target/release/purple run --profile minimal-sandbox -- \
  bash demo-showcase/scripts/test-agents/security_test.sh
```

### Expected Output

```
🛡️ Security Controls Test
==========================

1. Identity Check
   Current user: nobody
   UID: 65534

2. Testing Dangerous Operations...
   ✅ mount blocked
   ✅ reboot blocked
   ✅ Network isolated

✨ Security test complete
```

### Attack Vectors Blocked

| Attack | Protection |
|--------|------------|
| Privilege escalation | Capability dropping |
| Container escape | Namespace isolation |
| Fork bomb | PID limits |
| Memory exhaustion | Memory limits |
| Disk filling | I/O limits |
| Network exfiltration | Network isolation |
| Syscall exploits | Seccomp filtering |

---

## 🏭 Demo 10: Production Workflow

**Goal:** Show a complete production deployment workflow

### Commands

```bash
# Step 1: Validate policy
cat demo-showcase/policies/05-cicd-build-agent.yaml

# Step 2: Create profile
./target/release/purple profile create cicd-build-agent

# Step 3: Test with simple command
sudo ./target/release/purple run --profile cicd-build-agent -- gcc --version

# Step 4: Run actual build
sudo ./target/release/purple run --profile cicd-build-agent -- \
  sh -c "echo 'int main() { return 0; }' > /tmp/test.c && gcc /tmp/test.c -o /tmp/test"

# Step 5: Verify
sudo ./target/release/purple run --profile cicd-build-agent -- /tmp/test && echo "Build successful!"
```

### Expected Output

```
gcc (GCC) 11.4.0
...
Build successful!
```

---

## 🐛 Troubleshooting

### "Operation not permitted"

```bash
# Enable user namespaces
sudo sysctl -w kernel.unprivileged_userns_clone=1

# Or run as root
sudo ./target/release/purple run --profile minimal-sandbox -- id
```

### "Policy not found"

```bash
# Ensure policy is in policies/ folder
ls policies/
cp demo-showcase/policies/minimal-sandbox.yaml policies/
```

### "libseccomp not found"

```bash
# Ubuntu/Debian
sudo apt-get install libseccomp-dev

# Check pkg-config
pkg-config --libs libseccomp
```

### "Cgroup errors"

```bash
# Mount cgroups v2
sudo mount -t cgroup2 none /sys/fs/cgroup

# Check cgroup version
cat /proc/filesystems | grep cgroup
```

---

## 🎬 Recording a Demo Video

```bash
# Install asciinema
pip install asciinema

# Record demo
asciinema rec purple-demo.cast

# Run the demo script
sudo bash demo-showcase/scripts/run_all_demos.sh

# Stop recording
exit

# Upload (optional)
asciinema upload purple-demo.cast
```

---

## 📤 Sharing Results

### Screenshots to Capture

1. `purple --help` output
2. Profile list showing all 10 scenarios
3. Blocked `mount` command
4. Network isolation demo
5. Python agent execution
6. Trace logging output

### Key Messages for Community

- "Enterprise-grade security for AI agents"
- "Defense-in-depth with 7 isolation layers"
- "Declarative YAML policies"
- "Production-ready architecture"
- "Open source under MIT license"

---

**Happy demoing! 🚀**

Made with 💜 by the Purple Team
