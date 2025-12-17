# ⚡ Purple Quick Start Guide

## Prerequisites

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y build-essential libseccomp-dev pkg-config

# Fedora/RHEL
sudo dnf install -y gcc libseccomp-devel pkg-config

# Arch Linux
sudo pacman -S base-devel libseccomp
```

---

## 🔧 Build Purple

```bash
# Clone the repository
git clone https://github.com/your-org/purple.git
cd purple

# Build release binary
cargo build --release

# Verify the build
./target/release/purple --help
```

**Expected Output:**
```
Purple - AI Agent Sandbox

Usage: purple [OPTIONS] <COMMAND>

Commands:
  profile  Manage sandbox profiles
  run      Run a command in a sandbox
  help     Print this message or the help of the given subcommand(s)

Options:
  -l, --log-level <LEVEL>  Set log level [default: info]
  -h, --help               Print help
  -V, --version            Print version
```

---

## 📋 Profile Management

### List all profiles
```bash
./target/release/purple profile list
```

### Create a profile from YAML
```bash
# First, copy your policy file
cp demo-showcase/policies/10-minimal-sandbox.yaml policies/

# Create the profile
./target/release/purple profile create minimal-sandbox
```

### Show profile details
```bash
./target/release/purple profile show minimal-sandbox
```

### Delete a profile
```bash
./target/release/purple profile delete minimal-sandbox
```

---

## 🚀 Running Commands in Sandbox

### Basic execution
```bash
./target/release/purple run --profile minimal-sandbox -- echo "Hello, Purple!"
```

### With debug logging
```bash
./target/release/purple -l debug run --profile minimal-sandbox -- ls -la
```

### Run a Python script
```bash
./target/release/purple run --profile ai-code-assistant -- python3 script.py
```

### Run with trace logging (for demos)
```bash
./target/release/purple -l trace run --profile minimal-sandbox -- whoami
```

---

## 🔐 Root Privileges

Some features require root:

```bash
# Full functionality
sudo ./target/release/purple run --profile minimal-sandbox -- echo "Secure!"

# Or enable unprivileged user namespaces
sudo sysctl -w kernel.unprivileged_userns_clone=1
```

---

## 🎯 Quick Demo Commands

```bash
# Demo 1: Basic isolation
sudo ./target/release/purple run --profile minimal-sandbox -- id

# Demo 2: Filesystem isolation
sudo ./target/release/purple run --profile minimal-sandbox -- ls /

# Demo 3: Network isolation
sudo ./target/release/purple run --profile minimal-sandbox -- ping -c 1 google.com

# Demo 4: Resource limits
sudo ./target/release/purple run --profile ml-training-pipeline -- stress --cpu 8 --timeout 5

# Demo 5: Syscall filtering (will be blocked)
sudo ./target/release/purple run --profile minimal-sandbox -- mount /dev/sda1 /mnt
```

---

## ⚠️ Troubleshooting

| Error | Solution |
|-------|----------|
| `Operation not permitted` | Run with `sudo` or enable user namespaces |
| `Policy not found` | Copy YAML to `policies/` folder first |
| `libseccomp not found` | Install `libseccomp-dev` |
| `Cgroup error` | Ensure cgroups v2 is mounted |

---

## Next Steps

→ See **[DEMO_GUIDE.md](DEMO_GUIDE.md)** for the complete demonstration walkthrough
