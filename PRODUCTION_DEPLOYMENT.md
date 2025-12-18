# Purple AI Agent Sandbox - Production Deployment Guide

## 🚀 Overview

This guide provides comprehensive instructions for deploying the Purple AI Agent Sandbox in production environments. It covers system requirements, security considerations, performance tuning, and troubleshooting.

## 📋 System Requirements

### Minimum Requirements
- **OS**: Linux (kernel 5.4+ recommended)
- **CPU**: 2+ cores
- **RAM**: 4GB+ (8GB+ recommended for AI workloads)
- **Disk**: 10GB+ free space
- **Architecture**: x86_64

### Kernel Configuration

#### Required Kernel Features
```bash
# Check kernel version
uname -r

# Required kernel features:
# - User namespaces (CONFIG_USER_NS)
# - PID namespaces (CONFIG_PID_NS)
# - Network namespaces (CONFIG_NET_NS)
# - Mount namespaces (CONFIG_MNT_NS)
# - Seccomp filtering (CONFIG_SECCOMP)
# - Cgroups v2 (CONFIG_CGROUP)

# Enable user namespaces (if not already enabled)
sudo sysctl -w kernel.unprivileged_userns_clone=1

# Make persistent across reboots
echo "kernel.unprivileged_userns_clone=1" | sudo tee -a /etc/sysctl.conf
```

### Required Packages

#### Fedora/RHEL/CentOS
```bash
# Install required packages
sudo dnf install -y \
    libseccomp-devel \
    gcc \
    make \
    git \
    cargo

# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

#### Debian/Ubuntu
```bash
# Install required packages
sudo apt-get update
sudo apt-get install -y \
    libseccomp-dev \
    build-essential \
    git \
    cargo

# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

## 🛡️ Security Configuration

### Filesystem Permissions

```bash
# Create sandbox directory
sudo mkdir -p /tmp/purple-sandbox
sudo chmod 777 /tmp/purple-sandbox

# Create output directories
sudo mkdir -p /var/output/ai-strict
sudo chmod 777 /var/output/ai-strict

# Create log directory
sudo mkdir -p /var/log/purple
sudo chmod 777 /var/log/purple
```

### Cgroup Configuration

```bash
# Ensure cgroup2 is mounted
mount | grep cgroup

# If not mounted, mount cgroup2
sudo mount -t cgroup2 none /sys/fs/cgroup

# Make persistent (add to /etc/fstab)
echo "cgroup2 /sys/fs/cgroup cgroup2 rw,nosuid,nodev,noexec,relatime 0 0" | sudo tee -a /etc/fstab
```

### Network Configuration

```bash
# For network isolation, ensure iptables/nftables is available
sudo dnf install -y iptables nftables  # Fedora/RHEL
sudo apt-get install -y iptables nftables  # Debian/Ubuntu
```

## 📦 Deployment

### Building from Source

```bash
# Clone the repository
git clone https://github.com/your-org/purple.git
cd purple

# Build in release mode
cargo build --release

# Install (optional)
sudo cp target/release/purple /usr/local/bin/
```

### Configuration Files

#### Policy Files
Policy files are located in the `policies/` directory:
- `ai-dev-safe.yaml` - Development profile with safe defaults
- `ai-strict.yaml` - Production profile with strict security

#### Creating Custom Policies

```yaml
# Example custom policy
name: "custom-profile"
description: "Custom security policy for production AI agents"

filesystem:
  immutable_paths:
    - host_path: "/usr/bin"
      sandbox_path: "/usr/bin"
    - host_path: "/lib"
      sandbox_path: "/lib"
    - host_path: "/lib64"
      sandbox_path: "/lib64"
  scratch_paths:
    - "/tmp"
    - "/var/tmp"
  output_paths:
    - host_path: "/var/output/custom"
      sandbox_path: "/output"
  working_dir: "/tmp"

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
  log_path: "/var/log/purple/custom.log"
  detail_level:
    - "syscall"
    - "filesystem"
    - "resource"
```

### Running the Sandbox

```bash
# List available profiles
purple profile list

# Show profile details
purple profile show ai-dev-safe

# Run an AI agent with a profile
purple run --profile ai-dev-safe -- python3 ai_agent.py

# Run with debug logging
purple -l debug run --profile ai-dev-safe -- python3 ai_agent.py
```

## 🔧 Production Configuration

### Systemd Service

```ini
# /etc/systemd/system/purple-sandbox.service
[Unit]
Description=Purple AI Agent Sandbox Service
After=network.target

[Service]
User=purple
Group=purple
ExecStart=/usr/local/bin/purple run --profile ai-strict -- python3 /opt/ai/agent.py
Restart=always
RestartSec=5
Environment="RUST_LOG=info"
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

### Logging Configuration

```bash
# Configure log rotation
sudo tee /etc/logrotate.d/purple << EOF
/var/log/purple/*.log {
    daily
    rotate 30
    compress
    missingok
    notifempty
    create 0644 purple purple
}
EOF
```

## 📊 Performance Tuning

### Cgroup Tuning

```bash
# Adjust CPU shares
sudo echo 2048 > /sys/fs/cgroup/purple/cpu.shares

# Set memory limits
sudo echo 2147483648 > /sys/fs/cgroup/purple/memory.max

# Limit processes
sudo echo 100 > /sys/fs/cgroup/purple/pids.max
```

### Syscall Filtering Optimization

```yaml
# For performance-critical workloads, allow only essential syscalls
syscalls:
  default_deny: true
  allow:
    - "read"
    - "write"
    - "openat"
    - "close"
    - "execve"
    - "exit_group"
```

## 🛡️ Security Best Practices

### 1. Principle of Least Privilege
- Use `default_drop: true` for capabilities
- Only allow essential syscalls
- Minimize filesystem access

### 2. Network Isolation
- Use `isolated: true` for sensitive workloads
- Restrict outgoing connections to only necessary ports
- Block all incoming connections by default

### 3. Resource Limits
- Set appropriate CPU and memory limits
- Limit process creation (pids_limit)
- Configure session timeouts

### 4. Audit Logging
- Enable audit logging for all production workloads
- Monitor audit logs regularly
- Set up alerts for suspicious activity

## 🔍 Monitoring and Maintenance

### Monitoring Commands

```bash
# Check sandbox processes
ps aux | grep purple

# Monitor resource usage
top -c -p $(pgrep -d',' -f purple)

# Check cgroup usage
cat /sys/fs/cgroup/purple/cpu.stat
cat /sys/fs/cgroup/purple/memory.current

# Monitor logs
tail -f /var/log/purple/*.log
```

### Common Issues and Solutions

#### Permission Errors

**Error**: `Permission denied` when creating cgroups

**Solution**:
```bash
sudo sysctl -w kernel.unprivileged_userns_clone=1
sudo chmod 777 /sys/fs/cgroup/purple
```

#### Syscall Violations

**Error**: Process killed by SIGSYS

**Solution**:
```bash
# Check which syscall was blocked
dmesg | grep seccomp

# Add the required syscall to the policy
# Edit policies/your-profile.yaml and add the syscall to the allow list
```

#### Network Connectivity Issues

**Error**: DNS resolution fails

**Solution**:
```bash
# Check DNS configuration in sandbox
purple run --profile ai-dev-safe -- cat /etc/resolv.conf

# Ensure DNS servers are reachable
ping 8.8.8.8
```

## 📚 Additional Resources

- **Seccomp Documentation**: https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html
- **Cgroups v2 Documentation**: https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html
- **Linux Namespaces**: https://man7.org/linux/man-pages/man7/namespaces.7.html
- **Capability Documentation**: https://man7.org/linux/man-pages/man7/capabilities.7.html

## 🤝 Support

For issues, questions, or contributions:
- **GitHub Issues**: https://github.com/your-org/purple/issues
- **Documentation**: https://github.com/your-org/purple/wiki
- **Community**: Join our Discord/Slack community

## 📜 License

This software is licensed under the MIT License. See the LICENSE file for details.

---

**Production Checklist**

- [ ] System requirements met
- [ ] Kernel configuration verified
- [ ] Required packages installed
- [ ] Filesystem permissions configured
- [ ] Cgroup setup completed
- [ ] Network configuration verified
- [ ] Policies reviewed and customized
- [ ] Monitoring and logging configured
- [ ] Security audit completed
- [ ] Backup and recovery plan in place

**Get Started Today!**

```bash
# Quick start
sudo sysctl -w kernel.unprivileged_userns_clone=1
cargo build --release
./target/release/purple run --profile ai-dev-safe -- python3 ai_agent.py
```