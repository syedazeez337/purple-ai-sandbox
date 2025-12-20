#!/bin/bash
set -e

echo "=== Purple: Real World Active Defense Test ==="

# 1. Prereqs (Skipping explicit bpf-linker install, relying on build system)

# 2. Build
echo "Building project and eBPF probes..."
cargo build --features ebpf

# 3. Setup Test Environment
echo "Setting up test environment..."
# Create a dedicated directory for the script to avoid bind mount issues
mkdir -p /tmp/purple_test_scripts
cp examples/scripts/risky_agent.py /tmp/purple_test_scripts/risky_agent.py

# 4. Run Test
echo "Running Risky Agent under 'active-defense' policy..."
echo "---------------------------------------------------"
# We need sudo for eBPF and Namespaces
# -l debug to see eBPF map updates
sudo ./target/debug/purple -l debug run --profile active-defense -- python3 -u /scripts/risky_agent.py > test_output.log 2>&1 || true

# 5. Analyze Results
echo "---------------------------------------------------"
cat test_output.log
echo "---------------------------------------------------"

echo "=== Verification ==="

# Check Network Block
if grep -q "Connection BLOCKED/FAILED" test_output.log; then
    echo "✅ Network Defense: SUCCESS (Blocked 1.1.1.1)"
else
    echo "❌ Network Defense: FAILED (Connection allowed or script failed unexpectedly)"
fi

# Check Resource Defense (Memory Limit)
# The script asks for 300MB, policy is 200MB. It should fail or be killed.
if grep -q "Allocation BLOCKED" test_output.log || grep -q "Killed" test_output.log || grep -q "MemoryError" test_output.log || grep -q "Signaled.*SIGKILL" test_output.log; then
    echo "✅ Resource Defense: SUCCESS (Memory limit enforced - Process Killed)"
else
    echo "❌ Resource Defense: FAILED (Allocation succeeded or no kill detected)"
fi

# Check Filesystem (Passive defense via permissions/mounts)
# /etc/shadow is not mounted in the sandbox, so it shouldn't exist.
if grep -q "Read BLOCKED" test_output.log; then
    echo "✅ Filesystem Defense: SUCCESS (/etc/shadow access denied)"
else
    echo "❌ Filesystem Defense: FAILED (Read succeeded?)"
fi

echo "=== Test Complete ==="
