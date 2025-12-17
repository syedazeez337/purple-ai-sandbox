#!/bin/bash
# security_test.sh - Demonstrates security controls

echo "🛡️ Security Controls Test"
echo "=========================="
echo ""

echo "1. Identity Check"
echo "   Current user: $(whoami)"
echo "   UID: $(id -u)"
echo "   GID: $(id -g)"
echo ""

echo "2. Capabilities Check"
echo "   Capabilities: $(cat /proc/self/status | grep -i cap || echo 'N/A')"
echo ""

echo "3. Namespace Check"
echo "   PID namespace: $(ls -la /proc/1/ns/pid 2>/dev/null || echo 'Isolated')"
echo ""

echo "4. Filesystem Boundaries"
echo "   Root contents:"
ls -la / 2>/dev/null | head -10
echo ""

echo "5. Testing Dangerous Operations..."

# Try mount (should fail)
echo "   Attempting mount..."
mount /dev/null /tmp 2>&1 && echo "   ⚠️ MOUNT SUCCEEDED" || echo "   ✅ mount blocked"

# Try reboot (should fail)
echo "   Attempting reboot..."
reboot 2>&1 && echo "   ⚠️ REBOOT SUCCEEDED" || echo "   ✅ reboot blocked"

# Try network
echo "   Attempting network..."
ping -c 1 8.8.8.8 2>&1 >/dev/null && echo "   ℹ️ Network available" || echo "   ✅ Network isolated"

echo ""
echo "✨ Security test complete"
