#!/bin/bash
# run_all_demos.sh - Master script to run all Purple demos
# Usage: sudo ./run_all_demos.sh

set -e

PURPLE_BIN="./target/release/purple"
DEMO_DIR="./demo-showcase"
POLICY_DIR="$DEMO_DIR/policies"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

echo -e "${PURPLE}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                    🛡️  PURPLE DEMO SHOWCASE                    ║"
echo "║              Secure AI Agent Sandbox Demonstration            ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if Purple binary exists
if [ ! -f "$PURPLE_BIN" ]; then
    echo -e "${RED}Error: Purple binary not found. Please run 'cargo build --release' first.${NC}"
    exit 1
fi

# Check root privileges
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}Warning: Running without root. Some features may not work.${NC}"
    echo -e "${YELLOW}Consider running with: sudo $0${NC}"
    echo ""
fi

# Function to run a demo
run_demo() {
    local demo_num=$1
    local policy_name=$2
    local description=$3
    local command=$4
    
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}Demo $demo_num: $description${NC}"
    echo -e "${YELLOW}Policy: $policy_name${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    # Copy policy
    echo -e "📋 Loading policy..."
    cp "$POLICY_DIR/$policy_name.yaml" policies/ 2>/dev/null || true
    
    # Create profile
    echo -e "🔧 Creating profile..."
    $PURPLE_BIN profile create "$policy_name" 2>/dev/null || true
    
    # Run command
    echo -e "🚀 Executing in sandbox..."
    echo -e "${PURPLE}Command: $command${NC}"
    echo ""
    
    $PURPLE_BIN run --profile "$policy_name" -- $command || true
    
    echo ""
    read -p "Press Enter to continue to next demo..."
    echo ""
}

# Demo 1: Basic Identity Check (Minimal Sandbox)
run_demo 1 "10-minimal-sandbox" \
    "Maximum Security - Identity Check" \
    "id"

# Demo 2: Filesystem Isolation
run_demo 2 "10-minimal-sandbox" \
    "Filesystem Isolation - Limited View" \
    "ls -la /"

# Demo 3: Network Isolation (should fail)
run_demo 3 "10-minimal-sandbox" \
    "Network Isolation - Blocked Connection" \
    "ping -c 1 google.com"

# Demo 4: AI Code Assistant
run_demo 4 "01-ai-code-assistant" \
    "AI Code Assistant - Read Source Files" \
    "cat /etc/passwd"

# Demo 5: CI/CD Build Agent
run_demo 5 "05-cicd-build-agent" \
    "CI/CD Build Agent - Compiler Access" \
    "gcc --version"

# Demo 6: Data Processing
run_demo 6 "04-data-processing-agent" \
    "Data Processing - File Operations" \
    "sh -c 'echo test > /tmp/test.txt && cat /tmp/test.txt'"

# Demo 7: Web Scraper (Network Allowed)
run_demo 7 "03-web-scraper-agent" \
    "Web Scraper - Controlled Network" \
    "curl -s https://httpbin.org/ip"

# Demo 8: Dangerous Syscall Blocked
run_demo 8 "10-minimal-sandbox" \
    "Syscall Filter - Mount Blocked" \
    "mount /dev/sda1 /mnt"

# Demo 9: Resource Limits Display
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}Demo 9: Resource Limits${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Minimal Sandbox Resource Limits:"
echo "  • CPU: 10%"
echo "  • Memory: 256MB"
echo "  • PIDs: 5"
echo "  • I/O: 10MBps"
echo "  • Timeout: 60s"
echo ""

# Demo 10: Profile Listing
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}Demo 10: Profile Management${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
$PURPLE_BIN profile list
echo ""

echo -e "${PURPLE}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                    🎉 DEMO COMPLETE!                          ║"
echo "║                                                               ║"
echo "║  Purple provides enterprise-grade security for AI agents      ║"
echo "║  with multiple isolation layers and comprehensive controls.   ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
