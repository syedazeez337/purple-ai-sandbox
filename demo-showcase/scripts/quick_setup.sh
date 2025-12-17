#!/bin/bash
# quick_setup.sh - One-command setup for Purple demos
# Usage: bash quick_setup.sh

set -e

echo "🛡️ Purple AI Sandbox - Quick Setup"
echo "===================================="
echo ""

# Check if we're on Linux
if [ "$(uname)" != "Linux" ]; then
    echo "❌ Error: Purple requires Linux. You're on $(uname)."
    echo "   Use WSL2 or a Linux VM."
    exit 1
fi

# Check dependencies
echo "📦 Checking dependencies..."

if ! command -v cargo &> /dev/null; then
    echo "❌ Rust not found. Installing..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source $HOME/.cargo/env
fi

if ! pkg-config --exists libseccomp 2>/dev/null; then
    echo "❌ libseccomp not found. Installing..."
    if command -v apt-get &> /dev/null; then
        sudo apt-get update && sudo apt-get install -y libseccomp-dev pkg-config
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y libseccomp-devel pkg-config
    elif command -v pacman &> /dev/null; then
        sudo pacman -S --noconfirm libseccomp
    else
        echo "Please install libseccomp manually"
        exit 1
    fi
fi

echo "✅ Dependencies OK"
echo ""

# Build Purple
echo "🔧 Building Purple..."
cargo build --release
echo "✅ Build complete"
echo ""

# Create directories
echo "📁 Creating directories..."
mkdir -p output/{ai-code-assistant,ml-training,scraped-data,processed-data}
mkdir -p output/{build-artifacts,test-results,inference-logs,security-reports}
mkdir -p output/{migration-logs,orchestrator-logs}
sudo mkdir -p /var/log/purple
echo "✅ Directories created"
echo ""

# Copy policies
echo "📋 Loading policies..."
cp demo-showcase/policies/*.yaml policies/
echo "✅ Policies loaded"
echo ""

# Create profiles
echo "🔧 Creating profiles..."
for policy in policies/*.yaml; do
    name=$(basename "$policy" .yaml)
    ./target/release/purple profile create "$name" 2>/dev/null || true
done
echo "✅ Profiles created"
echo ""

# Test
echo "🧪 Quick test..."
sudo ./target/release/purple run --profile 10-minimal-sandbox -- echo "Purple is working!" || {
    echo "⚠️ Test failed. Try: sudo sysctl -w kernel.unprivileged_userns_clone=1"
}
echo ""

echo "🎉 Setup complete!"
echo ""
echo "Next steps:"
echo "  1. Run demos:     sudo bash demo-showcase/scripts/run_all_demos.sh"
echo "  2. View guide:    cat demo-showcase/DEMO_GUIDE.md"
echo "  3. List profiles: ./target/release/purple profile list"
