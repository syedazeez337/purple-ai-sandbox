#!/bin/bash

# Test script to verify all Purple AI Agent Sandbox profiles
# This recreates the test results shown in the documentation

echo "========================================================================"
echo "Purple AI Agent Sandbox - Profile Test Suite"
echo "========================================================================"
echo ""

# Array of all profiles to test
PROFILES=(
    "01-ai-code-assistant"
    "02-ml-training-pipeline"
    "03-web-scraper-agent"
    "04-data-processing-agent"
    "05-cicd-build-agent"
    "06-llm-inference-server"
    "07-security-scanner-agent"
    "08-database-migration-agent"
    "09-container-orchestrator"
    "10-minimal-sandbox"
    "ai-dev-safe"
)

PASSED=0
FAILED=0
TOTAL=${#PROFILES[@]}

echo "Test Results: All $TOTAL Profiles"
echo ""

for PROFILE in "${PROFILES[@]}"; do
    echo -n "  $PROFILE"
    
    # First try without sudo (for user namespaces if enabled)
    OUTPUT=$(./target/release/purple run --profile "$PROFILE" -- /bin/echo "Hello" 2>&1)
    EXIT_CODE=$?
    
    if [ $EXIT_CODE -eq 0 ]; then
        # Check if the command actually succeeded (output contains "Hello")
        if echo "$OUTPUT" | grep -q "Hello"; then
            echo "     ✓ ${PROFILE//-/_}-OK"
            PASSED=$((PASSED + 1))
        else
            echo "     ✗ ${PROFILE//-/_}-FAIL (no expected output)"
            FAILED=$((FAILED + 1))
            echo "$OUTPUT" | tail -3
        fi
    else
        # If it fails, try with sudo (but only if we're in a terminal)
        if [ -t 0 ]; then
            echo "     Trying with sudo..."
            OUTPUT=$(sudo ./target/release/purple run --profile "$PROFILE" -- /bin/echo "Hello" 2>&1)
            EXIT_CODE=$?
            
            if [ $EXIT_CODE -eq 0 ] && echo "$OUTPUT" | grep -q "Hello"; then
                echo "     ✓ ${PROFILE//-/_}-OK (with sudo)"
                PASSED=$((PASSED + 1))
            else
                echo "     ✗ ${PROFILE//-/_}-FAIL (exit code: $EXIT_CODE)"
                FAILED=$((FAILED + 1))
                echo "$OUTPUT" | tail -3
            fi
        else
            echo "     ✗ ${PROFILE//-/_}-FAIL (exit code: $EXIT_CODE)"
            FAILED=$((FAILED + 1))
            echo "$OUTPUT" | tail -3
        fi
    fi
done

echo ""
echo "========================================================================"
echo "Summary"
echo "========================================================================"
echo "Total Profiles: $TOTAL"
echo "Passed: $PASSED"
echo "Failed: $FAILED"
echo ""

if [ $FAILED -eq 0 ]; then
    echo "🎉 All profiles passed!"
    exit 0
else
    echo "❌ Some profiles failed"
    exit 1
fi