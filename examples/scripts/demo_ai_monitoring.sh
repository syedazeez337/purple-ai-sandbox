#!/bin/bash

# Purple AI Monitoring Demo Script
# This script demonstrates the core AI monitoring capabilities

echo "🎬 Purple AI Monitoring Demo"
echo "================================"
echo ""

# Step 1: Show the AI policy
 echo "📋 Step 1: AI Policy Configuration"
echo "-----------------------------------"
cat examples/policies/simple-ai-test.yaml | grep -A 20 "ai_policy:"
echo ""

# Step 2: Show the AI agent
 echo "🤖 Step 2: AI Agent Code"
echo "-------------------------"
head -20 examples/scripts/simple_ai_agent.py
echo ""

# Step 3: Run the AI agent with monitoring
echo "🚀 Step 3: Running AI Agent with Monitoring"
echo "------------------------------------------"
echo "Running: purple run --profile simple-ai-test -- python3 examples/scripts/simple_ai_agent.py"
echo ""

# Check if we can run the purple command
if [ -f "target/release/purple" ]; then
    # Run with a timeout to prevent hanging
    timeout 10 ./target/release/purple run --profile simple-ai-test -- python3 examples/scripts/simple_ai_agent.py
else
    echo "⚠️  Purple binary not found. Please build first:"
    echo "   cargo build --release"
    echo ""
    echo "🎯 What would happen if we ran it:"
    echo "   ✅ AI agent would execute in sandbox"
    echo "   ✅ All API calls would be monitored"
    echo "   ✅ Budget limits would be enforced"
    echo "   ✅ Usage statistics would be tracked"
    echo "   ✅ Comprehensive logging would be available"
fi

echo ""
echo "📊 Step 4: Expected Results"
echo "----------------------------"
echo "✅ AI Agent Summary:"
echo "   - Total API calls: 5"
echo "   - Total tokens used: ~820"
echo "   - Total cost: ~$0.41"
echo "   - Average cost per call: ~$0.08"
echo ""
echo "✅ AI Monitoring Features:"
echo "   - Budget enforcement: Active (10K tokens, $5.00 limit)"
echo "   - Token tracking: Enabled"
echo "   - Cost tracking: Enabled"
echo "   - Privacy protection: No prompt/response logging"
echo ""

echo "🎯 Step 5: Market Validation"
echo "------------------------------"
echo "This demo shows how Purple can:"
echo "1. 🔒 Monitor AI agent API calls"
echo "2. 💰 Enforce budget limits"
echo "3. 📊 Track usage statistics"
echo "4. 🛡️  Protect privacy"
echo "5. 🚀 Provide production-ready monitoring"
echo ""

echo "💡 Potential Market Applications:"
echo "- AI development environments"
echo "- LLM API cost control"
echo "- AI agent monitoring"
echo "- Budget enforcement for AI teams"
echo "- Compliance and auditing"
echo ""

echo "✅ Demo completed!"
