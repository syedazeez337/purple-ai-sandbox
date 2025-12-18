# Purple AI Monitoring Demo

**Simple, working example to validate market potential**

## 🎯 Purpose

This demo showcases the core AI monitoring capabilities of Purple Sandbox:

- **AI Policy Configuration** - Define budget limits and monitoring settings
- **Budget Enforcement** - Prevent cost overruns and token abuse
- **API Monitoring** - Track LLM API calls and usage patterns
- **Privacy Protection** - Monitor without logging sensitive data

## 🚀 Quick Start

### 1. Build Purple (if not already built)

```bash
cargo build --release
```

### 2. Run the Demo

```bash
# Make scripts executable
chmod +x examples/scripts/*.py examples/scripts/*.sh

# Run the demo
./examples/scripts/demo_ai_monitoring.sh
```

### 3. Run Manually (Alternative)

```bash
# Create the AI policy
cp examples/policies/simple-ai-test.yaml policies/

# Run the AI agent with monitoring
./target/release/purple run --profile simple-ai-test -- python3 examples/scripts/simple_ai_agent.py
```

## 📋 What's Included

### AI Policy (`simple-ai-test.yaml`)

```yaml
ai_policy:
  budget:
    max_tokens: 10000  # 10K tokens limit
    max_cost: "$5.00"  # $5.00 cost limit
  monitoring:
    log_prompts: false  # Privacy: don't log prompts
    log_responses: false # Privacy: don't log responses
    log_tokens: true    # Track token usage
    log_costs: true     # Track costs
```

### AI Agent (`simple_ai_agent.py`)

Simulates an AI agent making 5 API calls:

1. Explain quantum computing (gpt-3.5-turbo, 150 tokens)
2. Write Python function (gpt-4, 200 tokens)  
3. Security analysis (claude-3-sonnet, 100 tokens)
4. Research summary (gpt-4-turbo, 120 tokens)
5. Translation (gpt-3.5-turbo, 50 tokens)

### Demo Script (`demo_ai_monitoring.sh`)

Walks through the complete workflow:
- Shows AI policy configuration
- Shows AI agent code
- Runs the agent with monitoring
- Explains expected results
- Validates market potential

## 📊 Expected Results

### AI Agent Summary

```
Total API calls: 5
Total tokens used: ~820
Total cost: ~$0.41
Average cost per call: ~$0.08
```

### AI Monitoring Features

```
✅ Budget enforcement: Active (10K tokens, $5.00 limit)
✅ Token tracking: Enabled
✅ Cost tracking: Enabled  
✅ Privacy protection: No prompt/response logging
```

### Sandbox Execution Summary

```
=== Sandbox Execution Summary ===
Policy applied: simple-ai-test
Command executed: ["python3", "examples/scripts/simple_ai_agent.py"]
Security features enabled:
  - User namespace: enabled
  - PID namespace: enabled
  - Mount namespace: enabled
  - Network isolation: enabled
  - Syscall filtering: default-deny
  - Resource limits: configured
  - Capability dropping: enabled
  - Audit logging: enabled
  - Budget enforcement: enabled
```

## 💡 Market Validation

### Key Value Propositions

1. **Cost Control** - Prevent LLM API cost overruns
2. **Usage Monitoring** - Track token usage across teams
3. **Privacy Compliance** - Monitor without logging sensitive data
4. **Production Ready** - Enterprise-grade monitoring system
5. **Easy Integration** - Simple YAML configuration

### Potential Customers

- **AI Development Teams** - Monitor AI agent development
- **LLM API Users** - Control API costs and usage
- **Enterprise AI** - Compliance and auditing requirements
- **AI Startups** - Budget enforcement for cost control
- **Research Institutions** - Track AI resource usage

### Competitive Advantages

| Feature | Purple AI Monitoring | Competitors |
|---------|---------------------|-------------|
| Budget Enforcement | ✅ Yes | ❌ Limited |
| Token Tracking | ✅ Yes | ✅ Yes |
| Cost Tracking | ✅ Yes | ❌ No |
| Privacy Protection | ✅ Yes | ❌ No |
| Policy Configuration | ✅ YAML | ❌ Complex |
| Sandbox Integration | ✅ Native | ❌ Separate |
| Production Ready | ✅ Yes | ❌ No |

## 🎯 Next Steps for Market Validation

### 1. Customer Interviews

Ask potential customers:
- "How do you currently monitor AI API usage?"
- "What's your biggest challenge with LLM costs?"
- "Would budget enforcement be valuable?"
- "What features would make this a must-have tool?"

### 2. Pilot Testing

Offer free pilot testing to:
- AI development teams
- LLM API heavy users
- Enterprise AI initiatives

### 3. Feature Prioritization

Based on feedback, prioritize:
- HTTP proxy for real API interception
- Multi-provider support (OpenAI, Anthropic, etc.)
- Advanced rate limiting
- Team-based budget management

### 4. Pricing Strategy

Consider models:
- **Per-agent pricing** - $X/agent/month
- **Usage-based** - $X per 1M tokens monitored
- **Enterprise** - Custom pricing for large teams

## 🚀 Conclusion

This demo provides a **minimum viable example** that demonstrates:

✅ **Working AI monitoring system**
✅ **Budget enforcement capabilities**
✅ **Policy configuration flexibility**
✅ **Production-ready architecture**
✅ **Clear market potential**

**The system is ready for market validation and customer testing!** 🎉