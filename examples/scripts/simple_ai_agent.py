#!/usr/bin/env python3
"""
Simple AI Agent for Testing Purple AI Monitoring

This script simulates an AI agent making LLM API calls.
It demonstrates how the Purple sandbox can monitor and control AI usage.
"""

import json
import time
import sys
from typing import Dict, Any

class SimpleAIAgent:
    """Simple AI agent that simulates LLM API calls"""
    
    def __init__(self):
        self.call_count = 0
        self.total_tokens = 0
        self.total_cost = 0.0
        
    def make_api_call(self, model: str, prompt: str, max_tokens: int = 100) -> Dict[str, Any]:
        """Simulate an LLM API call"""
        self.call_count += 1
        
        # Simulate token usage (prompt + completion)
        prompt_tokens = len(prompt.split()) * 1.5  # Approximate tokens
        completion_tokens = max_tokens
        total_tokens = prompt_tokens + completion_tokens
        self.total_tokens += total_tokens
        
        # Simulate cost (using approximate pricing)
        cost_per_1k_tokens = 0.5  # $0.50 per 1K tokens
        call_cost = (total_tokens / 1000) * cost_per_1k_tokens
        self.total_cost += call_cost
        
        # Simulate API response
        response = {
            "model": model,
            "prompt": prompt,
            "completion": f"Response to: {prompt}",
            "usage": {
                "prompt_tokens": int(prompt_tokens),
                "completion_tokens": int(completion_tokens),
                "total_tokens": int(total_tokens)
            },
            "cost": call_cost
        }
        
        # Log the API call (this would be intercepted by Purple in real usage)
        print(json.dumps({
            "type": "api_call",
            "call_number": self.call_count,
            "model": model,
            "tokens": int(total_tokens),
            "cost": f"${call_cost:.4f}",
            "prompt": prompt
        }))
        
        return response
    
    def run(self):
        """Run the AI agent with various tasks"""
        print("🚀 Starting Simple AI Agent")
        print("=" * 50)
        
        # Simulate various AI tasks
        tasks = [
            ("gpt-3.5-turbo", "Explain quantum computing in simple terms", 150),
            ("gpt-4", "Write a Python function to calculate Fibonacci sequence", 200),
            ("claude-3-sonnet", "Analyze this code for security vulnerabilities", 100),
            ("gpt-4-turbo", "Generate a summary of recent AI research papers", 120),
            ("gpt-3.5-turbo", "Translate this to French: Hello, how are you?", 50),
        ]
        
        for model, prompt, max_tokens in tasks:
            try:
                response = self.make_api_call(model, prompt, max_tokens)
                time.sleep(0.5)  # Simulate network latency
                
            except Exception as e:
                print(f"❌ Error making API call: {e}")
        
        # Print summary
        print("\n📊 AI Agent Summary")
        print("=" * 50)
        print(f"Total API calls: {self.call_count}")
        print(f"Total tokens used: {self.total_tokens}")
        print(f"Total cost: ${self.total_cost:.2f}")
        print(f"Average cost per call: ${self.total_cost/self.call_count:.2f}")
        
        # Check if we're in a sandbox environment
        in_sandbox = "PURPLE_SANDBOX" in open("/proc/1/environ", "r").read()
        
        if in_sandbox:
            print("\n🔒 Running in Purple Sandbox")
            print("   ✅ All API calls are being monitored")
            print("   ✅ Budget limits are being enforced")
            print("   ✅ Usage statistics are being tracked")
        else:
            print("\n🌐 Running in regular environment")
            print("   ⚠️  API calls would be monitored in Purple Sandbox")
        
        print("\n✅ AI agent completed successfully!")

if __name__ == "__main__":
    agent = SimpleAIAgent()
    agent.run()