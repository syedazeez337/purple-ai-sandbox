#!/usr/bin/env python3
"""
AI Agent Demo Script for Purple Sandbox

This script demonstrates how AI agents can make LLM API calls
that will be intercepted and monitored by the Purple sandbox.

The sandbox will:
1. Intercept HTTP requests to LLM APIs
2. Track token usage and costs
3. Enforce budget limits
4. Provide comprehensive monitoring
"""

import os
import json
import time
import requests
from typing import Dict, Any, Optional

class MockLLMAgent:
    """Mock LLM agent that simulates API calls for demonstration"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or "mock-api-key-for-demo"
        self.call_count = 0
        self.total_tokens = 0
        
    def make_api_call(self, model: str, prompt: str, max_tokens: int = 100) -> Dict[str, Any]:
        """Simulate an LLM API call"""
        self.call_count += 1
        
        # Simulate token usage (prompt + completion)
        prompt_tokens = len(prompt.split()) * 1.5  # Approximate tokens
        completion_tokens = max_tokens
        total_tokens = prompt_tokens + completion_tokens
        self.total_tokens += total_tokens
        
        # Simulate API response
        response = {
            "id": f"chatcmpl-{int(time.time())}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": f"This is a simulated response to: {prompt}"
                },
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": int(prompt_tokens),
                "completion_tokens": int(completion_tokens),
                "total_tokens": int(total_tokens)
            }
        }
        
        print(f"🔄 API Call #{self.call_count}")
        print(f"   Model: {model}")
        print(f"   Prompt: {prompt[:50]}...")
        print(f"   Tokens: {int(prompt_tokens)} prompt + {int(completion_tokens)} completion = {int(total_tokens)} total")
        print(f"   Response: {response['choices'][0]['message']['content'][:50]}...")
        print()
        
        return response
    
    def run_demo(self):
        """Run a demonstration of multiple API calls"""
        print("🚀 Starting AI Agent Demo")
        print("=" * 50)
        print()
        
        # Simulate various LLM API calls
        tasks = [
            ("gpt-3.5-turbo", "Explain quantum computing in simple terms", 150),
            ("gpt-4", "Write a Python function to calculate Fibonacci sequence", 200),
            ("claude-3-5-sonnet-20241022", "Analyze this code for security vulnerabilities", 100),
            ("gpt-4-turbo", "Generate a summary of recent AI research papers", 120),
        ]
        
        for model, prompt, max_tokens in tasks:
            try:
                response = self.make_api_call(model, prompt, max_tokens)
                
                # Small delay to simulate network latency
                time.sleep(0.5)
                
            except Exception as e:
                print(f"❌ Error making API call: {e}")
        
        # Print summary
        print("📊 Demo Summary")
        print("=" * 50)
        print(f"Total API calls: {self.call_count}")
        print(f"Total tokens used: {int(self.total_tokens)}")
        print(f"Estimated cost: ~${self.total_tokens / 1000 * 0.5:.2f}")  # Approximate cost
        print()
        print("✅ Demo completed successfully!")
        print()
        print("Note: In a real Purple sandbox, these API calls would be:")
        print("  • Intercepted by the HTTP proxy")
        print("  • Monitored for token usage and costs")
        print("  • Subject to budget enforcement")
        print("  • Logged for audit purposes")

if __name__ == "__main__":
    # Check if we're running in a sandbox environment
    in_sandbox = os.environ.get("PURPLE_SANDBOX", "false").lower() == "true"
    
    if in_sandbox:
        print("🔒 Running in Purple Sandbox environment")
        print("    All API calls will be monitored and controlled")
    else:
        print("🌐 Running in regular environment")
        print("    API calls would be monitored if running in Purple Sandbox")
    
    print()
    
    # Create and run the demo agent
    agent = MockLLMAgent()
    agent.run_demo()