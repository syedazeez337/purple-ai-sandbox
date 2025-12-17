#!/usr/bin/env python3
"""
Test AI Code Assistant Agent
Simulates a code analysis tool running in the sandbox
"""

import os
import sys

def main():
    print("🤖 AI Code Assistant Agent")
    print("=" * 40)
    print()
    
    # Show environment
    print("📍 Environment:")
    print(f"  Working Dir: {os.getcwd()}")
    print(f"  User ID: {os.getuid()}")
    print(f"  Group ID: {os.getgid()}")
    print()
    
    # Try to read a file
    print("📖 Attempting to read source files...")
    try:
        with open("/usr/bin/env", "rb") as f:
            data = f.read(100)
            print(f"  ✅ Read {len(data)} bytes from /usr/bin/env")
    except Exception as e:
        print(f"  ❌ Failed: {e}")
    
    # Try to write (should work in /tmp only)
    print()
    print("📝 Attempting to write files...")
    try:
        with open("/tmp/test_output.txt", "w") as f:
            f.write("Hello from AI agent!")
        print("  ✅ Write to /tmp succeeded")
    except Exception as e:
        print(f"  ❌ Failed: {e}")
    
    # Try to write outside scratch (should fail)
    try:
        with open("/etc/test.txt", "w") as f:
            f.write("test")
        print("  ⚠️ WARNING: Write to /etc succeeded (unexpected)")
    except Exception as e:
        print(f"  ✅ Write to /etc blocked: {type(e).__name__}")
    
    print()
    print("✨ Agent execution complete")

if __name__ == "__main__":
    main()
