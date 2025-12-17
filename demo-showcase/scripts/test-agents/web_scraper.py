#!/usr/bin/env python3
"""
Test Web Scraper Agent
Demonstrates network access controls in the sandbox
"""

import urllib.request
import ssl
import socket

def main():
    print("🌐 Web Scraper Agent")
    print("=" * 40)
    print()
    
    # Test allowed HTTPS connection
    print("📡 Testing allowed connections...")
    
    try:
        ctx = ssl.create_default_context()
        with urllib.request.urlopen("https://httpbin.org/ip", timeout=10, context=ctx) as response:
            data = response.read().decode()
            print(f"  ✅ HTTPS (443) - Success")
            print(f"     Response: {data.strip()}")
    except Exception as e:
        print(f"  ❌ HTTPS (443) - Failed: {e}")
    
    print()
    
    # Test blocked connection (if policy blocks it)
    print("🚫 Testing blocked connections...")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(("smtp.gmail.com", 587))
        sock.close()
        print("  ⚠️ SMTP (587) - Connection allowed (check policy)")
    except Exception as e:
        print(f"  ✅ SMTP (587) - Blocked: {type(e).__name__}")
    
    # Test incoming connections (should be blocked)
    print()
    print("🔒 Testing incoming connections...")
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("0.0.0.0", 8080))
        server.listen(1)
        server.close()
        print("  ⚠️ Listen on 8080 - Allowed (check policy)")
    except Exception as e:
        print(f"  ✅ Listen blocked: {type(e).__name__}")
    
    print()
    print("✨ Scraper agent complete")

if __name__ == "__main__":
    main()
