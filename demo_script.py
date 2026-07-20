#!/usr/bin/env python3
"""
Working REAL Mode Demo (fixed)
This triggers actual detections based on your IDS thresholds.
Edits made:
 - Correct mode switch: POST /api/mode/switch with JSON
 - Ensure sniffer starts by calling /api/auto-detect/start
 - Fix blockchain length detection in show_results
 - Fix blockchain validation key check
"""

import time
import requests
from threading import Thread
from concurrent.futures import ThreadPoolExecutor

DASHBOARD = "http://127.0.0.1:5000"


def dos_attack_simulation():
    """
    Generate 150+ requests to trigger DOS_ATTACK
    Your IDS needs: packet_count > 100
    """
    print("\n🔴 Simulating DOS Attack (150 rapid requests)...")

    def make_request(i):
        try:
            requests.get(DASHBOARD, timeout=0.5)
            print(f"  Request {i+1}/150", end="\r")
        except:
            pass

    # Make 150 requests rapidly using threads
    with ThreadPoolExecutor(max_workers=20) as executor:
        executor.map(make_request, range(150))

    print("\n✅ DOS traffic generated")
    time.sleep(2)


def port_scan_simulation():
    """
    Connect to 5+ different ports to trigger PORT_SCAN
    Your IDS needs: 5+ unique ports
    """
    print("\n🔍 Simulating Port Scan (connecting to multiple ports)...")

    ports = [5000, 8080, 8000, 3000, 9000, 7000]

    for i, port in enumerate(ports):
        try:
            requests.get(f"http://127.0.0.1:{port}", timeout=0.5)
        except:
            pass  # Expected to fail on closed ports
        print(f"  Scanning port {port} ({i+1}/{len(ports)})")
        time.sleep(0.3)

    print("✅ Port scan traffic generated")
    time.sleep(2)


def large_packet_simulation():
    """
    Send large payload to trigger SUSPICIOUS_PACKET
    Your IDS needs: packet_size > 65000 bytes
    """
    print("\n📦 Sending Large Packet (70KB)...")

    try:
        # Send 70KB of data
        large_data = "X" * 70000
        # Use post with raw body so Flask "before_request" sees payload
        requests.post(DASHBOARD, data=large_data, headers={"Content-Type": "text/plain"}, timeout=5)
        print("✅ Large packet sent")
    except Exception:
        print("✅ Large packet attempted (connection may timeout)")

    time.sleep(2)


def sql_injection_simulation():
    """
    Send SQL injection payload to trigger SQL_INJECTION
    """
    print("\n💉 Simulating SQL Injection...")

    sql_payloads = [
        "' OR 1=1--",
        "SELECT * FROM users WHERE id=1",
        "'; DROP TABLE users;--",
        "UNION SELECT password FROM accounts"
    ]

    for payload in sql_payloads:
        try:
            requests.get(DASHBOARD, params={"search": payload}, timeout=1)
        except:
            pass
        time.sleep(0.5)

    print("✅ SQL injection payloads sent")
    time.sleep(2)


def show_results():
    """Display detected intrusions"""
    print("\n" + "="*60)
    print("📊 CHECKING DETECTION RESULTS")
    print("="*60)

    try:
        intrusions_resp = requests.get(f"{DASHBOARD}/api/intrusions", timeout=3)
        intrusions = intrusions_resp.json()
    except Exception as e:
        print(f"❌ Error fetching intrusions: {e}")
        intrusions = []

    try:
        blockchain_resp = requests.get(f"{DASHBOARD}/api/blockchain", timeout=3)
        blockchain_json = blockchain_resp.json()
    except Exception as e:
        print(f"❌ Error fetching blockchain: {e}")
        blockchain_json = {}

    # Filter REAL mode detections
    real_intrusions = [i for i in intrusions if i.get('mode') == 'REAL']

    # Compute chain length safely
    chain_len = 0
    if isinstance(blockchain_json, dict):
        # support both pretty JSON (with 'chain') and raw list responses
        chain_len = len(blockchain_json.get('chain', [])) if isinstance(blockchain_json.get('chain', None), list) else 0
    elif isinstance(blockchain_json, list):
        chain_len = len(blockchain_json)

    print(f"\n✅ Total Intrusions Detected: {len(real_intrusions)}")
    print(f"✅ Blockchain Blocks: {chain_len}")

    if real_intrusions:
        print("\n" + "-"*60)
        print("🔴 DETECTED ATTACKS (Last 5):")
        print("-"*60)

        for intrusion in real_intrusions[-5:]:
            print(f"\n🚨 {intrusion.get('type', 'UNKNOWN')}")
            print(f"   Severity: {intrusion.get('severity', 'N/A')}")
            print(f"   Source: {intrusion.get('src_ip', 'N/A')}")
            print(f"   Description: {intrusion.get('description', 'N/A')}")
            print(f"   Time: {intrusion.get('timestamp', 'N/A')}")
            print(f"   Mode: ✅ {intrusion.get('mode', 'N/A')}")
    else:
        print("\n⚠️ No REAL mode detections yet!")
        print("   This might mean:")
        print("   1. Packet sniffer needs admin privileges")
        print("   2. Network interface not capturing properly")
        print("   3. Thresholds not reached yet")

    print("\n" + "="*60)


def validate_blockchain():
    """Validate blockchain integrity"""
    print("\n🔗 Validating Blockchain...")

    try:
        response = requests.get(f"{DASHBOARD}/api/validate", timeout=3)
        result = response.json()

        # app.py returns {'is_valid': True/False}
        is_valid = result.get('is_valid') if isinstance(result, dict) else None

        if is_valid is True:
            print("✅ Blockchain is VALID - No tampering detected!")
        elif is_valid is False:
            print("❌ Blockchain INVALID - Tampering detected!")
        else:
            # backwards-compatible check
            if result.get('valid'):
                print("✅ Blockchain is VALID - No tampering detected!")
            else:
                print("⚠️ Could not determine blockchain validity from response:", result)

    except Exception as e:
        print(f"❌ Validation error: {e}")


# MAIN DEMO
if __name__ == "__main__":
    print("="*60)
    print("🔴 BLOCKCHAIN IDS - REAL MODE DEMO (fixed)")
    print("="*60)
    print("\n⚠️  IMPORTANT:")
    print("   - Flask app must be running with ADMIN/SUDO privileges")
    print("   - Packet capture requires elevated permissions")
    print("   - This generates 150+ network requests locally")
    print("\nPress Enter to start demo...")
    input()

    # Check if dashboard is accessible
    try:
        r = requests.get(DASHBOARD, timeout=2)
        print("✅ Dashboard is accessible")
    except Exception:
        print("❌ Dashboard not accessible! Make sure Flask is running.")
        exit()

    # Switch to REAL mode (correct endpoint + ensure sniffer starts)
    print("\n1️⃣ Switching to REAL mode...")
    try:
        r = requests.post(f"{DASHBOARD}/api/mode/switch", json={"mode": "REAL"}, timeout=3)
        print("Mode switch response:", r.status_code, r.text)
    except Exception as e:
        print("⚠️ Mode switch failed:", e)

    # Start auto-detect to ensure sniffer is running
    try:
        r2 = requests.post(f"{DASHBOARD}/api/auto-detect/start", timeout=3)
        print("Auto-detect start response:", r2.status_code, r2.text)
    except Exception as e:
        print("⚠️ Auto-detect start failed (you may need to start from dashboard):", e)

    # Run attack simulations
    print("\n2️⃣ Generating Attack Traffic...")
    print("-"*60)

    # Run all simulations
    dos_attack_simulation()
    port_scan_simulation()
    large_packet_simulation()
    sql_injection_simulation()

    print("\n✅ All traffic generation complete!")

    # Wait for IDS to process
    print("\n3️⃣ Waiting for IDS to process packets...")
    for i in range(5, 0, -1):
        print(f"   {i} seconds...", end="\r")
        time.sleep(1)
    print()

    # Show results
    print("\n4️⃣ Checking Detection Results...")
    show_results()

    # Validate blockchain
    print("\n5️⃣ Blockchain Validation...")
    validate_blockchain()

    # Final instructions
    print("\n" + "="*60)
    print("🎯 DEMO COMPLETE!")
    print("="*60)
    print("\n📌 Next Steps:")
    print(f"   1. Open dashboard: {DASHBOARD}")
    print("   2. Check 'Recent Intrusions' section")
    print("   3. View 'Blockchain Records' section")
    print("   4. Click 'View Analytics' for charts")
    print("   5. Click 'Validate Blockchain' button")
    print("\n💡 If no detections appeared:")
    print("   - Restart Flask with: sudo python3 app.py")
    print("   - Check if packet sniffer is capturing")
    print("   - Look at Flask terminal for errors")
    print("="*60)
