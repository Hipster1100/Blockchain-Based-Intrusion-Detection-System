"""
Blockchain IDS - REAL Mode Diagnostic Tool (v2)
Verifies that Flask auto-starts the sniffer when switching to REAL mode.
Save as debug_real_mode_v2.py and run the same way as your prior diagnostic.
"""

import sys
import time
import os
import json

def print_header(title):
    print("\n" + "="*60)
    print(f"  {title}")
    print("="*60)

def test_admin_privileges():
    print_header("1. Testing Administrator Privileges")
    if os.name == 'nt':
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if is_admin:
                print("✅ Running as Administrator")
                return True
            else:
                print("❌ NOT running as Administrator")
                print("   → Solution: Close and run PowerShell as Administrator")
                return False
        except Exception as e:
            print("⚠️  Cannot determine admin status:", e)
            return False
    else:
        try:
            if os.geteuid() == 0:
                print("✅ Running as root")
                return True
            else:
                print("❌ NOT running as root")
                print("   → Solution: Use sudo python3 debug_real_mode_v2.py")
                return False
        except Exception as e:
            print("⚠️  Cannot determine admin status:", e)
            return False

def test_scapy_import():
    print_header("2. Testing Scapy Installation")
    try:
        from scapy.all import conf, get_if_list, sniff
        ver = getattr(conf, 'version', getattr(conf, 'scapy_version', 'unknown'))
        print("✅ Scapy imported successfully")
        print(f"   Version: {ver}")
        return True
    except ImportError as e:
        print(f"❌ Scapy import failed: {e}")
        print("   → Solution: pip install scapy")
        return False
    except Exception as e:
        print(f"❌ Error importing scapy: {e}")
        return False

def test_network_interfaces():
    print_header("3. Testing Network Interfaces")
    try:
        from scapy.all import get_if_list, conf
        interfaces = get_if_list()
        print(f"✅ Found {len(interfaces)} network interface(s):")
        for i, iface in enumerate(interfaces, 1):
            print(f"   {i}. {iface}")
        print(f"\n   Default interface: {conf.iface}")
        return True, interfaces
    except Exception as e:
        print(f"❌ Error getting interfaces: {e}")
        return False, []

def test_npcap_windows():
    print_header("4. Testing Npcap/WinPcap (Windows)")
    if os.name != 'nt':
        print("⏭️  Skipping (not Windows)")
        return True
    try:
        from scapy.all import conf
        print(f"   use_pcap setting: {getattr(conf, 'use_pcap', 'unknown')}")
        npcap_paths = [
            r"C:\Windows\System32\Npcap",
            r"C:\Windows\SysWOW64\Npcap",
            r"C:\Program Files\Npcap"
        ]
        found = False
        for path in npcap_paths:
            if os.path.exists(path):
                print(f"✅ Found Npcap at: {path}")
                found = True
                break
        if not found:
            print("❌ Npcap not found")
            print("   → Solution: Download + install from https://npcap.com/ (enable WinPcap API-compatible mode)")
            return False
        return True
    except Exception as e:
        print(f"⚠️  Error checking Npcap: {e}")
        return False

def test_flask_connection():
    print_header("5. Testing Flask Server Connection")
    try:
        import requests
        resp = requests.get("http://127.0.0.1:5000", timeout=2)
        print(f"✅ Flask server is running (Status: {resp.status_code})")
        return True
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to Flask server at http://127.0.0.1:5000")
        print("   → Solution: Start Flask with: python app.py")
        return False
    except requests.exceptions.Timeout:
        print("❌ Flask server timeout")
        return False
    except ImportError:
        print("⚠️  'requests' module not installed")
        print("   → Install with: pip install requests")
        return False
    except Exception as e:
        print(f"❌ Error connecting to Flask: {e}")
        return False

def check_packet_sniffer_code():
    print_header("6. Checking packet_sniffer.py (code-level)")
    fname = 'packet_sniffer.py'
    if not os.path.exists(fname):
        print("❌ packet_sniffer.py not found in project root")
        return False
    try:
        content = open(fname, 'r', encoding='utf-8', errors='ignore').read()
        checks = {
            'has start_sniffing': 'def start_sniffing' in content or 'start_sniffing(' in content,
            'calls sniff (scapy)': 'sniff(' in content or 'AsyncSniffer' in content,
            'uses packet callback': 'packet_callback' in content or 'def packet_callback' in content,
            'uses stop_sniffing': 'def stop_sniffing' in content or 'stop_sniffing' in content,
            'references start()': '.start(' in content
        }
        print("   Code checks:")
        all_ok = True
        for k, v in checks.items():
            status = "✅" if v else "❌"
            print(f"   {status} {k}")
            if not v:
                all_ok = False
        return all_ok
    except Exception as e:
        print(f"❌ Error reading packet_sniffer.py: {e}")
        return False

def test_packet_capture_basic():
    print_header("7. Testing Packet Capture (quick sniff)")
    try:
        from scapy.all import sniff, conf
        iface = getattr(conf, 'iface', None)
        print(f"   Attempting to sniff 2 packets on interface: {iface or 'default'} (timeout 15s)")
        captured = []
        def cb(pkt):
            captured.append(pkt)
            try:
                print("   ✅ Packet captured:", pkt.summary())
            except:
                print("   ✅ Packet captured (no summary)")
        sniff(count=2, timeout=15, prn=cb, store=False, iface=iface)
        if captured:
            print(f"\n✅ Captured {len(captured)} packet(s)")
            return True
        else:
            print("\n❌ No packets captured during test sniff")
            return False
    except PermissionError:
        print("❌ Permission denied: need Administrator/root privileges")
        return False
    except Exception as e:
        print(f"❌ Error during capture test: {e}")
        return False

def test_mode_switch_and_sniffer_status():
    """
    Attempt to switch Flask to REAL mode and query /api/sniffer/status.
    This checks whether the app starts the sniffer on mode switch.
    """
    print_header("8. Testing MODE switch -> SNIFER status via API")
    try:
        import requests
    except ImportError:
        print("⚠️  'requests' module not installed; skipping this test")
        return False

    base = "http://127.0.0.1:5000"
    try:
        # Switch to REAL mode
        print("   POST /api/mode/switch -> REAL")
        r = requests.post(f"{base}/api/mode/switch", json={"mode": "REAL"}, timeout=5)
        print(f"   Response: {r.status_code} {r.text[:200]}")
        time.sleep(1.0)

        # Query sniffer status
        print("   GET /api/sniffer/status")
        r2 = requests.get(f"{base}/api/sniffer/status", timeout=5)
        print(f"   Response: {r2.status_code} {r2.text[:400]}")
        try:
            status = r2.json()
        except:
            status = None

        ok = False
        if status and isinstance(status, dict):
            sniffing = status.get('sniffing')
            thread_alive = status.get('thread_alive')
            print(f"   Parsed status -> sniffing: {sniffing}, thread_alive: {thread_alive}")
            if sniffing or thread_alive:
                print("✅ Sniffer appears to be running (sniffing=True or thread_alive=True)")
                ok = True
            else:
                print("❌ Sniffer not running according to /api/sniffer/status")
        else:
            print("❌ Could not parse /api/sniffer/status JSON")
        return ok
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to Flask API (is app running?)")
        return False
    except Exception as e:
        print(f"❌ Error switching mode or querying sniffer: {e}")
        return False

def main():
    print("\n" + "="*60)
    print("  🔍 BLOCKCHAIN IDS - REAL MODE DIAGNOSTICS (v2)")
    print("="*60)
    print("This tool checks admin, scapy, npcap (Windows), Flask, packet_sniffer.py,")
    print("attempts a quick sniff, and verifies Flask will start the sniffer on mode switch.\n")

    results = {}
    results['admin'] = test_admin_privileges()
    results['scapy'] = test_scapy_import()
    results['interfaces'], interfaces = test_network_interfaces()

    if sys.platform == 'win32':
        results['npcap'] = test_npcap_windows()
    else:
        results['npcap'] = True

    results['flask'] = test_flask_connection()
    results['code'] = check_packet_sniffer_code()

    # quick sniff if possible
    if results['admin'] and results['scapy']:
        results['capture'] = test_packet_capture_basic()
    else:
        print_header("7. Testing Packet Capture (skipped)")
        print("⏭️  Skipped (prereqs not met)")
        results['capture'] = False

    # API mode-switch / sniffer check (only if flask reachable)
    if results['flask']:
        results['mode_switch'] = test_mode_switch_and_sniffer_status()
    else:
        results['mode_switch'] = False

    # Summary
    print_header("DIAGNOSTIC SUMMARY")
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    print(f"\n   Tests Passed: {passed}/{total}\n")
    for k, v in results.items():
        status = "✅" if v else "❌"
        print(f"   {status} {k}")

    # Recommendations
    print_header("RECOMMENDATIONS")
    if not results['admin']:
        print("\n   🔴 CRITICAL: Run as Administrator/root")
        print("      Windows: Right-click PowerShell → 'Run as Administrator'")
        print("      Linux/Mac: Use sudo")
    if not results.get('npcap', True) and sys.platform == 'win32':
        print("\n   🔴 CRITICAL: Install Npcap (https://npcap.com/), enable WinPcap API-compatible mode")
    if not results['capture']:
        print("\n   🟡 Packet capture failed or was skipped")
        print("      Try: open a browser to generate traffic, try different interface, re-run as admin")
    if not results['flask']:
        print("\n   🟡 Flask server not running: Start it with python app.py (in admin PowerShell for sniffer)")

    if not results['mode_switch']:
        print("\n   🟡 Sniffer did not start on mode switch or /api/sniffer/status reported not running.")
        print("      - Ensure your switch_mode() calls start_real_monitoring() OR that you manually call /api/auto-detect/start")
        print("      - Check Flask logs for exceptions when switching to REAL mode")

    print("\n" + "="*60)
    print("  End of diagnostics. Paste the output here if you want help fixing remaining failures.")
    print("="*60 + "\n")

if __name__ == "__main__":
    main()
