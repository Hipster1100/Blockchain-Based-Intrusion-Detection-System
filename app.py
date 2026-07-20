from flask import Flask, render_template, jsonify, request, send_file, Response
from flask_cors import CORS
import json
import threading
import time
from datetime import datetime, timedelta
from io import StringIO, BytesIO
from blockchain import Blockchain
from intrusion_detector import IntrusionDetector
from packet_sniffer import PacketSniffer
from database import Database

app = Flask(__name__)
CORS(app)

# Helper: always return pretty JSON responses for large endpoints
def pretty_json_response(obj, indent=2):
    text = json.dumps(obj, indent=indent, ensure_ascii=False)
    return Response(text, mimetype='application/json')

# Initialize database
db = Database('blockchain.db')

# Initialize blockchain with database
blockchain = Blockchain(difficulty=2, database=db)
ids = IntrusionDetector()

# Initialize packet sniffer
packet_sniffer = PacketSniffer(ids, blockchain)

# Mode tracking
current_mode = "DEMO"  # "DEMO" or "REAL"
auto_detect_running = False
real_monitor_thread = None

# -----------------------
# Flask -> IDS bridge (REAL-mode demo helper)
# -----------------------
from datetime import datetime as _dt

def build_packet_info_from_flask_request(req):
    try:
        src_ip = req.remote_addr or '127.0.0.1'
        host = (req.host.split(':')[0]) if req.host else '127.0.0.1'
        src_port = req.environ.get('REMOTE_PORT') or None
        try:
            src_port = int(src_port) if src_port else None
        except:
            src_port = None
        try:
            dst_port = int(req.host.split(':')[1]) if ':' in req.host else int(app.config.get('SERVER_PORT', 5000))
        except:
            dst_port = 5000
        try:
            payload_text = req.get_data(as_text=True) or ''
        except:
            payload_text = ''
        packet_info = {
            'src_ip': src_ip,
            'dst_ip': host,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': 'HTTP',
            'payload': payload_text,
            'packet_size': len(payload_text) if payload_text else (int(req.content_length) if req.content_length else 0),
            'timestamp': _dt.now().isoformat()
        }
        return packet_info
    except Exception as e:
        print(f"Error building packet_info from Flask request: {e}")
        return {}

@app.before_request
def feed_real_requests_to_ids():
    try:
        if current_mode != "REAL":
            return
        packet_info = build_packet_info_from_flask_request(request)
        intrusions = ids.analyze_real_traffic(packet_info)
        for intrusion in intrusions:
            intrusion['mode'] = 'REAL'
            try:
                block = blockchain.add_block(intrusion)
                print(f"[REAL-DEMO] Intrusion detected: {intrusion.get('type')} from {intrusion.get('src_ip')} -> Block #{block.index}")
            except Exception as ex:
                print(f"Error saving intrusion block (REAL demo): {ex}")
    except Exception as e:
        print(f"Error in before_request REAL feed: {e}")

# ----- Demo auto-detect thread -----
def auto_detect_demo_intrusions():
    """Background thread for DEMO MODE - continuous intrusion detection"""
    global auto_detect_running
    while auto_detect_running and current_mode == "DEMO":
        # Generate demo traffic
        traffic = ids.generate_demo_traffic()
        
        # Analyze for intrusions
        intrusions = ids.analyze_traffic(traffic)
        
        # Add detected intrusions to blockchain
        for intrusion in intrusions:
            blockchain.add_block(intrusion)
            print(f"[DEMO MODE] Intrusion detected and added to blockchain: {intrusion['type']}")
        
        time.sleep(5)  # Check every 5 seconds

# ----- REAL mode starter (forces the validated interface) -----
# Replace the NPF id below with your validated interface if different.
DEFAULT_NPF_IFACE = r"\Device\NPF_{0896B3B8-8B71-4162-B7EB-96F00391A69C}"

def start_real_monitoring(interface=None):
    """Start real network packet capture (debug-friendly).
    If interface is None, use DEFAULT_NPF_IFACE which was validated during setup.
    """
    global real_monitor_thread
    try:
        print("\n" + "="*60)
        print("STARTING REAL NETWORK MONITORING MODE (DEBUG)")
        print("="*60)
        print("NOTE: You may need to run this as Administrator/Root")
        # force the interface we validated earlier if caller didn't pass one
        if not interface:
            interface = DEFAULT_NPF_IFACE
        print("Attempting to capture packets from interface:", interface)
        print("="*60 + "\n")

        # Start sniffing in a separate thread so Flask stays responsive
        real_monitor_thread = threading.Thread(
            target=packet_sniffer.start_sniffing,
            kwargs={'interface': interface, 'packet_count': 0},
            daemon=True
        )
        real_monitor_thread.start()
        print("✅ REAL mode thread started:", real_monitor_thread.name)
        print("✅ Packet sniffer is now capturing live network traffic")
    except Exception as e:
        print(f"❌ Error starting real monitoring: {e}")
        print("You may need administrator/root privileges")

# ----- Routes -----
@app.route('/')
def index():
    """Main dashboard"""
    return render_template('index.html')

@app.route('/analytics')
def analytics():
    """Analytics dashboard page"""
    return render_template('analytics.html')

@app.route('/api/mode', methods=['GET'])
def get_mode():
    """Get current operating mode"""
    return jsonify({
        'mode': current_mode,
        'auto_detect_running': auto_detect_running
    })

@app.route('/api/mode/switch', methods=['POST'])
def switch_mode():
    """Switch between DEMO and REAL mode"""
    global current_mode, auto_detect_running
    data = request.json
    new_mode = data.get('mode', 'DEMO').upper()
    if new_mode not in ['DEMO', 'REAL']:
        return jsonify({'error': 'Invalid mode. Use DEMO or REAL'}), 400

    # Stop any running detection
    if auto_detect_running:
        auto_detect_running = False
        time.sleep(1)  # Wait briefly for threads to stop

    # If switching away from REAL, stop sniffing
    if current_mode == "REAL" and new_mode != "REAL":
        try:
            packet_sniffer.stop_sniffing()
            print("⏸️ Stopped REAL mode packet capture")
        except Exception as e:
            print(f"Warning stopping sniffer: {e}")

    current_mode = new_mode
    print(f"🔄 Switched to {new_mode} mode")

    # If we just switched to REAL, start the real monitor/sniffer automatically
    if current_mode == "REAL":
        try:
            # If sniffer thread already alive, don't start another
            if real_monitor_thread and real_monitor_thread.is_alive():
                print("ℹ️ REAL monitor already running (thread alive).")
            else:
                start_real_monitoring()  # starts packet_sniffer.start_sniffing() in a thread
                print("▶️ REAL mode: packet sniffer start requested")
        except Exception as e:
            print(f"❌ Error starting real sniffer on mode switch: {e}")

    return jsonify({
        'message': f'Switched to {new_mode} mode',
        'mode': current_mode
    })

@app.route('/api/interfaces', methods=['GET'])
def get_interfaces():
    """Get available network interfaces"""
    interfaces = packet_sniffer.get_available_interfaces()
    return jsonify({'interfaces': interfaces})

@app.route('/api/blockchain', methods=['GET'])
def get_blockchain():
    """Get entire blockchain (pretty JSON)"""
    chain_obj = {
        'chain': blockchain.get_chain(),
        'length': len(blockchain.chain),
        'is_valid': blockchain.is_chain_valid()
    }
    return pretty_json_response(chain_obj)

@app.route('/api/block/<int:index>', methods=['GET'])
def get_block(index):
    """Get specific block by index (pretty JSON)"""
    block = blockchain.get_block_by_index(index)
    if block:
        return pretty_json_response(block)
    return jsonify({'error': 'Block not found'}), 404

@app.route('/api/validate', methods=['GET'])
def validate_chain():
    """Validate blockchain integrity"""
    is_valid = blockchain.is_chain_valid()
    return jsonify({
        'is_valid': is_valid,
        'message': 'Blockchain is valid' if is_valid else 'Blockchain has been tampered with!'
    })

@app.route('/api/intrusions', methods=['GET'])
def get_intrusions():
    """Get all intrusion records from blockchain (pretty JSON)"""
    intrusions = []
    for block in blockchain.chain[1:]:  # Skip genesis block
        try:
            if isinstance(block.data, dict) and 'type' in block.data:
                intrusions.append({
                    'block_index': block.index,
                    'block_hash': block.hash,
                    'mode': block.data.get('mode', 'DEMO'),  # Track which mode detected it
                    **block.data
                })
        except Exception:
            # skip malformed blocks gracefully
            continue
    return pretty_json_response(intrusions)

@app.route('/api/intrusions/search', methods=['GET'])
def search_intrusions():
    """Search intrusions by keyword"""
    keyword = request.args.get('q', '')
    results = blockchain.search_blocks(keyword)
    return pretty_json_response(results)

@app.route('/api/detect', methods=['POST'])
def manual_detect():
    """Manually trigger intrusion detection"""
    traffic_data = request.json
    # Add mode to intrusion data
    traffic_data['mode'] = current_mode
    intrusions = ids.analyze_traffic(traffic_data)
    # Add to blockchain
    for intrusion in intrusions:
        intrusion['mode'] = current_mode
        blockchain.add_block(intrusion)
    return jsonify({
        'detected': len(intrusions),
        'intrusions': intrusions,
        'mode': current_mode
    })

@app.route('/api/demo', methods=['POST'])
def add_demo_intrusion():
    """Add a demo intrusion to blockchain (DEMO MODE ONLY)"""
    if current_mode != "DEMO":
        return jsonify({
            'error': 'This endpoint only works in DEMO mode',
            'current_mode': current_mode
        }), 400
    traffic = ids.generate_demo_traffic()
    intrusions = ids.analyze_traffic(traffic)
    added = []
    for intrusion in intrusions:
        intrusion['mode'] = 'DEMO'
        block = blockchain.add_block(intrusion)
        added.append({
            'block_index': block.index,
            'intrusion': intrusion
        })
    if not added:
        return jsonify({'message': 'No intrusion detected in demo traffic'}), 200
    return jsonify({
        'message': 'Demo intrusion added',
        'intrusions': added,
        'mode': current_mode
    })

@app.route('/api/auto-detect/start', methods=['POST'])
def start_auto_detect():
    """Start automatic intrusion detection"""
    global auto_detect_running
    if auto_detect_running:
        return jsonify({'message': f'Auto-detection already running in {current_mode} mode'})
    auto_detect_running = True
    if current_mode == "DEMO":
        # Start demo mode thread
        thread = threading.Thread(target=auto_detect_demo_intrusions, daemon=True)
        thread.start()
        message = 'Demo auto-detection started (simulated attacks every 5 seconds)'
        print(f"🔵 {message}")
    else:
        # Start real network monitoring
        start_real_monitoring()
        message = 'Real-time network monitoring started (capturing live packets)'
        print(f"🔴 {message}")
    return jsonify({
        'message': message,
        'mode': current_mode
    })

@app.route('/api/auto-detect/stop', methods=['POST'])
def stop_auto_detect():
    """Stop automatic intrusion detection"""
    global auto_detect_running
    auto_detect_running = False
    if current_mode == "REAL":
        packet_sniffer.stop_sniffing()
        print("⏸️ Stopped real-time packet capture")
    return jsonify({
        'message': f'Auto-detection stopped ({current_mode} mode)',
        'mode': current_mode
    })

@app.route('/api/sniffer/status', methods=['GET'])
def sniffer_status():
    """Return basic sniffer status for debugging"""
    return jsonify({
        'sniffing': packet_sniffer.sniffing,
        'thread_alive': real_monitor_thread.is_alive() if real_monitor_thread else False,
        'thread_name': real_monitor_thread.name if real_monitor_thread else None
    })

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get system statistics from database"""
    db_stats = db.get_statistics()
    return jsonify({
        'total_blocks': db_stats.get('total_blocks', len(blockchain.chain)),
        'total_intrusions': db_stats.get('total_intrusions', len(blockchain.chain) - 1),
        'intrusion_types': db_stats.get('type_distribution', {}),
        'severity_distribution': db_stats.get('severity_distribution', {}),
        'mode_distribution': db_stats.get('mode_distribution', {}),
        'top_source_ips': db_stats.get('top_source_ips', []),
        'blockchain_valid': blockchain.is_chain_valid(),
        'current_mode': current_mode,
        'auto_detect_running': auto_detect_running
    })

@app.route('/api/export/json', methods=['GET'])
def export_json():
    """Export blockchain to JSON (pretty)"""
    blocks = db.export_to_json()
    payload = {
        'blockchain': blocks,
        'exported_at': datetime.now().isoformat(),
        'total_blocks': len(blocks)
    }
    return pretty_json_response(payload)

@app.route('/api/export/csv', methods=['GET'])
def export_csv():
    """Export intrusions to CSV"""
    csv_data = db.export_intrusions_csv()
    output = BytesIO()
    output.write(csv_data.encode('utf-8'))
    output.seek(0)
    return send_file(
        output,
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'intrusions_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    )

@app.route('/api/analytics', methods=['GET'])
def get_analytics():
    """Get detailed analytics (pretty JSON)"""
    stats = db.get_statistics()
    logs = db.get_system_logs(limit=20)
    payload = {
        'statistics': stats,
        'recent_logs': logs,
        'blockchain_health': {
            'is_valid': blockchain.is_chain_valid(),
            'total_blocks': len(blockchain.chain),
            'latest_block_hash': blockchain.get_latest_block().hash if blockchain.chain else None
        }
    }
    return pretty_json_response(payload)

@app.route('/api/analytics/data', methods=['GET'])
def get_analytics_data():
    """Get all analytics data for dashboard with filters"""
    try:
        # Get filter parameters
        time_range = request.args.get('time_range', '7d')
        mode_filter = request.args.get('mode', 'all')
        # Get basic stats
        stats = db.get_statistics()
        # Get intrusions with filters
        intrusions = db.get_intrusions()
        # Filter by mode
        if mode_filter != 'all':
            intrusions = [i for i in intrusions if i.get('mode', 'DEMO') == mode_filter]
        # Filter by time range
        now = datetime.now()
        if time_range == '24h':
            cutoff = now - timedelta(hours=24)
        elif time_range == '7d':
            cutoff = now - timedelta(days=7)
        elif time_range == '30d':
            cutoff = now - timedelta(days=30)
        else:  # 'all'
            cutoff = None
        filtered_intrusions = []
        for intrusion in intrusions:
            try:
                ts = datetime.fromisoformat(intrusion['timestamp'])
                if cutoff is None or ts >= cutoff:
                    filtered_intrusions.append(intrusion)
            except:
                pass
        # Process timeline data
        from collections import defaultdict
        timeline_data = defaultdict(int)
        hourly_data = defaultdict(int)
        severity_data = defaultdict(int)
        type_data = defaultdict(int)
        mode_data = defaultdict(int)
        ip_data = defaultdict(int)
        for intrusion in filtered_intrusions:
            try:
                ts = datetime.fromisoformat(intrusion['timestamp'])
                date_key = ts.strftime('%Y-%m-%d')
                timeline_data[date_key] += 1
                # Hourly pattern
                hour = ts.hour
                hour_bucket = f"{(hour//4)*4:02d}-{((hour//4)*4+4):02d}h"
                hourly_data[hour_bucket] += 1
                # Severity
                severity = intrusion.get('severity', 'UNKNOWN')
                severity_data[severity] += 1
                # Type
                attack_type = intrusion.get('type', 'UNKNOWN')
                type_data[attack_type] += 1
                # Mode
                mode = intrusion.get('mode', 'DEMO')
                mode_data[mode] += 1
                # IP
                ip = intrusion.get('source_ip')
                if ip:
                    ip_data[ip] += 1
            except:
                pass
        # Sort and prepare timeline
        sorted_dates = sorted(timeline_data.keys())
        if time_range == '24h':
            sorted_dates = sorted_dates[-1:]  # Last 1 day
        elif time_range == '7d':
            sorted_dates = sorted_dates[-7:]  # Last 7 days
        elif time_range == '30d':
            sorted_dates = sorted_dates[-30:]  # Last 30 days
        timeline_values = [timeline_data[date] for date in sorted_dates]
        # Prepare hourly data
        hourly_buckets = ['00-04h', '04-08h', '08-12h', '12-16h', '16-20h', '20-24h']
        hourly_values = [hourly_data.get(bucket, 0) for bucket in hourly_buckets]
        # Prepare other data
        severity_labels = list(severity_data.keys())
        severity_values = list(severity_data.values())
        type_labels = list(type_data.keys())
        type_values = list(type_data.values())
        mode_labels = list(mode_data.keys())
        mode_values = list(mode_data.values())
        # Get top IPs
        top_ips = sorted(
            [{'source_ip': ip, 'count': count} for ip, count in ip_data.items()],
            key=lambda x: x['count'],
            reverse=True
        )[:10]
        # Calculate critical count
        critical_count = severity_data.get('CRITICAL', 0)
        payload = {
            'total_intrusions': len(filtered_intrusions),
            'critical_count': critical_count,
            'unique_ips': len(ip_data),
            'timeline': {
                'labels': sorted_dates,
                'values': timeline_values
            },
            'severity': {
                'labels': severity_labels,
                'values': severity_values
            },
            'types': {
                'labels': type_labels,
                'values': type_values
            },
            'mode': {
                'labels': mode_labels,
                'values': mode_values
            },
            'hourly': {
                'labels': hourly_buckets,
                'values': hourly_values
            },
            'top_ips': top_ips,
            'filters_applied': {
                'time_range': time_range,
                'mode': mode_filter
            }
        }
        return pretty_json_response(payload)
    except Exception as e:
        print(f"Error getting analytics data: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/backup', methods=['POST'])
def create_backup():
    """Create database backup"""
    backup_file = f'blockchain_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.db'
    success = db.backup_database(backup_file)
    if success:
        return jsonify({
            'message': 'Backup created successfully',
            'backup_file': backup_file
        })
    else:
        return jsonify({'error': 'Backup failed'}), 500

if __name__ == '__main__':
    print("=" * 60)
    print("🛡️  Blockchain-Enabled Intrusion Detection System")
    print("=" * 60)
    print("Features:")
    print("  - DEMO Mode: Simulated attacks for testing")
    print("  - REAL Mode: Live network packet capture")
    print("  - Toggle between modes via dashboard")
    print("=" * 60)
    print(f"📊 Database: {db.db_file}")
    print(f"⛓️  Blockchain: {len(blockchain.chain)} blocks")
    print(f"🔧 Current Mode: {current_mode}")
    print(f"🌐 Starting server on http://localhost:5000")
    print(f"⚠️  Running with debug=False (production-safe mode)")
    print("=" * 60)
    print("\n💡 To enable REAL mode:")
    print("   1. Open dashboard at http://localhost:5000")
    print("   2. Click 'Switch to REAL Mode' button")
    print("   3. Click 'Start Auto-Detection' (optional if you want Scapy running too)")
    print("   4. Generate network traffic to see detections")
    print("=" * 60 + "\n")

    # Turn off debug mode to prevent Flask auto-reload and instability
    app.run(debug=False, host='0.0.0.0', port=5000)
