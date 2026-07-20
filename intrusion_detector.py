import time
import random
from datetime import datetime
from collections import defaultdict

class IntrusionDetector:
    def __init__(self):
        self.connection_tracker = defaultdict(list)
        # Demo-friendly threshold
        self.port_scan_threshold = 3  # lowered for demo
        self.failed_login_threshold = 3
        self.suspicious_ips = set()
        self.skipped_payloads = 0
        self.alert_suppression = {}  # to prevent duplicate alerts

    # -------------------------
    # Helper: avoid scanning binary/encrypted payloads
    # -------------------------
    def is_printable_text(self, s, threshold=0.9):
        try:
            if isinstance(s, bytes):
                s = s.decode('utf-8', errors='ignore')
        except Exception:
            return False
        if not s:
            return False
        printable = sum(1 for ch in s if 32 <= ord(ch) <= 126)
        return (printable / len(s)) >= threshold

    def should_emit(self, src_ip, atype, cooldown=30):
        """Prevent duplicate alerts within cooldown seconds"""
        key = (src_ip, atype)
        now = time.time()
        last = self.alert_suppression.get(key, 0)
        if now - last < cooldown:
            return False
        self.alert_suppression[key] = now
        return True

    def detect_port_scan(self, src_ip, dst_port):
        """Detect port scanning attempts"""
        self.connection_tracker[src_ip].append(dst_port)

        unique_ports = set(self.connection_tracker[src_ip])
        if len(unique_ports) >= self.port_scan_threshold:
            return {
                "type": "PORT_SCAN",
                "severity": "HIGH",
                "src_ip": src_ip,
                "ports_scanned": list(unique_ports),
                "description": f"Port scan detected from {src_ip}",
                "timestamp": datetime.now().isoformat()
            }
        return None

    def detect_brute_force(self, src_ip, failed_attempts):
        """Detect brute force login attempts"""
        if failed_attempts >= self.failed_login_threshold:
            return {
                "type": "BRUTE_FORCE",
                "severity": "CRITICAL",
                "src_ip": src_ip,
                "failed_attempts": failed_attempts,
                "description": f"Brute force attack detected from {src_ip}",
                "timestamp": datetime.now().isoformat()
            }
        return None

    def detect_dos_attack(self, src_ip, request_count, time_window):
        """Detect DoS attacks based on request rate"""
        requests_per_second = request_count / time_window

        # Demo-friendly threshold (was 100)
        if requests_per_second > 20:
            return {
                "type": "DOS_ATTACK",
                "severity": "CRITICAL",
                "src_ip": src_ip,
                "request_rate": requests_per_second,
                "description": f"DoS attack detected from {src_ip}",
                "timestamp": datetime.now().isoformat()
            }
        return None

    def detect_suspicious_traffic(self, src_ip, dst_ip, protocol, size):
        """Detect suspicious traffic patterns"""
        if size > 65000:
            return {
                "type": "SUSPICIOUS_PACKET",
                "severity": "MEDIUM",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "packet_size": size,
                "description": f"Unusually large packet detected from {src_ip}",
                "timestamp": datetime.now().isoformat()
            }
        return None

    def detect_sql_injection(self, payload):
        """Detect SQL injection attempts"""
        sql_keywords = ['SELECT', 'DROP', 'INSERT', 'UPDATE', 'DELETE',
                        'UNION', 'OR 1=1', '--', ';--']
        payload_upper = payload.upper()
        for keyword in sql_keywords:
            if keyword in payload_upper:
                return {
                    "type": "SQL_INJECTION",
                    "severity": "CRITICAL",
                    "payload": payload[:100],
                    "description": "SQL injection attempt detected",
                    "timestamp": datetime.now().isoformat()
                }
        return None

    def analyze_traffic(self, traffic_data):
        """Analyze demo traffic (DEMO mode)"""
        intrusions = []

        # Port scan
        port_scan = self.detect_port_scan(
            traffic_data.get('src_ip'),
            traffic_data.get('dst_port')
        )
        if port_scan:
            intrusions.append(port_scan)

        # Brute force
        if 'failed_login_attempts' in traffic_data:
            brute_force = self.detect_brute_force(
                traffic_data.get('src_ip'),
                traffic_data.get('failed_login_attempts')
            )
            if brute_force:
                intrusions.append(brute_force)

        # DoS
        if 'request_count' in traffic_data:
            dos = self.detect_dos_attack(
                traffic_data.get('src_ip'),
                traffic_data.get('request_count'),
                traffic_data.get('time_window', 1)
            )
            if dos:
                intrusions.append(dos)

        # Suspicious packet
        suspicious = self.detect_suspicious_traffic(
            traffic_data.get('src_ip'),
            traffic_data.get('dst_ip'),
            traffic_data.get('protocol'),
            traffic_data.get('size', 0)
        )
        if suspicious:
            intrusions.append(suspicious)

        # SQLi check
        payload = traffic_data.get('payload', '')
        if payload:
            if isinstance(payload, bytes):
                payload = payload.decode('utf-8', errors='ignore')
            if len(payload) > 16 and self.is_printable_text(payload):
                sql_inj = self.detect_sql_injection(payload)
                if sql_inj:
                    intrusions.append(sql_inj)
        return intrusions

    def generate_demo_traffic(self):
        """Generate demo traffic for testing"""
        traffic_types = [
            {'src_ip': '192.168.1.100', 'dst_port': random.randint(20, 1024),
             'protocol': 'TCP', 'size': 1500},
            {'src_ip': '10.0.0.50', 'failed_login_attempts': 5,
             'protocol': 'SSH', 'size': 512},
            {'src_ip': '172.16.0.25', 'dst_ip': '192.168.1.1',
             'request_count': 150, 'time_window': 1,
             'protocol': 'HTTP', 'size': 2000},
            {'src_ip': '203.0.113.45', 'dst_ip': '192.168.1.10',
             'protocol': 'TCP', 'size': 70000},
            {'src_ip': '198.51.100.30',
             'payload': "SELECT * FROM users WHERE username='admin' OR 1=1--",
             'protocol': 'HTTP', 'size': 256}
        ]
        return random.choice(traffic_types)

    def analyze_real_traffic(self, packet_info):
        """Analyze real network packet (REAL mode)"""
        intrusions = []

        src_ip = packet_info.get('src_ip')
        dst_ip = packet_info.get('dst_ip')
        dst_port = packet_info.get('dst_port')
        src_port = packet_info.get('src_port')
        protocol = packet_info.get('protocol')
        payload = packet_info.get('payload', '')

        if isinstance(payload, bytes):
            payload_str = payload.decode('utf-8', errors='ignore')
        else:
            payload_str = str(payload)

        # === Skip encrypted/system ports and noisy UDP ===
        skip_ports = {443, 53, 123, 465, 993, 995}
        if dst_port in skip_ports or src_port in skip_ports:
            self.skipped_payloads += 1
            return intrusions
        if protocol == 'UDP' and dst_port != 53 and src_port != 53:
            self.skipped_payloads += 1
            return intrusions

        # Connection tracking
        if not hasattr(self, 'real_connections'):
            self.real_connections = {}

        if src_ip not in self.real_connections:
            self.real_connections[src_ip] = {
                'ports': set(),
                'packet_count': 0,
                'first_seen': datetime.now()
            }

        if dst_port:
            self.real_connections[src_ip]['ports'].add(dst_port)
        self.real_connections[src_ip]['packet_count'] += 1

        # PORT SCAN
        if len(self.real_connections[src_ip]['ports']) >= self.port_scan_threshold:
            ports_list = sorted(list(self.real_connections[src_ip]['ports']))
            if self.should_emit(src_ip, "PORT_SCAN"):
                intrusions.append({
                    'type': 'PORT_SCAN',
                    'severity': 'HIGH',
                    'description': f'Port scan detected from {src_ip} - {len(ports_list)} ports scanned',
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'ports_scanned': ports_list[:10],
                    'total_ports': len(ports_list),
                    'protocol': protocol,
                    'scan_type': packet_info.get('scan_type', 'Sequential Scan'),
                    'packet_count': self.real_connections[src_ip]['packet_count'],
                    'timestamp': datetime.now().isoformat()
                })
            # keep ports list

        # DOS ATTACK (demo-friendly)
        pkt_count = self.real_connections[src_ip]['packet_count']
        print(f"DEBUG IDS: {src_ip} packet_count={pkt_count} ports={sorted(list(self.real_connections[src_ip]['ports']))}")
        if pkt_count > 20:
            if self.should_emit(src_ip, "DOS_ATTACK"):
                intrusions.append({
                    'type': 'DOS_ATTACK',
                    'severity': 'CRITICAL',
                    'description': f'Possible DoS attack from {src_ip} - {pkt_count} packets',
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'protocol': protocol,
                    'packet_count': pkt_count,
                    'packet_size': packet_info.get('packet_size'),
                    'attack_duration': str(datetime.now() - self.real_connections[src_ip]['first_seen']),
                    'timestamp': datetime.now().isoformat()
                })
            self.real_connections[src_ip]['packet_count'] = 0

        # --- Payload-based detections ---
        MIN_PAYLOAD_LEN = 16
        if not payload_str or len(payload_str) < MIN_PAYLOAD_LEN:
            self.skipped_payloads += 1
            payload_is_text = False
        else:
            payload_is_text = self.is_printable_text(payload_str, threshold=0.9)

        # SQL Injection
        sql_patterns = ['SELECT', 'UNION', 'DROP', 'INSERT', 'DELETE', 'UPDATE', '--', 'OR 1=1', 'OR 1=0', '; DROP']
        if payload_is_text and any(p in payload_str.upper() for p in sql_patterns):
            if self.should_emit(src_ip, "SQL_INJECTION"):
                intrusions.append({
                    'type': 'SQL_INJECTION',
                    'severity': 'CRITICAL',
                    'description': f'SQL injection attempt detected from {src_ip}',
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'protocol': protocol,
                    'payload_preview': payload_str[:100],
                    'timestamp': datetime.now().isoformat()
                })

        # XSS
        xss_patterns = ['<script', 'javascript:', 'onerror=', 'onload=', 'onclick=', '<iframe', 'alert(']
        if payload_is_text and any(p in payload_str.lower() for p in xss_patterns):
            if self.should_emit(src_ip, "XSS_ATTACK"):
                intrusions.append({
                    'type': 'XSS_ATTACK',
                    'severity': 'HIGH',
                    'description': f'Cross-site scripting attempt from {src_ip}',
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'protocol': protocol,
                    'payload_preview': payload_str[:100],
                    'timestamp': datetime.now().isoformat()
                })

        # COMMAND INJECTION
        cmd_patterns = ['system(', 'exec(', 'shell_exec', 'passthru', '&&', '||', ';', '`', '$(']
        if payload_is_text and any(p in payload_str.lower() for p in cmd_patterns):
            if self.should_emit(src_ip, "COMMAND_INJECTION"):
                intrusions.append({
                    'type': 'COMMAND_INJECTION',
                    'severity': 'CRITICAL',
                    'description': f'Command injection attempt from {src_ip}',
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'protocol': protocol,
                    'payload_preview': payload_str[:100],
                    'timestamp': datetime.now().isoformat()
                })

        # SUSPICIOUS PACKET SIZE
        if packet_info.get('packet_size', 0) > 65000:
            if self.should_emit(src_ip, "SUSPICIOUS_PACKET"):
                intrusions.append({
                    'type': 'SUSPICIOUS_PACKET',
                    'severity': 'MEDIUM',
                    'description': f'Unusually large packet from {src_ip} ({packet_info.get("packet_size")} bytes)',
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'packet_size': packet_info.get('packet_size'),
                    'protocol': protocol,
                    'timestamp': datetime.now().isoformat()
                })

        # BRUTE FORCE
        auth_ports = [21, 22, 23, 3389, 5900]
        if dst_port in auth_ports and self.real_connections[src_ip]['packet_count'] > 20:
            if self.should_emit(src_ip, "BRUTE_FORCE"):
                intrusions.append({
                    'type': 'BRUTE_FORCE',
                    'severity': 'HIGH',
                    'description': f'Possible brute force attack on {dst_ip}:{dst_port}',
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'protocol': protocol,
                    'attempt_count': self.real_connections[src_ip]['packet_count'],
                    'timestamp': datetime.now().isoformat()
                })

        return intrusions

    def _get_service_name(self, port):
        """Get common service name for port"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            80: 'HTTP', 443: 'HTTPS', 3306: 'MySQL', 3389: 'RDP',
            5432: 'PostgreSQL', 5900: 'VNC', 8080: 'HTTP-ALT'
        }
        return services.get(port, f'Port {port}')
