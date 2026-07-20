# packet_sniffer.py
from scapy.all import AsyncSniffer, sniff, IP, TCP, UDP, Raw, get_if_list, get_if_addr
import threading
from datetime import datetime
import time

class PacketSniffer:
    def __init__(self, ids, blockchain):
        self.ids = ids
        self.blockchain = blockchain
        self.sniffing = False
        self.sniffer_thread = None
        self.async_sniffer = None
        self.chosen_iface = None

    # -------------------------
    # Helper: choose a reasonable interface if none provided
    # -------------------------
    def _auto_select_interface(self):
        """
        Return the first Npcap interface that has a non-zero, non-loopback IP address.
        If none found, returns None (which lets scapy pick a default).
        """
        try:
            ifaces = get_if_list()
            for iface in ifaces:
                # skip obvious loopback entry if present
                if 'Loopback' in iface or iface.lower().startswith('lo'):
                    continue
                try:
                    ip = get_if_addr(iface)
                except Exception:
                    ip = None
                if ip and ip != '0.0.0.0' and not ip.startswith('127.'):
                    # Found a candidate
                    return iface
        except Exception as e:
            print(f"DEBUG: error enumerating interfaces: {e}")
        return None

    def packet_callback(self, packet):
        """Analyze captured packet for intrusions"""
        try:
            # debug: always print a short summary to confirm capture
            try:
                print("DEBUG: packet callback:", packet.summary())
            except Exception:
                print("DEBUG: packet callback: <could not summarize packet>")

            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst

                # Extract detailed packet information
                packet_info = {
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'protocol': 'TCP' if TCP in packet else 'UDP' if UDP in packet else 'OTHER',
                    'packet_size': len(packet),
                    'timestamp': datetime.fromtimestamp(packet.time).isoformat() if hasattr(packet, 'time') else None
                }

                # TCP specific details
                if TCP in packet:
                    packet_info['src_port'] = packet[TCP].sport
                    packet_info['dst_port'] = packet[TCP].dport
                    packet_info['tcp_flags'] = int(packet[TCP].flags)

                    # Detect SYN / NULL / XMAS scans heuristically
                    flags_val = int(packet[TCP].flags)
                    if flags_val == 0x02:  # SYN
                        packet_info['scan_type'] = 'SYN Scan'
                    elif flags_val == 0x00:  # NULL
                        packet_info['scan_type'] = 'NULL Scan'
                    elif flags_val == 0x29:  # XMAS (FIN+PSH+URG)
                        packet_info['scan_type'] = 'XMAS Scan'

                # UDP specific details
                if UDP in packet:
                    packet_info['src_port'] = packet[UDP].sport
                    packet_info['dst_port'] = packet[UDP].dport

                # Extract payload
                if Raw in packet:
                    try:
                        payload = packet[Raw].load.decode('utf-8', errors='ignore')
                        packet_info['payload'] = payload[:200]  # First 200 chars

                        # Extract HTTP-ish details conservatively
                        if 'HTTP' in payload or payload.startswith(('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS')):
                            # Extract HTTP method and path
                            if payload.startswith(('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS')):
                                parts = payload.split(' ')
                                if len(parts) >= 2:
                                    packet_info['http_method'] = parts[0]
                                    packet_info['http_path'] = parts[1]

                            # Extract Host header
                            if 'Host:' in payload:
                                host_start = payload.find('Host:') + len('Host:')
                                host_end = payload.find('\r\n', host_start)
                                if host_end > host_start:
                                    packet_info['host'] = payload[host_start:host_end].strip()

                            # Extract User-Agent if present
                            if 'User-Agent:' in payload:
                                ua_start = payload.find('User-Agent:') + len('User-Agent:')
                                ua_end = payload.find('\r\n', ua_start)
                                if ua_end > ua_start:
                                    packet_info['user_agent'] = payload[ua_start:ua_end].strip()

                    except Exception:
                        packet_info['payload'] = '[Binary Data]'

                # Analyze for intrusions with detailed info
                intrusions = []
                try:
                    intrusions = self.ids.analyze_real_traffic(packet_info)
                except Exception as e:
                    print(f"Error in IDS analysis: {e}")

                # Add to blockchain (if any intrusions)
                for intrusion in intrusions:
                    try:
                        intrusion['mode'] = 'REAL'
                        block = self.blockchain.add_block(intrusion)
                        port_info = f":{packet_info.get('src_port', 'N/A')}" if packet_info.get('src_port') else ""
                        print(f"[REAL MODE] {intrusion.get('type','UNKNOWN')} detected from {src_ip}{port_info} -> Block #{block.index}")
                    except Exception as e:
                        print(f"Error saving intrusion block: {e}")

        except Exception as e:
            print(f"Error processing packet: {e}")

    def start_sniffing(self, interface=None, packet_count=0):
        """
        Start packet capture.
        - interface: optional scapy/Npcap interface string (e.g. '\\Device\\NPF_{...}').
                     If None, an attempt is made to auto-select a suitable interface.
        - packet_count: 0 (default) means run indefinitely until stop_sniffing() is called.
                        >0 will capture that many packets then return.
        Uses AsyncSniffer for the indefinite mode so the sniffer keeps running in background.
        """
        if self.sniffing:
            print("DEBUG: Packet sniffer already running.")
            return

        # choose interface if none provided
        chosen_iface = interface or self._auto_select_interface()
        self.chosen_iface = chosen_iface
        self.sniffing = True

        print(f"DEBUG: Starting packet capture on interface: {chosen_iface or 'default (scapy choice)'} (packet_count={packet_count})")

        try:
            if packet_count and packet_count > 0:
                # Blocking sniff for a limited number of packets - run inside thread (app already starts this in a thread)
                sniff_kwargs = {
                    "prn": self.packet_callback,
                    "store": False,
                    "iface": chosen_iface,
                    "promisc": True,
                    "count": packet_count,
                    "timeout": max(5, packet_count)  # safety timeout
                }
                sniff(**sniff_kwargs)
                # finished capture
                print("DEBUG: Finite sniff complete.")
                self.sniffing = False
                return
            else:
                # Indefinite mode: use AsyncSniffer so sniff runs in background
                self.async_sniffer = AsyncSniffer(
                    prn=self.packet_callback,
                    store=False,
                    iface=chosen_iface,
                    promisc=True
                )
                self.async_sniffer.start()
                print("DEBUG: AsyncSniffer started (background).")
                # Keep this method's caller thread alive while sniffing so thread shows as alive
                # Many parts of the app rely on the monitor thread being alive; keep a loop until stopped.
                try:
                    while self.sniffing:
                        time.sleep(0.5)
                finally:
                    # If loop ends, ensure async sniffer is stopped
                    if self.async_sniffer:
                        try:
                            self.async_sniffer.stop()
                        except Exception:
                            pass
                    self.async_sniffer = None
                    self.sniffing = False
                    print("DEBUG: AsyncSniffer stopped and thread exiting.")
        except Exception as e:
            print(f"Error during packet capture: {e}")
            self.sniffing = False
            if self.async_sniffer:
                try:
                    self.async_sniffer.stop()
                except Exception:
                    pass
                self.async_sniffer = None
            print("Make sure you're running with administrator/root privileges and the correct Npcap driver is installed")

    def stop_sniffing(self):
        """Stop packet capture"""
        print("DEBUG: stop_sniffing called")
        self.sniffing = False
        # If using AsyncSniffer, stop it explicitly
        if self.async_sniffer:
            try:
                self.async_sniffer.stop()
                print("DEBUG: async_sniffer.stop() called")
            except Exception as e:
                print(f"DEBUG: error stopping async sniffer: {e}")
            self.async_sniffer = None

    def get_available_interfaces(self):
        """Get list of network interfaces (returns list)"""
        try:
            ifaces = get_if_list()
            result = []
            for iface in ifaces:
                try:
                    ip = get_if_addr(iface)
                except Exception:
                    ip = None
                result.append({"iface": iface, "ip": ip})
            return result
        except Exception as e:
            print(f"Error listing interfaces: {e}")
            return []
