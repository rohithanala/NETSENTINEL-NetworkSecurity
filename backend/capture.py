from __future__ import annotations

import socket
import subprocess
import threading
import time
from datetime import datetime, timezone

from scapy.all import (
    ARP,
    Ether,
    ICMP,
    IP,
    IPv6,
    TCP,
    UDP,
    conf,
    get_if_addr,
    get_if_hwaddr,
    sniff,
)

from .detectors import DetectionEngine
from .models import Alert, Device, Traffic, db


# ============================================================
# NETSENTINEL
# LIVE PACKET CAPTURE MANAGER
# ============================================================


class CaptureManager:
    """
    NETSENTINEL live packet capture manager.

    Responsibilities:
        - Immediate Scapy live packet capture
        - Packet parsing
        - Traffic persistence
        - Device discovery
        - Windows MAC/neighbor enrichment
        - Hostname resolution
        - IDS evaluation
        - Alert persistence
        - Runtime capture statistics
        - Socket.IO packet/alert events

    Important architecture:
        Scapy capture starts immediately after the capture
        thread begins.

        Expensive device enrichment is NOT allowed to block
        the packet capture startup.
    """

    def __init__(self, app=None):
        self.app = self._unwrap_app(app)

        self.running = False
        self.thread = None

        self.started_at = None
        self.last_packet_at = None
        self.last_error = None

        self.packets_captured = 0
        self.interface = None

        self.detector = None

        if self.app is not None:
            try:
                self.detector = DetectionEngine(self.app)
            except Exception as exc:
                self.last_error = str(exc)

        # ----------------------------------------------------
        # Identity caches
        # ----------------------------------------------------

        self.hostname_cache = {}
        self.mac_cache = {}

        self.local_ip_cache = set()
        self.local_mac_cache = set()

        self.cache_lock = threading.RLock()

        # ----------------------------------------------------
        # Refresh timing
        # ----------------------------------------------------

        self.last_neighbor_refresh = 0.0
        self.neighbor_refresh_interval = 10.0

        self.last_identity_refresh = 0.0
        self.identity_refresh_interval = 30.0

        # ----------------------------------------------------
        # Socket.IO
        # ----------------------------------------------------

        self.socketio = None

    # ========================================================
    # FLASK APP HANDLING
    # ========================================================

    @staticmethod
    def _unwrap_app(app):
        """
        Resolve Flask application objects safely.

        Background threads must never depend on a request
        context or a LocalProxy.
        """

        if app is None:
            return None

        try:
            getter = getattr(
                app,
                "_get_current_object",
                None,
            )

            if callable(getter):
                return getter()

        except Exception:
            pass

        return app

    # ========================================================
    # CONFIGURATION
    # ========================================================

    def configure(self, app, socketio=None):
        real_app = self._unwrap_app(app)

        self.app = real_app
        self.socketio = socketio

        if real_app is not None:
            try:
                if (
                    self.detector is None
                    or getattr(
                        self.detector,
                        "app",
                        None,
                    )
                    is not real_app
                ):
                    self.detector = DetectionEngine(
                        real_app
                    )

            except Exception as exc:
                self.set_error(exc)

    # ========================================================
    # TIME
    # ========================================================

    @staticmethod
    def utc_now():
        return datetime.now(timezone.utc)

    # ========================================================
    # ERROR HANDLING
    # ========================================================

    def set_error(self, exc):
        try:
            self.last_error = str(exc)
        except Exception:
            self.last_error = "Unknown capture error."

    # ========================================================
    # IP HELPERS
    # ========================================================

    @staticmethod
    def is_valid_ip(ip):
        if not ip:
            return False

        value = str(ip).strip()

        return value not in {
            "",
            "0.0.0.0",
            "::",
            "255.255.255.255",
        }

    @staticmethod
    def is_ipv4(ip):
        if not ip:
            return False

        return "." in str(ip)

    @staticmethod
    def is_private_or_local_ip(ip):
        if not ip:
            return False

        value = str(ip).strip().lower()

        if value.startswith("10."):
            return True

        if value.startswith("192.168."):
            return True

        if value.startswith("172."):
            try:
                second_octet = int(
                    value.split(".")[1]
                )

                if 16 <= second_octet <= 31:
                    return True

            except (ValueError, IndexError):
                pass

        if value.startswith("169.254."):
            return True

        if value == "::1":
            return True

        if value.startswith("fe80:"):
            return True

        if value.startswith("fc"):
            return True

        if value.startswith("fd"):
            return True

        return False

    # ========================================================
    # MAC HELPERS
    # ========================================================

    @staticmethod
    def normalize_mac(mac):
        if not mac:
            return None

        value = str(mac).strip().upper()

        invalid = {
            "",
            "00:00:00:00:00:00",
            "FF:FF:FF:FF:FF:FF",
            "N/A",
            "NA",
            "NONE",
            "NULL",
            "UNKNOWN",
            "UNSPECIFIED",
        }

        if value in invalid:
            return None

        compact = (
            value
            .replace(":", "")
            .replace("-", "")
            .replace(".", "")
            .replace(" ", "")
        )

        if len(compact) != 12:
            return None

        try:
            int(compact, 16)
        except ValueError:
            return None

        normalized = ":".join(
            compact[index:index + 2]
            for index in range(0, 12, 2)
        )

        if normalized in {
            "00:00:00:00:00:00",
            "FF:FF:FF:FF:FF:FF",
        }:
            return None

        return normalized

    # ========================================================
    # LOCAL COMPUTER IDENTITY
    # ========================================================

    def discover_local_identity(self):
        local_ips = set()
        local_macs = set()

        # ----------------------------------------------------
        # Hostname/IP information
        # ----------------------------------------------------

        try:
            hostname = socket.gethostname()

            try:
                _, _, addresses = socket.gethostbyname_ex(
                    hostname
                )

                for ip in addresses:
                    if self.is_valid_ip(ip):
                        local_ips.add(ip)

            except Exception:
                pass

            try:
                addr_info = socket.getaddrinfo(
                    hostname,
                    None,
                    socket.AF_UNSPEC,
                    socket.SOCK_STREAM,
                )

                for entry in addr_info:
                    sockaddr = entry[4]

                    if not sockaddr:
                        continue

                    ip = sockaddr[0]

                    if self.is_valid_ip(ip):
                        local_ips.add(ip)

            except Exception:
                pass

        except Exception:
            pass

        # ----------------------------------------------------
        # Selected capture interface
        # ----------------------------------------------------

        if self.interface:
            try:
                interface_ip = get_if_addr(
                    self.interface
                )

                if self.is_valid_ip(interface_ip):
                    local_ips.add(interface_ip)

            except Exception:
                pass

            try:
                interface_mac = get_if_hwaddr(
                    self.interface
                )

                interface_mac = self.normalize_mac(
                    interface_mac
                )

                if interface_mac:
                    local_macs.add(interface_mac)

            except Exception:
                pass

        # ----------------------------------------------------
        # Scapy default interface
        # ----------------------------------------------------

        try:
            default_interface = conf.iface

            try:
                default_ip = get_if_addr(
                    default_interface
                )

                if self.is_valid_ip(default_ip):
                    local_ips.add(default_ip)

            except Exception:
                pass

            try:
                default_mac = get_if_hwaddr(
                    default_interface
                )

                default_mac = self.normalize_mac(
                    default_mac
                )

                if default_mac:
                    local_macs.add(default_mac)

            except Exception:
                pass

        except Exception:
            pass

        # ----------------------------------------------------
        # Save caches
        # ----------------------------------------------------

        with self.cache_lock:
            self.local_ip_cache.update(local_ips)
            self.local_mac_cache.update(local_macs)

        self.last_identity_refresh = time.time()

        return local_ips, local_macs

    # ========================================================
    # WINDOWS NEIGHBOR TABLE
    # ========================================================

    def refresh_windows_neighbors(self, force=False):
        now = time.time()

        if not force:
            if (
                now - self.last_neighbor_refresh
                < self.neighbor_refresh_interval
            ):
                return 0

        self.last_neighbor_refresh = now

        discovered = 0

        # ----------------------------------------------------
        # Get-NetNeighbor
        # ----------------------------------------------------

        try:
            command = [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                (
                    "Get-NetNeighbor "
                    "| Select-Object "
                    "IPAddress,LinkLayerAddress,State "
                    "| ConvertTo-Csv "
                    "-NoTypeInformation"
                ),
            ]

            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=8,
                creationflags=getattr(
                    subprocess,
                    "CREATE_NO_WINDOW",
                    0,
                ),
            )

            if result.returncode == 0:
                lines = result.stdout.splitlines()

                for line in lines[1:]:
                    line = line.strip()

                    if not line:
                        continue

                    try:
                        parts = [
                            part.strip().strip('"')
                            for part in line.split(",")
                        ]

                        if len(parts) < 2:
                            continue

                        ip = parts[0]
                        mac = parts[1]

                    except Exception:
                        continue

                    if not self.is_valid_ip(ip):
                        continue

                    normalized_mac = self.normalize_mac(
                        mac
                    )

                    if not normalized_mac:
                        continue

                    if normalized_mac.startswith(
                        "01:00:5E:"
                    ):
                        continue

                    with self.cache_lock:
                        self.mac_cache[ip] = (
                            normalized_mac
                        )

                    discovered += 1

        except Exception:
            pass

        # ----------------------------------------------------
        # ARP fallback
        # ----------------------------------------------------

        try:
            result = subprocess.run(
                ["arp", "-a"],
                capture_output=True,
                text=True,
                timeout=8,
                creationflags=getattr(
                    subprocess,
                    "CREATE_NO_WINDOW",
                    0,
                ),
            )

            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    line = line.strip()

                    if not line:
                        continue

                    parts = line.split()

                    if len(parts) < 2:
                        continue

                    ip = parts[0]
                    mac = parts[1]

                    if not self.is_valid_ip(ip):
                        continue

                    normalized_mac = self.normalize_mac(
                        mac
                    )

                    if not normalized_mac:
                        continue

                    if normalized_mac.startswith(
                        "01:00:5E:"
                    ):
                        continue

                    with self.cache_lock:
                        self.mac_cache[ip] = (
                            normalized_mac
                        )

                    discovered += 1

        except Exception:
            pass

        return discovered

    # ========================================================
    # MAC LOOKUP
    # ========================================================

    def lookup_mac(self, ip, packet=None):
        if not ip:
            return None

        value = str(ip).strip()

        if not self.is_valid_ip(value):
            return None

        # ----------------------------------------------------
        # Cache
        # ----------------------------------------------------

        with self.cache_lock:
            cached = self.mac_cache.get(value)

            if cached:
                return cached

        # ----------------------------------------------------
        # Local computer
        # ----------------------------------------------------

        with self.cache_lock:
            is_local = value in self.local_ip_cache
            local_macs = list(
                self.local_mac_cache
            )

        if is_local and local_macs:
            return local_macs[0]

        # ----------------------------------------------------
        # ARP packet
        # ----------------------------------------------------

        try:
            if packet is not None and packet.haslayer(
                ARP
            ):
                arp = packet[ARP]

                if str(arp.psrc) == value:
                    mac = self.normalize_mac(
                        arp.hwsrc
                    )

                    if mac:
                        with self.cache_lock:
                            self.mac_cache[value] = mac

                        return mac

                if str(arp.pdst) == value:
                    mac = self.normalize_mac(
                        arp.hwdst
                    )

                    if mac:
                        with self.cache_lock:
                            self.mac_cache[value] = mac

                        return mac

        except Exception:
            pass

        # ----------------------------------------------------
        # Windows neighbor cache
        # ----------------------------------------------------

        self.refresh_windows_neighbors()

        with self.cache_lock:
            cached = self.mac_cache.get(value)

        if cached:
            return cached

        # ----------------------------------------------------
        # Ethernet source MAC
        #
        # Only trust this for the local computer.
        # Never assign a local Ethernet destination MAC
        # to a remote Internet address.
        # ----------------------------------------------------

        try:
            if packet is not None and packet.haslayer(
                Ether
            ):
                ether = packet[Ether]

                source_mac = self.normalize_mac(
                    ether.src
                )

                if (
                    value in self.local_ip_cache
                    and source_mac
                ):
                    with self.cache_lock:
                        self.mac_cache[value] = (
                            source_mac
                        )

                    return source_mac

        except Exception:
            pass

        return None

    # ========================================================
    # HOSTNAME RESOLUTION
    # ========================================================

    def resolve_hostname(self, ip):
        if not ip:
            return None

        value = str(ip).strip()

        if not self.is_valid_ip(value):
            return None

        # ----------------------------------------------------
        # Cache
        # ----------------------------------------------------

        with self.cache_lock:
            if value in self.hostname_cache:
                return self.hostname_cache[value]

            is_local = value in self.local_ip_cache

        hostname = None

        # ----------------------------------------------------
        # Local computer
        # ----------------------------------------------------

        if is_local:
            try:
                hostname = socket.gethostname()
            except Exception:
                hostname = None

        # ----------------------------------------------------
        # Private/local reverse DNS
        # ----------------------------------------------------

        if not hostname and self.is_private_or_local_ip(
            value
        ):
            try:
                result = socket.gethostbyaddr(
                    value
                )

                if result:
                    hostname = result[0]

            except Exception:
                hostname = None

        # ----------------------------------------------------
        # Cache result
        # ----------------------------------------------------

        with self.cache_lock:
            self.hostname_cache[value] = hostname

        return hostname

    # ========================================================
    # DEVICE UPDATE
    # ========================================================

    def update_device(
        self,
        ip,
        mac_address=None,
        hostname=None,
        packet_increment=1,
    ):
        if not self.is_valid_ip(ip):
            return None

        value = str(ip).strip()

        device = (
            Device.query
            .filter_by(
                ip_address=value,
                is_demo=False,
            )
            .first()
        )

        now = self.utc_now()

        # ----------------------------------------------------
        # Create
        # ----------------------------------------------------

        if device is None:
            device = Device(
                ip_address=value,
                first_seen=now,
                last_seen=now,
                packet_count=0,
                status="normal",
                is_demo=False,
            )

            db.session.add(device)

        # ----------------------------------------------------
        # MAC
        # ----------------------------------------------------

        normalized_mac = self.normalize_mac(
            mac_address
        )

        if normalized_mac:
            device.mac_address = normalized_mac

        # ----------------------------------------------------
        # Hostname
        # ----------------------------------------------------

        if hostname:
            hostname_value = str(
                hostname
            ).strip()

            if hostname_value:
                device.hostname = hostname_value

        # ----------------------------------------------------
        # Activity
        # ----------------------------------------------------

        device.last_seen = now

        device.packet_count = (
            int(device.packet_count or 0)
            + int(packet_increment or 0)
        )

        if device.status not in {
            "suspicious",
            "critical",
        }:
            device.status = "normal"

        return device

    # ========================================================
    # EXISTING DEVICE ENRICHMENT
    # ========================================================

    def enrich_existing_devices(self):
        """
        Enrich existing devices.

        This function is intentionally separate from the
        packet-capture startup path so it cannot prevent
        Scapy from beginning live capture.
        """

        self.discover_local_identity()

        self.refresh_windows_neighbors(
            force=True
        )

        devices = (
            Device.query
            .filter_by(is_demo=False)
            .limit(2000)
            .all()
        )

        changed = False
        now = self.utc_now()

        for device in devices:
            ip = device.ip_address

            if not self.is_valid_ip(ip):
                continue

            # ------------------------------------------------
            # MAC
            # ------------------------------------------------

            if not device.mac_address:
                mac = self.lookup_mac(ip)

                if mac:
                    device.mac_address = mac
                    changed = True

            # ------------------------------------------------
            # Hostname
            # ------------------------------------------------

            if not device.hostname:
                hostname = self.resolve_hostname(
                    ip
                )

                if hostname:
                    device.hostname = hostname
                    changed = True

            # ------------------------------------------------
            # Activity status
            # ------------------------------------------------

            if device.last_seen:
                try:
                    last_seen = device.last_seen

                    if last_seen.tzinfo is None:
                        last_seen = last_seen.replace(
                            tzinfo=timezone.utc
                        )

                    age = (
                        now - last_seen
                    ).total_seconds()

                    if device.status in {
                        "suspicious",
                        "critical",
                    }:
                        continue

                    if age <= 30:
                        new_status = "normal"
                    elif age <= 120:
                        new_status = "normal"
                    else:
                        new_status = "normal"

                    if device.status != new_status:
                        device.status = new_status
                        changed = True

                except Exception:
                    pass

        if changed:
            db.session.commit()

    # ========================================================
    # TCP FLAGS
    # ========================================================

    @staticmethod
    def get_tcp_flags(packet):
        try:
            if packet.haslayer(TCP):
                return str(
                    packet[TCP].flags
                )
        except Exception:
            pass

        return None

    # ========================================================
    # PACKET PARSING
    # ========================================================

    def parse_packet(self, packet):
        if packet is None:
            return None

        timestamp = self.utc_now()

        source_ip = None
        destination_ip = None

        protocol = "OTHER"

        source_port = None
        destination_port = None

        try:
            packet_size = len(packet)
        except Exception:
            packet_size = 0

        # ----------------------------------------------------
        # IPv4
        # ----------------------------------------------------

        if packet.haslayer(IP):
            ip_layer = packet[IP]

            source_ip = str(
                ip_layer.src
            )

            destination_ip = str(
                ip_layer.dst
            )

            if packet.haslayer(TCP):
                protocol = "TCP"

                source_port = int(
                    packet[TCP].sport
                )

                destination_port = int(
                    packet[TCP].dport
                )

            elif packet.haslayer(UDP):
                protocol = "UDP"

                source_port = int(
                    packet[UDP].sport
                )

                destination_port = int(
                    packet[UDP].dport
                )

            elif packet.haslayer(ICMP):
                protocol = "ICMP"

            else:
                protocol = str(
                    getattr(
                        ip_layer,
                        "proto",
                        "IP",
                    )
                )

        # ----------------------------------------------------
        # IPv6
        # ----------------------------------------------------

        elif packet.haslayer(IPv6):
            ip_layer = packet[IPv6]

            source_ip = str(
                ip_layer.src
            )

            destination_ip = str(
                ip_layer.dst
            )

            if packet.haslayer(TCP):
                protocol = "TCP"

                source_port = int(
                    packet[TCP].sport
                )

                destination_port = int(
                    packet[TCP].dport
                )

            elif packet.haslayer(UDP):
                protocol = "UDP"

                source_port = int(
                    packet[UDP].sport
                )

                destination_port = int(
                    packet[UDP].dport
                )

            elif packet.haslayer(ICMP):
                protocol = "ICMP"

            else:
                protocol = str(
                    getattr(
                        ip_layer,
                        "nh",
                        "IPv6",
                    )
                )

        # ----------------------------------------------------
        # ARP
        # ----------------------------------------------------

        elif packet.haslayer(ARP):
            arp = packet[ARP]

            source_ip = str(
                arp.psrc
            )

            destination_ip = str(
                arp.pdst
            )

            protocol = "ARP"

        # ----------------------------------------------------
        # Ignore packets without IP identity
        # ----------------------------------------------------

        if not source_ip and not destination_ip:
            return None

        return {
            "timestamp": timestamp,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "protocol": protocol,
            "source_port": source_port,
            "destination_port": destination_port,
            "packet_size": packet_size,
            "tcp_flags": self.get_tcp_flags(packet),
            "interface": (
                str(self.interface)
                if self.interface
                else None
            ),
            "is_demo": False,
        }

    # ========================================================
    # PACKET PROCESSING
    # ========================================================

    def process_packet(self, packet):
        """
        Process one captured packet.

        The capture counter is incremented immediately when
        a packet reaches this method, rather than only after
        database/IDS processing completes.
        """

        # ----------------------------------------------------
        # Count the packet immediately
        # ----------------------------------------------------

        self.packets_captured += 1
        self.last_packet_at = self.utc_now()

        parsed = self.parse_packet(packet)

        if parsed is None:
            return

        app = self._unwrap_app(
            self.app
        )

        if app is None:
            self.set_error(
                "Flask application is unavailable."
            )
            return

        try:
            with app.app_context():
                self._process_packet_context(
                    packet,
                    parsed,
                )

        except Exception as exc:
            self.set_error(exc)

    # ========================================================
    # CONTEXT-AWARE PROCESSING
    # ========================================================

    def _process_packet_context(
        self,
        packet,
        parsed,
    ):
        source_ip = parsed["source_ip"]

        destination_ip = parsed[
            "destination_ip"
        ]

        protocol = parsed["protocol"]

        # ----------------------------------------------------
        # Refresh identity occasionally
        # ----------------------------------------------------

        now = time.time()

        if (
            now - self.last_identity_refresh
            >= self.identity_refresh_interval
        ):
            try:
                self.discover_local_identity()
            except Exception:
                pass

        if (
            now - self.last_neighbor_refresh
            >= self.neighbor_refresh_interval
        ):
            try:
                self.refresh_windows_neighbors()
            except Exception:
                pass

        # ----------------------------------------------------
        # Identity
        # ----------------------------------------------------

        source_mac = self.lookup_mac(
            source_ip,
            packet,
        )

        destination_mac = self.lookup_mac(
            destination_ip,
            packet,
        )

        source_hostname = self.resolve_hostname(
            source_ip
        )

        destination_hostname = (
            self.resolve_hostname(
                destination_ip
            )
        )

        # ----------------------------------------------------
        # Device tracking
        # ----------------------------------------------------

        try:
            if source_ip:
                self.update_device(
                    ip=source_ip,
                    mac_address=source_mac,
                    hostname=source_hostname,
                    packet_increment=1,
                )

            if destination_ip:
                self.update_device(
                    ip=destination_ip,
                    mac_address=destination_mac,
                    hostname=destination_hostname,
                    packet_increment=1,
                )

            db.session.commit()

        except Exception as exc:
            try:
                db.session.rollback()
            except Exception:
                pass

            self.set_error(exc)

        # ----------------------------------------------------
        # TRAFFIC
        # ----------------------------------------------------

        try:
            traffic = Traffic(
                timestamp=parsed["timestamp"],
                source_ip=source_ip,
                destination_ip=destination_ip,
                source_port=parsed[
                    "source_port"
                ],
                destination_port=parsed[
                    "destination_port"
                ],
                protocol=protocol,
                packet_size=parsed[
                    "packet_size"
                ],
                tcp_flags=parsed[
                    "tcp_flags"
                ],
                interface=parsed[
                    "interface"
                ],
                is_demo=False,
            )

            db.session.add(traffic)
            db.session.commit()

        except Exception as exc:
            try:
                db.session.rollback()
            except Exception:
                pass

            self.set_error(exc)

        # ----------------------------------------------------
        # IDS
        # ----------------------------------------------------

        try:
            app = self._unwrap_app(
                self.app
            )

            if app is not None:
                if (
                    self.detector is None
                    or getattr(
                        self.detector,
                        "app",
                        None,
                    )
                    is not app
                ):
                    self.detector = (
                        DetectionEngine(app)
                    )

            if self.detector is not None:
                detection_packet = {
                    "timestamp": parsed[
                        "timestamp"
                    ],
                    "source_ip": source_ip,
                    "destination_ip": destination_ip,
                    "protocol": protocol,
                    "source_port": parsed[
                        "source_port"
                    ],
                    "destination_port": parsed[
                        "destination_port"
                    ],
                    "packet_size": parsed[
                        "packet_size"
                    ],
                }

                evaluate = getattr(
                    self.detector,
                    "evaluate",
                    None,
                )

                if callable(evaluate):
                    detections = evaluate(
                        detection_packet
                    )

                    if detections:
                        for detection in detections:
                            self._create_alert(
                                detection=detection,
                                source_ip=source_ip,
                                destination_ip=destination_ip,
                                protocol=protocol,
                            )

                else:
                    process_packet = getattr(
                        self.detector,
                        "process_packet",
                        None,
                    )

                    if callable(process_packet):
                        detection_packet[
                            "is_demo"
                        ] = False

                        process_packet(
                            detection_packet
                        )

        except Exception as exc:
            self.set_error(exc)

        # ----------------------------------------------------
        # Socket.IO
        # ----------------------------------------------------

        self.emit_packet(
            parsed=parsed,
            source_mac=source_mac,
            destination_mac=destination_mac,
            source_hostname=source_hostname,
            destination_hostname=destination_hostname,
        )

    # ========================================================
    # ALERT CREATION
    # ========================================================

    def _create_alert(
        self,
        detection,
        source_ip,
        destination_ip,
        protocol,
    ):
        """
        Persist an IDS detection.
        """

        try:
            # ------------------------------------------------
            # Tuple detection
            # ------------------------------------------------

            if isinstance(
                detection,
                tuple,
            ):
                detection_type = (
                    detection[0]
                    if len(detection) > 0
                    else "unknown"
                )

                severity = (
                    detection[1]
                    if len(detection) > 1
                    else "MEDIUM"
                )

                confidence = (
                    detection[2]
                    if len(detection) > 2
                    else 0.5
                )

                description = (
                    detection[3]
                    if len(detection) > 3
                    else "Suspicious activity detected."
                )

            # ------------------------------------------------
            # Dictionary detection
            # ------------------------------------------------

            elif isinstance(
                detection,
                dict,
            ):
                detection_type = detection.get(
                    "detection_type",
                    detection.get(
                        "type",
                        "unknown",
                    ),
                )

                severity = detection.get(
                    "severity",
                    "MEDIUM",
                )

                confidence = detection.get(
                    "confidence",
                    0.5,
                )

                description = detection.get(
                    "description",
                    "Suspicious activity detected.",
                )

                source_ip = detection.get(
                    "source_ip",
                    source_ip,
                )

                destination_ip = detection.get(
                    "destination_ip",
                    destination_ip,
                )

                protocol = detection.get(
                    "protocol",
                    protocol,
                )

            else:
                return

            # ------------------------------------------------
            # Normalize severity
            # ------------------------------------------------

            severity = str(
                severity
            ).upper()

            valid_severities = getattr(
                Alert,
                "VALID_SEVERITIES",
                (
                    "LOW",
                    "MEDIUM",
                    "HIGH",
                    "CRITICAL",
                ),
            )

            if severity not in valid_severities:
                severity = "MEDIUM"

            # ------------------------------------------------
            # Normalize confidence
            # ------------------------------------------------

            try:
                confidence = float(
                    confidence
                )

                if confidence > 1:
                    confidence /= 100.0

            except (
                TypeError,
                ValueError,
            ):
                confidence = 0.5

            confidence = max(
                0.0,
                min(
                    1.0,
                    confidence,
                ),
            )

            # ------------------------------------------------
            # Create alert
            # ------------------------------------------------

            alert = Alert(
                timestamp=self.utc_now(),
                detection_type=str(
                    detection_type
                ),
                source_ip=(
                    str(source_ip)
                    if source_ip
                    else "unknown"
                ),
                destination_ip=(
                    str(destination_ip)
                    if destination_ip
                    else None
                ),
                protocol=(
                    str(protocol)
                    if protocol
                    else None
                ),
                severity=severity,
                confidence=confidence,
                description=str(
                    description
                ),
                status="new",
                is_demo=False,
            )

            db.session.add(alert)
            db.session.commit()

            self.emit_alert(
                alert
            )

        except Exception as exc:
            try:
                db.session.rollback()
            except Exception:
                pass

            self.set_error(exc)

    # ========================================================
    # SCAPY CALLBACK
    # ========================================================

    def _packet_callback(self, packet):
        """
        Scapy packet callback.

        Keep this extremely lightweight.

        The packet immediately enters process_packet(),
        which increments the live capture counter before
        any database or IDS processing occurs.
        """

        if not self.running:
            return

        try:
            self.process_packet(
                packet
            )

        except Exception as exc:
            self.set_error(exc)

    # ========================================================
    # SOCKET.IO PACKET EVENT
    # ========================================================

    def emit_packet(
        self,
        parsed,
        source_mac=None,
        destination_mac=None,
        source_hostname=None,
        destination_hostname=None,
    ):
        if not self.socketio:
            return

        try:
            payload = {
                "timestamp": (
                    parsed["timestamp"]
                    .isoformat()
                ),
                "source_ip": parsed[
                    "source_ip"
                ],
                "destination_ip": parsed[
                    "destination_ip"
                ],
                "protocol": parsed[
                    "protocol"
                ],
                "source_port": parsed[
                    "source_port"
                ],
                "destination_port": parsed[
                    "destination_port"
                ],
                "packet_size": parsed[
                    "packet_size"
                ],
                "tcp_flags": parsed[
                    "tcp_flags"
                ],
                "interface": parsed[
                    "interface"
                ],
                "source_mac": source_mac,
                "destination_mac": destination_mac,
                "source_hostname": source_hostname,
                "destination_hostname": destination_hostname,
            }

            self.socketio.emit(
                "traffic:new",
                payload,
            )

        except Exception:
            pass

    # ========================================================
    # SOCKET.IO ALERT EVENT
    # ========================================================

    def emit_alert(self, alert):
        if not self.socketio:
            return

        try:
            payload = {
                "id": alert.id,
                "timestamp": (
                    alert.timestamp.isoformat()
                    if alert.timestamp
                    else None
                ),
                "detection_type": (
                    alert.detection_type
                ),
                "source_ip": alert.source_ip,
                "destination_ip": (
                    alert.destination_ip
                ),
                "protocol": alert.protocol,
                "severity": alert.severity,
                "confidence": alert.confidence,
                "description": alert.description,
                "status": alert.status,
            }

            self.socketio.emit(
                "alert:new",
                payload,
            )

        except Exception:
            pass

    # ========================================================
    # CAPTURE LOOP
    # ========================================================

    def _capture_loop(self):
        """
        Main background capture thread.

        IMPORTANT:
        Scapy starts FIRST.

        Device enrichment happens only after capture has
        successfully started and therefore cannot block
        the live packet sensor from receiving packets.
        """

        app = self._unwrap_app(
            self.app
        )

        try:
            # ------------------------------------------------
            # INITIAL IDENTITY
            #
            # Keep this lightweight.
            # ------------------------------------------------

            try:
                self.discover_local_identity()
            except Exception:
                pass

            # ------------------------------------------------
            # START LIVE CAPTURE IMMEDIATELY
            # ------------------------------------------------

            if not self.interface:
                raise RuntimeError(
                    "Capture interface is not configured."
                )

            sniff(
                iface=self.interface,
                prn=self._packet_callback,
                store=False,
                stop_filter=lambda packet: (
                    not self.running
                ),
            )

        except Exception as exc:
            self.set_error(exc)

        finally:
            self.running = False

    # ========================================================
    # BACKGROUND ENRICHMENT
    # ========================================================

    def _background_enrichment(self):
        """
        Perform expensive device enrichment separately.

        This function is intentionally independent from the
        Scapy capture loop.
        """

        app = self._unwrap_app(
            self.app
        )

        try:
            self.refresh_windows_neighbors(
                force=True
            )

            if app is not None:
                with app.app_context():
                    self.enrich_existing_devices()

        except Exception as exc:
            self.set_error(exc)

    # ========================================================
    # START
    # ========================================================

    def start(self, interface=None):
        if self.running:
            return {
                "success": True,
                "message": "Capture already running.",
                "interface": (
                    str(self.interface)
                    if self.interface
                    else None
                ),
            }

        self.last_error = None
        self.packets_captured = 0
        self.started_at = self.utc_now()
        self.last_packet_at = None

        # ----------------------------------------------------
        # Interface
        # ----------------------------------------------------

        if interface:
            self.interface = interface

        else:
            try:
                self.interface = conf.iface
            except Exception:
                self.interface = None

        if not self.interface:
            self.last_error = (
                "No network interface available."
            )

            return {
                "success": False,
                "message": self.last_error,
            }

        # ----------------------------------------------------
        # Detector
        # ----------------------------------------------------

        app = self._unwrap_app(
            self.app
        )

        if app is not None:
            try:
                self.detector = (
                    DetectionEngine(app)
                )

            except Exception as exc:
                self.set_error(exc)

                return {
                    "success": False,
                    "message": (
                        "IDS initialization failed."
                    ),
                    "error": str(exc),
                }

        # ----------------------------------------------------
        # Lightweight local identity
        # ----------------------------------------------------

        try:
            self.discover_local_identity()
        except Exception:
            pass

        # ----------------------------------------------------
        # START STATE
        # ----------------------------------------------------

        self.running = True

        # ----------------------------------------------------
        # CAPTURE THREAD
        # ----------------------------------------------------

        self.thread = threading.Thread(
            target=self._capture_loop,
            name="NETSENTINEL-Capture",
            daemon=True,
        )

        self.thread.start()

        # ----------------------------------------------------
        # ENRICHMENT THREAD
        #
        # Does NOT block Scapy.
        # ----------------------------------------------------

        enrichment_thread = threading.Thread(
            target=self._background_enrichment,
            name="NETSENTINEL-Enrichment",
            daemon=True,
        )

        enrichment_thread.start()

        return {
            "success": True,
            "message": "Live capture started.",
            "interface": str(
                self.interface
            ),
        }

    # ========================================================
    # STOP
    # ========================================================

    def stop(self):
        self.running = False

        return {
            "success": True,
            "message": "Capture stopped.",
        }

    # ========================================================
    # STATUS
    # ========================================================

    def status(self):
        uptime_seconds = 0

        if self.started_at:
            try:
                uptime_seconds = int(
                    (
                        self.utc_now()
                        - self.started_at
                    ).total_seconds()
                )

                if uptime_seconds < 0:
                    uptime_seconds = 0

            except Exception:
                uptime_seconds = 0

        return {
            "running": bool(
                self.running
            ),
            "interface": (
                str(self.interface)
                if self.interface
                else None
            ),
            "packets_captured": int(
                self.packets_captured
            ),
            "last_packet_at": (
                self.last_packet_at.isoformat()
                if self.last_packet_at
                else None
            ),
            "last_error": self.last_error,
            "uptime_seconds": int(
                uptime_seconds
            ),
        }


# ============================================================
# GLOBAL CAPTURE MANAGER
# ============================================================

_capture_manager = None


def get_manager(
    app=None,
    socketio=None,
):
    global _capture_manager

    real_app = CaptureManager._unwrap_app(
        app
    )

    if _capture_manager is None:
        _capture_manager = CaptureManager(
            app=real_app
        )

    if real_app is not None:
        _capture_manager.configure(
            app=real_app,
            socketio=socketio,
        )

    elif socketio is not None:
        _capture_manager.socketio = socketio

    return _capture_manager


# ============================================================
# START CAPTURE
# ============================================================

def start_capture(
    app,
    interface=None,
    socketio=None,
):
    real_app = CaptureManager._unwrap_app(
        app
    )

    manager = get_manager(
        app=real_app,
        socketio=socketio,
    )

    return manager.start(
        interface=interface
    )


# ============================================================
# START CAPTURE IF ENABLED
# ============================================================

def start_capture_if_enabled(
    app,
    interface=None,
    socketio=None,
):
    try:
        real_app = CaptureManager._unwrap_app(
            app
        )

        if real_app is None:
            return {
                "success": False,
                "started": False,
                "message": (
                    "Flask application unavailable."
                ),
            }

        config = getattr(
            real_app,
            "config",
            {},
        )

        mode = str(
            config.get(
                "NETSENTINEL_MODE",
                config.get(
                    "MODE",
                    config.get(
                        "mode",
                        "DEMO",
                    ),
                ),
            )
        ).upper()

        monitoring_enabled = config.get(
            "MONITORING_ENABLED",
            config.get(
                "monitoring_enabled",
                True,
            ),
        )

        if isinstance(
            monitoring_enabled,
            str,
        ):
            monitoring_enabled = (
                monitoring_enabled.lower()
                in {
                    "1",
                    "true",
                    "yes",
                    "on",
                    "enabled",
                }
            )

        if not monitoring_enabled:
            return {
                "success": True,
                "started": False,
                "message": (
                    "Live monitoring is disabled."
                ),
            }

        if mode in {
            "LIVE",
            "PRODUCTION",
            "REAL",
        }:
            result = start_capture(
                app=real_app,
                interface=interface,
                socketio=socketio,
            )

            result["mode"] = mode

            return result

        return {
            "success": True,
            "started": False,
            "message": (
                f"Capture not auto-started "
                f"because mode is {mode}."
            ),
            "mode": mode,
        }

    except Exception as exc:
        try:
            real_app = CaptureManager._unwrap_app(
                app
            )

            manager = get_manager(
                app=real_app,
                socketio=socketio,
            )

            manager.last_error = str(exc)

        except Exception:
            pass

        return {
            "success": False,
            "started": False,
            "message": (
                "Capture initialization failed."
            ),
            "error": str(exc),
        }