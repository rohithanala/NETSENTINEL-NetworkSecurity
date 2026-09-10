from __future__ import annotations

import random
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
# LIVE + DEMO PACKET CAPTURE MANAGER
# ============================================================


class CaptureManager:
    """
    NETSENTINEL packet capture manager.

    Supports two modes:

        LIVE
            Real Scapy packet capture from a network interface.

        DEMO
            Synthetic Scapy packets passed through the SAME
            packet-processing pipeline as LIVE traffic.

    DEMO traffic is stored with is_demo=True.
    LIVE traffic is stored with is_demo=False.
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
    # MODE
    # ========================================================

    def current_mode(self):
        app = self._unwrap_app(self.app)

        if app is None:
            return "LIVE"

        config = getattr(
            app,
            "config",
            {},
        )

        mode = str(
            config.get(
                "NETSENTINEL_MODE",
                config.get(
                    "MODE",
                    config.get(
                        "MONITOR_MODE",
                        "LIVE",
                    ),
                ),
            )
        ).upper()

        if mode in {
            "DEMO",
            "SIMULATION",
            "TEST",
        }:
            return "DEMO"

        return "LIVE"

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

        if self.interface and self.current_mode() != "DEMO":
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

        if self.current_mode() != "DEMO":
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

        with self.cache_lock:
            self.local_ip_cache.update(local_ips)
            self.local_mac_cache.update(local_macs)

        self.last_identity_refresh = time.time()

        return local_ips, local_macs

    # ========================================================
    # WINDOWS NEIGHBOR TABLE
    # ========================================================

    def refresh_windows_neighbors(self, force=False):
        if self.current_mode() == "DEMO":
            return 0

        now = time.time()

        if not force:
            if (
                now - self.last_neighbor_refresh
                < self.neighbor_refresh_interval
            ):
                return 0

        self.last_neighbor_refresh = now

        discovered = 0

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
        # DEMO packet Ethernet identity
        # ----------------------------------------------------

        if self.current_mode() == "DEMO":
            try:
                if packet is not None and packet.haslayer(
                    Ether
                ):
                    ether = packet[Ether]

                    source_mac = self.normalize_mac(
                        ether.src
                    )

                    destination_mac = self.normalize_mac(
                        ether.dst
                    )

                    if source_mac:
                        with self.cache_lock:
                            self.mac_cache[
                                value
                            ] = source_mac

                        if (
                            value
                            == str(
                                getattr(
                                    packet.getlayer(IP),
                                    "src",
                                    "",
                                )
                            )
                        ):
                            return source_mac

                    if destination_mac:
                        return destination_mac

            except Exception:
                pass

            with self.cache_lock:
                return self.mac_cache.get(value)

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

        self.refresh_windows_neighbors()

        with self.cache_lock:
            cached = self.mac_cache.get(value)

        if cached:
            return cached

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

        with self.cache_lock:
            if value in self.hostname_cache:
                return self.hostname_cache[value]

            is_local = value in self.local_ip_cache

        hostname = None

        if is_local:
            try:
                hostname = socket.gethostname()
            except Exception:
                hostname = None

        if (
            not hostname
            and self.current_mode() != "DEMO"
            and self.is_private_or_local_ip(value)
        ):
            try:
                result = socket.gethostbyaddr(
                    value
                )

                if result:
                    hostname = result[0]

            except Exception:
                hostname = None

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
        is_demo=False,
    ):
        if not self.is_valid_ip(ip):
            return None

        value = str(ip).strip()

        device = (
            Device.query
            .filter_by(
                ip_address=value,
                is_demo=bool(is_demo),
            )
            .first()
        )

        now = self.utc_now()

        if device is None:
            device = Device(
                ip_address=value,
                first_seen=now,
                last_seen=now,
                packet_count=0,
                status="normal",
                is_demo=bool(is_demo),
            )

            db.session.add(device)

        normalized_mac = self.normalize_mac(
            mac_address
        )

        if normalized_mac:
            device.mac_address = normalized_mac

        if hostname:
            hostname_value = str(
                hostname
            ).strip()

            if hostname_value:
                device.hostname = hostname_value

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
        if self.current_mode() == "DEMO":
            return

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

            if not device.mac_address:
                mac = self.lookup_mac(ip)

                if mac:
                    device.mac_address = mac
                    changed = True

            if not device.hostname:
                hostname = self.resolve_hostname(
                    ip
                )

                if hostname:
                    device.hostname = hostname
                    changed = True

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

    def parse_packet(
        self,
        packet,
        is_demo=False,
    ):
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
                else (
                    "DEMO"
                    if is_demo
                    else None
                )
            ),
            "is_demo": bool(is_demo),
        }

    # ========================================================
    # PACKET PROCESSING
    # ========================================================

    def process_packet(
        self,
        packet,
        is_demo=False,
    ):
        """
        Process a LIVE or DEMO packet.

        LIVE:
            is_demo=False

        DEMO:
            is_demo=True
        """

        self.packets_captured += 1
        self.last_packet_at = self.utc_now()

        parsed = self.parse_packet(
            packet,
            is_demo=is_demo,
        )

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

        is_demo = bool(
            parsed.get(
                "is_demo",
                False,
            )
        )

        # ----------------------------------------------------
        # Identity refresh
        # ----------------------------------------------------

        now = time.time()

        if not is_demo:
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
        # DEMO hostname fallback
        # ----------------------------------------------------

        if is_demo:
            demo_names = {
                "10.10.10.10": "WORKSTATION-01",
                "10.10.10.20": "WORKSTATION-02",
                "10.10.10.30": "DEV-LAPTOP",
                "10.10.10.40": "FILE-SERVER",
                "10.10.10.50": "DATABASE-SERVER",
                "10.10.10.60": "SECURITY-CLIENT",
                "8.8.8.8": "GOOGLE-DNS",
                "1.1.1.1": "CLOUDFLARE-DNS",
                "142.250.183.14": "WEB-SERVICE",
                "151.101.1.69": "CDN-SERVICE",
                "104.18.32.47": "CLOUD-SERVICE",
            }

            source_hostname = (
                source_hostname
                or demo_names.get(source_ip)
            )

            destination_hostname = (
                destination_hostname
                or demo_names.get(
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
                    is_demo=is_demo,
                )

            if destination_ip:
                self.update_device(
                    ip=destination_ip,
                    mac_address=destination_mac,
                    hostname=destination_hostname,
                    packet_increment=1,
                    is_demo=is_demo,
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
                is_demo=is_demo,
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
                    "is_demo": is_demo,
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
                                is_demo=is_demo,
                            )

                else:
                    process_packet = getattr(
                        self.detector,
                        "process_packet",
                        None,
                    )

                    if callable(process_packet):
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
        is_demo=False,
    ):
        """
        Persist an IDS detection.

        DEMO detections are stored separately from LIVE
        detections using is_demo=True.
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

                if "is_demo" in detection:
                    is_demo = bool(
                        detection[
                            "is_demo"
                        ]
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
                is_demo=bool(is_demo),
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
        if not self.running:
            return

        try:
            self.process_packet(
                packet,
                is_demo=False,
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
                "is_demo": bool(
                    parsed.get(
                        "is_demo",
                        False,
                    )
                ),
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
                "is_demo": bool(
                    getattr(
                        alert,
                        "is_demo",
                        False,
                    )
                ),
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
        app = self._unwrap_app(
            self.app
        )

        try:
            try:
                self.discover_local_identity()
            except Exception:
                pass

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
    # START LIVE CAPTURE
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

        try:
            self.discover_local_identity()
        except Exception:
            pass

        self.running = True

        self.thread = threading.Thread(
            target=self._capture_loop,
            name="NETSENTINEL-Capture",
            daemon=True,
        )

        self.thread.start()

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
            "mode": self.current_mode(),
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
# START LIVE CAPTURE
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
# DEMO PACKET BUILDERS
# ============================================================

DEMO_DEVICES = [
    {
        "ip": "10.10.10.10",
        "mac": "02:10:10:10:10:10",
        "name": "WORKSTATION-01",
    },
    {
        "ip": "10.10.10.20",
        "mac": "02:10:10:10:10:20",
        "name": "WORKSTATION-02",
    },
    {
        "ip": "10.10.10.30",
        "mac": "02:10:10:10:10:30",
        "name": "DEV-LAPTOP",
    },
    {
        "ip": "10.10.10.40",
        "mac": "02:10:10:10:10:40",
        "name": "FILE-SERVER",
    },
    {
        "ip": "10.10.10.50",
        "mac": "02:10:10:10:10:50",
        "name": "DATABASE-SERVER",
    },
    {
        "ip": "10.10.10.60",
        "mac": "02:10:10:10:10:60",
        "name": "SECURITY-CLIENT",
    },
]


DEMO_EXTERNAL_SERVICES = [
    {
        "ip": "8.8.8.8",
        "mac": "02:08:08:08:08:08",
        "port": 53,
        "protocol": "UDP",
    },
    {
        "ip": "1.1.1.1",
        "mac": "02:01:01:01:01:01",
        "port": 53,
        "protocol": "UDP",
    },
    {
        "ip": "142.250.183.14",
        "mac": "02:14:25:18:31:14",
        "port": 443,
        "protocol": "TCP",
    },
    {
        "ip": "151.101.1.69",
        "mac": "02:15:10:01:06:09",
        "port": 443,
        "protocol": "TCP",
    },
    {
        "ip": "104.18.32.47",
        "mac": "02:10:18:32:47:01",
        "port": 443,
        "protocol": "TCP",
    },
]


def _demo_tcp(
    source,
    destination_ip,
    destination_mac,
    destination_port,
):
    return (
        Ether(
            src=source["mac"],
            dst=destination_mac,
        )
        / IP(
            src=source["ip"],
            dst=destination_ip,
        )
        / TCP(
            sport=random.randint(
                30000,
                60000,
            ),
            dport=destination_port,
            flags="S",
        )
    )


def _demo_udp(
    source,
    destination_ip,
    destination_mac,
    destination_port,
):
    return (
        Ether(
            src=source["mac"],
            dst=destination_mac,
        )
        / IP(
            src=source["ip"],
            dst=destination_ip,
        )
        / UDP(
            sport=random.randint(
                30000,
                60000,
            ),
            dport=destination_port,
        )
        / b"NETSENTINEL-DEMO"
    )


def _demo_icmp(
    source,
    destination,
):
    return (
        Ether(
            src=source["mac"],
            dst=destination["mac"],
        )
        / IP(
            src=source["ip"],
            dst=destination["ip"],
        )
        / ICMP()
    )


def _demo_normal_packet():
    source = random.choice(
        DEMO_DEVICES
    )

    traffic_type = random.choice(
        [
            "TCP",
            "TCP",
            "TCP",
            "UDP",
            "ICMP",
        ]
    )

    if traffic_type == "ICMP":
        destination = random.choice(
            DEMO_DEVICES
        )

        while destination["ip"] == source["ip"]:
            destination = random.choice(
                DEMO_DEVICES
            )

        return _demo_icmp(
            source,
            destination,
        )

    service = random.choice(
        DEMO_EXTERNAL_SERVICES
    )

    if traffic_type == "UDP":
        return _demo_udp(
            source=source,
            destination_ip=service["ip"],
            destination_mac=service["mac"],
            destination_port=service["port"],
        )

    return _demo_tcp(
        source=source,
        destination_ip=service["ip"],
        destination_mac=service["mac"],
        destination_port=service["port"],
    )


def _demo_internal_packet():
    source = random.choice(
        DEMO_DEVICES[:3]
    )

    destination = random.choice(
        DEMO_DEVICES[3:]
    )

    destination_port = random.choice(
        [
            80,
            443,
            445,
            3306,
            5432,
            8080,
        ]
    )

    return _demo_tcp(
        source=source,
        destination_ip=destination["ip"],
        destination_mac=destination["mac"],
        destination_port=destination_port,
    )


def _demo_port_scan_packets():
    source = DEMO_DEVICES[2]
    destination = DEMO_DEVICES[4]

    packets = []

    ports = list(
        range(
            20,
            45,
        )
    )

    random.shuffle(
        ports
    )

    for port in ports:
        packets.append(
            _demo_tcp(
                source=source,
                destination_ip=destination["ip"],
                destination_mac=destination["mac"],
                destination_port=port,
            )
        )

    return packets


def _demo_connection_burst_packets():
    source = DEMO_DEVICES[1]
    destination = DEMO_DEVICES[3]

    packets = []

    for _ in range(65):
        packets.append(
            _demo_tcp(
                source=source,
                destination_ip=destination["ip"],
                destination_mac=destination["mac"],
                destination_port=random.choice(
                    [
                        22,
                        80,
                        443,
                        8080,
                        8443,
                    ]
                ),
            )
        )

    return packets


# ============================================================
# DEMO GENERATOR
# ============================================================

_demo_thread = None
_demo_running = False
_demo_lock = threading.RLock()


def _run_demo_cycle(
    manager,
):
    # --------------------------------------------------------
    # Normal traffic
    # --------------------------------------------------------

    for _ in range(15):
        if not _demo_running:
            return

        manager.process_packet(
            _demo_normal_packet(),
            is_demo=True,
        )

        time.sleep(
            0.08
        )

    # --------------------------------------------------------
    # Internal traffic
    # --------------------------------------------------------

    for _ in range(10):
        if not _demo_running:
            return

        manager.process_packet(
            _demo_internal_packet(),
            is_demo=True,
        )

        time.sleep(
            0.08
        )

    # --------------------------------------------------------
    # ICMP
    # --------------------------------------------------------

    source = DEMO_DEVICES[0]

    destination = DEMO_DEVICES[5]

    for _ in range(5):
        if not _demo_running:
            return

        manager.process_packet(
            _demo_icmp(
                source,
                destination,
            ),
            is_demo=True,
        )

        time.sleep(
            0.08
        )

    # --------------------------------------------------------
    # PORT SCAN
    # --------------------------------------------------------

    for packet in _demo_port_scan_packets():
        if not _demo_running:
            return

        manager.process_packet(
            packet,
            is_demo=True,
        )

        time.sleep(
            0.025
        )

    # --------------------------------------------------------
    # CONNECTION RATE BURST
    # --------------------------------------------------------

    for packet in _demo_connection_burst_packets():
        if not _demo_running:
            return

        manager.process_packet(
            packet,
            is_demo=True,
        )

        time.sleep(
            0.015
        )


def _demo_loop(
    app,
    socketio=None,
):
    global _demo_running

    manager = None

    try:
        manager = get_manager(
            app=app,
            socketio=socketio,
        )

        manager.interface = "DEMO"

        manager.running = True

        if manager.started_at is None:
            manager.started_at = manager.utc_now()

        while _demo_running:
            _run_demo_cycle(
                manager
            )

            if not _demo_running:
                break

            time.sleep(
                1.0
            )

    except Exception as exc:
        if manager is not None:
            manager.set_error(
                exc
            )

    finally:
        _demo_running = False

        if manager is not None:
            manager.running = False


def start_demo_if_enabled(
    app,
    socketio=None,
):
    global _demo_thread
    global _demo_running

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
                    "MONITOR_MODE",
                    "DEMO",
                ),
            ),
        )
    ).upper()

    if mode not in {
        "DEMO",
        "SIMULATION",
        "TEST",
    }:
        return {
            "success": True,
            "started": False,
            "mode": mode,
            "message": (
                "Demo generator not started "
                f"because mode is {mode}."
            ),
        }

    with _demo_lock:
        if _demo_running:
            return {
                "success": True,
                "started": True,
                "mode": mode,
                "message": (
                    "Demo generator already running."
                ),
            }

        _demo_running = True

        manager = get_manager(
            app=real_app,
            socketio=socketio,
        )

        manager.interface = "DEMO"
        manager.running = True
        manager.started_at = manager.utc_now()
        manager.last_packet_at = None
        manager.last_error = None

        _demo_thread = threading.Thread(
            target=_demo_loop,
            args=(
                real_app,
                socketio,
            ),
            name="NETSENTINEL-Demo",
            daemon=True,
        )

        _demo_thread.start()

    return {
        "success": True,
        "started": True,
        "mode": mode,
        "message": (
            "Demo traffic generator started."
        ),
    }


def stop_demo():
    global _demo_running

    with _demo_lock:
        _demo_running = False

    if _capture_manager is not None:
        if (
            _capture_manager.current_mode()
            == "DEMO"
        ):
            _capture_manager.running = False

    return {
        "success": True,
        "stopped": True,
        "message": (
            "Demo traffic generator stopped."
        ),
    }


def demo_status():
    return {
        "running": bool(
            _demo_running
        ),
        "thread_alive": bool(
            _demo_thread
            and _demo_thread.is_alive()
        ),
    }


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

        # ----------------------------------------------------
        # DEMO MODE
        #
        # DEMO does NOT require MONITORING_ENABLED=True.
        # This is important for Render because there is no
        # physical Wi-Fi interface available to Scapy.
        # ----------------------------------------------------

        if mode in {
            "DEMO",
            "SIMULATION",
            "TEST",
        }:
            return start_demo_if_enabled(
                app=real_app,
                socketio=socketio,
            )

        # ----------------------------------------------------
        # LIVE MODE
        # ----------------------------------------------------

        if not monitoring_enabled:
            return {
                "success": True,
                "started": False,
                "message": (
                    "Live monitoring is disabled."
                ),
                "mode": mode,
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