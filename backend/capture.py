from __future__ import annotations

import ipaddress
import random
import socket
import subprocess
import threading
import time
from collections import defaultdict
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

from .client_identity import (
    DEFAULT_CLIENT_ID,
    normalize_client_id,
)
from .detectors import DetectionEngine
from .models import (
    Alert,
    Device,
    Traffic,
    db,
)


# ============================================================
# NETSENTINEL
# LIVE + DEMO PACKET CAPTURE MANAGER
# ============================================================


class CaptureManager:

    def __init__(
        self,
        app=None,
        client_id=DEFAULT_CLIENT_ID,
    ):

        self.app = self._unwrap_app(
            app
        )

        self.running = False
        self.thread = None

        self.started_at = None
        self.last_packet_at = None
        self.last_error = None

        self.packets_captured = 0
        self.interface = None

        self.detector = None
        self.socketio = None

        self.client_id = normalize_client_id(
            client_id
        )

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
        # Database synchronization
        # ----------------------------------------------------

        self.db_lock = threading.RLock()

        # ----------------------------------------------------
        # BATCHED DATABASE WRITES
        #
        # This is the main SQLite lock fix.
        # ----------------------------------------------------

        config = (
            self.app.config
            if self.app is not None
            else {}
        )

        self.write_batch_size = max(
            1,
            int(
                config.get(
                    "CAPTURE_BATCH_SIZE",
                    25,
                )
            ),
        )

        self.batch_flush_interval = max(
            0.1,
            float(
                config.get(
                    "CAPTURE_BATCH_FLUSH_SECONDS",
                    1.0,
                )
            ),
        )

        self.pending_traffic = []
        self.pending_devices = {}
        self.pending_alerts = []

        self.pending_lock = threading.RLock()
        self.last_batch_flush = time.time()

        # ----------------------------------------------------
        # Detector
        # ----------------------------------------------------

        if self.app is not None:

            try:

                self.detector = DetectionEngine(
                    self.app
                )

            except Exception as exc:

                self.last_error = str(
                    exc
                )

    # ========================================================
    # FLASK APP
    # ========================================================

    @staticmethod
    def _unwrap_app(
        app,
    ):

        if app is None:
            return None

        try:

            getter = getattr(
                app,
                "_get_current_object",
                None,
            )

            if callable(
                getter
            ):

                return getter()

        except Exception:
            pass

        return app

    # ========================================================
    # CLIENT ID
    # ========================================================

    def set_client_id(
        self,
        client_id=None,
    ):

        normalized = normalize_client_id(
            client_id
        )

        if self.running:
            return self.get_client_id()

        self.client_id = normalized

        return normalized

    def get_client_id(
        self,
    ):

        return normalize_client_id(
            self.client_id
        )

    # ========================================================
    # CONFIGURE
    # ========================================================

    def configure(
        self,
        app,
        socketio=None,
        client_id=None,
    ):

        real_app = self._unwrap_app(
            app
        )

        self.app = real_app

        if socketio is not None:
            self.socketio = socketio

        if (
            client_id is not None
            and not self.running
        ):

            self.set_client_id(
                client_id
            )

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

                    self.detector = (
                        DetectionEngine(
                            real_app
                        )
                    )

                config = real_app.config

                self.write_batch_size = max(
                    1,
                    int(
                        config.get(
                            "CAPTURE_BATCH_SIZE",
                            self.write_batch_size,
                        )
                    ),
                )

                self.batch_flush_interval = max(
                    0.1,
                    float(
                        config.get(
                            "CAPTURE_BATCH_FLUSH_SECONDS",
                            self.batch_flush_interval,
                        )
                    ),
                )

            except Exception as exc:

                self.set_error(
                    exc
                )

    # ========================================================
    # MODE
    # ========================================================

    def current_mode(
        self,
    ):

        app = self._unwrap_app(
            self.app
        )

        if app is None:
            return "DEMO"

        mode = str(
            app.config.get(
                "NETSENTINEL_MODE",
                app.config.get(
                    "MODE",
                    app.config.get(
                        "MONITOR_MODE",
                        "DEMO",
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

        return datetime.now(
            timezone.utc
        )

    # ========================================================
    # ERROR HANDLING
    # ========================================================

    def set_error(
        self,
        exc,
    ):

        try:

            self.last_error = str(
                exc
            )

        except Exception:

            self.last_error = (
                "Unknown capture error."
            )

    def clear_error(
        self,
    ):

        self.last_error = None

    # ========================================================
    # IP HELPERS
    # ========================================================

    @staticmethod
    def is_valid_ip(
        ip,
    ):

        if not ip:
            return False

        value = str(
            ip
        ).strip()

        if value in {
            "",
            "0.0.0.0",
            "::",
            "255.255.255.255",
        }:

            return False

        try:

            ipaddress.ip_address(
                value
            )

            return True

        except ValueError:

            return False

    @staticmethod
    def is_private_or_local_ip(
        ip,
    ):

        if not ip:
            return False

        try:

            address = ipaddress.ip_address(
                str(ip).strip()
            )

        except ValueError:

            return False

        if address.is_multicast:
            return False

        if address.is_unspecified:
            return False

        return bool(
            address.is_private
            or address.is_loopback
            or address.is_link_local
        )

    # ========================================================
    # MAC HELPERS
    # ========================================================

    @staticmethod
    def normalize_mac(
        mac,
    ):

        if not mac:
            return None

        value = str(
            mac
        ).strip().upper()

        compact = (
            value
            .replace(":", "")
            .replace("-", "")
            .replace(".", "")
            .replace(" ", "")
        )

        if (
            len(compact)
            != 12
        ):

            return None

        invalid = {
            "000000000000",
            "FFFFFFFFFFFF",
        }

        if compact in invalid:
            return None

        try:

            int(
                compact,
                16,
            )

        except ValueError:

            return None

        return ":".join(
            compact[index:index + 2]
            for index in range(
                0,
                12,
                2,
            )
        )

    @staticmethod
    def is_multicast_mac(
        mac,
    ):

        normalized = (
            CaptureManager.normalize_mac(
                mac
            )
        )

        if not normalized:
            return False

        try:

            first_octet = int(
                normalized.split(":")[0],
                16,
            )

            return bool(
                first_octet & 1
            )

        except Exception:

            return False

    # ========================================================
    # LOCAL COMPUTER IDENTITY
    # ========================================================

    def discover_local_identity(
        self,
    ):

        local_ips = set()
        local_macs = set()

        try:

            hostname = socket.gethostname()

            try:

                _, _, addresses = (
                    socket.gethostbyname_ex(
                        hostname
                    )
                )

                for ip in addresses:

                    if self.is_valid_ip(
                        ip
                    ):

                        local_ips.add(
                            ip
                        )

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

                    if self.is_valid_ip(
                        ip
                    ):

                        local_ips.add(
                            ip
                        )

            except Exception:
                pass

        except Exception:
            pass

        if (
            self.interface
            and self.current_mode()
            != "DEMO"
        ):

            try:

                interface_ip = get_if_addr(
                    self.interface
                )

                if self.is_valid_ip(
                    interface_ip
                ):

                    local_ips.add(
                        interface_ip
                    )

            except Exception:
                pass

            try:

                interface_mac = (
                    get_if_hwaddr(
                        self.interface
                    )
                )

                interface_mac = (
                    self.normalize_mac(
                        interface_mac
                    )
                )

                if interface_mac:

                    local_macs.add(
                        interface_mac
                    )

            except Exception:
                pass

        if (
            self.current_mode()
            != "DEMO"
        ):

            try:

                default_interface = (
                    conf.iface
                )

                try:

                    default_ip = (
                        get_if_addr(
                            default_interface
                        )
                    )

                    if self.is_valid_ip(
                        default_ip
                    ):

                        local_ips.add(
                            default_ip
                        )

                except Exception:
                    pass

                try:

                    default_mac = (
                        get_if_hwaddr(
                            default_interface
                        )
                    )

                    default_mac = (
                        self.normalize_mac(
                            default_mac
                        )
                    )

                    if default_mac:

                        local_macs.add(
                            default_mac
                        )

                except Exception:
                    pass

            except Exception:
                pass

        with self.cache_lock:

            self.local_ip_cache.update(
                local_ips
            )

            self.local_mac_cache.update(
                local_macs
            )

        self.last_identity_refresh = (
            time.time()
        )

        return (
            local_ips,
            local_macs,
        )

    # ========================================================
    # WINDOWS NEIGHBORS
    # ========================================================

    def refresh_windows_neighbors(
        self,
        force=False,
    ):

        if self.current_mode() == "DEMO":
            return 0

        now = time.time()

        if not force:

            if (
                now
                - self.last_neighbor_refresh
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

                for line in (
                    result.stdout.splitlines()[1:]
                ):

                    parts = [
                        part.strip().strip('"')
                        for part in line.split(",")
                    ]

                    if len(parts) < 2:
                        continue

                    ip = parts[0]
                    mac = parts[1]

                    if not self.is_valid_ip(
                        ip
                    ):
                        continue

                    if not self.is_private_or_local_ip(
                        ip
                    ):
                        continue

                    normalized_mac = (
                        self.normalize_mac(
                            mac
                        )
                    )

                    if not normalized_mac:
                        continue

                    if self.is_multicast_mac(
                        normalized_mac
                    ):
                        continue

                    with self.cache_lock:

                        self.mac_cache[
                            ip
                        ] = normalized_mac

                    discovered += 1

        except Exception:
            pass

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

                for line in (
                    result.stdout.splitlines()
                ):

                    parts = line.strip().split()

                    if len(parts) < 2:
                        continue

                    ip = parts[0]
                    mac = parts[1]

                    if not self.is_valid_ip(
                        ip
                    ):
                        continue

                    if not self.is_private_or_local_ip(
                        ip
                    ):
                        continue

                    normalized_mac = (
                        self.normalize_mac(
                            mac
                        )
                    )

                    if not normalized_mac:
                        continue

                    if self.is_multicast_mac(
                        normalized_mac
                    ):
                        continue

                    with self.cache_lock:

                        self.mac_cache[
                            ip
                        ] = normalized_mac

                    discovered += 1

        except Exception:
            pass

        return discovered

    # ========================================================
    # MAC LOOKUP
    # ========================================================

    def lookup_mac(
        self,
        ip,
        packet=None,
    ):

        if not ip:
            return None

        value = str(
            ip
        ).strip()

        if not self.is_valid_ip(
            value
        ):
            return None

        if (
            not self.is_private_or_local_ip(
                value
            )
            and self.current_mode()
            != "DEMO"
        ):

            return None

        if self.current_mode() == "DEMO":

            try:

                if (
                    packet is not None
                    and packet.haslayer(Ether)
                ):

                    ether = packet[Ether]

                    source_mac = (
                        self.normalize_mac(
                            ether.src
                        )
                    )

                    destination_mac = (
                        self.normalize_mac(
                            ether.dst
                        )
                    )

                    if source_mac:

                        with self.cache_lock:

                            self.mac_cache[
                                value
                            ] = source_mac

                        packet_ip = (
                            packet.getlayer(
                                IP
                            )
                        )

                        if (
                            packet_ip is not None
                            and value
                            == str(
                                getattr(
                                    packet_ip,
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

                return self.mac_cache.get(
                    value
                )

        with self.cache_lock:

            cached = self.mac_cache.get(
                value
            )

            if cached:
                return cached

            is_local = (
                value
                in self.local_ip_cache
            )

            local_macs = list(
                self.local_mac_cache
            )

        if (
            is_local
            and local_macs
        ):

            return local_macs[0]

        try:

            if (
                packet is not None
                and packet.haslayer(ARP)
            ):

                arp = packet[ARP]

                if str(
                    arp.psrc
                ) == value:

                    mac = (
                        self.normalize_mac(
                            arp.hwsrc
                        )
                    )

                    if mac:

                        with self.cache_lock:

                            self.mac_cache[
                                value
                            ] = mac

                        return mac

                if str(
                    arp.pdst
                ) == value:

                    mac = (
                        self.normalize_mac(
                            arp.hwdst
                        )
                    )

                    if mac:

                        with self.cache_lock:

                            self.mac_cache[
                                value
                            ] = mac

                        return mac

        except Exception:
            pass

        self.refresh_windows_neighbors()

        with self.cache_lock:

            cached = self.mac_cache.get(
                value
            )

        if cached:
            return cached

        return None

    # ========================================================
    # HOSTNAME
    # ========================================================

    def resolve_hostname(
        self,
        ip,
    ):

        if not ip:
            return None

        value = str(
            ip
        ).strip()

        if not self.is_valid_ip(
            value
        ):
            return None

        if not self.is_private_or_local_ip(
            value
        ):
            return None

        with self.cache_lock:

            if value in self.hostname_cache:

                return self.hostname_cache[
                    value
                ]

            is_local = (
                value
                in self.local_ip_cache
            )

        hostname = None

        if is_local:

            try:
                hostname = socket.gethostname()
            except Exception:
                hostname = None

        if not hostname:

            try:

                result = socket.gethostbyaddr(
                    value
                )

                if result:
                    hostname = result[0]

            except Exception:
                hostname = None

        with self.cache_lock:

            self.hostname_cache[
                value
            ] = hostname

        return hostname

    # ========================================================
    # DEVICE BATCH ACCUMULATION
    # ========================================================

    def _queue_device(
        self,
        ip,
        mac_address=None,
        hostname=None,
        packet_increment=1,
        is_demo=False,
        client_id=None,
    ):

        if not self.is_valid_ip(
            ip
        ):
            return

        value = str(
            ip
        ).strip()

        if not self.is_private_or_local_ip(
            value
        ):
            return

        client_namespace = normalize_client_id(
            client_id
            if client_id is not None
            else self.get_client_id()
        )

        key = (
            value,
            client_namespace,
            bool(is_demo),
        )

        normalized_mac = (
            self.normalize_mac(
                mac_address
            )
        )

        with self.pending_lock:

            record = self.pending_devices.get(
                key
            )

            if record is None:

                record = {
                    "ip_address": value,
                    "mac_address": (
                        normalized_mac
                    ),
                    "hostname": (
                        str(hostname).strip()
                        if hostname
                        else None
                    ),
                    "packet_count": int(
                        packet_increment
                        or 0
                    ),
                    "client_id": (
                        client_namespace
                    ),
                    "is_demo": bool(
                        is_demo
                    ),
                }

                self.pending_devices[
                    key
                ] = record

            else:

                record["packet_count"] += int(
                    packet_increment
                    or 0
                )

                if (
                    normalized_mac
                    and not record.get(
                        "mac_address"
                    )
                ):

                    record["mac_address"] = (
                        normalized_mac
                    )

                if (
                    hostname
                    and not record.get(
                        "hostname"
                    )
                ):

                    record["hostname"] = (
                        str(
                            hostname
                        ).strip()
                    )

    # ========================================================
    # PARSE
    # ========================================================

    def parse_packet(
        self,
        packet,
        is_demo=False,
        client_id=None,
    ):

        if packet is None:
            return None

        timestamp = self.utc_now()

        source_ip = None
        destination_ip = None

        protocol = "OTHER"

        source_port = None
        destination_port = None

        client_namespace = normalize_client_id(
            client_id
            if client_id is not None
            else self.get_client_id()
        )

        try:

            packet_size = len(
                packet
            )

        except Exception:

            packet_size = 0

        if packet.haslayer(
            IP
        ):

            ip_layer = packet[IP]

            source_ip = str(
                ip_layer.src
            )

            destination_ip = str(
                ip_layer.dst
            )

            if packet.haslayer(
                TCP
            ):

                protocol = "TCP"

                source_port = int(
                    packet[TCP].sport
                )

                destination_port = int(
                    packet[TCP].dport
                )

            elif packet.haslayer(
                UDP
            ):

                protocol = "UDP"

                source_port = int(
                    packet[UDP].sport
                )

                destination_port = int(
                    packet[UDP].dport
                )

            elif packet.haslayer(
                ICMP
            ):

                protocol = "ICMP"

            else:

                protocol = str(
                    getattr(
                        ip_layer,
                        "proto",
                        "IP",
                    )
                )

        elif packet.haslayer(
            IPv6
        ):

            ip_layer = packet[IPv6]

            source_ip = str(
                ip_layer.src
            )

            destination_ip = str(
                ip_layer.dst
            )

            if packet.haslayer(
                TCP
            ):

                protocol = "TCP"

                source_port = int(
                    packet[TCP].sport
                )

                destination_port = int(
                    packet[TCP].dport
                )

            elif packet.haslayer(
                UDP
            ):

                protocol = "UDP"

                source_port = int(
                    packet[UDP].sport
                )

                destination_port = int(
                    packet[UDP].dport
                )

            elif packet.haslayer(
                ICMP
            ):

                protocol = "ICMP"

            else:

                protocol = str(
                    getattr(
                        ip_layer,
                        "nh",
                        "IPv6",
                    )
                )

        elif packet.haslayer(
            ARP
        ):

            arp = packet[ARP]

            source_ip = str(
                arp.psrc
            )

            destination_ip = str(
                arp.pdst
            )

            protocol = "ARP"

        if (
            not source_ip
            and not destination_ip
        ):
            return None

        tcp_flags = None

        try:

            if packet.haslayer(
                TCP
            ):

                tcp_flags = str(
                    packet[TCP].flags
                )

        except Exception:
            pass

        return {
            "timestamp": timestamp,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "protocol": protocol,
            "source_port": source_port,
            "destination_port": destination_port,
            "packet_size": packet_size,
            "tcp_flags": tcp_flags,
            "interface": (
                str(
                    self.interface
                )
                if self.interface
                else (
                    "DEMO"
                    if is_demo
                    else None
                )
            ),
            "client_id": client_namespace,
            "is_demo": bool(
                is_demo
            ),
        }

    # ========================================================
    # QUEUE TRAFFIC
    # ========================================================

    def _queue_traffic(
        self,
        parsed,
    ):

        with self.pending_lock:

            self.pending_traffic.append(
                parsed
            )

    # ========================================================
    # ALERT QUEUE
    # ========================================================

    def _queue_alert(
        self,
        detection,
        source_ip,
        destination_ip,
        protocol,
        is_demo,
        client_id,
    ):

        client_namespace = normalize_client_id(
            client_id
        )

        try:

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

                client_namespace = (
                    normalize_client_id(
                        detection.get(
                            "client_id",
                            client_namespace,
                        )
                    )
                )

                if "is_demo" in detection:
                    is_demo = bool(
                        detection["is_demo"]
                    )

            else:

                return

            severity = str(
                severity
            ).upper()

            if severity not in Alert.VALID_SEVERITIES:
                severity = "MEDIUM"

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

            alert_data = {

                "timestamp": self.utc_now(),

                "detection_type": str(
                    detection_type
                ),

                "source_ip": (
                    str(source_ip)
                    if source_ip
                    else "unknown"
                ),

                "destination_ip": (
                    str(destination_ip)
                    if destination_ip
                    else None
                ),

                "protocol": (
                    str(protocol)
                    if protocol
                    else None
                ),

                "severity": severity,

                "confidence": confidence,

                "description": str(
                    description
                ),

                "status": "new",

                "client_id": client_namespace,

                "is_demo": bool(
                    is_demo
                ),

            }

            with self.pending_lock:

                self.pending_alerts.append(
                    alert_data
                )

            self._emit_alert_data(
                alert_data
            )

        except Exception as exc:

            self.set_error(
                exc
            )

    # ========================================================
    # FLUSH BATCH
    # ========================================================

    def flush_pending(
        self,
        force=False,
    ):

        now = time.time()

        with self.pending_lock:

            traffic_batch = list(
                self.pending_traffic
            )

            device_batch = dict(
                self.pending_devices
            )

            alert_batch = list(
                self.pending_alerts
            )

            should_flush = bool(
                force
                or len(traffic_batch)
                >= self.write_batch_size
                or (
                    traffic_batch
                    and
                    (
                        now
                        - self.last_batch_flush
                        >= self.batch_flush_interval
                    )
                )
            )

            if not should_flush:
                return False

            self.pending_traffic.clear()
            self.pending_devices.clear()
            self.pending_alerts.clear()

            self.last_batch_flush = now

        if not (
            traffic_batch
            or device_batch
            or alert_batch
        ):
            return False

        app = self._unwrap_app(
            self.app
        )

        if app is None:

            self.set_error(
                "Flask application is unavailable."
            )

            return False

        try:

            with self.db_lock:

                with app.app_context():

                    # ----------------------------------------
                    # DEVICES
                    # ----------------------------------------

                    for device_data in (
                        device_batch.values()
                    ):

                        device = (
                            Device.query
                            .filter_by(
                                ip_address=device_data[
                                    "ip_address"
                                ],
                                client_id=device_data[
                                    "client_id"
                                ],
                                is_demo=device_data[
                                    "is_demo"
                                ],
                            )
                            .first()
                        )

                        now_dt = (
                            self.utc_now()
                        )

                        if device is None:

                            device = Device(
                                ip_address=device_data[
                                    "ip_address"
                                ],
                                first_seen=now_dt,
                                last_seen=now_dt,
                                packet_count=0,
                                status="normal",
                                client_id=device_data[
                                    "client_id"
                                ],
                                is_demo=device_data[
                                    "is_demo"
                                ],
                            )

                            db.session.add(
                                device
                            )

                        device.last_seen = (
                            now_dt
                        )

                        device.packet_count = (
                            int(
                                device.packet_count
                                or 0
                            )
                            + int(
                                device_data[
                                    "packet_count"
                                ]
                                or 0
                            )
                        )

                        mac = (
                            self.normalize_mac(
                                device_data.get(
                                    "mac_address"
                                )
                            )
                        )

                        if mac:
                            device.mac_address = mac

                        hostname = (
                            device_data.get(
                                "hostname"
                            )
                        )

                        if hostname:
                            device.hostname = (
                                str(
                                    hostname
                                ).strip()
                            )

                        if device.status not in {
                            "suspicious",
                            "critical",
                        }:

                            device.status = "normal"

                    # ----------------------------------------
                    # TRAFFIC
                    # ----------------------------------------

                    for parsed in traffic_batch:

                        traffic = Traffic(
                            timestamp=parsed[
                                "timestamp"
                            ],
                            source_ip=parsed[
                                "source_ip"
                            ],
                            destination_ip=parsed[
                                "destination_ip"
                            ],
                            source_port=parsed[
                                "source_port"
                            ],
                            destination_port=parsed[
                                "destination_port"
                            ],
                            protocol=parsed[
                                "protocol"
                            ],
                            packet_size=parsed[
                                "packet_size"
                            ],
                            tcp_flags=parsed[
                                "tcp_flags"
                            ],
                            interface=parsed[
                                "interface"
                            ],
                            client_id=parsed[
                                "client_id"
                            ],
                            is_demo=parsed[
                                "is_demo"
                            ],
                        )

                        db.session.add(
                            traffic
                        )

                    # ----------------------------------------
                    # ALERTS
                    # ----------------------------------------

                    for alert_data in alert_batch:

                        alert = Alert(
                            timestamp=alert_data[
                                "timestamp"
                            ],
                            detection_type=alert_data[
                                "detection_type"
                            ],
                            source_ip=alert_data[
                                "source_ip"
                            ],
                            destination_ip=alert_data[
                                "destination_ip"
                            ],
                            protocol=alert_data[
                                "protocol"
                            ],
                            severity=alert_data[
                                "severity"
                            ],
                            confidence=alert_data[
                                "confidence"
                            ],
                            description=alert_data[
                                "description"
                            ],
                            status=alert_data[
                                "status"
                            ],
                            client_id=alert_data[
                                "client_id"
                            ],
                            is_demo=alert_data[
                                "is_demo"
                            ],
                        )

                        db.session.add(
                            alert
                        )

                    # ----------------------------------------
                    # SINGLE TRANSACTION
                    # ----------------------------------------

                    db.session.commit()

                    self.clear_error()

                    return True

        except Exception as exc:

            with self.pending_lock:

                self.pending_traffic[
                    0:0
                ] = traffic_batch

                for key, value in (
                    device_batch.items()
                ):

                    existing = (
                        self.pending_devices.get(
                            key
                        )
                    )

                    if existing is None:

                        self.pending_devices[
                            key
                        ] = value

                    else:

                        existing[
                            "packet_count"
                        ] += value[
                            "packet_count"
                        ]

                self.pending_alerts[
                    0:0
                ] = alert_batch

            try:

                db.session.rollback()

            except Exception:
                pass

            self.set_error(
                exc
            )

            return False

    # ========================================================
    # PROCESS PACKET
    # ========================================================

    def process_packet(
        self,
        packet,
        is_demo=False,
        client_id=None,
    ):

        client_namespace = normalize_client_id(
            client_id
            if client_id is not None
            else self.get_client_id()
        )

        self.packets_captured += 1

        self.last_packet_at = (
            self.utc_now()
        )

        parsed = self.parse_packet(
            packet,
            is_demo=is_demo,
            client_id=client_namespace,
        )

        if parsed is None:
            return

        source_ip = parsed[
            "source_ip"
        ]

        destination_ip = parsed[
            "destination_ip"
        ]

        source_is_device = (
            self.is_private_or_local_ip(
                source_ip
            )
        )

        destination_is_device = (
            self.is_private_or_local_ip(
                destination_ip
            )
        )

        source_mac = (
            self.lookup_mac(
                source_ip,
                packet,
            )
            if source_is_device
            else None
        )

        destination_mac = (
            self.lookup_mac(
                destination_ip,
                packet,
            )
            if destination_is_device
            else None
        )

        source_hostname = (
            self.resolve_hostname(
                source_ip
            )
            if source_is_device
            else None
        )

        destination_hostname = (
            self.resolve_hostname(
                destination_ip
            )
            if destination_is_device
            else None
        )

        # ----------------------------------------------------
        # DEMO HOSTNAMES
        # ----------------------------------------------------

        if is_demo:

            demo_names = {

                "10.10.10.10":
                    "WORKSTATION-01",

                "10.10.10.20":
                    "WORKSTATION-02",

                "10.10.10.30":
                    "DEV-LAPTOP",

                "10.10.10.40":
                    "FILE-SERVER",

                "10.10.10.50":
                    "DATABASE-SERVER",

                "10.10.10.60":
                    "SECURITY-CLIENT",

                "8.8.8.8":
                    "GOOGLE-DNS",

                "1.1.1.1":
                    "CLOUDFLARE-DNS",

                "142.250.183.14":
                    "WEB-SERVICE",

                "151.101.1.69":
                    "CDN-SERVICE",

                "104.18.32.47":
                    "CLOUD-SERVICE",

            }

            source_hostname = (
                source_hostname
                or demo_names.get(
                    source_ip
                )
            )

            destination_hostname = (
                destination_hostname
                or demo_names.get(
                    destination_ip
                )
            )

        # ----------------------------------------------------
        # QUEUE DATABASE WORK
        # ----------------------------------------------------

        if source_is_device:

            self._queue_device(
                ip=source_ip,
                mac_address=source_mac,
                hostname=source_hostname,
                packet_increment=1,
                is_demo=is_demo,
                client_id=client_namespace,
            )

        if destination_is_device:

            self._queue_device(
                ip=destination_ip,
                mac_address=destination_mac,
                hostname=destination_hostname,
                packet_increment=1,
                is_demo=is_demo,
                client_id=client_namespace,
            )

        self._queue_traffic(
            parsed
        )

        # ----------------------------------------------------
        # IDS
        #
        # Detection happens immediately, but database writes
        # are queued and committed in batches.
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
                        DetectionEngine(
                            app
                        )
                    )

            if self.detector is not None:

                detection_packet = {
                    "timestamp": parsed[
                        "timestamp"
                    ],
                    "source_ip": source_ip,
                    "destination_ip": destination_ip,
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
                    "client_id": client_namespace,
                    "is_demo": bool(
                        is_demo
                    ),
                }

                evaluate = getattr(
                    self.detector,
                    "evaluate",
                    None,
                )

                if callable(
                    evaluate
                ):

                    detections = evaluate(
                        detection_packet
                    )

                    if detections:

                        for detection in detections:

                            self._queue_alert(
                                detection=detection,
                                source_ip=source_ip,
                                destination_ip=destination_ip,
                                protocol=parsed[
                                    "protocol"
                                ],
                                is_demo=is_demo,
                                client_id=client_namespace,
                            )

                else:

                    process_packet = getattr(
                        self.detector,
                        "process_packet",
                        None,
                    )

                    if callable(
                        process_packet
                    ):

                        process_packet(
                            detection_packet
                        )

        except Exception as exc:

            self.set_error(
                exc
            )

        # ----------------------------------------------------
        # SOCKET.IO
        # ----------------------------------------------------

        self.emit_packet(
            parsed=parsed,
            source_mac=source_mac,
            destination_mac=destination_mac,
            source_hostname=source_hostname,
            destination_hostname=destination_hostname,
        )

        # ----------------------------------------------------
        # FLUSH WHEN REQUIRED
        # ----------------------------------------------------

        self.flush_pending(
            force=False
        )

    # ========================================================
    # SCAPY CALLBACK
    # ========================================================

    def _packet_callback(
        self,
        packet,
    ):

        if not self.running:
            return

        try:

            self.process_packet(
                packet,
                is_demo=False,
                client_id=self.get_client_id(),
            )

        except Exception as exc:

            self.set_error(
                exc
            )

    # ========================================================
    # SOCKET.IO TRAFFIC
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
                    parsed[
                        "timestamp"
                    ].isoformat()
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

                "destination_mac":
                    destination_mac,

                "source_hostname":
                    source_hostname,

                "destination_hostname":
                    destination_hostname,

                "client_id": normalize_client_id(
                    parsed.get(
                        "client_id",
                        self.get_client_id(),
                    )
                ),

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
    # SOCKET.IO ALERT
    # ========================================================

    def _emit_alert_data(
        self,
        alert_data,
    ):

        if not self.socketio:
            return

        try:

            payload = {

                "id": None,

                "timestamp": (
                    alert_data[
                        "timestamp"
                    ].isoformat()
                ),

                "detection_type":
                    alert_data[
                        "detection_type"
                    ],

                "source_ip":
                    alert_data[
                        "source_ip"
                    ],

                "destination_ip":
                    alert_data[
                        "destination_ip"
                    ],

                "protocol":
                    alert_data[
                        "protocol"
                    ],

                "severity":
                    alert_data[
                        "severity"
                    ],

                "confidence":
                    alert_data[
                        "confidence"
                    ],

                "description":
                    alert_data[
                        "description"
                    ],

                "status":
                    alert_data[
                        "status"
                    ],

                "client_id":
                    alert_data[
                        "client_id"
                    ],

                "is_demo":
                    alert_data[
                        "is_demo"
                    ],

            }

            self.socketio.emit(
                "alert:new",
                payload,
            )

        except Exception:
            pass

    # ========================================================
    # ALERT EMITTER COMPATIBILITY
    # ========================================================

    def emit_alert(
        self,
        alert,
    ):

        try:

            data = {

                "timestamp":
                    getattr(
                        alert,
                        "timestamp",
                        None,
                    ),

                "detection_type":
                    getattr(
                        alert,
                        "detection_type",
                        "unknown",
                    ),

                "source_ip":
                    getattr(
                        alert,
                        "source_ip",
                        "unknown",
                    ),

                "destination_ip":
                    getattr(
                        alert,
                        "destination_ip",
                        None,
                    ),

                "protocol":
                    getattr(
                        alert,
                        "protocol",
                        None,
                    ),

                "severity":
                    getattr(
                        alert,
                        "severity",
                        "MEDIUM",
                    ),

                "confidence":
                    getattr(
                        alert,
                        "confidence",
                        0.5,
                    ),

                "description":
                    getattr(
                        alert,
                        "description",
                        "",
                    ),

                "status":
                    getattr(
                        alert,
                        "status",
                        "new",
                    ),

                "client_id":
                    normalize_client_id(
                        getattr(
                            alert,
                            "client_id",
                            self.get_client_id(),
                        )
                    ),

                "is_demo":
                    bool(
                        getattr(
                            alert,
                            "is_demo",
                            False,
                        )
                    ),

            }

            self._emit_alert_data(
                data
            )

        except Exception:
            pass

    # ========================================================
    # LIVE CAPTURE LOOP
    # ========================================================

    def _capture_loop(
        self,
    ):

        try:

            self.discover_local_identity()

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

            self.set_error(
                exc
            )

        finally:

            self.flush_pending(
                force=True
            )

            self.running = False

    # ========================================================
    # BACKGROUND ENRICHMENT
    # ========================================================

    def _background_enrichment(
        self,
        client_id=None,
    ):

        app = self._unwrap_app(
            self.app
        )

        client_namespace = normalize_client_id(
            client_id
            if client_id is not None
            else self.get_client_id()
        )

        if self.current_mode() == "DEMO":
            return

        try:

            self.refresh_windows_neighbors(
                force=True
            )

            if app is not None:

                with app.app_context():

                    self.enrich_existing_devices(
                        client_id=client_namespace
                    )

        except Exception as exc:

            self.set_error(
                exc
            )

    # ========================================================
    # DEVICE ENRICHMENT
    # ========================================================

    def enrich_existing_devices(
        self,
        client_id=None,
    ):

        if self.current_mode() == "DEMO":
            return

        self.discover_local_identity()

        self.refresh_windows_neighbors(
            force=True
        )

        client_namespace = normalize_client_id(
            client_id
            if client_id is not None
            else self.get_client_id()
        )

        devices = (
            Device.query
            .filter_by(
                is_demo=False,
                client_id=client_namespace,
            )
            .limit(2000)
            .all()
        )

        changed = False

        now = self.utc_now()

        for device in devices:

            ip = device.ip_address

            if not self.is_valid_ip(
                ip
            ):
                continue

            if not self.is_private_or_local_ip(
                ip
            ):
                continue

            if not device.mac_address:

                mac = self.lookup_mac(
                    ip
                )

                if mac:

                    device.mac_address = mac
                    changed = True

            if not device.hostname:

                hostname = (
                    self.resolve_hostname(
                        ip
                    )
                )

                if hostname:

                    device.hostname = (
                        hostname
                    )

                    changed = True

            if (
                device.status
                not in {
                    "suspicious",
                    "critical",
                }
            ):

                if device.status != "normal":

                    device.status = "normal"

                    changed = True

        if changed:

            try:

                db.session.commit()

            except Exception as exc:

                db.session.rollback()

                self.set_error(
                    exc
                )

    # ========================================================
    # START LIVE
    # ========================================================

    def start(
        self,
        interface=None,
        client_id=None,
    ):

        if self.running:

            return {
                "success": True,
                "message":
                    "Capture already running.",
                "interface":
                    str(
                        self.interface
                    )
                    if self.interface
                    else None,
                "client_id":
                    self.get_client_id(),
            }

        if client_id is not None:

            self.set_client_id(
                client_id
            )

        client_namespace = (
            self.get_client_id()
        )

        self.last_error = None
        self.packets_captured = 0
        self.started_at = (
            self.utc_now()
        )
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
                "client_id": client_namespace,
            }

        app = self._unwrap_app(
            self.app
        )

        if app is not None:

            try:

                self.detector = (
                    DetectionEngine(
                        app
                    )
                )

            except Exception as exc:

                self.set_error(
                    exc
                )

                return {
                    "success": False,
                    "message":
                        "IDS initialization failed.",
                    "error":
                        str(exc),
                    "client_id":
                        client_namespace,
                }

        self.discover_local_identity()

        self.running = True

        self.thread = threading.Thread(
            target=self._capture_loop,
            name="NETSENTINEL-Capture",
            daemon=True,
        )

        self.thread.start()

        enrichment_thread = threading.Thread(
            target=self._background_enrichment,
            args=(
                client_namespace,
            ),
            name="NETSENTINEL-Enrichment",
            daemon=True,
        )

        enrichment_thread.start()

        return {
            "success": True,
            "message":
                "Live capture started.",
            "interface":
                str(
                    self.interface
                ),
            "client_id":
                client_namespace,
        }

    # ========================================================
    # STOP
    # ========================================================

    def stop(
        self,
    ):

        self.running = False

        self.flush_pending(
            force=True
        )

        return {
            "success": True,
            "message":
                "Capture stopped.",
            "client_id":
                self.get_client_id(),
        }

    # ========================================================
    # STATUS
    # ========================================================

    def status(
        self,
    ):

        uptime_seconds = 0

        if self.started_at:

            try:

                uptime_seconds = int(
                    (
                        self.utc_now()
                        - self.started_at
                    ).total_seconds()
                )

                uptime_seconds = max(
                    0,
                    uptime_seconds,
                )

            except Exception:

                uptime_seconds = 0

        return {

            "running":
                bool(
                    self.running
                ),

            "interface":
                (
                    str(
                        self.interface
                    )
                    if self.interface
                    else None
                ),

            "packets_captured":
                int(
                    self.packets_captured
                ),

            "last_packet_at":
                (
                    self.last_packet_at.isoformat()
                    if self.last_packet_at
                    else None
                ),

            "last_error":
                self.last_error,

            "uptime_seconds":
                uptime_seconds,

            "mode":
                self.current_mode(),

            "client_id":
                self.get_client_id(),

        }


# ============================================================
# GLOBAL MANAGER
# ============================================================

_capture_manager = None

_capture_manager_lock = (
    threading.RLock()
)


def get_manager(
    app=None,
    socketio=None,
    client_id=None,
):

    global _capture_manager

    real_app = (
        CaptureManager._unwrap_app(
            app
        )
    )

    with _capture_manager_lock:

        if _capture_manager is None:

            _capture_manager = (
                CaptureManager(
                    app=real_app,
                    client_id=(
                        client_id
                        if client_id is not None
                        else DEFAULT_CLIENT_ID
                    ),
                )
            )

        if real_app is not None:

            _capture_manager.configure(
                app=real_app,
                socketio=socketio,
                client_id=client_id,
            )

        elif socketio is not None:

            _capture_manager.socketio = (
                socketio
            )

        return _capture_manager


# ============================================================
# START LIVE CAPTURE
# ============================================================

def start_capture(
    app,
    interface=None,
    socketio=None,
    client_id=None,
):

    real_app = (
        CaptureManager._unwrap_app(
            app
        )
    )

    manager = get_manager(
        app=real_app,
        socketio=socketio,
        client_id=client_id,
    )

    return manager.start(
        interface=interface,
        client_id=client_id,
    )


# ============================================================
# DEMO DEVICES
# ============================================================

DEMO_DEVICES = [

    {
        "ip":
            "10.10.10.10",
        "mac":
            "02:10:10:10:10:10",
        "name":
            "WORKSTATION-01",
    },

    {
        "ip":
            "10.10.10.20",
        "mac":
            "02:10:10:10:10:20",
        "name":
            "WORKSTATION-02",
    },

    {
        "ip":
            "10.10.10.30",
        "mac":
            "02:10:10:10:10:30",
        "name":
            "DEV-LAPTOP",
    },

    {
        "ip":
            "10.10.10.40",
        "mac":
            "02:10:10:10:10:40",
        "name":
            "FILE-SERVER",
    },

    {
        "ip":
            "10.10.10.50",
        "mac":
            "02:10:10:10:10:50",
        "name":
            "DATABASE-SERVER",
    },

    {
        "ip":
            "10.10.10.60",
        "mac":
            "02:10:10:10:10:60",
        "name":
            "SECURITY-CLIENT",
    },

]


DEMO_EXTERNAL_SERVICES = [

    {
        "ip":
            "8.8.8.8",
        "mac":
            "02:08:08:08:08:08",
        "port":
            53,
        "protocol":
            "UDP",
    },

    {
        "ip":
            "1.1.1.1",
        "mac":
            "02:01:01:01:01:01",
        "port":
            53,
        "protocol":
            "UDP",
    },

    {
        "ip":
            "142.250.183.14",
        "mac":
            "02:14:25:18:31:14",
        "port":
            443,
        "protocol":
            "TCP",
    },

    {
        "ip":
            "151.101.1.69",
        "mac":
            "02:15:10:01:06:09",
        "port":
            443,
        "protocol":
            "TCP",
    },

    {
        "ip":
            "104.18.32.47",
        "mac":
            "02:10:18:32:47:01",
        "port":
            443,
        "protocol":
            "TCP",
    },

]


# ============================================================
# DEMO PACKET BUILDERS
# ============================================================

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

        while (
            destination["ip"]
            == source["ip"]
        ):

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
# DEMO STATE
# ============================================================

_demo_thread = None

_demo_running = False

_demo_lock = threading.RLock()


# ============================================================
# DEMO CYCLE
# ============================================================

def _run_demo_cycle(
    manager,
    client_id=None,
):

    client_namespace = normalize_client_id(
        client_id
        if client_id is not None
        else manager.get_client_id()
    )

    # --------------------------------------------------------
    # NORMAL
    # --------------------------------------------------------

    for _ in range(15):

        if not _demo_running:
            return

        manager.process_packet(
            _demo_normal_packet(),
            is_demo=True,
            client_id=client_namespace,
        )

        time.sleep(
            0.08
        )

    # --------------------------------------------------------
    # INTERNAL
    # --------------------------------------------------------

    for _ in range(10):

        if not _demo_running:
            return

        manager.process_packet(
            _demo_internal_packet(),
            is_demo=True,
            client_id=client_namespace,
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
            client_id=client_namespace,
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
            client_id=client_namespace,
        )

        time.sleep(
            0.025
        )

    # --------------------------------------------------------
    # CONNECTION BURST
    # --------------------------------------------------------

    for packet in (
        _demo_connection_burst_packets()
    ):

        if not _demo_running:
            return

        manager.process_packet(
            packet,
            is_demo=True,
            client_id=client_namespace,
        )

        time.sleep(
            0.015
        )

    # --------------------------------------------------------
    # Force a final batch flush after the complete cycle.
    # --------------------------------------------------------

    manager.flush_pending(
        force=True
    )


# ============================================================
# DEMO LOOP
# ============================================================

def _demo_loop(
    app,
    socketio=None,
    client_id=None,
):

    global _demo_running

    manager = None

    client_namespace = normalize_client_id(
        client_id
        if client_id is not None
        else DEFAULT_CLIENT_ID
    )

    try:

        manager = get_manager(
            app=app,
            socketio=socketio,
            client_id=client_namespace,
        )

        manager.client_id = (
            client_namespace
        )

        manager.interface = "DEMO"
        manager.running = True

        if manager.started_at is None:

            manager.started_at = (
                manager.utc_now()
            )

        while _demo_running:

            _run_demo_cycle(
                manager,
                client_id=client_namespace,
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

            manager.flush_pending(
                force=True
            )

            manager.running = False


# ============================================================
# START DEMO
# ============================================================

def start_demo_if_enabled(
    app,
    socketio=None,
    client_id=None,
):

    global _demo_thread
    global _demo_running

    real_app = (
        CaptureManager._unwrap_app(
            app
        )
    )

    if real_app is None:

        return {
            "success": False,
            "started": False,
            "message":
                "Flask application unavailable.",
        }

    client_namespace = normalize_client_id(
        client_id
        if client_id is not None
        else DEFAULT_CLIENT_ID
    )

    config = real_app.config

    # --------------------------------------------------------
    # MONITORING ENABLED
    #
    # This check was missing before.
    # --------------------------------------------------------

    monitoring_enabled = (
        config.get(
            "MONITORING_ENABLED",
            False,
        )
    )

    if isinstance(
        monitoring_enabled,
        str,
    ):

        monitoring_enabled = (
            monitoring_enabled.strip().lower()
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
            "mode": str(
                config.get(
                    "NETSENTINEL_MODE",
                    "DEMO",
                )
            ).upper(),
            "client_id":
                client_namespace,
            "message":
                "Monitoring is disabled.",
        }

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
            "client_id":
                client_namespace,
            "message":
                (
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
                "client_id":
                    client_namespace,
                "message":
                    "Demo generator already running.",
            }

        _demo_running = True

        manager = get_manager(
            app=real_app,
            socketio=socketio,
            client_id=client_namespace,
        )

        manager.client_id = (
            client_namespace
        )

        manager.interface = "DEMO"
        manager.running = True
        manager.started_at = (
            manager.utc_now()
        )
        manager.last_packet_at = None
        manager.last_error = None

        _demo_thread = threading.Thread(
            target=_demo_loop,
            args=(
                real_app,
                socketio,
                client_namespace,
            ),
            name="NETSENTINEL-Demo",
            daemon=True,
        )

        _demo_thread.start()

    return {
        "success": True,
        "started": True,
        "mode": mode,
        "client_id":
            client_namespace,
        "message":
            "Demo traffic generator started.",
    }


# ============================================================
# STOP DEMO
# ============================================================

def stop_demo():

    global _demo_running

    with _demo_lock:

        _demo_running = False

    if _capture_manager is not None:

        _capture_manager.flush_pending(
            force=True
        )

        if (
            _capture_manager.current_mode()
            == "DEMO"
        ):

            _capture_manager.running = False

    return {
        "success": True,
        "stopped": True,
        "message":
            "Demo traffic generator stopped.",
    }


# ============================================================
# DEMO STATUS
# ============================================================

def demo_status():

    return {

        "running":
            bool(
                _demo_running
            ),

        "thread_alive":
            bool(
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
    client_id=None,
):

    try:

        real_app = (
            CaptureManager._unwrap_app(
                app
            )
        )

        if real_app is None:

            return {
                "success": False,
                "started": False,
                "message":
                    "Flask application unavailable.",
            }

        client_namespace = normalize_client_id(
            client_id
            if client_id is not None
            else DEFAULT_CLIENT_ID
        )

        config = real_app.config

        # ----------------------------------------------------
        # MONITORING ENABLED
        # ----------------------------------------------------

        monitoring_enabled = (
            config.get(
                "MONITORING_ENABLED",
                False,
            )
        )

        if isinstance(
            monitoring_enabled,
            str,
        ):

            monitoring_enabled = (
                monitoring_enabled.strip().lower()
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
                "message":
                    "Monitoring is disabled.",
                "mode":
                    str(
                        config.get(
                            "NETSENTINEL_MODE",
                            "DEMO",
                        )
                    ).upper(),
                "client_id":
                    client_namespace,
            }

        # ----------------------------------------------------
        # MODE
        # ----------------------------------------------------

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

        # ----------------------------------------------------
        # DEMO
        # ----------------------------------------------------

        if mode in {
            "DEMO",
            "SIMULATION",
            "TEST",
        }:

            return start_demo_if_enabled(
                app=real_app,
                socketio=socketio,
                client_id=client_namespace,
            )

        # ----------------------------------------------------
        # LIVE
        # ----------------------------------------------------

        if mode in {
            "LIVE",
            "PRODUCTION",
            "REAL",
        }:

            result = start_capture(
                app=real_app,
                interface=interface,
                socketio=socketio,
                client_id=client_namespace,
            )

            result["mode"] = mode

            result["client_id"] = (
                client_namespace
            )

            return result

        return {
            "success": True,
            "started": False,
            "message":
                (
                    "Capture not auto-started "
                    f"because mode is {mode}."
                ),
            "mode": mode,
            "client_id":
                client_namespace,
        }

    except Exception as exc:

        try:

            real_app = (
                CaptureManager._unwrap_app(
                    app
                )
            )

            manager = get_manager(
                app=real_app,
                socketio=socketio,
                client_id=client_id,
            )

            manager.last_error = str(
                exc
            )

        except Exception:
            pass

        return {
            "success": False,
            "started": False,
            "message":
                "Capture initialization failed.",
            "error":
                str(exc),
        }