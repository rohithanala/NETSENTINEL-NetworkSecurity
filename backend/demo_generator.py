from __future__ import annotations

import random
import threading
import time

from scapy.all import (
    Ether,
    ICMP,
    IP,
    TCP,
    UDP,
)

from .capture import get_manager


# ============================================================
# NETSENTINEL
# DEMO TRAFFIC GENERATOR
# ============================================================


_demo_thread = None
_demo_running = False
_demo_lock = threading.RLock()


# ============================================================
# DEMO NETWORK
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


EXTERNAL_SERVICES = [
    {
        "ip": "8.8.8.8",
        "port": 53,
        "protocol": "UDP",
    },
    {
        "ip": "1.1.1.1",
        "port": 53,
        "protocol": "UDP",
    },
    {
        "ip": "142.250.183.14",
        "port": 443,
        "protocol": "TCP",
    },
    {
        "ip": "151.101.1.69",
        "port": 443,
        "protocol": "TCP",
    },
    {
        "ip": "104.18.32.47",
        "port": 443,
        "protocol": "TCP",
    },
]


# ============================================================
# PACKET BUILDERS
# ============================================================


def _ether(src_mac, dst_mac):
    return Ether(
        src=src_mac,
        dst=dst_mac,
    )


def _tcp_packet(
    source_ip,
    destination_ip,
    source_port,
    destination_port,
    source_mac=None,
    destination_mac=None,
):
    packet = (
        IP(
            src=source_ip,
            dst=destination_ip,
        )
        / TCP(
            sport=source_port,
            dport=destination_port,
            flags="S",
        )
    )

    if source_mac and destination_mac:
        packet = (
            _ether(
                source_mac,
                destination_mac,
            )
            / packet
        )

    return packet


def _udp_packet(
    source_ip,
    destination_ip,
    source_port,
    destination_port,
    source_mac=None,
    destination_mac=None,
):
    packet = (
        IP(
            src=source_ip,
            dst=destination_ip,
        )
        / UDP(
            sport=source_port,
            dport=destination_port,
        )
        / b"NETSENTINEL-DEMO"
    )

    if source_mac and destination_mac:
        packet = (
            _ether(
                source_mac,
                destination_mac,
            )
            / packet
        )

    return packet


def _icmp_packet(
    source_ip,
    destination_ip,
    source_mac=None,
    destination_mac=None,
):
    packet = (
        IP(
            src=source_ip,
            dst=destination_ip,
        )
        / ICMP()
    )

    if source_mac and destination_mac:
        packet = (
            _ether(
                source_mac,
                destination_mac,
            )
            / packet
        )

    return packet


# ============================================================
# NORMAL TRAFFIC
# ============================================================


def _generate_normal_packet():
    source = random.choice(
        DEMO_DEVICES
    )

    traffic_type = random.choice(
        [
            "tcp",
            "tcp",
            "tcp",
            "udp",
            "icmp",
        ]
    )

    if traffic_type == "icmp":
        destination = random.choice(
            DEMO_DEVICES
        )

        if destination["ip"] == source["ip"]:
            destination = random.choice(
                DEMO_DEVICES
            )

        return _icmp_packet(
            source_ip=source["ip"],
            destination_ip=destination["ip"],
            source_mac=source["mac"],
            destination_mac=destination["mac"],
        )

    if traffic_type == "udp":
        service = random.choice(
            EXTERNAL_SERVICES[:2]
        )

        return _udp_packet(
            source_ip=source["ip"],
            destination_ip=service["ip"],
            source_port=random.randint(
                40000,
                60000,
            ),
            destination_port=service["port"],
            source_mac=source["mac"],
        )

    service = random.choice(
        EXTERNAL_SERVICES[2:]
    )

    return _tcp_packet(
        source_ip=source["ip"],
        destination_ip=service["ip"],
        source_port=random.randint(
            40000,
            60000,
        ),
        destination_port=service["port"],
        source_mac=source["mac"],
    )


# ============================================================
# INTERNAL SERVER TRAFFIC
# ============================================================


def _generate_internal_packet():
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

    return _tcp_packet(
        source_ip=source["ip"],
        destination_ip=destination["ip"],
        source_port=random.randint(
            40000,
            60000,
        ),
        destination_port=destination_port,
        source_mac=source["mac"],
        destination_mac=destination["mac"],
    )


# ============================================================
# PORT SCAN TRAFFIC
# ============================================================


def _generate_port_scan(
    source,
    destination,
):
    packets = []

    ports = list(
        range(
            20,
            20 + 25,
        )
    )

    random.shuffle(
        ports
    )

    for port in ports:
        packets.append(
            _tcp_packet(
                source_ip=source["ip"],
                destination_ip=destination["ip"],
                source_port=random.randint(
                    30000,
                    60000,
                ),
                destination_port=port,
                source_mac=source["mac"],
                destination_mac=destination["mac"],
            )
        )

    return packets


# ============================================================
# HIGH CONNECTION RATE
# ============================================================


def _generate_connection_burst(
    source,
    destination,
):
    packets = []

    for _ in range(65):
        destination_port = random.choice(
            [
                80,
                443,
                8080,
                8443,
                22,
            ]
        )

        packets.append(
            _tcp_packet(
                source_ip=source["ip"],
                destination_ip=destination["ip"],
                source_port=random.randint(
                    30000,
                    60000,
                ),
                destination_port=destination_port,
                source_mac=source["mac"],
                destination_mac=destination["mac"],
            )
        )

    return packets


# ============================================================
# PACKET EMISSION
# ============================================================


def _emit_packet(
    packet,
    manager,
):
    try:
        manager.process_packet(
            packet,
            is_demo=True,
        )
    except Exception as exc:
        try:
            manager.set_error(
                exc
            )
        except Exception:
            pass


# ============================================================
# DEMO SCENARIO
# ============================================================


def _run_demo_cycle(
    manager,
):
    # --------------------------------------------------------
    # Normal mixed traffic
    # --------------------------------------------------------

    for _ in range(12):
        if not _demo_running:
            return

        packet = _generate_normal_packet()

        _emit_packet(
            packet,
            manager,
        )

        time.sleep(
            0.08
        )

    # --------------------------------------------------------
    # Internal application traffic
    # --------------------------------------------------------

    for _ in range(8):
        if not _demo_running:
            return

        packet = _generate_internal_packet()

        _emit_packet(
            packet,
            manager,
        )

        time.sleep(
            0.08
        )

    # --------------------------------------------------------
    # ICMP monitoring
    # --------------------------------------------------------

    source = random.choice(
        DEMO_DEVICES
    )

    destination = random.choice(
        DEMO_DEVICES
    )

    for _ in range(4):
        if not _demo_running:
            return

        packet = _icmp_packet(
            source_ip=source["ip"],
            destination_ip=destination["ip"],
            source_mac=source["mac"],
            destination_mac=destination["mac"],
        )

        _emit_packet(
            packet,
            manager,
        )

        time.sleep(
            0.08
        )

    # --------------------------------------------------------
    # Port scan scenario
    # --------------------------------------------------------

    scanner = DEMO_DEVICES[2]
    target = DEMO_DEVICES[4]

    scan_packets = _generate_port_scan(
        scanner,
        target,
    )

    for packet in scan_packets:
        if not _demo_running:
            return

        _emit_packet(
            packet,
            manager,
        )

        time.sleep(
            0.025
        )

    # --------------------------------------------------------
    # High connection-rate scenario
    # --------------------------------------------------------

    source = DEMO_DEVICES[1]
    destination = DEMO_DEVICES[3]

    burst_packets = _generate_connection_burst(
        source,
        destination,
    )

    for packet in burst_packets:
        if not _demo_running:
            return

        _emit_packet(
            packet,
            manager,
        )

        time.sleep(
            0.015
        )


# ============================================================
# DEMO LOOP
# ============================================================


def _demo_loop(
    app,
    socketio=None,
):
    global _demo_running

    try:
        manager = get_manager(
            app=app,
            socketio=socketio,
        )

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
        try:
            manager = get_manager(
                app=app,
                socketio=socketio,
            )

            manager.set_error(
                exc
            )

        except Exception:
            pass

    finally:
        _demo_running = False


# ============================================================
# START DEMO
# ============================================================


def start_demo_if_enabled(
    app,
    socketio=None,
):
    global _demo_thread
    global _demo_running

    real_app = getattr(
        app,
        "_get_current_object",
        lambda: app,
    )()

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

    monitoring_enabled = config.get(
        "MONITORING_ENABLED",
        True,
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
                "because application mode is "
                f"{mode}."
            ),
        }

    if not monitoring_enabled:
        return {
            "success": True,
            "started": False,
            "mode": mode,
            "message": (
                "Demo generator not started "
                "because monitoring is disabled."
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


# ============================================================
# STOP DEMO
# ============================================================


def stop_demo():
    global _demo_running

    with _demo_lock:
        _demo_running = False

    return {
        "success": True,
        "stopped": True,
        "message": (
            "Demo traffic generator stopped."
        ),
    }


# ============================================================
# DEMO STATUS
# ============================================================


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