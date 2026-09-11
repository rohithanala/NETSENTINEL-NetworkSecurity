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
#
# Multi-client DEMO mode.
#
# Every browser/client gets its own DEMO worker and client_id.
# ============================================================


_demo_threads: dict[str, threading.Thread] = {}
_demo_running: dict[str, bool] = {}

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
# CLIENT-SPECIFIC DEMO DEVICES
# ============================================================


def _client_devices(client_id: str) -> list[dict]:
    """
    Create a deterministic DEMO network for a client.

    Different client IDs produce different private TEST-network
    addresses, so separate browsers do not see the exact same
    simulated device addresses.
    """

    client_id = str(
        client_id or "legacy"
    ).strip()

    if not client_id:
        client_id = "legacy"

    seed = sum(
        ord(character) * (index + 1)
        for index, character in enumerate(client_id)
    )

    rng = random.Random(seed)

    network_octet = rng.randint(
        10,
        220,
    )

    names = [
        "WORKSTATION-01",
        "WORKSTATION-02",
        "DEV-LAPTOP",
        "FILE-SERVER",
        "DATABASE-SERVER",
        "SECURITY-CLIENT",
    ]

    devices = []

    for index, name in enumerate(
        names,
        start=1,
    ):

        mac_1 = (
            seed + index * 17
        ) % 256

        mac_2 = (
            seed + index * 31
        ) % 256

        mac_3 = (
            seed + index * 47
        ) % 256

        mac = (
            f"02:{network_octet:02x}:"
            f"{index:02x}:"
            f"{mac_1:02x}:"
            f"{mac_2:02x}:"
            f"{mac_3:02x}"
        )

        devices.append(
            {
                "ip": (
                    f"10.{network_octet}."
                    f"{index}.10"
                ),
                "mac": mac,
                "name": name,
            }
        )

    return devices


# ============================================================
# PACKET BUILDERS
# ============================================================


def _ether(
    src_mac,
    dst_mac,
):
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


def _generate_normal_packet(
    devices,
):
    source = random.choice(
        devices
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
            devices
        )

        attempts = 0

        while (
            destination["ip"] == source["ip"]
            and attempts < 10
        ):
            destination = random.choice(
                devices
            )

            attempts += 1

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


def _generate_internal_packet(
    devices,
):
    source = random.choice(
        devices[:3]
    )

    destination = random.choice(
        devices[3:]
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
            45,
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
    client_id,
):
    """
    Pass the synthetic packet through the normal capture
    processing pipeline while preserving the client namespace.
    """

    try:

        manager.process_packet(
            packet,
            is_demo=True,
            client_id=client_id,
        )

    except Exception as exc:

        try:

            manager.set_error(
                exc
            )

        except Exception:

            pass


# ============================================================
# CLIENT RUNNING STATE
# ============================================================


def _is_client_running(
    client_id: str,
) -> bool:

    with _demo_lock:

        return bool(
            _demo_running.get(
                client_id,
                False,
            )
        )


# ============================================================
# DEMO SCENARIO
# ============================================================


def _run_demo_cycle(
    manager,
    client_id,
):
    devices = _client_devices(
        client_id
    )

    # --------------------------------------------------------
    # Normal mixed traffic
    # --------------------------------------------------------

    for _ in range(12):

        if not _is_client_running(
            client_id
        ):
            return

        packet = _generate_normal_packet(
            devices
        )

        _emit_packet(
            packet,
            manager,
            client_id,
        )

        time.sleep(
            0.08
        )

    # --------------------------------------------------------
    # Internal application traffic
    # --------------------------------------------------------

    for _ in range(8):

        if not _is_client_running(
            client_id
        ):
            return

        packet = _generate_internal_packet(
            devices
        )

        _emit_packet(
            packet,
            manager,
            client_id,
        )

        time.sleep(
            0.08
        )

    # --------------------------------------------------------
    # ICMP monitoring
    # --------------------------------------------------------

    source = random.choice(
        devices
    )

    destination = random.choice(
        devices
    )

    attempts = 0

    while (
        destination["ip"] == source["ip"]
        and attempts < 10
    ):

        destination = random.choice(
            devices
        )

        attempts += 1

    for _ in range(4):

        if not _is_client_running(
            client_id
        ):
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
            client_id,
        )

        time.sleep(
            0.08
        )

    # --------------------------------------------------------
    # Port scan scenario
    # --------------------------------------------------------

    scanner = devices[2]
    target = devices[4]

    scan_packets = _generate_port_scan(
        scanner,
        target,
    )

    for packet in scan_packets:

        if not _is_client_running(
            client_id
        ):
            return

        _emit_packet(
            packet,
            manager,
            client_id,
        )

        time.sleep(
            0.025
        )

    # --------------------------------------------------------
    # High connection-rate scenario
    # --------------------------------------------------------

    source = devices[1]
    destination = devices[3]

    burst_packets = _generate_connection_burst(
        source,
        destination,
    )

    for packet in burst_packets:

        if not _is_client_running(
            client_id
        ):
            return

        _emit_packet(
            packet,
            manager,
            client_id,
        )

        time.sleep(
            0.015
        )


# ============================================================
# DEMO LOOP FOR ONE CLIENT
# ============================================================


def _demo_loop(
    app,
    socketio,
    client_id,
):
    try:

        manager = get_manager(
            app=app,
            socketio=socketio,
            client_id=client_id,
        )

        while _is_client_running(
            client_id
        ):

            _run_demo_cycle(
                manager,
                client_id,
            )

            if not _is_client_running(
                client_id
            ):
                break

            time.sleep(
                1.0
            )

    except Exception as exc:

        try:

            manager = get_manager(
                app=app,
                socketio=socketio,
                client_id=client_id,
            )

            manager.set_error(
                exc
            )

        except Exception:

            pass

    finally:

        with _demo_lock:

            _demo_running[
                client_id
            ] = False


# ============================================================
# CONFIGURATION CHECK
# ============================================================


def _demo_enabled(
    app,
):
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

    enabled = (
        mode in {
            "DEMO",
            "SIMULATION",
            "TEST",
        }
        and bool(
            monitoring_enabled
        )
    )

    return (
        enabled,
        mode,
        bool(
            monitoring_enabled
        ),
        real_app,
    )


# ============================================================
# START DEMO FOR ONE CLIENT
# ============================================================


def start_demo_for_client(
    app,
    client_id,
    socketio=None,
):
    """
    Start an isolated DEMO worker for a specific client.
    """

    (
        enabled,
        mode,
        monitoring_enabled,
        real_app,
    ) = _demo_enabled(
        app
    )

    client_id = str(
        client_id or "legacy"
    ).strip()

    if not client_id:
        client_id = "legacy"

    if mode not in {
        "DEMO",
        "SIMULATION",
        "TEST",
    }:

        return {
            "success": True,
            "started": False,
            "mode": mode,
            "client_id": client_id,
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
            "client_id": client_id,
            "message": (
                "Demo generator not started "
                "because monitoring is disabled."
            ),
        }

    if not enabled:

        return {
            "success": True,
            "started": False,
            "mode": mode,
            "client_id": client_id,
            "message": (
                "Demo generator is not enabled."
            ),
        }

    with _demo_lock:

        existing_thread = _demo_threads.get(
            client_id
        )

        if (
            _demo_running.get(
                client_id,
                False,
            )
            and existing_thread
            and existing_thread.is_alive()
        ):

            return {
                "success": True,
                "started": True,
                "mode": mode,
                "client_id": client_id,
                "message": (
                    "Demo traffic generator already "
                    "running for this client."
                ),
            }

        _demo_running[
            client_id
        ] = True

        thread = threading.Thread(
            target=_demo_loop,
            args=(
                real_app,
                socketio,
                client_id,
            ),
            name=(
                "NETSENTINEL-Demo-"
                f"{client_id[:24]}"
            ),
            daemon=True,
        )

        _demo_threads[
            client_id
        ] = thread

        thread.start()

    return {
        "success": True,
        "started": True,
        "mode": mode,
        "client_id": client_id,
        "message": (
            "Demo traffic generator started "
            "for this client."
        ),
    }


# ============================================================
# BACKWARD-COMPATIBLE START
# ============================================================


def start_demo_if_enabled(
    app,
    socketio=None,
    client_id=None,
):
    """
    Existing code can still call the original function.

    A supplied client_id gets its own DEMO worker.
    """

    return start_demo_for_client(
        app=app,
        client_id=(
            client_id or "legacy"
        ),
        socketio=socketio,
    )


# ============================================================
# STOP ONE CLIENT
# ============================================================


def stop_demo_for_client(
    client_id,
):
    client_id = str(
        client_id or "legacy"
    ).strip()

    if not client_id:
        client_id = "legacy"

    with _demo_lock:

        _demo_running[
            client_id
        ] = False

    return {
        "success": True,
        "stopped": True,
        "client_id": client_id,
        "message": (
            "Demo traffic generator stopped "
            "for this client."
        ),
    }


# ============================================================
# STOP ALL CLIENTS
# ============================================================


def stop_demo():

    with _demo_lock:

        for client_id in list(
            _demo_running.keys()
        ):

            _demo_running[
                client_id
            ] = False

    return {
        "success": True,
        "stopped": True,
        "message": (
            "All DEMO traffic generators stopped."
        ),
    }


# ============================================================
# DEMO STATUS
# ============================================================


def demo_status(
    client_id=None,
):

    if client_id is not None:

        client_id = str(
            client_id
        ).strip()

        if not client_id:
            client_id = "legacy"

        thread = _demo_threads.get(
            client_id
        )

        return {
            "running": bool(
                _demo_running.get(
                    client_id,
                    False,
                )
            ),
            "thread_alive": bool(
                thread
                and thread.is_alive()
            ),
            "client_id": client_id,
        }

    with _demo_lock:

        active_clients = []

        for (
            current_client_id,
            running,
        ) in _demo_running.items():

            if not running:
                continue

            thread = _demo_threads.get(
                current_client_id
            )

            active_clients.append(
                {
                    "client_id": current_client_id,
                    "running": True,
                    "thread_alive": bool(
                        thread
                        and thread.is_alive()
                    ),
                }
            )

    return {
        "running": bool(
            active_clients
        ),
        "thread_alive": any(
            item["thread_alive"]
            for item in active_clients
        ),
        "clients": active_clients,
    }