from datetime import datetime, timezone, timedelta

from sqlalchemy import func, distinct

from flask import (
    Blueprint,
    jsonify,
    request,
    current_app,
)

from backend.app_factory import db
from backend.models import (
    Traffic,
    Alert,
    Device,
)
from backend.capture import get_manager
from backend.client_identity import get_request_client_id


api = Blueprint(
    "api",
    __name__,
)


# ============================================================
# HELPERS
# ============================================================

def iso(value):
    """
    Convert datetime to ISO-8601.
    """
    return value.isoformat() if value else None


def safe_int(value, default=0):
    try:
        return int(value)
    except (
        TypeError,
        ValueError,
    ):
        return default


def normalize_dt(value):
    """
    Normalize datetime for safe Python comparisons.

    SQLite may return naive datetime values.
    NETSENTINEL stores its live timestamps as UTC values.
    """

    if value is None:
        return None

    if value.tzinfo is None:
        return value

    return value.astimezone(
        timezone.utc
    ).replace(
        tzinfo=None
    )


def is_local_or_private_ip(ip):
    """
    Determine whether an IP belongs to a local/private range.
    """

    if not ip:
        return False

    ip = str(ip).strip().lower()

    # --------------------------------------------------------
    # IPv6
    # --------------------------------------------------------

    if ":" in ip:
        return (
            ip == "::1"
            or ip.startswith("fe80:")
            or ip.startswith("fc")
            or ip.startswith("fd")
        )

    # --------------------------------------------------------
    # IPv4
    # --------------------------------------------------------

    parts = ip.split(".")

    if len(parts) != 4:
        return False

    try:
        a, b, c, d = (
            int(x)
            for x in parts
        )
    except ValueError:
        return False

    if not all(
        0 <= x <= 255
        for x in (
            a,
            b,
            c,
            d,
        )
    ):
        return False

    # 10.0.0.0/8
    if a == 10:
        return True

    # 172.16.0.0/12
    if (
        a == 172
        and 16 <= b <= 31
    ):
        return True

    # 192.168.0.0/16
    if (
        a == 192
        and b == 168
    ):
        return True

    # Loopback
    if a == 127:
        return True

    # Link-local
    if (
        a == 169
        and b == 254
    ):
        return True

    return False


def normalize_protocol(protocol):
    """
    Normalize protocol names for analytics.
    """

    if not protocol:
        return "OTHER"

    value = str(
        protocol
    ).strip().upper()

    aliases = {
        "TCP": "TCP",
        "UDP": "UDP",
        "ICMP": "ICMP",
        "ICMPV4": "ICMP",
        "ICMPV6": "ICMP",
        "ARP": "ARP",
        "6": "TCP",
        "17": "UDP",
        "1": "ICMP",
        "58": "ICMP",
    }

    return aliases.get(
        value,
        value,
    )


def protocol_distribution_from_rows(rows):
    """
    Normalize protocol values in a small SQL result set.
    """

    distribution = {}

    for protocol, count in rows:
        normalized = normalize_protocol(
            protocol
        )

        distribution[normalized] = (
            distribution.get(
                normalized,
                0,
            )
            + int(count or 0)
        )

    return distribution


def get_client_id():
    """
    Return the client namespace associated with this request.

    The browser/sensor sends the value using:

        X-NETSENTINEL-CLIENT-ID

    Query-string fallback is supported by client_identity.py.
    """

    return get_request_client_id()


def client_filter(model):
    """
    Return the SQLAlchemy ownership filter for a telemetry model.

    Every telemetry record must belong to exactly one client.
    """

    return model.client_id == get_client_id()


# ============================================================
# HEALTH
# ============================================================

@api.get("/health")
def health():

    return jsonify(
        ok=True,
        service="NETSENTINEL",
    )


# ============================================================
# CAPTURE
# ============================================================

@api.get("/capture/status")
def capture_status():

    client_id = get_client_id()

    manager = get_manager(
        current_app,
        client_id=client_id,
    )

    result = manager.status()

    result["client_id"] = client_id

    return jsonify(
        result
    )


@api.post("/capture/start")
def capture_start():

    client_id = get_client_id()

    manager = get_manager(
        current_app,
        client_id=client_id,
    )

    payload = (
        request.get_json(
            silent=True
        )
        or {}
    )

    interface = payload.get(
        "interface"
    )

    result = manager.start(
        interface=interface,
        client_id=client_id,
    )

    result["client_id"] = client_id

    return jsonify(
        result
    )


@api.post("/capture/stop")
def capture_stop():

    client_id = get_client_id()

    manager = get_manager(
        current_app,
        client_id=client_id,
    )

    result = manager.stop()

    result["client_id"] = client_id

    return jsonify(
        result
    )


# ============================================================
# TRAFFIC
# ============================================================

@api.get("/traffic")
def traffic():

    limit = min(
        max(
            safe_int(
                request.args.get(
                    "limit",
                    200,
                ),
                200,
            ),
            1,
        ),
        1000,
    )

    client_id = get_client_id()

    rows = (
        db.session.query(
            Traffic.id,
            Traffic.timestamp,
            Traffic.source_ip,
            Traffic.destination_ip,
            Traffic.source_port,
            Traffic.destination_port,
            Traffic.protocol,
            Traffic.packet_size,
            Traffic.tcp_flags,
            Traffic.interface,
            Traffic.client_id,
            Traffic.is_demo,
        )
        .filter(
            Traffic.client_id == client_id
        )
        .order_by(
            Traffic.timestamp.desc()
        )
        .limit(limit)
        .all()
    )

    records = []

    for row in rows:

        records.append(
            {
                "id": row.id,
                "timestamp": iso(
                    row.timestamp
                ),
                "source_ip": row.source_ip,
                "destination_ip": row.destination_ip,
                "source_port": row.source_port,
                "destination_port": row.destination_port,
                "protocol": normalize_protocol(
                    row.protocol
                ),
                "packet_size": (
                    row.packet_size or 0
                ),
                "tcp_flags": row.tcp_flags,
                "interface": row.interface,
                "client_id": row.client_id,
                "is_demo": bool(
                    row.is_demo
                ),
            }
        )

    return jsonify(
        records
    )


# ============================================================
# ALERTS
# ============================================================

@api.get("/alerts")
def alerts():

    limit = min(
        max(
            safe_int(
                request.args.get(
                    "limit",
                    100,
                ),
                100,
            ),
            1,
        ),
        500,
    )

    client_id = get_client_id()

    rows = (
        db.session.query(
            Alert.id,
            Alert.timestamp,
            Alert.detection_type,
            Alert.source_ip,
            Alert.destination_ip,
            Alert.protocol,
            Alert.severity,
            Alert.confidence,
            Alert.description,
            Alert.status,
            Alert.client_id,
            Alert.is_demo,
        )
        .filter(
            Alert.client_id == client_id
        )
        .order_by(
            Alert.timestamp.desc()
        )
        .limit(limit)
        .all()
    )

    records = []

    for row in rows:

        records.append(
            {
                "id": row.id,
                "timestamp": iso(
                    row.timestamp
                ),
                "detection_type": row.detection_type,
                "source_ip": row.source_ip,
                "destination_ip": row.destination_ip,
                "protocol": normalize_protocol(
                    row.protocol
                ),
                "severity": row.severity,
                "confidence": row.confidence,
                "description": row.description,
                "status": row.status,
                "client_id": row.client_id,
                "is_demo": bool(
                    row.is_demo
                ),
            }
        )

    return jsonify(
        records
    )


# ============================================================
# DEVICES
# ============================================================

@api.get("/devices")
def devices():

    client_id = get_client_id()

    rows = (
        db.session.query(
            Device.id,
            Device.ip_address,
            Device.mac_address,
            Device.hostname,
            Device.first_seen,
            Device.last_seen,
            Device.packet_count,
            Device.status,
            Device.client_id,
            Device.is_demo,
        )
        .filter(
            Device.client_id == client_id
        )
        .order_by(
            Device.last_seen.desc()
        )
        .limit(500)
        .all()
    )

    records = []

    for row in rows:

        records.append(
            {
                "id": row.id,
                "ip_address": row.ip_address,
                "mac_address": row.mac_address,
                "hostname": row.hostname,
                "first_seen": iso(
                    row.first_seen
                ),
                "last_seen": iso(
                    row.last_seen
                ),
                "packet_count": (
                    row.packet_count or 0
                ),
                "status": row.status,
                "client_id": row.client_id,
                "is_demo": bool(
                    row.is_demo
                ),
            }
        )

    return jsonify(
        records
    )


# ============================================================
# STATS
# ============================================================

@api.get("/stats")
def stats():
    """
    Optimized real-time statistics.

    Statistics are calculated only from telemetry belonging
    to the requesting NETSENTINEL client.
    """

    client_id = get_client_id()

    manager = get_manager(
        current_app,
        client_id=client_id,
    )

    # --------------------------------------------------------
    # TOTAL PACKETS
    # --------------------------------------------------------

    packets_captured = (
        db.session.query(
            func.count(
                Traffic.id
            )
        )
        .filter(
            Traffic.client_id == client_id
        )
        .scalar()
        or 0
    )

    # --------------------------------------------------------
    # LATEST PACKET
    # --------------------------------------------------------

    latest_time = (
        db.session.query(
            func.max(
                Traffic.timestamp
            )
        )
        .filter(
            Traffic.client_id == client_id
        )
        .scalar()
    )

    # --------------------------------------------------------
    # ACTIVITY WINDOW
    # --------------------------------------------------------

    traffic_rate_pps = 0.0
    traffic_rate_bps = 0.0
    active_connections = 0
    active_devices = 0

    if latest_time is not None:

        normalized_latest = normalize_dt(
            latest_time
        )

        cutoff = (
            normalized_latest
            - timedelta(
                minutes=5
            )
        )

        # ----------------------------------------------------
        # SQL-SIDE TRAFFIC AGGREGATION
        # ----------------------------------------------------

        aggregate = (
            db.session.query(
                func.count(
                    Traffic.id
                ),
                func.coalesce(
                    func.sum(
                        Traffic.packet_size
                    ),
                    0,
                ),
                func.min(
                    Traffic.timestamp
                ),
                func.max(
                    Traffic.timestamp
                ),
            )
            .filter(
                Traffic.client_id == client_id,
                Traffic.timestamp >= cutoff,
                Traffic.timestamp <= normalized_latest,
            )
            .one()
        )

        packet_count = int(
            aggregate[0] or 0
        )

        total_bytes = int(
            aggregate[1] or 0
        )

        first_time = normalize_dt(
            aggregate[2]
        )

        last_time = normalize_dt(
            aggregate[3]
        )

        if (
            first_time is not None
            and last_time is not None
        ):

            elapsed = (
                last_time - first_time
            ).total_seconds()

            elapsed = max(
                elapsed,
                1.0,
            )

            traffic_rate_pps = (
                packet_count
                / elapsed
            )

            traffic_rate_bps = (
                total_bytes
                * 8
                / elapsed
            )

        # ----------------------------------------------------
        # ACTIVE CONNECTIONS
        # ----------------------------------------------------

        connection_count = (
            db.session.query(
                Traffic.source_ip,
                Traffic.destination_ip,
                Traffic.destination_port,
            )
            .filter(
                Traffic.client_id == client_id,
                Traffic.timestamp >= cutoff,
                Traffic.timestamp <= normalized_latest,
                Traffic.source_ip.isnot(None),
                Traffic.destination_ip.isnot(None),
            )
            .distinct()
            .count()
        )

        active_connections = int(
            connection_count
        )

        # ----------------------------------------------------
        # ACTIVE DEVICES
        # ----------------------------------------------------

        device_rows = (
            db.session.query(
                Traffic.source_ip,
                Traffic.destination_ip,
            )
            .filter(
                Traffic.client_id == client_id,
                Traffic.timestamp >= cutoff,
                Traffic.timestamp <= normalized_latest,
            )
            .all()
        )

        active_device_ips = set()

        for (
            source_ip,
            destination_ip,
        ) in device_rows:

            if (
                source_ip
                and is_local_or_private_ip(
                    source_ip
                )
            ):
                active_device_ips.add(
                    source_ip
                )

            if (
                destination_ip
                and is_local_or_private_ip(
                    destination_ip
                )
            ):
                active_device_ips.add(
                    destination_ip
                )

        active_devices = len(
            active_device_ips
        )

    # --------------------------------------------------------
    # SECURITY ALERTS
    # --------------------------------------------------------

    security_alerts = (
        db.session.query(
            func.count(
                Alert.id
            )
        )
        .filter(
            Alert.client_id == client_id,
            Alert.status != "resolved",
        )
        .scalar()
        or 0
    )

    # --------------------------------------------------------
    # THREATS DETECTED
    # --------------------------------------------------------

    threats_detected = (
        db.session.query(
            func.count(
                Alert.id
            )
        )
        .filter(
            Alert.client_id == client_id,
            Alert.severity.in_(
                [
                    "HIGH",
                    "CRITICAL",
                ]
            ),
        )
        .scalar()
        or 0
    )

    # --------------------------------------------------------
    # CAPTURE STATUS
    # --------------------------------------------------------

    capture = manager.status()

    monitoring_enabled = bool(
        manager.running
    )

    configured_mode = str(
        current_app.config.get(
            "NETSENTINEL_MODE",
            current_app.config.get(
                "MONITOR_MODE",
                "LIVE",
            ),
        )
    ).upper()

    # --------------------------------------------------------
    # RESPONSE
    # --------------------------------------------------------

    return jsonify(
        {
            "client_id": client_id,
            "packets_captured": int(
                packets_captured
            ),
            "active_connections": int(
                active_connections
            ),
            "active_devices": int(
                active_devices
            ),
            "security_alerts": int(
                security_alerts
            ),
            "threats_detected": int(
                threats_detected
            ),
            "traffic_rate_pps": round(
                traffic_rate_pps,
                2,
            ),
            "traffic_rate_bps": round(
                traffic_rate_bps,
                2,
            ),
            "last_packet_at": iso(
                latest_time
            ),
            "monitoring_enabled": monitoring_enabled,
            "ids_status": (
                "running"
                if monitoring_enabled
                else "stopped"
            ),
            "mode": configured_mode,
            "network_interface": capture.get(
                "interface"
            ),
            "capture": capture,
        }
    )


# ============================================================
# UPDATE ALERT
# ============================================================

@api.patch("/alerts/<int:alert_id>")
def update_alert(alert_id):

    client_id = get_client_id()

    alert = (
        db.session.query(
            Alert
        )
        .filter(
            Alert.id == alert_id,
            Alert.client_id == client_id,
        )
        .first()
    )

    if alert is None:

        return jsonify(
            {
                "ok": False,
                "error": "Alert not found.",
            }
        ), 404

    payload = (
        request.get_json(
            silent=True
        )
        or {}
    )

    status = payload.get(
        "status"
    )

    allowed_statuses = {
        "new",
        "acknowledged",
        "resolved",
        "false_positive",
    }

    if status in allowed_statuses:

        alert.status = status

        db.session.commit()

    return jsonify(
        {
            "ok": True,
            "status": alert.status,
            "client_id": client_id,
        }
    )


# ============================================================
# ANALYTICS
# ============================================================

@api.get("/analytics")
def analytics():
    """
    Optimized analytics endpoint.

    All analytics are calculated only from the requesting
    NETSENTINEL client's telemetry.
    """

    client_id = get_client_id()

    # --------------------------------------------------------
    # TOTAL PACKETS
    # --------------------------------------------------------

    total_packets = (
        db.session.query(
            func.count(
                Traffic.id
            )
        )
        .filter(
            Traffic.client_id == client_id
        )
        .scalar()
        or 0
    )

    # --------------------------------------------------------
    # PROTOCOL DISTRIBUTION
    # --------------------------------------------------------

    protocol_rows = (
        db.session.query(
            Traffic.protocol,
            func.count(
                Traffic.id
            ),
        )
        .filter(
            Traffic.client_id == client_id
        )
        .group_by(
            Traffic.protocol
        )
        .all()
    )

    protocol_distribution = (
        protocol_distribution_from_rows(
            protocol_rows
        )
    )

    # --------------------------------------------------------
    # TOTAL ALERTS
    # --------------------------------------------------------

    total_alerts = (
        db.session.query(
            func.count(
                Alert.id
            )
        )
        .filter(
            Alert.client_id == client_id
        )
        .scalar()
        or 0
    )

    # --------------------------------------------------------
    # ACTIVE DEVICES — LAST 5 MINUTES
    # --------------------------------------------------------

    latest_time = (
        db.session.query(
            func.max(
                Traffic.timestamp
            )
        )
        .filter(
            Traffic.client_id == client_id
        )
        .scalar()
    )

    active_device_ips = set()

    if latest_time is not None:

        normalized_latest = normalize_dt(
            latest_time
        )

        cutoff = (
            normalized_latest
            - timedelta(
                minutes=5
            )
        )

        device_rows = (
            db.session.query(
                Traffic.source_ip,
                Traffic.destination_ip,
            )
            .filter(
                Traffic.client_id == client_id,
                Traffic.timestamp >= cutoff,
                Traffic.timestamp <= normalized_latest,
            )
            .all()
        )

        for (
            source_ip,
            destination_ip,
        ) in device_rows:

            if (
                source_ip
                and is_local_or_private_ip(
                    source_ip
                )
            ):
                active_device_ips.add(
                    source_ip
                )

            if (
                destination_ip
                and is_local_or_private_ip(
                    destination_ip
                )
            ):
                active_device_ips.add(
                    destination_ip
                )

    return jsonify(
        {
            "client_id": client_id,
            "total_packets": int(
                total_packets
            ),
            "protocol_distribution":
                protocol_distribution,
            "alerts": int(
                total_alerts
            ),
            "devices": len(
                active_device_ips
            ),
        }
    )