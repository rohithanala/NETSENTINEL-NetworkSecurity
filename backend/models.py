"""
NETSENTINEL — Database models.

Three models match the spec exactly (Traffic, Alert, Device). A fourth,
AppSetting, is added as a simple key-value store so that Settings and the
LIVE/DEMO mode toggle persist across restarts.

Every table that stores traffic-derived data carries is_demo so Demo Mode
and Live Mode data can coexist in the same database without contaminating
each other's statistics.
"""

from datetime import datetime, timezone

from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()


def utcnow() -> datetime:
    """Timezone-aware UTC now, used as a default for timestamp columns."""
    return datetime.now(timezone.utc)


class Traffic(db.Model):
    __tablename__ = "traffic"

    id = db.Column(
        db.Integer,
        primary_key=True,
        autoincrement=True,
    )

    timestamp = db.Column(
        db.DateTime,
        nullable=False,
        default=utcnow,
        index=True,
    )

    source_ip = db.Column(
        db.String(45),
        nullable=False,
        index=True,
    )

    destination_ip = db.Column(
        db.String(45),
        nullable=False,
        index=True,
    )

    source_port = db.Column(
        db.Integer,
        nullable=True,
    )

    destination_port = db.Column(
        db.Integer,
        nullable=True,
    )

    protocol = db.Column(
        db.String(10),
        nullable=False,
        default="OTHER",
    )

    packet_size = db.Column(
        db.Integer,
        nullable=False,
        default=0,
    )

    tcp_flags = db.Column(
        db.String(20),
        nullable=True,
    )

    interface = db.Column(
        db.String(50),
        nullable=True,
    )

    is_demo = db.Column(
        db.Boolean,
        nullable=False,
        default=False,
        index=True,
    )

    __table_args__ = (
        db.Index(
            "ix_traffic_is_demo_timestamp",
            "is_demo",
            "timestamp",
        ),
        db.Index(
            "ix_traffic_protocol_is_demo",
            "protocol",
            "is_demo",
        ),
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": (
                self.timestamp.isoformat()
                if self.timestamp
                else None
            ),
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "packet_size": self.packet_size,
            "tcp_flags": self.tcp_flags,
            "interface": self.interface,
            "is_demo": self.is_demo,
        }


class Alert(db.Model):
    __tablename__ = "alerts"

    # These constants are required by the capture/detection pipeline.
    VALID_SEVERITIES = (
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    )

    VALID_STATUSES = (
        "new",
        "acknowledged",
        "resolved",
        "false_positive",
    )

    id = db.Column(
        db.Integer,
        primary_key=True,
        autoincrement=True,
    )

    timestamp = db.Column(
        db.DateTime,
        nullable=False,
        default=utcnow,
        index=True,
    )

    detection_type = db.Column(
        db.String(100),
        nullable=False,
        index=True,
    )

    source_ip = db.Column(
        db.String(45),
        nullable=False,
        index=True,
    )

    destination_ip = db.Column(
        db.String(45),
        nullable=True,
    )

    protocol = db.Column(
        db.String(10),
        nullable=True,
    )

    severity = db.Column(
        db.String(20),
        nullable=False,
        default="LOW",
        index=True,
    )

    confidence = db.Column(
        db.Float,
        nullable=False,
        default=0.5,
    )

    description = db.Column(
        db.Text,
        nullable=True,
    )

    status = db.Column(
        db.String(20),
        nullable=False,
        default="new",
        index=True,
    )

    is_demo = db.Column(
        db.Boolean,
        nullable=False,
        default=False,
        index=True,
    )

    __table_args__ = (
        db.Index(
            "ix_alerts_is_demo_timestamp",
            "is_demo",
            "timestamp",
        ),
        db.Index(
            "ix_alerts_severity_is_demo",
            "severity",
            "is_demo",
        ),
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": (
                self.timestamp.isoformat()
                if self.timestamp
                else None
            ),
            "detection_type": self.detection_type,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "protocol": self.protocol,
            "severity": self.severity,
            "confidence": self.confidence,
            "description": self.description,
            "status": self.status,
            "is_demo": self.is_demo,
        }


class Device(db.Model):
    __tablename__ = "devices"

    VALID_STATUSES = (
        "normal",
        "suspicious",
        "critical",
    )

    id = db.Column(
        db.Integer,
        primary_key=True,
        autoincrement=True,
    )

    ip_address = db.Column(
        db.String(45),
        nullable=False,
        index=True,
    )

    mac_address = db.Column(
        db.String(17),
        nullable=True,
    )

    hostname = db.Column(
        db.String(255),
        nullable=True,
    )

    first_seen = db.Column(
        db.DateTime,
        nullable=False,
        default=utcnow,
    )

    last_seen = db.Column(
        db.DateTime,
        nullable=False,
        default=utcnow,
        index=True,
    )

    packet_count = db.Column(
        db.Integer,
        nullable=False,
        default=0,
    )

    status = db.Column(
        db.String(20),
        nullable=False,
        default="normal",
        index=True,
    )

    is_demo = db.Column(
        db.Boolean,
        nullable=False,
        default=False,
        index=True,
    )

    __table_args__ = (
        db.UniqueConstraint(
            "ip_address",
            "is_demo",
            name="uq_devices_ip_mode",
        ),
        db.Index(
            "ix_devices_is_demo_last_seen",
            "is_demo",
            "last_seen",
        ),
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "hostname": self.hostname,
            "first_seen": (
                self.first_seen.isoformat()
                if self.first_seen
                else None
            ),
            "last_seen": (
                self.last_seen.isoformat()
                if self.last_seen
                else None
            ),
            "packet_count": self.packet_count,
            "status": self.status,
            "is_demo": self.is_demo,
        }


class AppSetting(db.Model):
    """
    Simple key-value store for persisted settings and current mode.
    """

    __tablename__ = "app_settings"

    key = db.Column(
        db.String(100),
        primary_key=True,
    )

    value = db.Column(
        db.Text,
        nullable=True,
    )

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "value": self.value,
        }