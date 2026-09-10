import os
from pathlib import Path

from dotenv import load_dotenv


# ============================================================
# ENVIRONMENT
# ============================================================

BASE_DIR = Path(__file__).parent

load_dotenv(BASE_DIR / ".env")


# ============================================================
# APPLICATION CONFIGURATION
# ============================================================

class Config:

    # --------------------------------------------------------
    # Flask
    # --------------------------------------------------------

    SECRET_KEY = os.getenv(
        "SECRET_KEY",
        "netsentinel-dev",
    )

    # --------------------------------------------------------
    # Database
    # --------------------------------------------------------

    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        f"sqlite:///{BASE_DIR / 'netsentinel.db'}",
    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # --------------------------------------------------------
    # NETSENTINEL MODE
    #
    # Supported:
    #
    #   LIVE
    #   DEMO
    #
    # NETSENTINEL_MODE is the primary setting.
    # MONITOR_MODE is retained as a fallback for compatibility.
    # --------------------------------------------------------

    NETSENTINEL_MODE = os.getenv(
        "NETSENTINEL_MODE",
        os.getenv(
            "MONITOR_MODE",
            "LIVE",
        ),
    ).upper()

    # Compatibility alias
    MODE = NETSENTINEL_MODE

    MONITOR_MODE = NETSENTINEL_MODE

    # --------------------------------------------------------
    # Monitoring
    # --------------------------------------------------------

    MONITOR_INTERFACE = os.getenv(
        "MONITOR_INTERFACE",
        "",
    )

    MONITORING_ENABLED = os.getenv(
        "MONITORING_ENABLED",
        "true",
    )

    # --------------------------------------------------------
    # Port scan detection
    # --------------------------------------------------------

    PORT_SCAN_WINDOW = int(
        os.getenv(
            "PORT_SCAN_WINDOW",
            "10",
        )
    )

    PORT_SCAN_THRESHOLD = int(
        os.getenv(
            "PORT_SCAN_THRESHOLD",
            "15",
        )
    )

    # --------------------------------------------------------
    # Connection-rate detection
    # --------------------------------------------------------

    CONNECTION_RATE_WINDOW = int(
        os.getenv(
            "CONNECTION_RATE_WINDOW",
            "10",
        )
    )

    CONNECTION_RATE_THRESHOLD = int(
        os.getenv(
            "CONNECTION_RATE_THRESHOLD",
            "50",
        )
    )

    # --------------------------------------------------------
    # Alert cooldown
    # --------------------------------------------------------

    ALERT_COOLDOWN_SECONDS = int(
        os.getenv(
            "ALERT_COOLDOWN_SECONDS",
            "10",
        )
    )